"""Restricted production trace refinement for :mod:`sluice_v2.durable_secure`.

The independent checker models one-use, scoped gates.  Durable v2 deliberately
has reusable routes and does not implement delegation or successor gates.
This module therefore exposes a fail-closed *subset* correspondence: a bound
route may commit successfully at most once, every bound gate has a unique
scope and no successors, and only denial shapes represented by the abstract
model are admitted.  Unsupported durable operations are rejected before the
monitor call whenever they are recognizable in advance.

Transitions are never supplied by a caller.  They are derived from two
consistent read transactions around an actual durable operation and from the
committed authorization, capability, attempt, and audit rows.  The exact
canonical JSONL line appended to ``trace_bytes`` is reparsed and accepted by
``FormalTraceChecker`` before it becomes part of the trace.

Emission is operation-atomic.  Transitions are accepted by a private candidate
checker and remain staged until the complete durable after-snapshot has passed
projection and inventory validation.  A post-call validation failure
permanently poisons the emitter and makes every evidence export fail closed.
A crash-committed ``RESERVED`` transition is retained for recovery, but is
available only through the explicitly named ``recovery_prefix_bytes`` API; it
cannot be mistaken for ordinary exportable evidence.

The durable audit journal inserts ``START`` for every charged reservation.  In
the formal model, ``auditStarts`` is indexed only by successfully claimed
gates.  Snapshot validation checks the broader database invariant (exactly one
START per attempt); ``audit_start_delta`` is the narrower successful-claim
join.  No audit row is ignored by the production-side validation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from types import MappingProxyType
import sqlite3
from typing import Any, Callable, Mapping

from .durable_secure import (
    AttemptCredential,
    DurableSecureDomain,
    EffectCapability,
    ReauthorizationGrant,
    RouteToken,
)
from .formal_trace import (
    AbstractTransitionV1,
    FormalManifest,
    FormalTraceChecker,
    TraceCheckReport,
    check_trace,
)
from .observer import EventKind, OutcomeCode, TranscriptEvent


class FormalEmitterError(RuntimeError):
    """The durable database did not refine the configured abstract trace."""


class UnsupportedCorrespondence(FormalEmitterError):
    """The requested durable operation is outside the proved trace subset."""


class IncompleteFormalEvidence(FormalEmitterError):
    """The checked trace is only a crash-recovery prefix, not final evidence."""


def _strict_slot(name: str, value: object, size: int) -> int:
    if type(value) is not int or not 0 <= value < size:
        raise ValueError(f"{name} must be an in-range strict integer slot")
    return value


def _string_slot_map(
    name: str, raw: Mapping[str, int], size: int, *, exact: bool
) -> Mapping[str, int]:
    if not isinstance(raw, Mapping):
        raise TypeError(f"{name} must be a mapping")
    copied: dict[str, int] = {}
    for identity, slot in raw.items():
        if type(identity) is not str or not identity:
            raise TypeError(f"{name} keys must be nonempty strings")
        copied[identity] = _strict_slot(f"{name} value", slot, size)
    if len(set(copied.values())) != len(copied):
        raise ValueError(f"{name} aliases two private identities to one slot")
    if exact and set(copied.values()) != set(range(size)):
        raise ValueError(f"{name} must cover every manifest slot exactly once")
    return MappingProxyType(copied)


def _pair_slot_map(
    name: str, raw: Mapping[tuple[str, str], int], size: int, *, exact: bool
) -> Mapping[tuple[str, str], int]:
    if not isinstance(raw, Mapping):
        raise TypeError(f"{name} must be a mapping")
    copied: dict[tuple[str, str], int] = {}
    for identity, slot in raw.items():
        if (
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(part) is not str or not part for part in identity)
        ):
            raise TypeError(f"{name} keys must be pairs of nonempty strings")
        copied[identity] = _strict_slot(f"{name} value", slot, size)
    if len(set(copied.values())) != len(copied):
        raise ValueError(f"{name} aliases two private identities to one slot")
    if exact and set(copied.values()) != set(range(size)):
        raise ValueError(f"{name} must cover every manifest slot exactly once")
    return MappingProxyType(copied)


@dataclass(frozen=True, slots=True)
class DurableFormalBinding:
    """Private, strict bijection from durable identities to manifest slots."""

    manifest: FormalManifest
    domain_slot: int
    object_slots: Mapping[str, int]
    route_gate_slots: Mapping[str, int]
    agent_slots: Mapping[str, int]
    credential_nonce_slots: Mapping[tuple[str, str], int]
    grant_slots: Mapping[tuple[str, str], int]
    capability_slots: Mapping[str, int]
    redeemer_slots: Mapping[str, int]

    @classmethod
    def from_maps(
        cls,
        manifest_line: bytes,
        *,
        domain_slot: int,
        object_slots: Mapping[str, int],
        route_gate_slots: Mapping[str, int],
        agent_slots: Mapping[str, int],
        credential_nonce_slots: Mapping[tuple[str, str], int],
        grant_slots: Mapping[tuple[str, str], int],
        capability_slots: Mapping[str, int],
        redeemer_slots: Mapping[str, int],
    ) -> "DurableFormalBinding":
        manifest = FormalManifest.from_bytes(manifest_line)
        domain = _strict_slot("domain_slot", domain_slot, len(manifest.domains))
        if len(manifest.domains) != 1:
            raise ValueError("the durable correspondence supports one physical domain")
        if manifest.delegations:
            raise ValueError("durable v2 has no delegation transition to bind")

        objects = _string_slot_map(
            "object_slots", object_slots, len(manifest.objects), exact=True
        )
        routes = _string_slot_map(
            "route_gate_slots", route_gate_slots, len(manifest.gates), exact=True
        )
        agents = _string_slot_map(
            "agent_slots", agent_slots, len(manifest.agents), exact=True
        )
        nonces = _pair_slot_map(
            "credential_nonce_slots",
            credential_nonce_slots,
            len(manifest.nonces),
            exact=True,
        )
        grants = _pair_slot_map(
            "grant_slots", grant_slots, len(manifest.reauth_grants), exact=True
        )
        capabilities = _string_slot_map(
            "capability_slots",
            capability_slots,
            len(manifest.capabilities),
            exact=True,
        )
        redeemers = _string_slot_map(
            "redeemer_slots", redeemer_slots, len(manifest.redeemers), exact=True
        )

        if any(agent not in agents for agent, _nonce in nonces):
            raise ValueError("every credential slot needs a bound agent slot")
        scopes = [manifest.gates[gate][1] for gate in routes.values()]
        if len(set(scopes)) != len(scopes):
            raise ValueError("bound durable gates must have unique complete scopes")
        for gate in routes.values():
            _name, scope, successors, _requires = manifest.gates[gate]
            if manifest.scopes[scope][0] != domain:
                raise ValueError("every bound gate must belong to the physical domain")
            if successors:
                raise ValueError("durable v2 cannot refine scoped successor gates")
        if any(record[1] != domain for record in manifest.reauth_grants):
            raise ValueError("every bound reauthorization grant must target the domain")

        return cls(
            manifest=manifest,
            domain_slot=domain,
            object_slots=objects,
            route_gate_slots=routes,
            agent_slots=agents,
            credential_nonce_slots=nonces,
            grant_slots=grants,
            capability_slots=capabilities,
            redeemer_slots=redeemers,
        )

    def validate_database(self, domain: DurableSecureDomain) -> "DurableFormalBinding":
        if type(domain) is not DurableSecureDomain:
            raise TypeError("domain must be a DurableSecureDomain")
        path = getattr(domain, "_path", None)
        if type(path) is not str:
            raise FormalEmitterError("durable database path is unavailable")
        snapshot = _read_snapshot(path, self)
        if snapshot.attempts or snapshot.credentials or snapshot.grants:
            raise ValueError("a new emitter binding requires an unused durable domain")
        if snapshot.audit_starts or snapshot.audit_finals:
            raise ValueError("a new emitter binding requires an empty audit journal")
        if snapshot.current_epoch != 0:
            raise ValueError("a new emitter binding requires epoch zero")
        if snapshot.charge != self.manifest.event_charge_units:
            raise ValueError("durable event charge differs from the formal manifest")
        if snapshot.budget != self.manifest.initial_budget_units:
            raise ValueError("durable initial budget differs from the formal manifest")
        if snapshot.horizon != self.manifest.initial_horizon:
            raise ValueError("durable initial horizon differs from the formal manifest")
        if snapshot.state != "active":
            raise ValueError("the durable domain must be ACTIVE before tracing")

        if set(snapshot.routes) != set(self.route_gate_slots):
            raise ValueError("route binding must cover the sealed database exactly")
        for route_handle, gate in self.route_gate_slots.items():
            route = snapshot.routes[route_handle]
            scope = self.manifest.scopes[self.manifest.gates[gate][1]]
            object_slot = self.object_slots.get(route.protected_object)
            if object_slot != scope[2]:
                raise ValueError("route protected object does not match its object slot")
            if route.requires_capability != self.manifest.gates[gate][3]:
                raise ValueError("route capability policy differs from its gate slot")

        if set(snapshot.capabilities) != set(self.capability_slots):
            raise ValueError("capability binding must cover the database exactly")
        for handle, slot in self.capability_slots.items():
            durable = snapshot.capabilities[handle]
            formal = self.manifest.capabilities[slot]
            if self.route_gate_slots[durable.route_handle] != formal[1]:
                raise ValueError("capability route differs from its formal gate")
            if self.redeemer_slots.get(durable.redeemer_id) != formal[2]:
                raise ValueError("capability redeemer differs from its formal binding")
            if durable.epoch != self.manifest.scopes[
                self.manifest.gates[formal[1]][1]
            ][3]:
                raise ValueError("capability epoch differs from its gate scope")
        return self


@dataclass(frozen=True, slots=True)
class _RouteRow:
    protected_object: str
    requires_capability: bool


@dataclass(frozen=True, slots=True)
class _CapabilityRow:
    route_handle: str
    redeemer_id: str
    epoch: int
    expires_at: int
    consumed_attempt: int | None


@dataclass(frozen=True, slots=True)
class _AttemptRow:
    number: int
    epoch: int
    state: str
    kind: str
    route_handle: str | None
    is_effect: bool
    effect_state: str
    event: TranscriptEvent | None


@dataclass(frozen=True, slots=True)
class _Projection:
    epoch: int
    epoch_spent: tuple[int, ...]
    attempts: int
    horizon: int
    spent: int
    budget: int
    visible: int
    closed: bool
    authorization_version: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    state: str
    current_epoch: int
    epoch_spent: tuple[int, ...]
    attempts_used: int
    horizon: int
    spent: int
    budget: int
    charge: int
    routes: Mapping[str, _RouteRow]
    capabilities: Mapping[str, _CapabilityRow]
    attempts: tuple[_AttemptRow, ...]
    credentials: frozenset[tuple[str, str, int]]
    grants: frozenset[tuple[str, str, int]]
    audit_starts: frozenset[int]
    audit_finals: frozenset[int]
    authorization_version: int

    @property
    def reserved(self) -> tuple[_AttemptRow, ...]:
        return tuple(row for row in self.attempts if row.state == "RESERVED")

    @property
    def projection(self) -> _Projection:
        # Durable v2 marks a terminal reservation CLOSED before its backend is
        # finalized.  The formal model closes only after no gate is pending.
        abstract_closed = self.state == "closed" and not self.reserved
        return _Projection(
            epoch=self.current_epoch,
            epoch_spent=self.epoch_spent,
            attempts=self.attempts_used,
            horizon=self.horizon,
            spent=self.spent,
            budget=self.budget,
            visible=len(self.audit_finals),
            closed=abstract_closed,
            authorization_version=self.authorization_version,
        )


@dataclass(slots=True)
class _EmissionBatch:
    """Checker-accepted transitions not yet published as evidence."""

    checker: FormalTraceChecker
    lines: list[bytes]
    step: int
    projection: _Projection


def _parse_event(encoded: object) -> TranscriptEvent | None:
    if encoded is None:
        return None
    if type(encoded) is not str:
        raise FormalEmitterError("attempt event_json has a non-text value")
    try:
        value = json.loads(encoded)
        return TranscriptEvent.from_wire(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FormalEmitterError("attempt event_json is not a strict public event") from exc


def _read_snapshot(path: str, binding: DurableFormalBinding) -> _Snapshot:
    connection = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        metadata = connection.execute(
            "SELECT * FROM metadata WHERE singleton=1"
        ).fetchone()
        if metadata is None:
            raise FormalEmitterError("durable metadata row is missing")
        epoch_rows = connection.execute(
            "SELECT * FROM epochs ORDER BY epoch"
        ).fetchall()
        route_rows = connection.execute(
            "SELECT route_handle,protected_object,requires_capability FROM routes"
        ).fetchall()
        capability_rows = connection.execute(
            """
            SELECT capability_handle,route_handle,redeemer_id,epoch,
                   expires_at_lifetime_attempt,consumed_attempt
            FROM capabilities
            """
        ).fetchall()
        attempt_rows = connection.execute(
            """
            SELECT lifetime_attempt,epoch,state,kind,route_handle,is_effect,
                   effect_state,event_json
            FROM attempts ORDER BY lifetime_attempt
            """
        ).fetchall()
        credential_rows = connection.execute(
            "SELECT agent_id,nonce,consumed_attempt FROM used_credentials"
        ).fetchall()
        grant_rows = connection.execute(
            "SELECT authorizer_id,nonce,consumed_attempt FROM used_grants"
        ).fetchall()
        audit_rows = connection.execute(
            "SELECT lifetime_attempt,phase FROM audit_log"
        ).fetchall()
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()

    current_epoch = int(metadata["current_epoch"])
    if not 0 <= current_epoch <= binding.manifest.max_epoch:
        raise UnsupportedCorrespondence("durable epoch exceeds the frozen formal bound")
    expected_epochs = list(range(current_epoch + 1))
    if [int(row["epoch"]) for row in epoch_rows] != expected_epochs:
        raise FormalEmitterError("durable epochs are not a complete monotone prefix")
    epoch_spent_list = [0] * (binding.manifest.max_epoch + 1)
    epoch_attempt_total = 0
    for row in epoch_rows:
        epoch = int(row["epoch"])
        spent_units = int(row["spent_units"])
        attempts = int(row["attempts"])
        if spent_units != attempts * int(metadata["event_charge_units"]):
            raise FormalEmitterError("durable epoch does not have fixed charging")
        epoch_spent_list[epoch] = spent_units
        epoch_attempt_total += attempts

    attempts = tuple(
        _AttemptRow(
            number=int(row["lifetime_attempt"]),
            epoch=int(row["epoch"]),
            state=str(row["state"]),
            kind=str(row["kind"]),
            route_handle=row["route_handle"],
            is_effect=bool(row["is_effect"]),
            effect_state=str(row["effect_state"]),
            event=_parse_event(row["event_json"]),
        )
        for row in attempt_rows
    )
    if [row.number for row in attempts] != list(range(1, len(attempts) + 1)):
        raise FormalEmitterError("durable attempt numbers are not a complete prefix")
    if any(
        (row.state == "FINALIZED") != (row.event is not None) for row in attempts
    ):
        raise FormalEmitterError("attempt finalization and public event disagree")
    for row in attempts:
        if row.event is not None and row.event.attempt != row.number:
            raise FormalEmitterError("public event is linked to the wrong attempt")

    attempts_used = int(metadata["lifetime_attempts"])
    spent = int(metadata["lifetime_spent_units"])
    charge = int(metadata["event_charge_units"])
    if attempts_used != len(attempts) or epoch_attempt_total != attempts_used:
        raise FormalEmitterError("metadata attempt count differs from its journals")
    if spent != attempts_used * charge or sum(epoch_spent_list) != spent:
        raise FormalEmitterError("metadata spend differs from exact epoch charging")

    starts = frozenset(
        int(row["lifetime_attempt"])
        for row in audit_rows
        if row["phase"] == "START"
    )
    finals = frozenset(
        int(row["lifetime_attempt"])
        for row in audit_rows
        if row["phase"] == "FINAL"
    )
    all_attempt_numbers = frozenset(row.number for row in attempts)
    finalized_numbers = frozenset(
        row.number for row in attempts if row.state == "FINALIZED"
    )
    if starts != all_attempt_numbers:
        raise FormalEmitterError("database must contain exactly one START per attempt")
    if finals != finalized_numbers:
        raise FormalEmitterError("database FINAL rows differ from finalized attempts")

    credentials = frozenset(
        (str(row["agent_id"]), str(row["nonce"]), int(row["consumed_attempt"]))
        for row in credential_rows
    )
    grants = frozenset(
        (str(row["authorizer_id"]), str(row["nonce"]), int(row["consumed_attempt"]))
        for row in grant_rows
    )
    if len({attempt for _agent, _nonce, attempt in credentials}) != len(credentials):
        raise FormalEmitterError("more than one credential is linked to an attempt")
    if len({attempt for _auth, _nonce, attempt in grants}) != len(grants):
        raise FormalEmitterError("more than one grant is linked to an attempt")

    routes = MappingProxyType(
        {
            str(row["route_handle"]): _RouteRow(
                protected_object=str(row["protected_object"]),
                requires_capability=bool(row["requires_capability"]),
            )
            for row in route_rows
        }
    )
    capabilities = MappingProxyType(
        {
            str(row["capability_handle"]): _CapabilityRow(
                route_handle=str(row["route_handle"]),
                redeemer_id=str(row["redeemer_id"]),
                epoch=int(row["epoch"]),
                expires_at=int(row["expires_at_lifetime_attempt"]),
                consumed_attempt=(
                    None
                    if row["consumed_attempt"] is None
                    else int(row["consumed_attempt"])
                ),
            )
            for row in capability_rows
        }
    )

    # Route and capability inventory is part of the private frozen binding.
    # Durable v2 permits capability issuance while ACTIVE, so checking this on
    # every snapshot prevents an unbound late capability from escaping the
    # attested configuration merely because it has not yet been consumed.
    if set(routes) != set(binding.route_gate_slots):
        raise UnsupportedCorrespondence(
            "sealed route inventory differs from the frozen slot binding"
        )
    for route_handle, gate in binding.route_gate_slots.items():
        route = routes[route_handle]
        scope = binding.manifest.scopes[binding.manifest.gates[gate][1]]
        if binding.object_slots.get(route.protected_object) != scope[2]:
            raise ValueError("route protected object does not match its object slot")
        if route.requires_capability != binding.manifest.gates[gate][3]:
            raise FormalEmitterError("route capability policy drifted from its gate")
    if set(capabilities) != set(binding.capability_slots):
        raise UnsupportedCorrespondence(
            "capability inventory differs from the frozen slot binding"
        )
    for handle, slot in binding.capability_slots.items():
        durable_capability = capabilities[handle]
        formal_capability = binding.manifest.capabilities[slot]
        if (
            binding.route_gate_slots.get(durable_capability.route_handle)
            != formal_capability[1]
            or binding.redeemer_slots.get(durable_capability.redeemer_id)
            != formal_capability[2]
        ):
            raise FormalEmitterError("capability binding drifted from its formal slot")

    by_attempt = {row.number: row for row in attempts}
    capability_attempts: dict[int, str] = {}
    for handle, capability in capabilities.items():
        if capability.consumed_attempt is not None:
            if capability.consumed_attempt in capability_attempts:
                raise FormalEmitterError("more than one capability is linked to an attempt")
            capability_attempts[capability.consumed_attempt] = handle

    claimed_gates: set[int] = set()
    authorization_version = len(grants)
    for agent, nonce, attempt_no in credentials:
        row = by_attempt.get(attempt_no)
        if row is None or row.kind != EventKind.ATTEMPT.value:
            raise FormalEmitterError("credential points outside an ATTEMPT row")
        if row.route_handle not in binding.route_gate_slots:
            raise UnsupportedCorrespondence("claimed route has no formal gate slot")
        if (agent, nonce) not in binding.credential_nonce_slots:
            raise UnsupportedCorrespondence("claimed credential has no nonce slot")
        gate = binding.route_gate_slots[row.route_handle]
        if gate in claimed_gates:
            raise UnsupportedCorrespondence(
                "durable route reuse cannot refine a one-use gate"
            )
        claimed_gates.add(gate)
        if row.is_effect != routes[row.route_handle].requires_capability:
            raise FormalEmitterError("claimed route and effect marker disagree")
        if row.is_effect:
            if attempt_no not in capability_attempts:
                raise FormalEmitterError("effect claim has no consumed capability")
            consumed = capabilities[capability_attempts[attempt_no]]
            if consumed.route_handle != row.route_handle:
                raise FormalEmitterError("consumed capability points to another route")
            authorization_version += 3
        else:
            if attempt_no in capability_attempts:
                raise FormalEmitterError("direct claim unexpectedly consumed a capability")
            authorization_version += 2
        if attempt_no not in starts:
            raise FormalEmitterError("successful claim has no audit START row")

    for authorizer, nonce, attempt_no in grants:
        row = by_attempt.get(attempt_no)
        if row is None or row.kind != EventKind.REAUTHORIZE.value:
            raise FormalEmitterError("grant points outside a REAUTHORIZE row")
        if row.event is None or row.event.outcome is not OutcomeCode.REAUTHORIZED:
            raise FormalEmitterError("used grant lacks a REAUTHORIZED final event")
        if (authorizer, nonce) not in binding.grant_slots:
            raise UnsupportedCorrespondence("used grant has no formal slot")
    for attempt_no in capability_attempts:
        if attempt_no not in {item[2] for item in credentials}:
            raise FormalEmitterError("capability consumption lacks credential linkage")

    state = str(metadata["state"])
    horizon = int(metadata["attempt_horizon"])
    budget = int(metadata["lifetime_budget_units"])
    if state == "closed" and attempts_used != horizon:
        raise FormalEmitterError("closed durable domain is not at its horizon")
    if state not in {"active", "closed"}:
        raise FormalEmitterError("trace snapshots require ACTIVE or CLOSED state")

    return _Snapshot(
        state=state,
        current_epoch=current_epoch,
        epoch_spent=tuple(epoch_spent_list),
        attempts_used=attempts_used,
        horizon=horizon,
        spent=spent,
        budget=budget,
        charge=charge,
        routes=routes,
        capabilities=capabilities,
        attempts=attempts,
        credentials=credentials,
        grants=grants,
        audit_starts=starts,
        audit_finals=finals,
        authorization_version=authorization_version,
    )


class DurableFormalEmitter:
    """Instrument one fresh durable domain and emit a checked private trace."""

    def __init__(
        self,
        domain: DurableSecureDomain,
        binding: DurableFormalBinding,
        *,
        trace_id: str,
    ) -> None:
        if type(binding) is not DurableFormalBinding:
            raise TypeError("binding must be a DurableFormalBinding")
        binding.validate_database(domain)
        self._domain = domain
        self._binding = binding
        self._path = os.path.realpath(getattr(domain, "_path"))
        self._checker = FormalTraceChecker(binding.manifest)
        self._trace_id = trace_id
        self._step = 0
        self._lines: tuple[bytes, ...] = ()
        self._batch: _EmissionBatch | None = None
        self._poisoned = False
        initial_snapshot = _read_snapshot(self._path, binding)
        initial = initial_snapshot.projection
        expected = _Projection(
            epoch=0,
            epoch_spent=(0,) * (binding.manifest.max_epoch + 1),
            attempts=0,
            horizon=binding.manifest.initial_horizon,
            spent=0,
            budget=binding.manifest.initial_budget_units,
            visible=0,
            closed=False,
            authorization_version=0,
        )
        if initial != expected:
            raise FormalEmitterError("durable initial state differs from Formal Init")
        self._projection = initial
        self._recovery_required = bool(initial_snapshot.reserved)

    def _raise_if_poisoned(self) -> None:
        if self._poisoned or self._batch is not None:
            self._poison()
            raise FormalEmitterError(
                "formal emitter is permanently poisoned; no trace evidence is exportable"
            )

    def _poison(self) -> None:
        self._batch = None
        self._poisoned = True

    @property
    def evidence_status(self) -> str:
        """Return the fail-closed export state without exposing trace contents."""

        if self._poisoned or self._batch is not None:
            self._poison()
            return "poisoned"
        if self._recovery_required:
            return "recovery_required"
        return "exportable"

    @property
    def trace_bytes(self) -> bytes:
        self._raise_if_poisoned()
        if self._batch is not None:
            raise FormalEmitterError("trace export is unavailable during an operation")
        if self._recovery_required:
            raise IncompleteFormalEvidence(
                "trace is a recovery prefix, not exportable final evidence; "
                "use recovery_prefix_bytes only to resume recovery"
            )
        return b"".join(self._lines)

    @property
    def recovery_prefix_bytes(self) -> bytes:
        """Return a checked prefix only while one durable reservation is pending."""

        self._raise_if_poisoned()
        if self._batch is not None:
            raise FormalEmitterError("recovery-prefix export is unavailable during an operation")
        if not self._recovery_required:
            raise IncompleteFormalEvidence("no recovery prefix is pending")
        return b"".join(self._lines)

    @property
    def transition_count(self) -> int:
        return self._step

    def verify(self) -> TraceCheckReport:
        """Reparse and check the exact accumulated canonical JSONL bytes."""

        return check_trace(self._binding.manifest.canonical, self.trace_bytes)

    def _snapshot(self) -> _Snapshot:
        return _read_snapshot(self._path, self._binding)

    def _assert_before(self, snapshot: _Snapshot) -> None:
        self._raise_if_poisoned()
        if self._batch is not None:
            raise FormalEmitterError("another formal emission operation is in progress")
        if snapshot.projection != self._projection:
            self._poison()
            raise FormalEmitterError("durable before-state diverged from checked trace")
        if bool(snapshot.reserved) != self._recovery_required:
            self._poison()
            raise FormalEmitterError(
                "durable recovery state diverged from the checked evidence status"
            )

    def _begin_operation(
        self, before: _Snapshot, *, allow_recovery: bool = False
    ) -> None:
        """Stage one durable call and publish it only after complete validation."""

        self._raise_if_poisoned()
        if self._batch is not None:
            raise FormalEmitterError("another formal emission operation is in progress")
        if self._recovery_required and not allow_recovery:
            raise IncompleteFormalEvidence(
                "a durable reservation is pending; recover it before another operation"
            )
        if allow_recovery and not self._recovery_required:
            raise IncompleteFormalEvidence("no recovery prefix is pending")

        candidate = FormalTraceChecker(self._binding.manifest)
        for wire in self._lines:
            candidate.accept(
                AbstractTransitionV1.from_bytes(wire, self._binding.manifest)
            )
        self._batch = _EmissionBatch(
            checker=candidate,
            lines=[],
            step=self._step,
            projection=self._projection,
        )

    def _commit_operation(
        self, snapshot: _Snapshot, expected: _Projection
    ) -> None:
        batch = self._batch
        if batch is None:
            self._poison()
            raise FormalEmitterError("no staged formal emission operation exists")
        try:
            if batch.projection != expected:
                raise FormalEmitterError(
                    "staged formal projection differs from the expected after-state"
                )
            self._assert_after(snapshot, expected)
        except BaseException:
            self._poison()
            raise

        # Publish the immutable byte tuple only after every transition and the
        # complete durable after-snapshot have passed.  No staged prefix is
        # observable through either evidence API.
        self._checker = batch.checker
        self._lines = self._lines + tuple(batch.lines)
        self._step = batch.step
        self._projection = expected
        self._recovery_required = bool(snapshot.reserved)
        self._batch = None

    def _emit(
        self,
        action: str,
        outcome: str,
        before: _Projection,
        after: _Projection,
        *,
        scope: int | None = None,
        gate: int | None = None,
        agent: int | None = None,
        nonce: int | None = None,
        reauth: int | None = None,
        capability: int | None = None,
        redeemer: int | None = None,
        gate_delta: int = 0,
        nonce_delta: int = 0,
        reauth_delta: int = 0,
        capability_delta: int = 0,
        audit_delta: int = 0,
        padding_delta: int = 0,
    ) -> None:
        batch = self._batch
        if batch is None:
            self._poison()
            raise FormalEmitterError("formal transitions must be emitted inside an operation")
        transition = AbstractTransitionV1(
            schema_version=1,
            config_sha256=self._binding.manifest.config_sha256,
            trace_id=self._trace_id,
            step=batch.step + 1,
            action=action,
            outcome=outcome,
            domain_slot=self._binding.domain_slot,
            scope_slot=scope,
            gate_slot=gate,
            agent_slot=agent,
            nonce_slot=nonce,
            delegation_slot=None,
            reauth_grant_slot=reauth,
            capability_slot=capability,
            redeemer_slot=redeemer,
            predecessor_gate_slot=None,
            epoch_before=before.epoch,
            epoch_after=after.epoch,
            epoch_spent_before=before.epoch_spent,
            epoch_spent_after=after.epoch_spent,
            attempts_before=before.attempts,
            attempts_after=after.attempts,
            horizon_before=before.horizon,
            horizon_after=after.horizon,
            lifetime_spent_before=before.spent,
            lifetime_spent_after=after.spent,
            lifetime_budget_before=before.budget,
            lifetime_budget_after=after.budget,
            visible_events_before=before.visible,
            visible_events_after=after.visible,
            closed_before=before.closed,
            closed_after=after.closed,
            gate_claim_delta=gate_delta,
            nonce_use_delta=nonce_delta,
            delegation_use_delta=0,
            reauth_use_delta=reauth_delta,
            capability_use_delta=capability_delta,
            audit_start_delta=audit_delta,
            padding_event_delta=padding_delta,
            authorization_version_before=before.authorization_version,
            authorization_version_after=after.authorization_version,
        )
        wire = transition.to_wire()
        parsed = AbstractTransitionV1.from_bytes(wire, self._binding.manifest)
        batch.checker.accept(parsed)
        batch.lines.append(wire)
        batch.step += 1
        batch.projection = after

    def _reserve_projection(
        self, before: _Projection, *, visible: int, authorization: int
    ) -> _Projection:
        vector = list(before.epoch_spent)
        vector[before.epoch] += self._binding.manifest.event_charge_units
        return replace(
            before,
            epoch_spent=tuple(vector),
            attempts=before.attempts + 1,
            spent=before.spent + self._binding.manifest.event_charge_units,
            visible=before.visible + visible,
            authorization_version=before.authorization_version + authorization,
            closed=False,
        )

    def _emit_close_if_needed(
        self, current: _Projection, actual: _Projection
    ) -> _Projection:
        if actual.closed and not current.closed:
            closed = replace(current, closed=True)
            self._emit("close_at_horizon", "domain_closed", current, closed)
            return closed
        return current

    def _assert_after(self, snapshot: _Snapshot, expected: _Projection) -> None:
        if snapshot.projection != expected:
            raise FormalEmitterError("durable after-state diverged from emitted trace")

    def _closed_stutter(
        self,
        before: _Snapshot,
        after: _Snapshot,
        event: TranscriptEvent,
    ) -> TranscriptEvent:
        if event.outcome is not OutcomeCode.DOMAIN_CLOSED:
            raise FormalEmitterError("closed operation returned a non-closed event")
        if before != after:
            raise FormalEmitterError("closed reply changed durable state")
        projection = before.projection
        self._emit(
            "closed_reply_stutter",
            "domain_closed",
            projection,
            projection,
        )
        self._commit_operation(after, projection)
        return event

    def _credential_slots(
        self, credential: AttemptCredential | None
    ) -> tuple[int, int, tuple[str, str]]:
        if type(credential) is not AttemptCredential:
            raise UnsupportedCorrespondence("modeled claims require an attempt credential")
        key = (credential.agent_id, credential.nonce)
        nonce = self._binding.credential_nonce_slots.get(key)
        agent = self._binding.agent_slots.get(credential.agent_id)
        if nonce is None or agent is None:
            raise UnsupportedCorrespondence("credential slot is absent from the binding")
        return agent, nonce, key

    @staticmethod
    def _credential_attempts(snapshot: _Snapshot) -> set[int]:
        return {attempt for _agent, _nonce, attempt in snapshot.credentials}

    def _gate_scope(self, gate: int) -> tuple[int, int]:
        scope = self._binding.manifest.gates[gate][1]
        epoch = self._binding.manifest.scopes[scope][3]
        return scope, epoch

    def attempt(
        self,
        route: RouteToken,
        payload: Any,
        *,
        credential: AttemptCredential | None,
        capability: EffectCapability | None = None,
        redeemer_id: str | None = None,
    ) -> TranscriptEvent:
        before = self._snapshot()
        self._assert_before(before)
        if before.projection.closed:
            self._begin_operation(before)
            event = self._domain.attempt(
                route,
                payload,
                credential=credential,
                capability=capability,
                redeemer_id=redeemer_id,
            )
            return self._closed_stutter(before, self._snapshot(), event)

        if type(route) is not RouteToken:
            raise UnsupportedCorrespondence("route has no bound formal gate")
        route_handle = route.to_wire()
        gate = self._binding.route_gate_slots.get(route_handle)
        if gate is None:
            raise UnsupportedCorrespondence("route has no bound formal gate")
        scope, gate_epoch = self._gate_scope(gate)
        claimed_routes = {
            row.route_handle
            for row in before.attempts
            if row.number in self._credential_attempts(before)
        }
        if route_handle in claimed_routes:
            raise UnsupportedCorrespondence(
                "durable route reuse cannot refine a one-use gate"
            )
        agent, nonce, credential_key = self._credential_slots(credential)
        if credential_key in {(a, n) for a, n, _attempt in before.credentials}:
            raise UnsupportedCorrespondence(
                "credential replay denial has no current abstract reject action"
            )
        assert credential is not None
        if credential.route_handle != route_handle:
            raise UnsupportedCorrespondence(
                "cross-route credential denial has no current abstract action"
            )

        requires_capability = before.routes[route_handle].requires_capability
        category: str
        cap_slot: int | None = None
        redeemer_slot: int | None = None
        if gate_epoch != before.current_epoch:
            if credential.expected_epoch != gate_epoch:
                raise UnsupportedCorrespondence(
                    "future-gate success cannot refine durable route semantics"
                )
            if requires_capability:
                raise UnsupportedCorrespondence(
                    "stale effect denial is outside the current checker actions"
                )
            if capability is not None or redeemer_id is not None:
                raise UnsupportedCorrespondence("stale direct denial must be direct")
            category = "stale"
        elif credential.expected_epoch != before.current_epoch:
            raise UnsupportedCorrespondence(
                "credential epoch and frozen gate scope do not correspond"
            )
        elif requires_capability:
            if type(capability) is not EffectCapability:
                raise UnsupportedCorrespondence(
                    "missing-capability denial has no strict capability slot"
                )
            handle = capability.to_wire()
            cap_slot = self._binding.capability_slots.get(handle)
            redeemer_slot = self._binding.redeemer_slots.get(redeemer_id)  # type: ignore[arg-type]
            durable_cap = before.capabilities.get(handle)
            if cap_slot is None or redeemer_slot is None or durable_cap is None:
                raise UnsupportedCorrespondence("capability or redeemer slot is absent")
            formal_cap = self._binding.manifest.capabilities[cap_slot]
            if formal_cap[1] != gate:
                raise UnsupportedCorrespondence("capability is bound to a different gate")
            if durable_cap.consumed_attempt is not None:
                raise UnsupportedCorrespondence(
                    "capability replay denial has no current abstract reject action"
                )
            expected_redeemer = self._binding.redeemer_slots[durable_cap.redeemer_id]
            if formal_cap[2] != expected_redeemer:
                raise FormalEmitterError("formal capability redeemer binding drifted")
            category = (
                "effect" if redeemer_id == durable_cap.redeemer_id else "capability_denial"
            )
        else:
            if capability is not None or redeemer_id is not None:
                raise UnsupportedCorrespondence(
                    "capability on a direct route has no abstract correspondence"
                )
            category = "direct"

        self._begin_operation(before)
        error: BaseException | None = None
        event: TranscriptEvent | None = None
        try:
            event = self._domain.attempt(
                route,
                payload,
                credential=credential,
                capability=capability,
                redeemer_id=redeemer_id,
            )
        except BaseException as exc:
            error = exc
        after = self._snapshot()

        if after.attempts_used == before.attempts_used:
            if after != before:
                raise FormalEmitterError("failed pre-commit attempt changed durable state")
            assert error is not None
            raise error
        if after.attempts_used != before.attempts_used + 1:
            raise FormalEmitterError("one attempt call did not reserve exactly one slot")
        row = after.attempts[-1]
        if row.route_handle != route_handle or row.kind != EventKind.ATTEMPT.value:
            raise FormalEmitterError("new attempt row has the wrong route or kind")
        new_credentials = after.credentials - before.credentials
        new_capabilities = {
            handle
            for handle, record in after.capabilities.items()
            if record.consumed_attempt == row.number
            and before.capabilities[handle].consumed_attempt is None
        }

        current = before.projection
        if category in {"direct", "effect"}:
            expected_credential = (credential_key[0], credential_key[1], row.number)
            if new_credentials != {expected_credential}:
                raise FormalEmitterError("successful claim did not consume its exact credential")
            weight = 3 if category == "effect" else 2
            if category == "effect":
                assert cap_slot is not None and redeemer_slot is not None
                expected_handle = capability.to_wire()  # type: ignore[union-attr]
                if new_capabilities != {expected_handle}:
                    raise FormalEmitterError("effect claim did not consume its exact capability")
                action = "commit_effect"
            else:
                if new_capabilities:
                    raise FormalEmitterError("direct claim consumed a capability")
                action = "commit_direct"
            committed = self._reserve_projection(
                current, visible=0, authorization=weight
            )
            self._emit(
                action,
                "reserved",
                current,
                committed,
                scope=scope,
                gate=gate,
                agent=agent,
                nonce=nonce,
                capability=cap_slot,
                redeemer=redeemer_slot,
                gate_delta=1,
                nonce_delta=1,
                capability_delta=1 if category == "effect" else 0,
                audit_delta=1,
            )
            current = committed
            if row.state == "FINALIZED":
                if event is None or row.event != event:
                    raise FormalEmitterError("returned event differs from the durable FINAL row")
                if event.outcome not in {
                    OutcomeCode.RELEASED,
                    OutcomeCode.OUTPUT_DENIED,
                    OutcomeCode.INTERNAL_DENIED,
                }:
                    raise FormalEmitterError("successful claim has an invalid final outcome")
                finalized = replace(current, visible=current.visible + 1)
                self._emit(
                    "finalize",
                    event.outcome.value,
                    current,
                    finalized,
                    gate=gate,
                )
                current = finalized
            elif row.state != "RESERVED":
                raise FormalEmitterError("claim row has an unknown durable state")
        else:
            if error is not None or event is None or row.state != "FINALIZED":
                raise FormalEmitterError("modeled denial did not finalize synchronously")
            if new_credentials or new_capabilities:
                raise FormalEmitterError("denial consumed authorization state")
            denied = self._reserve_projection(current, visible=1, authorization=0)
            if category == "stale":
                if event.outcome is not OutcomeCode.AUTH_DENIED:
                    raise FormalEmitterError("stale credential did not return AUTH_DENIED")
                action = "reject_stale_epoch"
            else:
                if event.outcome is not OutcomeCode.CAPABILITY_DENIED:
                    raise FormalEmitterError(
                        "wrong redeemer did not return CAPABILITY_DENIED"
                    )
                action = "reject_capability_binding"
            self._emit(
                action,
                event.outcome.value,
                current,
                denied,
                scope=scope,
                gate=gate,
                agent=agent,
                nonce=nonce,
                capability=cap_slot,
                redeemer=redeemer_slot,
            )
            current = denied

        current = self._emit_close_if_needed(current, after.projection)
        self._commit_operation(after, current)
        if error is not None:
            raise error
        assert event is not None
        return event

    def continue_work(self) -> TranscriptEvent:
        before = self._snapshot()
        self._assert_before(before)
        self._begin_operation(before)
        event = self._domain.continue_work()
        after = self._snapshot()
        if before.projection.closed:
            return self._closed_stutter(before, after, event)
        if (
            event.outcome is not OutcomeCode.CONTINUED
            or after.attempts_used != before.attempts_used + 1
        ):
            raise FormalEmitterError("continue did not produce one charged CONTINUED slot")
        current = self._reserve_projection(
            before.projection, visible=1, authorization=0
        )
        self._emit("continue", "continued", before.projection, current)
        current = self._emit_close_if_needed(current, after.projection)
        self._commit_operation(after, current)
        return event

    def stop(self) -> TranscriptEvent:
        before = self._snapshot()
        self._assert_before(before)
        self._begin_operation(before)
        event = self._domain.stop()
        after = self._snapshot()
        if before.projection.closed:
            return self._closed_stutter(before, after, event)
        remaining = before.horizon - before.attempts_used
        if (
            remaining <= 0
            or event.outcome is not OutcomeCode.STOPPED
            or after.attempts_used - before.attempts_used != remaining
        ):
            raise FormalEmitterError("stop did not fill exactly the remaining horizon")
        new_rows = after.attempts[before.attempts_used :]
        if (
            not new_rows
            or new_rows[0].kind != EventKind.STOP.value
            or any(row.kind != EventKind.PADDING.value for row in new_rows[1:])
            or any(row.state != "FINALIZED" for row in new_rows)
        ):
            raise FormalEmitterError("stop/padding durable rows have the wrong shape")
        vector = list(before.projection.epoch_spent)
        vector[before.projection.epoch] += remaining * before.charge
        stopped = replace(
            before.projection,
            epoch_spent=tuple(vector),
            attempts=before.projection.horizon,
            spent=before.projection.spent + remaining * before.charge,
            visible=before.projection.visible + remaining,
            closed=True,
        )
        self._emit(
            "stop_and_pad",
            "stopped",
            before.projection,
            stopped,
            padding_delta=remaining - 1,
        )
        self._commit_operation(after, stopped)
        return event

    def reauthorize(
        self, grant: ReauthorizationGrant | None
    ) -> TranscriptEvent:
        before = self._snapshot()
        self._assert_before(before)
        if before.projection.closed:
            self._begin_operation(before)
            event = self._domain.reauthorize(grant)
            return self._closed_stutter(before, self._snapshot(), event)
        if type(grant) is not ReauthorizationGrant:
            raise UnsupportedCorrespondence("reauthorization requires a bound grant")
        key = (grant.authorizer_id, grant.nonce)
        grant_slot = self._binding.grant_slots.get(key)
        if grant_slot is None:
            raise UnsupportedCorrespondence("reauthorization grant slot is absent")
        used = key in {(a, n) for a, n, _attempt in before.grants}
        if used:
            category = "replay"
        else:
            if grant.expected_epoch != before.current_epoch:
                raise UnsupportedCorrespondence(
                    "unused stale grant denial has no current abstract action"
                )
            if (
                grant.budget_increment_units
                != self._binding.manifest.reauth_budget_increment_units
                or grant.attempt_increment
                != self._binding.manifest.reauth_attempt_increment
            ):
                raise UnsupportedCorrespondence(
                    "grant increments differ from the frozen formal manifest"
                )
            if before.current_epoch >= self._binding.manifest.max_epoch:
                raise UnsupportedCorrespondence("formal maximum epoch is exhausted")
            category = "success"

        self._begin_operation(before)
        event = self._domain.reauthorize(grant)
        after = self._snapshot()
        if after.attempts_used != before.attempts_used + 1:
            raise FormalEmitterError("reauthorize did not reserve exactly one slot")
        current = before.projection
        charged = self._reserve_projection(current, visible=1, authorization=0)
        new_grants = after.grants - before.grants
        if category == "success":
            expected = (key[0], key[1], after.attempts_used)
            if event.outcome is not OutcomeCode.REAUTHORIZED or new_grants != {expected}:
                raise FormalEmitterError("accepted grant did not commit its exact replay key")
            vector = charged.epoch_spent
            accepted = replace(
                charged,
                epoch=charged.epoch + 1,
                epoch_spent=vector,
                horizon=charged.horizon
                + self._binding.manifest.reauth_attempt_increment,
                budget=charged.budget
                + self._binding.manifest.reauth_budget_increment_units,
                authorization_version=charged.authorization_version + 1,
            )
            self._emit(
                "reauthorize",
                "reauthorized",
                current,
                accepted,
                reauth=grant_slot,
                reauth_delta=1,
            )
            current = accepted
        else:
            if event.outcome is not OutcomeCode.REAUTH_DENIED or new_grants:
                raise FormalEmitterError("replayed grant did not roll back authorization")
            self._emit(
                "reject_reauthorization",
                "reauth_denied",
                current,
                charged,
                reauth=grant_slot,
            )
            current = charged
        current = self._emit_close_if_needed(current, after.projection)
        self._commit_operation(after, current)
        return event

    def recover(
        self, reopen: Callable[[], DurableSecureDomain]
    ) -> DurableSecureDomain:
        """Instrument constructor-driven recovery of one committed reservation."""

        if not callable(reopen):
            raise TypeError("reopen must be callable")
        before = self._snapshot()
        self._assert_before(before)
        if len(before.reserved) != 1:
            raise UnsupportedCorrespondence(
                "recovery correspondence requires exactly one pending attempt"
            )
        pending = before.reserved[0]
        if pending.route_handle not in self._binding.route_gate_slots:
            raise UnsupportedCorrespondence("pending route has no formal gate slot")
        self._begin_operation(before, allow_recovery=True)
        reopened = reopen()
        if type(reopened) is not DurableSecureDomain:
            raise TypeError("reopen must return a DurableSecureDomain")
        reopened_path = os.path.realpath(getattr(reopened, "_path", ""))
        if reopened_path != self._path:
            raise FormalEmitterError("reopen returned a different durable database")
        self._domain = reopened
        after = self._snapshot()
        if after.attempts_used != before.attempts_used:
            raise FormalEmitterError("recovery unexpectedly reserved another attempt")
        recovered = after.attempts[pending.number - 1]
        if recovered.state != "FINALIZED" or recovered.event is None:
            raise FormalEmitterError("reopen did not finalize the pending attempt")
        if recovered.event.outcome not in {
            OutcomeCode.RELEASED,
            OutcomeCode.OUTPUT_DENIED,
            OutcomeCode.INTERNAL_DENIED,
        }:
            raise FormalEmitterError("recovery produced an unmodeled final outcome")
        gate = self._binding.route_gate_slots[pending.route_handle]
        finalized = replace(
            before.projection, visible=before.projection.visible + 1
        )
        self._emit(
            "finalize",
            recovered.event.outcome.value,
            before.projection,
            finalized,
            gate=gate,
        )
        current = self._emit_close_if_needed(finalized, after.projection)
        self._commit_operation(after, current)
        return reopened


__all__ = [
    "DurableFormalBinding",
    "DurableFormalEmitter",
    "FormalEmitterError",
    "IncompleteFormalEvidence",
    "UnsupportedCorrespondence",
]
