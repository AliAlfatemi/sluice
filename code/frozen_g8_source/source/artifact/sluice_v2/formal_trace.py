"""Independent strict checker for the ``SluiceSecure`` abstract trace.

The checker deliberately does not import monitor, store, or durable-domain
transition code.  It reconstructs the abstract state from a frozen canonical
manifest and accepts a transition only when one named ``SluiceSecure.Next``
shape accounts for the complete emitted before/after projection.

These traces are private verification evidence.  They contain only integer
slots into the frozen manifest and must never contain raw identifiers,
payloads, keys, credentials, capabilities, or backend exception text.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping


MAX_INTEGER = (1 << 63) - 1
MAX_JSON_LINE_BYTES = 1 << 20
MAX_MANIFEST_DIMENSION = 4096
MAX_EPOCH = MAX_MANIFEST_DIMENSION - 1
MAX_EPOCH_STATE_CELLS = 1 << 20
MANIFEST_SCHEMA = "sluice.formal-config.v1"
TRACE_SCHEMA_VERSION = 1


class FormalTraceError(ValueError):
    """First fail-closed manifest or trace-conformance error."""


_ACTIONS = frozenset(
    {
        "commit_direct",
        "commit_delegated",
        "commit_effect",
        "reject_scoped_direct",
        "reject_scoped_delegated",
        "reject_capability_binding",
        "reject_stale_epoch",
        "finalize",
        "continue",
        "reauthorize",
        "reject_reauthorization",
        "stop_and_pad",
        "close_at_horizon",
        "closed_reply_stutter",
    }
)

_OUTCOMES = frozenset(
    {
        "none",
        "reserved",
        "released",
        "auth_denied",
        "route_denied",
        "capability_denied",
        "output_denied",
        "internal_denied",
        "continued",
        "stopped",
        "reauthorized",
        "reauth_denied",
        "domain_closed",
    }
)

_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "domains",
        "objects",
        "workflows",
        "agents",
        "nonces",
        "scopes",
        "gates",
        "delegations",
        "reauth_grants",
        "capabilities",
        "redeemers",
        "event_charge_units",
        "initial_budget_units",
        "initial_horizon",
        "reauth_budget_increment_units",
        "reauth_attempt_increment",
        "max_epoch",
    }
)

_TRANSITION_KEYS = frozenset(
    {
        "schema_version",
        "config_sha256",
        "trace_id",
        "step",
        "action",
        "outcome",
        "domain_slot",
        "scope_slot",
        "gate_slot",
        "agent_slot",
        "nonce_slot",
        "delegation_slot",
        "reauth_grant_slot",
        "capability_slot",
        "redeemer_slot",
        "predecessor_gate_slot",
        "epoch_before",
        "epoch_after",
        "epoch_spent_before",
        "epoch_spent_after",
        "attempts_before",
        "attempts_after",
        "horizon_before",
        "horizon_after",
        "lifetime_spent_before",
        "lifetime_spent_after",
        "lifetime_budget_before",
        "lifetime_budget_after",
        "visible_events_before",
        "visible_events_after",
        "closed_before",
        "closed_after",
        "gate_claim_delta",
        "nonce_use_delta",
        "delegation_use_delta",
        "reauth_use_delta",
        "capability_use_delta",
        "audit_start_delta",
        "padding_event_delta",
        "authorization_version_before",
        "authorization_version_after",
    }
)

_TRACE_ID = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _reject_constant(value: str) -> None:
    raise FormalTraceError(f"non-finite JSON constant is forbidden: {value}")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FormalTraceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json_line(value: object) -> bytes:
    """Return the only accepted JSON wire form."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FormalTraceError("value is not canonical-JSON serializable") from exc
    return encoded + b"\n"


def _parse_canonical_line(raw: bytes, *, label: str) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise TypeError(f"{label} must be bytes")
    if len(raw) > MAX_JSON_LINE_BYTES:
        raise FormalTraceError(
            f"{label} exceeds the {MAX_JSON_LINE_BYTES}-byte wire bound"
        )
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise FormalTraceError(f"{label} must be exactly one newline-terminated line")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormalTraceError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise FormalTraceError(f"{label} must be a JSON object")
    if canonical_json_line(value) != raw:
        raise FormalTraceError(f"{label} is not canonical JSON")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise FormalTraceError(f"{label} key mismatch: missing={missing}, extra={extra}")


def _integer(name: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise FormalTraceError(f"{name} must be a strict integer")
    if not minimum <= value <= MAX_INTEGER:
        raise FormalTraceError(f"{name} is outside [{minimum}, {MAX_INTEGER}]")
    return value


def _boolean(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise FormalTraceError(f"{name} must be a strict boolean")
    return value


def _slot(name: str, value: object, size: int, *, optional: bool) -> int | None:
    if value is None and optional:
        return None
    parsed = _integer(name, value)
    if parsed >= size:
        raise FormalTraceError(f"{name} is outside its manifest slot array")
    return parsed


def _name_array(name: str, value: object) -> tuple[str, ...]:
    if type(value) is not list or not value:
        raise FormalTraceError(f"{name} must be a nonempty array")
    if len(value) > MAX_MANIFEST_DIMENSION:
        raise FormalTraceError(
            f"{name} exceeds the {MAX_MANIFEST_DIMENSION}-entry manifest bound"
        )
    result: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str or not item or len(item.encode("utf-8")) > 256:
            raise FormalTraceError(f"{name}[{index}] must be a bounded string")
        result.append(item)
    if len(set(result)) != len(result):
        raise FormalTraceError(f"{name} contains duplicate identities")
    return tuple(result)


@dataclass(frozen=True, slots=True)
class FormalManifest:
    """Strict frozen slot manifest used to reconstruct ``Init``."""

    canonical: bytes
    config_sha256: str
    domains: tuple[str, ...]
    objects: tuple[str, ...]
    workflows: tuple[str, ...]
    agents: tuple[str, ...]
    nonces: tuple[str, ...]
    scopes: tuple[tuple[int, int, int, int], ...]
    gates: tuple[tuple[str, int, tuple[int, ...], bool], ...]
    delegations: tuple[tuple[str, int, int], ...]
    reauth_grants: tuple[tuple[str, int], ...]
    capabilities: tuple[tuple[str, int, int], ...]
    redeemers: tuple[str, ...]
    event_charge_units: int
    initial_budget_units: int
    initial_horizon: int
    reauth_budget_increment_units: int
    reauth_attempt_increment: int
    max_epoch: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> "FormalManifest":
        value = _parse_canonical_line(raw, label="formal manifest")
        _exact_keys(value, _MANIFEST_KEYS, "formal manifest")
        if value["schema_version"] != MANIFEST_SCHEMA:
            raise FormalTraceError("unsupported formal manifest schema")

        domains = _name_array("domains", value["domains"])
        objects = _name_array("objects", value["objects"])
        workflows = _name_array("workflows", value["workflows"])
        agents = _name_array("agents", value["agents"])
        nonces = _name_array("nonces", value["nonces"])
        redeemers = _name_array("redeemers", value["redeemers"])
        max_epoch = _integer("max_epoch", value["max_epoch"])
        if max_epoch > MAX_EPOCH:
            raise FormalTraceError(
                f"max_epoch exceeds the finite allocation bound {MAX_EPOCH}"
            )
        if len(domains) * (max_epoch + 1) > MAX_EPOCH_STATE_CELLS:
            raise FormalTraceError("domain-by-epoch state dimension exceeds its bound")

        raw_scopes = value["scopes"]
        if type(raw_scopes) is not list or not raw_scopes:
            raise FormalTraceError("scopes must be a nonempty array")
        if len(raw_scopes) > MAX_MANIFEST_DIMENSION:
            raise FormalTraceError("scopes exceeds the manifest dimension bound")
        scopes: list[tuple[int, int, int, int]] = []
        for index, item in enumerate(raw_scopes):
            if type(item) is not dict:
                raise FormalTraceError(f"scopes[{index}] must be an object")
            _exact_keys(
                item,
                frozenset({"domain_slot", "workflow_slot", "object_slot", "epoch"}),
                f"scopes[{index}]",
            )
            scope = (
                _slot("scope domain_slot", item["domain_slot"], len(domains), optional=False),
                _slot("scope workflow_slot", item["workflow_slot"], len(workflows), optional=False),
                _slot("scope object_slot", item["object_slot"], len(objects), optional=False),
                _integer("scope epoch", item["epoch"]),
            )
            assert all(type(part) is int for part in scope)
            if scope[3] > max_epoch:
                raise FormalTraceError("scope epoch exceeds max_epoch")
            scopes.append(scope)  # type: ignore[arg-type]
        if len(set(scopes)) != len(scopes):
            raise FormalTraceError("scopes contains duplicate complete scopes")

        raw_gates = value["gates"]
        if type(raw_gates) is not list or not raw_gates:
            raise FormalTraceError("gates must be a nonempty array")
        if len(raw_gates) > MAX_MANIFEST_DIMENSION:
            raise FormalTraceError("gates exceeds the manifest dimension bound")
        gates: list[tuple[str, int, tuple[int, ...], bool]] = []
        gate_names: set[str] = set()
        for index, item in enumerate(raw_gates):
            if type(item) is not dict:
                raise FormalTraceError(f"gates[{index}] must be an object")
            _exact_keys(
                item,
                frozenset({"name", "scope_slot", "successor_gate_slots", "requires_capability"}),
                f"gates[{index}]",
            )
            name = item["name"]
            if type(name) is not str or not name or name in gate_names:
                raise FormalTraceError("gate names must be nonempty and unique")
            gate_names.add(name)
            scope_slot = _slot("gate scope_slot", item["scope_slot"], len(scopes), optional=False)
            raw_successors = item["successor_gate_slots"]
            if type(raw_successors) is not list:
                raise FormalTraceError("successor_gate_slots must be an array")
            successors = tuple(
                _slot("successor gate slot", slot, len(raw_gates), optional=False)
                for slot in raw_successors
            )
            if any(slot is None for slot in successors) or len(set(successors)) != len(successors):
                raise FormalTraceError("successor slots must be unique integers")
            requires = _boolean("requires_capability", item["requires_capability"])
            assert scope_slot is not None
            gates.append((name, scope_slot, successors, requires))  # type: ignore[arg-type]

        def records(
            field: str,
            keys: frozenset[str],
            parse: Any,
        ) -> tuple[Any, ...]:
            raw_records = value[field]
            if type(raw_records) is not list:
                raise FormalTraceError(f"{field} must be an array")
            if len(raw_records) > MAX_MANIFEST_DIMENSION:
                raise FormalTraceError(
                    f"{field} exceeds the manifest dimension bound"
                )
            parsed: list[Any] = []
            names: set[str] = set()
            for index, item in enumerate(raw_records):
                if type(item) is not dict:
                    raise FormalTraceError(f"{field}[{index}] must be an object")
                _exact_keys(item, keys, f"{field}[{index}]")
                name = item.get("name")
                if type(name) is not str or not name or name in names:
                    raise FormalTraceError(f"{field} names must be nonempty and unique")
                names.add(name)
                parsed.append(parse(item))
            return tuple(parsed)

        delegations = records(
            "delegations",
            frozenset({"name", "agent_slot", "gate_slot"}),
            lambda item: (
                item["name"],
                _slot("delegation agent_slot", item["agent_slot"], len(agents), optional=False),
                _slot("delegation gate_slot", item["gate_slot"], len(gates), optional=False),
            ),
        )
        reauth_grants = records(
            "reauth_grants",
            frozenset({"name", "domain_slot"}),
            lambda item: (
                item["name"],
                _slot("reauth domain_slot", item["domain_slot"], len(domains), optional=False),
            ),
        )
        capabilities = records(
            "capabilities",
            frozenset({"name", "gate_slot", "redeemer_slot"}),
            lambda item: (
                item["name"],
                _slot("capability gate_slot", item["gate_slot"], len(gates), optional=False),
                _slot("capability redeemer_slot", item["redeemer_slot"], len(redeemers), optional=False),
            ),
        )

        charge = _integer("event_charge_units", value["event_charge_units"], minimum=1)
        initial_budget = _integer("initial_budget_units", value["initial_budget_units"], minimum=1)
        initial_horizon = _integer("initial_horizon", value["initial_horizon"], minimum=1)
        budget_increment = _integer(
            "reauth_budget_increment_units",
            value["reauth_budget_increment_units"],
            minimum=1,
        )
        attempt_increment = _integer(
            "reauth_attempt_increment", value["reauth_attempt_increment"], minimum=1
        )
        if initial_horizon * charge != initial_budget:
            raise FormalTraceError("initial budget must exactly fund the initial horizon")
        if attempt_increment * charge != budget_increment:
            raise FormalTraceError("reauthorization increment must exactly fund its added horizon")
        if initial_budget > MAX_INTEGER or budget_increment > MAX_INTEGER:
            raise FormalTraceError("manifest arithmetic exceeds the supported bound")

        canonical = canonical_json_line(value)
        return cls(
            canonical=canonical,
            config_sha256=hashlib.sha256(canonical).hexdigest(),
            domains=domains,
            objects=objects,
            workflows=workflows,
            agents=agents,
            nonces=nonces,
            scopes=tuple(scopes),
            gates=tuple(gates),
            delegations=delegations,
            reauth_grants=reauth_grants,
            capabilities=capabilities,
            redeemers=redeemers,
            event_charge_units=charge,
            initial_budget_units=initial_budget,
            initial_horizon=initial_horizon,
            reauth_budget_increment_units=budget_increment,
            reauth_attempt_increment=attempt_increment,
            max_epoch=max_epoch,
        )


@dataclass(frozen=True, slots=True)
class AbstractTransitionV1:
    schema_version: int
    config_sha256: str
    trace_id: str
    step: int
    action: str
    outcome: str
    domain_slot: int
    scope_slot: int | None
    gate_slot: int | None
    agent_slot: int | None
    nonce_slot: int | None
    delegation_slot: int | None
    reauth_grant_slot: int | None
    capability_slot: int | None
    redeemer_slot: int | None
    predecessor_gate_slot: int | None
    epoch_before: int
    epoch_after: int
    epoch_spent_before: tuple[int, ...]
    epoch_spent_after: tuple[int, ...]
    attempts_before: int
    attempts_after: int
    horizon_before: int
    horizon_after: int
    lifetime_spent_before: int
    lifetime_spent_after: int
    lifetime_budget_before: int
    lifetime_budget_after: int
    visible_events_before: int
    visible_events_after: int
    closed_before: bool
    closed_after: bool
    gate_claim_delta: int
    nonce_use_delta: int
    delegation_use_delta: int
    reauth_use_delta: int
    capability_use_delta: int
    audit_start_delta: int
    padding_event_delta: int
    authorization_version_before: int
    authorization_version_after: int

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        value["epoch_spent_before"] = list(self.epoch_spent_before)
        value["epoch_spent_after"] = list(self.epoch_spent_after)
        return value

    def to_wire(self) -> bytes:
        return canonical_json_line(self.to_mapping())

    @classmethod
    def from_bytes(cls, raw: bytes, manifest: FormalManifest) -> "AbstractTransitionV1":
        value = _parse_canonical_line(raw, label="abstract transition")
        _exact_keys(value, _TRANSITION_KEYS, "abstract transition")
        if value["schema_version"] != TRACE_SCHEMA_VERSION:
            raise FormalTraceError("unsupported transition schema")
        digest = value["config_sha256"]
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise FormalTraceError("config_sha256 is malformed")
        if digest != manifest.config_sha256:
            raise FormalTraceError("transition manifest hash mismatch")
        trace_id = value["trace_id"]
        if type(trace_id) is not str or _TRACE_ID.fullmatch(trace_id) is None:
            raise FormalTraceError("trace_id is malformed")
        action = value["action"]
        outcome = value["outcome"]
        if type(action) is not str or action not in _ACTIONS:
            raise FormalTraceError("unknown transition action")
        if type(outcome) is not str or outcome not in _OUTCOMES:
            raise FormalTraceError("unknown abstract outcome")

        def vector(name: str) -> tuple[int, ...]:
            raw_vector = value[name]
            if type(raw_vector) is not list or len(raw_vector) != manifest.max_epoch + 1:
                raise FormalTraceError(f"{name} has the wrong epoch dimension")
            return tuple(_integer(f"{name}[{index}]", item) for index, item in enumerate(raw_vector))

        for delta in (
            "gate_claim_delta",
            "nonce_use_delta",
            "delegation_use_delta",
            "reauth_use_delta",
            "capability_use_delta",
            "audit_start_delta",
        ):
            if _integer(delta, value[delta]) not in (0, 1):
                raise FormalTraceError(f"{delta} must be zero or one")

        return cls(
            schema_version=TRACE_SCHEMA_VERSION,
            config_sha256=digest,
            trace_id=trace_id,
            step=_integer("step", value["step"], minimum=1),
            action=action,
            outcome=outcome,
            domain_slot=_slot("domain_slot", value["domain_slot"], len(manifest.domains), optional=False),  # type: ignore[arg-type]
            scope_slot=_slot("scope_slot", value["scope_slot"], len(manifest.scopes), optional=True),
            gate_slot=_slot("gate_slot", value["gate_slot"], len(manifest.gates), optional=True),
            agent_slot=_slot("agent_slot", value["agent_slot"], len(manifest.agents), optional=True),
            nonce_slot=_slot("nonce_slot", value["nonce_slot"], len(manifest.nonces), optional=True),
            delegation_slot=_slot("delegation_slot", value["delegation_slot"], len(manifest.delegations), optional=True),
            reauth_grant_slot=_slot("reauth_grant_slot", value["reauth_grant_slot"], len(manifest.reauth_grants), optional=True),
            capability_slot=_slot("capability_slot", value["capability_slot"], len(manifest.capabilities), optional=True),
            redeemer_slot=_slot("redeemer_slot", value["redeemer_slot"], len(manifest.redeemers), optional=True),
            predecessor_gate_slot=_slot("predecessor_gate_slot", value["predecessor_gate_slot"], len(manifest.gates), optional=True),
            epoch_before=_integer("epoch_before", value["epoch_before"]),
            epoch_after=_integer("epoch_after", value["epoch_after"]),
            epoch_spent_before=vector("epoch_spent_before"),
            epoch_spent_after=vector("epoch_spent_after"),
            attempts_before=_integer("attempts_before", value["attempts_before"]),
            attempts_after=_integer("attempts_after", value["attempts_after"]),
            horizon_before=_integer("horizon_before", value["horizon_before"]),
            horizon_after=_integer("horizon_after", value["horizon_after"]),
            lifetime_spent_before=_integer("lifetime_spent_before", value["lifetime_spent_before"]),
            lifetime_spent_after=_integer("lifetime_spent_after", value["lifetime_spent_after"]),
            lifetime_budget_before=_integer("lifetime_budget_before", value["lifetime_budget_before"]),
            lifetime_budget_after=_integer("lifetime_budget_after", value["lifetime_budget_after"]),
            visible_events_before=_integer("visible_events_before", value["visible_events_before"]),
            visible_events_after=_integer("visible_events_after", value["visible_events_after"]),
            closed_before=_boolean("closed_before", value["closed_before"]),
            closed_after=_boolean("closed_after", value["closed_after"]),
            gate_claim_delta=value["gate_claim_delta"],
            nonce_use_delta=value["nonce_use_delta"],
            delegation_use_delta=value["delegation_use_delta"],
            reauth_use_delta=value["reauth_use_delta"],
            capability_use_delta=value["capability_use_delta"],
            audit_start_delta=value["audit_start_delta"],
            padding_event_delta=_integer("padding_event_delta", value["padding_event_delta"]),
            authorization_version_before=_integer("authorization_version_before", value["authorization_version_before"]),
            authorization_version_after=_integer("authorization_version_after", value["authorization_version_after"]),
        )


@dataclass(slots=True)
class _ModelState:
    epoch: list[int]
    epoch_spent: list[list[int]]
    attempts: list[int]
    horizon: list[int]
    spent: list[int]
    budget: list[int]
    visible: list[int]
    closed: list[bool]
    gate_claims: set[int]
    nonce_uses: set[tuple[int, int]]
    delegation_uses: set[int]
    reauth_uses: set[int]
    capability_uses: set[int]
    nonce_claim_gate: dict[tuple[int, int], int]
    delegation_claim_gate: dict[int, int]
    capability_claim: dict[int, tuple[int, int]]
    gate_predecessor: dict[int, int | None]
    pending: set[int]
    finalized: set[int]
    audit_starts: set[int]
    last_gate: dict[int, int]
    padding_events: list[int]
    authorization_version: int
    claim_weight: dict[int, int]

    @classmethod
    def initial(cls, manifest: FormalManifest) -> "_ModelState":
        domains = len(manifest.domains)
        return cls(
            epoch=[0] * domains,
            epoch_spent=[[0] * (manifest.max_epoch + 1) for _ in range(domains)],
            attempts=[0] * domains,
            horizon=[manifest.initial_horizon] * domains,
            spent=[0] * domains,
            budget=[manifest.initial_budget_units] * domains,
            visible=[0] * domains,
            closed=[False] * domains,
            gate_claims=set(),
            nonce_uses=set(),
            delegation_uses=set(),
            reauth_uses=set(),
            capability_uses=set(),
            nonce_claim_gate={},
            delegation_claim_gate={},
            capability_claim={},
            gate_predecessor={},
            pending=set(),
            finalized=set(),
            audit_starts=set(),
            last_gate={},
            padding_events=[0] * domains,
            authorization_version=0,
            claim_weight={},
        )


@dataclass(frozen=True, slots=True)
class TraceCheckReport:
    trace_id: str
    transitions: int
    final_authorization_version: int
    final_attempts: tuple[int, ...]
    final_visible_events: tuple[int, ...]


class FormalTraceChecker:
    """Independent deterministic validator for one private abstract trace."""

    def __init__(self, manifest: FormalManifest) -> None:
        if type(manifest) is not FormalManifest:
            raise TypeError("manifest must be a FormalManifest")
        self.manifest = manifest
        self._state = _ModelState.initial(manifest)
        self._trace_id: str | None = None
        self._step = 0

    def check_bytes(self, raw: bytes) -> TraceCheckReport:
        if type(raw) is not bytes:
            raise TypeError("trace must be bytes")
        if not raw:
            raise FormalTraceError("trace is empty")
        lines = raw.splitlines(keepends=True)
        if b"".join(lines) != raw or any(not line.endswith(b"\n") for line in lines):
            raise FormalTraceError("trace has a truncated final line")
        for line in lines:
            self.accept(AbstractTransitionV1.from_bytes(line, self.manifest))
        assert self._trace_id is not None
        return TraceCheckReport(
            trace_id=self._trace_id,
            transitions=self._step,
            final_authorization_version=self._state.authorization_version,
            final_attempts=tuple(self._state.attempts),
            final_visible_events=tuple(self._state.visible),
        )

    def accept(self, transition: AbstractTransitionV1) -> None:
        if type(transition) is not AbstractTransitionV1:
            raise TypeError("transition must be AbstractTransitionV1")
        # The public incremental API must enforce exactly the same strict,
        # canonical schema as the JSONL API.  Frozen dataclasses do not enforce
        # their annotations at runtime, so round-trip and reparse before any
        # checker state is consulted or mutated.
        normalized = AbstractTransitionV1.from_bytes(
            transition.to_wire(), self.manifest
        )
        if normalized != transition:
            raise FormalTraceError("transition object is not in canonical typed form")
        transition = normalized
        candidate_trace_id = self._trace_id
        if candidate_trace_id is None:
            candidate_trace_id = transition.trace_id
        elif transition.trace_id != candidate_trace_id:
            raise FormalTraceError("trace_id changed within a trace")
        if transition.step != self._step + 1:
            raise FormalTraceError("transition step is skipped, duplicated, or reordered")

        self._compare_projection(transition, self._state, suffix="before")
        candidate_state = deepcopy(self._state)
        deltas = self._apply(transition, candidate_state)
        self._check_invariants(candidate_state)
        self._compare_projection(transition, candidate_state, suffix="after")
        for field, expected in deltas.items():
            actual = getattr(transition, field)
            if actual != expected:
                raise FormalTraceError(
                    f"step {transition.step}: {field} is {actual}, expected {expected}"
                )
        # Commit the reconstructed state and cursor only after every guard,
        # invariant, projection, and delta has been validated.
        self._state = candidate_state
        self._trace_id = candidate_trace_id
        self._step = transition.step

    def _compare_projection(
        self, transition: AbstractTransitionV1, state: _ModelState, *, suffix: str
    ) -> None:
        domain = transition.domain_slot
        values: dict[str, object] = {
            f"epoch_{suffix}": state.epoch[domain],
            f"epoch_spent_{suffix}": tuple(state.epoch_spent[domain]),
            f"attempts_{suffix}": state.attempts[domain],
            f"horizon_{suffix}": state.horizon[domain],
            f"lifetime_spent_{suffix}": state.spent[domain],
            f"lifetime_budget_{suffix}": state.budget[domain],
            f"visible_events_{suffix}": state.visible[domain],
            f"closed_{suffix}": state.closed[domain],
            f"authorization_version_{suffix}": state.authorization_version,
        }
        for field, expected in values.items():
            if getattr(transition, field) != expected:
                raise FormalTraceError(
                    f"step {transition.step}: {field} does not match reconstructed state"
                )

    def _gate_domain(self, gate: int) -> int:
        scope = self.manifest.gates[gate][1]
        return self.manifest.scopes[scope][0]

    def _gate_epoch(self, gate: int) -> int:
        scope = self.manifest.gates[gate][1]
        return self.manifest.scopes[scope][3]

    def _reserved_successor(self, gate: int) -> bool:
        return any(gate in record[2] for record in self.manifest.gates)

    def _successor_authorized(self, state: _ModelState, gate: int) -> bool:
        scope = self.manifest.gates[gate][1]
        predecessor = state.last_gate.get(scope)
        if self._reserved_successor(gate):
            return (
                predecessor is not None
                and gate in self.manifest.gates[predecessor][2]
                and self.manifest.gates[predecessor][1] == scope
            )
        return predecessor is None

    def _can_reserve(self, state: _ModelState, domain: int) -> bool:
        q = self.manifest.event_charge_units
        return (
            not state.closed[domain]
            and state.attempts[domain] < state.horizon[domain]
            and state.spent[domain] + q <= state.budget[domain]
        )

    def _reserve(self, state: _ModelState, domain: int, *, count: int = 1) -> None:
        q = self.manifest.event_charge_units
        state.attempts[domain] += count
        state.spent[domain] += count * q
        state.epoch_spent[domain][state.epoch[domain]] += count * q

    @staticmethod
    def _require_slots(
        transition: AbstractTransitionV1,
        *,
        required: Iterable[str],
        optional: Iterable[str] = (),
    ) -> None:
        slot_fields = {
            "scope_slot",
            "gate_slot",
            "agent_slot",
            "nonce_slot",
            "delegation_slot",
            "reauth_grant_slot",
            "capability_slot",
            "redeemer_slot",
            "predecessor_gate_slot",
        }
        required_set = set(required)
        optional_set = set(optional)
        for field in slot_fields:
            value = getattr(transition, field)
            if field in required_set and value is None:
                raise FormalTraceError(f"step {transition.step}: {field} is required")
            if field not in required_set | optional_set and value is not None:
                raise FormalTraceError(f"step {transition.step}: {field} must be null")

    def _validate_gate_slots(
        self, transition: AbstractTransitionV1, state: _ModelState
    ) -> tuple[int, int]:
        gate = transition.gate_slot
        scope = transition.scope_slot
        assert gate is not None and scope is not None
        if self.manifest.gates[gate][1] != scope:
            raise FormalTraceError(f"step {transition.step}: gate scope mismatch")
        domain = self._gate_domain(gate)
        if transition.domain_slot != domain:
            raise FormalTraceError(f"step {transition.step}: gate domain mismatch")
        predecessor = state.last_gate.get(scope)
        if transition.predecessor_gate_slot != predecessor:
            raise FormalTraceError(f"step {transition.step}: predecessor projection mismatch")
        return gate, domain

    def _apply(self, transition: AbstractTransitionV1, state: _ModelState) -> dict[str, int]:
        action = transition.action
        delta = {
            "gate_claim_delta": 0,
            "nonce_use_delta": 0,
            "delegation_use_delta": 0,
            "reauth_use_delta": 0,
            "capability_use_delta": 0,
            "audit_start_delta": 0,
            "padding_event_delta": 0,
        }
        commit_actions = {"commit_direct", "commit_delegated", "commit_effect"}
        reject_actions = {
            "reject_scoped_direct",
            "reject_scoped_delegated",
            "reject_capability_binding",
            "reject_stale_epoch",
        }

        if action in commit_actions | reject_actions:
            required = {"scope_slot", "gate_slot", "agent_slot", "nonce_slot"}
            if action in {"commit_delegated", "reject_scoped_delegated"}:
                required.add("delegation_slot")
            if action in {"commit_effect", "reject_capability_binding"}:
                required.update({"capability_slot", "redeemer_slot"})
            self._require_slots(
                transition,
                required=required,
                optional={"predecessor_gate_slot"},
            )
            gate, domain = self._validate_gate_slots(transition, state)
            agent = transition.agent_slot
            nonce = transition.nonce_slot
            assert agent is not None and nonce is not None
            replay_key = (agent, nonce)
            if not self._can_reserve(state, domain):
                raise FormalTraceError(f"step {transition.step}: claim cannot reserve")
            gate_fresh = gate not in state.gate_claims
            nonce_fresh = replay_key not in state.nonce_uses
            current_epoch = self._gate_epoch(gate) == state.epoch[domain]
            successor_ok = self._successor_authorized(state, gate)
            needs_capability = self.manifest.gates[gate][3]

            if action == "commit_direct":
                if transition.outcome != "reserved" or not (
                    gate_fresh and nonce_fresh and current_epoch and successor_ok and not needs_capability
                ):
                    raise FormalTraceError(f"step {transition.step}: invalid CommitDirect guard")
                weight = 2
            elif action == "commit_delegated":
                delegation = transition.delegation_slot
                assert delegation is not None
                binding = self.manifest.delegations[delegation]
                if transition.outcome != "reserved" or not (
                    gate_fresh
                    and nonce_fresh
                    and current_epoch
                    and successor_ok
                    and not needs_capability
                    and delegation not in state.delegation_uses
                    and binding[1] == agent
                    and binding[2] == gate
                ):
                    raise FormalTraceError(f"step {transition.step}: invalid CommitDelegated guard")
                weight = 3
            elif action == "commit_effect":
                capability = transition.capability_slot
                redeemer = transition.redeemer_slot
                assert capability is not None and redeemer is not None
                binding = self.manifest.capabilities[capability]
                if transition.outcome != "reserved" or not (
                    gate_fresh
                    and nonce_fresh
                    and current_epoch
                    and successor_ok
                    and needs_capability
                    and capability not in state.capability_uses
                    and binding[1] == gate
                    and binding[2] == redeemer
                ):
                    raise FormalTraceError(f"step {transition.step}: invalid CommitEffect guard")
                weight = 3
            else:
                weight = 0
                if action == "reject_scoped_direct":
                    valid = (
                        current_epoch
                        and gate_fresh
                        and nonce_fresh
                        and not needs_capability
                        and not successor_ok
                        and transition.outcome == "route_denied"
                    )
                elif action == "reject_scoped_delegated":
                    delegation = transition.delegation_slot
                    assert delegation is not None
                    binding = self.manifest.delegations[delegation]
                    valid = (
                        current_epoch
                        and gate_fresh
                        and nonce_fresh
                        and delegation not in state.delegation_uses
                        and binding[1] == agent
                        and binding[2] == gate
                        and not needs_capability
                        and not successor_ok
                        and transition.outcome == "route_denied"
                    )
                elif action == "reject_capability_binding":
                    capability = transition.capability_slot
                    redeemer = transition.redeemer_slot
                    assert capability is not None and redeemer is not None
                    binding = self.manifest.capabilities[capability]
                    valid = (
                        current_epoch
                        and gate_fresh
                        and nonce_fresh
                        and needs_capability
                        and successor_ok
                        and capability not in state.capability_uses
                        and (binding[1] != gate or binding[2] != redeemer)
                        and transition.outcome == "capability_denied"
                    )
                else:
                    valid = (
                        gate_fresh
                        and nonce_fresh
                        and not current_epoch
                        and transition.outcome == "auth_denied"
                    )
                if not valid:
                    raise FormalTraceError(f"step {transition.step}: invalid {action} guard")

            self._reserve(state, domain)
            if action in reject_actions:
                state.visible[domain] += 1
                return delta

            predecessor = state.last_gate.get(transition.scope_slot)  # type: ignore[arg-type]
            state.gate_claims.add(gate)
            state.nonce_uses.add(replay_key)
            state.nonce_claim_gate[replay_key] = gate
            state.gate_predecessor[gate] = predecessor
            state.pending.add(gate)
            state.audit_starts.add(gate)
            state.last_gate[transition.scope_slot] = gate  # type: ignore[index]
            state.authorization_version += weight
            state.claim_weight[gate] = weight
            delta.update(
                gate_claim_delta=1,
                nonce_use_delta=1,
                audit_start_delta=1,
            )
            if action == "commit_delegated":
                delegation = transition.delegation_slot
                assert delegation is not None
                state.delegation_uses.add(delegation)
                state.delegation_claim_gate[delegation] = gate
                delta["delegation_use_delta"] = 1
            if action == "commit_effect":
                capability = transition.capability_slot
                redeemer = transition.redeemer_slot
                assert capability is not None and redeemer is not None
                state.capability_uses.add(capability)
                state.capability_claim[capability] = (gate, redeemer)
                delta["capability_use_delta"] = 1
            return delta

        if action == "finalize":
            self._require_slots(transition, required={"gate_slot"})
            gate = transition.gate_slot
            assert gate is not None
            domain = self._gate_domain(gate)
            if transition.domain_slot != domain or gate not in state.pending:
                raise FormalTraceError(f"step {transition.step}: no matching pending gate")
            if transition.outcome not in {"released", "output_denied", "internal_denied"}:
                raise FormalTraceError(f"step {transition.step}: invalid finalization outcome")
            state.pending.remove(gate)
            state.finalized.add(gate)
            state.visible[domain] += 1
            return delta

        if action == "continue":
            self._require_slots(transition, required=set())
            domain = transition.domain_slot
            if transition.outcome != "continued" or not self._can_reserve(state, domain):
                raise FormalTraceError(f"step {transition.step}: invalid Continue guard")
            self._reserve(state, domain)
            state.visible[domain] += 1
            return delta

        if action in {"reauthorize", "reject_reauthorization"}:
            self._require_slots(transition, required={"reauth_grant_slot"})
            domain = transition.domain_slot
            grant = transition.reauth_grant_slot
            assert grant is not None
            if self.manifest.reauth_grants[grant][1] != domain or not self._can_reserve(state, domain):
                raise FormalTraceError(f"step {transition.step}: invalid reauthorization scope/reservation")
            if action == "reauthorize":
                valid = (
                    transition.outcome == "reauthorized"
                    and grant not in state.reauth_uses
                    and state.epoch[domain] < self.manifest.max_epoch
                )
            else:
                valid = transition.outcome == "reauth_denied" and grant in state.reauth_uses
            if not valid:
                raise FormalTraceError(f"step {transition.step}: invalid {action} guard")
            self._reserve(state, domain)
            state.visible[domain] += 1
            if action == "reauthorize":
                state.reauth_uses.add(grant)
                state.budget[domain] += self.manifest.reauth_budget_increment_units
                state.horizon[domain] += self.manifest.reauth_attempt_increment
                state.epoch[domain] += 1
                state.authorization_version += 1
                delta["reauth_use_delta"] = 1
            return delta

        if action == "stop_and_pad":
            self._require_slots(transition, required=set())
            domain = transition.domain_slot
            remaining = state.horizon[domain] - state.attempts[domain]
            pending = any(self._gate_domain(gate) == domain for gate in state.pending)
            if (
                transition.outcome != "stopped"
                or remaining <= 0
                or pending
                or not self._can_reserve(state, domain)
                or state.spent[domain] + remaining * self.manifest.event_charge_units
                > state.budget[domain]
            ):
                raise FormalTraceError(f"step {transition.step}: invalid StopAndPad guard")
            self._reserve(state, domain, count=remaining)
            state.visible[domain] += remaining
            state.padding_events[domain] += remaining - 1
            state.closed[domain] = True
            delta["padding_event_delta"] = remaining - 1
            return delta

        if action == "close_at_horizon":
            self._require_slots(transition, required=set())
            domain = transition.domain_slot
            pending = any(self._gate_domain(gate) == domain for gate in state.pending)
            if (
                transition.outcome != "domain_closed"
                or state.closed[domain]
                or state.attempts[domain] != state.horizon[domain]
                or pending
            ):
                raise FormalTraceError(f"step {transition.step}: invalid CloseAtHorizon guard")
            state.closed[domain] = True
            return delta

        if action == "closed_reply_stutter":
            self._require_slots(transition, required=set())
            if transition.outcome != "domain_closed" or not state.closed[transition.domain_slot]:
                raise FormalTraceError(f"step {transition.step}: invalid closed stutter")
            return delta

        raise FormalTraceError(f"step {transition.step}: unimplemented action")

    def _check_invariants(self, state: _ModelState) -> None:
        m = self.manifest
        for domain in range(len(m.domains)):
            if state.spent[domain] > state.budget[domain]:
                raise FormalTraceError("NoBudgetOverspend violated")
            if state.attempts[domain] > state.horizon[domain]:
                raise FormalTraceError("AttemptHorizonRespected violated")
            if state.spent[domain] != state.attempts[domain] * m.event_charge_units:
                raise FormalTraceError("fixed attempt charging violated")
            if sum(state.epoch_spent[domain]) != state.spent[domain]:
                raise FormalTraceError("LifetimeBudgetComposition epoch sum violated")
            used_reauth = sum(
                1
                for grant in state.reauth_uses
                if m.reauth_grants[grant][1] == domain
            )
            if state.budget[domain] != m.initial_budget_units + used_reauth * m.reauth_budget_increment_units:
                raise FormalTraceError("LifetimeBudgetComposition budget violated")
            if state.horizon[domain] != m.initial_horizon + used_reauth * m.reauth_attempt_increment:
                raise FormalTraceError("LifetimeBudgetComposition horizon violated")
            if not 0 <= state.epoch[domain] <= m.max_epoch:
                raise FormalTraceError("EpochMonotonicity violated")
            pending_count = sum(1 for gate in state.pending if self._gate_domain(gate) == domain)
            if state.visible[domain] != state.attempts[domain] - pending_count:
                raise FormalTraceError("complete public-event accounting violated")
            if state.closed[domain] and (
                state.attempts[domain] != state.horizon[domain] or pending_count
            ):
                raise FormalTraceError("closed-domain completeness violated")

        if not (state.pending | state.finalized) == state.gate_claims:
            raise FormalTraceError("atomic gate claim state violated")
        if state.pending & state.finalized:
            raise FormalTraceError("gate cannot be pending and finalized")
        if state.audit_starts != state.gate_claims:
            raise FormalTraceError("AuditStartExistsForEveryCommittedClaim violated")
        if set(state.nonce_claim_gate.values()) != state.gate_claims:
            raise FormalTraceError("AuthorizationConsumedOnlyWithSuccessfulClaim violated")
        if set(state.nonce_claim_gate) != state.nonce_uses:
            raise FormalTraceError("nonce claim linkage violated")
        for delegation, gate in state.delegation_claim_gate.items():
            if delegation not in state.delegation_uses or gate not in state.gate_claims:
                raise FormalTraceError("delegation claim linkage violated")
        for capability, (gate, redeemer) in state.capability_claim.items():
            binding = m.capabilities[capability]
            if (
                capability not in state.capability_uses
                or gate not in state.gate_claims
                or binding[1:] != (gate, redeemer)
            ):
                raise FormalTraceError("RedeemerBindingPreserved violated")
        for gate, predecessor in state.gate_predecessor.items():
            if predecessor is not None and (
                gate not in m.gates[predecessor][2]
                or m.gates[gate][1] != m.gates[predecessor][1]
            ):
                raise FormalTraceError("NoCrossDomainSuccessorAuthorization violated")
        expected_version = sum(state.claim_weight.values()) + len(state.reauth_uses)
        if state.authorization_version != expected_version:
            raise FormalTraceError("authorization-version composition violated")


def check_trace(manifest_line: bytes, trace: bytes) -> TraceCheckReport:
    """Parse a canonical manifest and check a complete canonical JSONL trace."""

    return FormalTraceChecker(FormalManifest.from_bytes(manifest_line)).check_bytes(trace)


__all__ = [
    "AbstractTransitionV1",
    "FormalManifest",
    "FormalTraceChecker",
    "FormalTraceError",
    "TraceCheckReport",
    "canonical_json_line",
    "check_trace",
]
