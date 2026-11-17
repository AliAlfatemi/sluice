#!/usr/bin/env python3
"""Derived effect charging and per-effect one-time gates for the Sluice condition.

This module replaces two pieces of the S1 harness:

``EffectAuthority``  (fixed charge, one durable route per TOOL)
    -> ``DerivedEffectAuthority``  (charge derived from and verified against the
       real domain; one durable route, one distinct public value code, and one
       one-time capability per EXACT EFFECT)

``DurableGrantRedeemer``  (redeems, discards the transcript event)
    -> ``CrossBindingRedeemer``  (redeems, then cross-binds the authorized
       charge, the observed charge, the tool, the canonical arguments, the
       released value code, the result and the broker audit record; any
       mismatch is a closed failure, not a silent pass)

WHAT WAS WRONG, precisely
-------------------------

1.  CHARGE.  ``DomainConfig(event_charge_units=4)`` was a literal.  The sealed
    domain refuses any charge below its own ObserverSpec support bound, and that
    bound grows with the number of routes, so a fixed 4 errored every arm whose
    compiled policy needed three or more distinct effect tools -- 3 + 5 + 3 + 3
    real arms across four S1 shards.  S1's repair re-derived the bound by
    transcribing the formula out of ``durable_secure.py`` into the harness.  A
    transcription is not a derivation: nothing detects it drifting from the
    implementation it copies.  Here the candidate is computed, the REAL domain
    is then asked to seal at that charge, an escalation loop converges if the
    implementation ever disagrees, the sealed value is read back out of the
    domain's own metadata, and every subsequent event's charge is compared
    against what the domain actually charged.

2.  GATE SCOPE.  Routes were registered per TOOL
    (``{tool: register_route(name=tool, ...)}``) with the single public value
    ``{1}`` on every route, so two authorized effects on the same tool shared
    one durable gate, and EVERY released effect in an episode produced the
    identical transcript event ``value_code=1``.  At the durable layer the
    trust was therefore episode-scoped: the transcript could not say which of
    the authorized effects had been released, and nothing bound a released
    event to the specific arguments it was authorized for.  Here each template
    gets its own route and its own value code, so a released event names the
    exact effect, and the effect handler derives that code FROM THE PAYLOAD it
    is actually handed -- an unrecognised payload yields a code outside the
    route's alphabet and the domain fails it closed as ``OUTPUT_DENIED``.

WHAT WAS DELIBERATELY NOT CHANGED, and why
------------------------------------------

``expires_at_lifetime_attempt`` stays at the episode horizon for every
capability.  It is tempting to expire capability *i* at attempt *i*, but the
durable attempt counter is global and the agent may legitimately invoke the
third authorized effect first, so per-ordinal expiry would deny correct
behaviour.  ``test_effect_charging.py`` pins that with an out-of-order
redemption case.  The one-time property comes from the capability being
consumed (``UPDATE capabilities SET consumed_attempt=...``), from the credential
replay table, and from the broker's own template retirement -- not from expiry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any, Mapping

LEDGER_SCHEMA = "sluice-agentdojo-effect-charge-ledger-v1"
EFFECT_PROTECTED_OBJECT = "agentdojo-effect"
EFFECT_AGENT_ID = "sluice-agentdojo-agent"

# The durable domain's own bound, restated here as a CANDIDATE only.  It is
# never trusted: `DerivedEffectAuthority` asks the real domain to seal at the
# value this returns and escalates if the domain disagrees, and
# `test_effect_charging.py` proves both that it seals and that one unit less is
# refused, for every route count the benchmark actually produces.
def derive_event_charge_units(
    *, route_value_counts: "tuple[int, ...]", units_per_bit: int, floor: int = 4
) -> int:
    """Candidate per-event charge for a domain with these route alphabets."""

    if units_per_bit < 1:
        raise ValueError("units_per_bit must be positive")
    if not route_value_counts or any(count < 1 for count in route_value_counts):
        raise ValueError("every route needs a nonempty public alphabet")
    support = 4 + sum(count + 5 for count in route_value_counts)
    bits = (support - 1).bit_length()
    return max(floor, bits * units_per_bit)


class CrossBindingError(RuntimeError):
    """An authorized effect and its observed durable event disagree."""


class _Unobserved:
    """Marker for a result the binding seam genuinely could not see."""

    def __repr__(self) -> str:
        return "<result-not-observed-at-this-seam>"


_UNOBSERVED = _Unobserved()


def payload_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        b"sluice-agentdojo-singleton-grant-payload-v1"
        + b"\0"
        + json.dumps(
            dict(payload), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _result_digest(value: Any) -> str:
    try:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True, default=repr)
    except BaseException:  # noqa: BLE001
        text = repr(value)
    return hashlib.sha256(
        b"sluice-agentdojo-effect-result-v1\0" + text.encode("utf-8", "surrogatepass")
    ).hexdigest()


@dataclass(frozen=True)
class AuthorizedEffect:
    """Everything the policy authorised about ONE exact effect, before any run."""

    ordinal: int
    template_id: str
    tool: str
    exact_args: str
    exact_args_sha256: str
    route_name: str
    value_code: int
    authorized_charge_units: int
    payload_sha256: str
    workflow_id: str
    episode_id: str

    def wire(self) -> "dict[str, Any]":
        return {
            "ordinal": self.ordinal,
            "template_id": self.template_id,
            "tool": self.tool,
            "exact_args_sha256": self.exact_args_sha256,
            "route_name": self.route_name,
            "value_code": self.value_code,
            "authorized_charge_units": self.authorized_charge_units,
            "payload_sha256": self.payload_sha256,
            "workflow_id": self.workflow_id,
            "episode_id": self.episode_id,
        }


@dataclass(frozen=True)
class ObservedEffect:
    """Everything the DOMAIN actually did for one redemption."""

    template_id: str
    attempt: int
    outcome: str
    value_code: "int | None"
    charge_units: int
    payload_sha256: str
    spent_units_after: int

    def wire(self) -> "dict[str, Any]":
        return dict(self.__dict__)


@dataclass
class ExecutedEffect:
    """What the BROKER did with the authorisation, after the domain released it."""

    template_id: str
    tool: str
    canonical_args: str
    result_sha256: str
    audit_sequence: int
    audit_outcome: str
    audit_args_sha256: str
    source: str = "broker_wrapper"


class EffectChargeLedger:
    """Create-once, cross-binding record of authorization -> event -> execution.

    Every method fails CLOSED: an inconsistency raises ``CrossBindingError``
    rather than returning a soft value, and the caller turns that into an
    authorization ERROR.
    """

    def __init__(self, *, workflow_id: str, episode_id: str, domain_charge_units: int):
        self.workflow_id = workflow_id
        self.episode_id = episode_id
        self.domain_charge_units = int(domain_charge_units)
        self._authorized: dict[str, AuthorizedEffect] = {}
        self._by_value_code: dict[int, str] = {}
        self._by_payload: dict[str, str] = {}
        self._observed: dict[str, ObservedEffect] = {}
        self._executed: dict[str, ExecutedEffect] = {}
        self._violations: list[str] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------ authorize
    def authorize(self, effect: AuthorizedEffect) -> None:
        with self._lock:
            if effect.template_id in self._authorized:
                raise CrossBindingError("template authorised twice")
            if effect.value_code in self._by_value_code:
                raise CrossBindingError("value code is not unique to one effect")
            if effect.payload_sha256 in self._by_payload:
                raise CrossBindingError("two effects share one payload digest")
            if effect.workflow_id != self.workflow_id:
                raise CrossBindingError("effect workflow does not match the ledger")
            if effect.episode_id != self.episode_id:
                raise CrossBindingError("effect episode does not match the ledger")
            if effect.authorized_charge_units != self.domain_charge_units:
                raise CrossBindingError(
                    "authorised charge differs from the sealed domain charge"
                )
            if hashlib.sha256(
                effect.exact_args.encode("utf-8")
            ).hexdigest() != effect.exact_args_sha256:
                raise CrossBindingError("authorised argument digest mismatch")
            self._authorized[effect.template_id] = effect
            self._by_value_code[effect.value_code] = effect.template_id
            self._by_payload[effect.payload_sha256] = effect.template_id

    def value_code_for_payload_digest(self, digest: str) -> "int | None":
        """The handler's own derivation: payload -> exactly one value code."""
        template_id = self._by_payload.get(digest)
        if template_id is None:
            return None
        return self._authorized[template_id].value_code

    @property
    def authorized(self) -> "tuple[AuthorizedEffect, ...]":
        return tuple(
            self._authorized[key]
            for key in sorted(self._authorized, key=lambda k: self._authorized[k].ordinal)
        )

    # -------------------------------------------------------------- observe
    def observe(
        self,
        *,
        template_id: str,
        payload: Mapping[str, Any],
        event: Any,
        released: bool,
        spent_units_after: int,
        domain_charge_units: int,
    ) -> ObservedEffect:
        with self._lock:
            effect = self._authorized.get(template_id)
            if effect is None:
                raise CrossBindingError("redeemed a template that was never authorised")
            if template_id in self._observed:
                raise CrossBindingError("template redeemed twice")
            supplied = payload_digest(payload)
            if supplied != effect.payload_sha256:
                raise CrossBindingError("redeemed payload is not the authorised payload")
            charge = getattr(event, "charge_units", None)
            if type(charge) is not int:
                raise CrossBindingError("durable event carries no integer charge")
            if charge != effect.authorized_charge_units:
                raise CrossBindingError(
                    f"observed charge {charge} != authorised charge "
                    f"{effect.authorized_charge_units}"
                )
            if charge != domain_charge_units:
                raise CrossBindingError(
                    "observed charge differs from the domain's own sealed charge"
                )
            value_code = getattr(event, "value_code", None)
            if released:
                if value_code != effect.value_code:
                    raise CrossBindingError(
                        f"released value code {value_code!r} does not name the "
                        f"authorised effect {effect.template_id!r} "
                        f"(expected {effect.value_code})"
                    )
            elif value_code is not None:
                raise CrossBindingError("a non-released event carries a value code")
            attempt = getattr(event, "attempt", None)
            if type(attempt) is not int or attempt < 1:
                raise CrossBindingError("durable event carries no attempt ordinal")
            expected_spend = charge * (len(self._observed) + 1)
            if spent_units_after != expected_spend:
                raise CrossBindingError(
                    f"domain spent {spent_units_after} units after "
                    f"{len(self._observed) + 1} redemptions; expected {expected_spend}"
                )
            observed = ObservedEffect(
                template_id=template_id,
                attempt=attempt,
                outcome=str(getattr(getattr(event, "outcome", None), "value", "")),
                value_code=value_code,
                charge_units=charge,
                payload_sha256=supplied,
                spent_units_after=spent_units_after,
            )
            self._observed[template_id] = observed
            return observed

    # ------------------------------------------------------------- execute
    def bind_execution(
        self,
        *,
        template_id: str,
        tool: str,
        canonical_args: str,
        result: Any,
        audit_record: Any,
        source: str = "broker_wrapper",
    ) -> None:
        with self._lock:
            effect = self._authorized.get(template_id)
            if effect is None:
                raise CrossBindingError("execution for an unauthorised template")
            # Identity mismatches are reported BEFORE state mismatches, so a
            # wrong-tool or wrong-argument binding is named as such whatever
            # order the caller happens to be in.
            if tool != effect.tool:
                raise CrossBindingError(
                    f"executed tool {tool!r} != authorised tool {effect.tool!r}"
                )
            if canonical_args != effect.exact_args:
                raise CrossBindingError(
                    "executed arguments are not the authorised exact arguments"
                )
            if template_id not in self._observed:
                raise CrossBindingError("execution before the durable event")
            if template_id in self._executed:
                raise CrossBindingError("execution recorded twice")
            sequence = getattr(audit_record, "sequence", None)
            outcome = str(getattr(getattr(audit_record, "outcome", None), "value", ""))
            args_sha = getattr(audit_record, "args_sha256", None)
            record_template = getattr(audit_record, "template_id", None)
            if record_template != template_id:
                raise CrossBindingError("audit record names a different template")
            if type(sequence) is not int or sequence < 1:
                raise CrossBindingError("audit record has no sequence")
            if not getattr(audit_record, "authorized", False):
                raise CrossBindingError("audit record is not marked authorized")
            expected_args_sha = hashlib.sha256(
                effect.exact_args.encode("utf-8")
            ).hexdigest()
            if str(args_sha) != expected_args_sha:
                raise CrossBindingError(
                    "the broker's own argument digest is not the digest of the "
                    "authorised exact arguments"
                )
            self._executed[template_id] = ExecutedEffect(
                template_id=template_id,
                tool=tool,
                canonical_args=canonical_args,
                result_sha256=_result_digest(result),
                audit_sequence=sequence,
                audit_outcome=outcome,
                audit_args_sha256=str(args_sha),
                source=source,
            )

    def reconcile_from_broker(self, broker: Any, manifest: Any) -> "list[str]":
        """Bind every EXECUTED_EFFECT the broker recorded, from the audit log.

        The broker's audit log is digest-only by design, so this seam cannot
        supply the tool RESULT -- only ``bind_execution`` from a wrapper that
        holds the result can.  What it can do, and does, is bind the audit
        record to the authorised template by the broker's OWN argument digest:
        ``BrokerAuditRecord.args_sha256`` is ``sha256(canonical_args(args))`` and
        ``CallTemplate.args_sha256`` is ``sha256(exact_args)`` over the identical
        canonical text, so the two must be equal for the authorised effect.
        """

        problems: list[str] = []
        templates = {
            template.template_id: template for template in manifest.templates
        }
        for record in getattr(broker, "audit_log", ()):
            if getattr(record.outcome, "value", "") != "executed_effect":
                continue
            template = templates.get(record.template_id)
            if template is None:
                problems.append(
                    f"broker executed {record.template_id!r}, which is not a template"
                )
                continue
            if record.template_id in self._executed:
                continue
            try:
                self.bind_execution(
                    template_id=template.template_id,
                    tool=template.tool,
                    canonical_args=template.exact_args,
                    result=_UNOBSERVED,
                    audit_record=record,
                    source="audit_log",
                )
            except CrossBindingError as exc:
                problems.append(f"{record.template_id}: {exc}")
        return problems

    # -------------------------------------------------------------- verify
    def verify(
        self, *, broker: Any = None, domain: Any = None, manifest: Any = None
    ) -> "dict[str, Any]":
        """Whole-episode consistency check.  Returns a report; never a bare bool."""

        problems: list[str] = []
        if broker is not None and manifest is not None:
            problems.extend(self.reconcile_from_broker(broker, manifest))
        released = {
            key for key, observed in self._observed.items()
            if observed.outcome == "released"
        }
        if not set(self._executed).issubset(released):
            problems.append("an effect executed without a released durable event")
        for template_id, observed in self._observed.items():
            effect = self._authorized[template_id]
            if observed.charge_units != effect.authorized_charge_units:
                problems.append(f"{template_id}: charge drifted")
            if observed.outcome == "released" and observed.value_code != effect.value_code:
                problems.append(f"{template_id}: value code drifted")
        attempts = sorted(observed.attempt for observed in self._observed.values())
        if attempts != sorted(set(attempts)):
            problems.append("two effects claim the same durable attempt")
        total_charged = sum(o.charge_units for o in self._observed.values())
        if self._observed and total_charged != self.domain_charge_units * len(
            self._observed
        ):
            problems.append("total charged units are not the sum of per-event charges")

        if domain is not None:
            try:
                spent = int(getattr(domain, "lifetime_spent_units"))
            except BaseException:  # noqa: BLE001
                spent = None
            if spent is not None and spent != total_charged:
                problems.append(
                    f"domain spent {spent} units; ledger accounts for {total_charged}"
                )

        if broker is not None:
            executed_records = [
                record for record in broker.audit_log
                if getattr(record.outcome, "value", "") == "executed_effect"
            ]
            if len(executed_records) != len(self._executed):
                problems.append(
                    f"broker executed {len(executed_records)} effects; ledger bound "
                    f"{len(self._executed)}"
                )
            for record in executed_records:
                if record.template_id not in self._executed:
                    problems.append(
                        f"broker executed template {record.template_id!r} with no "
                        "ledger binding"
                    )
                elif (
                    self._executed[record.template_id].audit_sequence != record.sequence
                ):
                    problems.append(f"{record.template_id}: audit sequence drifted")
            consumed = getattr(broker, "consumed_effect_count", None)
            if type(consumed) is int and consumed != len(self._observed):
                problems.append(
                    f"broker consumed {consumed} templates; the domain saw "
                    f"{len(self._observed)} redemptions"
                )

        problems.extend(self._violations)
        return {
            "schema": LEDGER_SCHEMA,
            "workflow_id": self.workflow_id,
            "episode_id": self.episode_id,
            "domain_charge_units": self.domain_charge_units,
            "authorized": [effect.wire() for effect in self.authorized],
            "observed": [
                self._observed[key].wire() for key in sorted(self._observed)
            ],
            "executed": [
                dict(self._executed[key].__dict__) for key in sorted(self._executed)
            ],
            "authorized_count": len(self._authorized),
            "observed_count": len(self._observed),
            "executed_count": len(self._executed),
            "total_charged_units": total_charged,
            "consistent": not problems,
            "problems": problems,
        }

    def record_violation(self, message: str) -> None:
        with self._lock:
            self._violations.append(message)


class CrossBindingRedeemer:
    """``DurableGrantRedeemer`` plus the cross-binding the ledger requires.

    Identical in its authorisation semantics -- identity-check the grant,
    compare payload digests, retire locally before the ambiguous step, then ask
    the real ``DurableSecureDomain`` -- and additionally refuses to report
    RELEASED unless the durable event the domain produced actually names this
    exact effect at this exact charge.
    """

    __slots__ = ("_domain", "_grant_by_id", "_consumed", "_lock", "_ledger", "_charge")

    def __init__(self, domain: Any, grants: tuple, ledger: EffectChargeLedger):
        self._domain = domain
        self._grant_by_id = {grant.template_id: grant for grant in grants}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()
        self._ledger = ledger
        self._charge = int(domain.event_charge_units)

    @property
    def ledger(self) -> EffectChargeLedger:
        return self._ledger

    def redeem(self, grant: Any, payload: Any) -> Any:
        from sluice_v2.evaluation.agentdojo import AuthorizationOutcome
        from sluice_v2.observer import EventKind, OutcomeCode, TranscriptEvent

        if type(payload) is not dict:
            return AuthorizationOutcome.ERROR
        expected = self._grant_by_id.get(getattr(grant, "template_id", None))
        if expected is None or grant is not expected:
            return AuthorizationOutcome.ERROR
        try:
            if payload_digest(dict(payload)) != payload_digest(expected.payload()):
                return AuthorizationOutcome.ERROR
        except BaseException:  # noqa: BLE001
            return AuthorizationOutcome.ERROR
        with self._lock:
            if grant.template_id in self._consumed:
                return AuthorizationOutcome.ERROR
            self._consumed.add(grant.template_id)
        try:
            event = self._domain.attempt(
                grant.route,
                grant.payload(),
                credential=grant.credential,
                capability=grant.capability,
                redeemer_id=grant.redeemer_id,
            )
        except BaseException:  # noqa: BLE001
            return AuthorizationOutcome.ERROR
        if type(event) is not TranscriptEvent or event.kind is not EventKind.ATTEMPT:
            return AuthorizationOutcome.ERROR
        released = event.outcome is OutcomeCode.RELEASED
        try:
            spent = int(self._domain.lifetime_spent_units)
        except BaseException:  # noqa: BLE001
            return AuthorizationOutcome.ERROR
        try:
            self._ledger.observe(
                template_id=grant.template_id,
                payload=grant.payload(),
                event=event,
                released=released,
                spent_units_after=spent,
                domain_charge_units=self._charge,
            )
        except CrossBindingError as exc:
            # A released event that does not bind to its authorisation is worse
            # than a denial: it is an unaccounted effect.  Fail closed and keep
            # the reason.
            self._ledger.record_violation(f"{grant.template_id}: {exc}")
            return AuthorizationOutcome.ERROR
        return (
            AuthorizationOutcome.RELEASED if released else AuthorizationOutcome.DENIED
        )


class DerivedEffectAuthority:
    """A real durable domain with one exact one-time gate per expected effect."""

    MAX_CHARGE_ESCALATIONS = 8

    def __init__(self, *, foundation: Any, manifest: Any, scratch: Path):
        from sluice_v2.durable_secure import (
            DurableSecureDomain,
            EffectResult,
            IdempotentEffectHandler,
            ObserverSpec,
            RouteCodebook,
        )
        from sluice_v2.secure import DomainConfig

        templates = tuple(manifest.templates)
        if not templates:
            raise ValueError("effect authority requires at least one template")
        count = len(templates)
        units_per_bit = 1

        # ---- one route, one public value code, one gate per EXACT effect ----
        route_names = [template.template_id for template in templates]
        if len(set(route_names)) != count:
            raise ValueError("template ids are not unique")
        value_codes = {
            template.template_id: index + 1
            for index, template in enumerate(templates)
        }
        permitted = frozenset(value_codes.values())

        self.charge_escalations: list[int] = []
        candidate = derive_event_charge_units(
            route_value_counts=tuple(1 for _ in templates),
            units_per_bit=units_per_bit,
        )

        ledger_holder: dict[str, EffectChargeLedger] = {}

        def _execute(request):
            ledger = ledger_holder.get("ledger")
            if ledger is None:
                # Unreachable in normal use; an out-of-alphabet code fails closed.
                return EffectResult.for_request(request, -1)
            code = ledger.value_code_for_payload_digest(
                payload_digest(request.payload)
                if isinstance(request.payload, Mapping)
                else payload_digest({"opaque": repr(request.payload)})
            )
            # An unrecognised payload gets a code outside every route alphabet,
            # so the domain itself answers OUTPUT_DENIED.
            return EffectResult.for_request(request, code if code is not None else -1)

        key = secrets.token_bytes(32)
        path = scratch / f"effects-{secrets.token_hex(8)}.sqlite"
        domain = None
        last_error: BaseException | None = None
        for attempt in range(self.MAX_CHARGE_ESCALATIONS):
            charge = candidate
            attempt_path = Path(f"{path}.{attempt}") if attempt else path
            try:
                domain = DurableSecureDomain.create(
                    attempt_path,
                    config=DomainConfig(
                        domain_id="sluice-agentdojo-effects",
                        protected_objects=frozenset({EFFECT_PROTECTED_OBJECT}),
                        lifetime_budget_units=charge * count,
                        attempt_horizon=count,
                        event_charge_units=charge,
                    ),
                    observer_spec=ObserverSpec(
                        permitted_value_codes=permitted,
                        observer_spec_id="sluice-agentdojo-effect-codebook-v2",
                        route_codebooks=tuple(
                            RouteCodebook(
                                template.template_id,
                                frozenset({value_codes[template.template_id]}),
                                True,
                            )
                            for template in templates
                        ),
                        accounting_units_per_bit=units_per_bit,
                    ),
                    agent_keys={EFFECT_AGENT_ID: key},
                    reauthorization_keys={"authority": secrets.token_bytes(32)},
                    handler_registry={
                        "authorize": IdempotentEffectHandler(
                            execute=_execute, reconcile=lambda _request: None
                        )
                    },
                )
                routes = {
                    template.template_id: domain.register_route(
                        name=template.template_id,
                        protected_object=EFFECT_PROTECTED_OBJECT,
                        handler_key="authorize",
                        public_values=frozenset({value_codes[template.template_id]}),
                        requires_capability=True,
                    )
                    for template in templates
                }
                domain.seal()
            except BaseException as exc:  # noqa: BLE001
                last_error = exc
                try:
                    if domain is not None:
                        domain.close()
                except BaseException:  # noqa: BLE001
                    pass
                domain = None
                for suffix in ("", "-wal", "-shm"):
                    candidate_path = Path(str(attempt_path) + suffix)
                    try:
                        if candidate_path.exists():
                            candidate_path.unlink()
                    except OSError:
                        pass
                # The ONLY thing this loop absorbs is the domain disagreeing
                # about how many units one event must carry.  Everything else
                # is a real configuration error and is re-raised immediately.
                if "support bound" not in str(exc) and "budget" not in str(exc):
                    raise
                self.charge_escalations.append(candidate)
                candidate = candidate * 2
                continue
            self.path = attempt_path
            break
        else:
            raise RuntimeError(
                f"could not derive an acceptable event charge: {last_error!r}"
            )

        if domain is None:
            raise RuntimeError("effect domain construction ended without a domain")
        sealed_charge = int(domain.event_charge_units)
        if sealed_charge != charge:
            raise RuntimeError("domain did not seal at the charge it was funded for")
        domain.activate()

        self._domain = domain
        self._manifest = manifest
        self.event_charge_units = sealed_charge
        self.value_codes = dict(value_codes)
        self.routes = routes

        ledger = EffectChargeLedger(
            workflow_id=manifest.workflow_id,
            episode_id=manifest.episode_id,
            domain_charge_units=sealed_charge,
        )
        ledger_holder["ledger"] = ledger
        self.ledger = ledger

        self.grants = foundation.issue_durable_effect_grants(
            domain,
            manifest,
            route_by_tool=routes,
            agent_id=EFFECT_AGENT_ID,
            signing_key=key,
            redeemer_id=f"pid:{os.getpid()}",
        )
        by_template = {grant.template_id: grant for grant in self.grants}
        for ordinal, template in enumerate(templates, 1):
            grant = by_template.get(template.template_id)
            if grant is None:
                raise RuntimeError("issued grants do not cover every template")
            if grant.tool != template.tool or grant.exact_args != template.exact_args:
                raise RuntimeError("issued grant does not match its template")
            ledger.authorize(
                AuthorizedEffect(
                    ordinal=ordinal,
                    template_id=template.template_id,
                    tool=template.tool,
                    exact_args=template.exact_args,
                    exact_args_sha256=template.args_sha256,
                    route_name=template.template_id,
                    value_code=value_codes[template.template_id],
                    authorized_charge_units=sealed_charge,
                    payload_sha256=payload_digest(grant.payload()),
                    workflow_id=manifest.workflow_id,
                    episode_id=manifest.episode_id,
                )
            )
        self._redeemer = CrossBindingRedeemer(domain, self.grants, ledger)

    # ---------------------------------------------------------------- API
    @property
    def authorizer(self) -> Any:
        return self._redeemer

    @property
    def domain(self) -> Any:
        return self._domain

    @property
    def transcript_length(self) -> int:
        return len(self._domain.transcript)

    def report(self, *, broker: Any = None) -> "dict[str, Any]":
        payload = self.ledger.verify(
            broker=broker, domain=self._domain, manifest=self._manifest
        )
        payload["charge_escalations"] = list(self.charge_escalations)
        payload["route_count"] = len(self.routes)
        payload["gate_scope"] = "one_route_and_one_value_code_per_exact_effect"
        return payload

    def close(self) -> None:
        try:
            self._domain.close()
        finally:
            try:
                for suffix in ("", "-wal", "-shm"):
                    candidate = Path(str(self.path) + suffix)
                    if candidate.exists():
                        candidate.unlink()
            except OSError:
                pass


class RecordingBroker:
    """Wraps ``NonOracleToolBroker`` so the ledger also sees the RESULT.

    The broker's own audit log is digest-only, so reconciling from it can bind
    the tool, the canonical arguments and the audit record but never the value
    the tool returned.  Where the harness owns the call site -- the benign
    element, and any executor that is not the audited ``OfficialBrokerExecutor``
    -- this wrapper binds the result too, at the one moment it exists.

    It is a strict pass-through: the ``BrokerResult`` returned to the caller is
    the broker's own object, unmodified.  A cross-binding failure is recorded as
    a violation, which ``EffectChargeLedger.verify`` reports; it does not and
    must not rewrite an authorization decision that has already been made.
    """

    __slots__ = ("_broker", "_ledger", "_templates")

    def __init__(self, broker: Any, ledger: EffectChargeLedger, manifest: Any):
        self._broker = broker
        self._ledger = ledger
        self._templates = {
            template.template_id: template for template in manifest.templates
        }

    def __getattr__(self, name: str) -> Any:
        return getattr(self._broker, name)

    def execute(self, request: Any, environment: Any) -> Any:
        result = self._broker.execute(request, environment)
        try:
            record = self._broker.audit_log[-1]
        except BaseException:  # noqa: BLE001
            return result
        if getattr(record.outcome, "value", "") != "executed_effect":
            return result
        template = self._templates.get(record.template_id)
        if template is None:
            self._ledger.record_violation(
                f"executed template {record.template_id!r} is not in the manifest"
            )
            return result
        try:
            self._ledger.bind_execution(
                template_id=template.template_id,
                tool=template.tool,
                canonical_args=template.exact_args,
                result=result.value,
                audit_record=record,
                source="broker_wrapper",
            )
        except CrossBindingError as exc:
            self._ledger.record_violation(f"{record.template_id}: {exc}")
        return result


class NullEffectAuthority:
    """Authority for a manifest that compiled zero templates."""

    grants: tuple = ()
    event_charge_units = 0
    charge_escalations: list = []

    def __init__(self) -> None:
        self.ledger = EffectChargeLedger(
            workflow_id="none", episode_id="none", domain_charge_units=0
        )

    def redeem(self, grant: Any, payload: Any) -> Any:
        from sluice_v2.evaluation.agentdojo import AuthorizationOutcome

        return AuthorizationOutcome.DENIED

    @property
    def authorizer(self) -> Any:
        return self

    @property
    def transcript_length(self) -> int:
        return 0

    def report(self, *, broker: Any = None) -> "dict[str, Any]":
        return {
            "schema": LEDGER_SCHEMA,
            "authorized_count": 0,
            "observed_count": 0,
            "executed_count": 0,
            "consistent": True,
            "problems": [],
            "charge_escalations": [],
            "route_count": 0,
            "gate_scope": "no_authorised_effect",
        }

    def close(self) -> None:
        return None
