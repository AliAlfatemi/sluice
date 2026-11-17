"""Sluice v2 reference monitor: capability-based invoke() API,
EndorseGate/ReleaseGate direction split, atomic reserve-before-decode,
finite typed result alphabet, tool-argument/effect enforcement. The result
alphabet is not the entire observer transcript; identities, credentials,
arguments, capabilities, effects, and audit metadata require the separate
premises documented in the paper and ``formal/FORMAL_REVIEW.md``.

Supersedes sluice/gate.py + sluice/ledger.py's caller-facing shape per the
2026-08-11 novelty/correctness audit (NOVELTY_GO_NO_GO.md, C20/C21 in
CLAIM_EVIDENCE_MATRIX.csv). The v1 modules are kept for historical
comparison and are not the monitor this project claims a security property
for going forward.

Design summary (see SECURITY_PROOF.md for the formal statement):

- AuthorGate() is the ONLY way a GateRecord is created, and only a
  trusted planner identity may call it. The record is immutable,
  digest-bound (HMAC, domain-separated), and stored server-side; the
  caller only ever receives an opaque GateHandle (gate_id + digest), never
  the record itself.
- invoke(handle, content, caller_id, args) is the ONLY caller-facing
  entry point. It does not accept an alphabet, cardinality, cost, schema
  hash, protected-object name, or provenance assertion from the caller --
  all of that is resolved server-side from the stored record.
- Budget is reserved ATOMICALLY, before decoding is even attempted, for
  the gate's full declared worst-case cost. The same cost is charged
  regardless of which observable outcome results (OK or one of four generic
  post-decode failures) as long as decoding was actually attempted against real
  content. Pre-claim outcomes are left unreserved/free. Most are ledger/time
  checks, but optional caller authentication hashes content and arguments
  before the claim; a confidentiality deployment must therefore keep those
  authentication fields/outcomes private or establish their secret-
  independence. The monitor does not enforce that theorem premise.
- The atomic charge writes an ``invocation_started`` entry to a hash-linked
  audit log.  Outcome entries are best-effort after that transaction.  Local
  verification checks only the rows currently present; tamper evidence and
  suffix-deletion detection require an integrity-protected external checkpoint.
- Optional, opt-in per protected-object chain: a gate may declare
  ``allowed_successor_gates``, and the first gate for an object/epoch may
  declare ``entry_fanout``. On a successful claim, the monitor reserves
  ``ceil(1e6*log2(fanout))`` selection units together with the gate's own
  content cost; it also atomically enforces successor membership and mutual
  exclusion. A denied claim is free even though its gate identifier is
  observable, so this mechanism does *not* make secret-dependent routing
  safe. The confidentiality theorem still requires the route/gate schedule
  to satisfy its public-routing premise. Chains that never declare
  successors behave exactly as before.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from .actions import ActionTemplate, EffectClass
from .store import (
    ABSOLUTE_MAX_CARDINALITY,
    ClaimStatus,
    DurableStore,
    PreparedAuthorization,
    ReplayError,
    cap_bits_to_units,
    selection_cost_units,
    units_to_bits,
)

DOMAIN_GATE = b"sluice-gate-v4\x00"
DOMAIN_GRANT = b"sluice-grant-v4\x00"
DOMAIN_ACTION = b"sluice-action-v4\x00"
# Agent-identity call authentication and single-hop delegation (multi-agent
# workflows, \S\ref{sec:multiagent}). Domain-separated from DOMAIN_GRANT/
# DOMAIN_ACTION so a signature valid under one purpose can never verify
# under another even if the same key were mistakenly reused.
DOMAIN_CALL = b"sluice-call-v4\x00"
DOMAIN_DELEGATION = b"sluice-delegation-v4\x00"
# Tolerance for clock skew between the agent process that stamped
# issued_at and the monitor process checking it -- not a validity
# extension past expires_at, only slack on the *lower* bound so a
# credential is not rejected as "not yet valid" over ordinary NTP drift.
_CLOCK_SKEW_TOLERANCE_SECONDS = 5.0
RECORD_FORMAT_VERSION = 4
# ABSOLUTE_MAX_CARDINALITY is imported from store, which now also owns the
# selection-charge table (claim_and_reserve_gate needs it, §store.py).


class SluiceV2Error(Exception):
    pass


class ProvenanceViolation(SluiceV2Error):
    pass


class TamperViolation(SluiceV2Error):
    pass


class Direction(str, Enum):
    ENDORSE = "endorse"  # untrusted content -> bounded influence over a trusted decision (integrity)
    RELEASE = "release"  # protected secret -> bounded observation by a less-trusted party (confidentiality)


class Outcome(str, Enum):
    OK = "ok"
    SCHEMA_VIOLATION = "schema_violation"
    BACKEND_ERROR = "backend_error"
    BUDGET_EXHAUSTED = "budget_exhausted"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    STALE_EPOCH = "stale_epoch"
    UNAUTHORIZED_CALLER = "unauthorized_caller"
    ARG_INVALID = "arg_invalid"
    EFFECT_TOO_STRONG = "effect_too_strong"
    UNAUTHORIZED_SUCCESSOR = "unauthorized_successor"
    UNAUTHENTICATED_CALLER = "unauthenticated_caller"
    UNAUTHORIZED_DELEGATION = "unauthorized_delegation"


# Pre-claim outcomes are charged zero. Ledger/sequence/time checks are
# independent of this request's content once their public inputs are fixed,
# but optional caller/delegation verification hashes content and arguments
# before the claim. Consequently this classification is an accounting/API
# distinction, not by itself a proof that every free outcome is independent
# of a protected secret. The paper's typed-transcript theorem explicitly
# requires that property (or a private authentication view).
_CHARGED_FAILURES = (
    Outcome.SCHEMA_VIOLATION,
    Outcome.BACKEND_ERROR,
    Outcome.ARG_INVALID,
    Outcome.EFFECT_TOO_STRONG,
)
_FREE_OUTCOMES = frozenset({
    Outcome.EXPIRED,
    Outcome.REPLAYED,
    Outcome.STALE_EPOCH,
    Outcome.UNAUTHORIZED_CALLER,
    Outcome.BUDGET_EXHAUSTED,
    Outcome.UNAUTHORIZED_SUCCESSOR,
    Outcome.UNAUTHENTICATED_CALLER,
    Outcome.UNAUTHORIZED_DELEGATION,
})


# Reviewed exact values of ceil(10^6 * log2(K + 4)) for K=1..32.  They were
# generated with high-precision Decimal logarithms and checked by the exact
# integer inequalities 2^(u-1) < (K+4)^10^6 <= 2^u.  A table avoids turning
# policy authorship into a multi-second big-integer denial-of-service surface.
_GATE_COST_UNITS = (
    2_321_929, 2_584_963, 2_807_355, 3_000_000,
    3_169_926, 3_321_929, 3_459_432, 3_584_963,
    3_700_440, 3_807_355, 3_906_891, 4_000_000,
    4_087_463, 4_169_926, 4_247_928, 4_321_929,
    4_392_318, 4_459_432, 4_523_562, 4_584_963,
    4_643_857, 4_700_440, 4_754_888, 4_807_355,
    4_857_981, 4_906_891, 4_954_197, 5_000_000,
    5_044_395, 5_087_463, 5_129_284, 5_169_926,
)


def gate_cost_units(cardinality: int) -> int:
    """Exact table lookup for ``ceil(10^6 * log2(K + 4))`` microbits."""
    if (
        isinstance(cardinality, bool)
        or not isinstance(cardinality, int)
        or not 1 <= cardinality <= ABSOLUTE_MAX_CARDINALITY
    ):
        raise ValueError(
            f"cardinality must be an integer in [1, {ABSOLUTE_MAX_CARDINALITY}]"
        )
    return _GATE_COST_UNITS[cardinality - 1]


# selection_cost_units is now defined in store.py (imported above), since
# claim_and_reserve_gate computes it internally as part of the atomic
# successor-authorization fix; this module only needs the bits-valued
# convenience wrapper.
def selection_cost_bits(fanout: int) -> float:
    return units_to_bits(selection_cost_units(fanout))


def gate_cost_bits(cardinality: int) -> float:
    """Human-readable bit representation of the exact integer charge.

    A successful observation is the typed pair ``(OK, symbol)``.  Four
    generic post-decode failures are also distinguishable, so the support
    has ``cardinality + 4`` members.  Rounding upward to six decimal places
    prevents the accounting value from falling below the real logarithm.
    """
    return units_to_bits(gate_cost_units(cardinality))


def _require_finite_nonnegative(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SluiceV2Error(f"{field_name} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise SluiceV2Error(f"{field_name} must be a finite non-negative number")
    return 0.0 if result == 0 else result


def _require_nfc_tree(value, field_name: str = "policy") -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise SluiceV2Error(f"{field_name} contains a non-NFC string")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require_nfc_tree(key, field_name)
            _require_nfc_tree(item, field_name)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _require_nfc_tree(item, field_name)


def canonical_bytes(value) -> bytes:
    """Length-prefixed, exact-UTF-8, sorted-key canonical encoding.

    Security-relevant strings are required to be NFC before this function is
    called.  The encoder itself is injective over the runtime values: it must
    never silently identify two strings Python treats as different.

    Closes canonicalization-collision attacks (embedded NUL/delimiter
    injection and dict key ordering) that a naive concatenation would permit.
    """
    if isinstance(value, str):
        b = value.encode("utf-8")
        return b"S" + len(b).to_bytes(8, "big") + b
    if isinstance(value, bool):
        return b"B1" if value else b"B0"
    if isinstance(value, int):
        s = str(value).encode("ascii")
        return b"I" + len(s).to_bytes(8, "big") + s
    if isinstance(value, float):
        s = repr(value).encode("ascii")
        return b"F" + len(s).to_bytes(8, "big") + s
    if value is None:
        return b"N"
    if isinstance(value, (list, tuple)):
        parts = b"".join(canonical_bytes(v) for v in value)
        return b"[" + len(parts).to_bytes(8, "big") + parts
    if isinstance(value, (set, frozenset)):
        parts = b"".join(canonical_bytes(v) for v in sorted(value, key=repr))
        return b"<" + len(parts).to_bytes(8, "big") + parts
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        parts = b"".join(canonical_bytes(k) + canonical_bytes(v) for k, v in items)
        return b"{" + len(parts).to_bytes(8, "big") + parts
    raise TypeError(f"canonical_bytes: unsupported type {type(value)!r}")


@dataclass(frozen=True)
class Symbol:
    value: str
    action: Optional[ActionTemplate] = None


@dataclass(frozen=True)
class GateRecord:
    record_format_version: int
    gate_id: str
    workflow_id: str
    policy_version: str
    policy_epoch: int
    protected_object: str
    direction: Direction
    confidentiality_label: str
    integrity_label: str
    symbols: Tuple[Symbol, ...]
    authorized_cost_bits: float
    authorized_cost_units: int
    author_identity: str
    permitted_callers: FrozenSet[str]
    allowed_successor_gates: FrozenSet[str]
    expiration: Optional[float]
    max_effect_class: str
    nonce: str
    entry_fanout: int
    require_authenticated_caller: bool = True

    def symbol_values(self) -> Tuple[str, ...]:
        return tuple(s.value for s in self.symbols)

    def action_for(self, value: str) -> Optional[ActionTemplate]:
        for s in self.symbols:
            if s.value == value:
                return s.action
        return None

    def charged_observable_support(self) -> Tuple[Tuple[Outcome, Optional[str]], ...]:
        """Typed support of every outcome possible after content is read."""
        return tuple((Outcome.OK, value) for value in self.symbol_values()) + tuple(
            (outcome, None) for outcome in _CHARGED_FAILURES
        )

    def observable_alphabet(self) -> Tuple[Tuple[Outcome, Optional[str]], ...]:
        """Complete typed support, including public pre-decode rejections."""
        return self.charged_observable_support() + tuple(
            (outcome, None) for outcome in sorted(_FREE_OUTCOMES, key=lambda item: item.value)
        )

    def to_canonical_dict(self) -> dict:
        return {
            "record_format_version": self.record_format_version,
            "gate_id": self.gate_id,
            "workflow_id": self.workflow_id,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "protected_object": self.protected_object,
            "direction": self.direction.value,
            "confidentiality_label": self.confidentiality_label,
            "integrity_label": self.integrity_label,
            "symbols": [
                {"value": s.value, "action": s.action.to_dict() if s.action is not None else None}
                for s in self.symbols
            ],
            "authorized_cost_bits": self.authorized_cost_bits,
            "authorized_cost_units": self.authorized_cost_units,
            "author_identity": self.author_identity,
            "permitted_callers": sorted(self.permitted_callers),
            "allowed_successor_gates": sorted(self.allowed_successor_gates),
            "expiration": self.expiration,
            "max_effect_class": self.max_effect_class,
            "nonce": self.nonce,
            "entry_fanout": self.entry_fanout,
            "require_authenticated_caller": self.require_authenticated_caller,
        }


@dataclass(frozen=True)
class GateHandle:
    """The ONLY thing a caller ever holds. Carries no alphabet, cost, or
    provenance data -- those live only in the store, keyed by gate_id, and
    are re-verified against `digest` server-side on every invoke()."""
    gate_id: str
    digest: str


@dataclass(frozen=True)
class Observation:
    outcome: Outcome
    value: Optional[str]
    action: Optional[ActionTemplate]
    gate_id: str
    charged_bits: float
    policy_epoch: int = 0
    protected_object: str = ""
    authorized_args: Tuple[Tuple[str, str], ...] = ()
    capability_id: Optional[str] = None
    capability_tag: Optional[str] = None
    redeemer_agent_id: Optional[str] = None


@dataclass(frozen=True)
class ReauthorizationGrant:
    grant_id: str
    protected_object: str
    previous_epoch: int
    new_epoch: int
    new_cap_bits: float
    new_cap_units: int
    authorizer_identity: str
    signature: str


@dataclass(frozen=True)
class CallerCredential:
    """A fresh, single-use, request-bound signed envelope proving possession
    of ``agent_id``'s registered key -- not a bare identity claim, and not
    a bare (agent_id, gate_id) tag either. An earlier revision signed only
    (agent_id, gate_id): that value is fixed for the credential's entire
    validity window, so an interceptor who captures one in transit (a
    compromised transport, a logging sidecar, a relay) could replay it to
    win the gate claim ahead of the legitimate holder, and -- more
    seriously -- nothing about the signature depended on *what* was being
    submitted, so a relay that captured a genuine credential could pair it
    with different content or arguments than the agent actually signed.

    This version signs the full request: which gate, which workflow, which
    policy epoch, a digest of the untrusted content, a digest of the
    action arguments, a fresh single-use nonce, and an expiry. Verification
    (``_verify_call_credential``) recomputes both digests from the request
    actually being processed -- not from the credential's own claimed
    digest fields -- so tampering with content or arguments after issuance
    invalidates the signature regardless of how the credential in transit
    was obtained. The nonce is consumed transactionally
    (\\S\\ref{sec:multiagent}), so a captured-and-replayed credential fails
    on its second use even within its expiry window, and a delayed replay
    fails once ``expires_at`` has passed even on first use.

    Confidentiality caveat: these are plain SHA-256 digests, not hiding
    commitments. Exposing a credential can enable dictionary testing of
    low-entropy content/arguments, and verification precedes budget
    reservation. Deployments using the paper's information-theoretic theorem
    must keep this envelope outside the stated public view or establish that
    its fields and rejection outcome are secret-independent."""
    agent_id: str
    gate_id: str
    workflow_id: str
    epoch: int
    content_digest: str
    args_digest: str
    nonce: str
    issued_at: float
    expires_at: float
    signature: str


@dataclass(frozen=True)
class DelegationGrant:
    """A single-hop, one-time-redeemable authorization: ``delegator_agent_id``
    (who must itself be in the target gate's ``permitted_callers``) lets
    ``delegate_agent_id`` invoke one specific ``gate_id`` on its behalf,
    until ``expiration``. Redeeming it still requires the delegate to
    present their own valid ``CallerCredential`` -- possessing a copy of the
    grant (e.g. a forwarded message containing it) is not sufficient without
    also holding the delegate's own key, which is what prevents a grant
    meant for one agent from being used by whichever agent happens to
    receive or intercept it."""
    grant_id: str
    delegator_agent_id: str
    delegate_agent_id: str
    gate_id: str
    expiration: Optional[float]
    signature: str


class Backend:
    def decode(self, untrusted_content: str, symbol_values: Sequence[str]) -> str:
        raise NotImplementedError


class MockBackend(Backend):
    def decode(self, untrusted_content: str, symbol_values: Sequence[str]) -> str:
        lowered = untrusted_content.lower()
        for v in symbol_values:
            if v.lower() in lowered:
                return v
        return symbol_values[0]


class ReferenceMonitor:
    """The trusted computing base holding the gate/action HMAC key.

    The reproducibility fallback persists that key in ``DurableStore``.  A
    deployment that treats the database writer as adversarial must instead
    supply a key from an isolated hardware/KMS-backed trust root.
    """

    def __init__(
        self,
        store: DurableStore,
        backend: Backend,
        hmac_key: Optional[bytes] = None,
        default_cap_bits: float = 32.0,
        max_cardinality: int = 32,
        trusted_authorizer_keys: Optional[Mapping[str, bytes]] = None,
        trusted_planner_identities: Optional[FrozenSet[str]] = None,
        agent_keys: Optional[Mapping[str, bytes]] = None,
    ):
        self._store = store
        self._backend = backend
        if hmac_key is None:
            self._hmac_key = store.get_or_create_hmac_key()
        elif not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise SluiceV2Error(
                "hmac_key must be immutable bytes containing at least 256 bits"
            )
        else:
            self._hmac_key = hmac_key
        validated_default_cap = _require_finite_nonnegative(
            default_cap_bits, "default_cap_bits"
        )
        self._default_cap_units = cap_bits_to_units(validated_default_cap)
        if (
            isinstance(max_cardinality, bool)
            or not isinstance(max_cardinality, int)
            or not 1 <= max_cardinality <= ABSOLUTE_MAX_CARDINALITY
        ):
            raise SluiceV2Error(
                f"max_cardinality must be in [1, {ABSOLUTE_MAX_CARDINALITY}]"
            )
        self._max_cardinality = max_cardinality
        self._trusted_authorizer_keys = dict(trusted_authorizer_keys or {})
        for identity, key in self._trusted_authorizer_keys.items():
            if not isinstance(identity, str) or not identity:
                raise SluiceV2Error("authorizer identities must be non-empty strings")
            _require_nfc_tree(identity, "authorizer identity")
            if not isinstance(key, bytes) or len(key) < 16:
                raise SluiceV2Error("trusted authorizer keys must be bytes with at least 128 bits")
        self._trusted_planner_identities = frozenset(
            {"planner"} if trusted_planner_identities is None else trusted_planner_identities
        )
        if any(
            not isinstance(identity, str) or not identity
            for identity in self._trusted_planner_identities
        ):
            raise SluiceV2Error("planner identities must be non-empty strings")
        _require_nfc_tree(self._trusted_planner_identities, "planner identity")
        # Per-agent HMAC keys the monitor trusts for CallerCredential/
        # DelegationGrant verification (\S\ref{sec:multiagent}), mirroring
        # trusted_authorizer_keys' existing pattern for reauthorization.
        # Registered by trusted deployment/setup code, never by an agent
        # itself -- an agent proves possession of a key it was handed, it
        # does not get to name its own identity.
        self._agent_keys = dict(agent_keys or {})
        for identity, key in self._agent_keys.items():
            if not isinstance(identity, str) or not identity:
                raise SluiceV2Error("agent identities must be non-empty strings")
            _require_nfc_tree(identity, "agent identity")
            if not isinstance(key, bytes) or len(key) < 16:
                raise SluiceV2Error("agent keys must be bytes with at least 128 bits")

    # ---- digesting -------------------------------------------------
    def _digest(self, record_dict: dict, domain: bytes) -> str:
        mac = hmac.new(self._hmac_key, domain + canonical_bytes(record_dict), hashlib.sha256)
        return mac.hexdigest()

    # ---- AuthorGate: trusted-planner-only ---------------------------
    def author_gate(
        self,
        gate_id: str,
        workflow_id: str,
        protected_object: str,
        direction: Direction,
        symbols: Sequence[Symbol],
        author_identity: str,
        permitted_callers: FrozenSet[str],
        confidentiality_label: str = "public",
        integrity_label: str = "trusted",
        allowed_successor_gates: FrozenSet[str] = frozenset(),
        expiration: Optional[float] = None,
        max_effect_class: str = EffectClass.NONE,
        policy_version: str = "v1",
        policy_epoch: int = 0,
        cap_bits: Optional[float] = None,
        entry_fanout: int = 1,
        unsafe_allow_unauthenticated_caller: bool = False,
    ) -> GateHandle:
        if not isinstance(direction, Direction):
            raise SluiceV2Error("direction must be a Direction value")
        required_strings = {
            "gate_id": gate_id,
            "workflow_id": workflow_id,
            "protected_object": protected_object,
            "author_identity": author_identity,
            "confidentiality_label": confidentiality_label,
            "integrity_label": integrity_label,
            "policy_version": policy_version,
        }
        if any(not isinstance(value, str) or not value for value in required_strings.values()):
            raise SluiceV2Error("gate identifiers and policy labels must be non-empty strings")
        try:
            symbols = tuple(symbols)
            permitted_callers = frozenset(permitted_callers)
            allowed_successor_gates = frozenset(allowed_successor_gates)
        except TypeError as exc:
            raise SluiceV2Error("symbols and caller/successor sets must be iterable") from exc
        if any(
            not isinstance(symbol, Symbol)
            or not isinstance(symbol.value, str)
            or not symbol.value
            for symbol in symbols
        ):
            raise SluiceV2Error("every symbol must have a non-empty string value")
        if any(not isinstance(value, str) or not value for value in permitted_callers):
            raise SluiceV2Error("permitted caller identities must be non-empty strings")
        if any(not isinstance(value, str) or not value for value in allowed_successor_gates):
            raise SluiceV2Error("successor gate identifiers must be non-empty strings")
        if author_identity not in self._trusted_planner_identities:
            raise ProvenanceViolation(f"untrusted gate author {author_identity!r}")
        if isinstance(policy_epoch, bool) or not isinstance(policy_epoch, int) or policy_epoch < 0:
            raise SluiceV2Error("policy_epoch must be a non-negative integer")
        if type(unsafe_allow_unauthenticated_caller) is not bool:
            raise SluiceV2Error(
                "unsafe_allow_unauthenticated_caller must be an actual bool"
            )
        if max_effect_class not in EffectClass.ORDER:
            raise SluiceV2Error(f"unknown effect class {max_effect_class!r}")
        if (
            isinstance(entry_fanout, bool)
            or not isinstance(entry_fanout, int)
            or not 1 <= entry_fanout <= ABSOLUTE_MAX_CARDINALITY
        ):
            raise SluiceV2Error(
                f"entry_fanout must be an integer in [1, {ABSOLUTE_MAX_CARDINALITY}]"
            )
        if expiration is not None:
            if isinstance(expiration, bool) or not isinstance(expiration, (int, float)):
                raise SluiceV2Error("expiration must be a finite timestamp or None")
            expiration = float(expiration)
            if not math.isfinite(expiration):
                raise SluiceV2Error("expiration must be a finite timestamp or None")
        if len(symbols) == 0:
            raise SluiceV2Error(f"gate {gate_id!r}: empty symbol set")
        if len(symbols) > self._max_cardinality:
            raise SluiceV2Error(
                f"gate {gate_id!r}: |Sigma|={len(symbols)} exceeds MaxCardinality={self._max_cardinality}"
            )
        values = [s.value for s in symbols]
        policy_strings = {
            "gate_id": gate_id,
            "workflow_id": workflow_id,
            "protected_object": protected_object,
            "author_identity": author_identity,
            "confidentiality_label": confidentiality_label,
            "integrity_label": integrity_label,
            "policy_version": policy_version,
            "permitted_callers": sorted(permitted_callers),
            "allowed_successor_gates": sorted(allowed_successor_gates),
            "symbols": [
                {"value": symbol.value, "action": symbol.action.to_dict() if symbol.action else None}
                for symbol in symbols
            ],
        }
        _require_nfc_tree(policy_strings)
        if len(set(values)) != len(values):
            raise SluiceV2Error(f"gate {gate_id!r}: duplicate symbol values {values!r}")
        for s in symbols:
            if s.action is not None:
                valid_action, reason = s.action.validate_definition()
                if not valid_action:
                    raise SluiceV2Error(
                        f"gate {gate_id!r}: symbol {s.value!r} has invalid action policy ({reason})"
                    )
            if s.action is not None and not EffectClass.at_most(s.action.max_effect_class, max_effect_class):
                raise SluiceV2Error(
                    f"gate {gate_id!r}: symbol {s.value!r}'s action effect class "
                    f"{s.action.max_effect_class!r} exceeds gate ceiling {max_effect_class!r}"
                )
        cost_units = gate_cost_units(len(symbols))
        cost_bits = units_to_bits(cost_units)
        nonce = secrets.token_hex(16)

        record = GateRecord(
            record_format_version=RECORD_FORMAT_VERSION,
            gate_id=gate_id,
            workflow_id=workflow_id,
            policy_version=policy_version,
            policy_epoch=policy_epoch,
            protected_object=protected_object,
            direction=direction,
            confidentiality_label=confidentiality_label,
            integrity_label=integrity_label,
            symbols=tuple(symbols),
            authorized_cost_bits=cost_bits,
            authorized_cost_units=cost_units,
            author_identity=author_identity,
            permitted_callers=frozenset(permitted_callers),
            allowed_successor_gates=frozenset(allowed_successor_gates),
            expiration=expiration,
            max_effect_class=max_effect_class,
            nonce=nonce,
            entry_fanout=entry_fanout,
            require_authenticated_caller=not unsafe_allow_unauthenticated_caller,
        )
        digest = self._digest(record.to_canonical_dict(), DOMAIN_GATE)

        import json as _json
        # Actions are serialized as part of the SAME dict the digest is
        # computed over (to_canonical_dict includes each symbol's action),
        # so record_json is a complete, authenticated, restart-durable
        # representation -- no separate in-memory registry needed, and an
        # attacker who edits an action's constraints in storage invalidates
        # the digest exactly like editing any other field would.
        record_json = _json.dumps(record.to_canonical_dict(), sort_keys=True)

        if cap_bits is None:
            cap_units = self._default_cap_units
        else:
            requested_cap = _require_finite_nonnegative(cap_bits, "cap_bits")
            cap_units = cap_bits_to_units(requested_cap)
        try:
            self._store.put_gate_and_initialize_budget(
                gate_id,
                record_json,
                digest,
                protected_object,
                policy_epoch,
                cap_units,
                cost_units,
                {
                    "workflow_id": workflow_id,
                    "protected_object": protected_object,
                    "direction": direction.value,
                    "cardinality": len(symbols),
                    "cost_bits": cost_bits,
                    "cost_units": cost_units,
                    "author_identity": author_identity,
                    "caller_authentication": (
                        "unsafe_caller_id_compat"
                        if unsafe_allow_unauthenticated_caller
                        else "authenticated"
                    ),
                },
            )
        except ReplayError as e:
            raise ProvenanceViolation(str(e)) from e
        except ValueError as e:
            raise ProvenanceViolation(str(e)) from e

        return GateHandle(gate_id=gate_id, digest=digest)

    def _load_record(self, gate_id: str) -> Tuple[GateRecord, str, bool]:
        if not isinstance(gate_id, str) or not gate_id:
            raise ProvenanceViolation("invalid gate identifier")
        try:
            row = self._store.get_gate(gate_id)
        except Exception as exc:
            raise TamperViolation("stored gate record is malformed") from exc
        if row is None:
            raise ProvenanceViolation(f"gate {gate_id!r} was never authored")
        try:
            d = row["record"]
            # Verify the exact parsed representation before enum/dataclass
            # conversion. This catches type changes and Unicode aliases.
            recomputed = self._digest(d, DOMAIN_GATE)
            if not isinstance(row["digest"], str) or not hmac.compare_digest(
                recomputed, row["digest"]
            ):
                raise TamperViolation("stored record digest verification failed")
            _require_nfc_tree(d, "stored gate record")
            if d.get("record_format_version") != RECORD_FORMAT_VERSION:
                raise TamperViolation("unsupported stored gate format")
            symbols = tuple(
                Symbol(
                    symbol["value"],
                    ActionTemplate.from_dict(symbol["action"])
                    if symbol["action"] is not None
                    else None,
                )
                for symbol in d["symbols"]
            )
            stored_authentication = d.get("require_authenticated_caller")
            if type(stored_authentication) is not bool:
                raise TamperViolation(
                    "stored authentication policy must be an actual bool"
                )
            record = GateRecord(
                record_format_version=d["record_format_version"],
                gate_id=d["gate_id"],
                workflow_id=d["workflow_id"],
                policy_version=d["policy_version"],
                policy_epoch=d["policy_epoch"],
                protected_object=d["protected_object"],
                direction=Direction(d["direction"]),
                confidentiality_label=d["confidentiality_label"],
                integrity_label=d["integrity_label"],
                symbols=symbols,
                authorized_cost_bits=d["authorized_cost_bits"],
                authorized_cost_units=d["authorized_cost_units"],
                author_identity=d["author_identity"],
                permitted_callers=frozenset(d["permitted_callers"]),
                allowed_successor_gates=frozenset(d["allowed_successor_gates"]),
                expiration=d["expiration"],
                max_effect_class=d["max_effect_class"],
                nonce=d["nonce"],
                entry_fanout=d["entry_fanout"],
                require_authenticated_caller=stored_authentication,
            )
            expected_cost_units = gate_cost_units(len(record.symbols))
            if (
                record.gate_id != gate_id
                or record.protected_object != row["protected_object"]
                or record.policy_epoch != row["policy_epoch"]
                or record.authorized_cost_units != row["authorized_cost_units"]
                or record.authorized_cost_units != expected_cost_units
                or record.authorized_cost_bits != units_to_bits(expected_cost_units)
            ):
                raise TamperViolation("stored gate binding is inconsistent")
        except TamperViolation:
            raise
        except Exception as exc:
            raise TamperViolation("stored gate record is malformed") from exc
        return record, row["digest"], row["consumed"]

    # ---- invoke(): the ONLY caller-facing entry point -------------------
    def invoke(
        self,
        handle: GateHandle,
        untrusted_content: str,
        caller_id: str,
        args: Optional[Mapping[str, str]] = None,
        credential: Optional[CallerCredential] = None,
        delegation: Optional[DelegationGrant] = None,
        redeemer_agent_id: Optional[str] = None,
    ) -> Observation:
        if redeemer_agent_id is not None and (
            not isinstance(redeemer_agent_id, str) or not redeemer_agent_id
        ):
            raise SluiceV2Error("redeemer_agent_id must be a non-empty string or None")
        record, stored_digest, _ = self._load_record(handle.gate_id)

        # Tamper check: the handle's digest must match what AuthorGate
        # actually committed. A caller cannot construct a valid handle for
        # a record it did not receive from AuthorGate.
        if not hmac.compare_digest(handle.digest, stored_digest):
            raise TamperViolation(f"gate {handle.gate_id!r}: handle digest does not match committed record")
        def _reject(outcome: Outcome, charged: float, detail: dict) -> Observation:
            self._store.append_audit(handle.gate_id, f"outcome:{outcome.value}", detail)
            return Observation(
                outcome,
                None,
                None,
                handle.gate_id,
                charged,
                record.policy_epoch,
                record.protected_object,
            )

        if record.expiration is not None and time.time() > record.expiration:
            return _reject(Outcome.EXPIRED, 0.0, {"caller_id": caller_id})

        # Direct authorization: caller_id must be a declared permitted
        # caller. This alone is only ever a claim, not a proof -- any code
        # with a GateHandle can pass any caller_id string. When the gate
        # opts in (require_authenticated_caller), that claim must also be
        # backed by a CallerCredential: a fresh, request-bound proof the
        # caller holds the key the monitor has on file for that agent_id,
        # covering this exact gate/workflow/epoch/content/args, not yet
        # used (\S\ref{sec:multiagent}). Verification and nonce consumption
        # are two separate steps *by design*: verification is a read-only
        # check so a bad credential is rejected for free (charged zero)
        # without touching durable state, and only a credential that has
        # already passed every other check spends its one-time nonce --
        # otherwise an attacker submitting deliberately-invalid credentials
        # could burn a legitimate agent's future nonces for free.
        prepared_authorization: Optional[PreparedAuthorization] = None
        if caller_id in record.permitted_callers:
            if record.require_authenticated_caller:
                if not (
                    credential is not None
                    and credential.agent_id == caller_id
                    and self._verify_call_credential(
                        credential, record.gate_id, record.workflow_id,
                        record.policy_epoch, untrusted_content, args,
                    )
                ):
                    return _reject(Outcome.UNAUTHENTICATED_CALLER, 0.0, {"caller_id": caller_id})
                prepared_authorization = PreparedAuthorization(
                    agent_id=credential.agent_id,
                    nonce=credential.nonce,
                    gate_id=credential.gate_id,
                    workflow_id=credential.workflow_id,
                    policy_epoch=credential.epoch,
                    expires_at=credential.expires_at,
                )
        elif delegation is not None:
            # Delegated authorization always requires authentication,
            # regardless of require_authenticated_caller: a delegation
            # grant is meaningless as an access-control primitive if it can
            # be redeemed by anyone merely claiming to be the named
            # delegate. Presenting a copy of the grant (e.g. one forwarded
            # by an eavesdropping or colluding agent) is not sufficient --
            # the redeemer must also produce a CallerCredential signed with
            # the specific delegate's own key, which a third party who
            # merely observed or forwarded the grant does not possess. This
            # is what makes capability forwarding and delegation laundering
            # fail rather than merely being undocumented.
            if (
                delegation.gate_id != handle.gate_id
                or delegation.delegate_agent_id != caller_id
                or delegation.delegator_agent_id not in record.permitted_callers
                or (delegation.expiration is not None and time.time() > delegation.expiration)
                or not self._verify_delegation_signature(delegation)
                or credential is None
                or credential.agent_id != caller_id
                or not self._verify_call_credential(
                    credential, record.gate_id, record.workflow_id,
                    record.policy_epoch, untrusted_content, args,
                )
            ):
                return _reject(Outcome.UNAUTHORIZED_DELEGATION, 0.0, {"caller_id": caller_id})
            prepared_authorization = PreparedAuthorization(
                agent_id=credential.agent_id,
                nonce=credential.nonce,
                gate_id=credential.gate_id,
                workflow_id=credential.workflow_id,
                policy_epoch=credential.epoch,
                expires_at=credential.expires_at,
                grant_id=delegation.grant_id,
                delegator_agent_id=delegation.delegator_agent_id,
                delegate_agent_id=delegation.delegate_agent_id,
                delegation_expires_at=delegation.expiration,
            )
        else:
            return _reject(Outcome.UNAUTHORIZED_CALLER, 0.0, {"caller_id": caller_id})

        # Sequencing / selection charge. When a predecessor gate declares a
        # nonempty ``allowed_successor_gates`` and the caller's claim
        # SUCCEEDS, which permitted option was invoked is now charged
        # ceil(1e6*log2(fanout)) bits, exactly as conservatively as content
        # decoding is charged ceil(1e6*log2(K+4)): the full worst-case
        # support of "which permitted option was this," not the true
        # correlation. A gate whose predecessor never declares successors
        # (the default) pays nothing here and this check never rejects --
        # the mechanism is opt-in per chain, not a global behavior change.
        #
        # This charge does NOT extend the confidentiality theorem to
        # secret-dependent routing, and must not be described that way: it
        # is only ever applied on a successful claim, so a denied attempt
        # (including BUDGET_EXHAUSTED) still reveals which gate_id was
        # named, in the audit record, for zero charge. The public-adaptive-
        # schedule premise (gate choice is a function of public history
        # alone) is required unconditionally, including here -- see
        # formal/counterexamples/free_route_leak_repro.py and paper/main.tex
        # Sec. 5's "What Sec. 4's successor mechanism does and does not
        # buy." Reserving this charge unconditionally, before the claim's
        # success/failure is known, and never refunding it, would close
        # that gap; it is not implemented.
        #
        # The predecessor lookup, the successor-membership check, the
        # fanout computation, and the resulting selection charge all happen
        # *inside* claim_and_reserve_gate's own atomic transaction now, not
        # here beforehand -- an earlier revision did all four as a separate
        # non-atomic pre-check, which let two mutually exclusive successors
        # of the same predecessor each independently pass it and then each
        # independently win their own claim call (store.py's docstring on
        # claim_and_reserve_gate has the full argument for why atomicity
        # closes this).
        claim = self._store.claim_and_reserve_gate(
            record.gate_id,
            entry_fanout=record.entry_fanout,
            authorization=prepared_authorization,
        )
        if (
            claim.protected_object != record.protected_object
            or claim.policy_epoch != record.policy_epoch
            or claim.authorized_cost_units < record.authorized_cost_units
        ):
            raise TamperViolation("claimed gate binding differs from authenticated record")
        if claim.status == ClaimStatus.UNAUTHORIZED_SUCCESSOR:
            return _reject(Outcome.UNAUTHORIZED_SUCCESSOR, 0.0, {"caller_id": caller_id})
        if claim.status in {ClaimStatus.AUTH_REPLAYED, ClaimStatus.AUTH_INVALID}:
            replay_outcome = (
                Outcome.UNAUTHORIZED_DELEGATION
                if delegation is not None
                else Outcome.UNAUTHENTICATED_CALLER
            )
            return _reject(replay_outcome, 0.0, {"caller_id": caller_id})
        if claim.status == ClaimStatus.REPLAYED:
            return _reject(Outcome.REPLAYED, 0.0, {"caller_id": caller_id})
        if claim.status == ClaimStatus.STALE_EPOCH:
            return _reject(Outcome.STALE_EPOCH, 0.0, {"caller_id": caller_id})
        if claim.status == ClaimStatus.BUDGET_EXHAUSTED:
            return _reject(Outcome.BUDGET_EXHAUSTED, 0.0, {
                "caller_id": caller_id, "requested_bits": claim.authorized_cost_bits,
                "spent_before": claim.spent_before,
            })

        # From here on, real content has been (or is about to be) read
        # against a reserved budget -- every remaining outcome is charged
        # the same total (content + selection) bits regardless of which one
        # occurs, so the outcome itself cannot be used to infer anything
        # cheaper than a full gate call's worth of information. The total is
        # read from the claim, computed atomically by the store, not
        # recomputed here from a separately-tracked selection_units.
        charged = claim.authorized_cost_bits

        def _charged_outcome(outcome: Outcome) -> Observation:
            # Nothing derived from content, raw backend output, runtime
            # arguments, or exception text enters this public audit record.
            try:
                self._store.append_audit(
                    record.gate_id,
                    f"outcome:{outcome.value}",
                    {"caller_id": caller_id},
                )
            except Exception:
                # The invocation_started entry was committed atomically with
                # the charge. Audit storage failure cannot be allowed to turn
                # into an exception-valued secret channel.
                pass
            return Observation(
                outcome,
                None,
                None,
                record.gate_id,
                charged,
                record.policy_epoch,
                record.protected_object,
            )

        try:
            try:
                raw = self._backend.decode(untrusted_content, record.symbol_values())
            except BaseException as exc:
                # Ordinary Python exceptions are collapsed to the one generic
                # backend outcome.  Process death/native crashes require the
                # isolation assumption stated in SECURITY_PROOF.md.
                if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                    raise
                return _charged_outcome(Outcome.BACKEND_ERROR)

            if (
                not isinstance(raw, str)
                or unicodedata.normalize("NFC", raw) != raw
                or raw not in record.symbol_values()
            ):
                return _charged_outcome(Outcome.SCHEMA_VIOLATION)

            action = record.action_for(raw)
            try:
                supplied_args = {} if args is None else dict(args)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                    raise
                return _charged_outcome(Outcome.ARG_INVALID)
            if action is not None:
                try:
                    valid_args, _ = action.validate_args(supplied_args)
                except BaseException as exc:
                    if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                        raise
                    return _charged_outcome(Outcome.ARG_INVALID)
                if not valid_args:
                    return _charged_outcome(Outcome.ARG_INVALID)
                if not action.effect_permitted(record.max_effect_class):
                    return _charged_outcome(Outcome.EFFECT_TOO_STRONG)

            frozen_args = tuple(sorted(supplied_args.items())) if action is not None else ()
            observation = Observation(
                Outcome.OK,
                raw,
                action,
                record.gate_id,
                charged,
                record.policy_epoch,
                record.protected_object,
                frozen_args,
            )
            if action is not None:
                try:
                    capability_id = secrets.token_hex(16)
                    unsigned = Observation(
                        observation.outcome,
                        observation.value,
                        observation.action,
                        observation.gate_id,
                        observation.charged_bits,
                        observation.policy_epoch,
                        observation.protected_object,
                        observation.authorized_args,
                        capability_id,
                        None,
                        redeemer_agent_id,
                    )
                    tag = self._digest(
                        self._action_capability_payload(unsigned), DOMAIN_ACTION
                    )
                    import json as _json

                    self._store.put_action_capability(
                        capability_id,
                        observation.gate_id,
                        observation.protected_object,
                        observation.policy_epoch,
                        _json.dumps(action.to_dict(), sort_keys=True),
                        _json.dumps(dict(observation.authorized_args), sort_keys=True),
                        tag,
                        redeemer_agent_id,
                    )
                    observation = Observation(
                        unsigned.outcome,
                        unsigned.value,
                        unsigned.action,
                        unsigned.gate_id,
                        unsigned.charged_bits,
                        unsigned.policy_epoch,
                        unsigned.protected_object,
                        unsigned.authorized_args,
                        capability_id,
                        tag,
                        redeemer_agent_id,
                    )
                except BaseException as exc:
                    if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                        raise
                    return _charged_outcome(Outcome.BACKEND_ERROR)
            try:
                self._store.append_audit(
                    record.gate_id,
                    "outcome:ok",
                    {"caller_id": caller_id, "value": raw},
                )
            except Exception:
                return _charged_outcome(Outcome.BACKEND_ERROR)
            return observation
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            # The atomic claim audit already records the conservative charge;
            # these control-flow exits intentionally remain process-boundary
            # events rather than being swallowed by library code.
            raise
        except BaseException:
            return _charged_outcome(Outcome.BACKEND_ERROR)

    def _action_capability_payload(self, observation: Observation) -> dict:
        return {
            "capability_id": observation.capability_id,
            "gate_id": observation.gate_id,
            "outcome": observation.outcome.value,
            "value": observation.value,
            "charged_bits": observation.charged_bits,
            "policy_epoch": observation.policy_epoch,
            "protected_object": observation.protected_object,
            "action": observation.action.to_dict() if observation.action else None,
            "authorized_args": list(observation.authorized_args),
            "redeemer_agent_id": observation.redeemer_agent_id,
        }

    def consume_action_capability(
        self,
        observation: Observation,
        credential: Optional[CallerCredential] = None,
    ) -> Tuple[ActionTemplate, Dict[str, str]]:
        """Redeem an action capability.

        When the capability was minted with no ``redeemer_agent_id`` (the
        default, and every existing single-agent use in this paper),
        redemption is unchanged from before this mechanism existed: whoever
        holds a structurally valid, HMAC-authenticated ``Observation``
        redeems it, exactly as previously. When a ``redeemer_agent_id`` was
        bound at mint time (\\S\\ref{sec:multiagent} multi-agent handoff --
        e.g. a Research agent's gate mints a capability only an Executor
        agent may redeem), a matching ``credential`` is required here too:
        without this check, an intercepted or forwarded ``Observation``
        (the capability_id/capability_tag pair alone) would let *any*
        holder execute the action regardless of which agent it was actually
        handed to, since HMAC authentication alone proves the capability is
        genuine, not who is entitled to redeem it.
        """
        if (
            observation.outcome != Outcome.OK
            or observation.action is None
            or observation.capability_id is None
            or observation.capability_tag is None
        ):
            raise TamperViolation("observation does not carry an action capability")
        expected = self._digest(self._action_capability_payload(
            Observation(
                observation.outcome,
                observation.value,
                observation.action,
                observation.gate_id,
                observation.charged_bits,
                observation.policy_epoch,
                observation.protected_object,
                observation.authorized_args,
                observation.capability_id,
                None,
                observation.redeemer_agent_id,
            )
        ), DOMAIN_ACTION)
        if not hmac.compare_digest(expected, observation.capability_tag):
            raise TamperViolation("action capability authentication failed")
        prepared_authorization: Optional[PreparedAuthorization] = None
        if observation.redeemer_agent_id is not None:
            # Redemption credentials are bound to the capability_id and the
            # authorized args being redeemed (there is no untrusted content
            # or workflow_id on an Observation to bind to instead) --
            # "" is the fixed sentinel both issuance and verification use
            # for the workflow_id field in this scope, not a wildcard.
            if not (
                credential is not None
                and credential.agent_id == observation.redeemer_agent_id
                and self._verify_call_credential(
                    credential, observation.gate_id, "", observation.policy_epoch,
                    observation.capability_id, dict(observation.authorized_args),
                )
            ):
                raise ProvenanceViolation(
                    "action capability is bound to a specific redeemer agent; "
                    "no valid credential for that agent was presented"
                )
            prepared_authorization = PreparedAuthorization(
                agent_id=credential.agent_id,
                nonce=credential.nonce,
                gate_id=credential.gate_id,
                workflow_id=credential.workflow_id,
                policy_epoch=credential.epoch,
                expires_at=credential.expires_at,
            )
        stored = self._store.consume_action_capability(
            observation.capability_id,
            observation.capability_tag,
            authorization=prepared_authorization,
        )
        if stored is None:
            raise ReplayError("action capability is unknown or already consumed")
        try:
            stored_action = ActionTemplate.from_dict(stored["action"])
            stored_args = dict(stored["args"])
        except Exception as exc:
            raise TamperViolation("stored action capability payload is malformed") from exc
        if (
            stored["gate_id"] != observation.gate_id
            or stored["protected_object"] != observation.protected_object
            or stored["policy_epoch"] != observation.policy_epoch
            or stored_action != observation.action
            or stored_args != dict(observation.authorized_args)
            or stored.get("redeemer_agent_id") != observation.redeemer_agent_id
        ):
            raise TamperViolation("action capability payload differs from observation")
        return stored_action, stored_args

    # ---- signed reauthorization -----------------------------------
    def issue_reauthorization(
        self,
        protected_object: str,
        previous_epoch: int,
        new_epoch: int,
        new_cap_bits: float,
        authorizer_identity: str,
        authorizer_key: bytes,
    ) -> ReauthorizationGrant:
        """Construct a signed grant; redemption trusts only configured keys."""
        if not isinstance(authorizer_key, bytes) or len(authorizer_key) < 16:
            raise SluiceV2Error("authorizer_key must contain at least 128 bits")
        if (
            isinstance(previous_epoch, bool)
            or isinstance(new_epoch, bool)
            or not isinstance(previous_epoch, int)
            or not isinstance(new_epoch, int)
            or previous_epoch < 0
            or new_epoch != previous_epoch + 1
        ):
            raise SluiceV2Error("reauthorization must advance a non-negative epoch by one")
        requested_cap = _require_finite_nonnegative(new_cap_bits, "new_cap_bits")
        cap_units = cap_bits_to_units(requested_cap)
        cap = units_to_bits(cap_units)
        _require_nfc_tree({
            "protected_object": protected_object, "authorizer_identity": authorizer_identity
        }, "reauthorization grant")
        grant_id = secrets.token_hex(16)
        payload = canonical_bytes({
            "record_format_version": RECORD_FORMAT_VERSION,
            "grant_id": grant_id, "protected_object": protected_object,
            "previous_epoch": previous_epoch, "new_epoch": new_epoch,
            "new_cap_bits": cap, "new_cap_units": cap_units,
            "authorizer_identity": authorizer_identity,
        })
        signature = hmac.new(authorizer_key, DOMAIN_GRANT + payload, hashlib.sha256).hexdigest()
        return ReauthorizationGrant(
            grant_id=grant_id,
            protected_object=protected_object,
            previous_epoch=previous_epoch,
            new_epoch=new_epoch,
            new_cap_bits=cap,
            new_cap_units=cap_units,
            authorizer_identity=authorizer_identity,
            signature=signature,
        )

    def redeem_reauthorization(
        self, grant: ReauthorizationGrant,
    ) -> None:
        if not isinstance(grant, ReauthorizationGrant):
            raise SluiceV2Error("invalid reauthorization grant type")
        if (
            isinstance(grant.previous_epoch, bool)
            or isinstance(grant.new_epoch, bool)
            or not isinstance(grant.previous_epoch, int)
            or not isinstance(grant.new_epoch, int)
            or grant.previous_epoch < 0
            or grant.new_epoch != grant.previous_epoch + 1
        ):
            raise SluiceV2Error("reauthorization must advance a non-negative epoch by one")
        _require_finite_nonnegative(grant.new_cap_bits, "new_cap_bits")
        if (
            isinstance(grant.new_cap_units, bool)
            or not isinstance(grant.new_cap_units, int)
            or grant.new_cap_units < 0
            or grant.new_cap_bits != units_to_bits(grant.new_cap_units)
        ):
            raise TamperViolation("reauthorization grant has inconsistent exact cap units")
        _require_nfc_tree({
            "grant_id": grant.grant_id,
            "protected_object": grant.protected_object,
            "authorizer_identity": grant.authorizer_identity,
            "signature": grant.signature,
        }, "reauthorization grant")
        authorizer_key = self._trusted_authorizer_keys.get(grant.authorizer_identity)
        if authorizer_key is None:
            raise ProvenanceViolation(f"unknown reauthorization authority {grant.authorizer_identity!r}")
        payload = canonical_bytes({
            "record_format_version": RECORD_FORMAT_VERSION,
            "grant_id": grant.grant_id, "protected_object": grant.protected_object,
            "previous_epoch": grant.previous_epoch, "new_epoch": grant.new_epoch,
            "new_cap_bits": grant.new_cap_bits, "new_cap_units": grant.new_cap_units,
            "authorizer_identity": grant.authorizer_identity,
        })
        expected = hmac.new(authorizer_key, DOMAIN_GRANT + payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, grant.signature):
            raise TamperViolation(
                f"reauthorization grant {grant.grant_id!r}: signature verification failed"
            )
        self._store.redeem_grant(
            grant.grant_id,
            grant.protected_object,
            grant.previous_epoch,
            grant.new_epoch,
            grant.new_cap_units,
            grant.authorizer_identity,
            grant.signature,
        )

    # ---- agent-identity call authentication (\S\ref{sec:multiagent}) ----
    @staticmethod
    def _content_digest(content: str) -> str:
        if not isinstance(content, str):
            raise SluiceV2Error("content to digest must be a string")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _args_digest(args: Optional[Mapping[str, str]]) -> str:
        normalized = dict(args) if args else {}
        return hashlib.sha256(canonical_bytes(normalized)).hexdigest()

    def issue_call_credential(
        self,
        agent_id: str,
        agent_key: bytes,
        gate_id: str,
        workflow_id: str,
        epoch: int,
        content: str,
        args: Optional[Mapping[str, str]] = None,
        ttl_seconds: float = 300.0,
    ) -> CallerCredential:
        """Sign a fresh, request-bound proof that the caller holding
        ``agent_key`` is ``agent_id``, submitting exactly this ``content``
        and ``args`` against this ``gate_id``/``workflow_id``/``epoch``,
        valid for ``ttl_seconds``. Called by the agent's own process (which
        alone holds ``agent_key``); the monitor only ever verifies, via its
        own registered copy in ``agent_keys``, never signs on an agent's
        behalf. Digests, not raw content, are signed -- the credential does
        not itself carry the secret-dependent content, only a commitment to
        it verified against what ``invoke()`` actually receives."""
        if not isinstance(agent_key, bytes) or len(agent_key) < 16:
            raise SluiceV2Error("agent_key must contain at least 128 bits")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise SluiceV2Error("epoch must be a non-negative integer")
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise SluiceV2Error("ttl_seconds must be a finite positive number")
        _require_nfc_tree(
            {"agent_id": agent_id, "gate_id": gate_id, "workflow_id": workflow_id},
            "caller credential",
        )
        content_digest = self._content_digest(content)
        args_digest = self._args_digest(args)
        nonce = secrets.token_hex(16)
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds
        payload = canonical_bytes({
            "agent_id": agent_id,
            "gate_id": gate_id,
            "workflow_id": workflow_id,
            "epoch": epoch,
            "content_digest": content_digest,
            "args_digest": args_digest,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
        })
        signature = hmac.new(agent_key, DOMAIN_CALL + payload, hashlib.sha256).hexdigest()
        return CallerCredential(
            agent_id=agent_id,
            gate_id=gate_id,
            workflow_id=workflow_id,
            epoch=epoch,
            content_digest=content_digest,
            args_digest=args_digest,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

    def _verify_call_credential(
        self,
        credential: CallerCredential,
        gate_id: str,
        workflow_id: str,
        epoch: int,
        content: str,
        args: Optional[Mapping[str, str]],
    ) -> bool:
        """Pure check: signature, freshness window, and that every bound
        field matches both the server-committed values the caller passes in
        and the request actually being processed. Does not consume the
        nonce -- callers that accept the credential on this check's
        strength must separately call ``self._store.consume_call_nonce``
        before relying on it, so a credential presented twice concurrently
        cannot both pass this read-only check and then both be treated as
        fresh. Takes scalars rather than a ``GateRecord`` so the same
        primitive covers both gate invocation (``gate_id``/``workflow_id``/
        ``epoch`` from the record; ``content``/``args`` the untrusted
        request) and action-capability redemption (``workflow_id=""`` --
        ``Observation`` carries no workflow_id to check; ``content`` is the
        capability_id being redeemed, ``args`` the authorized arguments)."""
        if not isinstance(credential, CallerCredential):
            return False
        if (
            credential.gate_id != gate_id
            or credential.workflow_id != workflow_id
            or credential.epoch != epoch
        ):
            return False
        now = time.time()
        if not (
            math.isfinite(credential.issued_at)
            and math.isfinite(credential.expires_at)
            and credential.issued_at <= credential.expires_at
            and credential.issued_at - _CLOCK_SKEW_TOLERANCE_SECONDS <= now <= credential.expires_at
        ):
            return False
        if credential.content_digest != self._content_digest(content):
            return False
        if credential.args_digest != self._args_digest(args):
            return False
        key = self._agent_keys.get(credential.agent_id)
        if key is None:
            return False
        payload = canonical_bytes({
            "agent_id": credential.agent_id,
            "gate_id": credential.gate_id,
            "workflow_id": credential.workflow_id,
            "epoch": credential.epoch,
            "content_digest": credential.content_digest,
            "args_digest": credential.args_digest,
            "nonce": credential.nonce,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
        })
        expected = hmac.new(key, DOMAIN_CALL + payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, credential.signature)

    # ---- single-hop delegation (\S\ref{sec:multiagent}) ------------------
    def issue_delegation(
        self,
        delegator_agent_id: str,
        delegator_key: bytes,
        delegate_agent_id: str,
        gate_id: str,
        expiration: Optional[float] = None,
    ) -> DelegationGrant:
        """Let ``delegate_agent_id`` invoke one specific ``gate_id`` on
        ``delegator_agent_id``'s behalf. Signed by the delegator (who must
        hold a key the monitor trusts and, at redemption time, must
        actually be one of the gate's ``permitted_callers`` -- delegating
        authority you do not yourself hold is rejected at redemption, not
        merely left unenforced, which is what rules out laundering an
        unauthorized agent's request through a delegation chain)."""
        if not isinstance(delegator_key, bytes) or len(delegator_key) < 16:
            raise SluiceV2Error("delegator_key must contain at least 128 bits")
        if expiration is not None:
            if isinstance(expiration, bool) or not isinstance(expiration, (int, float)):
                raise SluiceV2Error("expiration must be a finite timestamp or None")
            expiration = float(expiration)
            if not math.isfinite(expiration):
                raise SluiceV2Error("expiration must be a finite timestamp or None")
        _require_nfc_tree({
            "delegator_agent_id": delegator_agent_id,
            "delegate_agent_id": delegate_agent_id,
            "gate_id": gate_id,
        }, "delegation grant")
        grant_id = secrets.token_hex(16)
        payload = canonical_bytes({
            "grant_id": grant_id,
            "delegator_agent_id": delegator_agent_id,
            "delegate_agent_id": delegate_agent_id,
            "gate_id": gate_id,
            "expiration": expiration,
        })
        signature = hmac.new(
            delegator_key, DOMAIN_DELEGATION + payload, hashlib.sha256
        ).hexdigest()
        return DelegationGrant(
            grant_id=grant_id,
            delegator_agent_id=delegator_agent_id,
            delegate_agent_id=delegate_agent_id,
            gate_id=gate_id,
            expiration=expiration,
            signature=signature,
        )

    def _verify_delegation_signature(self, delegation: DelegationGrant) -> bool:
        key = self._agent_keys.get(delegation.delegator_agent_id)
        if key is None:
            return False
        payload = canonical_bytes({
            "grant_id": delegation.grant_id,
            "delegator_agent_id": delegation.delegator_agent_id,
            "delegate_agent_id": delegation.delegate_agent_id,
            "gate_id": delegation.gate_id,
            "expiration": delegation.expiration,
        })
        expected = hmac.new(
            key, DOMAIN_DELEGATION + payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, delegation.signature)

    def spent(self, protected_object: str, epoch: int) -> float:
        return self._store.spent(protected_object, epoch)

    def spent_units(self, protected_object: str, epoch: int) -> int:
        return self._store.spent_units(protected_object, epoch)

    def lifetime_spent(self, protected_object: str) -> float:
        return self._store.lifetime_spent(protected_object)

    def lifetime_spent_units(self, protected_object: str) -> int:
        return self._store.lifetime_spent_units(protected_object)
