"""Sealed, fixed-horizon secure domains with a complete public transcript.

The API in this module is intentionally additive: it does not wrap or weaken
the legacy reference monitor.  Configuration and backend state remain private;
the only observer-visible results are finite :mod:`sluice_v2.observer` events.

This is deliberately an in-memory, single-process prototype.  Its lock and
immutable setup objects do not provide crash durability, process isolation,
kernel mediation, or an end-to-end G2 security boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
from typing import Any, Callable, Mapping

from .observer import (
    TRANSCRIPT_SCHEMA_VERSION,
    EventKind,
    OutcomeCode,
    TranscriptEvent,
)


class DomainLifecycleError(RuntimeError):
    """Raised when a trusted lifecycle operation is out of order."""


class DomainState(str, Enum):
    DRAFT = "draft"
    SEALED = "sealed"
    ACTIVE = "active"
    CLOSED = "closed"


MAX_SECURE_INTEGER = (1 << 63) - 1
MAX_ATTEMPT_HORIZON = 1_000_000
MAX_ROUTES = 4_096
MAX_PUBLIC_VALUES_PER_ROUTE = 65_536
MAX_IDENTIFIER_BYTES = 256
MAX_PAYLOAD_BYTES = 1_048_576
MAX_PAYLOAD_DEPTH = 64
MAX_PAYLOAD_ITEMS = 100_000


def _is_int(value: object) -> bool:
    return type(value) is int


def _positive_int(name: str, value: object) -> int:
    if not _is_int(value):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    if value > MAX_SECURE_INTEGER:
        raise ValueError(f"{name} exceeds the supported bound")
    return value


def _identifier(name: str, value: object) -> str:
    if type(value) is not str:
        raise TypeError(f"{name} must be a string")
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise ValueError(f"{name} exceeds the supported length")
    return value


def _key_bytes(name: str, value: object) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be bytes")
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value) < 16:
        raise ValueError(f"{name} must contain at least 128 bits")
    return value


def _canonical_payload(payload: Any) -> bytes:
    """Return an injective, bounded, type-tagged payload representation."""

    item_count = 0

    def encode(value: Any, depth: int) -> object:
        nonlocal item_count
        if depth > MAX_PAYLOAD_DEPTH:
            raise TypeError("payload exceeds the supported nesting depth")
        item_count += 1
        if item_count > MAX_PAYLOAD_ITEMS:
            raise TypeError("payload exceeds the supported item count")
        if value is None:
            return ["null"]
        if type(value) is bool:
            return ["bool", value]
        if type(value) is int:
            if not -MAX_SECURE_INTEGER <= value <= MAX_SECURE_INTEGER:
                raise TypeError("payload integer exceeds the supported bound")
            return ["int", str(value)]
        if type(value) is float:
            if not math.isfinite(value):
                raise TypeError("payload contains a non-finite number")
            return ["float", value.hex()]
        if type(value) is str:
            if len(value.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                raise TypeError("payload string exceeds the supported bound")
            return ["string", value]
        if type(value) is list:
            return ["list", [encode(item, depth + 1) for item in value]]
        if type(value) is tuple:
            return ["tuple", [encode(item, depth + 1) for item in value]]
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise TypeError("payload object keys must be strings")
            return [
                "object",
                [[key, encode(value[key], depth + 1)] for key in sorted(value)],
            ]
        raise TypeError("payload contains an unsupported value type")

    encoded = json.dumps(
        encode(payload, 0),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise TypeError("canonical payload exceeds the supported byte size")
    return encoded


def _payload_hash(payload: Any) -> str:
    return hashlib.sha256(_canonical_payload(payload)).hexdigest()


def _decode_canonical_payload(canonical_payload: bytes) -> Any:
    """Reconstruct the exact private snapshot authenticated by a caller."""

    encoded = json.loads(canonical_payload.decode("ascii"))

    def decode(value: object) -> Any:
        if type(value) is not list or not value or type(value[0]) is not str:
            raise ValueError("canonical payload snapshot is malformed")
        tag = value[0]
        if tag == "null" and len(value) == 1:
            return None
        if tag == "bool" and len(value) == 2 and type(value[1]) is bool:
            return value[1]
        if tag == "int" and len(value) == 2 and type(value[1]) is str:
            return int(value[1])
        if tag == "float" and len(value) == 2 and type(value[1]) is str:
            return float.fromhex(value[1])
        if tag == "string" and len(value) == 2 and type(value[1]) is str:
            return value[1]
        if tag in ("list", "tuple") and len(value) == 2 and type(value[1]) is list:
            items = [decode(item) for item in value[1]]
            return items if tag == "list" else tuple(items)
        if tag == "object" and len(value) == 2 and type(value[1]) is list:
            result: dict[str, Any] = {}
            for pair in value[1]:
                if (
                    type(pair) is not list
                    or len(pair) != 2
                    or type(pair[0]) is not str
                    or pair[0] in result
                ):
                    raise ValueError("canonical payload object is malformed")
                result[pair[0]] = decode(pair[1])
            return result
        raise ValueError("canonical payload tag is malformed")

    return decode(encoded)


def _mac(key: bytes, purpose: bytes, fields: tuple[str, ...]) -> str:
    body = json.dumps(fields, ensure_ascii=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hmac.new(key, purpose + b"\x00" + body, hashlib.sha256).hexdigest()


class _OpaqueHandle:
    """A serializable bearer handle whose representation never reveals it."""

    __slots__ = ("_wire",)
    _prefix = ""

    def __init__(self, wire: str) -> None:
        if type(wire) is not str:
            raise TypeError("opaque handle must be a string")
        if not wire.startswith(self._prefix):
            raise ValueError("malformed opaque handle")
        suffix = wire[len(self._prefix) :]
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", suffix) is None:
            raise ValueError("malformed opaque handle")
        self._wire = wire

    @classmethod
    def _new(cls):
        return cls(cls._prefix + secrets.token_urlsafe(32))

    @classmethod
    def from_wire(cls, wire: str):
        return cls(wire)

    def to_wire(self) -> str:
        return self._wire

    def __repr__(self) -> str:
        return f"<{type(self).__name__} opaque>"

    def __hash__(self) -> int:
        return hash((type(self), self._wire))

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and hmac.compare_digest(
            self._wire, other._wire
        )


class RouteToken(_OpaqueHandle):
    """Opaque, domain-bound route handle."""

    _prefix = "sluice-route-v1."


class EffectCapability(_OpaqueHandle):
    """Opaque, one-use capability delivered only to an effect broker."""

    _prefix = "sluice-effect-v1."


@dataclass(frozen=True, slots=True, repr=False)
class AttemptCredential:
    """Caller-signed binding of an agent, route, nonce, and exact payload."""

    agent_id: str
    route_handle: str
    nonce: str
    signature: str

    def __repr__(self) -> str:
        return "<AttemptCredential opaque>"

    @classmethod
    def sign(
        cls,
        *,
        agent_id: str,
        signing_key: bytes,
        route: RouteToken,
        payload: Any,
        nonce: str,
    ) -> "AttemptCredential":
        agent_id = _identifier("agent_id", agent_id)
        signing_key = _key_bytes("signing_key", signing_key)
        if type(route) is not RouteToken:
            raise TypeError("route must be a RouteToken")
        nonce = _identifier("nonce", nonce)
        route_handle = route.to_wire()
        digest = _payload_hash(payload)
        signature = _mac(
            signing_key,
            b"sluice-attempt-credential-v1",
            (agent_id, route_handle, digest, nonce),
        )
        return cls(
            agent_id=agent_id,
            route_handle=route_handle,
            nonce=nonce,
            signature=signature,
        )


@dataclass(frozen=True, slots=True)
class ReauthorizationGrant:
    """Authority-signed, one-use additive budget and horizon grant."""

    authorizer_id: str
    domain_context: str
    budget_increment_units: int
    attempt_increment: int
    nonce: str
    signature: str

    @classmethod
    def sign(
        cls,
        *,
        authorizer_id: str,
        signing_key: bytes,
        domain_context: str,
        budget_increment_units: int,
        attempt_increment: int,
        nonce: str,
    ) -> "ReauthorizationGrant":
        authorizer_id = _identifier("authorizer_id", authorizer_id)
        signing_key = _key_bytes("signing_key", signing_key)
        domain_context = _identifier("domain_context", domain_context)
        budget_increment_units = _positive_int(
            "budget_increment_units", budget_increment_units
        )
        attempt_increment = _positive_int("attempt_increment", attempt_increment)
        nonce = _identifier("nonce", nonce)
        signature = _mac(
            signing_key,
            b"sluice-reauthorization-v1",
            (
                authorizer_id,
                domain_context,
                str(budget_increment_units),
                str(attempt_increment),
                nonce,
            ),
        )
        return cls(
            authorizer_id=authorizer_id,
            domain_context=domain_context,
            budget_increment_units=budget_increment_units,
            attempt_increment=attempt_increment,
            nonce=nonce,
            signature=signature,
        )


@dataclass(frozen=True, slots=True)
class DomainConfig:
    """Trusted configuration for one correlated secrecy domain."""

    domain_id: str
    protected_objects: frozenset[str]
    lifetime_budget_units: int
    attempt_horizon: int
    event_charge_units: int

    def __post_init__(self) -> None:
        _identifier("domain_id", self.domain_id)
        if type(self.protected_objects) is not frozenset:
            raise TypeError("protected_objects must be a frozenset")
        if not self.protected_objects:
            raise ValueError("protected_objects must not be empty")
        for protected_object in self.protected_objects:
            _identifier("protected object", protected_object)
        _positive_int("lifetime_budget_units", self.lifetime_budget_units)
        _positive_int("attempt_horizon", self.attempt_horizon)
        _positive_int("event_charge_units", self.event_charge_units)
        if self.attempt_horizon > MAX_ATTEMPT_HORIZON:
            raise ValueError("attempt_horizon exceeds the maximum padding bound")
        required = self.attempt_horizon * self.event_charge_units
        if required > MAX_SECURE_INTEGER:
            raise ValueError("horizon and charge exceed the accounting bound")


@dataclass(frozen=True, slots=True)
class ReauthorizationPolicy:
    """One public, immutable additive grant shape for this domain."""

    budget_increment_units: int
    attempt_increment: int

    def __post_init__(self) -> None:
        _positive_int("budget_increment_units", self.budget_increment_units)
        attempts = _positive_int("attempt_increment", self.attempt_increment)
        if attempts > MAX_ATTEMPT_HORIZON:
            raise ValueError("attempt_increment exceeds the maximum padding bound")


@dataclass(frozen=True, slots=True)
class RouteCodebook:
    """One route's public release alphabet, fixed before handler attachment."""

    name: str
    public_values: frozenset[int]
    requires_capability: bool = False

    def __post_init__(self) -> None:
        _identifier("route codebook name", self.name)
        if type(self.public_values) is not frozenset or not self.public_values:
            raise TypeError("route codebook values must be a nonempty frozenset")
        if len(self.public_values) > MAX_PUBLIC_VALUES_PER_ROUTE:
            raise ValueError("route codebook alphabet exceeds the supported bound")
        if any(
            type(value) is not int or not 0 <= value <= MAX_SECURE_INTEGER
            for value in self.public_values
        ):
            raise TypeError(
                "route codebook values must be bounded nonnegative integers"
            )
        if type(self.requires_capability) is not bool:
            raise TypeError("route codebook capability flag must be a boolean")


def _route_codebooks_json(codebooks: tuple[RouteCodebook, ...]) -> str:
    return json.dumps(
        [
            {
                "name": codebook.name,
                "public_values": sorted(codebook.public_values),
                "requires_capability": codebook.requires_capability,
            }
            for codebook in codebooks
        ],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _route_codebook_sha256(encoded: str) -> str:
    return hashlib.sha256(
        b"sluice-inmemory-route-codebook-v1\x00" + encoded.encode("ascii")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ObserverSpec:
    """Immutable finite observer alphabet committed before protected handlers."""

    permitted_value_codes: frozenset[int]
    observer_spec_id: str
    route_codebooks: tuple[RouteCodebook, ...]
    accounting_units_per_bit: int = 1
    codebook_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.permitted_value_codes) is not frozenset:
            raise TypeError("permitted_value_codes must be a frozenset")
        if not self.permitted_value_codes:
            raise ValueError("permitted_value_codes must not be empty")
        if len(self.permitted_value_codes) > MAX_PUBLIC_VALUES_PER_ROUTE:
            raise ValueError("observer value alphabet exceeds the supported bound")
        if any(
            type(value) is not int or not 0 <= value <= MAX_SECURE_INTEGER
            for value in self.permitted_value_codes
        ):
            raise TypeError("observer value codes must be bounded integers")
        _identifier("observer_spec_id", self.observer_spec_id)
        if type(self.route_codebooks) is not tuple or not self.route_codebooks:
            raise TypeError("route_codebooks must be a nonempty tuple")
        if len(self.route_codebooks) > MAX_ROUTES:
            raise ValueError("route codebook exceeds the maximum route count")
        if any(
            type(codebook) is not RouteCodebook
            for codebook in self.route_codebooks
        ):
            raise TypeError("route_codebooks must contain RouteCodebook values")
        canonical = tuple(
            sorted(self.route_codebooks, key=lambda codebook: codebook.name)
        )
        if len({codebook.name for codebook in canonical}) != len(canonical):
            raise ValueError("route codebook names must be unique")
        if any(
            not codebook.public_values.issubset(self.permitted_value_codes)
            for codebook in canonical
        ):
            raise ValueError("route codebook values are outside the ObserverSpec")
        _positive_int("accounting_units_per_bit", self.accounting_units_per_bit)
        encoded = _route_codebooks_json(canonical)
        object.__setattr__(self, "route_codebooks", canonical)
        object.__setattr__(self, "codebook_sha256", _route_codebook_sha256(encoded))


@dataclass(frozen=True, slots=True)
class _RouteRecord:
    name: str
    protected_object: str
    handler: Callable[[Any], Any]
    public_values: frozenset[int]
    requires_capability: bool


class SecureDomain:
    """A sealed correlated domain with a fixed, completely charged horizon."""

    def __init__(
        self,
        config: DomainConfig,
        *,
        observer_spec: ObserverSpec,
        agent_keys: Mapping[str, bytes],
        reauthorization_keys: Mapping[str, bytes],
        reauthorization_policy: ReauthorizationPolicy | None = None,
    ) -> None:
        if type(config) is not DomainConfig:
            raise TypeError("config must be a DomainConfig")
        if type(observer_spec) is not ObserverSpec:
            raise TypeError("observer_spec must be an ObserverSpec")
        if (
            reauthorization_policy is not None
            and type(reauthorization_policy) is not ReauthorizationPolicy
        ):
            raise TypeError(
                "reauthorization_policy must be a ReauthorizationPolicy or null"
            )
        if reauthorization_policy is not None:
            added_funding = (
                reauthorization_policy.attempt_increment
                * config.event_charge_units
            )
            if reauthorization_policy.budget_increment_units < added_funding:
                raise ValueError(
                    "reauthorization policy does not fund every added attempt"
                )
            if (
                config.attempt_horizon
                + reauthorization_policy.attempt_increment
                > MAX_ATTEMPT_HORIZON
            ):
                raise ValueError(
                    "reauthorization policy cannot fit the maximum padding bound"
                )
            if (
                config.lifetime_budget_units
                + reauthorization_policy.budget_increment_units
                > MAX_SECURE_INTEGER
            ):
                raise ValueError(
                    "reauthorization policy cannot fit the accounting bound"
                )
        self._config = config
        self._observer_spec = observer_spec
        self._route_codebooks_by_name = {
            codebook.name: codebook for codebook in observer_spec.route_codebooks
        }
        self._reauthorization_policy = reauthorization_policy
        self._agent_keys = self._copy_keys("agent_keys", agent_keys)
        self._reauthorization_keys = self._copy_keys(
            "reauthorization_keys", reauthorization_keys
        )
        self._state = DomainState.DRAFT
        self._routes: dict[str, _RouteRecord] = {}
        self._route_names: set[str] = set()
        self._capabilities: dict[str, str] = {}
        self._used_credentials: set[tuple[str, str]] = set()
        self._used_grants: set[tuple[str, str]] = set()
        self._transcript: list[TranscriptEvent] = []
        self._attempts_used = 0
        self._lifetime_spent_units = 0
        self._lifetime_budget_units = config.lifetime_budget_units
        self._attempt_horizon = config.attempt_horizon
        self._reauthorization_context = (
            "sluice-reauth-context-v1." + secrets.token_urlsafe(32)
        )
        self._closed_reply: TranscriptEvent | None = None
        self._in_handler = False
        self._lock = threading.RLock()

    @staticmethod
    def _copy_keys(name: str, keys: Mapping[str, bytes]) -> dict[str, bytes]:
        if not isinstance(keys, Mapping):
            raise TypeError(f"{name} must be a mapping")
        copied: dict[str, bytes] = {}
        for identity, key in keys.items():
            copied[_identifier(f"{name} identity", identity)] = _key_bytes(
                f"{name} key", key
            )
        return copied

    @property
    def state(self) -> DomainState:
        return self._state

    @property
    def transcript(self) -> tuple[TranscriptEvent, ...]:
        with self._lock:
            return tuple(self._transcript)

    @property
    def attempts_used(self) -> int:
        return self._attempts_used

    @property
    def lifetime_spent_units(self) -> int:
        return self._lifetime_spent_units

    @property
    def lifetime_budget_units(self) -> int:
        return self._lifetime_budget_units

    @property
    def attempt_horizon(self) -> int:
        return self._attempt_horizon

    @property
    def event_charge_units(self) -> int:
        return self._config.event_charge_units

    @property
    def observer_spec_id(self) -> str:
        return self._observer_spec.observer_spec_id

    @property
    def codebook_sha256(self) -> str:
        return self._observer_spec.codebook_sha256

    @property
    def route_codebooks(self) -> tuple[RouteCodebook, ...]:
        return self._observer_spec.route_codebooks

    @property
    def reauthorization_policy(self) -> ReauthorizationPolicy | None:
        """Return the fixed public grant shape, or null when reauth is disabled."""

        return self._reauthorization_policy

    @property
    def reauthorization_context(self) -> str:
        return self._reauthorization_context

    def register_route(
        self,
        *,
        name: str,
        protected_object: str,
        handler: Callable[[Any], Any],
        public_values: frozenset[int] = frozenset(),
        requires_capability: bool = False,
    ) -> RouteToken:
        """Register private route metadata while the domain is still DRAFT."""

        with self._lock:
            self._require_state(DomainState.DRAFT, "register routes")
            name = _identifier("route name", name)
            protected_object = _identifier("protected_object", protected_object)
            if protected_object not in self._config.protected_objects:
                raise ValueError("route object is outside the protected domain")
            if not callable(handler):
                raise TypeError("handler must be callable")
            if type(public_values) is not frozenset:
                raise TypeError("public_values must be a frozenset")
            if not public_values:
                raise ValueError("public_values must be a nonempty finite alphabet")
            if any(not _is_int(value) or value < 0 for value in public_values):
                raise TypeError("public_values must contain nonnegative integers")
            if type(requires_capability) is not bool:
                raise TypeError("requires_capability must be a boolean")
            if name in self._route_names:
                raise ValueError("route names must be unique within a domain")
            if len(self._routes) >= MAX_ROUTES:
                raise ValueError("domain exceeds the maximum route count")
            if len(public_values) > MAX_PUBLIC_VALUES_PER_ROUTE:
                raise ValueError("route public alphabet exceeds the maximum size")
            if any(value > MAX_SECURE_INTEGER for value in public_values):
                raise ValueError("route public value exceeds the supported bound")
            codebook = self._route_codebooks_by_name.get(name)
            if (
                codebook is None
                or public_values != codebook.public_values
                or requires_capability != codebook.requires_capability
            ):
                raise ValueError(
                    "route does not exactly match the precommitted public codebook"
                )
            if not public_values.issubset(
                self._observer_spec.permitted_value_codes
            ):
                raise ValueError("route values are outside the ObserverSpec")
            route = RouteToken._new()
            self._routes[route.to_wire()] = _RouteRecord(
                name=name,
                protected_object=protected_object,
                handler=handler,
                public_values=codebook.public_values,
                requires_capability=codebook.requires_capability,
            )
            self._route_names.add(name)
            return route

    def issue_capability(self, route: RouteToken) -> EffectCapability:
        """Create a hidden, one-use capability during trusted setup."""

        with self._lock:
            self._require_state(DomainState.DRAFT, "issue capabilities")
            route_handle = self._known_route_handle(route)
            if route_handle is None:
                raise ValueError("route does not belong to this domain")
            if not self._routes[route_handle].requires_capability:
                raise ValueError("route does not require an effect capability")
            capability = EffectCapability._new()
            self._capabilities[capability.to_wire()] = route_handle
            return capability

    def seal(self) -> None:
        with self._lock:
            self._require_state(DomainState.DRAFT, "seal domain")
            actual_codebooks = tuple(
                sorted(
                    (
                        RouteCodebook(
                            name=record.name,
                            public_values=record.public_values,
                            requires_capability=record.requires_capability,
                        )
                        for record in self._routes.values()
                    ),
                    key=lambda codebook: codebook.name,
                )
            )
            if actual_codebooks != self._observer_spec.route_codebooks:
                raise ValueError(
                    "registered routes do not match the complete precommitted codebook"
                )
            # This conservatively includes a route-specific release/denial
            # support plus CONTINUE, STOP, and both REAUTHORIZE outcomes.
            support = 4 + sum(
                len(record.public_values) + 5 for record in self._routes.values()
            )
            required_charge = (
                (support - 1).bit_length()
                * self._observer_spec.accounting_units_per_bit
            )
            if self.event_charge_units < required_charge:
                raise ValueError(
                    "event charge is below the sealed ObserverSpec support bound"
                )
            required = self._attempt_horizon * self.event_charge_units
            if self._lifetime_budget_units < required:
                raise ValueError(
                    "lifetime budget must fund every horizon slot at fixed charge"
                )
            self._state = DomainState.SEALED

    def activate(self) -> None:
        with self._lock:
            self._require_state(DomainState.SEALED, "activate domain")
            self._state = DomainState.ACTIVE

    def attempt(
        self,
        route: RouteToken,
        payload: Any,
        *,
        credential: AttemptCredential | None,
        capability: EffectCapability | None = None,
    ) -> TranscriptEvent:
        """Charge a slot, then authenticate and execute a private route."""

        self._reject_cross_thread_reentry()
        with self._lock:
            closed = self._begin_operation()
            if closed is not None:
                return closed
            self._reserve_slot()

            route_handle = self._known_route_handle(route)
            if route_handle is None:
                return self._append_and_maybe_close(
                    EventKind.ATTEMPT, OutcomeCode.ROUTE_DENIED
                )
            record = self._routes[route_handle]
            validated_credential = self._validate_attempt_credential(
                route_handle, payload, credential
            )
            if validated_credential is None:
                return self._append_and_maybe_close(
                    EventKind.ATTEMPT, OutcomeCode.AUTH_DENIED
                )
            replay_key, handler_payload = validated_credential
            capability_handle = self._validate_capability(
                route_handle, record.requires_capability, capability
            )
            if capability_handle is False:
                return self._append_and_maybe_close(
                    EventKind.ATTEMPT, OutcomeCode.CAPABILITY_DENIED
                )

            # The claim is now valid in full. Consume the credential and, when
            # required, the capability together before backend execution.
            self._used_credentials.add(replay_key)
            if type(capability_handle) is str:
                del self._capabilities[capability_handle]

            try:
                self._in_handler = True
                result = record.handler(handler_payload)
            except BaseException:
                return self._append_and_maybe_close(
                    EventKind.ATTEMPT, OutcomeCode.INTERNAL_DENIED
                )
            finally:
                self._in_handler = False
            if not _is_int(result) or result not in record.public_values:
                return self._append_and_maybe_close(
                    EventKind.ATTEMPT, OutcomeCode.OUTPUT_DENIED
                )
            return self._append_and_maybe_close(
                EventKind.ATTEMPT, OutcomeCode.RELEASED, value_code=result
            )

    def continue_work(self) -> TranscriptEvent:
        self._reject_cross_thread_reentry()
        with self._lock:
            closed = self._begin_operation()
            if closed is not None:
                return closed
            self._reserve_slot()
            return self._append_and_maybe_close(
                EventKind.CONTINUE, OutcomeCode.CONTINUED
            )

    def stop(self) -> TranscriptEvent:
        """Stop and deterministically fill every remaining charged slot."""

        self._reject_cross_thread_reentry()
        with self._lock:
            closed = self._begin_operation()
            if closed is not None:
                return closed
            self._reserve_slot()
            stopped = self._append_event(
                EventKind.STOP, OutcomeCode.STOPPED, terminal=True
            )
            while self._attempts_used < self._attempt_horizon:
                self._reserve_slot()
                self._append_event(
                    EventKind.PADDING, OutcomeCode.PADDED, terminal=True
                )
            self._close()
            return stopped

    def reauthorize(
        self, grant: ReauthorizationGrant | None
    ) -> TranscriptEvent:
        """Charge a slot, then validate and atomically apply an additive grant."""

        self._reject_cross_thread_reentry()
        with self._lock:
            closed = self._begin_operation()
            if closed is not None:
                return closed
            self._reserve_slot()
            accepted = self._validate_reauthorization(grant)
            if accepted is None:
                return self._append_and_maybe_close(
                    EventKind.REAUTHORIZE, OutcomeCode.REAUTH_DENIED
                )
            budget_increment, attempt_increment, replay_key = accepted
            policy = self._reauthorization_policy
            if (
                policy is None
                or budget_increment != policy.budget_increment_units
                or attempt_increment != policy.attempt_increment
            ):
                return self._append_and_maybe_close(
                    EventKind.REAUTHORIZE, OutcomeCode.REAUTH_DENIED
                )
            added_requirement = attempt_increment * self.event_charge_units
            if (
                added_requirement > MAX_SECURE_INTEGER
                or budget_increment < added_requirement
            ):
                return self._append_and_maybe_close(
                    EventKind.REAUTHORIZE, OutcomeCode.REAUTH_DENIED
                )
            proposed_budget = self._lifetime_budget_units + budget_increment
            proposed_horizon = self._attempt_horizon + attempt_increment
            if (
                proposed_budget > MAX_SECURE_INTEGER
                or proposed_horizon > MAX_ATTEMPT_HORIZON
                or proposed_horizon * self.event_charge_units > MAX_SECURE_INTEGER
                or proposed_budget < proposed_horizon * self.event_charge_units
            ):
                return self._append_and_maybe_close(
                    EventKind.REAUTHORIZE, OutcomeCode.REAUTH_DENIED
                )
            self._used_grants.add(replay_key)
            self._lifetime_budget_units = proposed_budget
            self._attempt_horizon = proposed_horizon
            return self._append_and_maybe_close(
                EventKind.REAUTHORIZE, OutcomeCode.REAUTHORIZED
            )

    def _require_state(self, expected: DomainState, operation: str) -> None:
        if self._state is not expected:
            raise DomainLifecycleError(
                f"cannot {operation} while domain is {self._state.value}"
            )

    def _reject_cross_thread_reentry(self) -> None:
        # A handler runs while holding the domain lock. Checking before lock
        # acquisition prevents a handler-created thread from merely queueing a
        # nested operation that executes after the handler returns.
        if self._in_handler:
            raise DomainLifecycleError("domain operations cannot be called by a handler")

    def _begin_operation(self) -> TranscriptEvent | None:
        if self._state is DomainState.CLOSED:
            assert self._closed_reply is not None
            return self._closed_reply
        if self._state is not DomainState.ACTIVE:
            raise DomainLifecycleError(
                f"domain operations require ACTIVE state, not {self._state.value}"
            )
        if self._in_handler:
            raise DomainLifecycleError("domain operations cannot be re-entered by a handler")
        return None

    def _reserve_slot(self) -> None:
        """Reserve both counters before any outcome-dependent computation."""

        if self._attempts_used >= self._attempt_horizon:
            raise RuntimeError("sealed domain horizon invariant violated")
        charge = self.event_charge_units
        if self._lifetime_spent_units + charge > self._lifetime_budget_units:
            raise RuntimeError("sealed domain budget invariant violated")
        self._attempts_used += 1
        self._lifetime_spent_units += charge

    def _known_route_handle(self, route: object) -> str | None:
        if type(route) is not RouteToken:
            return None
        handle = route.to_wire()
        return handle if handle in self._routes else None

    def _validate_attempt_credential(
        self,
        route_handle: str,
        payload: Any,
        credential: AttemptCredential | None,
    ) -> tuple[tuple[str, str], Any] | None:
        if type(credential) is not AttemptCredential:
            return None
        try:
            agent_id = _identifier("agent_id", credential.agent_id)
            nonce = _identifier("nonce", credential.nonce)
            if type(credential.route_handle) is not str:
                return None
            if type(credential.signature) is not str:
                return None
            key = self._agent_keys.get(agent_id)
            replay_key = (agent_id, nonce)
            if key is None or replay_key in self._used_credentials:
                return None
            canonical_payload = _canonical_payload(payload)
            digest = hashlib.sha256(canonical_payload).hexdigest()
            if not hmac.compare_digest(credential.route_handle, route_handle):
                return None
            expected = _mac(
                key,
                b"sluice-attempt-credential-v1",
                (agent_id, route_handle, digest, nonce),
            )
            if not hmac.compare_digest(credential.signature, expected):
                return None
            handler_payload = _decode_canonical_payload(canonical_payload)
        except (TypeError, ValueError):
            return None
        return replay_key, handler_payload

    def _validate_capability(
        self,
        route_handle: str,
        required: bool,
        capability: EffectCapability | None,
    ) -> str | None | bool:
        if capability is None:
            return None if not required else False
        if not required:
            return False
        if type(capability) is not EffectCapability:
            return False
        capability_handle = capability.to_wire()
        bound_route = self._capabilities.get(capability_handle)
        if bound_route is None or not hmac.compare_digest(bound_route, route_handle):
            return False
        return capability_handle

    def _validate_reauthorization(
        self, grant: ReauthorizationGrant | None
    ) -> tuple[int, int, tuple[str, str]] | None:
        if type(grant) is not ReauthorizationGrant:
            return None
        try:
            authorizer_id = _identifier("authorizer_id", grant.authorizer_id)
            nonce = _identifier("nonce", grant.nonce)
            domain_context = _identifier("domain_context", grant.domain_context)
            budget_increment = _positive_int(
                "budget_increment_units", grant.budget_increment_units
            )
            attempt_increment = _positive_int(
                "attempt_increment", grant.attempt_increment
            )
            if type(grant.signature) is not str:
                return None
            key = self._reauthorization_keys.get(authorizer_id)
            replay_key = (authorizer_id, nonce)
            if key is None or replay_key in self._used_grants:
                return None
            if not hmac.compare_digest(domain_context, self._reauthorization_context):
                return None
            expected = _mac(
                key,
                b"sluice-reauthorization-v1",
                (
                    authorizer_id,
                    domain_context,
                    str(budget_increment),
                    str(attempt_increment),
                    nonce,
                ),
            )
            if not hmac.compare_digest(grant.signature, expected):
                return None
        except (TypeError, ValueError):
            return None
        return budget_increment, attempt_increment, replay_key

    def _append_and_maybe_close(
        self,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        value_code: int | None = None,
    ) -> TranscriptEvent:
        terminal = self._attempts_used == self._attempt_horizon
        event = self._append_event(
            kind, outcome, value_code=value_code, terminal=terminal
        )
        if terminal:
            self._close()
        return event

    def _append_event(
        self,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        value_code: int | None = None,
        terminal: bool,
    ) -> TranscriptEvent:
        event = TranscriptEvent(
            schema_version=TRANSCRIPT_SCHEMA_VERSION,
            sequence=len(self._transcript) + 1,
            attempt=self._attempts_used,
            kind=kind,
            outcome=outcome,
            value_code=value_code,
            charge_units=self.event_charge_units,
            terminal=terminal,
        )
        self._transcript.append(event)
        return event

    def _close(self) -> None:
        self._state = DomainState.CLOSED
        self._closed_reply = TranscriptEvent(
            schema_version=TRANSCRIPT_SCHEMA_VERSION,
            sequence=len(self._transcript) + 1,
            attempt=self._attempts_used,
            kind=EventKind.DOMAIN_CLOSED,
            outcome=OutcomeCode.DOMAIN_CLOSED,
            value_code=None,
            charge_units=0,
            terminal=True,
        )
