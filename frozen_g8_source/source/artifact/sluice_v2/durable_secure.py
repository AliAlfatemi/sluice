"""SQLite-backed sealed secure domains.

This module is an additive durable counterpart to :mod:`sluice_v2.secure`.
Private identifiers, authorization state, audit records, and route metadata are
kept in the monitor database.  Its only public operation results are the
finite, versioned :class:`~sluice_v2.observer.TranscriptEvent` values.

The theorem-facing observer alphabet is not inferred from realized protected
state.  Schema 3 persists an immutable public route-codebook manifest before
handler attachment, and route registration must match it exactly.  One fixed
public reauthorization increment pair is optional; omitting it disables
successful reauthorization.

Backend functions are deliberately not serialized.  A route stores a stable
``handler_key`` and trusted code supplies a registry when creating or reopening
the service.  Same-process handlers are part of the trusted computing base;
untrusted model code must execute behind the separate process/IPC isolation
service.  Every operation opens its own SQLite connection; ``BEGIN IMMEDIATE``
therefore provides cross-thread and cross-process serialization of the
reservation/claim transaction.

SQLite WAL durability is accepted only on a verified local Linux filesystem.
The process-local response sequencer linearizes concurrent calls to one ledger.
Direct callers in different processes are supported for atomic-claim/recovery
tests, but their wall-clock return order is not a public-channel guarantee; the
deployed boundary is one singleton monitor process that serializes IPC replies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
from typing import Any, Callable, Mapping

from .observer import (
    TRANSCRIPT_SCHEMA_VERSION,
    EventKind,
    OutcomeCode,
    TranscriptEvent,
)
from .secure import (
    MAX_ATTEMPT_HORIZON,
    MAX_PUBLIC_VALUES_PER_ROUTE,
    MAX_ROUTES,
    MAX_SECURE_INTEGER,
    DomainConfig,
    DomainLifecycleError,
    DomainState,
    EffectCapability,
    RouteToken,
    _canonical_payload,
    _identifier,
    _key_bytes,
    _mac,
    _positive_int,
)


SCHEMA_VERSION = 3


_ACTIVE_OWNER_LOCK = threading.Lock()
_ACTIVE_OWNER_TOKENS: set[tuple[int, str]] = set()
_RUNTIME_REGISTRY_LOCK = threading.Lock()
_HANDLER_CONTEXT = threading.local()


class _LedgerRuntime:
    """Process-local sequencing and handler state for one durable ledger.

    SQLite supplies the durable transaction order.  This object supplies the
    distinct process-local response property that SQLite cannot express: no
    public response is linearized ahead of an earlier response.  Handler
    provenance is only thread-local in this direct-call module; callbacks are
    trusted, and cross-thread origin enforcement belongs to the isolated IPC
    service.
    """

    def __init__(self, next_delivery_sequence: int) -> None:
        self.condition = threading.Condition()
        self.next_delivery_sequence = next_delivery_sequence
        self.abandoned_deliveries: dict[int, int] = {}


_RUNTIME_BY_LEDGER: dict[tuple[str, str, str], _LedgerRuntime] = {}


_LOCAL_WAL_FILESYSTEMS = frozenset(
    {
        "btrfs",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "jfs",
        "nilfs2",
        "overlay",
        "ramfs",
        "reiserfs",
        "tmpfs",
        "xfs",
        "zfs",
    }
)


def _reset_process_local_state_after_fork() -> None:
    global _ACTIVE_OWNER_LOCK, _ACTIVE_OWNER_TOKENS, _RUNTIME_REGISTRY_LOCK
    global _RUNTIME_BY_LEDGER
    _ACTIVE_OWNER_LOCK = threading.Lock()
    _ACTIVE_OWNER_TOKENS = set()
    _RUNTIME_REGISTRY_LOCK = threading.Lock()
    _RUNTIME_BY_LEDGER = {}
    _HANDLER_CONTEXT.database_paths = set()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_process_local_state_after_fork)


def _decode_mount_path(value: str) -> str:
    """Decode the octal escapes used by Linux ``/proc/*/mountinfo``."""

    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _filesystem_type(path: str | os.PathLike[str]) -> str:
    """Return the longest-prefix Linux mount type, failing closed if unknown."""

    target = os.path.realpath(os.fspath(path))
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise DurableConfigurationError(
            "cannot verify that the durable ledger uses a local filesystem"
        ) from exc
    best: tuple[int, str] | None = None
    for line in lines:
        try:
            left, right = line.split(" - ", 1)
            mountpoint = _decode_mount_path(left.split()[4])
            filesystem = right.split()[0].lower()
            if os.path.commonpath((target, mountpoint)) != mountpoint:
                continue
        except (IndexError, ValueError):
            continue
        if best is None or len(mountpoint) > best[0]:
            best = (len(mountpoint), filesystem)
    if best is None:
        raise DurableConfigurationError(
            "cannot verify that the durable ledger uses a local filesystem"
        )
    return best[1]


def _require_local_wal_filesystem(path: str | os.PathLike[str]) -> None:
    filesystem = _filesystem_type(path)
    if filesystem not in _LOCAL_WAL_FILESYSTEMS:
        raise DurableConfigurationError(
            "SQLite WAL durable ledgers require a local filesystem; "
            f"refusing unverified filesystem {filesystem}"
        )


def _runtime_for_ledger(
    identity: tuple[str, str, str], next_delivery_sequence: int
) -> _LedgerRuntime:
    with _RUNTIME_REGISTRY_LOCK:
        runtime = _RUNTIME_BY_LEDGER.get(identity)
        if runtime is None:
            runtime = _LedgerRuntime(next_delivery_sequence)
            _RUNTIME_BY_LEDGER[identity] = runtime
        return runtime


def _safe_text_equal(left: object, right: object) -> bool:
    """Compare text without ``compare_digest``'s non-ASCII ``str`` trap."""

    if type(left) is not str or type(right) is not str:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _payload_digest(canonical_payload: bytes) -> str:
    return hashlib.sha256(canonical_payload).hexdigest()


def _decode_canonical_payload(canonical_payload: bytes) -> Any:
    """Reconstruct the exact type-tagged snapshot authenticated by a caller."""

    encoded = json.loads(canonical_payload.decode("ascii"))

    def decode(value: object) -> Any:
        if type(value) is not list or not value or type(value[0]) is not str:
            raise DurableConfigurationError("stored canonical payload is malformed")
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
                    raise DurableConfigurationError(
                        "stored canonical payload object is malformed"
                    )
                result[pair[0]] = decode(pair[1])
            return result
        raise DurableConfigurationError("stored canonical payload tag is malformed")

    return decode(encoded)


def _process_identity(pid: int | None = None) -> str:
    """Return a kernel-derived process incarnation, not a caller assertion."""

    selected_pid = os.getpid() if pid is None else pid
    try:
        stat = Path(f"/proc/{selected_pid}/stat").read_text(encoding="ascii")
        close = stat.rfind(")")
        if close < 0:
            raise ValueError("malformed proc stat")
        fields = stat[close + 2 :].split()
        # fields[0] is process state (field 3); fields[19] is starttime (field 22).
        if fields[0] in ("Z", "X"):
            raise ProcessLookupError(selected_pid)
        start_time = fields[19]
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
        return f"linux:{boot_id}:{selected_pid}:{start_time}"
    except (OSError, IndexError, ValueError):
        if selected_pid != os.getpid():
            # On non-Linux POSIX systems, fail safe on PID reuse: a live PID is
            # treated as the owner even though no incarnation counter exists.
            try:
                os.kill(selected_pid, 0)
            except ProcessLookupError:
                raise
            except PermissionError:
                pass
        return f"process:{selected_pid}"


def _owner_is_live(pid: int, process_identity: str, owner_token: str) -> bool:
    if pid == os.getpid():
        with _ACTIVE_OWNER_LOCK:
            return (pid, owner_token) in _ACTIVE_OWNER_TOKENS
    try:
        return _safe_text_equal(_process_identity(pid), process_identity)
    except ProcessLookupError:
        return False


@dataclass(frozen=True, slots=True, repr=False)
class AttemptCredential:
    """Durable v2 caller authorization, bound to context, epoch and expiry."""

    agent_id: str
    domain_context: str
    expected_epoch: int
    route_handle: str
    nonce: str
    expires_at_lifetime_attempt: int
    signature: str

    def __repr__(self) -> str:
        return "<DurableAttemptCredential v2 opaque>"

    @classmethod
    def sign(
        cls,
        *,
        agent_id: str,
        signing_key: bytes,
        domain_context: str,
        expected_epoch: int,
        route: RouteToken,
        payload: Any,
        nonce: str,
        expires_at_lifetime_attempt: int,
    ) -> "AttemptCredential":
        agent_id = _identifier("agent_id", agent_id)
        signing_key = _key_bytes("signing_key", signing_key)
        domain_context = _identifier("domain_context", domain_context)
        if (
            type(expected_epoch) is not int
            or expected_epoch < 0
            or expected_epoch > MAX_SECURE_INTEGER
        ):
            raise ValueError("expected_epoch must be a nonnegative integer")
        if type(route) is not RouteToken:
            raise TypeError("route must be a RouteToken")
        nonce = _identifier("nonce", nonce)
        expiry = _positive_int(
            "expires_at_lifetime_attempt", expires_at_lifetime_attempt
        )
        canonical = _canonical_payload(payload).decode("ascii")
        route_handle = route.to_wire()
        signature = _mac(
            signing_key,
            b"sluice-durable-attempt-credential-v2",
            (
                agent_id,
                domain_context,
                str(expected_epoch),
                route_handle,
                canonical,
                nonce,
                str(expiry),
            ),
        )
        return cls(
            agent_id=agent_id,
            domain_context=domain_context,
            expected_epoch=expected_epoch,
            route_handle=route_handle,
            nonce=nonce,
            expires_at_lifetime_attempt=expiry,
            signature=signature,
        )


@dataclass(frozen=True, slots=True)
class ReauthorizationGrant:
    """Durable v2 one-use additive grant with epoch and lifetime expiry."""

    authorizer_id: str
    domain_context: str
    expected_epoch: int
    budget_increment_units: int
    attempt_increment: int
    nonce: str
    expires_at_lifetime_attempt: int
    signature: str

    @classmethod
    def sign(
        cls,
        *,
        authorizer_id: str,
        signing_key: bytes,
        domain_context: str,
        expected_epoch: int,
        budget_increment_units: int,
        attempt_increment: int,
        nonce: str,
        expires_at_lifetime_attempt: int,
    ) -> "ReauthorizationGrant":
        authorizer_id = _identifier("authorizer_id", authorizer_id)
        signing_key = _key_bytes("signing_key", signing_key)
        domain_context = _identifier("domain_context", domain_context)
        if (
            type(expected_epoch) is not int
            or expected_epoch < 0
            or expected_epoch > MAX_SECURE_INTEGER
        ):
            raise ValueError("expected_epoch must be a nonnegative integer")
        budget = _positive_int("budget_increment_units", budget_increment_units)
        attempts = _positive_int("attempt_increment", attempt_increment)
        nonce = _identifier("nonce", nonce)
        expiry = _positive_int(
            "expires_at_lifetime_attempt", expires_at_lifetime_attempt
        )
        signature = _mac(
            signing_key,
            b"sluice-durable-reauthorization-v2",
            (
                authorizer_id,
                domain_context,
                str(expected_epoch),
                str(budget),
                str(attempts),
                nonce,
                str(expiry),
            ),
        )
        return cls(
            authorizer_id=authorizer_id,
            domain_context=domain_context,
            expected_epoch=expected_epoch,
            budget_increment_units=budget,
            attempt_increment=attempts,
            nonce=nonce,
            expires_at_lifetime_attempt=expiry,
            signature=signature,
        )


@dataclass(frozen=True, slots=True)
class EffectRequest:
    """Private, stable request passed across an idempotent effect boundary."""

    request_id: str
    fingerprint: str
    payload: Any


@dataclass(frozen=True, slots=True)
class EffectResult:
    """Broker-journal result explicitly linked to the private effect request."""

    request_id: str
    fingerprint: str
    value_code: int

    @classmethod
    def for_request(cls, request: EffectRequest, value_code: int) -> "EffectResult":
        if type(request) is not EffectRequest:
            raise TypeError("request must be an EffectRequest")
        if type(value_code) is not int:
            raise TypeError("value_code must be an integer")
        return cls(request.request_id, request.fingerprint, value_code)


@dataclass(frozen=True, slots=True)
class IdempotentEffectHandler:
    """Crash-reconciliation seam for an externally idempotent effect broker."""

    execute: Callable[[EffectRequest], EffectResult]
    reconcile: Callable[[EffectRequest], EffectResult | None]

    def __post_init__(self) -> None:
        if not callable(self.execute) or not callable(self.reconcile):
            raise TypeError("effect execute and reconcile hooks must be callable")


class DurableConfigurationError(RuntimeError):
    """Raised when persisted configuration cannot be safely rebound."""


class DurableDeliveryError(RuntimeError):
    """Finite transport failure after an immutable response was abandoned."""


@dataclass(frozen=True, slots=True)
class ReauthorizationPolicy:
    """One public, immutable additive grant shape for a durable domain."""

    budget_increment_units: int
    attempt_increment: int

    def __post_init__(self) -> None:
        _positive_int("budget_increment_units", self.budget_increment_units)
        attempts = _positive_int("attempt_increment", self.attempt_increment)
        if attempts > MAX_ATTEMPT_HORIZON:
            raise ValueError("attempt_increment exceeds the maximum padding bound")


@dataclass(frozen=True, slots=True)
class RouteCodebook:
    """One route's public, precommitted finite release alphabet."""

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
        b"sluice-durable-route-codebook-v1\x00" + encoded.encode("ascii")
    ).hexdigest()


def _decode_route_codebooks(encoded: object) -> tuple[RouteCodebook, ...]:
    if type(encoded) is not str:
        raise DurableConfigurationError("persisted route codebook is malformed")
    try:
        value = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise DurableConfigurationError(
            "persisted route codebook is malformed"
        ) from exc
    if type(value) is not list or not value:
        raise DurableConfigurationError("persisted route codebook is malformed")
    codebooks: list[RouteCodebook] = []
    try:
        for item in value:
            if type(item) is not dict or set(item) != {
                "name",
                "public_values",
                "requires_capability",
            }:
                raise DurableConfigurationError(
                    "persisted route codebook is malformed"
                )
            values = item["public_values"]
            if type(values) is not list:
                raise DurableConfigurationError(
                    "persisted route codebook is malformed"
                )
            codebooks.append(
                RouteCodebook(
                    name=item["name"],
                    public_values=frozenset(values),
                    requires_capability=item["requires_capability"],
                )
            )
    except (TypeError, ValueError) as exc:
        raise DurableConfigurationError(
            "persisted route codebook is malformed"
        ) from exc
    canonical = tuple(sorted(codebooks, key=lambda item: item.name))
    if (
        len({codebook.name for codebook in canonical}) != len(canonical)
        or _route_codebooks_json(canonical) != encoded
    ):
        raise DurableConfigurationError("persisted route codebook is malformed")
    return canonical


@dataclass(frozen=True, slots=True)
class ObserverSpec:
    """Sealed finite observer alphabet and accounting scale."""

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
        for value in self.permitted_value_codes:
            if type(value) is not int or not 0 <= value <= MAX_SECURE_INTEGER:
                raise TypeError("observer value codes must be bounded integers")
        _identifier("observer_spec_id", self.observer_spec_id)
        if type(self.route_codebooks) is not tuple or not self.route_codebooks:
            raise TypeError("route_codebooks must be a nonempty tuple")
        if len(self.route_codebooks) > MAX_ROUTES:
            raise ValueError("route codebook exceeds the maximum route count")
        if any(type(codebook) is not RouteCodebook for codebook in self.route_codebooks):
            raise TypeError("route_codebooks must contain RouteCodebook values")
        canonical = tuple(sorted(self.route_codebooks, key=lambda item: item.name))
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
class EpochStats:
    """Trusted durable accounting summary for one epoch."""

    epoch: int
    attempts: int
    spent_units: int
    horizon_limit: int
    budget_increment_units: int


def _copy_keys(name: str, keys: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(keys, Mapping):
        raise TypeError(f"{name} must be a mapping")
    copied: dict[str, bytes] = {}
    for identity, key in keys.items():
        copied[_identifier(f"{name} identity", identity)] = _key_bytes(
            f"{name} key", key
        )
    return copied


def _copy_handlers(
    handlers: Mapping[str, Callable[[Any], Any] | IdempotentEffectHandler],
) -> dict[str, Callable[[Any], Any] | IdempotentEffectHandler]:
    if not isinstance(handlers, Mapping):
        raise TypeError("handler_registry must be a mapping")
    copied: dict[str, Callable[[Any], Any] | IdempotentEffectHandler] = {}
    for key, handler in handlers.items():
        key = _identifier("handler key", key)
        if not callable(handler) and type(handler) is not IdempotentEffectHandler:
            raise TypeError(
                "handler registry values must be callable or IdempotentEffectHandler"
            )
        copied[key] = handler
    return copied


def _event_json(event: TranscriptEvent) -> str:
    return json.dumps(event.to_wire(), sort_keys=True, separators=(",", ":"))


def _event_from_json(encoded: str) -> TranscriptEvent:
    value = json.loads(encoded)
    if type(value) is not dict:
        raise DurableConfigurationError("persisted public event is malformed")
    return TranscriptEvent.from_wire(value)


_SCHEMA = """
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    domain_id TEXT NOT NULL,
    protected_objects_json TEXT NOT NULL,
    observer_values_json TEXT NOT NULL,
    observer_spec_id TEXT NOT NULL,
    route_codebooks_json TEXT NOT NULL,
    codebook_sha256 TEXT NOT NULL,
    units_per_bit INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('draft','sealed','active','closed')),
    event_charge_units INTEGER NOT NULL,
    lifetime_budget_units INTEGER NOT NULL,
    attempt_horizon INTEGER NOT NULL,
    lifetime_spent_units INTEGER NOT NULL,
    lifetime_attempts INTEGER NOT NULL,
    current_epoch INTEGER NOT NULL,
    reauthorization_context TEXT NOT NULL,
    reauthorization_budget_increment_units INTEGER,
    reauthorization_attempt_increment INTEGER,
    closed_reply_json TEXT,
    CHECK (
        (reauthorization_budget_increment_units IS NULL
         AND reauthorization_attempt_increment IS NULL)
        OR
        (reauthorization_budget_increment_units > 0
         AND reauthorization_attempt_increment > 0)
    )
);

CREATE TABLE epochs (
    epoch INTEGER PRIMARY KEY,
    attempts INTEGER NOT NULL,
    spent_units INTEGER NOT NULL,
    horizon_limit INTEGER NOT NULL,
    budget_increment_units INTEGER NOT NULL
);

CREATE TABLE routes (
    route_handle TEXT PRIMARY KEY,
    route_name TEXT NOT NULL UNIQUE,
    protected_object TEXT NOT NULL,
    handler_key TEXT NOT NULL,
    public_values_json TEXT NOT NULL,
    requires_capability INTEGER NOT NULL CHECK (requires_capability IN (0,1))
);

CREATE TABLE capabilities (
    capability_handle TEXT PRIMARY KEY,
    route_handle TEXT NOT NULL REFERENCES routes(route_handle),
    payload_hash TEXT NOT NULL,
    redeemer_id TEXT NOT NULL,
    redeemer_process_identity TEXT,
    epoch INTEGER NOT NULL,
    expires_at_lifetime_attempt INTEGER NOT NULL,
    consumed_attempt INTEGER
);

CREATE TABLE used_credentials (
    agent_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    consumed_attempt INTEGER NOT NULL,
    PRIMARY KEY (agent_id, nonce)
);

CREATE TABLE used_grants (
    authorizer_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    consumed_attempt INTEGER NOT NULL,
    PRIMARY KEY (authorizer_id, nonce)
);

CREATE TABLE attempts (
    lifetime_attempt INTEGER PRIMARY KEY,
    epoch INTEGER NOT NULL REFERENCES epochs(epoch),
    epoch_attempt INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RESERVED','FINALIZED')),
    kind TEXT NOT NULL,
    route_handle TEXT,
    terminal INTEGER NOT NULL CHECK (terminal IN (0,1)),
    is_effect INTEGER NOT NULL CHECK (is_effect IN (0,1)),
    event_json TEXT,
    owner_pid INTEGER,
    owner_process_identity TEXT,
    owner_token TEXT,
    canonical_payload TEXT,
    effect_state TEXT NOT NULL CHECK (
        effect_state IN ('NONE','UNSTARTED','STARTED')
    ),
    effect_request_id TEXT,
    effect_fingerprint TEXT,
    effect_result_code INTEGER,
    UNIQUE (epoch, epoch_attempt)
);

CREATE TABLE audit_log (
    audit_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    lifetime_attempt INTEGER NOT NULL REFERENCES attempts(lifetime_attempt),
    phase TEXT NOT NULL CHECK (phase IN ('START','FINAL')),
    UNIQUE (lifetime_attempt, phase)
);

CREATE TRIGGER finalized_attempt_is_immutable
BEFORE UPDATE ON attempts
WHEN OLD.state = 'FINALIZED'
BEGIN
    SELECT RAISE(ABORT, 'finalized transcript is immutable');
END;

CREATE TRIGGER attempts_are_not_deletable
BEFORE DELETE ON attempts
BEGIN
    SELECT RAISE(ABORT, 'attempt history is immutable');
END;

CREATE TRIGGER audit_is_not_updatable
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit history is immutable');
END;

CREATE TRIGGER audit_is_not_deletable
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit history is immutable');
END;

CREATE TRIGGER sealed_routes_are_not_updatable
BEFORE UPDATE ON routes
WHEN (SELECT state FROM metadata WHERE singleton = 1) != 'draft'
BEGIN
    SELECT RAISE(ABORT, 'sealed routes are immutable');
END;

CREATE TRIGGER sealed_routes_are_not_deletable
BEFORE DELETE ON routes
WHEN (SELECT state FROM metadata WHERE singleton = 1) != 'draft'
BEGIN
    SELECT RAISE(ABORT, 'sealed routes are immutable');
END;

CREATE TRIGGER sealed_routes_are_not_insertable
BEFORE INSERT ON routes
WHEN (SELECT state FROM metadata WHERE singleton = 1) != 'draft'
BEGIN
    SELECT RAISE(ABORT, 'sealed routes are immutable');
END;

CREATE TRIGGER public_manifest_is_immutable
BEFORE UPDATE OF schema_version, domain_id, protected_objects_json,
                 observer_values_json, observer_spec_id,
                 route_codebooks_json, codebook_sha256, units_per_bit,
                 event_charge_units, reauthorization_context,
                 reauthorization_budget_increment_units,
                 reauthorization_attempt_increment ON metadata
BEGIN
    SELECT RAISE(ABORT, 'public observer manifest is immutable');
END;

CREATE TRIGGER sealed_observer_config_is_immutable
BEFORE UPDATE OF schema_version, domain_id, protected_objects_json,
                 observer_values_json,
                 observer_spec_id, route_codebooks_json, codebook_sha256,
                 units_per_bit, event_charge_units, reauthorization_context,
                 reauthorization_budget_increment_units,
                 reauthorization_attempt_increment ON metadata
WHEN OLD.state != 'draft'
BEGIN
    SELECT RAISE(ABORT, 'sealed observer configuration is immutable');
END;

CREATE TRIGGER lifecycle_transitions_are_monotone
BEFORE UPDATE OF state ON metadata
WHEN NOT (
    NEW.state = OLD.state
    OR (OLD.state = 'draft' AND NEW.state = 'sealed')
    OR (OLD.state = 'sealed' AND NEW.state = 'active')
    OR (OLD.state = 'active' AND NEW.state = 'closed')
)
BEGIN
    SELECT RAISE(ABORT, 'sealed lifecycle is immutable');
END;

CREATE TRIGGER metadata_is_not_deletable
BEFORE DELETE ON metadata
BEGIN
    SELECT RAISE(ABORT, 'domain metadata is immutable');
END;
"""


class DurableSecureDomain:
    """A crash-consistent sealed secure domain backed by one SQLite file."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        agent_keys: Mapping[str, bytes],
        reauthorization_keys: Mapping[str, bytes],
        handler_registry: Mapping[
            str, Callable[[Any], Any] | IdempotentEffectHandler
        ],
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._path = os.path.realpath(os.fspath(path))
        # Reopen must validate the database inode's mount, not merely its
        # parent directory: Linux permits a network-backed file bind mount at
        # an otherwise local pathname.
        _require_local_wal_filesystem(self._path)
        self._agent_keys = _copy_keys("agent_keys", agent_keys)
        self._reauthorization_keys = _copy_keys(
            "reauthorization_keys", reauthorization_keys
        )
        self._handlers = _copy_handlers(handler_registry)
        if fault_hook is not None and not callable(fault_hook):
            raise TypeError("fault_hook must be callable or null")
        self._fault_hook = fault_hook
        self._validate_database()
        metadata = self._metadata()
        self._database_identity = (
            self._path,
            str(metadata["domain_id"]),
            str(metadata["reauthorization_context"]),
        )
        self._runtime = _runtime_for_ledger(
            self._database_identity, self._initial_delivery_sequence()
        )
        self._validate_handler_bindings()
        self._recover_reserved_attempts()

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str],
        *,
        config: DomainConfig,
        observer_spec: ObserverSpec,
        reauthorization_policy: ReauthorizationPolicy | None = None,
        agent_keys: Mapping[str, bytes],
        reauthorization_keys: Mapping[str, bytes],
        handler_registry: Mapping[
            str, Callable[[Any], Any] | IdempotentEffectHandler
        ],
        fault_hook: Callable[[str], None] | None = None,
    ) -> "DurableSecureDomain":
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
        target = Path(path)
        if target.exists():
            raise FileExistsError(f"durable domain already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        _require_local_wal_filesystem(target.parent)
        try:
            descriptor = os.open(
                target,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            raise FileExistsError(f"durable domain already exists: {target}")
        else:
            os.close(descriptor)
        try:
            connection = sqlite3.connect(str(target), isolation_level=None)
        except BaseException:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        try:
            selected_journal = connection.execute(
                "PRAGMA journal_mode=WAL"
            ).fetchone()
            if (
                selected_journal is None
                or type(selected_journal[0]) is not str
                or selected_journal[0].lower() != "wal"
            ):
                raise DurableConfigurationError(
                    "durable-domain database could not enable SQLite WAL"
                )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript(_SCHEMA)
            context = "sluice-durable-reauth-v1." + secrets.token_urlsafe(32)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO metadata VALUES (
                    1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL
                )
                """,
                (
                    SCHEMA_VERSION,
                    config.domain_id,
                    json.dumps(sorted(config.protected_objects), separators=(",", ":")),
                    json.dumps(sorted(observer_spec.permitted_value_codes), separators=(",", ":")),
                    observer_spec.observer_spec_id,
                    _route_codebooks_json(observer_spec.route_codebooks),
                    observer_spec.codebook_sha256,
                    observer_spec.accounting_units_per_bit,
                    DomainState.DRAFT.value,
                    config.event_charge_units,
                    config.lifetime_budget_units,
                    config.attempt_horizon,
                    0,
                    0,
                    0,
                    context,
                    None
                    if reauthorization_policy is None
                    else reauthorization_policy.budget_increment_units,
                    None
                    if reauthorization_policy is None
                    else reauthorization_policy.attempt_increment,
                ),
            )
            connection.execute(
                "INSERT INTO epochs VALUES (0,0,0,?,?)",
                (config.attempt_horizon, config.lifetime_budget_units),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            connection.close()
            try:
                target.unlink()
            except OSError:
                pass
            raise
        finally:
            try:
                connection.close()
            except Exception:
                pass
        os.chmod(target, 0o600)
        return cls(
            target,
            agent_keys=agent_keys,
            reauthorization_keys=reauthorization_keys,
            handler_registry=handler_registry,
            fault_hook=fault_hook,
        )

    @classmethod
    def reopen(
        cls,
        path: str | os.PathLike[str],
        *,
        agent_keys: Mapping[str, bytes],
        reauthorization_keys: Mapping[str, bytes],
        handler_registry: Mapping[
            str, Callable[[Any], Any] | IdempotentEffectHandler
        ],
        fault_hook: Callable[[str], None] | None = None,
    ) -> "DurableSecureDomain":
        if not Path(path).is_file():
            raise FileNotFoundError(os.fspath(path))
        return cls(
            path,
            agent_keys=agent_keys,
            reauthorization_keys=reauthorization_keys,
            handler_registry=handler_registry,
            fault_hook=fault_hook,
        )

    def close(self) -> None:
        """Compatibility no-op: operations own short-lived connections."""

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=30.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _validate_database(self) -> None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM metadata WHERE singleton=1"
            ).fetchone()
            journal = connection.execute("PRAGMA journal_mode").fetchone()
        except sqlite3.DatabaseError as exc:
            raise DurableConfigurationError("not a durable secure-domain database") from exc
        finally:
            connection.close()
        if row is None or row["schema_version"] != SCHEMA_VERSION:
            raise DurableConfigurationError("unsupported durable-domain schema")
        try:
            _identifier("observer_spec_id", row["observer_spec_id"])
            codebooks = _decode_route_codebooks(row["route_codebooks_json"])
            codebook_hash = row["codebook_sha256"]
            if (
                type(codebook_hash) is not str
                or len(codebook_hash) != 64
                or not _safe_text_equal(
                    codebook_hash,
                    _route_codebook_sha256(row["route_codebooks_json"]),
                )
            ):
                raise DurableConfigurationError(
                    "persisted route codebook hash is malformed"
                )
            permitted_values = json.loads(row["observer_values_json"])
            if (
                type(permitted_values) is not list
                or any(type(value) is not int for value in permitted_values)
                or any(
                    not codebook.public_values.issubset(permitted_values)
                    for codebook in codebooks
                )
            ):
                raise DurableConfigurationError(
                    "persisted ObserverSpec/codebook binding is malformed"
                )
            policy = self._reauthorization_policy_in(row)
            charge = int(row["event_charge_units"])
        except (IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DurableConfigurationError(
                "persisted durable observer configuration is malformed"
            ) from exc
        if (
            policy is not None
            and policy.budget_increment_units
            < policy.attempt_increment * charge
        ):
            raise DurableConfigurationError(
                "persisted reauthorization policy is underfunded"
            )
        if (
            journal is None
            or type(journal[0]) is not str
            or journal[0].lower() != "wal"
        ):
            raise DurableConfigurationError(
                "durable-domain database is not using SQLite WAL"
            )

    def _initial_delivery_sequence(self) -> int:
        """Seed a fresh process after the durable finalized prefix."""

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT lifetime_attempt FROM attempts
                WHERE state='RESERVED' ORDER BY lifetime_attempt LIMIT 1
                """
            ).fetchone()
            if row is not None:
                return int(row["lifetime_attempt"])
            metadata = self._metadata_in(connection)
            return int(metadata["lifetime_attempts"]) + 1
        finally:
            connection.close()

    def _validate_handler_bindings(self) -> None:
        connection = self._connect()
        try:
            routes = connection.execute(
                """
                SELECT route_name, handler_key, public_values_json,
                       requires_capability
                FROM routes ORDER BY route_name
                """
            ).fetchall()
            metadata = self._metadata_in(connection)
        finally:
            connection.close()
        if metadata["state"] != DomainState.DRAFT.value:
            actual_codebooks = tuple(
                RouteCodebook(
                    name=row["route_name"],
                    public_values=frozenset(json.loads(row["public_values_json"])),
                    requires_capability=bool(row["requires_capability"]),
                )
                for row in routes
            )
            if actual_codebooks != _decode_route_codebooks(
                metadata["route_codebooks_json"]
            ):
                raise DurableConfigurationError(
                    "persisted routes do not match the sealed public codebook"
                )
        required = {row["handler_key"] for row in routes}
        missing = sorted(required.difference(self._handlers))
        if missing:
            raise DurableConfigurationError(
                "handler registry is missing persisted keys: " + ", ".join(missing)
            )
        unsafe_effects = sorted(
            {
                row["handler_key"]
                for row in routes
                if bool(row["requires_capability"])
                and type(self._handlers[row["handler_key"]])
                is not IdempotentEffectHandler
            }
        )
        if unsafe_effects:
            raise DurableConfigurationError(
                "capability-protected routes require IdempotentEffectHandler: "
                + ", ".join(unsafe_effects)
            )

    @property
    def state(self) -> DomainState:
        return DomainState(self._metadata()["state"])

    @property
    def attempts_used(self) -> int:
        return int(self._metadata()["lifetime_attempts"])

    @property
    def lifetime_spent_units(self) -> int:
        return int(self._metadata()["lifetime_spent_units"])

    @property
    def lifetime_budget_units(self) -> int:
        return int(self._metadata()["lifetime_budget_units"])

    @property
    def attempt_horizon(self) -> int:
        return int(self._metadata()["attempt_horizon"])

    @property
    def event_charge_units(self) -> int:
        return int(self._metadata()["event_charge_units"])

    @property
    def observer_spec_id(self) -> str:
        return str(self._metadata()["observer_spec_id"])

    @property
    def codebook_sha256(self) -> str:
        return str(self._metadata()["codebook_sha256"])

    @property
    def route_codebooks(self) -> tuple[RouteCodebook, ...]:
        return _decode_route_codebooks(self._metadata()["route_codebooks_json"])

    @property
    def current_epoch(self) -> int:
        return int(self._metadata()["current_epoch"])

    @property
    def reauthorization_context(self) -> str:
        return str(self._metadata()["reauthorization_context"])

    @property
    def reauthorization_policy(self) -> ReauthorizationPolicy | None:
        """Return the public fixed grant shape, or null when reauth is disabled."""

        return self._reauthorization_policy_in(self._metadata())

    @property
    def credential_context(self) -> str:
        """Per-domain context required by durable v2 attempt credentials."""

        return self.reauthorization_context

    @property
    def epoch_stats(self) -> tuple[EpochStats, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM epochs ORDER BY epoch"
            ).fetchall()
        finally:
            connection.close()
        return tuple(
            EpochStats(
                epoch=int(row["epoch"]),
                attempts=int(row["attempts"]),
                spent_units=int(row["spent_units"]),
                horizon_limit=int(row["horizon_limit"]),
                budget_increment_units=int(row["budget_increment_units"]),
            )
            for row in rows
        )

    @property
    def transcript(self) -> tuple[TranscriptEvent, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT state, event_json FROM attempts ORDER BY lifetime_attempt
                """
            ).fetchall()
        finally:
            connection.close()
        events: list[TranscriptEvent] = []
        for row in rows:
            if row["state"] != "FINALIZED":
                break
            events.append(_event_from_json(row["event_json"]))
        return tuple(events)

    @property
    def audit_start_count(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM audit_log WHERE phase='START'"
            ).fetchone()
            assert row is not None
            return int(row["count"])
        finally:
            connection.close()

    def _metadata(self) -> sqlite3.Row:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM metadata WHERE singleton=1"
            ).fetchone()
            if row is None:
                raise DurableConfigurationError("durable-domain metadata is missing")
            return row
        finally:
            connection.close()

    def register_route(
        self,
        *,
        name: str,
        protected_object: str,
        handler_key: str,
        public_values: frozenset[int],
        requires_capability: bool = False,
    ) -> RouteToken:
        self._reject_handler_reentry()
        name = _identifier("route name", name)
        protected_object = _identifier("protected_object", protected_object)
        handler_key = _identifier("handler_key", handler_key)
        if handler_key not in self._handlers:
            raise DurableConfigurationError("handler key is not bound")
        if type(public_values) is not frozenset or not public_values:
            raise TypeError("public_values must be a nonempty frozenset")
        if len(public_values) > MAX_PUBLIC_VALUES_PER_ROUTE:
            raise ValueError("route public alphabet exceeds the supported bound")
        if any(type(value) is not int or not 0 <= value <= MAX_SECURE_INTEGER for value in public_values):
            raise TypeError("public_values must contain bounded nonnegative integers")
        if type(requires_capability) is not bool:
            raise TypeError("requires_capability must be a boolean")
        if (
            requires_capability
            and type(self._handlers[handler_key]) is not IdempotentEffectHandler
        ):
            raise DurableConfigurationError(
                "capability-protected routes require IdempotentEffectHandler"
            )
        route = RouteToken._new()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            self._require_state(metadata, DomainState.DRAFT, "register routes")
            codebooks = {
                codebook.name: codebook
                for codebook in _decode_route_codebooks(
                    metadata["route_codebooks_json"]
                )
            }
            codebook = codebooks.get(name)
            if (
                codebook is None
                or public_values != codebook.public_values
                or requires_capability != codebook.requires_capability
            ):
                raise ValueError(
                    "route does not exactly match the precommitted public codebook"
                )
            objects = set(json.loads(metadata["protected_objects_json"]))
            permitted = set(json.loads(metadata["observer_values_json"]))
            if protected_object not in objects:
                raise ValueError("route object is outside the protected domain")
            if not public_values.issubset(permitted):
                raise ValueError("route values are outside the ObserverSpec")
            count = connection.execute("SELECT COUNT(*) FROM routes").fetchone()[0]
            if count >= MAX_ROUTES:
                raise ValueError("domain exceeds the maximum route count")
            connection.execute(
                "INSERT INTO routes VALUES (?,?,?,?,?,?)",
                (
                    route.to_wire(),
                    name,
                    protected_object,
                    handler_key,
                    json.dumps(sorted(public_values), separators=(",", ":")),
                    int(requires_capability),
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return route

    def issue_capability(
        self,
        route: RouteToken,
        *,
        payload: Any,
        redeemer_id: str,
        expires_at_lifetime_attempt: int,
    ) -> EffectCapability:
        """Issue one exact, epoch-bound effect capability.

        ``redeemer_id`` is a logical broker label.  OS peer authentication is
        enforced by the isolation service.  The direct-call spelling
        ``pid:<current-pid>`` additionally binds the capability to the
        kernel-derived current process incarnation and rejects a forked or
        separately reopened caller even if it repeats the same text.
        """

        self._reject_handler_reentry()
        redeemer_id = _identifier("redeemer_id", redeemer_id)
        # ``redeemer_id`` is a logical broker label.  A direct-process binding
        # is established only when the requested pid is independently verified
        # against this execution context.  Network peer identity belongs to the
        # AF_UNIX/SO_PEERCRED isolation boundary, not to caller-supplied text.
        redeemer_process_identity: str | None = None
        if redeemer_id.startswith("pid:"):
            if redeemer_id != f"pid:{os.getpid()}":
                raise ValueError("pid redeemer must name the issuing process")
            redeemer_process_identity = _process_identity()
        expires = _positive_int(
            "expires_at_lifetime_attempt", expires_at_lifetime_attempt
        )
        payload_hash = _payload_digest(_canonical_payload(payload))
        route_handle = route.to_wire() if type(route) is RouteToken else None
        capability = EffectCapability._new()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            if metadata["state"] not in (DomainState.DRAFT.value, DomainState.ACTIVE.value):
                raise DomainLifecycleError(
                    "capabilities may be issued only during DRAFT or ACTIVE"
                )
            record = connection.execute(
                "SELECT * FROM routes WHERE route_handle=?", (route_handle,)
            ).fetchone()
            if record is None or not record["requires_capability"]:
                raise ValueError("route is not a capability-protected domain route")
            if expires < int(metadata["lifetime_attempts"]) + 1:
                raise ValueError("capability is already expired")
            connection.execute(
                "INSERT INTO capabilities VALUES (?,?,?,?,?,?,?,NULL)",
                (
                    capability.to_wire(),
                    route_handle,
                    payload_hash,
                    redeemer_id,
                    redeemer_process_identity,
                    int(metadata["current_epoch"]),
                    expires,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return capability

    def seal(self) -> None:
        self._reject_handler_reentry()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            self._require_state(metadata, DomainState.DRAFT, "seal domain")
            routes = connection.execute(
                """
                SELECT route_name, public_values_json, requires_capability
                FROM routes ORDER BY route_name
                """
            ).fetchall()
            if not routes:
                raise ValueError("a sealed domain requires at least one route")
            actual_codebooks = tuple(
                RouteCodebook(
                    name=row["route_name"],
                    public_values=frozenset(json.loads(row["public_values_json"])),
                    requires_capability=bool(row["requires_capability"]),
                )
                for row in routes
            )
            expected_codebooks = _decode_route_codebooks(
                metadata["route_codebooks_json"]
            )
            if (
                actual_codebooks != expected_codebooks
                or not _safe_text_equal(
                    metadata["codebook_sha256"],
                    _route_codebook_sha256(
                        _route_codebooks_json(actual_codebooks)
                    ),
                )
            ):
                raise ValueError(
                    "registered routes do not match the precommitted public codebook"
                )
            effect_routes = connection.execute(
                """
                SELECT handler_key FROM routes
                WHERE requires_capability=1 ORDER BY handler_key
                """
            ).fetchall()
            if any(
                type(self._handlers.get(row["handler_key"]))
                is not IdempotentEffectHandler
                for row in effect_routes
            ):
                raise DurableConfigurationError(
                    "capability-protected routes require IdempotentEffectHandler"
                )
            policy = self._reauthorization_policy_in(metadata)
            if policy is not None:
                charge = int(metadata["event_charge_units"])
                if (
                    policy.budget_increment_units
                    < policy.attempt_increment * charge
                ):
                    raise ValueError(
                        "reauthorization policy does not fund every added attempt"
                    )
            support = 4 + sum(
                len(json.loads(row["public_values_json"])) + 5
                for row in routes
            )
            bits = (support - 1).bit_length()
            required_charge = bits * int(metadata["units_per_bit"])
            if int(metadata["event_charge_units"]) < required_charge:
                raise ValueError(
                    "event charge is below the sealed ObserverSpec support bound"
                )
            required_funding = (
                int(metadata["attempt_horizon"])
                * int(metadata["event_charge_units"])
            )
            if int(metadata["lifetime_budget_units"]) < required_funding:
                raise ValueError("lifetime budget does not fund the sealed horizon")
            connection.execute(
                "UPDATE metadata SET state=? WHERE singleton=1",
                (DomainState.SEALED.value,),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def activate(self) -> None:
        self._reject_handler_reentry()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            self._require_state(metadata, DomainState.SEALED, "activate domain")
            connection.execute(
                "UPDATE metadata SET state=? WHERE singleton=1",
                (DomainState.ACTIVE.value,),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def attempt(
        self,
        route: RouteToken,
        payload: Any,
        *,
        credential: AttemptCredential | None,
        capability: EffectCapability | None = None,
        redeemer_id: str | None = None,
    ) -> TranscriptEvent:
        self._reject_handler_reentry()
        route_handle = route.to_wire() if type(route) is RouteToken else None
        try:
            canonical_payload = _canonical_payload(payload)
            payload_hash: str | None = _payload_digest(canonical_payload)
            payload_snapshot: Any | None = _decode_canonical_payload(canonical_payload)
        except (TypeError, ValueError):
            canonical_payload = None
            payload_hash = None
            payload_snapshot = None

        owner_pid, owner_identity, owner_token = self._acquire_owner()
        attempt_no: int | None = None
        route_record: sqlite3.Row | None = None
        effect_request: EffectRequest | None = None
        immediate_event: TranscriptEvent | None = None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            closed = self._closed_reply(metadata)
            if closed is not None:
                connection.commit()
                immediate_event = closed
            else:
                self._require_state(metadata, DomainState.ACTIVE, "perform attempts")
                route_record = connection.execute(
                    "SELECT * FROM routes WHERE route_handle=?", (route_handle,)
                ).fetchone()
                attempt_no, epoch, _ = self._reserve(
                    connection,
                    metadata,
                    EventKind.ATTEMPT,
                    route_handle,
                    owner_pid=owner_pid,
                    owner_process_identity=owner_identity,
                    owner_token=owner_token,
                )
                outcome: OutcomeCode | None = None
                replay_key: tuple[str, str] | None = None
                capability_handle: str | None = None
                if route_record is None:
                    outcome = OutcomeCode.ROUTE_DENIED
                elif canonical_payload is None or payload_hash is None:
                    outcome = OutcomeCode.AUTH_DENIED
                else:
                    replay_key = self._validate_credential(
                        connection,
                        metadata,
                        route_handle,
                        canonical_payload,
                        credential,
                        epoch,
                        attempt_no,
                    )
                    if replay_key is None:
                        outcome = OutcomeCode.AUTH_DENIED
                if outcome is None and route_record is not None:
                    assert payload_hash is not None
                    capability_handle = self._validate_capability(
                        connection,
                        route_record,
                        payload_hash,
                        capability,
                        redeemer_id,
                        epoch,
                        attempt_no,
                    )
                    if capability_handle is False:  # type: ignore[comparison-overlap]
                        outcome = OutcomeCode.CAPABILITY_DENIED
                        capability_handle = None

                if outcome is not None:
                    terminal = self._close_if_exhausted(connection, attempt_no)
                    immediate_event = self._make_event(
                        attempt_no, EventKind.ATTEMPT, outcome, terminal=terminal
                    )
                    self._finalize_in_transaction(
                        connection, attempt_no, immediate_event
                    )
                else:
                    assert (
                        replay_key is not None
                        and route_record is not None
                        and canonical_payload is not None
                        and payload_hash is not None
                    )
                    connection.execute(
                        "INSERT INTO used_credentials VALUES (?,?,?)",
                        (replay_key[0], replay_key[1], attempt_no),
                    )
                    if capability_handle is not None:
                        updated = connection.execute(
                            """
                            UPDATE capabilities SET consumed_attempt=?
                            WHERE capability_handle=? AND consumed_attempt IS NULL
                            """,
                            (attempt_no, capability_handle),
                        ).rowcount
                        if updated != 1:
                            raise RuntimeError("capability claim lost atomicity")
                    terminal = self._close_if_exhausted(connection, attempt_no)
                    is_effect = bool(route_record["requires_capability"])
                    effect_state = "NONE"
                    request_id: str | None = None
                    fingerprint: str | None = None
                    if is_effect:
                        effect_state = "UNSTARTED"
                        request_id = (
                            "sluice-effect-request-v1." + secrets.token_urlsafe(32)
                        )
                        fingerprint = hashlib.sha256(
                            json.dumps(
                                (
                                    metadata["reauthorization_context"],
                                    str(attempt_no),
                                    route_handle,
                                    payload_hash,
                                    request_id,
                                ),
                                ensure_ascii=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                        effect_request = EffectRequest(
                            request_id=request_id,
                            fingerprint=fingerprint,
                            payload=payload_snapshot,
                        )
                    connection.execute(
                        """
                        UPDATE attempts
                        SET terminal=?, is_effect=?, canonical_payload=?,
                            effect_state=?, effect_request_id=?, effect_fingerprint=?
                        WHERE lifetime_attempt=?
                        """,
                        (
                            terminal,
                            int(is_effect),
                            canonical_payload.decode("ascii"),
                            effect_state,
                            request_id,
                            fingerprint,
                            attempt_no,
                        ),
                    )
                self._call_fault("before_reservation_commit")
                connection.commit()
        except BaseException:
            connection.rollback()
            self._release_owner(owner_pid, owner_token)
            raise
        finally:
            connection.close()

        try:
            if immediate_event is not None:
                if attempt_no is not None:
                    try:
                        self._call_fault("after_reservation_commit")
                    except BaseException:
                        self._abandon_delivery(immediate_event)
                        raise
                return self._deliver_in_order(immediate_event)

            assert attempt_no is not None and route_record is not None
            self._call_fault("after_reservation_commit")
            handler = self._handlers[route_record["handler_key"]]
            if effect_request is not None:
                self._mark_effect_started(attempt_no, owner_token)
            self._enter_handler()
            handler_failed = False
            try:
                if effect_request is not None and type(handler) is IdempotentEffectHandler:
                    result: Any = handler.execute(effect_request)
                elif callable(handler):
                    result = handler(payload_snapshot)
                else:
                    raise TypeError("effect adapter cannot serve a non-effect route")
            except BaseException:
                # An effect exception is transport-ambiguous: the external
                # broker may have committed immediately before its reply was
                # lost.  Consult the same durable journal seam used after a
                # process crash before choosing a public outcome.
                if (
                    effect_request is not None
                    and type(handler) is IdempotentEffectHandler
                ):
                    try:
                        result = handler.reconcile(effect_request)
                    except BaseException:
                        result = None
                    handler_failed = self._linked_effect_value(
                        effect_request, result
                    ) is None
                else:
                    handler_failed = True
                    result = None
            finally:
                self._exit_handler()

            if handler_failed:
                return self._finalize_and_deliver(
                    attempt_no, EventKind.ATTEMPT, OutcomeCode.INTERNAL_DENIED
                )

            if effect_request is not None and type(handler) is IdempotentEffectHandler:
                value_code = self._linked_effect_value(effect_request, result)
                if value_code is None:
                    return self._finalize_and_deliver(
                        attempt_no,
                        EventKind.ATTEMPT,
                        OutcomeCode.OUTPUT_DENIED,
                    )
                result = value_code
            public_values = frozenset(json.loads(route_record["public_values_json"]))
            if type(result) is not int or result not in public_values:
                return self._finalize_and_deliver(
                    attempt_no, EventKind.ATTEMPT, OutcomeCode.OUTPUT_DENIED
                )
            return self._finalize_and_deliver(
                attempt_no,
                EventKind.ATTEMPT,
                OutcomeCode.RELEASED,
                value_code=result,
            )
        finally:
            self._release_owner(owner_pid, owner_token)

    def continue_work(self) -> TranscriptEvent:
        self._reject_handler_reentry()
        return self._simple_event(EventKind.CONTINUE, OutcomeCode.CONTINUED)

    def stop(self) -> TranscriptEvent:
        self._reject_handler_reentry()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            closed = self._closed_reply(metadata)
            if closed is not None:
                connection.commit()
                return self._deliver_in_order(closed)
            self._require_state(metadata, DomainState.ACTIVE, "stop domain")
            attempt_no, _, _ = self._reserve(
                connection, metadata, EventKind.STOP, None
            )
            stopped = self._make_event(
                attempt_no, EventKind.STOP, OutcomeCode.STOPPED, terminal=True
            )
            self._finalize_in_transaction(connection, attempt_no, stopped)
            metadata = self._metadata_in(connection)
            while int(metadata["lifetime_attempts"]) < int(metadata["attempt_horizon"]):
                padding_no, _, _ = self._reserve(
                    connection, metadata, EventKind.PADDING, None
                )
                padded = self._make_event(
                    padding_no,
                    EventKind.PADDING,
                    OutcomeCode.PADDED,
                    terminal=True,
                )
                self._finalize_in_transaction(connection, padding_no, padded)
                metadata = self._metadata_in(connection)
            self._set_closed(connection, int(metadata["lifetime_attempts"]))
            connection.commit()
            return self._deliver_in_order(stopped)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def reauthorize(
        self, grant: ReauthorizationGrant | None
    ) -> TranscriptEvent:
        self._reject_handler_reentry()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            closed = self._closed_reply(metadata)
            if closed is not None:
                connection.commit()
                return self._deliver_in_order(closed)
            self._require_state(metadata, DomainState.ACTIVE, "reauthorize domain")
            attempt_no, _, _ = self._reserve(
                connection, metadata, EventKind.REAUTHORIZE, None
            )
            accepted = self._validate_grant(
                connection, metadata, grant, attempt_no
            )
            outcome = OutcomeCode.REAUTH_DENIED
            if accepted is not None:
                budget_increment, attempt_increment, replay_key = accepted
                policy = self._reauthorization_policy_in(metadata)
                charge = int(metadata["event_charge_units"])
                added_funding = attempt_increment * charge
                proposed_budget = int(metadata["lifetime_budget_units"]) + budget_increment
                proposed_horizon = int(metadata["attempt_horizon"]) + attempt_increment
                if (
                    policy is not None
                    and budget_increment == policy.budget_increment_units
                    and attempt_increment == policy.attempt_increment
                    and budget_increment >= added_funding
                    and proposed_budget <= MAX_SECURE_INTEGER
                    and proposed_horizon <= MAX_ATTEMPT_HORIZON
                    and proposed_horizon * charge <= MAX_SECURE_INTEGER
                    and proposed_budget >= proposed_horizon * charge
                ):
                    old_remaining = int(metadata["attempt_horizon"]) - attempt_no
                    new_epoch = int(metadata["current_epoch"]) + 1
                    connection.execute(
                        "INSERT INTO used_grants VALUES (?,?,?)",
                        (replay_key[0], replay_key[1], attempt_no),
                    )
                    connection.execute(
                        "INSERT INTO epochs VALUES (?,0,0,?,?)",
                        (
                            new_epoch,
                            old_remaining + attempt_increment,
                            budget_increment,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE metadata
                        SET lifetime_budget_units=?, attempt_horizon=?, current_epoch=?
                        WHERE singleton=1
                        """,
                        (proposed_budget, proposed_horizon, new_epoch),
                    )
                    outcome = OutcomeCode.REAUTHORIZED
            terminal = self._close_if_exhausted(connection, attempt_no)
            event = self._make_event(
                attempt_no, EventKind.REAUTHORIZE, outcome, terminal=terminal
            )
            self._finalize_in_transaction(connection, attempt_no, event)
            self._call_fault("before_reservation_commit")
            connection.commit()
            try:
                self._call_fault("after_reservation_commit")
            except BaseException:
                self._abandon_delivery(event)
                raise
            return self._deliver_in_order(event)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _simple_event(self, kind: EventKind, outcome: OutcomeCode) -> TranscriptEvent:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = self._metadata_in(connection)
            closed = self._closed_reply(metadata)
            if closed is not None:
                connection.commit()
                return self._deliver_in_order(closed)
            self._require_state(metadata, DomainState.ACTIVE, "continue domain")
            attempt_no, _, _ = self._reserve(connection, metadata, kind, None)
            terminal = self._close_if_exhausted(connection, attempt_no)
            event = self._make_event(attempt_no, kind, outcome, terminal=terminal)
            self._finalize_in_transaction(connection, attempt_no, event)
            connection.commit()
            return self._deliver_in_order(event)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _metadata_in(connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM metadata WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise DurableConfigurationError("durable-domain metadata is missing")
        return row

    @staticmethod
    def _reauthorization_policy_in(
        metadata: sqlite3.Row,
    ) -> ReauthorizationPolicy | None:
        budget = metadata["reauthorization_budget_increment_units"]
        attempts = metadata["reauthorization_attempt_increment"]
        if budget is None and attempts is None:
            return None
        if type(budget) is not int or type(attempts) is not int:
            raise DurableConfigurationError(
                "persisted reauthorization policy is malformed"
            )
        try:
            return ReauthorizationPolicy(budget, attempts)
        except (TypeError, ValueError) as exc:
            raise DurableConfigurationError(
                "persisted reauthorization policy is malformed"
            ) from exc

    @staticmethod
    def _require_state(
        metadata: sqlite3.Row, expected: DomainState, operation: str
    ) -> None:
        if metadata["state"] != expected.value:
            raise DomainLifecycleError(
                f"cannot {operation} while domain is {metadata['state']}"
            )

    @staticmethod
    def _closed_reply(metadata: sqlite3.Row) -> TranscriptEvent | None:
        if metadata["state"] != DomainState.CLOSED.value:
            return None
        encoded = metadata["closed_reply_json"]
        if type(encoded) is not str:
            raise DurableConfigurationError("closed domain has no cached reply")
        return _event_from_json(encoded)

    def _reserve(
        self,
        connection: sqlite3.Connection,
        metadata: sqlite3.Row,
        kind: EventKind,
        route_handle: str | None,
        *,
        owner_pid: int | None = None,
        owner_process_identity: str | None = None,
        owner_token: str | None = None,
    ) -> tuple[int, int, int]:
        attempts = int(metadata["lifetime_attempts"])
        horizon = int(metadata["attempt_horizon"])
        spent = int(metadata["lifetime_spent_units"])
        budget = int(metadata["lifetime_budget_units"])
        charge = int(metadata["event_charge_units"])
        if attempts >= horizon or spent + charge > budget:
            raise RuntimeError("sealed durable-domain accounting invariant violated")
        epoch = int(metadata["current_epoch"])
        epoch_row = connection.execute(
            "SELECT * FROM epochs WHERE epoch=?", (epoch,)
        ).fetchone()
        if epoch_row is None:
            raise DurableConfigurationError("current epoch is missing")
        epoch_attempt = int(epoch_row["attempts"]) + 1
        if epoch_attempt > int(epoch_row["horizon_limit"]):
            raise RuntimeError("durable epoch horizon invariant violated")
        attempt_no = attempts + 1
        connection.execute(
            """
            UPDATE metadata
            SET lifetime_attempts=?, lifetime_spent_units=? WHERE singleton=1
            """,
            (attempt_no, spent + charge),
        )
        connection.execute(
            "UPDATE epochs SET attempts=?, spent_units=? WHERE epoch=?",
            (epoch_attempt, int(epoch_row["spent_units"]) + charge, epoch),
        )
        connection.execute(
            """
            INSERT INTO attempts (
                lifetime_attempt, epoch, epoch_attempt, state, kind,
                route_handle, terminal, is_effect, event_json, owner_pid,
                owner_process_identity, owner_token, canonical_payload,
                effect_state, effect_request_id, effect_fingerprint,
                effect_result_code
            ) VALUES (?,?,?,?,?,?,0,0,NULL,?,?,?,?, 'NONE',NULL,NULL,NULL)
            """,
            (
                attempt_no,
                epoch,
                epoch_attempt,
                "RESERVED",
                kind.value,
                route_handle,
                owner_pid,
                owner_process_identity,
                owner_token,
                None,
            ),
        )
        connection.execute(
            "INSERT INTO audit_log(lifetime_attempt,phase) VALUES (?, 'START')",
            (attempt_no,),
        )
        return attempt_no, epoch, epoch_attempt

    def _validate_credential(
        self,
        connection: sqlite3.Connection,
        metadata: sqlite3.Row,
        route_handle: str,
        canonical_payload: bytes,
        credential: AttemptCredential | None,
        epoch: int,
        attempt_no: int,
    ) -> tuple[str, str] | None:
        if type(credential) is not AttemptCredential:
            return None
        try:
            agent_id = _identifier("agent_id", credential.agent_id)
            nonce = _identifier("nonce", credential.nonce)
            context = _identifier("domain_context", credential.domain_context)
            route_claim = _identifier("route_handle", credential.route_handle)
            expiry = _positive_int(
                "expires_at_lifetime_attempt",
                credential.expires_at_lifetime_attempt,
            )
            if (
                type(credential.expected_epoch) is not int
                or credential.expected_epoch < 0
                or credential.expected_epoch > MAX_SECURE_INTEGER
                or type(credential.signature) is not str
                or len(credential.signature) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in credential.signature
                )
            ):
                return None
            key = self._agent_keys.get(agent_id)
            if key is None:
                return None
            used = connection.execute(
                "SELECT 1 FROM used_credentials WHERE agent_id=? AND nonce=?",
                (agent_id, nonce),
            ).fetchone()
            if (
                used is not None
                or not _safe_text_equal(route_claim, route_handle)
                or not _safe_text_equal(
                    context, metadata["reauthorization_context"]
                )
                or credential.expected_epoch != epoch
                or attempt_no > expiry
            ):
                return None
            expected = _mac(
                key,
                b"sluice-durable-attempt-credential-v2",
                (
                    agent_id,
                    context,
                    str(credential.expected_epoch),
                    route_handle,
                    canonical_payload.decode("ascii"),
                    nonce,
                    str(expiry),
                ),
            )
            if not _safe_text_equal(credential.signature, expected):
                return None
        except (TypeError, ValueError):
            return None
        return agent_id, nonce

    @staticmethod
    def _validate_capability(
        connection: sqlite3.Connection,
        route_record: sqlite3.Row,
        payload_hash: str,
        capability: EffectCapability | None,
        redeemer_id: str | None,
        epoch: int,
        attempt_no: int,
    ) -> str | None | bool:
        required = bool(route_record["requires_capability"])
        if not required:
            return None if capability is None else False
        if type(capability) is not EffectCapability or type(redeemer_id) is not str:
            return False
        try:
            checked_redeemer_id = _identifier("redeemer_id", redeemer_id)
        except (TypeError, ValueError):
            return False
        record = connection.execute(
            "SELECT * FROM capabilities WHERE capability_handle=?",
            (capability.to_wire(),),
        ).fetchone()
        if record is None or record["consumed_attempt"] is not None:
            return False
        matches = (
            _safe_text_equal(record["route_handle"], route_record["route_handle"])
            and _safe_text_equal(record["payload_hash"], payload_hash)
            and _safe_text_equal(record["redeemer_id"], checked_redeemer_id)
            and (
                record["redeemer_process_identity"] is None
                or _safe_text_equal(
                    record["redeemer_process_identity"], _process_identity()
                )
            )
            and int(record["epoch"]) == epoch
            and attempt_no <= int(record["expires_at_lifetime_attempt"])
        )
        return record["capability_handle"] if matches else False

    def _validate_grant(
        self,
        connection: sqlite3.Connection,
        metadata: sqlite3.Row,
        grant: ReauthorizationGrant | None,
        attempt_no: int,
    ) -> tuple[int, int, tuple[str, str]] | None:
        if type(grant) is not ReauthorizationGrant:
            return None
        try:
            authorizer = _identifier("authorizer_id", grant.authorizer_id)
            nonce = _identifier("nonce", grant.nonce)
            context = _identifier("domain_context", grant.domain_context)
            expiry = _positive_int(
                "expires_at_lifetime_attempt", grant.expires_at_lifetime_attempt
            )
            budget = _positive_int(
                "budget_increment_units", grant.budget_increment_units
            )
            attempts = _positive_int("attempt_increment", grant.attempt_increment)
            if (
                type(grant.expected_epoch) is not int
                or grant.expected_epoch < 0
                or grant.expected_epoch > MAX_SECURE_INTEGER
                or type(grant.signature) is not str
                or len(grant.signature) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in grant.signature
                )
            ):
                return None
            key = self._reauthorization_keys.get(authorizer)
            if key is None:
                return None
            if connection.execute(
                "SELECT 1 FROM used_grants WHERE authorizer_id=? AND nonce=?",
                (authorizer, nonce),
            ).fetchone() is not None:
                return None
            if (
                not _safe_text_equal(context, metadata["reauthorization_context"])
                or grant.expected_epoch != int(metadata["current_epoch"])
                or attempt_no > expiry
            ):
                return None
            expected = _mac(
                key,
                b"sluice-durable-reauthorization-v2",
                (
                    authorizer,
                    context,
                    str(grant.expected_epoch),
                    str(budget),
                    str(attempts),
                    nonce,
                    str(expiry),
                ),
            )
            if not _safe_text_equal(grant.signature, expected):
                return None
        except (TypeError, ValueError):
            return None
        return budget, attempts, (authorizer, nonce)

    def _close_if_exhausted(
        self, connection: sqlite3.Connection, attempt_no: int
    ) -> bool:
        metadata = self._metadata_in(connection)
        terminal = attempt_no == int(metadata["attempt_horizon"])
        if terminal:
            self._set_closed(connection, attempt_no)
        return terminal

    def _make_event(
        self,
        attempt_no: int,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        terminal: bool,
        value_code: int | None = None,
    ) -> TranscriptEvent:
        return self._charged_event(
            attempt_no,
            kind,
            outcome,
            value_code=value_code,
            terminal=terminal,
        )

    def _charged_event(
        self,
        attempt_no: int,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        terminal: bool,
        value_code: int | None = None,
    ) -> TranscriptEvent:
        return TranscriptEvent(
            schema_version=TRANSCRIPT_SCHEMA_VERSION,
            sequence=attempt_no,
            attempt=attempt_no,
            kind=kind,
            outcome=outcome,
            value_code=value_code,
            charge_units=self.event_charge_units,
            terminal=terminal,
        )

    def _finalize_in_transaction(
        self,
        connection: sqlite3.Connection,
        attempt_no: int,
        event: TranscriptEvent,
    ) -> None:
        connection.execute(
            """
            UPDATE attempts
            SET state='FINALIZED', terminal=?, event_json=?, effect_result_code=?
            WHERE lifetime_attempt=? AND state='RESERVED'
            """,
            (
                int(event.terminal),
                _event_json(event),
                event.value_code if event.outcome is OutcomeCode.RELEASED else None,
                attempt_no,
            ),
        )
        connection.execute(
            "INSERT INTO audit_log(lifetime_attempt,phase) VALUES (?, 'FINAL')",
            (attempt_no,),
        )

    def _finalize_attempt(
        self,
        attempt_no: int,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        value_code: int | None = None,
    ) -> TranscriptEvent:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM attempts WHERE lifetime_attempt=?", (attempt_no,)
            ).fetchone()
            if row is None:
                raise DurableConfigurationError("reserved attempt disappeared")
            if row["state"] == "FINALIZED":
                connection.commit()
                return _event_from_json(row["event_json"])
            event = self._charged_event(
                attempt_no,
                kind,
                outcome,
                value_code=value_code,
                terminal=bool(row["terminal"]),
            )
            self._finalize_in_transaction(connection, attempt_no, event)
            connection.commit()
            return event
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _finalized_event(self, attempt_no: int) -> TranscriptEvent | None:
        """Load the immutable committed response for one attempt, if present."""

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT state, event_json FROM attempts WHERE lifetime_attempt=?
                """,
                (attempt_no,),
            ).fetchone()
        finally:
            connection.close()
        if (
            row is None
            or row["state"] != "FINALIZED"
            or type(row["event_json"]) is not str
        ):
            return None
        return _event_from_json(row["event_json"])

    def _finalize_and_deliver(
        self,
        attempt_no: int,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        value_code: int | None = None,
    ) -> TranscriptEvent:
        """Return the authoritative event even if finalization reply is lost.

        SQLite may have committed the immutable FINALIZED row immediately
        before an asynchronous interruption or transport failure.  Reloading
        that row avoids both relabeling the attempt and leaving the
        process-local delivery sequencer permanently blocked on a response
        that no caller can advance.
        """

        try:
            event = self._finalize_attempt(
                attempt_no,
                kind,
                outcome,
                value_code=value_code,
            )
        except BaseException:
            event = self._finalized_event(attempt_no)
            if event is None:
                raise
        return self._deliver_in_order(event)

    def _finalize_and_abandon(
        self,
        attempt_no: int,
        kind: EventKind,
        outcome: OutcomeCode,
        *,
        value_code: int | None = None,
    ) -> TranscriptEvent:
        """Finalize recovery when the original response recipient is gone."""

        try:
            event = self._finalize_attempt(
                attempt_no,
                kind,
                outcome,
                value_code=value_code,
            )
        except BaseException:
            event = self._finalized_event(attempt_no)
            if event is None:
                raise
        # Persistence exposes this event through ``transcript``; no live
        # original caller remains to receive it, so advance the response
        # sequencer even when the COMMIT reply itself was interrupted.
        self._abandon_delivery(event)
        return event

    def _set_closed(self, connection: sqlite3.Connection, attempt_no: int) -> None:
        closed = TranscriptEvent(
            schema_version=TRANSCRIPT_SCHEMA_VERSION,
            sequence=attempt_no + 1,
            attempt=attempt_no,
            kind=EventKind.DOMAIN_CLOSED,
            outcome=OutcomeCode.DOMAIN_CLOSED,
            value_code=None,
            charge_units=0,
            terminal=True,
        )
        connection.execute(
            "UPDATE metadata SET state=?, closed_reply_json=? WHERE singleton=1",
            (DomainState.CLOSED.value, _event_json(closed)),
        )

    def _recover_reserved_attempts(self) -> None:
        """Recover only attempts whose recorded process owner is no longer live."""

        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE state='RESERVED' ORDER BY lifetime_attempt"
            ).fetchall()
        finally:
            connection.close()

        for candidate in rows:
            claimed = self._claim_stale_attempt(int(candidate["lifetime_attempt"]))
            if claimed is None:
                continue
            row, owner_pid, owner_token = claimed
            try:
                outcome = OutcomeCode.INTERNAL_DENIED
                value_code: int | None = None
                if row["effect_state"] == "STARTED":
                    request = self._effect_request_from_row(row)
                    route = self._route_for_attempt(row)
                    if request is not None and route is not None:
                        binding = self._handlers.get(route["handler_key"])
                        if type(binding) is IdempotentEffectHandler:
                            self._enter_handler()
                            try:
                                try:
                                    result = binding.reconcile(request)
                                except BaseException:
                                    result = None
                            finally:
                                self._exit_handler()
                            linked = self._linked_effect_value(request, result)
                            allowed = frozenset(
                                json.loads(route["public_values_json"])
                            )
                            if linked is not None and linked in allowed:
                                outcome = OutcomeCode.RELEASED
                                value_code = linked
                self._finalize_and_abandon(
                    int(row["lifetime_attempt"]),
                    EventKind(row["kind"]),
                    outcome,
                    value_code=value_code,
                )
            finally:
                self._release_owner(owner_pid, owner_token)

    def _claim_stale_attempt(
        self, attempt_no: int
    ) -> tuple[sqlite3.Row, int, str] | None:
        owner_pid, owner_identity, owner_token = self._acquire_owner()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM attempts WHERE lifetime_attempt=?", (attempt_no,)
            ).fetchone()
            if row is None or row["state"] != "RESERVED":
                connection.commit()
                self._release_owner(owner_pid, owner_token)
                return None
            previous_pid = row["owner_pid"]
            if (
                type(previous_pid) is int
                and type(row["owner_process_identity"]) is str
                and type(row["owner_token"]) is str
                and _owner_is_live(
                    previous_pid,
                    row["owner_process_identity"],
                    row["owner_token"],
                )
            ):
                connection.commit()
                self._release_owner(owner_pid, owner_token)
                return None
            connection.execute(
                """
                UPDATE attempts
                SET owner_pid=?, owner_process_identity=?, owner_token=?
                WHERE lifetime_attempt=? AND state='RESERVED'
                """,
                (owner_pid, owner_identity, owner_token, attempt_no),
            )
            connection.commit()
            claimed = connection.execute(
                "SELECT * FROM attempts WHERE lifetime_attempt=?", (attempt_no,)
            ).fetchone()
            if claimed is None:
                raise DurableConfigurationError("claimed attempt disappeared")
            return claimed, owner_pid, owner_token
        except BaseException:
            connection.rollback()
            self._release_owner(owner_pid, owner_token)
            raise
        finally:
            connection.close()

    def _route_for_attempt(self, row: sqlite3.Row) -> sqlite3.Row | None:
        if type(row["route_handle"]) is not str:
            return None
        connection = self._connect()
        try:
            return connection.execute(
                "SELECT * FROM routes WHERE route_handle=?",
                (row["route_handle"],),
            ).fetchone()
        finally:
            connection.close()

    @staticmethod
    def _effect_request_from_row(row: sqlite3.Row) -> EffectRequest | None:
        if not (
            type(row["effect_request_id"]) is str
            and type(row["effect_fingerprint"]) is str
            and type(row["canonical_payload"]) is str
        ):
            return None
        try:
            payload = _decode_canonical_payload(
                row["canonical_payload"].encode("ascii")
            )
        except (UnicodeError, ValueError, DurableConfigurationError):
            return None
        return EffectRequest(
            request_id=row["effect_request_id"],
            fingerprint=row["effect_fingerprint"],
            payload=payload,
        )

    @staticmethod
    def _linked_effect_value(
        request: EffectRequest, result: object
    ) -> int | None:
        if type(result) is not EffectResult or type(result.value_code) is not int:
            return None
        if not (
            _safe_text_equal(result.request_id, request.request_id)
            and _safe_text_equal(result.fingerprint, request.fingerprint)
        ):
            return None
        return result.value_code

    def _mark_effect_started(self, attempt_no: int, owner_token: str) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """
                UPDATE attempts SET effect_state='STARTED'
                WHERE lifetime_attempt=? AND state='RESERVED'
                  AND effect_state='UNSTARTED' AND owner_token=?
                """,
                (attempt_no, owner_token),
            ).rowcount
            if updated != 1:
                raise DurableConfigurationError(
                    "effect start lost its private reservation"
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _deliver_in_order(self, event: TranscriptEvent) -> TranscriptEvent:
        target = int(event.sequence)
        try:
            while True:
                with self._runtime.condition:
                    next_sequence = self._runtime.next_delivery_sequence
                    if target < next_sequence:
                        # Cached DOMAIN_CLOSED replies intentionally reuse one
                        # public value.  A repeated identical stutter has no order
                        # distinction; a recovered charged response is available
                        # in the persisted transcript.
                        return event
                    if target == next_sequence:
                        if event.kind is EventKind.STOP:
                            # STOP persists deterministic PADDING entries that have
                            # no separate method return.  The next deliverable value
                            # is the cached DOMAIN_CLOSED reply at H+1.
                            self._runtime.next_delivery_sequence = (
                                self.attempt_horizon + 1
                            )
                        else:
                            self._runtime.next_delivery_sequence += 1
                        self._advance_abandoned_deliveries_locked()
                        self._runtime.condition.notify_all()
                        return event
                # Direct multi-process callers are retained only for durable-claim
                # race testing.  Their Python return order is outside the singleton
                # monitor-service boundary, so a finalized response owned by a
                # different process is an already externalized/abandoned prefix for
                # this process-local sequencer.
                if self._advance_foreign_finalized_delivery():
                    continue
                self._recover_reserved_attempts()
                with self._runtime.condition:
                    self._runtime.condition.wait(timeout=0.005)
        except BaseException:
            # The transcript row remains authoritative, but this caller can no
            # longer promise to deliver it.  Advancing only through the ordered
            # abandoned set prevents later live responses from deadlocking.
            self._abandon_delivery(event)
            raise DurableDeliveryError(
                "durable response delivery was interrupted"
            ) from None

    def _advance_foreign_finalized_delivery(self) -> bool:
        with self._runtime.condition:
            sequence = self._runtime.next_delivery_sequence
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT state, owner_pid, event_json FROM attempts
                WHERE lifetime_attempt=?
                """,
                (sequence,),
            ).fetchone()
        finally:
            connection.close()
        if (
            row is None
            or row["state"] != "FINALIZED"
            or type(row["owner_pid"]) is not int
            or int(row["owner_pid"]) == os.getpid()
            or type(row["event_json"]) is not str
        ):
            return False
        self._abandon_delivery(_event_from_json(row["event_json"]))
        return True

    def _advance_abandoned_deliveries_locked(self) -> None:
        while self._runtime.next_delivery_sequence in self._runtime.abandoned_deliveries:
            sequence = self._runtime.next_delivery_sequence
            self._runtime.next_delivery_sequence = (
                self._runtime.abandoned_deliveries.pop(sequence)
            )

    def _abandon_delivery(self, event: TranscriptEvent) -> None:
        sequence = int(event.sequence)
        successor = (
            self.attempt_horizon + 1
            if event.kind is EventKind.STOP
            else sequence + 1
        )
        with self._runtime.condition:
            if sequence >= self._runtime.next_delivery_sequence:
                self._runtime.abandoned_deliveries[sequence] = successor
                self._advance_abandoned_deliveries_locked()
                self._runtime.condition.notify_all()

    def _reject_handler_reentry(self) -> None:
        active = getattr(_HANDLER_CONTEXT, "database_paths", set())
        if self._database_identity in active:
            raise DomainLifecycleError(
                "a durable backend handler cannot reenter its secure domain"
            )

    def _enter_handler(self) -> None:
        self._reject_handler_reentry()
        active = set(getattr(_HANDLER_CONTEXT, "database_paths", set()))
        active.add(self._database_identity)
        _HANDLER_CONTEXT.database_paths = active

    def _exit_handler(self) -> None:
        active = set(getattr(_HANDLER_CONTEXT, "database_paths", set()))
        active.discard(self._database_identity)
        _HANDLER_CONTEXT.database_paths = active

    @staticmethod
    def _acquire_owner() -> tuple[int, str, str]:
        pid = os.getpid()
        identity = _process_identity()
        token = secrets.token_urlsafe(32)
        with _ACTIVE_OWNER_LOCK:
            _ACTIVE_OWNER_TOKENS.add((pid, token))
        return pid, identity, token

    @staticmethod
    def _release_owner(pid: int, owner_token: str) -> None:
        with _ACTIVE_OWNER_LOCK:
            _ACTIVE_OWNER_TOKENS.discard((pid, owner_token))

    def _call_fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)


__all__ = [
    "AttemptCredential",
    "DomainConfig",
    "DomainLifecycleError",
    "DomainState",
    "DurableConfigurationError",
    "DurableDeliveryError",
    "DurableSecureDomain",
    "EffectCapability",
    "EffectRequest",
    "EffectResult",
    "EpochStats",
    "IdempotentEffectHandler",
    "ObserverSpec",
    "ReauthorizationGrant",
    "ReauthorizationPolicy",
    "RouteCodebook",
    "RouteToken",
]
