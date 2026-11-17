"""Singleton AF_UNIX service boundary for :mod:`sluice_v2.durable_secure`.

This module is a Linux CPU integration foundation.  It puts the durable
domain behind one monitor process and deliberately exposes only a bounded
request identifier plus finite operation/template codes to the model.  Route
tokens, payloads, credentials, capabilities, signing material, fingerprints,
and audit state remain in private monitor bindings.

The request cache is stored in the same local SQLite ledger.  A request is
durably bound to its operation and template before the domain call.  On a
monitor crash, the reopened domain first recovers any reserved attempt; a
pending cache row is then reconciled against its pre-recorded transcript
sequence.  This closes the commit/reply window without changing the committed
durable-domain implementation.

Effect routes may use :class:`AuthenticatedBrokerEffectAdapter`.  Its broker
journal never re-executes a PENDING external request: recovery invokes the
predeclared reconcile hook.  Thus an ambiguous broker crash fails closed unless
the external system can report the idempotent request's committed result.  The
external system's own request-ID idempotency and reconcile semantics remain a
deployment assumption, not a theorem established by this CPU module.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import IntEnum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import threading
from typing import Any, Callable, Mapping

from .durable_secure import (
    AttemptCredential,
    DurableConfigurationError,
    DurableSecureDomain,
    EffectRequest,
    EffectResult,
    IdempotentEffectHandler,
    _require_local_wal_filesystem,
)
from .isolation import IPCSchemaError, IPC_MAX_FRAME_BYTES, MAX_IPC_INTEGER
from .linux_isolation import (
    _close_unneeded_fds,
    _connect,
    _harden_process,
    _listener,
    _peer_credentials,
    _recv_packet,
    _seal_process_visibility,
    _send_packet,
)
from .observer import EventKind, TranscriptEvent, TranscriptSchemaError
from .secure import (
    DomainState,
    EffectCapability,
    RouteToken,
    _canonical_payload,
)


MONITOR_PROTOCOL_VERSION = 1
BROKER_PROTOCOL_VERSION = 1
MONITOR_REQUEST_ID_MAX_BYTES = 64
BROKER_FINGERPRINT_BYTES = 64
_ADDRESS_MAX_BYTES = 107
_IPC_IDLE_TIMEOUT_SECONDS = 5.0
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_BROKER_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")


class RequestConfusionError(RuntimeError):
    """One request ID was presented with a different immutable meaning."""


class MonitorCacheError(RuntimeError):
    """The durable service cache cannot be reconciled safely."""


class SingletonServiceBusy(RuntimeError):
    """Another process already owns this ledger's monitor-service lease."""


class ModelOperationCode(IntEnum):
    """Complete model-visible operation alphabet."""

    ATTEMPT_TEMPLATE = 1
    CONTINUE = 2
    STOP = 3


class BrokerOutcomeCode(IntEnum):
    """Finite private monitor-to-broker result alphabet."""

    EXECUTED = 1
    DENIED = 2
    INTERNAL_DENIED = 3
    OUTPUT_DENIED = 4


def _strict_wire_int(
    value: object,
    name: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_IPC_INTEGER,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an exact bounded integer")
    return value


def _request_identifier(value: object, name: str = "request_id") -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is outside the bounded identifier alphabet")
    if len(value.encode("ascii")) > MONITOR_REQUEST_ID_MAX_BYTES:
        raise ValueError(f"{name} exceeds the bounded identifier size")
    return value


def _fingerprint(value: object) -> str:
    if type(value) is not str or _FINGERPRINT.fullmatch(value) is None:
        raise ValueError("fingerprint must be exactly 64 lowercase hexadecimal bytes")
    return value


def _broker_request_identifier(value: object) -> str:
    # Durable v2 effect IDs contain a fixed domain separator plus a 256-bit
    # token and are intentionally longer than the model-facing 64-byte ID.
    if type(value) is not str or _BROKER_IDENTIFIER.fullmatch(value) is None:
        raise ValueError("broker request_id is outside its bounded identifier alphabet")
    if len(value.encode("ascii")) > 128:
        raise ValueError("broker request_id exceeds its bounded identifier size")
    return value


def _exact_wire(wire: object, fields: frozenset[str], version: int) -> dict[str, Any]:
    if type(wire) is not dict or frozenset(wire) != fields:
        raise ValueError("wire object has missing or unexpected fields")
    if type(wire.get("schema_version")) is not int or wire["schema_version"] != version:
        raise ValueError("unsupported wire schema version")
    return wire


def _validate_address(address: object) -> str:
    if type(address) is not str or not address.startswith("\0"):
        raise ValueError("service address must be a private abstract AF_UNIX name")
    try:
        encoded = address.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("service address is not encodable") from exc
    if len(encoded) < 2 or len(encoded) > _ADDRESS_MAX_BYTES:
        raise ValueError("service address exceeds the AF_UNIX address bound")
    return address


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """Kernel-authenticated Linux AF_UNIX peer identity."""

    pid: int
    uid: int
    gid: int

    def __post_init__(self) -> None:
        _strict_wire_int(self.pid, "peer pid", minimum=1)
        _strict_wire_int(self.uid, "peer uid")
        _strict_wire_int(self.gid, "peer gid")

    @classmethod
    def observed(cls, channel: socket.socket) -> "PeerIdentity":
        pid, uid, gid = _peer_credentials(channel)
        return cls(pid=pid, uid=uid, gid=gid)


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """The complete model-to-monitor request DTO."""

    schema_version: int
    request_id: str
    operation_code: ModelOperationCode
    template_code: int | None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != MONITOR_PROTOCOL_VERSION:
            raise ValueError("unsupported monitor protocol version")
        _request_identifier(self.request_id)
        if type(self.operation_code) is not ModelOperationCode:
            raise TypeError("operation_code must be a ModelOperationCode")
        if self.operation_code is ModelOperationCode.ATTEMPT_TEMPLATE:
            _strict_wire_int(self.template_code, "template_code", minimum=1)
        elif self.template_code is not None:
            raise ValueError("non-attempt operations require a null template code")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "operation_code": int(self.operation_code),
            "template_code": self.template_code,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "ModelRequest":
        value = _exact_wire(
            wire,
            frozenset({"schema_version", "request_id", "operation_code", "template_code"}),
            MONITOR_PROTOCOL_VERSION,
        )
        operation_value = _strict_wire_int(value["operation_code"], "operation_code", minimum=1)
        try:
            operation = ModelOperationCode(operation_value)
        except ValueError as exc:
            raise ValueError("unknown model operation code") from exc
        return cls(
            schema_version=value["schema_version"],
            request_id=_request_identifier(value["request_id"]),
            operation_code=operation,
            template_code=value["template_code"],
        )


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """A request binding plus one already-schema-checked public event."""

    schema_version: int
    request_id: str
    event: TranscriptEvent

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != MONITOR_PROTOCOL_VERSION:
            raise ValueError("unsupported monitor protocol version")
        _request_identifier(self.request_id)
        if type(self.event) is not TranscriptEvent:
            raise TypeError("event must be an exact TranscriptEvent")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "event": self.event.to_wire(),
        }

    @classmethod
    def from_wire(cls, wire: object) -> "ModelResponse":
        value = _exact_wire(
            wire,
            frozenset({"schema_version", "request_id", "event"}),
            MONITOR_PROTOCOL_VERSION,
        )
        try:
            event = TranscriptEvent.from_wire(value["event"])
        except (TypeError, ValueError, TranscriptSchemaError) as exc:
            raise ValueError("invalid public transcript response") from exc
        return cls(
            schema_version=value["schema_version"],
            request_id=_request_identifier(value["request_id"]),
            event=event,
        )


@dataclass(frozen=True, slots=True, repr=False)
class PrivateTemplateBinding:
    """Monitor-private exact authority for one public template code."""

    template_code: int
    route: RouteToken
    payload: Any
    credential: AttemptCredential
    capability: EffectCapability | None = None
    redeemer_id: str | None = None
    _payload_canonical: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _strict_wire_int(self.template_code, "template_code", minimum=1)
        if type(self.route) is not RouteToken:
            raise TypeError("route must be an exact RouteToken")
        if type(self.credential) is not AttemptCredential:
            raise TypeError("credential must be an exact AttemptCredential")
        if self.capability is not None and type(self.capability) is not EffectCapability:
            raise TypeError("capability must be an exact EffectCapability or null")
        if self.capability is None:
            if self.redeemer_id is not None:
                raise ValueError("non-effect templates require a null redeemer")
        else:
            _request_identifier(self.redeemer_id, "redeemer_id")
        try:
            canonical = _canonical_payload(self.payload)
            snapshot = copy.deepcopy(self.payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("template payload is outside the durable canonical schema") from exc
        object.__setattr__(self, "payload", snapshot)
        object.__setattr__(self, "_payload_canonical", canonical)

    def payload_snapshot(self) -> Any:
        return copy.deepcopy(self.payload)

    def private_manifest(self) -> dict[str, object]:
        credential = self.credential
        return {
            "template_code": self.template_code,
            "route": self.route.to_wire(),
            "payload": self._payload_canonical.decode("ascii"),
            "credential": {
                "agent_id": credential.agent_id,
                "domain_context": credential.domain_context,
                "expected_epoch": credential.expected_epoch,
                "route_handle": credential.route_handle,
                "nonce": credential.nonce,
                "expires_at_lifetime_attempt": credential.expires_at_lifetime_attempt,
                "signature": credential.signature,
            },
            "capability": None if self.capability is None else self.capability.to_wire(),
            "redeemer_id": self.redeemer_id,
        }


@dataclass(frozen=True, slots=True, repr=False)
class DurableDomainOpener:
    """Trusted data needed only inside the monitor to reopen one ledger."""

    ledger_path: Path
    agent_keys: Mapping[str, bytes] = field(repr=False)
    reauthorization_keys: Mapping[str, bytes] = field(repr=False)
    handler_registry: Mapping[str, Callable[[Any], Any] | IdempotentEffectHandler] = field(
        repr=False
    )

    def __post_init__(self) -> None:
        path = Path(self.ledger_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        object.__setattr__(self, "ledger_path", path)
        if not isinstance(self.agent_keys, Mapping):
            raise TypeError("agent_keys must be a mapping")
        if not isinstance(self.reauthorization_keys, Mapping):
            raise TypeError("reauthorization_keys must be a mapping")
        if not isinstance(self.handler_registry, Mapping):
            raise TypeError("handler_registry must be a mapping")
        object.__setattr__(self, "agent_keys", dict(self.agent_keys))
        object.__setattr__(self, "reauthorization_keys", dict(self.reauthorization_keys))
        object.__setattr__(self, "handler_registry", dict(self.handler_registry))

    def open(self) -> DurableSecureDomain:
        return DurableSecureDomain.reopen(
            self.ledger_path,
            agent_keys=self.agent_keys,
            reauthorization_keys=self.reauthorization_keys,
            handler_registry=self.handler_registry,
        )

    def authenticated_broker_peers(self) -> frozenset[PeerIdentity]:
        peers: set[PeerIdentity] = set()
        for handler in self.handler_registry.values():
            if type(handler) is not IdempotentEffectHandler:
                continue
            execute_owner = getattr(handler.execute, "__self__", None)
            reconcile_owner = getattr(handler.reconcile, "__self__", None)
            if (
                type(execute_owner) is AuthenticatedBrokerEffectAdapter
                and execute_owner is reconcile_owner
            ):
                peers.add(execute_owner.expected_broker)
        return frozenset(peers)


@dataclass(frozen=True, slots=True, repr=False)
class MonitorServiceConfig:
    """Immutable singleton service configuration."""

    address: str
    opener: DurableDomainOpener = field(repr=False)
    templates: tuple[PrivateTemplateBinding, ...] = field(repr=False)
    expected_model: PeerIdentity
    expected_broker: PeerIdentity | None = None
    binding_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_address(self.address)
        if type(self.opener) is not DurableDomainOpener:
            raise TypeError("opener must be a DurableDomainOpener")
        if type(self.templates) is not tuple or not self.templates:
            raise TypeError("templates must be a nonempty tuple")
        if any(type(item) is not PrivateTemplateBinding for item in self.templates):
            raise TypeError("templates must contain exact PrivateTemplateBinding values")
        codes = [item.template_code for item in self.templates]
        if len(codes) != len(set(codes)):
            raise ValueError("template codes must be unique")
        if type(self.expected_model) is not PeerIdentity:
            raise TypeError("expected_model must be a PeerIdentity")
        if self.expected_broker is not None and type(self.expected_broker) is not PeerIdentity:
            raise TypeError("expected_broker must be a PeerIdentity or null")
        if self.expected_broker is not None and self.expected_broker.pid == self.expected_model.pid:
            raise ValueError("model and broker must be distinct processes")

        effect_templates = any(item.capability is not None for item in self.templates)
        adapter_peers = self.opener.authenticated_broker_peers()
        if effect_templates:
            if self.expected_broker is None:
                raise ValueError("effect templates require one authenticated broker peer")
            if adapter_peers != frozenset({self.expected_broker}):
                raise ValueError("effect adapter does not match the configured broker peer")
        elif adapter_peers:
            raise ValueError("broker adapters require an effect template")

        manifest = {
            "schema_version": MONITOR_PROTOCOL_VERSION,
            "templates": [
                binding.private_manifest()
                for binding in sorted(self.templates, key=lambda item: item.template_code)
            ],
            "expected_broker": None
            if self.expected_broker is None
            else {
                "pid": self.expected_broker.pid,
                "uid": self.expected_broker.uid,
                "gid": self.expected_broker.gid,
            },
        }
        encoded = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        object.__setattr__(
            self,
            "binding_sha256",
            hashlib.sha256(b"sluice-monitor-private-bindings-v1\0" + encoded.encode("ascii")).hexdigest(),
        )


class _ExclusiveFileLease:
    """Non-bypassable among cooperating singleton service processes."""

    def __init__(self, path: Path, label: str) -> None:
        self.path = Path(path)
        self.label = label
        self.descriptor: int | None = None

    def acquire(self) -> int:
        if self.descriptor is not None:
            raise RuntimeError("lease is already held")
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid():
                raise MonitorCacheError(f"{self.label} lease is not an owner regular file")
            if status.st_nlink != 1:
                raise MonitorCacheError(f"{self.label} lease has an unsafe link count")
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise SingletonServiceBusy(
                    f"another {self.label} process owns this durable state"
                ) from exc
            os.ftruncate(descriptor, 0)
            encoded = f"{os.getpid()}\n".encode("ascii")
            if os.write(descriptor, encoded) != len(encoded):
                raise OSError("short lease owner write")
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor = descriptor
        return descriptor

    def close(self) -> None:
        if self.descriptor is not None:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = None


_CACHE_META_TABLE_SQL = """
CREATE TABLE sluice_monitor_cache_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    binding_sha256 TEXT NOT NULL
)
""".strip()

_CACHE_TABLE_SQL = """
CREATE TABLE sluice_monitor_request_cache (
    request_id TEXT PRIMARY KEY,
    operation_code INTEGER NOT NULL,
    template_code INTEGER,
    state TEXT NOT NULL CHECK (state IN ('PENDING','DONE')),
    expected_sequence INTEGER,
    event_json TEXT,
    CHECK (
        (state = 'PENDING' AND event_json IS NULL)
        OR (state = 'DONE' AND event_json IS NOT NULL)
    )
)
""".strip()

_CACHE_SEQUENCE_INDEX_SQL = """
CREATE UNIQUE INDEX sluice_monitor_expected_sequence_unique
ON sluice_monitor_request_cache(expected_sequence)
WHERE expected_sequence IS NOT NULL
""".strip()

_CACHE_TRIGGER_IDENTITY_SQL = """
CREATE TRIGGER sluice_monitor_request_identity_immutable
BEFORE UPDATE OF request_id, operation_code, template_code, expected_sequence
ON sluice_monitor_request_cache
BEGIN
    SELECT RAISE(ABORT, 'monitor request identity is immutable');
END
""".strip()

_CACHE_TRIGGER_DONE_SQL = """
CREATE TRIGGER sluice_monitor_done_is_immutable
BEFORE UPDATE ON sluice_monitor_request_cache
WHEN OLD.state = 'DONE'
BEGIN
    SELECT RAISE(ABORT, 'monitor response is immutable');
END
""".strip()

_CACHE_TRIGGER_DELETE_SQL = """
CREATE TRIGGER sluice_monitor_request_is_not_deletable
BEFORE DELETE ON sluice_monitor_request_cache
BEGIN
    SELECT RAISE(ABORT, 'monitor request history is immutable');
END
""".strip()

_CACHE_META_IMMUTABLE_SQL = """
CREATE TRIGGER sluice_monitor_cache_metadata_immutable
BEFORE UPDATE ON sluice_monitor_cache_metadata
BEGIN
    SELECT RAISE(ABORT, 'monitor cache metadata is immutable');
END
""".strip()

_CACHE_META_DELETE_SQL = """
CREATE TRIGGER sluice_monitor_cache_metadata_not_deletable
BEFORE DELETE ON sluice_monitor_cache_metadata
BEGIN
    SELECT RAISE(ABORT, 'monitor cache metadata is immutable');
END
""".strip()


def _normalize_sql(value: str) -> str:
    return " ".join(value.replace(";", " ; ").split()).strip().rstrip(" ;")


class _DurableRequestCache:
    def __init__(self, path: Path, binding_sha256: str) -> None:
        self.path = Path(path)
        self.binding_sha256 = _fingerprint(binding_sha256)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        expected = {
            ("table", "sluice_monitor_cache_metadata"): _CACHE_META_TABLE_SQL,
            ("table", "sluice_monitor_request_cache"): _CACHE_TABLE_SQL,
            ("index", "sluice_monitor_expected_sequence_unique"): _CACHE_SEQUENCE_INDEX_SQL,
            ("trigger", "sluice_monitor_request_identity_immutable"): _CACHE_TRIGGER_IDENTITY_SQL,
            ("trigger", "sluice_monitor_done_is_immutable"): _CACHE_TRIGGER_DONE_SQL,
            ("trigger", "sluice_monitor_request_is_not_deletable"): _CACHE_TRIGGER_DELETE_SQL,
            ("trigger", "sluice_monitor_cache_metadata_immutable"): _CACHE_META_IMMUTABLE_SQL,
            ("trigger", "sluice_monitor_cache_metadata_not_deletable"): _CACHE_META_DELETE_SQL,
        }
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for (kind, name), sql in expected.items():
                row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type=? AND name=?",
                    (kind, name),
                ).fetchone()
                if row is None:
                    if kind == "index" and name == "sluice_monitor_expected_sequence_unique":
                        duplicate = connection.execute(
                            "SELECT expected_sequence FROM sluice_monitor_request_cache "
                            "WHERE expected_sequence IS NOT NULL "
                            "GROUP BY expected_sequence HAVING COUNT(*) > 1 LIMIT 1"
                        ).fetchone()
                        if duplicate is not None:
                            raise MonitorCacheError(
                                "durable monitor cache has conflicting sequence owners"
                            )
                    connection.execute(sql)
                elif type(row["sql"]) is not str or _normalize_sql(row["sql"]) != _normalize_sql(sql):
                    raise MonitorCacheError(f"durable monitor {kind} {name} is malformed")
            row = connection.execute(
                "SELECT schema_version, binding_sha256 FROM sluice_monitor_cache_metadata WHERE singleton=1"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO sluice_monitor_cache_metadata VALUES (1,?,?)",
                    (MONITOR_PROTOCOL_VERSION, self.binding_sha256),
                )
            elif (
                type(row["schema_version"]) is not int
                or row["schema_version"] != MONITOR_PROTOCOL_VERSION
                or type(row["binding_sha256"]) is not str
                or row["binding_sha256"] != self.binding_sha256
            ):
                raise MonitorCacheError("monitor cache is bound to a different private configuration")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _row_event(row: sqlite3.Row) -> TranscriptEvent:
        encoded = row["event_json"]
        if type(encoded) is not str:
            raise MonitorCacheError("completed monitor cache row has no event")
        try:
            value = json.loads(encoded)
            return TranscriptEvent.from_wire(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MonitorCacheError("completed monitor cache event is malformed") from exc

    def lookup_or_begin(self, request: ModelRequest) -> tuple[str, int | None, TranscriptEvent | None]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM sluice_monitor_request_cache WHERE request_id=?",
                (request.request_id,),
            ).fetchone()
            if row is None:
                metadata = connection.execute(
                    "SELECT state, lifetime_attempts, attempt_horizon "
                    "FROM metadata WHERE singleton=1"
                ).fetchone()
                if metadata is None:
                    raise MonitorCacheError("durable domain metadata disappeared")
                state = metadata["state"]
                attempts = metadata["lifetime_attempts"]
                horizon = metadata["attempt_horizon"]
                if (
                    type(state) is not str
                    or type(attempts) is not int
                    or attempts < 0
                    or type(horizon) is not int
                    or horizon <= 0
                    or attempts > horizon
                ):
                    raise MonitorCacheError("durable domain metadata is malformed")
                cache_count = connection.execute(
                    "SELECT COUNT(*) FROM sluice_monitor_request_cache"
                ).fetchone()[0]
                if type(cache_count) is not int or cache_count < 0:
                    raise MonitorCacheError("monitor cache cardinality is malformed")
                # Charged operations contribute at most one request row per
                # horizon slot.  Permit one additional closed-domain stutter
                # binding, then reject novel IDs so uncharged post-close calls
                # cannot grow private durable state without bound.
                if cache_count >= horizon + 1:
                    raise IPCSchemaError("monitor request cache reached its finite bound")
                expected_sequence = attempts + 1 if state == DomainState.ACTIVE.value else None
                if expected_sequence is not None:
                    owner = connection.execute(
                        "SELECT request_id, state, event_json "
                        "FROM sluice_monitor_request_cache WHERE expected_sequence=?",
                        (expected_sequence,),
                    ).fetchone()
                    if owner is not None:
                        if (
                            type(owner["request_id"]) is not str
                            or owner["state"] not in {"PENDING", "DONE"}
                            or (
                                owner["state"] == "PENDING"
                                and owner["event_json"] is not None
                            )
                            or (
                                owner["state"] == "DONE"
                                and type(owner["event_json"]) is not str
                            )
                        ):
                            raise MonitorCacheError(
                                "monitor cache sequence owner is malformed"
                            )
                        if owner["state"] == "PENDING":
                            raise IPCSchemaError(
                                "the next durable sequence belongs to an unresolved request"
                            )
                        raise MonitorCacheError(
                            "a completed cache row is ahead of durable domain state"
                        )
                connection.execute(
                    "INSERT INTO sluice_monitor_request_cache VALUES (?,?,?,?,?,NULL)",
                    (
                        request.request_id,
                        int(request.operation_code),
                        request.template_code,
                        "PENDING",
                        expected_sequence,
                    ),
                )
                connection.commit()
                return "PENDING", expected_sequence, None

            if (
                type(row["operation_code"]) is not int
                or row["operation_code"] != int(request.operation_code)
                or row["template_code"] != request.template_code
            ):
                raise RequestConfusionError(
                    "request ID is already bound to a different operation or template"
                )
            expected = row["expected_sequence"]
            if expected is not None and (type(expected) is not int or expected <= 0):
                raise MonitorCacheError("monitor cache expected sequence is malformed")
            if row["state"] == "DONE":
                event = self._row_event(row)
                connection.commit()
                return "DONE", expected, event
            if row["state"] != "PENDING" or row["event_json"] is not None:
                raise MonitorCacheError("monitor cache state is malformed")
            connection.commit()
            return "PENDING", expected, None
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete(self, request: ModelRequest, event: TranscriptEvent) -> None:
        encoded = json.dumps(event.to_wire(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM sluice_monitor_request_cache WHERE request_id=?",
                (request.request_id,),
            ).fetchone()
            if row is None:
                raise MonitorCacheError("monitor cache reservation disappeared")
            if (
                row["operation_code"] != int(request.operation_code)
                or row["template_code"] != request.template_code
            ):
                raise RequestConfusionError("monitor cache reservation changed meaning")
            if row["state"] == "DONE":
                existing = self._row_event(row)
                if existing != event:
                    raise MonitorCacheError("monitor request has conflicting public responses")
                connection.commit()
                return
            updated = connection.execute(
                "UPDATE sluice_monitor_request_cache SET state='DONE', event_json=? "
                "WHERE request_id=? AND state='PENDING'",
                (encoded, request.request_id),
            ).rowcount
            if updated != 1:
                raise MonitorCacheError("monitor response cache update lost atomicity")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def _expected_kind(operation: ModelOperationCode) -> EventKind:
    if operation is ModelOperationCode.ATTEMPT_TEMPLATE:
        return EventKind.ATTEMPT
    if operation is ModelOperationCode.CONTINUE:
        return EventKind.CONTINUE
    if operation is ModelOperationCode.STOP:
        return EventKind.STOP
    raise AssertionError("unreachable finite operation")


class SingletonMonitorService:
    """Blocking singleton monitor server; construct before fork, open after fork."""

    def __init__(
        self,
        config: MonitorServiceConfig,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if type(config) is not MonitorServiceConfig:
            raise TypeError("config must be a MonitorServiceConfig")
        if fault_hook is not None and not callable(fault_hook):
            raise TypeError("fault_hook must be callable or null")
        self.config = config
        self.fault_hook = fault_hook
        self._templates = {item.template_code: item for item in config.templates}
        self._domain: DurableSecureDomain | None = None
        self._cache: _DurableRequestCache | None = None

    def _fault(self, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(stage)

    def _validate_event(
        self,
        request: ModelRequest,
        event: TranscriptEvent,
        expected_sequence: int | None,
    ) -> None:
        if type(event) is not TranscriptEvent:
            raise MonitorCacheError("domain returned a non-transcript value")
        if expected_sequence is None:
            if event.kind is not EventKind.DOMAIN_CLOSED:
                raise MonitorCacheError("an uncharged service call did not return DOMAIN_CLOSED")
            return
        if event.sequence != expected_sequence:
            raise MonitorCacheError("domain response does not match the reserved service sequence")
        if event.kind is not _expected_kind(request.operation_code):
            raise MonitorCacheError("domain response kind does not match the service operation")

    def _recover_pending(
        self,
        request: ModelRequest,
        expected_sequence: int | None,
    ) -> TranscriptEvent | None:
        assert self._domain is not None
        if expected_sequence is None:
            return None
        for event in self._domain.transcript:
            if event.sequence == expected_sequence:
                self._validate_event(request, event, expected_sequence)
                return event
        if self._domain.attempts_used >= expected_sequence:
            raise MonitorCacheError("pending request sequence is absent from the finalized transcript")
        return None

    def _execute(self, request: ModelRequest) -> TranscriptEvent:
        assert self._domain is not None
        if request.operation_code is ModelOperationCode.ATTEMPT_TEMPLATE:
            assert request.template_code is not None
            binding = self._templates.get(request.template_code)
            if binding is None:
                raise IPCSchemaError("unknown predeclared template code")
            return self._domain.attempt(
                binding.route,
                binding.payload_snapshot(),
                credential=binding.credential,
                capability=binding.capability,
                redeemer_id=binding.redeemer_id,
            )
        if request.operation_code is ModelOperationCode.CONTINUE:
            return self._domain.continue_work()
        if request.operation_code is ModelOperationCode.STOP:
            return self._domain.stop()
        raise IPCSchemaError("unknown finite operation code")

    def _handle(self, request: ModelRequest) -> TranscriptEvent:
        if (
            request.operation_code is ModelOperationCode.ATTEMPT_TEMPLATE
            and request.template_code not in self._templates
        ):
            raise IPCSchemaError("unknown predeclared template code")
        assert self._cache is not None
        state, expected_sequence, cached = self._cache.lookup_or_begin(request)
        if state == "DONE":
            assert cached is not None
            self._validate_event(request, cached, expected_sequence)
            return cached
        recovered = self._recover_pending(request, expected_sequence)
        if recovered is not None:
            self._cache.complete(request, recovered)
            return recovered
        self._fault("after_pending_before_domain")
        event = self._execute(request)
        self._validate_event(request, event, expected_sequence)
        self._fault("after_domain_before_cache")
        self._cache.complete(request, event)
        self._fault("after_cache_before_send")
        return event

    def _serve_connection(self, channel: socket.socket) -> None:
        if PeerIdentity.observed(channel) != self.config.expected_model:
            return
        channel.settimeout(_IPC_IDLE_TIMEOUT_SECONDS)
        while True:
            try:
                wire = _recv_packet(channel)
            except (EOFError, OSError):
                return
            try:
                request = ModelRequest.from_wire(wire)
                event = self._handle(request)
                _send_packet(
                    channel,
                    ModelResponse(
                        schema_version=MONITOR_PROTOCOL_VERSION,
                        request_id=request.request_id,
                        event=event,
                    ).to_wire(),
                )
            except (IPCSchemaError, ValueError, RequestConfusionError, OSError):
                return

    def serve_forever(self, *, expected_parent_pid: int, ready_fd: int | None = None) -> None:
        _harden_process(expected_parent_pid)
        _seal_process_visibility()
        if self.config.expected_model.pid == os.getpid():
            raise ValueError("the monitor process cannot also be the model peer")
        if self.config.expected_broker is not None and self.config.expected_broker.pid == os.getpid():
            raise ValueError("the monitor process cannot also be the broker peer")
        if ready_fd is not None and (type(ready_fd) is not int or ready_fd < 3):
            raise ValueError("ready_fd must be an inherited descriptor >= 3")
        lease = _ExclusiveFileLease(
            Path(str(self.config.opener.ledger_path) + ".monitor-service.lock"),
            "monitor service",
        )
        listener: socket.socket | None = None
        try:
            lease_fd = lease.acquire()
            self._domain = self.config.opener.open()
            self._cache = _DurableRequestCache(
                self.config.opener.ledger_path,
                self.config.binding_sha256,
            )
            listener = _listener(self.config.address)
            # A trusted handler that forks must not leave its child holding the
            # monitor listener, current model connection, singleton lease, or
            # any other inherited descriptor.  RLIMIT_NOFILE was capped at 64
            # by the audited process hardener before this callback is installed.
            os.register_at_fork(after_in_child=lambda: os.closerange(3, 64))
            keep = {lease_fd, listener.fileno()}
            if ready_fd is not None:
                keep.add(ready_fd)
            _close_unneeded_fds(frozenset(keep))
            if ready_fd is not None:
                if os.write(ready_fd, b"R") != 1:
                    raise OSError("short monitor ready write")
                os.close(ready_fd)
                ready_fd = None
            while True:
                channel, _ = listener.accept()
                try:
                    self._serve_connection(channel)
                finally:
                    channel.close()
        finally:
            if ready_fd is not None:
                try:
                    os.close(ready_fd)
                except OSError:
                    pass
            if listener is not None:
                listener.close()
            if self._domain is not None:
                self._domain.close()
            lease.close()


def connect_model(
    address: str,
    request: ModelRequest,
    *,
    expected_monitor: PeerIdentity,
    timeout_seconds: float = 5.0,
) -> TranscriptEvent:
    """Send one exact request and authenticate the singleton monitor peer."""

    _validate_address(address)
    if type(request) is not ModelRequest:
        raise TypeError("request must be a ModelRequest")
    if type(expected_monitor) is not PeerIdentity:
        raise TypeError("expected_monitor must be a PeerIdentity")
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
        raise ValueError("timeout_seconds must be in (0,60]")
    channel = _connect(address)
    try:
        channel.settimeout(float(timeout_seconds))
        if PeerIdentity.observed(channel) != expected_monitor:
            raise ConnectionError("monitor SO_PEERCRED identity mismatch")
        _send_packet(channel, request.to_wire())
        try:
            wire = _recv_packet(channel)
        except (IPCSchemaError, socket.timeout) as exc:
            raise ConnectionError("monitor returned no valid bounded response") from exc
        response = ModelResponse.from_wire(wire)
        if response.request_id != request.request_id:
            raise RequestConfusionError("monitor response is bound to another request")
        return response.event
    finally:
        channel.close()


@dataclass(frozen=True, slots=True)
class BrokerCommand:
    """Exact private monitor-to-broker command; it contains no raw payload."""

    schema_version: int
    request_id: str
    fingerprint: str
    template_code: int

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != BROKER_PROTOCOL_VERSION:
            raise ValueError("unsupported broker protocol version")
        _broker_request_identifier(self.request_id)
        _fingerprint(self.fingerprint)
        _strict_wire_int(self.template_code, "broker template_code", minimum=1)

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "fingerprint": self.fingerprint,
            "template_code": self.template_code,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "BrokerCommand":
        value = _exact_wire(
            wire,
            frozenset({"schema_version", "request_id", "fingerprint", "template_code"}),
            BROKER_PROTOCOL_VERSION,
        )
        return cls(
            schema_version=value["schema_version"],
            request_id=_broker_request_identifier(value["request_id"]),
            fingerprint=_fingerprint(value["fingerprint"]),
            template_code=_strict_wire_int(value["template_code"], "template_code", minimum=1),
        )


@dataclass(frozen=True, slots=True)
class BrokerReply:
    schema_version: int
    request_id: str
    fingerprint: str
    outcome_code: BrokerOutcomeCode
    value_code: int | None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != BROKER_PROTOCOL_VERSION:
            raise ValueError("unsupported broker protocol version")
        _broker_request_identifier(self.request_id)
        _fingerprint(self.fingerprint)
        if type(self.outcome_code) is not BrokerOutcomeCode:
            raise TypeError("outcome_code must be a BrokerOutcomeCode")
        if self.outcome_code is BrokerOutcomeCode.EXECUTED:
            _strict_wire_int(self.value_code, "value_code")
        elif self.value_code is not None:
            raise ValueError("only EXECUTED broker replies may carry a value")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "fingerprint": self.fingerprint,
            "outcome_code": int(self.outcome_code),
            "value_code": self.value_code,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "BrokerReply":
        value = _exact_wire(
            wire,
            frozenset({"schema_version", "request_id", "fingerprint", "outcome_code", "value_code"}),
            BROKER_PROTOCOL_VERSION,
        )
        outcome_value = _strict_wire_int(value["outcome_code"], "outcome_code", minimum=1)
        try:
            outcome = BrokerOutcomeCode(outcome_value)
        except ValueError as exc:
            raise ValueError("unknown broker outcome code") from exc
        return cls(
            schema_version=value["schema_version"],
            request_id=_broker_request_identifier(value["request_id"]),
            fingerprint=_fingerprint(value["fingerprint"]),
            outcome_code=outcome,
            value_code=value["value_code"],
        )


@dataclass(frozen=True, slots=True, repr=False)
class BrokerTemplateBinding:
    template_code: int
    public_values: frozenset[int]
    execute: Callable[[str], int] = field(repr=False)
    reconcile: Callable[[str], int | None] = field(repr=False)

    def __post_init__(self) -> None:
        _strict_wire_int(self.template_code, "broker template_code", minimum=1)
        if type(self.public_values) is not frozenset or not self.public_values:
            raise TypeError("broker public_values must be a nonempty frozenset")
        for value in self.public_values:
            _strict_wire_int(value, "broker public value")
        if not callable(self.execute) or not callable(self.reconcile):
            raise TypeError("broker execute and reconcile hooks must be callable")


_BROKER_META_SQL = """
CREATE TABLE broker_journal_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    binding_sha256 TEXT NOT NULL
)
""".strip()

_BROKER_TABLE_SQL = """
CREATE TABLE broker_requests (
    request_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    template_code INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','DONE')),
    value_code INTEGER,
    CHECK (
        (state = 'PENDING' AND value_code IS NULL)
        OR (state = 'DONE' AND value_code IS NOT NULL)
    )
)
""".strip()

_BROKER_IDENTITY_TRIGGER_SQL = """
CREATE TRIGGER broker_request_identity_immutable
BEFORE UPDATE OF request_id, fingerprint, template_code ON broker_requests
BEGIN
    SELECT RAISE(ABORT, 'broker request identity is immutable');
END
""".strip()

_BROKER_DONE_TRIGGER_SQL = """
CREATE TRIGGER broker_done_is_immutable
BEFORE UPDATE ON broker_requests WHEN OLD.state = 'DONE'
BEGIN
    SELECT RAISE(ABORT, 'broker result is immutable');
END
""".strip()

_BROKER_DELETE_TRIGGER_SQL = """
CREATE TRIGGER broker_request_is_not_deletable
BEFORE DELETE ON broker_requests
BEGIN
    SELECT RAISE(ABORT, 'broker request history is immutable');
END
""".strip()

_BROKER_META_IMMUTABLE_SQL = """
CREATE TRIGGER broker_journal_metadata_immutable
BEFORE UPDATE ON broker_journal_metadata
BEGIN
    SELECT RAISE(ABORT, 'broker journal metadata is immutable');
END
""".strip()

_BROKER_META_DELETE_SQL = """
CREATE TRIGGER broker_journal_metadata_not_deletable
BEFORE DELETE ON broker_journal_metadata
BEGIN
    SELECT RAISE(ABORT, 'broker journal metadata is immutable');
END
""".strip()


class BrokerJournal:
    """Durable at-most-once claim and reconcile seam for external effects."""

    def __init__(
        self,
        path: Path,
        bindings: tuple[BrokerTemplateBinding, ...],
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path).resolve()
        if type(bindings) is not tuple or not bindings:
            raise TypeError("broker bindings must be a nonempty tuple")
        if any(type(binding) is not BrokerTemplateBinding for binding in bindings):
            raise TypeError("broker bindings contain a wrong value")
        codes = [binding.template_code for binding in bindings]
        if len(codes) != len(set(codes)):
            raise ValueError("broker template codes must be unique")
        if fault_hook is not None and not callable(fault_hook):
            raise TypeError("fault_hook must be callable or null")
        self._bindings = {binding.template_code: binding for binding in bindings}
        self._fault_hook = fault_hook
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _require_local_wal_filesystem(self.path if self.path.exists() else self.path.parent)
        manifest = [
            {
                "template_code": binding.template_code,
                "public_values": sorted(binding.public_values),
            }
            for binding in sorted(bindings, key=lambda item: item.template_code)
        ]
        encoded = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        self.binding_sha256 = hashlib.sha256(
            b"sluice-broker-bindings-v1\0" + encoded.encode("ascii")
        ).hexdigest()
        self._initialize()

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        expected = {
            ("table", "broker_journal_metadata"): _BROKER_META_SQL,
            ("table", "broker_requests"): _BROKER_TABLE_SQL,
            ("trigger", "broker_request_identity_immutable"): _BROKER_IDENTITY_TRIGGER_SQL,
            ("trigger", "broker_done_is_immutable"): _BROKER_DONE_TRIGGER_SQL,
            ("trigger", "broker_request_is_not_deletable"): _BROKER_DELETE_TRIGGER_SQL,
            ("trigger", "broker_journal_metadata_immutable"): _BROKER_META_IMMUTABLE_SQL,
            ("trigger", "broker_journal_metadata_not_deletable"): _BROKER_META_DELETE_SQL,
        }
        connection = self._connect()
        try:
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if journal is None or type(journal[0]) is not str or journal[0].lower() != "wal":
                raise MonitorCacheError("broker journal could not enable SQLite WAL")
            connection.execute("BEGIN IMMEDIATE")
            for (kind, name), sql in expected.items():
                row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type=? AND name=?",
                    (kind, name),
                ).fetchone()
                if row is None:
                    connection.execute(sql)
                elif type(row["sql"]) is not str or _normalize_sql(row["sql"]) != _normalize_sql(sql):
                    raise MonitorCacheError(f"broker {kind} {name} is malformed")
            row = connection.execute(
                "SELECT schema_version, binding_sha256 FROM broker_journal_metadata WHERE singleton=1"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO broker_journal_metadata VALUES (1,?,?)",
                    (BROKER_PROTOCOL_VERSION, self.binding_sha256),
                )
            elif (
                row["schema_version"] != BROKER_PROTOCOL_VERSION
                or row["binding_sha256"] != self.binding_sha256
            ):
                raise MonitorCacheError("broker journal is bound to another configuration")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        os.chmod(self.path, 0o600)
        status = self.path.stat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
        ):
            raise MonitorCacheError("broker journal is not an owner regular file")

    @staticmethod
    def _reply(command: BrokerCommand, outcome: BrokerOutcomeCode, value: int | None = None) -> BrokerReply:
        return BrokerReply(
            schema_version=BROKER_PROTOCOL_VERSION,
            request_id=command.request_id,
            fingerprint=command.fingerprint,
            outcome_code=outcome,
            value_code=value,
        )

    def _complete(self, command: BrokerCommand, value: int) -> BrokerReply:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE broker_requests SET state='DONE', value_code=? "
                "WHERE request_id=? AND fingerprint=? AND template_code=? AND state='PENDING'",
                (value, command.request_id, command.fingerprint, command.template_code),
            ).rowcount
            if updated != 1:
                raise MonitorCacheError("broker result update lost atomicity")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self._reply(command, BrokerOutcomeCode.EXECUTED, value)

    def execute(self, command: BrokerCommand) -> BrokerReply:
        if type(command) is not BrokerCommand:
            raise TypeError("command must be a BrokerCommand")
        binding = self._bindings.get(command.template_code)
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM broker_requests WHERE request_id=?",
                    (command.request_id,),
                ).fetchone()
                is_new = row is None
                if row is None:
                    if binding is None:
                        connection.rollback()
                        return self._reply(command, BrokerOutcomeCode.DENIED)
                    connection.execute(
                        "INSERT INTO broker_requests VALUES (?,?,?,'PENDING',NULL)",
                        (command.request_id, command.fingerprint, command.template_code),
                    )
                    connection.commit()
                else:
                    if (
                        row["fingerprint"] != command.fingerprint
                        or row["template_code"] != command.template_code
                    ):
                        raise RequestConfusionError(
                            "broker request ID is already bound to another command"
                        )
                    if row["state"] == "DONE":
                        value = row["value_code"]
                        if type(value) is not int or value not in binding.public_values:
                            raise MonitorCacheError("broker cached value is outside its codebook")
                        connection.commit()
                        return self._reply(command, BrokerOutcomeCode.EXECUTED, value)
                    if row["state"] != "PENDING" or row["value_code"] is not None:
                        raise MonitorCacheError("broker request state is malformed")
                    connection.commit()
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

            # An existing ID is checked for confusion before this point even
            # if its newly supplied code is unknown.  A new unknown code was
            # denied above without reserving or executing an effect.
            assert binding is not None

            if is_new:
                self._fault("after_claim_before_execute")
                try:
                    value: object = binding.execute(command.request_id)
                except BaseException:
                    try:
                        value = binding.reconcile(command.request_id)
                    except BaseException:
                        return self._reply(command, BrokerOutcomeCode.INTERNAL_DENIED)
            else:
                # Never execute a PENDING external request twice.  A missing
                # reconciliation result is a fail-closed availability loss.
                try:
                    value = binding.reconcile(command.request_id)
                except BaseException:
                    return self._reply(command, BrokerOutcomeCode.INTERNAL_DENIED)

            if value is None:
                return self._reply(command, BrokerOutcomeCode.DENIED)
            if type(value) is not int or value not in binding.public_values:
                return self._reply(command, BrokerOutcomeCode.OUTPUT_DENIED)
            self._fault("after_execute_before_done")
            return self._complete(command, value)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedBrokerEffectAdapter:
    """Durable effect handler backed by one SO_PEERCRED-authenticated broker."""

    address: str
    expected_broker: PeerIdentity
    payload_templates: tuple[tuple[Any, int], ...] = field(repr=False)
    timeout_seconds: float = 5.0
    _canonical_templates: tuple[tuple[bytes, int], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _validate_address(self.address)
        if type(self.expected_broker) is not PeerIdentity:
            raise TypeError("expected_broker must be a PeerIdentity")
        if type(self.payload_templates) is not tuple or not self.payload_templates:
            raise TypeError("payload_templates must be a nonempty tuple")
        if type(self.timeout_seconds) not in (int, float) or not 0 < self.timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be in (0,60]")
        canonical: list[tuple[bytes, int]] = []
        for item in self.payload_templates:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("payload template entries must be exact pairs")
            payload, code = item
            _strict_wire_int(code, "broker template code", minimum=1)
            encoded = _canonical_payload(payload)
            if any(existing == encoded for existing, _ in canonical):
                raise ValueError("broker payload templates must be unique")
            canonical.append((encoded, code))
        object.__setattr__(self, "_canonical_templates", tuple(canonical))

    def _template_code(self, payload: Any) -> int | None:
        try:
            encoded = _canonical_payload(payload)
        except (TypeError, ValueError):
            return None
        for candidate, code in self._canonical_templates:
            if candidate == encoded:
                return code
        return None

    def _exchange(self, request: EffectRequest) -> EffectResult | None:
        if type(request) is not EffectRequest:
            return None
        code = self._template_code(request.payload)
        if code is None:
            return None
        try:
            command = BrokerCommand(
                schema_version=BROKER_PROTOCOL_VERSION,
                request_id=request.request_id,
                fingerprint=request.fingerprint,
                template_code=code,
            )
            channel = _connect(self.address)
            try:
                channel.settimeout(float(self.timeout_seconds))
                if PeerIdentity.observed(channel) != self.expected_broker:
                    return None
                _send_packet(channel, command.to_wire())
                reply = BrokerReply.from_wire(_recv_packet(channel))
            finally:
                channel.close()
        except (OSError, EOFError, ValueError, IPCSchemaError):
            return None
        if (
            reply.request_id != request.request_id
            or reply.fingerprint != request.fingerprint
            or reply.outcome_code is not BrokerOutcomeCode.EXECUTED
            or type(reply.value_code) is not int
        ):
            return None
        return EffectResult.for_request(request, reply.value_code)

    def execute(self, request: EffectRequest) -> EffectResult | None:
        return self._exchange(request)

    def reconcile(self, request: EffectRequest) -> EffectResult | None:
        return self._exchange(request)

    def as_effect_handler(self) -> IdempotentEffectHandler:
        return IdempotentEffectHandler(execute=self.execute, reconcile=self.reconcile)


def _peer_from_bootstrap_fd(descriptor: int) -> PeerIdentity:
    if type(descriptor) is not int or descriptor < 3:
        raise ValueError("expected_monitor_fd must be a descriptor >= 3")
    encoded = os.read(descriptor, 257)
    if not encoded or len(encoded) > 256:
        raise IPCSchemaError("broker peer bootstrap exceeds its finite bound")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCSchemaError("broker peer bootstrap is malformed") from exc
    if type(value) is not dict or frozenset(value) != frozenset({"pid", "uid", "gid"}):
        raise IPCSchemaError("broker peer bootstrap fields are not exact")
    return PeerIdentity(pid=value["pid"], uid=value["uid"], gid=value["gid"])


def serve_broker(
    *,
    address: str,
    expected_monitor: PeerIdentity | None,
    journal: BrokerJournal,
    expected_parent_pid: int,
    ready_fd: int | None = None,
    expected_monitor_fd: int | None = None,
) -> None:
    """Serve the private broker journal to exactly one monitor process PID."""

    _validate_address(address)
    if type(journal) is not BrokerJournal:
        raise TypeError("journal must be a BrokerJournal")
    if (expected_monitor is None) == (expected_monitor_fd is None):
        raise ValueError("provide exactly one expected monitor identity source")
    _harden_process(expected_parent_pid)
    _seal_process_visibility()
    if expected_monitor_fd is not None:
        expected_monitor = _peer_from_bootstrap_fd(expected_monitor_fd)
        os.close(expected_monitor_fd)
        expected_monitor_fd = None
    assert expected_monitor is not None
    if type(expected_monitor) is not PeerIdentity:
        raise TypeError("expected_monitor must be a PeerIdentity")
    if expected_monitor.pid == os.getpid():
        raise ValueError("the broker process cannot also be the monitor peer")
    if ready_fd is not None and (type(ready_fd) is not int or ready_fd < 3):
        raise ValueError("ready_fd must be an inherited descriptor >= 3")
    lease = _ExclusiveFileLease(Path(str(journal.path) + ".broker-service.lock"), "broker service")
    listener: socket.socket | None = None
    try:
        lease_fd = lease.acquire()
        listener = _listener(address)
        os.register_at_fork(after_in_child=lambda: os.closerange(3, 64))
        keep = {lease_fd, listener.fileno()}
        if ready_fd is not None:
            keep.add(ready_fd)
        _close_unneeded_fds(frozenset(keep))
        if ready_fd is not None:
            if os.write(ready_fd, b"R") != 1:
                raise OSError("short broker ready write")
            os.close(ready_fd)
            ready_fd = None
        while True:
            channel, _ = listener.accept()
            try:
                if PeerIdentity.observed(channel) != expected_monitor:
                    continue
                channel.settimeout(_IPC_IDLE_TIMEOUT_SECONDS)
                try:
                    command = BrokerCommand.from_wire(_recv_packet(channel))
                    reply = journal.execute(command)
                    _send_packet(channel, reply.to_wire())
                except (EOFError, IPCSchemaError, ValueError, RequestConfusionError, OSError):
                    continue
            finally:
                channel.close()
    finally:
        if expected_monitor_fd is not None:
            try:
                os.close(expected_monitor_fd)
            except OSError:
                pass
        if ready_fd is not None:
            try:
                os.close(ready_fd)
            except OSError:
                pass
        if listener is not None:
            listener.close()
        lease.close()


__all__ = [
    "AuthenticatedBrokerEffectAdapter",
    "BROKER_PROTOCOL_VERSION",
    "BrokerCommand",
    "BrokerJournal",
    "BrokerOutcomeCode",
    "BrokerReply",
    "BrokerTemplateBinding",
    "DurableDomainOpener",
    "MONITOR_PROTOCOL_VERSION",
    "ModelOperationCode",
    "ModelRequest",
    "ModelResponse",
    "MonitorCacheError",
    "MonitorServiceConfig",
    "PeerIdentity",
    "PrivateTemplateBinding",
    "RequestConfusionError",
    "SingletonMonitorService",
    "SingletonServiceBusy",
    "connect_model",
    "serve_broker",
]
