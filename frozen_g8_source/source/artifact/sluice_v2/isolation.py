"""Fail-closed process-boundary primitives for a Sluice deployment.

This module contains the finite IPC and startup-validation layer.  It does not
pretend that the presence of a namespace utility proves that a process was
launched inside a sandbox: :func:`detect_host_enforcement` reports the current
process conservatively, and a strict service launcher must supply evidence for
each boundary it actually establishes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import shutil
import sqlite3
import threading
from typing import Any, Callable, Mapping


IPC_SCHEMA_VERSION = 1
IPC_MAX_FRAME_BYTES = 4096
MAX_IPC_INTEGER = (1 << 63) - 1
_MAX_TOKEN_BYTES = 1024


class IPCSchemaError(ValueError):
    """A message or durable request violates the finite IPC schema."""


class IsolationStartupError(RuntimeError):
    """The requested isolation policy cannot be enforced."""


class InjectedCrash(RuntimeError):
    """Test-only crash edge reached by the durable claim journal."""


class ProcessRole(str, Enum):
    MODEL = "model"
    MONITOR = "monitor"
    EFFECT_BROKER = "effect_broker"


class IPCMessageKind(str, Enum):
    MODEL_REQUEST = "model_request"
    PUBLIC_EVENT = "public_event"
    EFFECT_COMMAND = "effect_command"
    EFFECT_RESULT = "effect_result"


class BrokerOutcome(str, Enum):
    EXECUTED = "executed"
    DENIED = "denied"
    INTERNAL_DENIED = "internal_denied"
    OUTPUT_DENIED = "output_denied"


class CrashPoint(str, Enum):
    NONE = "none"
    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT = "after_commit"


class RecoveryDisposition(str, Enum):
    NOT_COMMITTED = "not_committed"
    COMMITTED = "committed"


def _strict_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_IPC_INTEGER:
        raise IPCSchemaError(f"{name} must be an integer >= {minimum}")
    return value


def _strict_text(value: Any, name: str) -> str:
    if type(value) is not str or not value:
        raise IPCSchemaError(f"{name} must be a non-empty string")
    if len(value.encode("utf-8")) > _MAX_TOKEN_BYTES:
        raise IPCSchemaError(f"{name} exceeds the bounded token size")
    return value


def _exact_keys(wire: Any, expected: frozenset[str]) -> dict[str, Any]:
    if type(wire) is not dict or frozenset(wire) != expected:
        raise IPCSchemaError("message has missing or unexpected fields")
    if wire.get("schema_version") != IPC_SCHEMA_VERSION:
        raise IPCSchemaError("unsupported IPC schema version")
    return wire


@dataclass(frozen=True)
class IsolationManifest:
    ipc_max_frame_bytes: int
    process_roles: tuple[ProcessRole, ...] = (
        ProcessRole.MODEL,
        ProcessRole.MONITOR,
        ProcessRole.EFFECT_BROKER,
    )
    ipc_transport: str = "unix_domain_socket"
    require_kernel_enforcement: bool = True
    model_network: str = "deny"
    model_ledger: str = "deny"
    model_signing_keys: str = "deny"
    model_tool_credentials: str = "deny"
    model_raw_audit: str = "deny"
    broker_effects: str = "allowlist"
    tool_sandbox: str = "required"
    worker_error_policy: str = "fail_closed"

    def __post_init__(self) -> None:
        if type(self.ipc_max_frame_bytes) is not int or self.ipc_max_frame_bytes <= 0:
            raise TypeError("ipc_max_frame_bytes must be a positive integer")
        if self.process_roles != (
            ProcessRole.MODEL,
            ProcessRole.MONITOR,
            ProcessRole.EFFECT_BROKER,
        ):
            raise ValueError("strict topology requires model, monitor, and effect broker")
        canonical = {
            "ipc_transport": "unix_domain_socket",
            "require_kernel_enforcement": True,
            "model_network": "deny",
            "model_ledger": "deny",
            "model_signing_keys": "deny",
            "model_tool_credentials": "deny",
            "model_raw_audit": "deny",
            "broker_effects": "allowlist",
            "tool_sandbox": "required",
            "worker_error_policy": "fail_closed",
        }
        for name, expected in canonical.items():
            if getattr(self, name) != expected:
                raise ValueError(f"strict manifest requires canonical {name}")
        if type(self.require_kernel_enforcement) is not bool:
            raise TypeError("require_kernel_enforcement must be Boolean")
        if self.ipc_max_frame_bytes > IPC_MAX_FRAME_BYTES:
            raise ValueError("IPC frame ceiling exceeds the audited maximum")

    @classmethod
    def strict(cls, *, ipc_max_frame_bytes: int) -> "IsolationManifest":
        return cls(ipc_max_frame_bytes=ipc_max_frame_bytes)

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": IPC_SCHEMA_VERSION,
            "process_roles": [role.value for role in self.process_roles],
            "ipc_transport": self.ipc_transport,
            "ipc_max_frame_bytes": self.ipc_max_frame_bytes,
            "require_kernel_enforcement": self.require_kernel_enforcement,
            "model_network": self.model_network,
            "model_ledger": self.model_ledger,
            "model_signing_keys": self.model_signing_keys,
            "model_tool_credentials": self.model_tool_credentials,
            "model_raw_audit": self.model_raw_audit,
            "broker_effects": self.broker_effects,
            "tool_sandbox": self.tool_sandbox,
            "worker_error_policy": self.worker_error_policy,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "IsolationManifest":
        expected = frozenset(
            {
                "schema_version",
                "process_roles",
                "ipc_transport",
                "ipc_max_frame_bytes",
                "require_kernel_enforcement",
                "model_network",
                "model_ledger",
                "model_signing_keys",
                "model_tool_credentials",
                "model_raw_audit",
                "broker_effects",
                "tool_sandbox",
                "worker_error_policy",
            }
        )
        value = _exact_keys(wire, expected)
        canonical = cls.strict(
            ipc_max_frame_bytes=_strict_int(
                value["ipc_max_frame_bytes"], "ipc_max_frame_bytes", minimum=1
            )
        )
        if value != canonical.to_wire():
            raise IPCSchemaError("non-canonical or weakened isolation manifest")
        return canonical


_REQUIREMENT_FIELDS = (
    "kernel_enforced",
    "distinct_processes",
    "private_ipc",
    "model_network_denied",
    "model_ledger_denied",
    "model_signing_keys_denied",
    "model_tool_credentials_denied",
    "model_raw_audit_denied",
    "broker_allowlist_enforced",
    "tool_sandbox_enforced",
)


@dataclass(frozen=True)
class EnforcementReport:
    kernel_enforced: bool
    distinct_processes: bool
    private_ipc: bool
    model_network_denied: bool
    model_ledger_denied: bool
    model_signing_keys_denied: bool
    model_tool_credentials_denied: bool
    model_raw_audit_denied: bool
    broker_allowlist_enforced: bool
    tool_sandbox_enforced: bool
    unshare_available: bool = field(
        default_factory=lambda: shutil.which("unshare") is not None
    )

    def __post_init__(self) -> None:
        for name in (*_REQUIREMENT_FIELDS, "unshare_available"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a Boolean")

    def missing_requirements(self, manifest: IsolationManifest) -> tuple[str, ...]:
        if not isinstance(manifest, IsolationManifest):
            raise TypeError("manifest must be IsolationManifest")
        return tuple(name for name in _REQUIREMENT_FIELDS if not getattr(self, name))


def detect_host_enforcement() -> EnforcementReport:
    """Report enforcement for the current, unsandboxed process conservatively.

    Capability discovery and deployment attestation are separate.  A launcher
    may use ``unshare``/LSM/container primitives and construct a positive report
    only after verifying the child topology and access-denial probes.
    """

    return EnforcementReport(
        kernel_enforced=False,
        distinct_processes=False,
        private_ipc=False,
        model_network_denied=False,
        model_ledger_denied=False,
        model_signing_keys_denied=False,
        model_tool_credentials_denied=False,
        model_raw_audit_denied=False,
        broker_allowlist_enforced=False,
        tool_sandbox_enforced=False,
        unshare_available=shutil.which("unshare") is not None,
    )


def validate_startup(
    manifest: IsolationManifest, report: EnforcementReport
) -> None:
    if not isinstance(manifest, IsolationManifest):
        raise TypeError("manifest must be IsolationManifest")
    if not isinstance(report, EnforcementReport):
        raise TypeError("report must be EnforcementReport")
    missing = report.missing_requirements(manifest)
    if missing:
        raise IsolationStartupError(
            "strict isolation requirements unavailable: " + ", ".join(missing)
        )


@dataclass(frozen=True)
class ProcessTopology:
    pids: Mapping[ProcessRole, int]

    def validate_live_and_distinct(self) -> None:
        if type(self.pids) is not dict or set(self.pids) != set(ProcessRole):
            raise IsolationStartupError("topology must contain all three process roles")
        values: list[int] = []
        for role, pid in self.pids.items():
            if not isinstance(role, ProcessRole) or type(pid) is not int or pid <= 0:
                raise IsolationStartupError("topology contains an invalid process ID")
            try:
                os.kill(pid, 0)
            except OSError as exc:
                raise IsolationStartupError(f"{role.value} process is not live") from exc
            values.append(pid)
        if len(set(values)) != len(ProcessRole):
            raise IsolationStartupError("service process IDs must be distinct")


def sanitize_model_environment(
    parent: Mapping[str, str], *, allowed_names: frozenset[str]
) -> dict[str, str]:
    if not isinstance(parent, Mapping) or type(allowed_names) is not frozenset:
        raise TypeError("environment and positive allowlist have invalid types")
    if any(type(name) is not str for name in allowed_names):
        raise TypeError("environment allowlist names must be strings")
    child: dict[str, str] = {}
    for name in sorted(allowed_names):
        if name in parent:
            value = parent[name]
            if type(value) is not str:
                raise TypeError("environment values must be strings")
            child[name] = value
    return child


@dataclass(frozen=True)
class IPCEnvelope:
    sequence: int
    kind: IPCMessageKind
    route_token: str | None = None
    payload_code: int | None = None
    credential: str | None = None
    event: dict[str, object] | None = None
    capability_token: str | None = None
    tool_code: int | None = None
    argument_codes: tuple[int, ...] | None = None
    outcome: BrokerOutcome | None = None
    value_code: int | None = None

    @staticmethod
    def _bounded(message: "IPCEnvelope") -> "IPCEnvelope":
        try:
            encoded = json.dumps(
                message.to_wire(),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise IPCSchemaError("IPC message is not canonically serializable") from exc
        if len(encoded) > IPC_MAX_FRAME_BYTES:
            raise IPCSchemaError("IPC message exceeds the complete frame ceiling")
        return message

    @classmethod
    def model_request(
        cls,
        *,
        sequence: int,
        route_token: str,
        payload_code: int,
        credential: str,
    ) -> "IPCEnvelope":
        return cls._bounded(cls(
            sequence=_strict_int(sequence, "sequence", minimum=1),
            kind=IPCMessageKind.MODEL_REQUEST,
            route_token=_strict_text(route_token, "route_token"),
            payload_code=_strict_int(payload_code, "payload_code"),
            credential=_strict_text(credential, "credential"),
        ))

    @classmethod
    def public_event(
        cls, *, sequence: int, event: Mapping[str, object]
    ) -> "IPCEnvelope":
        from .observer import TranscriptEvent

        canonical = TranscriptEvent.from_wire(dict(event)).to_wire()
        return cls._bounded(cls(
            sequence=_strict_int(sequence, "sequence", minimum=1),
            kind=IPCMessageKind.PUBLIC_EVENT,
            event=canonical,
        ))

    @classmethod
    def effect_command(
        cls,
        *,
        sequence: int,
        capability_token: str,
        tool_code: int,
        argument_codes: tuple[int, ...],
    ) -> "IPCEnvelope":
        if type(argument_codes) is not tuple:
            raise IPCSchemaError("argument_codes must be a finite tuple")
        args = tuple(_strict_int(value, "argument_code") for value in argument_codes)
        return cls._bounded(cls(
            sequence=_strict_int(sequence, "sequence", minimum=1),
            kind=IPCMessageKind.EFFECT_COMMAND,
            capability_token=_strict_text(capability_token, "capability_token"),
            tool_code=_strict_int(tool_code, "tool_code"),
            argument_codes=args,
        ))

    @classmethod
    def effect_result(
        cls,
        *,
        sequence: int,
        outcome: BrokerOutcome,
        value_code: int | None,
    ) -> "IPCEnvelope":
        if not isinstance(outcome, BrokerOutcome):
            raise IPCSchemaError("outcome must be a finite BrokerOutcome")
        if value_code is not None:
            value_code = _strict_int(value_code, "value_code")
        if outcome is BrokerOutcome.EXECUTED and value_code is None:
            raise IPCSchemaError("executed effect results require a value code")
        if outcome is not BrokerOutcome.EXECUTED and value_code is not None:
            raise IPCSchemaError("denied effect results cannot carry a value code")
        return cls._bounded(cls(
            sequence=_strict_int(sequence, "sequence", minimum=1),
            kind=IPCMessageKind.EFFECT_RESULT,
            outcome=outcome,
            value_code=value_code,
        ))

    def to_wire(self) -> dict[str, object]:
        base: dict[str, object] = {
            "schema_version": IPC_SCHEMA_VERSION,
            "sequence": self.sequence,
            "kind": self.kind.value,
        }
        if self.kind is IPCMessageKind.MODEL_REQUEST:
            base.update(
                route_token=self.route_token,
                payload_code=self.payload_code,
                credential=self.credential,
            )
        elif self.kind is IPCMessageKind.PUBLIC_EVENT:
            base["event"] = self.event
        elif self.kind is IPCMessageKind.EFFECT_COMMAND:
            base.update(
                capability_token=self.capability_token,
                tool_code=self.tool_code,
                argument_codes=list(self.argument_codes or ()),
            )
        elif self.kind is IPCMessageKind.EFFECT_RESULT:
            base.update(
                outcome=self.outcome.value if self.outcome else None,
                value_code=self.value_code,
            )
        else:  # pragma: no cover - Enum construction prevents this
            raise IPCSchemaError("unknown message kind")
        return base

    @classmethod
    def from_wire(cls, wire: object) -> "IPCEnvelope":
        if type(wire) is not dict:
            raise IPCSchemaError("IPC envelope must be an object")
        if wire.get("schema_version") != IPC_SCHEMA_VERSION:
            raise IPCSchemaError("unsupported IPC schema version")
        try:
            kind = IPCMessageKind(wire.get("kind"))
        except (TypeError, ValueError) as exc:
            raise IPCSchemaError("unknown IPC message kind") from exc
        sequence = _strict_int(wire.get("sequence"), "sequence", minimum=1)
        common = frozenset({"schema_version", "sequence", "kind"})
        if kind is IPCMessageKind.MODEL_REQUEST:
            value = _exact_keys(
                wire, common | {"route_token", "payload_code", "credential"}
            )
            return cls.model_request(
                sequence=sequence,
                route_token=value["route_token"],
                payload_code=value["payload_code"],
                credential=value["credential"],
            )
        if kind is IPCMessageKind.PUBLIC_EVENT:
            value = _exact_keys(wire, common | {"event"})
            return cls.public_event(sequence=sequence, event=value["event"])
        if kind is IPCMessageKind.EFFECT_COMMAND:
            value = _exact_keys(
                wire,
                common | {"capability_token", "tool_code", "argument_codes"},
            )
            if type(value["argument_codes"]) is not list:
                raise IPCSchemaError("argument_codes wire value must be a list")
            return cls.effect_command(
                sequence=sequence,
                capability_token=value["capability_token"],
                tool_code=value["tool_code"],
                argument_codes=tuple(value["argument_codes"]),
            )
        value = _exact_keys(wire, common | {"outcome", "value_code"})
        try:
            outcome = BrokerOutcome(value["outcome"])
        except (TypeError, ValueError) as exc:
            raise IPCSchemaError("unknown broker outcome") from exc
        return cls.effect_result(
            sequence=sequence, outcome=outcome, value_code=value["value_code"]
        )

    def for_model(self) -> "IPCEnvelope":
        if self.kind is not IPCMessageKind.PUBLIC_EVENT:
            raise IPCSchemaError("model channel accepts only public_event messages")
        return self


class EffectBroker:
    """Execute one schema-validated effect without exposing broker secrets."""

    def __init__(
        self,
        *,
        allowed_arguments: Mapping[int, frozenset[tuple[int, ...]]],
        public_values: Mapping[int, frozenset[int]],
        tool_credentials: Mapping[int, bytes],
        handlers: Mapping[int, Callable[[bytes, tuple[int, ...]], object]],
        capability_validator: Callable[[str, int, tuple[int, ...]], bool],
    ) -> None:
        registries = [
            set(allowed_arguments),
            set(public_values),
            set(tool_credentials),
            set(handlers),
        ]
        if not registries or any(keys != registries[0] for keys in registries[1:]):
            raise ValueError("effect broker registries must cover identical tools")
        if any(type(code) is not int for code in registries[0]):
            raise TypeError("tool codes must be integers")
        for code, families in allowed_arguments.items():
            if type(families) is not frozenset:
                raise TypeError("allowed argument families must be frozen")
            for family in families:
                if type(family) is not tuple:
                    raise TypeError("argument families must be tuples")
                for value in family:
                    _strict_int(value, "argument_code")
        for code, values in public_values.items():
            if type(values) is not frozenset or not values:
                raise TypeError("public value alphabets must be nonempty frozensets")
            for value in values:
                _strict_int(value, "public value")
        if any(type(value) is not bytes or not value for value in tool_credentials.values()):
            raise TypeError("tool credentials must be nonempty bytes")
        if any(not callable(handler) for handler in handlers.values()):
            raise TypeError("effect handlers must be callable")
        if not callable(capability_validator):
            raise TypeError("capability_validator must be callable")
        self._allowed_arguments = {
            code: frozenset(tuple(family) for family in families)
            for code, families in allowed_arguments.items()
        }
        self._public_values = {
            code: frozenset(values) for code, values in public_values.items()
        }
        self._tool_credentials = dict(tool_credentials)
        self._handlers = dict(handlers)
        self._capability_validator = capability_validator
        self._used_capabilities: set[str] = set()
        self._executing = False
        self._lock = threading.RLock()

    def _reply(
        self, command: IPCEnvelope, outcome: BrokerOutcome, value: int | None = None
    ) -> IPCEnvelope:
        return IPCEnvelope.effect_result(
            sequence=command.sequence, outcome=outcome, value_code=value
        )

    def execute(self, command: IPCEnvelope) -> IPCEnvelope:
        if not isinstance(command, IPCEnvelope) or command.kind is not IPCMessageKind.EFFECT_COMMAND:
            raise IPCSchemaError("effect broker accepts only effect_command")
        # Reparse the public dataclass at the trust boundary. Direct
        # construction must not bypass factory validation or smuggle fields.
        canonical = IPCEnvelope.from_wire(command.to_wire())
        if canonical != command:
            raise IPCSchemaError("non-canonical effect command")
        if self._executing:
            return self._reply(command, BrokerOutcome.DENIED)
        with self._lock:
            if self._executing:
                return self._reply(command, BrokerOutcome.DENIED)
            tool = command.tool_code
            args = command.argument_codes
            token = command.capability_token
            assert tool is not None and args is not None and token is not None
            if tool not in self._handlers or args not in self._allowed_arguments[tool]:
                return self._reply(command, BrokerOutcome.DENIED)
            if token in self._used_capabilities:
                return self._reply(command, BrokerOutcome.DENIED)
            try:
                permitted = self._capability_validator(token, tool, args)
            except Exception:
                permitted = False
            if permitted is not True:
                return self._reply(command, BrokerOutcome.DENIED)
            self._used_capabilities.add(token)
            self._executing = True
            try:
                try:
                    value = self._handlers[tool](self._tool_credentials[tool], args)
                except BaseException:
                    return self._reply(command, BrokerOutcome.INTERNAL_DENIED)
                if type(value) is not int or value not in self._public_values[tool]:
                    return self._reply(command, BrokerOutcome.OUTPUT_DENIED)
                return self._reply(command, BrokerOutcome.EXECUTED, value)
            finally:
                self._executing = False


class DurableClaimJournal:
    """Minimal exactly-once durable edge for monitor-to-broker commands."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS claims ("
                "request_id TEXT PRIMARY KEY, "
                "command_fingerprint TEXT NOT NULL"
                ")"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30.0)
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def claim_once(
        self,
        *,
        request_id: str,
        command_fingerprint: str,
        crash_point: CrashPoint = CrashPoint.NONE,
    ) -> bool:
        request_id = _strict_text(request_id, "request_id")
        command_fingerprint = _strict_text(
            command_fingerprint, "command_fingerprint"
        )
        if not isinstance(crash_point, CrashPoint):
            raise TypeError("crash_point must be CrashPoint")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT command_fingerprint FROM claims WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is not None:
                if row[0] != command_fingerprint:
                    connection.rollback()
                    raise IPCSchemaError(
                        "request ID was previously bound to a different fingerprint"
                    )
                connection.rollback()
                return False
            connection.execute(
                "INSERT INTO claims(request_id, command_fingerprint) VALUES (?, ?)",
                (request_id, command_fingerprint),
            )
            if crash_point is CrashPoint.BEFORE_COMMIT:
                raise InjectedCrash("before durable commit")
            connection.commit()
            if crash_point is CrashPoint.AFTER_COMMIT:
                raise InjectedCrash("after durable commit")
            return True
        except InjectedCrash:
            # The caller may terminate immediately.  An explicit rollback here
            # would erase the distinction between the two injected edges.
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            if crash_point is CrashPoint.NONE:
                connection.close()

    def recover(self, request_id: str) -> RecoveryDisposition:
        request_id = _strict_text(request_id, "request_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM claims WHERE request_id = ?", (request_id,)
            ).fetchone()
        return (
            RecoveryDisposition.COMMITTED
            if row is not None
            else RecoveryDisposition.NOT_COMMITTED
        )

    def durable_claim_count(self, request_id: str) -> int:
        request_id = _strict_text(request_id, "request_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM claims WHERE request_id = ?", (request_id,)
            ).fetchone()
        assert row is not None
        return int(row[0])
