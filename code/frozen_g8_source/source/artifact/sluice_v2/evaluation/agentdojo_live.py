"""Authenticated live AgentDojo adapter for the non-oracle Sluice broker.

The module is an additive execution foundation.  It accepts a compiled
``PolicyManifest`` and exact official ``FunctionCall`` values; it never accepts
an AgentDojo task or scorer object.  Every call is converted to a fresh
``ToolRequest`` and traverses ``NonOracleToolBroker``.  Effect authority can be
redeemed through the singleton durable monitor using exact private template
bindings.  Public evidence contains hashes and finite outcomes, not raw tool
arguments, tool results, provider call identifiers, socket addresses, or
credentials.

No model request, benchmark scoring operation, or GPU operation is performed
by this module.
"""

from __future__ import annotations

import copy
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import platform
import re
import sys
import threading
from types import MappingProxyType, ModuleType
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .agentdojo import (
    AGENTDOJO_COMMIT,
    AGENTDOJO_TREE,
    AGENTDOJO_VERSION,
    BENCHMARK_VERSION,
    AuthorizationOutcome,
    BrokerAuditRecord,
    BrokerOutcome,
    BrokerResult,
    NonOracleToolBroker,
    PolicyDecision,
    PolicyManifest,
    PinnedSourceSummary,
    ScheduledRun,
    SecureEffectGrant,
    ToolRequest,
    V122_TOOL_REGISTRIES,
    canonical_args,
    generate_counterbalanced_schedule,
    validate_pinned_checkout,
    validate_v122_suites,
)


SOURCE_ATTESTATION_SCHEMA = "sluice-agentdojo-official-source-v1"
REGISTRY_ATTESTATION_SCHEMA = "sluice-agentdojo-live-registry-v2"
ENDPOINT_ATTESTATION_SCHEMA = "sluice-agentdojo-endpoint-attestation-v2"
PAIRED_SCHEDULE_SCHEMA = "sluice-agentdojo-live-paired-schedule-v2"
LIVE_PROVENANCE_SCHEMA = "sluice-agentdojo-live-provenance-v3"
LIVE_CALL_AUDIT_SCHEMA = "sluice-agentdojo-live-call-audit-v1"
RUNTIME_ENVIRONMENT_SCHEMA = "sluice-agentdojo-runtime-environment-v1"

V122_RUNTIME_TOOL_COUNT = 74
MAX_LIVE_CALLS = 4_096
MAX_RESULT_BYTES = 1_048_576
MAX_IDENTIFIER_BYTES = 512
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
_PINNED_SCHEMA_DIGESTS = MappingProxyType(
    {
        "banking": "f23fef04916f69a3e5ef875c66ceff729ecd685f4b790a5d8629401cf93be355",
        "slack": "d68133a16a3b80e2b53fb9db700f2ea57629e0683920a59cda24ec92de9275c4",
        "travel": "42291163f6f975cf674328c3697c19296843ac5e1f2130c3e2e2da93e88ead8a",
        "workspace": "b285f9ef2aa59b507e5c69768e98063ca0648cf8511ec7e7c0a9a2ccc48acda1",
    }
)
_VERIFIED_REGISTRY_TOKEN = object()
_VERIFIED_SOURCE_TOKEN = object()
_VERIFIED_ENDPOINT_TOKEN = object()
_VERIFIED_PROVENANCE_TOKEN = object()
_VERIFIED_SCHEDULE_TOKEN = object()
_VERIFIED_RUNTIME_ENVIRONMENT_TOKEN = object()
_PREVALIDATED_SOURCE_TOKEN = object()
_PREVALIDATED_REGISTRY_TOKEN = object()

PRINCIPAL_RUNTIME_ENVIRONMENT_ID = "agentdojo-upstream-lock-v1"
CPU_AUDIT_RUNTIME_ENVIRONMENT_ID = "sluice-artifact-cpu-audit-20260820"
_RUNTIME_ENVIRONMENTS = MappingProxyType(
    {
        PRINCIPAL_RUNTIME_ENVIRONMENT_ID: MappingProxyType(
            {
                "pydantic": "2.11.4",
                "pyyaml": "6.0.2",
                "principal_eligible": True,
            }
        ),
        CPU_AUDIT_RUNTIME_ENVIRONMENT_ID: MappingProxyType(
            {
                "pydantic": "2.13.4",
                "pyyaml": "6.0.3",
                "principal_eligible": False,
            }
        ),
    }
)

_MODULE_SOURCE_PATH = Path(__file__).resolve()
_MODULE_SOURCE_SHA256_AT_IMPORT = hashlib.sha256(
    _MODULE_SOURCE_PATH.read_bytes()
).hexdigest()


class LivePipelineError(ValueError):
    """A trusted live-pipeline binding or finite input is invalid."""


class CallAdapterOutcome(str, Enum):
    BROKERED = "brokered"
    PLACEHOLDER_ARGUMENTS_DENIED = "placeholder_arguments_denied"
    REPLAY_DENIED = "replay_denied"
    RESULT_FORMAT_DENIED = "result_format_denied"


def _text(name: str, value: object, *, maximum: int = MAX_IDENTIFIER_BYTES) -> str:
    if type(value) is not str or not value:
        raise LivePipelineError(f"{name} must be a nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise LivePipelineError(f"{name} is not valid UTF-8") from exc
    if len(encoded) > maximum:
        raise LivePipelineError(f"{name} exceeds the supported length")
    return value


def _sha256(name: str, value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise LivePipelineError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _revision(name: str, value: object) -> str:
    if type(value) is not str or _REVISION_RE.fullmatch(value) is None:
        raise LivePipelineError(f"{name} must be an exact lowercase 40-hex revision")
    return value


def _digest_bytes(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + b"\x00" + value).hexdigest()


def _digest_text(domain: bytes, value: str) -> str:
    return _digest_bytes(domain, value.encode("utf-8", errors="surrogatepass"))


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise LivePipelineError("value is outside the canonical JSON schema") from exc
    return encoded


def _json_digest(domain: bytes, value: object) -> str:
    return _digest_bytes(domain, _canonical_json(value))


def _args_digest(args: Mapping[str, Any]) -> str:
    try:
        return hashlib.sha256(canonical_args(args).encode("utf-8")).hexdigest()
    except BaseException:
        return hashlib.sha256(b"sluice-agentdojo-invalid-arguments-v1").hexdigest()


def _wire_value(value: Any) -> Any:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return value.model_dump(mode="json", round_trip=True)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


def _safe_value_digest(domain: bytes, value: Any) -> str:
    try:
        wire = _wire_value(value)
        if isinstance(wire, Mapping):
            encoded = canonical_args(wire).encode("utf-8")
        else:
            encoded = canonical_args({"value": wire}).encode("utf-8")
        return _digest_bytes(domain, encoded)
    except BaseException:
        return _digest_bytes(domain, b"unavailable")


def _adapter_source_sha256() -> str:
    try:
        path = Path(__file__).resolve()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, TypeError, ValueError) as exc:
        raise LivePipelineError("live adapter source attestation is unavailable") from exc
    if path != _MODULE_SOURCE_PATH or digest != _MODULE_SOURCE_SHA256_AT_IMPORT:
        raise LivePipelineError("live adapter source changed after import")
    return digest


def _source_filesystem_guard(
    root: Path,
    relative_paths: tuple[str, ...] | None = None,
) -> tuple[tuple[object, ...], ...]:
    """Seal the already-hashed checkout closure against later replacement."""

    checkout = Path(root).resolve()
    source_root = checkout / "src" / "agentdojo"
    if relative_paths is None:
        paths = [source_root, *source_root.rglob("*")]
        paths.extend(
            checkout / name for name in ("LICENSE", "pyproject.toml", "uv.lock")
        )
    else:
        paths = [checkout / relative for relative in relative_paths]
    rows: list[tuple[object, ...]] = []
    try:
        for path in sorted(paths, key=lambda item: item.relative_to(checkout).as_posix()):
            if path.is_symlink():
                raise LivePipelineError("official source filesystem seal contains a symlink")
            stat = path.stat(follow_symlinks=False)
            rows.append(
                (
                    path.relative_to(checkout).as_posix(),
                    stat.st_dev,
                    stat.st_ino,
                    stat.st_mode,
                    stat.st_size,
                    stat.st_mtime_ns,
                    stat.st_ctime_ns,
                )
            )
    except (OSError, TypeError, ValueError) as exc:
        raise LivePipelineError("official source filesystem seal is unavailable") from exc
    return tuple(rows)


def _source_summary_digest(summary: Mapping[str, object]) -> str:
    return _json_digest(b"sluice-agentdojo-source-summary-private-v1", summary)


@dataclass(frozen=True, slots=True, repr=False)
class OfficialSourceAttestation:
    """Authenticated official checkout identity with its local path private."""

    root: Path = field(repr=False, compare=False)
    version: str
    commit: str
    git_tree: str
    python_file_count: int
    python_tree_sha256: str
    loaded_asset_file_count: int
    loaded_asset_tree_sha256: str
    key_file_sha256: Mapping[str, str] = field(repr=False)
    _filesystem_guard: tuple[tuple[object, ...], ...] = field(
        repr=False, compare=False
    )
    _summary_sha256: str = field(repr=False, compare=False)
    _verification_token: object = field(repr=False, compare=False)
    schema_version: str = SOURCE_ATTESTATION_SCHEMA

    @classmethod
    def authenticate(cls, root: str | Path) -> "OfficialSourceAttestation":
        summary: PinnedSourceSummary = validate_pinned_checkout(root)
        guard = _source_filesystem_guard(summary.root)
        confirmation: PinnedSourceSummary = validate_pinned_checkout(summary.root)
        if (
            confirmation.python_file_count != summary.python_file_count
            or confirmation.python_tree_sha256 != summary.python_tree_sha256
            or confirmation.loaded_asset_file_count != summary.loaded_asset_file_count
            or confirmation.loaded_asset_tree_sha256
            != summary.loaded_asset_tree_sha256
            or dict(confirmation.key_file_sha256) != dict(summary.key_file_sha256)
            or _source_filesystem_guard(
                summary.root, tuple(row[0] for row in guard)
            )
            != guard
        ):
            raise LivePipelineError("official source changed during authentication")
        public = {
            "schema_version": SOURCE_ATTESTATION_SCHEMA,
            "version": AGENTDOJO_VERSION,
            "commit": AGENTDOJO_COMMIT,
            "git_tree": AGENTDOJO_TREE,
            "python_file_count": summary.python_file_count,
            "python_tree_sha256": summary.python_tree_sha256,
            "loaded_asset_file_count": summary.loaded_asset_file_count,
            "loaded_asset_tree_sha256": summary.loaded_asset_tree_sha256,
            "key_file_sha256": dict(summary.key_file_sha256),
        }
        return cls(
            root=summary.root,
            version=AGENTDOJO_VERSION,
            commit=AGENTDOJO_COMMIT,
            git_tree=AGENTDOJO_TREE,
            python_file_count=summary.python_file_count,
            python_tree_sha256=summary.python_tree_sha256,
            loaded_asset_file_count=summary.loaded_asset_file_count,
            loaded_asset_tree_sha256=summary.loaded_asset_tree_sha256,
            key_file_sha256=summary.key_file_sha256,
            _filesystem_guard=guard,
            _summary_sha256=_source_summary_digest(public),
            _verification_token=_VERIFIED_SOURCE_TOKEN,
        )

    def __post_init__(self) -> None:
        if self.schema_version != SOURCE_ATTESTATION_SCHEMA:
            raise LivePipelineError("unsupported official-source attestation schema")
        if self._verification_token is not _VERIFIED_SOURCE_TOKEN:
            raise LivePipelineError("official source was not factory authenticated")
        root = Path(self.root).resolve()
        if not root.is_dir():
            raise LivePipelineError("authenticated checkout root is unavailable")
        object.__setattr__(self, "root", root)
        if (
            self.version != AGENTDOJO_VERSION
            or self.commit != AGENTDOJO_COMMIT
            or self.git_tree != AGENTDOJO_TREE
        ):
            raise LivePipelineError("official source identity mismatch")
        if type(self.python_file_count) is not int or self.python_file_count != 99:
            raise LivePipelineError("official Python source count mismatch")
        if (
            type(self.loaded_asset_file_count) is not int
            or self.loaded_asset_file_count != 112
        ):
            raise LivePipelineError("official loaded-asset count mismatch")
        _sha256("Python source digest", self.python_tree_sha256)
        _sha256("loaded-asset digest", self.loaded_asset_tree_sha256)
        if not isinstance(self.key_file_sha256, Mapping):
            raise TypeError("key-file digests must be a mapping")
        copied = dict(self.key_file_sha256)
        if set(copied) != {"LICENSE", "pyproject.toml", "uv.lock"}:
            raise LivePipelineError("official key-file digest set mismatch")
        for name, digest in copied.items():
            _sha256(f"{name} digest", digest)
        object.__setattr__(self, "key_file_sha256", MappingProxyType(copied))
        if type(self._filesystem_guard) is not tuple or not self._filesystem_guard:
            raise LivePipelineError("official source filesystem seal is invalid")
        _sha256("official source summary digest", self._summary_sha256)
        if self._summary_sha256 != _source_summary_digest(self.to_wire()):
            raise LivePipelineError("official source authenticated summary changed")
        # Direct dataclass construction must not be able to assert an
        # authenticated checkout.  Re-run the byte-level verifier and compare
        # every public field to its result.
        self.revalidate()

    def revalidate(self) -> None:
        """Reauthenticate every pinned source/data byte at its point of use."""

        if self._verification_token is not _VERIFIED_SOURCE_TOKEN:
            raise LivePipelineError("official source was not factory authenticated")
        if self._summary_sha256 != _source_summary_digest(self.to_wire()):
            raise LivePipelineError("official source authenticated summary changed")
        if _source_filesystem_guard(
            self.root, tuple(row[0] for row in self._filesystem_guard)
        ) != self._filesystem_guard:
            raise LivePipelineError("official source attestation does not match checkout bytes")

    def __repr__(self) -> str:
        return (
            "OfficialSourceAttestation("
            f"version={self.version!r}, commit={self.commit!r}, "
            f"loaded_asset_tree_sha256={self.loaded_asset_tree_sha256!r})"
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "commit": self.commit,
            "git_tree": self.git_tree,
            "python_file_count": self.python_file_count,
            "python_tree_sha256": self.python_tree_sha256,
            "loaded_asset_file_count": self.loaded_asset_file_count,
            "loaded_asset_tree_sha256": self.loaded_asset_tree_sha256,
            "key_file_sha256": dict(self.key_file_sha256),
        }


def _resolve_module_qualname(module: ModuleType, qualname: str) -> object:
    if not qualname or "<locals>" in qualname:
        raise LivePipelineError("authenticated object has no importable qualified name")
    current: object = module
    try:
        for component in qualname.split("."):
            current = inspect.getattr_static(current, component)
    except AttributeError as exc:
        raise LivePipelineError("authenticated object is absent from its module") from exc
    return current


def _authenticated_loaded_type(
    source: OfficialSourceAttestation,
    value: object,
    *,
    expected_module: str | None = None,
    expected_qualname: str | None = None,
    authenticate_source_bytes: bool = True,
) -> tuple[dict[str, str], tuple[int, ...]]:
    """Authenticate one exact loaded class against the pinned checkout."""

    if not isinstance(value, type):
        raise LivePipelineError("authenticated suite object does not use a class")
    module_name = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if type(module_name) is not str or not module_name.startswith("agentdojo."):
        raise LivePipelineError("authenticated class module is not AgentDojo")
    if type(qualname) is not str:
        raise LivePipelineError("authenticated class qualified name is unavailable")
    if expected_module is not None and module_name != expected_module:
        raise LivePipelineError("authenticated class module mismatch")
    if expected_qualname is not None and qualname != expected_qualname:
        raise LivePipelineError("authenticated class qualified name mismatch")
    module = sys.modules.get(module_name)
    if type(module) is not ModuleType:
        raise LivePipelineError("authenticated class module is not loaded exactly once")
    dynamic_guard: tuple[int, ...] = ()
    dynamic_files: tuple[Path, Path, ModuleType] | None = None
    dynamic_wire: dict[str, str] = {}
    if "<locals>" not in qualname:
        if _resolve_module_qualname(module, qualname) is not value:
            raise LivePipelineError("authenticated class is not its module's exact class")
    else:
        # AgentDojo v0.1.35 creates a small set of combined user-task classes
        # inside this exact authenticated factory.  They cannot be resolved as
        # module attributes, so bind the factory code, exact generated class,
        # and its one official direct base without reading any task method or
        # answer-bearing task attribute.
        if (
            module_name != "agentdojo.task_suite.task_combinators"
            or qualname
            != "TaskCombinator._create_combined_task.<locals>.NewCombinedTask"
            or len(value.__bases__) != 1
        ):
            raise LivePipelineError("authenticated dynamic class is not official")
        combinator = _resolve_module_qualname(module, "TaskCombinator")
        factory = inspect.getattr_static(combinator, "_create_combined_task")
        if not inspect.isfunction(factory):
            raise LivePipelineError("authenticated dynamic-class factory changed")
        base = value.__bases__[0]
        base_module = sys.modules.get(getattr(base, "__module__", ""))
        base_qualname = getattr(base, "__qualname__", "")
        if (
            type(base_module) is not ModuleType
            or "<locals>" in base_qualname
            or _resolve_module_qualname(base_module, base_qualname) is not base
        ):
            raise LivePipelineError("authenticated dynamic class base is not official")
        try:
            factory_file = Path(inspect.getsourcefile(factory) or "").resolve()
            base_file = Path(inspect.getsourcefile(base) or "").resolve()
        except (OSError, TypeError, ValueError) as exc:
            raise LivePipelineError("authenticated dynamic class origin is unavailable") from exc
        dynamic_guard = (
            id(combinator),
            id(factory),
            id(factory.__code__),
            id(base_module),
            id(base),
        )
        dynamic_files = (factory_file, base_file, base_module)
        dynamic_wire = {
            "factory": "TaskCombinator._create_combined_task",
            "factory_source_sha256": ""
            if not authenticate_source_bytes
            else hashlib.sha256(factory_file.read_bytes()).hexdigest(),
            "base": f"{base.__module__}.{base_qualname}",
            "base_source_sha256": ""
            if not authenticate_source_bytes
            else hashlib.sha256(base_file.read_bytes()).hexdigest(),
        }
    try:
        module_file = Path(module.__file__).resolve()
        spec_origin = Path(module.__spec__.origin).resolve()
        class_file = Path(inspect.getsourcefile(value) or "").resolve()
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise LivePipelineError("authenticated class source origin is unavailable") from exc
    source_root = (source.root / "src" / "agentdojo").resolve()
    if (
        module_file != spec_origin
        or class_file != module_file
        or not module_file.is_file()
        or module_file.is_symlink()
        or not module_file.is_relative_to(source_root)
    ):
        raise LivePipelineError("authenticated class source is outside the checkout")
    if dynamic_files is not None:
        factory_file, base_file, base_module = dynamic_files
        try:
            base_module_file = Path(base_module.__file__).resolve()
            base_spec_origin = Path(base_module.__spec__.origin).resolve()
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise LivePipelineError("authenticated dynamic class base origin is unavailable") from exc
        if (
            factory_file != module_file
            or base_file != base_module_file
            or base_file != base_spec_origin
            or not base_file.is_file()
            or not base_file.is_relative_to(source_root)
        ):
            raise LivePipelineError("authenticated dynamic class origin is outside checkout")
    relative = module_file.relative_to(source_root).as_posix()
    source_sha256 = (
        hashlib.sha256(module_file.read_bytes()).hexdigest()
        if authenticate_source_bytes
        else ""
    )
    static_names = (
        "__new__",
        "__init__",
        "__getattribute__",
        "__setattr__",
    )
    try:
        guard = (
            id(module),
            id(value),
            *(id(base) for base in value.__bases__),
            *(id(inspect.getattr_static(value, name)) for name in static_names),
            *dynamic_guard,
        )
    except AttributeError as exc:
        raise LivePipelineError("authenticated class runtime guard is incomplete") from exc
    return (
        {
            "module": module_name,
            "qualname": qualname,
            "source": relative,
            "source_sha256": source_sha256,
            **dynamic_wire,
        },
        guard,
    )


@dataclass(frozen=True, slots=True, repr=False)
class OfficialFunctionCallBinding:
    """Exact loaded official type, bound to the authenticated source path."""

    source: OfficialSourceAttestation
    function_call_type: type = field(repr=False)
    source_file_sha256: str
    runtime_guard: tuple[int, ...] = field(repr=False)
    field_schema_sha256: str = field(repr=False)

    @classmethod
    def bind(
        cls,
        *,
        source: OfficialSourceAttestation,
        function_call_type: type,
    ) -> "OfficialFunctionCallBinding":
        if type(source) is not OfficialSourceAttestation:
            raise TypeError("source must be an OfficialSourceAttestation")
        source.revalidate()
        # Pydantic resolves the recursive FunctionCall argument annotation on
        # first validation and legitimately replaces its validator/field
        # metadata.  Perform that one trusted finalization before freezing the
        # live guard; no model-supplied value participates in this probe.
        _validate_function_call_type(source, function_call_type)
        try:
            function_call_type(
                function="sluice_binding_probe",
                args={},
                id=None,
                placeholder_args=None,
            )
        except BaseException as exc:
            raise LivePipelineError("official FunctionCall initialization failed") from exc
        origin, source_digest, guard, field_digest = _validate_function_call_type(
            source, function_call_type
        )
        return cls(
            source=source,
            function_call_type=function_call_type,
            source_file_sha256=source_digest,
            runtime_guard=guard,
            field_schema_sha256=field_digest,
        )

    def __post_init__(self) -> None:
        if type(self.source) is not OfficialSourceAttestation:
            raise TypeError("source must be an OfficialSourceAttestation")
        if not isinstance(self.function_call_type, type):
            raise TypeError("function_call_type must be a type")
        _sha256("FunctionCall source digest", self.source_file_sha256)
        _sha256("FunctionCall field-schema digest", self.field_schema_sha256)
        _, source_digest, guard, field_digest = _validate_function_call_type(
            self.source, self.function_call_type
        )
        if (
            source_digest != self.source_file_sha256
            or guard != self.runtime_guard
            or field_digest != self.field_schema_sha256
        ):
            raise LivePipelineError("official FunctionCall live identity mismatch")

    def _revalidate(self, *, source_prevalidated: bool = False) -> None:
        _, source_digest, guard, field_digest = _validate_function_call_type(
            self.source,
            self.function_call_type,
            revalidate_source=not source_prevalidated,
        )
        if (
            source_digest != self.source_file_sha256
            or guard != self.runtime_guard
            or field_digest != self.field_schema_sha256
        ):
            raise LivePipelineError("official FunctionCall changed after binding")

    def snapshot(
        self, call: object, *, _source_prevalidated_token: object | None = None
    ) -> object:
        self._revalidate(
            source_prevalidated=(
                _source_prevalidated_token is _PREVALIDATED_SOURCE_TOKEN
            )
        )
        if type(call) is not self.function_call_type:
            raise LivePipelineError("live execution requires an exact official FunctionCall")
        try:
            instance = object.__getattribute__(call, "__dict__")
            if type(instance) is not dict or set(instance) != {
                "function",
                "args",
                "id",
                "placeholder_args",
            }:
                raise LivePipelineError("official FunctionCall instance fields are not exact")
            values = copy.deepcopy(instance)
            snapshot = self.function_call_type(**values)
        except BaseException as exc:
            raise LivePipelineError("official FunctionCall snapshot failed") from exc
        if type(snapshot) is not self.function_call_type:
            raise LivePipelineError("official FunctionCall snapshot changed type")
        return snapshot

    def sanitized(
        self,
        snapshot: object,
        *,
        _source_prevalidated_token: object | None = None,
    ) -> object:
        self._revalidate(
            source_prevalidated=(
                _source_prevalidated_token is _PREVALIDATED_SOURCE_TOKEN
            )
        )
        if type(snapshot) is not self.function_call_type:
            raise LivePipelineError("cannot sanitize a nonofficial FunctionCall")
        try:
            return self.function_call_type(
                function=snapshot.function,
                args=copy.deepcopy(snapshot.args),
                id=snapshot.id,
                placeholder_args=None,
            )
        except BaseException as exc:
            raise LivePipelineError("official FunctionCall sanitization failed") from exc


def _validate_function_call_type(
    source: OfficialSourceAttestation,
    function_call_type: object,
    *,
    revalidate_source: bool = True,
) -> tuple[Path, str, tuple[int, ...], str]:
    if revalidate_source:
        source.revalidate()
    from pydantic import BaseModel

    _wire, type_guard = _authenticated_loaded_type(
        source,
        function_call_type,
        expected_module="agentdojo.functions_runtime",
        expected_qualname="FunctionCall",
    )
    if function_call_type.__name__ != "FunctionCall" or function_call_type.__bases__ != (
        BaseModel,
    ):
        raise LivePipelineError("FunctionCall is not the exact official base class")
    try:
        origin = Path(inspect.getsourcefile(function_call_type) or "").resolve()
    except (OSError, TypeError, ValueError) as exc:
        raise LivePipelineError("official FunctionCall origin is unavailable") from exc
    expected = (source.root / "src" / "agentdojo" / "functions_runtime.py").resolve()
    if origin != expected or not origin.is_file() or origin.is_symlink():
        raise LivePipelineError("official FunctionCall origin is outside the checkout")
    fields = getattr(function_call_type, "model_fields", None)
    if not isinstance(fields, Mapping) or set(fields) != {
        "function",
        "args",
        "id",
        "placeholder_args",
    }:
        raise LivePipelineError("official FunctionCall field schema mismatch")
    field_wire = []
    for name in sorted(fields):
        item = fields[name]
        field_wire.append(
            {
                "name": name,
                "annotation": repr(getattr(item, "annotation", None)),
                "required": bool(item.is_required()),
                "default": repr(getattr(item, "default", None)),
            }
        )
    guard_names = (
        "__new__",
        "__init__",
        "__getattribute__",
        "__setattr__",
        "model_copy",
        "model_dump",
        "model_validate",
        "__pydantic_validator__",
        "__pydantic_serializer__",
    )
    try:
        guard = type_guard + tuple(
            id(inspect.getattr_static(function_call_type, name))
            for name in guard_names
        )
    except AttributeError as exc:
        raise LivePipelineError("official FunctionCall runtime guard is incomplete") from exc
    return (
        origin,
        hashlib.sha256(origin.read_bytes()).hexdigest(),
        guard,
        _json_digest(b"sluice-agentdojo-function-call-fields-v1", field_wire),
    )


def _registry_wire() -> dict[str, object]:
    return {
        suite: {
            "read_only": sorted(registry.read_only),
            "effectful": sorted(registry.effectful),
        }
        for suite, registry in sorted(V122_TOOL_REGISTRIES.items())
    }


def _authenticated_loaded_callable(
    source: OfficialSourceAttestation,
    value: object,
    *,
    authenticate_source_bytes: bool = True,
) -> tuple[dict[str, str], tuple[int, ...]]:
    if not inspect.isfunction(value):
        raise LivePipelineError("official tool implementation is not an exact function")
    module_name = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if type(module_name) is not str or type(qualname) is not str:
        raise LivePipelineError("official tool implementation identity is unavailable")
    module = sys.modules.get(module_name)
    if type(module) is not ModuleType or _resolve_module_qualname(module, qualname) is not value:
        raise LivePipelineError("official tool implementation is not its module function")
    try:
        module_file = Path(module.__file__).resolve()
        spec_origin = Path(module.__spec__.origin).resolve()
        function_file = Path(inspect.getsourcefile(value) or "").resolve()
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise LivePipelineError("official tool implementation source is unavailable") from exc
    source_root = (source.root / "src" / "agentdojo").resolve()
    if (
        module_file != spec_origin
        or function_file != module_file
        or not module_file.is_file()
        or module_file.is_symlink()
        or not module_file.is_relative_to(source_root)
    ):
        raise LivePipelineError("official tool implementation is outside the checkout")
    return (
        {
            "module": module_name,
            "qualname": qualname,
            "source": module_file.relative_to(source_root).as_posix(),
            "source_sha256": hashlib.sha256(module_file.read_bytes()).hexdigest()
            if authenticate_source_bytes
            else "",
        },
        (id(module), id(value), id(value.__code__)),
    )


def _loaded_class_identity_guard(value: type) -> tuple[object, ...]:
    module_name = getattr(value, "__module__", None)
    module = sys.modules.get(module_name)
    if type(module_name) is not str or type(module) is not ModuleType:
        raise LivePipelineError("authenticated class module identity changed")
    try:
        static = tuple(
            id(inspect.getattr_static(value, name))
            for name in ("__new__", "__init__", "__getattribute__", "__setattr__")
        )
    except AttributeError as exc:
        raise LivePipelineError("authenticated class live guard is incomplete") from exc
    return (
        module_name,
        id(module),
        id(value),
        tuple(id(base) for base in value.__bases__),
        static,
    )


def _suite_live_identity_guard(
    suites: Mapping[str, object],
) -> tuple[object, ...]:
    """Seal live suite objects without consulting tasks or answer APIs."""

    if not isinstance(suites, Mapping) or set(suites) != set(V122_TOOL_REGISTRIES):
        raise LivePipelineError("official suite object set mismatch")
    rows: list[object] = []
    for suite_name in sorted(suites):
        suite = suites[suite_name]
        tools = getattr(suite, "tools", None)
        user_tasks = getattr(suite, "user_tasks", None)
        injection_tasks = getattr(suite, "injection_tasks", None)
        if type(tools) is not list or type(user_tasks) is not dict or type(injection_tasks) is not dict:
            raise LivePipelineError("official suite containers changed")
        tool_rows: list[object] = []
        for tool in tools:
            try:
                tool_guard = _function_dispatch_guard(tool)
            except LivePipelineError as exc:
                raise LivePipelineError(
                    "official suite object identity changed"
                ) from exc
            tool_rows.append(
                (
                    _loaded_class_identity_guard(type(tool)),
                    tool_guard,
                )
            )
        task_rows: list[object] = []
        for category, tasks in (("user", user_tasks), ("injection", injection_tasks)):
            for task_id in sorted(tasks):
                task = tasks[task_id]
                task_rows.append(
                    (
                        category,
                        task_id,
                        id(task),
                        _loaded_class_identity_guard(type(task)),
                    )
                )
        rows.append(
            (
                suite_name,
                id(suite),
                _loaded_class_identity_guard(type(suite)),
                id(tools),
                _loaded_class_identity_guard(getattr(suite, "environment_type", None)),
                getattr(suite, "benchmark_version", None),
                None if getattr(suite, "data_path", None) is None else str(suite.data_path),
                tuple(tool_rows),
                tuple(task_rows),
            )
        )
    return tuple(rows)


def _suite_object_snapshot(
    source: OfficialSourceAttestation,
    suites: Mapping[str, object],
    *,
    authenticate_source_bytes: bool = True,
) -> tuple[str, tuple[int, ...]]:
    """Bind exact official suite/task/tool objects without reading answer APIs."""

    if authenticate_source_bytes:
        source.revalidate()
    if not isinstance(suites, Mapping) or set(suites) != set(V122_TOOL_REGISTRIES):
        raise LivePipelineError("official suite object set mismatch")
    wire: list[dict[str, object]] = []
    guard: list[int] = []
    for suite_name in sorted(suites):
        suite = suites[suite_name]
        suite_type_wire, suite_type_guard = _authenticated_loaded_type(
            source,
            type(suite),
            expected_module="agentdojo.task_suite.task_suite",
            expected_qualname="TaskSuite",
            authenticate_source_bytes=authenticate_source_bytes,
        )
        if getattr(suite, "name", None) != suite_name:
            raise LivePipelineError("official suite name mismatch")
        tools = getattr(suite, "tools", None)
        user_tasks = getattr(suite, "user_tasks", None)
        injection_tasks = getattr(suite, "injection_tasks", None)
        if type(tools) is not list or type(user_tasks) is not dict or type(injection_tasks) is not dict:
            raise LivePipelineError("official suite containers are not exact")
        environment_type = getattr(suite, "environment_type", None)
        environment_wire, environment_guard = _authenticated_loaded_type(
            source,
            environment_type,
            authenticate_source_bytes=authenticate_source_bytes,
        )
        tool_wire: list[dict[str, object]] = []
        task_wire: dict[str, list[dict[str, object]]] = {
            "user": [],
            "injection": [],
        }
        # TaskSuite exposes task registries through properties that return new
        # dictionaries on each access.  Bind the exact suite/tool/task objects
        # and the authenticated property implementation, not those ephemeral
        # container identities.
        guard.extend((id(suite), id(tools)))
        guard.extend(suite_type_guard)
        guard.extend(environment_guard)
        for tool in tools:
            type_wire, type_guard = _authenticated_loaded_type(
                source,
                type(tool),
                expected_module="agentdojo.functions_runtime",
                expected_qualname="Function",
                authenticate_source_bytes=authenticate_source_bytes,
            )
            run = getattr(tool, "run", None)
            run_wire, run_guard = _authenticated_loaded_callable(
                source,
                run,
                authenticate_source_bytes=authenticate_source_bytes,
            )
            name = _text("official tool name", getattr(tool, "name", None))
            tool_wire.append(
                {
                    "name": name,
                    "type": type_wire,
                    "run": run_wire,
                }
            )
            guard.append(id(tool))
            guard.extend(type_guard)
            guard.extend(run_guard)
        for category, tasks in (
            ("user", user_tasks),
            ("injection", injection_tasks),
        ):
            for task_id in sorted(tasks):
                _text(f"{category} task ID", task_id)
                task = tasks[task_id]
                type_wire, type_guard = _authenticated_loaded_type(
                    source,
                    type(task),
                    authenticate_source_bytes=authenticate_source_bytes,
                )
                task_wire[category].append({"task_id": task_id, "type": type_wire})
                guard.append(id(task))
                guard.extend(type_guard)
        benchmark_version = getattr(suite, "benchmark_version", None)
        if type(benchmark_version) is not tuple or any(
            type(item) is not int for item in benchmark_version
        ):
            raise LivePipelineError("official suite benchmark version is malformed")
        data_path = getattr(suite, "data_path", None)
        if data_path is not None:
            try:
                resolved_data = Path(data_path).resolve()
            except (OSError, TypeError, ValueError) as exc:
                raise LivePipelineError("official suite data path is invalid") from exc
            source_root = (source.root / "src" / "agentdojo").resolve()
            if resolved_data.is_symlink() or not resolved_data.is_relative_to(source_root):
                raise LivePipelineError("official suite data path is outside the checkout")
            data_path_wire: str | None = resolved_data.relative_to(source_root).as_posix()
        else:
            data_path_wire = None
        wire.append(
            {
                "suite_name": suite_name,
                "suite_type": suite_type_wire,
                "environment_type": environment_wire,
                "benchmark_version": list(benchmark_version),
                "data_path": data_path_wire,
                "tools": sorted(tool_wire, key=lambda item: item["name"]),
                "user_tasks": task_wire["user"],
                "injection_tasks": task_wire["injection"],
            }
        )
    digest = _json_digest(b"sluice-agentdojo-official-suite-objects-v2", wire)
    if authenticate_source_bytes:
        source.revalidate()
    return digest, tuple(guard)


@dataclass(frozen=True, slots=True)
class OfficialRegistryAttestation:
    source: OfficialSourceAttestation = field(repr=False, compare=False)
    suites: Mapping[str, object] = field(repr=False, compare=False)
    source_assets_sha256: str
    runtime_tool_count: int
    suite_tool_counts: Mapping[str, int]
    suite_tool_schema_sha256: Mapping[str, str]
    suite_object_sha256: str
    registry_sha256: str
    official_suite_objects_verified: bool
    _runtime_guard: tuple[int, ...] = field(repr=False, compare=False)
    _verification_token: object = field(repr=False, compare=False)
    schema_version: str = REGISTRY_ATTESTATION_SCHEMA

    @classmethod
    def verify(
        cls,
        *,
        source: OfficialSourceAttestation,
        suites: Mapping[str, object],
    ) -> "OfficialRegistryAttestation":
        if type(source) is not OfficialSourceAttestation:
            raise TypeError("source must be an OfficialSourceAttestation")
        if type(suites) is not dict:
            raise TypeError("suites must be the exact official suite dictionary")
        source.revalidate()
        summary = validate_v122_suites(suites, authenticate_schemas=True)
        suite_object_sha256, _snapshot_guard = _suite_object_snapshot(source, suites)
        runtime_guard = _suite_live_identity_guard(suites)
        source.revalidate()
        count = sum(summary.suite_tool_counts.values())
        if count != V122_RUNTIME_TOOL_COUNT:
            raise LivePipelineError("official runtime tool count is not 74")
        return cls(
            source=source,
            suites=dict(suites),
            source_assets_sha256=source.loaded_asset_tree_sha256,
            runtime_tool_count=count,
            suite_tool_counts=summary.suite_tool_counts,
            suite_tool_schema_sha256=summary.suite_tool_schema_sha256,
            suite_object_sha256=suite_object_sha256,
            registry_sha256=_json_digest(
                b"sluice-agentdojo-live-registry-v2", _registry_wire()
            ),
            official_suite_objects_verified=True,
            _runtime_guard=runtime_guard,
            _verification_token=_VERIFIED_REGISTRY_TOKEN,
        )

    def __post_init__(self) -> None:
        if self.schema_version != REGISTRY_ATTESTATION_SCHEMA:
            raise LivePipelineError("unsupported registry-attestation schema")
        if type(self.source) is not OfficialSourceAttestation:
            raise TypeError("registry source must be an OfficialSourceAttestation")
        if not isinstance(self.suites, Mapping):
            raise TypeError("registry suites must be a mapping")
        if type(self._runtime_guard) is not tuple:
            raise TypeError("registry runtime guard must be a tuple")
        _sha256("source asset digest", self.source_assets_sha256)
        _sha256("suite object digest", self.suite_object_sha256)
        _sha256("registry digest", self.registry_sha256)
        if type(self.runtime_tool_count) is not int or self.runtime_tool_count != 74:
            raise LivePipelineError("runtime registry must contain exactly 74 tools")
        if type(self.official_suite_objects_verified) is not bool:
            raise TypeError("suite verification flag must be a boolean")
        if (
            not self.official_suite_objects_verified
            or self._verification_token is not _VERIFIED_REGISTRY_TOKEN
        ):
            raise LivePipelineError("official suite objects were not verified")
        counts = dict(self.suite_tool_counts)
        if counts != {"banking": 11, "slack": 11, "travel": 28, "workspace": 24}:
            raise LivePipelineError("official per-suite tool counts mismatch")
        schema_digests = dict(self.suite_tool_schema_sha256)
        if schema_digests != dict(_PINNED_SCHEMA_DIGESTS):
            raise LivePipelineError("official tool-schema digest set mismatch")
        for suite, digest in schema_digests.items():
            _sha256(f"{suite} schema digest", digest)
        expected_registry = _json_digest(
            b"sluice-agentdojo-live-registry-v2", _registry_wire()
        )
        if self.registry_sha256 != expected_registry:
            raise LivePipelineError("frozen 74-tool classification digest mismatch")
        object.__setattr__(self, "suite_tool_counts", MappingProxyType(counts))
        object.__setattr__(
            self, "suite_tool_schema_sha256", MappingProxyType(schema_digests)
        )
        object.__setattr__(self, "suites", MappingProxyType(dict(self.suites)))
        self.revalidate()

    def revalidate(self) -> None:
        self.source.revalidate()
        if self.source.loaded_asset_tree_sha256 != self.source_assets_sha256:
            raise LivePipelineError("registry source/data binding changed")
        guard = _suite_live_identity_guard(self.suites)
        self.source.revalidate()
        if guard != self._runtime_guard:
            raise LivePipelineError("official suite object graph changed after verification")

    def revalidate_runtime_objects(
        self, *, _source_prevalidated_token: object | None = None
    ) -> None:
        if _source_prevalidated_token is not _PREVALIDATED_SOURCE_TOKEN:
            self.revalidate()
            return
        guard = _suite_live_identity_guard(self.suites)
        if guard != self._runtime_guard:
            raise LivePipelineError("official suite object graph changed after verification")

    def _contains_pair_snapshot(self, pair: "PairedEpisodeIdentity") -> bool:
        if type(pair) is not PairedEpisodeIdentity:
            return False
        suite = self.suites.get(pair.suite_name)
        if suite is None:
            return False
        return (
            pair.user_task_id in suite.user_tasks
            and pair.injection_task_id in suite.injection_tasks
        )

    def contains_pair(self, pair: "PairedEpisodeIdentity") -> bool:
        self.revalidate()
        return self._contains_pair_snapshot(pair)

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_assets_sha256": self.source_assets_sha256,
            "runtime_tool_count": self.runtime_tool_count,
            "suite_tool_counts": dict(self.suite_tool_counts),
            "suite_tool_schema_sha256": dict(self.suite_tool_schema_sha256),
            "suite_object_sha256": self.suite_object_sha256,
            "registry_sha256": self.registry_sha256,
            "official_suite_objects_verified": self.official_suite_objects_verified,
        }


def _validate_endpoint_url(value: object) -> str:
    endpoint = _text("endpoint URL", value, maximum=2_048)
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise LivePipelineError("endpoint URL is malformed") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65_535
        or parsed.path != "/v1"
        or parsed.query
        or parsed.fragment
    ):
        raise LivePipelineError(
            "endpoint must be an uncredentialed numeric-loopback HTTP /v1 URL"
        )
    return endpoint


@dataclass(frozen=True, slots=True, repr=False)
class EndpointObservation:
    endpoint_url: str = field(repr=False)
    model_id: str
    model_revision: str
    model_artifact_sha256: str
    backend: str
    backend_version: str

    def __post_init__(self) -> None:
        _validate_endpoint_url(self.endpoint_url)
        _text("model_id", self.model_id)
        _revision("model_revision", self.model_revision)
        _sha256("model artifact digest", self.model_artifact_sha256)
        _text("backend", self.backend)
        _text("backend_version", self.backend_version)


@dataclass(frozen=True, slots=True, repr=False)
class EndpointExpectation:
    endpoint_url: str = field(repr=False)
    model_id: str
    model_revision: str
    model_artifact_sha256: str
    backend: str
    backend_version: str

    def __post_init__(self) -> None:
        _validate_endpoint_url(self.endpoint_url)
        _text("model_id", self.model_id)
        _revision("model_revision", self.model_revision)
        _sha256("model artifact digest", self.model_artifact_sha256)
        _text("backend", self.backend)
        _text("backend_version", self.backend_version)

    def verify(
        self, probe: Callable[[str], EndpointObservation]
    ) -> "EndpointAttestation":
        if not callable(probe):
            raise TypeError("endpoint probe must be callable")
        try:
            observed = probe(self.endpoint_url)
        except BaseException:
            raise LivePipelineError("endpoint probe failed") from None
        if type(observed) is not EndpointObservation:
            raise LivePipelineError("endpoint observation has the wrong type")
        expected = (
            self.endpoint_url,
            self.model_id,
            self.model_revision,
            self.model_artifact_sha256,
            self.backend,
            self.backend_version,
        )
        actual = (
            observed.endpoint_url,
            observed.model_id,
            observed.model_revision,
            observed.model_artifact_sha256,
            observed.backend,
            observed.backend_version,
        )
        if actual != expected:
            raise LivePipelineError("endpoint observation or model revision mismatch")
        return EndpointAttestation._create_verified(observed)


@dataclass(frozen=True, slots=True)
class EndpointAttestation:
    endpoint_sha256: str
    model_id: str
    model_revision: str
    model_artifact_sha256: str
    backend: str
    backend_version: str
    sha256: str
    _verification_token: object = field(repr=False, compare=False)
    schema_version: str = ENDPOINT_ATTESTATION_SCHEMA

    @classmethod
    def create(cls, observation: EndpointObservation) -> "EndpointAttestation":
        raise LivePipelineError(
            "endpoint attestations require an exact expectation/probe verification"
        )

    @classmethod
    def _create_verified(cls, observation: EndpointObservation) -> "EndpointAttestation":
        if type(observation) is not EndpointObservation:
            raise TypeError("observation must be an EndpointObservation")
        base = {
            "schema_version": ENDPOINT_ATTESTATION_SCHEMA,
            "endpoint_sha256": _digest_text(
                b"sluice-agentdojo-model-endpoint-v1", observation.endpoint_url
            ),
            "model_id": observation.model_id,
            "model_revision": observation.model_revision,
            "model_artifact_sha256": observation.model_artifact_sha256,
            "backend": observation.backend,
            "backend_version": observation.backend_version,
        }
        return cls(
            **base,
            sha256=_json_digest(b"sluice-agentdojo-endpoint-v2", base),
            _verification_token=_VERIFIED_ENDPOINT_TOKEN,
        )

    def __post_init__(self) -> None:
        if self.schema_version != ENDPOINT_ATTESTATION_SCHEMA:
            raise LivePipelineError("unsupported endpoint-attestation schema")
        if self._verification_token is not _VERIFIED_ENDPOINT_TOKEN:
            raise LivePipelineError("endpoint attestation was not probe-verified")
        _sha256("endpoint digest", self.endpoint_sha256)
        _text("model_id", self.model_id)
        _revision("model_revision", self.model_revision)
        _sha256("model artifact digest", self.model_artifact_sha256)
        _text("backend", self.backend)
        _text("backend_version", self.backend_version)
        _sha256("endpoint attestation digest", self.sha256)
        base = self.to_wire()
        base.pop("sha256")
        expected = _json_digest(b"sluice-agentdojo-endpoint-v2", base)
        if self.sha256 != expected:
            raise LivePipelineError("endpoint attestation digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "endpoint_sha256": self.endpoint_sha256,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "model_artifact_sha256": self.model_artifact_sha256,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "sha256": self.sha256,
        }

    def revalidate(self) -> None:
        self.__post_init__()


def _pair_id(suite_name: str, user_task_id: str, injection_task_id: str) -> str:
    return _digest_text(
        b"sluice-agentdojo-pair-id-v1",
        f"{suite_name}\x00{user_task_id}\x00{injection_task_id}",
    )


@dataclass(frozen=True, slots=True)
class PairedEpisodeIdentity:
    episode_id: str
    suite_name: str
    user_task_id: str
    injection_task_id: str
    pair_id: str

    @classmethod
    def create(
        cls,
        *,
        episode_id: str,
        suite_name: str,
        user_task_id: str,
        injection_task_id: str,
    ) -> "PairedEpisodeIdentity":
        return cls(
            episode_id=episode_id,
            suite_name=suite_name,
            user_task_id=user_task_id,
            injection_task_id=injection_task_id,
            pair_id=_pair_id(suite_name, user_task_id, injection_task_id),
        )

    def __post_init__(self) -> None:
        for name in (
            "episode_id",
            "suite_name",
            "user_task_id",
            "injection_task_id",
        ):
            _text(name, getattr(self, name))
        _sha256("pair_id", self.pair_id)
        if self.pair_id != _pair_id(
            self.suite_name, self.user_task_id, self.injection_task_id
        ):
            raise LivePipelineError("episode pair identity digest mismatch")


@dataclass(frozen=True, slots=True)
class PairedScheduledRun:
    block: int
    order: int
    episode_id: str
    suite_name: str
    user_task_id: str
    injection_task_id: str
    pair_id: str
    condition: str


def _schedule_base(
    conditions: tuple[str, str],
    seed_sha256: str,
    registry_sha256: str,
    suite_object_sha256: str,
    entries: tuple[PairedScheduledRun, ...],
) -> dict[str, object]:
    return {
        "schema_version": PAIRED_SCHEDULE_SCHEMA,
        "conditions": list(conditions),
        "seed_sha256": seed_sha256,
        "registry_sha256": registry_sha256,
        "suite_object_sha256": suite_object_sha256,
        "entries": [
            {
                "block": entry.block,
                "order": entry.order,
                "episode_id": entry.episode_id,
                "suite_name": entry.suite_name,
                "user_task_id": entry.user_task_id,
                "injection_task_id": entry.injection_task_id,
                "pair_id": entry.pair_id,
                "condition": entry.condition,
            }
            for entry in entries
        ],
    }


@dataclass(frozen=True, slots=True)
class PairedScheduleManifest:
    conditions: tuple[str, str]
    seed_sha256: str
    registry_sha256: str
    suite_object_sha256: str
    entries: tuple[PairedScheduledRun, ...]
    sha256: str
    registry: OfficialRegistryAttestation = field(repr=False, compare=False)
    _verification_token: object = field(repr=False, compare=False)
    schema_version: str = PAIRED_SCHEDULE_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        episode_pairs: Iterable[PairedEpisodeIdentity],
        conditions: tuple[str, str],
        seed: str,
        registry: OfficialRegistryAttestation,
    ) -> "PairedScheduleManifest":
        if type(registry) is not OfficialRegistryAttestation:
            raise TypeError("registry must be an OfficialRegistryAttestation")
        registry.revalidate()
        pairs = tuple(episode_pairs)
        if not pairs or any(type(pair) is not PairedEpisodeIdentity for pair in pairs):
            raise LivePipelineError("paired schedule requires exact episode identities")
        if len({pair.episode_id for pair in pairs}) != len(pairs):
            raise LivePipelineError("paired schedule episode IDs must be unique")
        if len({pair.pair_id for pair in pairs}) != len(pairs):
            raise LivePipelineError("paired schedule pair IDs must be unique")
        for pair in pairs:
            if not registry._contains_pair_snapshot(pair):
                raise LivePipelineError("paired schedule contains a nonofficial task pair")
        _text("schedule seed", seed)
        generated = generate_counterbalanced_schedule(
            (pair.episode_id for pair in pairs), arms=conditions, seed=seed
        )
        by_episode = {pair.episode_id: pair for pair in pairs}
        entries = tuple(
            PairedScheduledRun(
                block=item.block,
                order=item.order,
                episode_id=item.episode_id,
                suite_name=by_episode[item.episode_id].suite_name,
                user_task_id=by_episode[item.episode_id].user_task_id,
                injection_task_id=by_episode[item.episode_id].injection_task_id,
                pair_id=by_episode[item.episode_id].pair_id,
                condition=item.arm,
            )
            for item in generated
        )
        seed_sha = _digest_text(b"sluice-agentdojo-schedule-seed-v2", seed)
        base = _schedule_base(
            conditions,
            seed_sha,
            registry.registry_sha256,
            registry.suite_object_sha256,
            entries,
        )
        return cls(
            conditions=conditions,
            seed_sha256=seed_sha,
            registry_sha256=registry.registry_sha256,
            suite_object_sha256=registry.suite_object_sha256,
            entries=entries,
            sha256=_json_digest(b"sluice-agentdojo-paired-schedule-v2", base),
            registry=registry,
            _verification_token=_VERIFIED_SCHEDULE_TOKEN,
        )

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self, *, registry_prevalidated: bool = False) -> None:
        if self.schema_version != PAIRED_SCHEDULE_SCHEMA:
            raise LivePipelineError("unsupported paired-schedule schema")
        if self._verification_token is not _VERIFIED_SCHEDULE_TOKEN:
            raise LivePipelineError("paired schedule was not factory authenticated")
        if type(self.registry) is not OfficialRegistryAttestation:
            raise TypeError("paired schedule registry is invalid")
        if not registry_prevalidated:
            self.registry.revalidate()
        if (
            type(self.conditions) is not tuple
            or len(self.conditions) != 2
            or self.conditions[0] == self.conditions[1]
        ):
            raise LivePipelineError("paired schedule requires two distinct conditions")
        for condition in self.conditions:
            _text("schedule condition", condition)
        _sha256("schedule seed digest", self.seed_sha256)
        _sha256("schedule registry digest", self.registry_sha256)
        _sha256("schedule suite-object digest", self.suite_object_sha256)
        _sha256("schedule digest", self.sha256)
        if (
            self.registry_sha256 != self.registry.registry_sha256
            or self.suite_object_sha256 != self.registry.suite_object_sha256
        ):
            raise LivePipelineError("paired schedule registry binding mismatch")
        if type(self.entries) is not tuple or not self.entries:
            raise LivePipelineError("paired schedule entries must be a nonempty tuple")
        if any(type(entry) is not PairedScheduledRun for entry in self.entries):
            raise TypeError("paired schedule contains an invalid entry")
        if len(self.entries) % 2 or len(self.entries) > 2 * MAX_LIVE_CALLS:
            raise LivePipelineError("paired schedule cardinality is invalid")
        blocks: dict[int, list[PairedScheduledRun]] = {}
        for entry in self.entries:
            if type(entry.block) is not int or entry.block < 0:
                raise LivePipelineError("paired schedule block is invalid")
            if entry.order not in (1, 2):
                raise LivePipelineError("paired schedule order is invalid")
            identity = PairedEpisodeIdentity(
                episode_id=entry.episode_id,
                suite_name=entry.suite_name,
                user_task_id=entry.user_task_id,
                injection_task_id=entry.injection_task_id,
                pair_id=entry.pair_id,
            )
            if not self.registry._contains_pair_snapshot(identity):
                raise LivePipelineError("paired schedule task pair is not official")
            if entry.condition not in self.conditions:
                raise LivePipelineError("paired schedule condition is unknown")
            blocks.setdefault(entry.block, []).append(entry)
        if sorted(blocks) != list(range(len(blocks))):
            raise LivePipelineError("paired schedule blocks are not contiguous")
        episodes: list[str] = []
        pair_ids: list[str] = []
        for block in sorted(blocks):
            pair = blocks[block]
            if (
                len(pair) != 2
                or {item.order for item in pair} != {1, 2}
                or {item.condition for item in pair} != set(self.conditions)
                or len({item.episode_id for item in pair}) != 1
                or len({item.suite_name for item in pair}) != 1
                or len({item.user_task_id for item in pair}) != 1
                or len({item.injection_task_id for item in pair}) != 1
                or len({item.pair_id for item in pair}) != 1
            ):
                raise LivePipelineError("paired schedule block is malformed")
            episodes.append(pair[0].episode_id)
            pair_ids.append(pair[0].pair_id)
        if len(episodes) != len(set(episodes)) or len(pair_ids) != len(set(pair_ids)):
            raise LivePipelineError("paired schedule repeats an episode or pair block")
        first = [entry.condition for entry in self.entries if entry.order == 1]
        if abs(first.count(self.conditions[0]) - first.count(self.conditions[1])) > 1:
            raise LivePipelineError("paired schedule is not counterbalanced")
        base = _schedule_base(
            self.conditions,
            self.seed_sha256,
            self.registry_sha256,
            self.suite_object_sha256,
            self.entries,
        )
        expected = _json_digest(b"sluice-agentdojo-paired-schedule-v2", base)
        if self.sha256 != expected:
            raise LivePipelineError("paired schedule digest mismatch")

    def to_wire(self) -> dict[str, object]:
        wire = _schedule_base(
            self.conditions,
            self.seed_sha256,
            self.registry_sha256,
            self.suite_object_sha256,
            self.entries,
        )
        wire["sha256"] = self.sha256
        return wire

    def revalidate(
        self, *, _registry_prevalidated_token: object | None = None
    ) -> None:
        self._validate(
            registry_prevalidated=(
                _registry_prevalidated_token is _PREVALIDATED_REGISTRY_TOKEN
            )
        )


def policy_manifest_sha256(manifest: PolicyManifest) -> str:
    if type(manifest) is not PolicyManifest:
        raise TypeError("manifest must be a PolicyManifest")
    wire = {
        "schema_version": manifest.schema_version,
        "policy_id": manifest.policy_id,
        "workflow_id": manifest.workflow_id,
        "episode_id": manifest.episode_id,
        "suite_name": manifest.suite_name,
        "task_id": manifest.task_id,
        "split": manifest.split.value,
        "decision": manifest.decision.value,
        "abstention": manifest.abstention.value,
        "templates": [
            {
                "schema_version": template.schema_version,
                "template_id": template.template_id,
                "tool": template.tool,
                "exact_args": template.exact_args,
                "args_sha256": template.args_sha256,
            }
            for template in manifest.templates
        ],
        "source_commit": manifest.source_commit,
        "benchmark_version": manifest.benchmark_version,
        "prompt_sha256": manifest.prompt_sha256,
        "state_sha256": manifest.state_sha256,
        "tool_schema_sha256": manifest.tool_schema_sha256,
        "organization_policy_sha256": manifest.organization_policy_sha256,
        "split_manifest_sha256": manifest.split_manifest_sha256,
        "compiler_id": manifest.compiler_id,
        "compiler_sha256": manifest.compiler_sha256,
        "compiler_runtime_sha256": manifest.compiler_runtime_sha256,
        "source_assets_sha256": manifest.source_assets_sha256,
        "input_sha256": manifest.input_sha256,
    }
    return _json_digest(b"sluice-agentdojo-policy-manifest-live-v1", wire)


def live_run_provenance_sha256(wire: Mapping[str, object]) -> str:
    if not isinstance(wire, Mapping):
        raise TypeError("provenance wire value must be a mapping")
    value = dict(wire)
    value.pop("provenance_sha256", None)
    return _json_digest(b"sluice-agentdojo-live-provenance-v3", value)


@dataclass(frozen=True, slots=True)
class RuntimeEnvironmentAttestation:
    environment_id: str
    python_version: str
    pydantic_version: str
    pyyaml_version: str
    principal_eligible: bool
    sha256: str
    _verification_token: object = field(repr=False, compare=False)
    schema_version: str = RUNTIME_ENVIRONMENT_SCHEMA

    @classmethod
    def authenticate(
        cls,
        environment_id: str = PRINCIPAL_RUNTIME_ENVIRONMENT_ID,
    ) -> "RuntimeEnvironmentAttestation":
        _text("runtime environment ID", environment_id)
        expected = _RUNTIME_ENVIRONMENTS.get(environment_id)
        if expected is None:
            raise LivePipelineError("runtime environment is not authenticated")
        try:
            python_version = platform.python_version()
            pydantic_version = importlib.metadata.version("pydantic")
            pyyaml_version = importlib.metadata.version("PyYAML")
        except importlib.metadata.PackageNotFoundError as exc:
            raise LivePipelineError("live adapter runtime dependency is unavailable") from exc
        if (
            pydantic_version != expected["pydantic"]
            or pyyaml_version != expected["pyyaml"]
        ):
            raise LivePipelineError("live adapter runtime dependency pin mismatch")
        base = {
            "schema_version": RUNTIME_ENVIRONMENT_SCHEMA,
            "environment_id": environment_id,
            "python_version": python_version,
            "pydantic_version": pydantic_version,
            "pyyaml_version": pyyaml_version,
            "principal_eligible": expected["principal_eligible"],
        }
        return cls(
            **base,
            sha256=_json_digest(
                b"sluice-agentdojo-runtime-environment-v1", base
            ),
            _verification_token=_VERIFIED_RUNTIME_ENVIRONMENT_TOKEN,
        )

    def __post_init__(self) -> None:
        if self.schema_version != RUNTIME_ENVIRONMENT_SCHEMA:
            raise LivePipelineError("unsupported runtime-environment schema")
        if self._verification_token is not _VERIFIED_RUNTIME_ENVIRONMENT_TOKEN:
            raise LivePipelineError("runtime environment was not authenticated")
        expected = _RUNTIME_ENVIRONMENTS.get(self.environment_id)
        if expected is None:
            raise LivePipelineError("runtime environment ID is not allowlisted")
        for name in ("python_version", "pydantic_version", "pyyaml_version"):
            _text(name, getattr(self, name))
        if type(self.principal_eligible) is not bool:
            raise TypeError("principal eligibility must be a boolean")
        if (
            self.pydantic_version != expected["pydantic"]
            or self.pyyaml_version != expected["pyyaml"]
            or self.principal_eligible is not expected["principal_eligible"]
        ):
            raise LivePipelineError("runtime environment differs from its authenticated manifest")
        _sha256("runtime environment digest", self.sha256)
        base = self.to_wire()
        base.pop("sha256")
        if self.sha256 != _json_digest(
            b"sluice-agentdojo-runtime-environment-v1", base
        ):
            raise LivePipelineError("runtime environment digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "environment_id": self.environment_id,
            "python_version": self.python_version,
            "pydantic_version": self.pydantic_version,
            "pyyaml_version": self.pyyaml_version,
            "principal_eligible": self.principal_eligible,
            "sha256": self.sha256,
        }

    def revalidate(self) -> None:
        self.__post_init__()


def _adapter_runtime_dependencies() -> tuple[str, str, str, str]:
    """Authenticate the principal dependency lock or fail closed."""

    environment = RuntimeEnvironmentAttestation.authenticate()
    return (
        environment.python_version,
        environment.pydantic_version,
        environment.pyyaml_version,
        environment.sha256,
    )


@dataclass(frozen=True, slots=True)
class LiveRunProvenance:
    benchmark_version: str
    source_commit: str
    source_assets_sha256: str
    registry_sha256: str
    suite_object_sha256: str
    runtime_tool_count: int
    policy_manifest_sha256: str
    split_manifest_sha256: str
    schedule_sha256: str
    suite_name: str
    user_task_id: str
    injection_task_id: str
    pair_id: str
    condition: str
    schedule_block: int
    schedule_order: int
    endpoint_attestation_sha256: str
    adapter_source_sha256: str
    runtime_environment_id: str
    runtime_environment_sha256: str
    principal_eligible: bool
    python_version: str
    pydantic_version: str
    pyyaml_version: str
    runtime_dependencies_sha256: str
    durable_binding_sha256: str
    provenance_sha256: str
    source: OfficialSourceAttestation = field(repr=False, compare=False)
    registry: OfficialRegistryAttestation = field(repr=False, compare=False)
    endpoint: EndpointAttestation = field(repr=False, compare=False)
    schedule: PairedScheduleManifest = field(repr=False, compare=False)
    runtime_environment: RuntimeEnvironmentAttestation = field(
        repr=False, compare=False
    )
    _verification_token: object = field(repr=False, compare=False)
    schema_version: str = LIVE_PROVENANCE_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        source: OfficialSourceAttestation,
        registry: OfficialRegistryAttestation,
        endpoint: EndpointAttestation,
        schedule: PairedScheduleManifest,
        policy_manifest: PolicyManifest,
        durable_binding_sha256: str,
        condition: str,
        runtime_environment: RuntimeEnvironmentAttestation | None = None,
    ) -> "LiveRunProvenance":
        if type(source) is not OfficialSourceAttestation:
            raise TypeError("source must be an OfficialSourceAttestation")
        if type(registry) is not OfficialRegistryAttestation:
            raise TypeError("registry must be an OfficialRegistryAttestation")
        if type(endpoint) is not EndpointAttestation:
            raise TypeError("endpoint must be an EndpointAttestation")
        if type(schedule) is not PairedScheduleManifest:
            raise TypeError("schedule must be a PairedScheduleManifest")
        if type(policy_manifest) is not PolicyManifest:
            raise TypeError("policy_manifest must be a PolicyManifest")
        if runtime_environment is None:
            runtime_environment = RuntimeEnvironmentAttestation.authenticate()
        if type(runtime_environment) is not RuntimeEnvironmentAttestation:
            raise TypeError("runtime_environment must be authenticated exactly")
        source.revalidate()
        registry.revalidate()
        if registry.source is not source:
            raise LivePipelineError("registry is not bound to this exact source attestation")
        if schedule.registry is not registry:
            raise LivePipelineError("schedule is not bound to this exact registry attestation")
        if policy_manifest.decision is not PolicyDecision.COMPILED:
            raise LivePipelineError("live provenance requires a compiled policy")
        if source.loaded_asset_tree_sha256 != registry.source_assets_sha256:
            raise LivePipelineError("source and registry attestations differ")
        if policy_manifest.source_assets_sha256 != source.loaded_asset_tree_sha256:
            raise LivePipelineError("policy and official source attestations differ")
        _text("run condition", condition)
        episode_entries = [
            entry for entry in schedule.entries
            if entry.episode_id == policy_manifest.episode_id
        ]
        if len(episode_entries) != 2:
            raise LivePipelineError("policy episode is absent from the paired schedule")
        if len({entry.pair_id for entry in episode_entries}) != 1:
            raise LivePipelineError("policy episode has an ambiguous paired identity")
        selected = [
            entry for entry in episode_entries if entry.condition == condition
        ]
        if len(selected) != 1:
            raise LivePipelineError("run condition is absent from the paired schedule")
        selected_entry = selected[0]
        if runtime_environment.principal_eligible:
            if policy_manifest.suite_name not in V122_TOOL_REGISTRIES:
                raise LivePipelineError("principal provenance requires an official suite")
            if (
                policy_manifest.suite_name != selected_entry.suite_name
                or policy_manifest.task_id
                != f"{selected_entry.suite_name}:{selected_entry.user_task_id}"
            ):
                raise LivePipelineError("policy and paired official task identity differ")
        _sha256("durable binding digest", durable_binding_sha256)
        values = {
            "benchmark_version": BENCHMARK_VERSION,
            "source_commit": AGENTDOJO_COMMIT,
            "source_assets_sha256": source.loaded_asset_tree_sha256,
            "registry_sha256": registry.registry_sha256,
            "suite_object_sha256": registry.suite_object_sha256,
            "runtime_tool_count": registry.runtime_tool_count,
            "policy_manifest_sha256": policy_manifest_sha256(policy_manifest),
            "split_manifest_sha256": policy_manifest.split_manifest_sha256,
            "schedule_sha256": schedule.sha256,
            "suite_name": selected_entry.suite_name,
            "user_task_id": selected_entry.user_task_id,
            "injection_task_id": selected_entry.injection_task_id,
            "pair_id": selected_entry.pair_id,
            "condition": selected_entry.condition,
            "schedule_block": selected_entry.block,
            "schedule_order": selected_entry.order,
            "endpoint_attestation_sha256": endpoint.sha256,
            "adapter_source_sha256": _adapter_source_sha256(),
            "runtime_environment_id": runtime_environment.environment_id,
            "runtime_environment_sha256": runtime_environment.sha256,
            "principal_eligible": runtime_environment.principal_eligible,
            "python_version": runtime_environment.python_version,
            "pydantic_version": runtime_environment.pydantic_version,
            "pyyaml_version": runtime_environment.pyyaml_version,
            "runtime_dependencies_sha256": runtime_environment.sha256,
            "durable_binding_sha256": durable_binding_sha256,
            "schema_version": LIVE_PROVENANCE_SCHEMA,
        }
        digest = live_run_provenance_sha256(values)
        return cls(
            **values,
            provenance_sha256=digest,
            source=source,
            registry=registry,
            endpoint=endpoint,
            schedule=schedule,
            runtime_environment=runtime_environment,
            _verification_token=_VERIFIED_PROVENANCE_TOKEN,
        )

    def __post_init__(self) -> None:
        if self.schema_version != LIVE_PROVENANCE_SCHEMA:
            raise LivePipelineError("unsupported live-provenance schema")
        if self._verification_token is not _VERIFIED_PROVENANCE_TOKEN:
            raise LivePipelineError("live provenance was not factory authenticated")
        if (
            type(self.source) is not OfficialSourceAttestation
            or type(self.registry) is not OfficialRegistryAttestation
            or type(self.endpoint) is not EndpointAttestation
            or type(self.schedule) is not PairedScheduleManifest
            or type(self.runtime_environment) is not RuntimeEnvironmentAttestation
        ):
            raise LivePipelineError("live provenance has invalid private attestations")
        self.registry.revalidate()
        self.schedule.revalidate(
            _registry_prevalidated_token=_PREVALIDATED_REGISTRY_TOKEN
        )
        self.endpoint.revalidate()
        self.runtime_environment.revalidate()
        if (
            self.registry.source is not self.source
            or self.schedule.registry is not self.registry
            or self.source_assets_sha256 != self.source.loaded_asset_tree_sha256
            or self.registry_sha256 != self.registry.registry_sha256
            or self.suite_object_sha256 != self.registry.suite_object_sha256
            or self.schedule_sha256 != self.schedule.sha256
            or self.endpoint_attestation_sha256 != self.endpoint.sha256
            or self.runtime_environment_id != self.runtime_environment.environment_id
            or self.runtime_environment_sha256 != self.runtime_environment.sha256
        ):
            raise LivePipelineError("live provenance private binding mismatch")
        if self.benchmark_version != BENCHMARK_VERSION:
            raise LivePipelineError("live benchmark version mismatch")
        if self.source_commit != AGENTDOJO_COMMIT:
            raise LivePipelineError("live source commit mismatch")
        if type(self.runtime_tool_count) is not int or self.runtime_tool_count != 74:
            raise LivePipelineError("live provenance does not bind 74 tools")
        for name in (
            "suite_name",
            "user_task_id",
            "injection_task_id",
            "condition",
        ):
            _text(name, getattr(self, name))
        if type(self.schedule_block) is not int or self.schedule_block < 0:
            raise LivePipelineError("live provenance schedule block is invalid")
        if self.schedule_order not in (1, 2):
            raise LivePipelineError("live provenance schedule order is invalid")
        selected = [
            entry
            for entry in self.schedule.entries
            if (
                entry.block == self.schedule_block
                and entry.order == self.schedule_order
                and entry.suite_name == self.suite_name
                and entry.user_task_id == self.user_task_id
                and entry.injection_task_id == self.injection_task_id
                and entry.pair_id == self.pair_id
                and entry.condition == self.condition
            )
        ]
        if len(selected) != 1:
            raise LivePipelineError("live provenance scheduled-run binding mismatch")
        if type(self.principal_eligible) is not bool:
            raise TypeError("principal eligibility must be a boolean")
        environment = _RUNTIME_ENVIRONMENTS.get(self.runtime_environment_id)
        if environment is None:
            raise LivePipelineError("live provenance runtime environment is unknown")
        if (
            self.pydantic_version != environment["pydantic"]
            or self.pyyaml_version != environment["pyyaml"]
            or self.principal_eligible is not environment["principal_eligible"]
        ):
            raise LivePipelineError("live provenance runtime environment mismatch")
        for name in ("python_version", "pydantic_version", "pyyaml_version"):
            _text(name, getattr(self, name))
        runtime_base = {
            "schema_version": RUNTIME_ENVIRONMENT_SCHEMA,
            "environment_id": self.runtime_environment_id,
            "python_version": self.python_version,
            "pydantic_version": self.pydantic_version,
            "pyyaml_version": self.pyyaml_version,
            "principal_eligible": self.principal_eligible,
        }
        expected_dependencies = _json_digest(
            b"sluice-agentdojo-runtime-environment-v1", runtime_base
        )
        if (
            self.runtime_dependencies_sha256 != expected_dependencies
            or self.runtime_environment_sha256 != expected_dependencies
        ):
            raise LivePipelineError("live runtime-environment digest mismatch")
        for name in (
            "source_assets_sha256",
            "registry_sha256",
            "suite_object_sha256",
            "policy_manifest_sha256",
            "split_manifest_sha256",
            "schedule_sha256",
            "pair_id",
            "endpoint_attestation_sha256",
            "adapter_source_sha256",
            "runtime_environment_sha256",
            "runtime_dependencies_sha256",
            "durable_binding_sha256",
            "provenance_sha256",
        ):
            _sha256(name, getattr(self, name))
        if self.provenance_sha256 != live_run_provenance_sha256(self.to_wire()):
            raise LivePipelineError("live provenance digest mismatch")

    @property
    def sha256(self) -> str:
        return self.provenance_sha256

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark_version": self.benchmark_version,
            "source_commit": self.source_commit,
            "source_assets_sha256": self.source_assets_sha256,
            "registry_sha256": self.registry_sha256,
            "suite_object_sha256": self.suite_object_sha256,
            "runtime_tool_count": self.runtime_tool_count,
            "policy_manifest_sha256": self.policy_manifest_sha256,
            "split_manifest_sha256": self.split_manifest_sha256,
            "schedule_sha256": self.schedule_sha256,
            "suite_name": self.suite_name,
            "user_task_id": self.user_task_id,
            "injection_task_id": self.injection_task_id,
            "pair_id": self.pair_id,
            "condition": self.condition,
            "schedule_block": self.schedule_block,
            "schedule_order": self.schedule_order,
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "adapter_source_sha256": self.adapter_source_sha256,
            "runtime_environment_id": self.runtime_environment_id,
            "runtime_environment_sha256": self.runtime_environment_sha256,
            "principal_eligible": self.principal_eligible,
            "python_version": self.python_version,
            "pydantic_version": self.pydantic_version,
            "pyyaml_version": self.pyyaml_version,
            "runtime_dependencies_sha256": self.runtime_dependencies_sha256,
            "durable_binding_sha256": self.durable_binding_sha256,
            "provenance_sha256": self.provenance_sha256,
        }

    def revalidate(self) -> None:
        self.__post_init__()


@dataclass(frozen=True, slots=True, repr=False)
class SingletonGrantPlan:
    """Monitor-private bindings plus a redacted immutable binding digest."""

    manifest_sha256: str
    binding_sha256: str
    manifest: PolicyManifest = field(repr=False)
    private_bindings: tuple[object, ...] = field(repr=False)
    template_codes: Mapping[str, int] = field(repr=False)
    grants: tuple[SecureEffectGrant, ...] = field(repr=False)

    @classmethod
    def create(
        cls,
        *,
        manifest: PolicyManifest,
        grants: tuple[SecureEffectGrant, ...],
        template_codes: Mapping[str, int],
    ) -> "SingletonGrantPlan":
        from ..durable_service import PrivateTemplateBinding

        if type(manifest) is not PolicyManifest or manifest.decision is not PolicyDecision.COMPILED:
            raise LivePipelineError("singleton grants require a compiled manifest")
        if type(grants) is not tuple or any(
            type(grant) is not SecureEffectGrant for grant in grants
        ):
            raise TypeError("grants must be an exact SecureEffectGrant tuple")
        if not isinstance(template_codes, Mapping):
            raise TypeError("template_codes must be a mapping")
        codes = dict(template_codes)
        template_ids = {template.template_id for template in manifest.templates}
        if set(codes) != template_ids or len(grants) != len(template_ids):
            raise LivePipelineError("singleton template code registry is incomplete")
        if any(type(code) is not int or code <= 0 for code in codes.values()):
            raise LivePipelineError("singleton template code must be a positive integer")
        if len(set(codes.values())) != len(codes):
            raise LivePipelineError("singleton template codes must be unique")
        grant_by_id = {grant.template_id: grant for grant in grants}
        if len(grant_by_id) != len(grants) or set(grant_by_id) != template_ids:
            raise LivePipelineError("singleton grant/template binding mismatch")
        bindings: list[object] = []
        ordered_grants: list[SecureEffectGrant] = []
        for template in manifest.templates:
            grant = grant_by_id[template.template_id]
            if (
                grant.workflow_id != manifest.workflow_id
                or grant.episode_id != manifest.episode_id
                or grant.tool != template.tool
                or grant.exact_args != template.exact_args
            ):
                raise LivePipelineError("singleton grant does not match its exact template")
            binding = PrivateTemplateBinding(
                template_code=codes[template.template_id],
                route=grant.route,
                payload=grant.payload(),
                credential=grant.credential,
                capability=grant.capability,
                redeemer_id=grant.redeemer_id,
            )
            bindings.append(binding)
            ordered_grants.append(grant)
        private_wire = [binding.private_manifest() for binding in bindings]
        binding_digest = _json_digest(
            b"sluice-agentdojo-singleton-private-bindings-v1", private_wire
        )
        return cls(
            manifest_sha256=policy_manifest_sha256(manifest),
            binding_sha256=binding_digest,
            manifest=manifest,
            private_bindings=tuple(bindings),
            template_codes=MappingProxyType(codes),
            grants=tuple(ordered_grants),
        )

    def __post_init__(self) -> None:
        from ..durable_service import PrivateTemplateBinding

        _sha256("manifest digest", self.manifest_sha256)
        _sha256("singleton binding digest", self.binding_sha256)
        if type(self.manifest) is not PolicyManifest or self.manifest.decision is not PolicyDecision.COMPILED:
            raise LivePipelineError("singleton plan manifest is not compiled")
        if self.manifest_sha256 != policy_manifest_sha256(self.manifest):
            raise LivePipelineError("singleton plan manifest digest mismatch")
        if type(self.private_bindings) is not tuple or not self.private_bindings:
            raise LivePipelineError("singleton plan requires private bindings")
        if any(type(binding) is not PrivateTemplateBinding for binding in self.private_bindings):
            raise TypeError("singleton plan contains a nonprivate template binding")
        if (
            type(self.grants) is not tuple
            or any(type(grant) is not SecureEffectGrant for grant in self.grants)
            or len(self.grants) != len(self.private_bindings)
        ):
            raise LivePipelineError("singleton plan grant cardinality mismatch")
        codes = dict(self.template_codes)
        if set(codes) != {grant.template_id for grant in self.grants}:
            raise LivePipelineError("singleton plan template code set mismatch")
        templates = {template.template_id: template for template in self.manifest.templates}
        if set(templates) != set(codes):
            raise LivePipelineError("singleton plan differs from manifest templates")
        if [binding.template_code for binding in self.private_bindings] != [
            codes[grant.template_id] for grant in self.grants
        ]:
            raise LivePipelineError("singleton plan codes differ from private bindings")
        for binding, grant in zip(self.private_bindings, self.grants, strict=True):
            template = templates[grant.template_id]
            if (
                grant.workflow_id != self.manifest.workflow_id
                or grant.episode_id != self.manifest.episode_id
                or grant.tool != template.tool
                or grant.exact_args != template.exact_args
                or binding.route != grant.route
                or binding.payload_snapshot() != grant.payload()
                or binding.credential != grant.credential
                or binding.capability != grant.capability
                or binding.redeemer_id != grant.redeemer_id
            ):
                raise LivePipelineError("singleton private binding differs from its grant")
        expected = _json_digest(
            b"sluice-agentdojo-singleton-private-bindings-v1",
            [binding.private_manifest() for binding in self.private_bindings],
        )
        if self.binding_sha256 != expected:
            raise LivePipelineError("singleton private binding digest mismatch")
        object.__setattr__(self, "template_codes", MappingProxyType(codes))

    def __repr__(self) -> str:
        return (
            "SingletonGrantPlan("
            f"manifest_sha256={self.manifest_sha256!r}, "
            f"binding_sha256={self.binding_sha256!r}, "
            f"template_count={len(self.private_bindings)})"
        )

    def client(
        self,
        *,
        address: str,
        expected_monitor: object,
        timeout_seconds: float = 5.0,
    ) -> "SingletonAuthorizationClient":
        return SingletonAuthorizationClient(
            plan=self,
            address=address,
            expected_monitor=expected_monitor,
            timeout_seconds=timeout_seconds,
        )


def _singleton_exchange(
    address: str,
    request: object,
    *,
    expected_monitor: object,
    timeout_seconds: float,
) -> object:
    from ..durable_service import connect_model

    return connect_model(
        address,
        request,
        expected_monitor=expected_monitor,
        timeout_seconds=timeout_seconds,
    )


class SingletonAuthorizationClient:
    """One-shot authorizer compatible with ``NonOracleToolBroker.redeem``."""

    def __init__(
        self,
        *,
        plan: SingletonGrantPlan,
        address: str,
        expected_monitor: object,
        timeout_seconds: float,
    ) -> None:
        from ..durable_service import PeerIdentity

        if type(plan) is not SingletonGrantPlan:
            raise TypeError("plan must be a SingletonGrantPlan")
        if type(address) is not str or not address.startswith("\0"):
            raise LivePipelineError("singleton address must be a private abstract socket")
        if len(address.encode("utf-8")) > 107:
            raise LivePipelineError("singleton address exceeds the AF_UNIX bound")
        if type(expected_monitor) is not PeerIdentity:
            raise TypeError("expected_monitor must be an exact PeerIdentity")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
            raise LivePipelineError("singleton timeout must be in (0,60]")
        self._plan = plan
        self._address = address
        self._expected_monitor = expected_monitor
        self._timeout_seconds = float(timeout_seconds)
        self._grant_by_id = {grant.template_id: grant for grant in plan.grants}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def redeem(
        self, grant: SecureEffectGrant, payload: Mapping[str, str]
    ) -> AuthorizationOutcome:
        from ..durable_service import (
            MONITOR_PROTOCOL_VERSION,
            ModelOperationCode,
            ModelRequest,
        )
        from ..observer import EventKind, OutcomeCode, TranscriptEvent

        if type(grant) is not SecureEffectGrant or type(payload) is not dict:
            return AuthorizationOutcome.ERROR
        expected = self._grant_by_id.get(grant.template_id)
        if expected is None or grant is not expected:
            return AuthorizationOutcome.ERROR
        try:
            supplied_digest = _json_digest(
                b"sluice-agentdojo-singleton-grant-payload-v1", dict(payload)
            )
            expected_digest = _json_digest(
                b"sluice-agentdojo-singleton-grant-payload-v1", expected.payload()
            )
        except BaseException:
            return AuthorizationOutcome.ERROR
        if supplied_digest != expected_digest:
            return AuthorizationOutcome.ERROR
        with self._lock:
            if grant.template_id in self._consumed:
                return AuthorizationOutcome.ERROR
            self._consumed.add(grant.template_id)
        request_id = "adj-" + _digest_text(
            b"sluice-agentdojo-singleton-request-v1",
            f"{grant.workflow_id}\x00{grant.episode_id}\x00{grant.template_id}",
        )[:60]
        try:
            request = ModelRequest(
                schema_version=MONITOR_PROTOCOL_VERSION,
                request_id=request_id,
                operation_code=ModelOperationCode.ATTEMPT_TEMPLATE,
                template_code=self._plan.template_codes[grant.template_id],
            )
            event = _singleton_exchange(
                self._address,
                request,
                expected_monitor=self._expected_monitor,
                timeout_seconds=self._timeout_seconds,
            )
        except BaseException:
            return AuthorizationOutcome.ERROR
        if type(event) is not TranscriptEvent or event.kind is not EventKind.ATTEMPT:
            return AuthorizationOutcome.ERROR
        return (
            AuthorizationOutcome.RELEASED
            if event.outcome is OutcomeCode.RELEASED
            else AuthorizationOutcome.DENIED
        )


def _audit_base(record: "RedactedLiveCallRecord") -> dict[str, object]:
    return {
        "schema_version": record.schema_version,
        "sequence": record.sequence,
        "workflow_id": record.workflow_id,
        "episode_id": record.episode_id,
        "call_ordinal": record.call_ordinal,
        "call_id_sha256": record.call_id_sha256,
        "tool_sha256": record.tool_sha256,
        "args_sha256": record.args_sha256,
        "adapter_outcome": record.adapter_outcome.value,
        "broker_outcome": None
        if record.broker_outcome is None
        else record.broker_outcome.value,
        "broker_audit_sequence": record.broker_audit_sequence,
        "authorized": record.authorized,
        "executed": record.executed,
        "environment_before_sha256": record.environment_before_sha256,
        "environment_after_sha256": record.environment_after_sha256,
        "result_sha256": record.result_sha256,
        "provenance_sha256": record.provenance_sha256,
    }


@dataclass(frozen=True, slots=True)
class RedactedLiveCallRecord:
    sequence: int
    workflow_id: str
    episode_id: str
    call_ordinal: int
    call_id_sha256: str
    tool_sha256: str
    args_sha256: str
    adapter_outcome: CallAdapterOutcome
    broker_outcome: BrokerOutcome | None
    broker_audit_sequence: int | None
    authorized: bool
    executed: bool
    environment_before_sha256: str
    environment_after_sha256: str
    result_sha256: str
    provenance_sha256: str
    record_sha256: str
    schema_version: str = LIVE_CALL_AUDIT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != LIVE_CALL_AUDIT_SCHEMA:
            raise LivePipelineError("unsupported live-call audit schema")
        if type(self.sequence) is not int or not 1 <= self.sequence <= MAX_LIVE_CALLS:
            raise LivePipelineError("audit sequence is outside the finite bound")
        if type(self.call_ordinal) is not int or not 1 <= self.call_ordinal <= MAX_LIVE_CALLS:
            raise LivePipelineError("audit call ordinal is outside the finite bound")
        _text("workflow_id", self.workflow_id)
        _text("episode_id", self.episode_id)
        for name in (
            "call_id_sha256",
            "tool_sha256",
            "args_sha256",
            "environment_before_sha256",
            "environment_after_sha256",
            "result_sha256",
            "provenance_sha256",
            "record_sha256",
        ):
            _sha256(name, getattr(self, name))
        if type(self.adapter_outcome) is not CallAdapterOutcome:
            raise TypeError("adapter_outcome must be a finite enum")
        if self.broker_outcome is not None and type(self.broker_outcome) is not BrokerOutcome:
            raise TypeError("broker_outcome must be a finite enum or null")
        if self.broker_outcome is None:
            if self.broker_audit_sequence is not None or self.authorized or self.executed:
                raise LivePipelineError("nonbrokered audit record has broker-only fields")
        elif (
            type(self.broker_audit_sequence) is not int
            or self.broker_audit_sequence < 1
        ):
            raise LivePipelineError("brokered audit record lacks a broker sequence")
        if type(self.authorized) is not bool or type(self.executed) is not bool:
            raise TypeError("audit authorization/execution flags must be booleans")
        expected = _json_digest(b"sluice-agentdojo-live-call-audit-v1", _audit_base(self))
        if self.record_sha256 != expected:
            raise LivePipelineError("live-call audit digest mismatch")

    @classmethod
    def create(cls, **values: object) -> "RedactedLiveCallRecord":
        provisional = cls.__new__(cls)
        for name, value in values.items():
            object.__setattr__(provisional, name, value)
        object.__setattr__(provisional, "schema_version", LIVE_CALL_AUDIT_SCHEMA)
        digest = _json_digest(
            b"sluice-agentdojo-live-call-audit-v1", _audit_base(provisional)
        )
        values["record_sha256"] = digest
        return cls(**values)

    @classmethod
    def from_wire(cls, wire: object) -> "RedactedLiveCallRecord":
        if type(wire) is not dict:
            raise LivePipelineError("live-call audit wire value must be an object")
        expected = {
            "schema_version",
            "sequence",
            "workflow_id",
            "episode_id",
            "call_ordinal",
            "call_id_sha256",
            "tool_sha256",
            "args_sha256",
            "adapter_outcome",
            "broker_outcome",
            "broker_audit_sequence",
            "authorized",
            "executed",
            "environment_before_sha256",
            "environment_after_sha256",
            "result_sha256",
            "provenance_sha256",
            "record_sha256",
        }
        if set(wire) != expected:
            raise LivePipelineError("live-call audit wire fields are not exact")
        try:
            adapter = CallAdapterOutcome(wire["adapter_outcome"])
            broker = (
                None
                if wire["broker_outcome"] is None
                else BrokerOutcome(wire["broker_outcome"])
            )
        except (TypeError, ValueError) as exc:
            raise LivePipelineError("live-call audit outcome is invalid") from exc
        return cls(
            sequence=wire["sequence"],
            workflow_id=wire["workflow_id"],
            episode_id=wire["episode_id"],
            call_ordinal=wire["call_ordinal"],
            call_id_sha256=wire["call_id_sha256"],
            tool_sha256=wire["tool_sha256"],
            args_sha256=wire["args_sha256"],
            adapter_outcome=adapter,
            broker_outcome=broker,
            broker_audit_sequence=wire["broker_audit_sequence"],
            authorized=wire["authorized"],
            executed=wire["executed"],
            environment_before_sha256=wire["environment_before_sha256"],
            environment_after_sha256=wire["environment_after_sha256"],
            result_sha256=wire["result_sha256"],
            provenance_sha256=wire["provenance_sha256"],
            record_sha256=wire["record_sha256"],
            schema_version=wire["schema_version"],
        )

    def to_wire(self) -> dict[str, object]:
        wire = _audit_base(self)
        wire["record_sha256"] = self.record_sha256
        return wire


@dataclass(frozen=True, slots=True)
class OfficialExecutionResult:
    message: Mapping[str, Any]
    environment: Any
    adapter_outcome: CallAdapterOutcome
    broker_outcome: BrokerOutcome | None
    audit: RedactedLiveCallRecord


def _official_result_text(value: Any) -> str:
    """Match the pinned AgentDojo default formatter without importing clients."""

    import yaml
    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        result = yaml.safe_dump(value.model_dump()).strip()
    elif isinstance(value, list):
        items: list[Any] = []
        for item in value:
            if type(item) in (str, int):
                items.append(str(item))
            elif isinstance(item, BaseModel):
                items.append(item.model_dump())
            else:
                raise TypeError("unsupported official list result item")
        result = yaml.safe_dump(items).strip()
    else:
        result = str(value)
    if len(result.encode("utf-8")) > MAX_RESULT_BYTES:
        raise LivePipelineError("official tool result exceeds the live bound")
    return result


def _callable_guard(value: object) -> tuple[object, ...]:
    target = value.__func__ if inspect.ismethod(value) else value
    if not callable(target):
        raise LivePipelineError("sealed runtime callable is unavailable")
    code = getattr(target, "__code__", None)
    return (
        id(target),
        id(code),
        getattr(target, "__module__", None),
        getattr(target, "__qualname__", None),
    )


def _function_dispatch_guard(function: object) -> tuple[object, ...]:
    """Seal every attribute consulted by FunctionsRuntime.run_function."""

    run = getattr(function, "run", None)
    parameters_model = getattr(function, "parameters", None)
    parameters_schema = getattr(function, "parameters_schema", None)
    if parameters_model is not None and isinstance(parameters_model, type):
        if not hasattr(parameters_model, "model_json_schema"):
            raise LivePipelineError("sealed runtime parameter model is malformed")
        parameters_schema = parameters_model.model_json_schema()
        try:
            parameter_guard: tuple[object, ...] = (
                id(parameters_model),
                id(type(parameters_model)),
                *(
                    id(inspect.getattr_static(parameters_model, name))
                    for name in (
                        "model_validate",
                        "model_dump",
                        "model_json_schema",
                        "__pydantic_validator__",
                        "__pydantic_serializer__",
                    )
                ),
            )
        except AttributeError as exc:
            raise LivePipelineError("sealed runtime parameter model changed") from exc
    elif parameters_schema is not None:
        parameter_guard = ("static-schema",)
    else:
        raise LivePipelineError("sealed runtime schema is unavailable")
    dependencies = getattr(function, "dependencies", None)
    dependency_rows: list[object] = []
    if dependencies is not None:
        if type(dependencies) is not dict:
            raise LivePipelineError("sealed runtime dependencies are malformed")
        for name in sorted(dependencies):
            dependency = dependencies[name]
            env_dependency = getattr(dependency, "env_dependency", None)
            if type(env_dependency) is str:
                target_guard: object = ("attribute", env_dependency)
            elif callable(env_dependency):
                target_guard = ("callable", _callable_guard(env_dependency))
            else:
                raise LivePipelineError("sealed runtime dependency target is malformed")
            try:
                extract = inspect.getattr_static(type(dependency), "extract_dep_from_env")
            except AttributeError as exc:
                raise LivePipelineError("sealed runtime dependency extractor changed") from exc
            dependency_rows.append(
                (
                    name,
                    id(dependency),
                    id(type(dependency)),
                    id(extract),
                    _callable_guard(getattr(dependency, "extract_dep_from_env")),
                    target_guard,
                )
            )
        dependency_guard: object = (id(dependencies), tuple(dependency_rows))
    else:
        dependency_guard = ("no-dependency-field",)
    try:
        call_impl = inspect.getattr_static(type(function), "__call__")
    except AttributeError:
        call_impl = None
    return (
        getattr(function, "name", None),
        id(function),
        id(type(function)),
        id(call_impl),
        _json_digest(b"sluice-agentdojo-sealed-runtime-schema-v2", parameters_schema),
        parameter_guard,
        dependency_guard,
        _callable_guard(run),
    )


def _sealed_runtime_guard(runtime: object) -> tuple[object, ...]:
    """Snapshot the exact runtime registry and dispatch implementation."""

    try:
        functions = getattr(runtime, "functions", None)
        if not isinstance(functions, Mapping):
            raise LivePipelineError("sealed runtime function registry is malformed")
        run_function = inspect.getattr_static(type(runtime), "run_function")
        rows: list[tuple[object, ...]] = []
        for name in sorted(functions):
            if type(name) is not str:
                raise LivePipelineError("sealed runtime tool name is invalid")
            function = functions[name]
            if getattr(function, "name", None) != name:
                raise LivePipelineError("sealed runtime function name changed")
            rows.append((name, _function_dispatch_guard(function)))
        nested_dispatch = inspect.getattr_static(
            type(runtime), "_execute_nested_calls", None
        )
        nested_bound = getattr(runtime, "_execute_nested_calls", None)
        nested_guard: object = (
            ("absent",)
            if nested_bound is None
            else _callable_guard(nested_bound)
        )
        return (
            id(runtime),
            id(type(runtime)),
            id(functions),
            *_callable_guard(run_function),
            *_callable_guard(getattr(runtime, "run_function")),
            id(nested_dispatch),
            nested_guard,
            tuple(rows),
        )
    except LivePipelineError:
        raise
    except BaseException as exc:
        raise LivePipelineError("sealed runtime identity is unavailable") from exc


def _broker_identity_guard(broker: NonOracleToolBroker) -> tuple[object, ...]:
    """Seal immutable broker configuration while allowing accounted state changes."""

    try:
        manifest = broker._manifest
        registry = broker._registry
        schemas = broker._tool_schemas
        schema_by_name = broker._schema_by_name
        grants = broker._grants
        authorizer = broker._authorizer
        if type(schemas) is not tuple or type(schema_by_name) is not dict or type(grants) is not dict:
            raise LivePipelineError("broker configuration containers changed")
        schema_rows = tuple(
            (
                id(schema),
                schema.name,
                _json_digest(
                    b"sluice-agentdojo-broker-static-schema-v1",
                    schema.parameters_copy(),
                ),
            )
            for schema in schemas
        )
        schema_index = tuple(
            (name, id(schema_by_name[name])) for name in sorted(schema_by_name)
        )
        grant_rows = tuple(
            (repr(key), id(grants[key])) for key in sorted(grants, key=repr)
        )
        redeem = inspect.getattr_static(type(authorizer), "redeem")
        return (
            id(manifest),
            policy_manifest_sha256(manifest),
            id(registry),
            getattr(registry, "suite_name", None),
            tuple(sorted(getattr(registry, "read_only", ()))),
            tuple(sorted(getattr(registry, "effectful", ()))),
            id(schemas),
            schema_rows,
            id(schema_by_name),
            schema_index,
            id(broker._runtime),
            id(authorizer),
            id(type(authorizer)),
            id(redeem),
            _callable_guard(getattr(authorizer, "redeem")),
            id(grants),
            grant_rows,
            id(broker._unused),
            id(broker._consumed),
            id(broker._audit),
            id(broker._audit_lock),
            id(broker._execution_lock),
            id(broker._local),
            id(inspect.getattr_static(type(broker), "execute")),
            _callable_guard(getattr(broker, "execute")),
            id(inspect.getattr_static(type(broker), "audit_log")),
        )
    except LivePipelineError:
        raise
    except BaseException as exc:
        raise LivePipelineError("broker identity seal is unavailable") from exc


def _authenticate_principal_runtime(
    provenance: LiveRunProvenance,
    manifest: PolicyManifest,
    runtime: object,
    broker: NonOracleToolBroker,
    *,
    provenance_prevalidated: bool = False,
) -> None:
    """Bind a principal run to the exact official suite runtime objects."""

    if not provenance.principal_eligible:
        return
    if not provenance_prevalidated:
        provenance.revalidate()
    _authenticated_loaded_type(
        provenance.source,
        type(runtime),
        expected_module="agentdojo.functions_runtime",
        expected_qualname="FunctionsRuntime",
    )
    suite = provenance.registry.suites.get(manifest.suite_name)
    if suite is None:
        raise LivePipelineError("principal runtime suite is not official")
    functions = getattr(runtime, "functions", None)
    if type(functions) is not dict:
        raise LivePipelineError("principal runtime registry is not an exact dictionary")
    expected = {tool.name: tool for tool in suite.tools}
    if set(functions) != set(expected) or any(
        functions[name] is not expected[name] for name in expected
    ):
        raise LivePipelineError("principal runtime is not the authenticated suite registry")
    broker_registry = getattr(broker, "_registry", None)
    frozen_registry = V122_TOOL_REGISTRIES[manifest.suite_name]
    if (
        getattr(broker_registry, "suite_name", None) != manifest.suite_name
        or getattr(broker_registry, "read_only", None) != frozen_registry.read_only
        or getattr(broker_registry, "effectful", None) != frozen_registry.effectful
    ):
        raise LivePipelineError("principal broker classification is not official")
    broker_schemas = getattr(broker, "_schema_by_name", None)
    if type(broker_schemas) is not dict:
        raise LivePipelineError("principal broker schema index is malformed")
    observed_schemas = {
        name: broker_schemas[name].parameters_copy() for name in broker_schemas
    }
    expected_schemas = {
        tool.name: tool.parameters.model_json_schema() for tool in suite.tools
    }
    if observed_schemas != expected_schemas:
        raise LivePipelineError("principal broker schemas are not the official suite schemas")
    if not provenance_prevalidated:
        provenance.source.revalidate()


def _live_private_guard(provenance: LiveRunProvenance) -> tuple[object, ...]:
    return (
        id(provenance),
        id(provenance.source),
        id(provenance.registry),
        id(provenance.endpoint),
        id(provenance.schedule),
        id(provenance.runtime_environment),
        _json_digest(b"sluice-agentdojo-live-private-provenance-v1", provenance.to_wire()),
        _json_digest(
            b"sluice-agentdojo-live-private-endpoint-v1",
            provenance.endpoint.to_wire(),
        ),
        _json_digest(
            b"sluice-agentdojo-live-private-schedule-v1",
            provenance.schedule.to_wire(),
        ),
        _json_digest(
            b"sluice-agentdojo-live-private-environment-v1",
            provenance.runtime_environment.to_wire(),
        ),
    )


class OfficialBrokerExecutor:
    """Serial official-call adapter; the broker remains the sole dispatcher."""

    def __init__(
        self,
        *,
        binding: OfficialFunctionCallBinding,
        broker: NonOracleToolBroker,
        manifest: PolicyManifest,
        provenance: LiveRunProvenance,
    ) -> None:
        if type(binding) is not OfficialFunctionCallBinding:
            raise TypeError("binding must be an OfficialFunctionCallBinding")
        if type(broker) is not NonOracleToolBroker:
            raise TypeError("broker must be an exact NonOracleToolBroker")
        if type(manifest) is not PolicyManifest or manifest.decision is not PolicyDecision.COMPILED:
            raise LivePipelineError("executor requires a compiled policy manifest")
        if type(provenance) is not LiveRunProvenance:
            raise TypeError("provenance must be a LiveRunProvenance")
        provenance.revalidate()
        if provenance.policy_manifest_sha256 != policy_manifest_sha256(manifest):
            raise LivePipelineError("executor policy and provenance differ")
        if binding.source is not provenance.source:
            raise LivePipelineError("executor binding and provenance source differ")
        if getattr(broker, "_manifest", None) is not manifest and getattr(
            broker, "_manifest", None
        ) != manifest:
            raise LivePipelineError("executor broker and policy manifest differ")
        self._binding = binding
        self._broker = broker
        self._manifest = manifest
        self._provenance = provenance
        self._runtime = getattr(broker, "_runtime", None)
        if self._runtime is None:
            raise LivePipelineError("executor broker runtime is unavailable")
        _authenticate_principal_runtime(
            provenance,
            manifest,
            self._runtime,
            broker,
            provenance_prevalidated=True,
        )
        self._provenance_guard = _live_private_guard(provenance)
        self._runtime_guard = _sealed_runtime_guard(self._runtime)
        self._broker_guard = _broker_identity_guard(broker)
        self._seen_ordinals: set[int] = set()
        self._seen_provider_ids: set[str] = set()
        self._audit: list[RedactedLiveCallRecord] = []
        self._lock = threading.RLock()
        self._executor_state_guard = (
            id(self._seen_ordinals),
            id(self._seen_provider_ids),
            id(self._audit),
            id(self._lock),
        )

    def _revalidate_runtime(self, *, execution_boundary: bool = False) -> None:
        try:
            broker_guard = _broker_identity_guard(self._broker)
            executor_state_guard = (
                id(self._seen_ordinals),
                id(self._seen_provider_ids),
                id(self._audit),
                id(self._lock),
            )
        except AttributeError as exc:
            raise LivePipelineError("broker runtime guard is incomplete") from exc
        if (
            getattr(self._broker, "_runtime", None) is not self._runtime
            or broker_guard != self._broker_guard
            or executor_state_guard != self._executor_state_guard
            or _sealed_runtime_guard(self._runtime) != self._runtime_guard
            or _live_private_guard(self._provenance) != self._provenance_guard
        ):
            raise LivePipelineError("broker/runtime identity changed after sealing")
        if execution_boundary:
            # Source/data were hashed twice and filesystem-sealed at
            # acquisition, then revalidated when this executor was created.
            # Execution consumes only the already-loaded objects, so recheck
            # that exact live graph here without reading task/answer fields or
            # reintroducing a filesystem dependency into concurrent calls.
            self._provenance.registry.revalidate_runtime_objects(
                _source_prevalidated_token=_PREVALIDATED_SOURCE_TOKEN
            )
            _authenticate_principal_runtime(
                self._provenance,
                self._manifest,
                self._runtime,
                self._broker,
                provenance_prevalidated=True,
            )

    @property
    def audit_log(self) -> tuple[RedactedLiveCallRecord, ...]:
        with self._lock:
            return tuple(self._audit)

    def _request_id(self, snapshot: object, call_ordinal: int) -> str:
        provider = "none" if snapshot.id is None else _digest_text(
            b"sluice-agentdojo-provider-call-id-v1", snapshot.id
        )
        material = (
            f"{self._manifest.workflow_id}\x00{self._manifest.episode_id}\x00"
            f"{call_ordinal}\x00{provider}"
        )
        return "live-" + _digest_text(
            b"sluice-agentdojo-live-request-id-v1", material
        )[:59]

    def _message(
        self, snapshot: object, *, content: str, error: str | None
    ) -> Mapping[str, Any]:
        message = {
            "role": "tool",
            "content": [{"type": "text", "content": content}],
            "tool_call_id": snapshot.id,
            "tool_call": snapshot,
            "error": error,
        }
        # AgentDojo's ChatToolResultMessage is a TypedDict at runtime.  Return
        # an ordinary dict so the official message serializers can consume it.
        return message

    def _append_record(
        self,
        *,
        snapshot: object,
        call_ordinal: int,
        args_sha256: str,
        adapter_outcome: CallAdapterOutcome,
        broker_record: BrokerAuditRecord | None,
        broker_outcome: BrokerOutcome | None,
        environment_before: Any,
        environment_after: Any,
        result_text: str,
    ) -> RedactedLiveCallRecord:
        call_id_value = "none" if snapshot.id is None else snapshot.id
        record = RedactedLiveCallRecord.create(
            sequence=len(self._audit) + 1,
            workflow_id=self._manifest.workflow_id,
            episode_id=self._manifest.episode_id,
            call_ordinal=call_ordinal,
            call_id_sha256=_digest_text(
                b"sluice-agentdojo-live-provider-call-v1", call_id_value
            ),
            tool_sha256=_digest_text(
                b"sluice-agentdojo-live-tool-v1", snapshot.function
            ),
            args_sha256=args_sha256,
            adapter_outcome=adapter_outcome,
            broker_outcome=broker_outcome,
            broker_audit_sequence=None
            if broker_record is None
            else broker_record.sequence,
            authorized=False if broker_record is None else broker_record.authorized,
            executed=False if broker_record is None else broker_record.executed,
            environment_before_sha256=_safe_value_digest(
                b"sluice-agentdojo-live-env-before-v1", environment_before
            ),
            environment_after_sha256=_safe_value_digest(
                b"sluice-agentdojo-live-env-after-v1", environment_after
            ),
            result_sha256=_digest_text(
                b"sluice-agentdojo-live-result-v1", result_text
            ),
            provenance_sha256=self._provenance.sha256,
        )
        self._audit.append(record)
        return record

    def execute(
        self,
        call: object,
        environment: Any,
        *,
        call_ordinal: int,
    ) -> OfficialExecutionResult:
        if type(call_ordinal) is not int or not 1 <= call_ordinal <= MAX_LIVE_CALLS:
            raise LivePipelineError("call ordinal is outside the finite bound")
        self._revalidate_runtime(execution_boundary=True)
        snapshot = self._binding.snapshot(
            call, _source_prevalidated_token=_PREVALIDATED_SOURCE_TOKEN
        )
        sanitized = self._binding.sanitized(
            snapshot, _source_prevalidated_token=_PREVALIDATED_SOURCE_TOKEN
        )
        try:
            args_snapshot = copy.deepcopy(snapshot.args)
        except BaseException as exc:
            raise LivePipelineError("official tool arguments cannot be snapshotted") from exc
        if not isinstance(args_snapshot, Mapping) or any(
            type(key) is not str for key in args_snapshot
        ):
            raise LivePipelineError("official tool arguments are not a string-keyed mapping")
        args_sha = _args_digest(args_snapshot)
        with self._lock:
            provider_id = None if snapshot.id is None else snapshot.id
            replay = call_ordinal in self._seen_ordinals or (
                provider_id is not None and provider_id in self._seen_provider_ids
            )
            if replay:
                message = self._message(
                    sanitized, content="", error="SLUICE_REPLAY_DENIED"
                )
                record = self._append_record(
                    snapshot=sanitized,
                    call_ordinal=call_ordinal,
                    args_sha256=args_sha,
                    adapter_outcome=CallAdapterOutcome.REPLAY_DENIED,
                    broker_record=None,
                    broker_outcome=None,
                    environment_before=environment,
                    environment_after=environment,
                    result_text="",
                )
                return OfficialExecutionResult(
                    message, environment, CallAdapterOutcome.REPLAY_DENIED, None, record
                )
            self._seen_ordinals.add(call_ordinal)
            if provider_id is not None:
                self._seen_provider_ids.add(provider_id)
            if snapshot.placeholder_args is not None:
                message = self._message(
                    sanitized,
                    content="",
                    error="SLUICE_PLACEHOLDER_ARGUMENTS_DENIED",
                )
                record = self._append_record(
                    snapshot=sanitized,
                    call_ordinal=call_ordinal,
                    args_sha256=args_sha,
                    adapter_outcome=CallAdapterOutcome.PLACEHOLDER_ARGUMENTS_DENIED,
                    broker_record=None,
                    broker_outcome=None,
                    environment_before=environment,
                    environment_after=environment,
                    result_text="",
                )
                return OfficialExecutionResult(
                    message,
                    environment,
                    CallAdapterOutcome.PLACEHOLDER_ARGUMENTS_DENIED,
                    None,
                    record,
                )

            request = ToolRequest(
                call_id=self._request_id(snapshot, call_ordinal),
                function=snapshot.function,
                args=args_snapshot,
            )
            broker_before = len(self._broker.audit_log)
            self._revalidate_runtime()
            result: BrokerResult = self._broker.execute(request, environment)
            self._revalidate_runtime()
            broker_after = self._broker.audit_log
            if len(broker_after) != broker_before + 1:
                raise LivePipelineError("broker did not append exactly one audit record")
            broker_record = broker_after[-1]
            if broker_record.args_sha256 != args_sha:
                raise LivePipelineError("broker and live adapter argument snapshots differ")

            adapter_outcome = CallAdapterOutcome.BROKERED
            text = ""
            error: str | None = f"SLUICE_{result.outcome.value.upper()}"
            if result.outcome in {
                BrokerOutcome.EXECUTED_READ_ONLY,
                BrokerOutcome.EXECUTED_EFFECT,
            }:
                try:
                    text = _official_result_text(result.value)
                    error = None
                except BaseException:
                    text = ""
                    error = "SLUICE_RESULT_FORMAT_DENIED"
                    adapter_outcome = CallAdapterOutcome.RESULT_FORMAT_DENIED
            message = self._message(sanitized, content=text, error=error)
            record = self._append_record(
                snapshot=sanitized,
                call_ordinal=call_ordinal,
                args_sha256=args_sha,
                adapter_outcome=adapter_outcome,
                broker_record=broker_record,
                broker_outcome=result.outcome,
                environment_before=environment,
                environment_after=result.environment,
                result_text=text,
            )
            return OfficialExecutionResult(
                message=message,
                environment=result.environment,
                adapter_outcome=adapter_outcome,
                broker_outcome=result.outcome,
                audit=record,
            )


class OfficialBrokerPipelineElement:
    """AgentDojo-compatible tool element that cannot dispatch around Sluice.

    The class intentionally uses structural ``query`` compatibility instead
    of importing AgentDojo's provider-heavy pipeline package.  It accepts only
    the exact runtime already sealed inside ``NonOracleToolBroker`` and appends
    ordinary official tool-result dictionaries.
    """

    def __init__(self, executor: OfficialBrokerExecutor) -> None:
        if type(executor) is not OfficialBrokerExecutor:
            raise TypeError("executor must be an OfficialBrokerExecutor")
        executor._revalidate_runtime()
        runtime = executor._runtime
        self._executor = executor
        self._runtime = runtime
        self._next_ordinal = 1
        self._lock = threading.RLock()

    def query(
        self,
        query: str,
        runtime: object,
        env: Any,
        messages: object,
        extra_args: object,
    ) -> tuple[str, object, Any, list[object], dict[str, Any]]:
        self._executor._revalidate_runtime()
        if type(query) is not str:
            raise LivePipelineError("pipeline query must be a string")
        if runtime is not self._runtime:
            raise LivePipelineError("pipeline runtime differs from the broker runtime")
        if type(messages) not in (list, tuple):
            raise LivePipelineError("pipeline messages must be an exact finite sequence")
        if type(extra_args) is not dict:
            raise LivePipelineError("pipeline extra_args must be an exact dict")
        original = list(messages)
        if not original:
            return query, runtime, env, original, extra_args
        last = original[-1]
        if type(last) is not dict:
            raise LivePipelineError("pipeline message must be an exact official dict")
        if last.get("role") != "assistant":
            return query, runtime, env, original, extra_args
        if set(last) != {"role", "content", "tool_calls"}:
            raise LivePipelineError("assistant message fields are not exact")
        calls = last["tool_calls"]
        if calls is None:
            return query, runtime, env, original, extra_args
        if type(calls) is not list:
            raise LivePipelineError("assistant tool calls must be an exact list")
        if not calls:
            return query, runtime, env, original, extra_args
        if len(calls) > MAX_LIVE_CALLS:
            raise LivePipelineError("assistant tool-call list is outside the finite bound")
        appended: list[object] = []
        working = env
        with self._lock:
            for call in calls:
                if self._next_ordinal > MAX_LIVE_CALLS:
                    raise LivePipelineError("episode call horizon is exhausted")
                ordinal = self._next_ordinal
                self._next_ordinal += 1
                result = self._executor.execute(
                    call,
                    working,
                    call_ordinal=ordinal,
                )
                working = result.environment
                appended.append(dict(result.message))
        return query, runtime, working, [*original, *appended], extra_args


__all__ = [
    "CallAdapterOutcome",
    "CPU_AUDIT_RUNTIME_ENVIRONMENT_ID",
    "EndpointAttestation",
    "EndpointExpectation",
    "EndpointObservation",
    "LivePipelineError",
    "LiveRunProvenance",
    "OfficialBrokerExecutor",
    "OfficialBrokerPipelineElement",
    "OfficialExecutionResult",
    "OfficialFunctionCallBinding",
    "OfficialRegistryAttestation",
    "OfficialSourceAttestation",
    "PairedEpisodeIdentity",
    "PairedScheduleManifest",
    "PairedScheduledRun",
    "PRINCIPAL_RUNTIME_ENVIRONMENT_ID",
    "RedactedLiveCallRecord",
    "SingletonAuthorizationClient",
    "SingletonGrantPlan",
    "RuntimeEnvironmentAttestation",
    "V122_RUNTIME_TOOL_COUNT",
    "live_run_provenance_sha256",
    "policy_manifest_sha256",
]
