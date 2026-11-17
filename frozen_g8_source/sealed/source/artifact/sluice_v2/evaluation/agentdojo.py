"""Non-oracle AgentDojo v1.2.2 policy and execution foundation.

This module is intentionally separate from the invalidated historical pilot.
Its policy-authoring input consists only of the user-visible class-level
``PROMPT``, a trusted pre-injection state snapshot, static tool schemas, and a
versioned organization policy.  The compiled manifest records every source
digest and the dev/held-out assignment.  The primary path is source-audited
for hidden-answer attribute access.

The compiler accepts only a frozen, slotted DTO that contains no task/scorer
object.  The AST lint is defense in depth; the DTO/process boundary is the
non-oracle security boundary.  The broker mediates every runtime tool.
Mutating tools require one exact, single-use template and one durable
credential/capability pair.  Declared read-only tools execute against a copy
and are denied if the copy changes.
The durable authorization decision and capability consumption are crash
consistent; an AgentDojo in-memory environment mutation is not part of the
SQLite transaction.  Accordingly this is a harness foundation, not a claim
of crash-atomic external effects or a completed benchmark evaluation.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
from dataclasses import dataclass, field, replace
from enum import Enum
from fractions import Fraction
import hashlib
import inspect
import json
import math
from pathlib import Path
import re
import secrets
import struct
import threading
from types import CodeType, MappingProxyType
from typing import Any, Iterable, Mapping, Sequence


AGENTDOJO_VERSION = "0.1.35"
AGENTDOJO_COMMIT = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
AGENTDOJO_TREE = "3c74b60f2bad4ff321d864e0c0483f256cc8f8d2"
BENCHMARK_VERSION = "v1.2.2"

POLICY_INPUT_SCHEMA = "sluice-agentdojo-policy-input-v1"
ORG_POLICY_SCHEMA = "sluice-agentdojo-org-policy-v1"
CALL_TEMPLATE_SCHEMA = "sluice-agentdojo-call-template-v1"
POLICY_MANIFEST_SCHEMA = "sluice-agentdojo-policy-manifest-v1"
GRANT_PAYLOAD_SCHEMA = "sluice-agentdojo-effect-grant-v1"
SPLIT_SCHEMA = "sluice-agentdojo-split-v1"
SCHEDULE_SCHEMA = "sluice-agentdojo-counterbalanced-schedule-v1"

MAX_IDENTIFIER_BYTES = 512
MAX_PROMPT_BYTES = 1_048_576
MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 100_000
MAX_POLICY_RULES = 4_096
MAX_POLICY_TEMPLATES = 256
MAX_TOOL_SCHEMA_COUNT = 4_096
MAX_SPLIT_TASKS = 4_096
MAX_INTEGER = (1 << 63) - 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_MISSING = object()

# Capture the import origin before any caller can redirect the mutable module
# ``__file__`` attribute.  The compiler later verifies the path and bytes and
# separately hashes the live code objects that actually execute.
_MODULE_SOURCE_PATH = Path(__file__).resolve()
_MODULE_SOURCE_SHA256_AT_IMPORT = hashlib.sha256(
    _MODULE_SOURCE_PATH.read_bytes()
).hexdigest()

_PINNED_KEY_FILE_SHA256 = MappingProxyType(
    {
        "LICENSE": "4285a071f2d382338e52b4fb0a186d952984a34d43a33d8872e1a1d8cb43401e",
        "pyproject.toml": "f69dde819258d5dc2c6dca13ecbb116e54904374879a5c921332db36474e0a3b",
        "uv.lock": "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330",
    }
)
_PINNED_PYTHON_FILE_COUNT = 99
_PINNED_PYTHON_TREE_SHA256 = (
    "1d277192874c252ca21ece753b4ab10217958a1f41511b1f7175e919d9c01114"
)
_PINNED_LOADED_ASSET_FILE_COUNT = 112
_PINNED_LOADED_ASSET_TREE_SHA256 = (
    "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
)
# Filled from the specialization-independent semantic code graph below.  This
# makes the runtime identity an assertion, not merely an observer-supplied
# label; update it only after an intentional compiler implementation change.
_PINNED_COMPILER_RUNTIME_SHA256 = (
    "950876bcdc566ca830b4c29d20244fa2aa1ece77b73352164ae47cfdc930928e"
)
_LOADED_ASSET_SUFFIXES = frozenset({".py", ".yaml", ".yml", ".txt"})


class AgentDojoHarnessError(ValueError):
    """A versioned harness contract or trusted input is invalid."""


class EvaluationSplit(str, Enum):
    DEV = "dev"
    HELDOUT = "heldout"


class PolicyDecision(str, Enum):
    COMPILED = "compiled"
    ABSTAINED = "abstained"


class AbstentionCategory(str, Enum):
    NONE = "none"
    NO_MATCHING_RULE = "no_matching_rule"
    AMBIGUOUS_RULE = "ambiguous_rule"
    MISSING_STATE_VALUE = "missing_state_value"
    SCHEMA_MISMATCH = "schema_mismatch"
    UNDECLARED_EFFECT = "undeclared_effect"
    TEMPLATE_LIMIT = "template_limit"
    INVALID_POLICY = "invalid_policy"


class ToolKind(str, Enum):
    READ_ONLY = "read_only"
    EFFECTFUL = "effectful"


class AuthorizationOutcome(str, Enum):
    RELEASED = "released"
    DENIED = "denied"
    ERROR = "error"


class BrokerOutcome(str, Enum):
    EXECUTED_READ_ONLY = "executed_read_only"
    EXECUTED_EFFECT = "executed_effect"
    UNKNOWN_TOOL = "unknown_tool"
    REGISTRY_MISMATCH = "registry_mismatch"
    ARGUMENT_SCHEMA_DENIED = "argument_schema_denied"
    NESTED_CALL_DENIED = "nested_call_denied"
    REENTRANT_CALL_DENIED = "reentrant_call_denied"
    NO_AUTHORIZED_TEMPLATE = "no_authorized_template"
    AUTHORIZATION_DENIED = "authorization_denied"
    AUTHORIZER_ERROR = "authorizer_error"
    STATE_COPY_DENIED = "state_copy_denied"
    READ_ONLY_MUTATION = "read_only_mutation"
    TOOL_ERROR = "tool_error"


class ArgumentSource(str, Enum):
    LITERAL = "literal"
    STATE_POINTER = "state_pointer"


def _identifier(name: str, value: object) -> str:
    if type(value) is not str or not value:
        raise AgentDojoHarnessError(f"{name} must be a nonempty string")
    if len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise AgentDojoHarnessError(f"{name} exceeds the supported length")
    return value


def _sha256(name: str, value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise AgentDojoHarnessError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _freeze_json(value: Any, *, _depth: int = 0, _counter: list[int] | None = None) -> Any:
    if _counter is None:
        _counter = [0]
    if _depth > MAX_JSON_DEPTH:
        raise AgentDojoHarnessError("JSON value exceeds the supported nesting depth")
    _counter[0] += 1
    if _counter[0] > MAX_JSON_ITEMS:
        raise AgentDojoHarnessError("JSON value exceeds the supported item count")
    if value is None or type(value) in (str, bool):
        if type(value) is str and len(value.encode("utf-8")) > MAX_JSON_BYTES:
            raise AgentDojoHarnessError("JSON string exceeds the supported byte bound")
        return value
    if type(value) is int:
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            raise AgentDojoHarnessError("JSON integer exceeds the supported bound")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise AgentDojoHarnessError("JSON number must be finite")
        return value
    if type(value) in (list, tuple):
        return tuple(
            _freeze_json(item, _depth=_depth + 1, _counter=_counter) for item in value
        )
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise AgentDojoHarnessError("JSON object keys must be strings")
        return MappingProxyType(
            {
                key: _freeze_json(value[key], _depth=_depth + 1, _counter=_counter)
                for key in sorted(value)
            }
        )
    raise AgentDojoHarnessError(
        f"unsupported JSON value type: {type(value).__name__}"
    )


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


def _tagged(value: Any, *, _depth: int = 0, _counter: list[int] | None = None) -> Any:
    """Return a bounded injective JSON wire value with explicit type tags."""

    if _counter is None:
        _counter = [0]
    if _depth > MAX_JSON_DEPTH:
        raise AgentDojoHarnessError("value exceeds the supported nesting depth")
    _counter[0] += 1
    if _counter[0] > MAX_JSON_ITEMS:
        raise AgentDojoHarnessError("value exceeds the supported item count")
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            raise AgentDojoHarnessError("integer exceeds the supported bound")
        return ["int", str(value)]
    if type(value) is float:
        if not math.isfinite(value):
            raise AgentDojoHarnessError("number must be finite")
        return ["float", value.hex()]
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_JSON_BYTES:
            raise AgentDojoHarnessError("string exceeds the supported byte bound")
        return ["string", value]
    if type(value) in (list, tuple):
        tag = "list" if type(value) is list else "tuple"
        return [
            tag,
            [_tagged(item, _depth=_depth + 1, _counter=_counter) for item in value],
        ]
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise AgentDojoHarnessError("object keys must be strings")
        return [
            "object",
            [
                [key, _tagged(value[key], _depth=_depth + 1, _counter=_counter)]
                for key in sorted(value)
            ],
        ]
    raise AgentDojoHarnessError(
        f"unsupported value type: {type(value).__name__}"
    )


def _canonical_tagged(value: Any) -> str:
    encoded = json.dumps(
        _tagged(value), ensure_ascii=True, allow_nan=False, separators=(",", ":")
    )
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise AgentDojoHarnessError("canonical value exceeds the supported byte bound")
    return encoded


def canonical_args(args: Mapping[str, Any]) -> str:
    """Canonicalize exact tool arguments without JSON's type coercions."""

    if not isinstance(args, Mapping):
        raise TypeError("tool arguments must be a mapping")
    if any(type(key) is not str for key in args):
        raise TypeError("tool argument names must be strings")
    return _canonical_tagged({key: args[key] for key in sorted(args)})


def _json_wire_digest(value: Any) -> str:
    return _digest(_canonical_tagged(value).encode("utf-8"))


@dataclass(frozen=True, slots=True)
class StaticToolSchema:
    """Static pre-injection schema for one runtime tool."""

    name: str
    parameters: Mapping[str, Any]

    def __post_init__(self) -> None:
        _identifier("tool name", self.name)
        if not isinstance(self.parameters, Mapping):
            raise TypeError("tool parameters must be a mapping")
        _validate_supported_json_schema(self.parameters)
        frozen = _freeze_json(self.parameters)
        if not isinstance(frozen, Mapping):
            raise TypeError("tool parameters must be an object")
        object.__setattr__(self, "parameters", frozen)

    def parameters_copy(self) -> dict[str, Any]:
        return _thaw_json(self.parameters)

    def wire(self) -> dict[str, Any]:
        return {"name": self.name, "parameters": self.parameters_copy()}


def static_tool_schemas_from_suite(suite: object) -> tuple[StaticToolSchema, ...]:
    """Extract schemas from an official suite without consulting any task."""

    tools = inspect.getattr_static(suite, "tools", _MISSING)
    if tools is _MISSING:
        # Normal TaskSuite stores tools as a plain instance attribute.
        tools = getattr(suite, "tools", _MISSING)
    if not isinstance(tools, Sequence):
        raise AgentDojoHarnessError("suite has no static tool sequence")
    schemas: list[StaticToolSchema] = []
    for tool in tools:
        name = getattr(tool, "name", None)
        parameters = getattr(tool, "parameters", None)
        if parameters is None or not hasattr(parameters, "model_json_schema"):
            raise AgentDojoHarnessError("runtime tool has no static Pydantic schema")
        schemas.append(
            StaticToolSchema(name=name, parameters=parameters.model_json_schema())
        )
    return tuple(sorted(schemas, key=lambda item: item.name))


@dataclass(frozen=True, slots=True)
class ToolRegistry:
    """Exhaustive, non-overlapping classification for one suite."""

    suite_name: str
    read_only: frozenset[str]
    effectful: frozenset[str]

    def __post_init__(self) -> None:
        _identifier("suite_name", self.suite_name)
        if type(self.read_only) is not frozenset or type(self.effectful) is not frozenset:
            raise TypeError("tool registry partitions must be frozensets")
        if self.read_only & self.effectful:
            raise AgentDojoHarnessError("tool registry partitions overlap")
        if not self.declared:
            raise AgentDojoHarnessError("tool registry must not be empty")
        if len(self.declared) > MAX_TOOL_SCHEMA_COUNT:
            raise AgentDojoHarnessError("tool registry exceeds the supported bound")
        for name in self.declared:
            _identifier("tool name", name)

    @property
    def declared(self) -> frozenset[str]:
        return self.read_only | self.effectful

    def classify(self, tool: str) -> ToolKind:
        if tool in self.effectful:
            return ToolKind.EFFECTFUL
        if tool in self.read_only:
            return ToolKind.READ_ONLY
        raise AgentDojoHarnessError(f"unknown tool: {tool!r}")


_BANKING_EFFECTFUL = frozenset(
    {
        "schedule_transaction",
        "send_money",
        "update_password",
        "update_scheduled_transaction",
        "update_user_info",
    }
)
_BANKING_READ_ONLY = frozenset(
    {
        "get_balance",
        "get_iban",
        "get_most_recent_transactions",
        "get_scheduled_transactions",
        "get_user_info",
        "read_file",
    }
)
_SLACK_EFFECTFUL = frozenset(
    {
        "add_user_to_channel",
        # The pinned upstream get_webpage appends the requested URL to
        # web.web_requests (agentdojo/default_suites/v1/tools/web.py), so
        # it mutates the environment and is not read-only.  Same reason
        # workspace.get_unread_emails is classified effectful below.
        "get_webpage",
        "invite_user_to_slack",
        "post_webpage",
        "remove_user_from_slack",
        "send_channel_message",
        "send_direct_message",
    }
)
_SLACK_READ_ONLY = frozenset(
    {
        "get_channels",
        "get_users_in_channel",
        "read_channel_messages",
        "read_inbox",
    }
)
_TRAVEL_EFFECTFUL = frozenset(
    {
        "cancel_calendar_event",
        "create_calendar_event",
        "reserve_car_rental",
        "reserve_hotel",
        "reserve_restaurant",
        "send_email",
    }
)
_TRAVEL_READ_ONLY = frozenset(
    {
        "check_restaurant_opening_hours",
        "get_all_car_rental_companies_in_city",
        "get_all_hotels_in_city",
        "get_all_restaurants_in_city",
        "get_car_fuel_options",
        "get_car_price_per_day",
        "get_car_rental_address",
        "get_car_types_available",
        "get_contact_information_for_restaurants",
        "get_cuisine_type_for_restaurants",
        "get_day_calendar_events",
        "get_dietary_restrictions_for_all_restaurants",
        "get_flight_information",
        "get_hotels_address",
        "get_hotels_prices",
        "get_price_for_restaurants",
        "get_rating_reviews_for_car_rental",
        "get_rating_reviews_for_hotels",
        "get_rating_reviews_for_restaurants",
        "get_restaurants_address",
        "get_user_information",
        "search_calendar_events",
    }
)
_WORKSPACE_EFFECTFUL = frozenset(
    {
        "add_calendar_event_participants",
        "append_to_file",
        "cancel_calendar_event",
        "create_calendar_event",
        "create_file",
        "delete_email",
        "delete_file",
        # The official Inbox.get_unread implementation flips read=True.
        "get_unread_emails",
        "reschedule_calendar_event",
        "send_email",
        "share_file",
    }
)
_WORKSPACE_READ_ONLY = frozenset(
    {
        "get_current_day",
        "get_day_calendar_events",
        "get_draft_emails",
        "get_file_by_id",
        "get_received_emails",
        "get_sent_emails",
        "list_files",
        "search_calendar_events",
        "search_contacts_by_email",
        "search_contacts_by_name",
        "search_emails",
        "search_files",
        "search_files_by_filename",
    }
)

V122_TOOL_REGISTRIES: Mapping[str, ToolRegistry] = MappingProxyType(
    {
        "banking": ToolRegistry("banking", _BANKING_READ_ONLY, _BANKING_EFFECTFUL),
        "slack": ToolRegistry("slack", _SLACK_READ_ONLY, _SLACK_EFFECTFUL),
        "travel": ToolRegistry("travel", _TRAVEL_READ_ONLY, _TRAVEL_EFFECTFUL),
        "workspace": ToolRegistry(
            "workspace", _WORKSPACE_READ_ONLY, _WORKSPACE_EFFECTFUL
        ),
    }
)

_V122_TASK_COUNTS = MappingProxyType(
    {
        "banking": (16, 9),
        "slack": (21, 5),
        "travel": (20, 7),
        "workspace": (40, 14),
    }
)
_V122_TOOL_SCHEMA_SHA256 = MappingProxyType(
    {
        "banking": "f23fef04916f69a3e5ef875c66ceff729ecd685f4b790a5d8629401cf93be355",
        "slack": "d68133a16a3b80e2b53fb9db700f2ea57629e0683920a59cda24ec92de9275c4",
        "travel": "42291163f6f975cf674328c3697c19296843ac5e1f2130c3e2e2da93e88ead8a",
        "workspace": "b285f9ef2aa59b507e5c69768e98063ca0648cf8511ec7e7c0a9a2ccc48acda1",
    }
)


@dataclass(frozen=True, slots=True)
class V122ValidationSummary:
    benign_task_count: int
    injection_task_count: int
    attacked_pair_count: int
    suite_tool_counts: Mapping[str, int]
    suite_tool_schema_sha256: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class PinnedSourceSummary:
    root: Path
    python_file_count: int
    python_tree_sha256: str
    loaded_asset_file_count: int
    loaded_asset_tree_sha256: str
    key_file_sha256: Mapping[str, str]


def validate_pinned_checkout(root: str | Path) -> PinnedSourceSummary:
    """Authenticate the executable source and lock files before import.

    The Python-tree construction is the acquisition manifest's documented
    ``sha256(length(path)||path||length(content)||content)`` with unsigned
    64-bit big-endian lengths and POSIX paths relative to ``src/agentdojo``.
    The complete Git-tree/archive identity remains recorded in
    ``manifests/AGENTDOJO_SOURCE.json``; this fast check authenticates every
    executable Python byte, every loaded YAML/TXT benchmark asset, the license,
    package metadata, and lockfile.
    """

    requested_checkout = Path(root)
    if requested_checkout.is_symlink():
        raise AgentDojoHarnessError("pinned checkout root must not be a symlink")
    checkout = requested_checkout.resolve()
    source_root = checkout / "src" / "agentdojo"
    if not source_root.is_dir():
        raise AgentDojoHarnessError("pinned AgentDojo source directory is missing")
    if source_root.is_symlink():
        raise AgentDojoHarnessError("pinned AgentDojo source root must not be a symlink")
    # Reject links before selecting files: a link to bytes that currently hash
    # correctly can be retargeted after validation and is not an authenticated
    # checkout asset.  ``rglob`` reports symlinked directories without
    # traversing them, so this covers the entire selected source/data closure.
    if any(path.is_symlink() for path in source_root.rglob("*")):
        raise AgentDojoHarnessError("pinned AgentDojo source tree contains a symlink")
    all_source_files = sorted(
        (path for path in source_root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    unexpected = [
        path.relative_to(source_root).as_posix()
        for path in all_source_files
        if path.suffix not in _LOADED_ASSET_SUFFIXES
    ]
    if unexpected:
        # In particular, reject __pycache__/*.pyc: timestamp-valid cached
        # bytecode can be selected by Python even while every .py digest is
        # authentic.  The pinned official package contains exactly the 112
        # Python/YAML/TXT assets below and no other regular source-tree files.
        raise AgentDojoHarnessError(
            "pinned AgentDojo source tree contains an unauthenticated file type"
        )
    observed: dict[str, str] = {}
    for relative, expected in _PINNED_KEY_FILE_SHA256.items():
        path = checkout / relative
        if not path.is_file():
            raise AgentDojoHarnessError(f"pinned key file is missing: {relative}")
        if path.is_symlink():
            raise AgentDojoHarnessError(f"pinned key file is a symlink: {relative}")
        digest = _digest(path.read_bytes())
        if digest != expected:
            raise AgentDojoHarnessError(f"pinned key file digest mismatch: {relative}")
        observed[relative] = digest
    files = sorted(
        (path for path in all_source_files if path.suffix == ".py"),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    if len(files) != _PINNED_PYTHON_FILE_COUNT:
        raise AgentDojoHarnessError("pinned Python source file count mismatch")
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(source_root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(struct.pack(">Q", len(relative)))
        digest.update(relative)
        digest.update(struct.pack(">Q", len(content)))
        digest.update(content)
    tree_digest = digest.hexdigest()
    if tree_digest != _PINNED_PYTHON_TREE_SHA256:
        raise AgentDojoHarnessError("pinned Python source tree digest mismatch")

    # AgentDojo loads benchmark environments, injection vectors, system
    # messages, and one prompt corpus from package data.  Authenticating only
    # executable Python permits silent benchmark substitution while retaining
    # the same registry counts.  Pin every loaded source/data asset using the
    # same unambiguous path/content construction.
    loaded_assets = sorted(
        all_source_files,
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    if len(loaded_assets) != _PINNED_LOADED_ASSET_FILE_COUNT:
        raise AgentDojoHarnessError("pinned loaded-asset file count mismatch")
    asset_digest = hashlib.sha256()
    for path in loaded_assets:
        relative = path.relative_to(source_root).as_posix().encode("utf-8")
        content = path.read_bytes()
        asset_digest.update(struct.pack(">Q", len(relative)))
        asset_digest.update(relative)
        asset_digest.update(struct.pack(">Q", len(content)))
        asset_digest.update(content)
    loaded_asset_tree_digest = asset_digest.hexdigest()
    if loaded_asset_tree_digest != _PINNED_LOADED_ASSET_TREE_SHA256:
        raise AgentDojoHarnessError("pinned loaded-asset tree digest mismatch")
    return PinnedSourceSummary(
        root=checkout,
        python_file_count=len(files),
        python_tree_sha256=tree_digest,
        loaded_asset_file_count=len(loaded_assets),
        loaded_asset_tree_sha256=loaded_asset_tree_digest,
        key_file_sha256=MappingProxyType(observed),
    )


def validate_v122_suites(
    suites: Mapping[str, object], *, authenticate_schemas: bool = False
) -> V122ValidationSummary:
    """Validate official v1.2.2 suite objects against the frozen registry."""

    if type(authenticate_schemas) is not bool:
        raise TypeError("authenticate_schemas must be a boolean")
    if set(suites) != set(V122_TOOL_REGISTRIES):
        raise AgentDojoHarnessError("v1.2.2 suite set mismatch")
    benign = 0
    injections = 0
    pairs = 0
    tool_counts: dict[str, int] = {}
    schema_digests: dict[str, str] = {}
    for suite_name in sorted(V122_TOOL_REGISTRIES):
        suite = suites[suite_name]
        registry = V122_TOOL_REGISTRIES[suite_name]
        tools = getattr(suite, "tools", None)
        if not isinstance(tools, Sequence):
            raise AgentDojoHarnessError(f"{suite_name} suite has no tool sequence")
        names = [getattr(tool, "name", None) for tool in tools]
        if any(type(name) is not str for name in names) or len(names) != len(set(names)):
            raise AgentDojoHarnessError(f"{suite_name} runtime registry is malformed")
        actual = frozenset(names)
        if actual != registry.declared:
            raise AgentDojoHarnessError(
                f"{suite_name} registry mismatch: "
                f"unknown={sorted(actual - registry.declared)!r}, "
                f"missing={sorted(registry.declared - actual)!r}"
            )
        if authenticate_schemas:
            schemas = static_tool_schemas_from_suite(suite)
            schema_digest = _json_wire_digest([schema.wire() for schema in schemas])
            if schema_digest != _V122_TOOL_SCHEMA_SHA256[suite_name]:
                raise AgentDojoHarnessError(
                    f"{suite_name} v1.2.2 tool-schema digest mismatch"
                )
            schema_digests[suite_name] = schema_digest
        user_tasks = getattr(suite, "user_tasks", None)
        injection_tasks = getattr(suite, "injection_tasks", None)
        if not isinstance(user_tasks, Mapping) or not isinstance(injection_tasks, Mapping):
            raise AgentDojoHarnessError(f"{suite_name} task registries are malformed")
        expected_users, expected_injections = _V122_TASK_COUNTS[suite_name]
        if len(user_tasks) != expected_users or len(injection_tasks) != expected_injections:
            raise AgentDojoHarnessError(
                f"{suite_name} v1.2.2 task-count mismatch"
            )
        expected_user_ids = {f"user_task_{index}" for index in range(expected_users)}
        injection_start = 1 if suite_name == "slack" else 0
        expected_injection_ids = {
            f"injection_task_{index}"
            for index in range(injection_start, injection_start + expected_injections)
        }
        if set(user_tasks) != expected_user_ids:
            raise AgentDojoHarnessError(f"{suite_name} user task identifier mismatch")
        if set(injection_tasks) != expected_injection_ids:
            raise AgentDojoHarnessError(
                f"{suite_name} injection task identifier mismatch"
            )
        benign += len(user_tasks)
        injections += len(injection_tasks)
        pairs += len(user_tasks) * len(injection_tasks)
        tool_counts[suite_name] = len(actual)
    if benign != 97 or pairs != 949:
        raise AgentDojoHarnessError("aggregate v1.2.2 task-count mismatch")
    return V122ValidationSummary(
        benign_task_count=benign,
        injection_task_count=injections,
        attacked_pair_count=pairs,
        suite_tool_counts=MappingProxyType(tool_counts),
        suite_tool_schema_sha256=MappingProxyType(schema_digests),
    )


@dataclass(frozen=True, slots=True)
class SplitManifest:
    dev_task_ids: tuple[str, ...]
    heldout_task_ids: tuple[str, ...]
    sha256: str
    schema_version: str = SPLIT_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        dev_task_ids: Iterable[str],
        heldout_task_ids: Iterable[str],
    ) -> "SplitManifest":
        dev = tuple(sorted(dev_task_ids))
        heldout = tuple(sorted(heldout_task_ids))
        if len(dev) + len(heldout) > MAX_SPLIT_TASKS:
            raise AgentDojoHarnessError("split task bound exceeded")
        if len(dev) != len(set(dev)) or len(heldout) != len(set(heldout)):
            raise AgentDojoHarnessError("split contains duplicate task identifiers")
        if set(dev) & set(heldout):
            raise AgentDojoHarnessError("dev and heldout task splits overlap")
        if not dev and not heldout:
            raise AgentDojoHarnessError("split manifest must not be empty")
        wire = {
            "schema_version": SPLIT_SCHEMA,
            "dev_task_ids": list(dev),
            "heldout_task_ids": list(heldout),
        }
        return cls(dev, heldout, _json_wire_digest(wire))

    def __post_init__(self) -> None:
        if self.schema_version != SPLIT_SCHEMA:
            raise AgentDojoHarnessError("unsupported split schema")
        _sha256("split sha256", self.sha256)
        if type(self.dev_task_ids) is not tuple or type(self.heldout_task_ids) is not tuple:
            raise TypeError("split task identifiers must be tuples")
        if len(self.dev_task_ids) + len(self.heldout_task_ids) > MAX_SPLIT_TASKS:
            raise AgentDojoHarnessError("split task bound exceeded")
        for task_id in self.dev_task_ids + self.heldout_task_ids:
            _identifier("task_id", task_id)
            match = re.fullmatch(r"([^:]+):(user_task_(0|[1-9][0-9]*))", task_id)
            if match is None:
                raise AgentDojoHarnessError(
                    "split task identifiers must be suite-qualified user_task_N values"
                )
            suite, local, raw_index = match.groups()
            _identifier("split suite", suite)
            _identifier("split local task", local)
            if suite in _V122_TASK_COUNTS:
                expected_users = _V122_TASK_COUNTS[suite][0]
                if int(raw_index) >= expected_users:
                    raise AgentDojoHarnessError(
                        "official split task identifier is outside the pinned registry"
                    )
        if self.dev_task_ids != tuple(sorted(self.dev_task_ids)) or self.heldout_task_ids != tuple(
            sorted(self.heldout_task_ids)
        ):
            raise AgentDojoHarnessError("split identifiers must be canonically sorted")
        if len(self.dev_task_ids) != len(set(self.dev_task_ids)) or len(
            self.heldout_task_ids
        ) != len(set(self.heldout_task_ids)):
            raise AgentDojoHarnessError("split contains duplicate task identifiers")
        if set(self.dev_task_ids) & set(self.heldout_task_ids):
            raise AgentDojoHarnessError("dev and heldout task splits overlap")
        if not self.dev_task_ids and not self.heldout_task_ids:
            raise AgentDojoHarnessError("split manifest must not be empty")
        expected = _json_wire_digest(
            {
                "schema_version": SPLIT_SCHEMA,
                "dev_task_ids": list(self.dev_task_ids),
                "heldout_task_ids": list(self.heldout_task_ids),
            }
        )
        if self.sha256 != expected:
            raise AgentDojoHarnessError("split sha256 digest mismatch")

    def assignment(self, task_id: str) -> EvaluationSplit:
        _identifier("task_id", task_id)
        if task_id in self.dev_task_ids:
            return EvaluationSplit.DEV
        if task_id in self.heldout_task_ids:
            return EvaluationSplit.HELDOUT
        raise AgentDojoHarnessError("task is absent from the frozen split")


@dataclass(frozen=True, slots=True)
class ArgumentBinding:
    source: ArgumentSource
    value: Any

    def __post_init__(self) -> None:
        if type(self.source) is not ArgumentSource:
            raise TypeError("argument source must use the finite enum")
        if self.source is ArgumentSource.LITERAL:
            object.__setattr__(self, "value", _freeze_json(self.value))
        else:
            if type(self.value) is not str or not self.value.startswith("/"):
                raise AgentDojoHarnessError(
                    "state pointers must be nonempty RFC 6901-style paths"
                )
            if len(self.value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
                raise AgentDojoHarnessError("state pointer exceeds the supported length")

    @classmethod
    def literal(cls, value: Any) -> "ArgumentBinding":
        return cls(ArgumentSource.LITERAL, value)

    @classmethod
    def from_state(cls, pointer: str) -> "ArgumentBinding":
        return cls(ArgumentSource.STATE_POINTER, pointer)

    def wire(self) -> dict[str, Any]:
        return {"source": self.source.value, "value": _thaw_json(self.value)}


@dataclass(frozen=True, slots=True)
class CallTemplateSpec:
    tool: str
    arguments: Mapping[str, ArgumentBinding]
    schema_version: str = CALL_TEMPLATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != CALL_TEMPLATE_SCHEMA:
            raise AgentDojoHarnessError("unsupported call-template schema")
        _identifier("tool", self.tool)
        if not isinstance(self.arguments, Mapping):
            raise TypeError("template arguments must be a mapping")
        if any(type(key) is not str for key in self.arguments):
            raise TypeError("template argument names must be strings")
        if any(type(value) is not ArgumentBinding for value in self.arguments.values()):
            raise TypeError("template arguments must be ArgumentBinding values")
        object.__setattr__(
            self,
            "arguments",
            MappingProxyType({key: self.arguments[key] for key in sorted(self.arguments)}),
        )

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": self.tool,
            "arguments": {
                key: binding.wire() for key, binding in self.arguments.items()
            },
        }


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    suite_name: str
    prompt_sha256: str
    calls: tuple[CallTemplateSpec, ...]

    def __post_init__(self) -> None:
        _identifier("rule_id", self.rule_id)
        _identifier("suite_name", self.suite_name)
        _sha256("prompt_sha256", self.prompt_sha256)
        if type(self.calls) is not tuple:
            raise TypeError("rule calls must be a tuple")
        if len(self.calls) > MAX_POLICY_TEMPLATES:
            raise AgentDojoHarnessError("rule exceeds the template bound")
        if any(type(call) is not CallTemplateSpec for call in self.calls):
            raise TypeError("rule calls must be CallTemplateSpec values")

    def with_id(self, rule_id: str) -> "PolicyRule":
        return replace(self, rule_id=rule_id)

    def wire(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "suite_name": self.suite_name,
            "prompt_sha256": self.prompt_sha256,
            "calls": [call.wire() for call in self.calls],
        }


@dataclass(frozen=True, slots=True)
class OrganizationPolicy:
    policy_id: str
    rules: tuple[PolicyRule, ...]
    schema_version: str = ORG_POLICY_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ORG_POLICY_SCHEMA:
            raise AgentDojoHarnessError("unsupported organization-policy schema")
        _identifier("policy_id", self.policy_id)
        if type(self.rules) is not tuple:
            raise TypeError("organization policy rules must be a tuple")
        if len(self.rules) > MAX_POLICY_RULES:
            raise AgentDojoHarnessError("organization policy exceeds the rule bound")
        if any(type(rule) is not PolicyRule for rule in self.rules):
            raise TypeError("organization policy contains an invalid rule")
        identifiers = [rule.rule_id for rule in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise AgentDojoHarnessError("organization policy rule IDs must be unique")

    @property
    def sha256(self) -> str:
        return _json_wire_digest(self.wire())

    def wire(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "rules": [rule.wire() for rule in self.rules],
        }


@dataclass(frozen=True, slots=True)
class PolicyInput:
    source_commit: str
    benchmark_version: str
    suite_name: str
    task_id: str
    trusted_user_prompt: str
    pre_injection_state: Any
    tool_schemas: tuple[StaticToolSchema, ...]
    organization_policy: OrganizationPolicy
    split_manifest: SplitManifest
    schema_version: str = POLICY_INPUT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != POLICY_INPUT_SCHEMA:
            raise AgentDojoHarnessError("unsupported policy-input schema")
        if type(self.source_commit) is not str or _COMMIT_RE.fullmatch(self.source_commit) is None:
            raise AgentDojoHarnessError("source commit must be a lowercase Git SHA-1")
        if self.source_commit != AGENTDOJO_COMMIT:
            raise AgentDojoHarnessError("policy input source commit does not match the pin")
        if self.benchmark_version != BENCHMARK_VERSION:
            raise AgentDojoHarnessError("unsupported AgentDojo benchmark version")
        _identifier("suite_name", self.suite_name)
        _identifier("task_id", self.task_id)
        if self.suite_name in V122_TOOL_REGISTRIES:
            expected_prefix = f"{self.suite_name}:"
            if not self.task_id.startswith(expected_prefix):
                raise AgentDojoHarnessError(
                    "official AgentDojo task IDs must be suite-qualified"
                )
        if type(self.trusted_user_prompt) is not str or not self.trusted_user_prompt:
            raise AgentDojoHarnessError("trusted prompt must be a nonempty string")
        if len(self.trusted_user_prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise AgentDojoHarnessError("trusted prompt exceeds the supported bound")
        object.__setattr__(self, "pre_injection_state", _freeze_json(self.pre_injection_state))
        if type(self.tool_schemas) is not tuple or not self.tool_schemas:
            raise TypeError("tool_schemas must be a nonempty tuple")
        if len(self.tool_schemas) > MAX_TOOL_SCHEMA_COUNT:
            raise AgentDojoHarnessError("too many tool schemas")
        if any(type(schema) is not StaticToolSchema for schema in self.tool_schemas):
            raise TypeError("tool_schemas contains an invalid value")
        names = [schema.name for schema in self.tool_schemas]
        if len(names) != len(set(names)):
            raise AgentDojoHarnessError("tool schema names must be unique")
        if type(self.organization_policy) is not OrganizationPolicy:
            raise TypeError("organization_policy must be an OrganizationPolicy")
        if type(self.split_manifest) is not SplitManifest:
            raise TypeError("split_manifest must be a SplitManifest")
        self.split_manifest.assignment(self.task_id)

    @classmethod
    def from_task_prompt(
        cls,
        task: object,
        *,
        task_id: str,
        suite_name: str,
        pre_injection_state: Any,
        tool_schemas: tuple[StaticToolSchema, ...],
        organization_policy: OrganizationPolicy,
        split_manifest: SplitManifest,
    ) -> "PolicyInput":
        # Static lookup avoids executing a descriptor on an untrusted task
        # instance.  Only a literal class-level user prompt is accepted.
        prompt = inspect.getattr_static(type(task), "PROMPT", _MISSING)
        if type(prompt) is not str:
            raise TypeError("task must expose a literal class-level PROMPT string")
        return cls(
            source_commit=AGENTDOJO_COMMIT,
            benchmark_version=BENCHMARK_VERSION,
            suite_name=suite_name,
            task_id=task_id,
            trusted_user_prompt=prompt,
            pre_injection_state=pre_injection_state,
            tool_schemas=tool_schemas,
            organization_policy=organization_policy,
            split_manifest=split_manifest,
        )

    @property
    def split(self) -> EvaluationSplit:
        return self.split_manifest.assignment(self.task_id)

    @property
    def prompt_sha256(self) -> str:
        return _digest(self.trusted_user_prompt.encode("utf-8"))

    @property
    def state_sha256(self) -> str:
        return _json_wire_digest(_thaw_json(self.pre_injection_state))

    @property
    def tool_schema_sha256(self) -> str:
        return _json_wire_digest([schema.wire() for schema in self.tool_schemas])


@dataclass(frozen=True, slots=True)
class CallTemplate:
    template_id: str
    tool: str
    exact_args: str
    args_sha256: str
    schema_version: str = CALL_TEMPLATE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != CALL_TEMPLATE_SCHEMA:
            raise AgentDojoHarnessError("unsupported compiled-template schema")
        _identifier("template_id", self.template_id)
        _identifier("tool", self.tool)
        if type(self.exact_args) is not str or not self.exact_args:
            raise AgentDojoHarnessError("exact_args must be canonical text")
        _sha256("args_sha256", self.args_sha256)
        if _digest(self.exact_args.encode("utf-8")) != self.args_sha256:
            raise AgentDojoHarnessError("compiled template argument digest mismatch")


@dataclass(frozen=True, slots=True)
class PolicyManifest:
    policy_id: str
    workflow_id: str
    episode_id: str
    suite_name: str
    task_id: str
    split: EvaluationSplit
    decision: PolicyDecision
    abstention: AbstentionCategory
    templates: tuple[CallTemplate, ...]
    source_commit: str
    benchmark_version: str
    prompt_sha256: str
    state_sha256: str
    tool_schema_sha256: str
    organization_policy_sha256: str
    split_manifest_sha256: str
    compiler_id: str
    compiler_sha256: str
    compiler_runtime_sha256: str
    source_assets_sha256: str
    input_sha256: str
    schema_version: str = POLICY_MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != POLICY_MANIFEST_SCHEMA:
            raise AgentDojoHarnessError("unsupported policy-manifest schema")
        for name, value in (
            ("policy_id", self.policy_id),
            ("workflow_id", self.workflow_id),
            ("episode_id", self.episode_id),
            ("suite_name", self.suite_name),
            ("task_id", self.task_id),
            ("compiler_id", self.compiler_id),
        ):
            _identifier(name, value)
        if type(self.split) is not EvaluationSplit:
            raise TypeError("split must use the finite enum")
        if type(self.decision) is not PolicyDecision:
            raise TypeError("decision must use the finite enum")
        if type(self.abstention) is not AbstentionCategory:
            raise TypeError("abstention must use the finite enum")
        if type(self.templates) is not tuple or len(self.templates) > MAX_POLICY_TEMPLATES:
            raise AgentDojoHarnessError("manifest template bound exceeded")
        if any(type(template) is not CallTemplate for template in self.templates):
            raise TypeError("manifest contains an invalid template")
        identifiers = [template.template_id for template in self.templates]
        if len(identifiers) != len(set(identifiers)):
            raise AgentDojoHarnessError("template IDs must be unique")
        if self.decision is PolicyDecision.ABSTAINED:
            if self.abstention is AbstentionCategory.NONE or self.templates:
                raise AgentDojoHarnessError("abstained manifests must have a reason and no templates")
        elif self.abstention is not AbstentionCategory.NONE:
            raise AgentDojoHarnessError("compiled manifests cannot carry an abstention")
        if self.source_commit != AGENTDOJO_COMMIT or self.benchmark_version != BENCHMARK_VERSION:
            raise AgentDojoHarnessError("manifest source identity mismatch")
        for name, value in (
            ("prompt_sha256", self.prompt_sha256),
            ("state_sha256", self.state_sha256),
            ("tool_schema_sha256", self.tool_schema_sha256),
            ("organization_policy_sha256", self.organization_policy_sha256),
            ("split_manifest_sha256", self.split_manifest_sha256),
            ("compiler_sha256", self.compiler_sha256),
            ("compiler_runtime_sha256", self.compiler_runtime_sha256),
            ("source_assets_sha256", self.source_assets_sha256),
            ("input_sha256", self.input_sha256),
        ):
            _sha256(name, value)
        if self.source_assets_sha256 != _PINNED_LOADED_ASSET_TREE_SHA256:
            raise AgentDojoHarnessError("manifest loaded-source/data digest mismatch")


def _resolve_pointer(root: Any, pointer: str) -> Any:
    current = root
    parts = pointer.split("/")[1:]
    for raw in parts:
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if part not in current:
                raise KeyError(pointer)
            current = current[part]
        elif type(current) is tuple:
            if re.fullmatch(r"0|[1-9][0-9]*", part) is None:
                raise KeyError(pointer)
            index = int(part)
            if index >= len(current):
                raise KeyError(pointer)
            current = current[index]
        else:
            raise KeyError(pointer)
    return _thaw_json(current)


_SCHEMA_ANNOTATION_KEYS = frozenset(
    {
        "$id",
        "$schema",
        "default",
        "deprecated",
        "description",
        "examples",
        "format",
        "readOnly",
        "title",
        "writeOnly",
    }
)
_SCHEMA_ASSERTION_KEYS = frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "not",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "type",
    }
)
_JSON_TYPES = frozenset(
    {"null", "boolean", "integer", "number", "string", "array", "object"}
)


def _validate_supported_json_schema(schema: Any, *, _path: str = "$") -> None:
    """Reject every unsupported JSON Schema assertion instead of ignoring it.

    This is a deliberately finite Draft 2020-12-compatible subset covering
    every construct emitted by the pinned AgentDojo/Pydantic registry.  Schema
    annotations are inert.  Unknown assertions, external references, malformed
    combinators, and malformed constraints fail during schema construction.
    """

    if type(schema) is bool:
        return
    if not isinstance(schema, Mapping):
        raise AgentDojoHarnessError(f"JSON Schema at {_path} must be an object or boolean")
    if any(type(key) is not str for key in schema):
        raise AgentDojoHarnessError(f"JSON Schema keys at {_path} must be strings")
    unknown = set(schema) - _SCHEMA_ANNOTATION_KEYS - _SCHEMA_ASSERTION_KEYS
    if unknown:
        raise AgentDojoHarnessError(
            f"unsupported JSON Schema keyword at {_path}: {sorted(unknown)!r}"
        )
    expected = schema.get("type", _MISSING)
    if expected is not _MISSING:
        choices = expected if type(expected) in (list, tuple) else (expected,)
        if not choices or any(type(item) is not str or item not in _JSON_TYPES for item in choices):
            raise AgentDojoHarnessError(f"invalid JSON Schema type at {_path}")
        if len(choices) != len(set(choices)):
            raise AgentDojoHarnessError(f"duplicate JSON Schema types at {_path}")
    for keyword in ("anyOf", "oneOf", "allOf"):
        if keyword in schema:
            branches = schema[keyword]
            if type(branches) not in (list, tuple) or not branches:
                raise AgentDojoHarnessError(f"{keyword} at {_path} must be nonempty")
            for index, branch in enumerate(branches):
                _validate_supported_json_schema(
                    branch, _path=f"{_path}/{keyword}/{index}"
                )
    if "not" in schema:
        _validate_supported_json_schema(schema["not"], _path=f"{_path}/not")
    if "$defs" in schema:
        definitions = schema["$defs"]
        if not isinstance(definitions, Mapping) or any(
            type(name) is not str for name in definitions
        ):
            raise AgentDojoHarnessError(f"$defs at {_path} must be an object")
        for name, definition in definitions.items():
            _validate_supported_json_schema(
                definition, _path=f"{_path}/$defs/{name}"
            )
    if "$ref" in schema:
        reference = schema["$ref"]
        if type(reference) is not str or not reference.startswith("#/"):
            raise AgentDojoHarnessError(
                f"only local JSON Schema references are supported at {_path}"
            )
    if "properties" in schema:
        properties = schema["properties"]
        if not isinstance(properties, Mapping) or any(
            type(name) is not str for name in properties
        ):
            raise AgentDojoHarnessError(f"properties at {_path} must be an object")
        for name, child in properties.items():
            _validate_supported_json_schema(
                child, _path=f"{_path}/properties/{name}"
            )
    if "required" in schema:
        required = schema["required"]
        if type(required) not in (list, tuple) or any(
            type(name) is not str for name in required
        ) or len(required) != len(set(required)):
            raise AgentDojoHarnessError(f"required at {_path} must be unique strings")
    if "additionalProperties" in schema:
        additional = schema["additionalProperties"]
        if type(additional) is not bool:
            _validate_supported_json_schema(
                additional, _path=f"{_path}/additionalProperties"
            )
    if "items" in schema:
        _validate_supported_json_schema(schema["items"], _path=f"{_path}/items")
    if "enum" in schema:
        enum = schema["enum"]
        if type(enum) not in (list, tuple) or not enum:
            raise AgentDojoHarnessError(f"enum at {_path} must be nonempty")
        encodings = [_canonical_tagged(item) for item in enum]
        if len(encodings) != len(set(encodings)):
            raise AgentDojoHarnessError(f"enum at {_path} contains typed duplicates")
    for keyword in (
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minProperties",
        "maxProperties",
    ):
        if keyword in schema and (
            type(schema[keyword]) is not int or schema[keyword] < 0
        ):
            raise AgentDojoHarnessError(f"{keyword} at {_path} must be nonnegative")
    if "pattern" in schema:
        if type(schema["pattern"]) is not str:
            raise AgentDojoHarnessError(f"pattern at {_path} must be a string")
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise AgentDojoHarnessError(f"invalid pattern at {_path}") from exc
    for keyword in (
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    ):
        if keyword in schema:
            number = schema[keyword]
            if type(number) is int:
                finite = -MAX_INTEGER <= number <= MAX_INTEGER
            elif type(number) is float:
                finite = math.isfinite(number)
            else:
                finite = False
            if not finite:
                raise AgentDojoHarnessError(f"{keyword} at {_path} must be finite")
            if keyword == "multipleOf" and number <= 0:
                raise AgentDojoHarnessError(f"multipleOf at {_path} must be positive")


def _typed_json_equal(left: Any, right: Any) -> bool:
    try:
        return _canonical_tagged(left) == _canonical_tagged(right)
    except (TypeError, ValueError):
        return False


def _resolve_schema_reference(root: Mapping[str, Any], reference: str) -> Any:
    current: Any = root
    for raw in reference[2:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or part not in current:
            raise AgentDojoHarnessError("unresolved local JSON Schema reference")
        current = current[part]
    return current


def _has_json_type(value: Any, expected: str) -> bool:
    checks = {
        "null": lambda item: item is None,
        "boolean": lambda item: type(item) is bool,
        "integer": lambda item: type(item) is int,
        "number": lambda item: type(item) in (int, float) and type(item) is not bool,
        "string": lambda item: type(item) is str,
        "array": lambda item: type(item) is list,
        "object": lambda item: type(item) is dict,
    }
    return checks[expected](value)


def _matches_json_schema(
    value: Any,
    schema: Any,
    *,
    _root: Mapping[str, Any] | None = None,
) -> bool:
    if type(schema) is bool:
        return schema
    if not isinstance(schema, Mapping):
        return False
    root = schema if _root is None else _root
    if "$ref" in schema:
        try:
            target = _resolve_schema_reference(root, schema["$ref"])
        except AgentDojoHarnessError:
            return False
        if not _matches_json_schema(value, target, _root=root):
            return False
    if "enum" in schema and not any(
        _typed_json_equal(value, candidate) for candidate in schema["enum"]
    ):
        return False
    if "const" in schema and not _typed_json_equal(value, schema["const"]):
        return False
    if "allOf" in schema and not all(
        _matches_json_schema(value, branch, _root=root)
        for branch in schema["allOf"]
    ):
        return False
    if "anyOf" in schema and not any(
        _matches_json_schema(value, branch, _root=root)
        for branch in schema["anyOf"]
    ):
        return False
    if "oneOf" in schema and sum(
        _matches_json_schema(value, branch, _root=root)
        for branch in schema["oneOf"]
    ) != 1:
        return False
    if "not" in schema and _matches_json_schema(value, schema["not"], _root=root):
        return False
    expected = schema.get("type", _MISSING)
    if expected is not _MISSING:
        choices = expected if type(expected) in (list, tuple) else (expected,)
        if not any(_has_json_type(value, item) for item in choices):
            return False
    if type(value) is str:
        if "minLength" in schema and len(value) < schema["minLength"]:
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
    if type(value) in (int, float) and type(value) is not bool:
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            return False
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            return False
        if "multipleOf" in schema:
            # JSON numbers are mathematical decimal values.  Converting their
            # bounded Python spelling to exact rational values avoids both
            # binary-float tolerance errors and overflow for divisors such as
            # the smallest positive finite float.
            if Fraction(str(value)) % Fraction(str(schema["multipleOf"])) != 0:
                return False
    if type(value) is list:
        if "minItems" in schema and len(value) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        if "items" in schema and not all(
            _matches_json_schema(item, schema["items"], _root=root)
            for item in value
        ):
            return False
    if type(value) is dict:
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            return False
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            return False
        properties = schema.get("properties", {})
        required = schema.get("required", ())
        if any(name not in value for name in required):
            return False
        for name, item in value.items():
            if name in properties:
                if not _matches_json_schema(item, properties[name], _root=root):
                    return False
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                return False
            if additional is not True and not _matches_json_schema(
                item, additional, _root=root
            ):
                return False
    return True


def _arguments_match_schema(args: Mapping[str, Any], schema: StaticToolSchema) -> bool:
    try:
        if type(args) is not dict:
            args = dict(args)
        return _matches_json_schema(args, schema.parameters, _root=schema.parameters)
    except BaseException:
        # A trusted schema should have been validated at construction, but no
        # malformed or numerically adversarial combination may escape the
        # finite compiler/broker decision surface.
        return False


def _policy_input_digest(policy_input: PolicyInput) -> str:
    return _json_wire_digest(
        {
            "schema_version": policy_input.schema_version,
            "source_commit": policy_input.source_commit,
            "benchmark_version": policy_input.benchmark_version,
            "source_assets_sha256": _PINNED_LOADED_ASSET_TREE_SHA256,
            "suite_name": policy_input.suite_name,
            "task_id": policy_input.task_id,
            "split": policy_input.split.value,
            "split_manifest_sha256": policy_input.split_manifest.sha256,
            "prompt_sha256": policy_input.prompt_sha256,
            "state_sha256": policy_input.state_sha256,
            "tool_schema_sha256": policy_input.tool_schema_sha256,
            "organization_policy_sha256": policy_input.organization_policy.sha256,
        }
    )


def _stable_code_constant(value: Any) -> Any:
    """Return an injective, specialization-independent code constant wire."""

    if isinstance(value, CodeType):
        return ["code", _stable_code_wire(value)]
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", str(value)]
    if type(value) is float:
        if not math.isfinite(value):
            raise AgentDojoHarnessError("compiler code contains a non-finite constant")
        return ["float", value.hex()]
    if type(value) is str:
        return ["string", value]
    if type(value) is bytes:
        return ["bytes", value.hex()]
    if type(value) is tuple:
        return ["tuple", [_stable_code_constant(item) for item in value]]
    if type(value) is frozenset:
        items = [_stable_code_constant(item) for item in value]
        items.sort(
            key=lambda item: json.dumps(
                item, ensure_ascii=True, allow_nan=False, separators=(",", ":")
            )
        )
        return ["frozenset", items]
    raise AgentDojoHarnessError(
        f"unsupported compiler code constant: {type(value).__name__}"
    )


def _stable_code_wire(code: CodeType) -> list[Any]:
    """Serialize behavior-bearing fields without CPython quickening state."""

    return [
        code.co_name,
        code.co_qualname,
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code.hex(),
        [_stable_code_constant(item) for item in code.co_consts],
        list(code.co_names),
        list(code.co_varnames),
        list(code.co_freevars),
        list(code.co_cellvars),
        code.co_exceptiontable.hex(),
    ]


def _executing_compiler_digest() -> str:
    """Hash the live semantic code graph used by the static compiler.

    ``marshal.dumps(code)`` is deliberately not used: on CPython 3.11 its
    representation incorporates adaptive specialization state and changes
    after the first execution.  ``co_code`` exposes the stable unquickened
    bytecode.  Together with behavior-bearing metadata and recursively tagged
    constants, this records the code that actually executes while remaining
    reproducible across first/subsequent calls and fresh processes.
    """

    functions = (
        compile_static_policy,
        _manifest,
        _policy_input_digest,
        _resolve_pointer,
        _arguments_match_schema,
        _matches_json_schema,
        _validate_supported_json_schema,
        _resolve_schema_reference,
        _has_json_type,
        _typed_json_equal,
        _canonical_tagged,
        _tagged,
        _freeze_json,
        _thaw_json,
        _json_wire_digest,
        _identifier,
        _sha256,
        canonical_args,
        StaticToolSchema.__post_init__,
        SplitManifest.__post_init__,
        ArgumentBinding.__post_init__,
        ArgumentBinding.wire,
        CallTemplateSpec.__post_init__,
        CallTemplateSpec.wire,
        PolicyRule.__post_init__,
        PolicyRule.wire,
        OrganizationPolicy.__post_init__,
        OrganizationPolicy.wire,
        OrganizationPolicy.sha256.fget,
        PolicyInput.__post_init__,
        PolicyInput.prompt_sha256.fget,
        PolicyInput.state_sha256.fget,
        PolicyInput.tool_schema_sha256.fget,
        CallTemplate.__post_init__,
        PolicyManifest.__post_init__,
        ToolRegistry.classify,
        _stable_code_constant,
        _stable_code_wire,
        _executing_compiler_digest,
        _verified_compiler_identity,
    )
    wire = [
        [function.__qualname__, _stable_code_wire(function.__code__)]
        for function in sorted(functions, key=lambda item: item.__qualname__)
    ]
    encoded = json.dumps(
        wire,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return _digest(encoded)


def _verified_compiler_identity() -> tuple[str, str]:
    try:
        current_path = Path(__file__).resolve()
        current_source_sha256 = _digest(current_path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise AgentDojoHarnessError("compiler source attestation is unavailable") from exc
    if current_path != _MODULE_SOURCE_PATH:
        raise AgentDojoHarnessError("compiler source path changed after import")
    if current_source_sha256 != _MODULE_SOURCE_SHA256_AT_IMPORT:
        raise AgentDojoHarnessError("compiler source bytes changed after import")
    runtime_sha256 = _executing_compiler_digest()
    if runtime_sha256 != _PINNED_COMPILER_RUNTIME_SHA256:
        raise AgentDojoHarnessError("compiler executable graph identity mismatch")
    return current_source_sha256, runtime_sha256


def _manifest(
    policy_input: PolicyInput,
    *,
    workflow_id: str,
    episode_id: str,
    compiler_id: str,
    compiler_sha256: str,
    compiler_runtime_sha256: str,
    decision: PolicyDecision,
    abstention: AbstentionCategory,
    templates: tuple[CallTemplate, ...],
) -> PolicyManifest:
    return PolicyManifest(
        policy_id=policy_input.organization_policy.policy_id,
        workflow_id=workflow_id,
        episode_id=episode_id,
        suite_name=policy_input.suite_name,
        task_id=policy_input.task_id,
        split=policy_input.split,
        decision=decision,
        abstention=abstention,
        templates=templates,
        source_commit=policy_input.source_commit,
        benchmark_version=policy_input.benchmark_version,
        prompt_sha256=policy_input.prompt_sha256,
        state_sha256=policy_input.state_sha256,
        tool_schema_sha256=policy_input.tool_schema_sha256,
        organization_policy_sha256=policy_input.organization_policy.sha256,
        split_manifest_sha256=policy_input.split_manifest.sha256,
        compiler_id=compiler_id,
        compiler_sha256=compiler_sha256,
        compiler_runtime_sha256=compiler_runtime_sha256,
        source_assets_sha256=_PINNED_LOADED_ASSET_TREE_SHA256,
        input_sha256=_policy_input_digest(policy_input),
    )


def compile_static_policy(
    policy_input: PolicyInput,
    *,
    registry: ToolRegistry,
    workflow_id: str,
    episode_id: str,
    compiler_id: str,
) -> PolicyManifest:
    """Compile exact calls from only the four fields in ``PolicyInput``."""

    if type(policy_input) is not PolicyInput:
        raise TypeError("policy_input must be a PolicyInput")
    if type(registry) is not ToolRegistry:
        raise TypeError("registry must be a ToolRegistry")
    if registry.suite_name != policy_input.suite_name:
        raise AgentDojoHarnessError("policy input and registry suites differ")
    for name, value in (
        ("workflow_id", workflow_id),
        ("episode_id", episode_id),
        ("compiler_id", compiler_id),
    ):
        _identifier(name, value)
    # Bind both immutable-at-import source bytes and the live code objects that
    # actually execute.  The complete pinned AgentDojo source/data asset digest
    # is carried separately in every manifest and policy-input digest.
    compiler_sha256, compiler_runtime_sha256 = _verified_compiler_identity()
    schemas = {schema.name: schema for schema in policy_input.tool_schemas}
    if set(schemas) != set(registry.declared):
        raise AgentDojoHarnessError("static tool schemas and registry differ")
    matches = [
        rule
        for rule in policy_input.organization_policy.rules
        if rule.suite_name == policy_input.suite_name
        and rule.prompt_sha256 == policy_input.prompt_sha256
    ]
    if not matches:
        return _manifest(
            policy_input,
            workflow_id=workflow_id,
            episode_id=episode_id,
            compiler_id=compiler_id,
            compiler_sha256=compiler_sha256,
            compiler_runtime_sha256=compiler_runtime_sha256,
            decision=PolicyDecision.ABSTAINED,
            abstention=AbstentionCategory.NO_MATCHING_RULE,
            templates=(),
        )
    if len(matches) != 1:
        return _manifest(
            policy_input,
            workflow_id=workflow_id,
            episode_id=episode_id,
            compiler_id=compiler_id,
            compiler_sha256=compiler_sha256,
            compiler_runtime_sha256=compiler_runtime_sha256,
            decision=PolicyDecision.ABSTAINED,
            abstention=AbstentionCategory.AMBIGUOUS_RULE,
            templates=(),
        )
    rule = matches[0]
    if len(rule.calls) > MAX_POLICY_TEMPLATES:
        category = AbstentionCategory.TEMPLATE_LIMIT
        return _manifest(
            policy_input,
            workflow_id=workflow_id,
            episode_id=episode_id,
            compiler_id=compiler_id,
            compiler_sha256=compiler_sha256,
            compiler_runtime_sha256=compiler_runtime_sha256,
            decision=PolicyDecision.ABSTAINED,
            abstention=category,
            templates=(),
        )
    resolved_templates: list[CallTemplate] = []
    for index, spec in enumerate(rule.calls):
        if spec.tool not in registry.effectful:
            return _manifest(
                policy_input,
                workflow_id=workflow_id,
                episode_id=episode_id,
                compiler_id=compiler_id,
                compiler_sha256=compiler_sha256,
                compiler_runtime_sha256=compiler_runtime_sha256,
                decision=PolicyDecision.ABSTAINED,
                abstention=AbstentionCategory.UNDECLARED_EFFECT,
                templates=(),
            )
        args: dict[str, Any] = {}
        try:
            for name, binding in spec.arguments.items():
                if binding.source is ArgumentSource.LITERAL:
                    args[name] = _thaw_json(binding.value)
                else:
                    args[name] = _resolve_pointer(
                        policy_input.pre_injection_state, binding.value
                    )
        except KeyError:
            return _manifest(
                policy_input,
                workflow_id=workflow_id,
                episode_id=episode_id,
                compiler_id=compiler_id,
                compiler_sha256=compiler_sha256,
                compiler_runtime_sha256=compiler_runtime_sha256,
                decision=PolicyDecision.ABSTAINED,
                abstention=AbstentionCategory.MISSING_STATE_VALUE,
                templates=(),
            )
        if not _arguments_match_schema(args, schemas[spec.tool]):
            return _manifest(
                policy_input,
                workflow_id=workflow_id,
                episode_id=episode_id,
                compiler_id=compiler_id,
                compiler_sha256=compiler_sha256,
                compiler_runtime_sha256=compiler_runtime_sha256,
                decision=PolicyDecision.ABSTAINED,
                abstention=AbstentionCategory.SCHEMA_MISMATCH,
                templates=(),
            )
        exact = canonical_args(args)
        resolved_templates.append(
            CallTemplate(
                template_id=f"{rule.rule_id}-{index:04d}",
                tool=spec.tool,
                exact_args=exact,
                args_sha256=_digest(exact.encode("utf-8")),
            )
        )
    return _manifest(
        policy_input,
        workflow_id=workflow_id,
        episode_id=episode_id,
        compiler_id=compiler_id,
        compiler_sha256=compiler_sha256,
        compiler_runtime_sha256=compiler_runtime_sha256,
        decision=PolicyDecision.COMPILED,
        abstention=AbstentionCategory.NONE,
        templates=tuple(resolved_templates),
    )


@dataclass(frozen=True, slots=True)
class ScheduledRun:
    block: int
    order: int
    episode_id: str
    arm: str


def generate_counterbalanced_schedule(
    episode_ids: Iterable[str], *, arms: tuple[str, str], seed: str
) -> tuple[ScheduledRun, ...]:
    """Return deterministic AB/BA pairs with arm order balanced by one."""

    episodes = tuple(episode_ids)
    if len(episodes) != len(set(episodes)):
        raise AgentDojoHarnessError("schedule episode IDs must be unique")
    for episode in episodes:
        _identifier("episode_id", episode)
    if type(arms) is not tuple or len(arms) != 2 or arms[0] == arms[1]:
        raise AgentDojoHarnessError("counterbalanced schedule requires two distinct arms")
    for arm in arms:
        _identifier("arm", arm)
    _identifier("schedule seed", seed)
    ordered = sorted(
        episodes,
        key=lambda episode: _digest(
            f"{SCHEDULE_SCHEMA}\x00{seed}\x00{episode}".encode("utf-8")
        ),
    )
    schedule: list[ScheduledRun] = []
    for block, episode in enumerate(ordered):
        first, second = arms if block % 2 == 0 else (arms[1], arms[0])
        schedule.append(ScheduledRun(block, 1, episode, first))
        schedule.append(ScheduledRun(block, 2, episode, second))
    return tuple(schedule)


@dataclass(frozen=True, slots=True)
class ToolRequest:
    call_id: str
    function: str
    args: Mapping[str, Any]

    def __post_init__(self) -> None:
        _identifier("call_id", self.call_id)
        _identifier("function", self.function)
        if not isinstance(self.args, Mapping):
            raise TypeError("tool request args must be a mapping")
        if any(type(key) is not str for key in self.args):
            raise TypeError("tool request argument names must be strings")
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))


@dataclass(frozen=True, slots=True)
class SecureEffectGrant:
    workflow_id: str
    episode_id: str
    template_id: str
    tool: str
    exact_args: str
    agent_id: str
    redeemer_id: str
    route: object = field(repr=False)
    credential: object = field(repr=False)
    capability: object = field(repr=False)

    def __post_init__(self) -> None:
        for name, value in (
            ("workflow_id", self.workflow_id),
            ("episode_id", self.episode_id),
            ("template_id", self.template_id),
            ("tool", self.tool),
            ("agent_id", self.agent_id),
            ("redeemer_id", self.redeemer_id),
        ):
            _identifier(name, value)
        if type(self.exact_args) is not str or not self.exact_args:
            raise AgentDojoHarnessError("grant exact args must be canonical text")

    def replace(self, **changes: Any) -> "SecureEffectGrant":
        return replace(self, **changes)

    def payload(self) -> dict[str, str]:
        return {
            "schema_version": GRANT_PAYLOAD_SCHEMA,
            "workflow_id": self.workflow_id,
            "episode_id": self.episode_id,
            "template_id": self.template_id,
            "tool": self.tool,
            "exact_args": self.exact_args,
            "agent_id": self.agent_id,
            "redeemer_id": self.redeemer_id,
        }


def issue_durable_effect_grants(
    domain: object,
    manifest: PolicyManifest,
    *,
    route_by_tool: Mapping[str, object],
    agent_id: str,
    signing_key: bytes,
    redeemer_id: str,
) -> tuple[SecureEffectGrant, ...]:
    """Issue one v2 credential/capability pair for every exact effect.

    The implementation deliberately inspects the durable API at call time so
    importing the evaluation package never creates or opens trusted state.

    ``route_by_tool`` is an effect-route registry.  A key may be either a
    template id or a tool name, and a template-id key WINS.  A registry
    keyed only by tool -- the original spelling -- necessarily shares one
    durable route between every authorised effect on that tool, so the
    durable transcript cannot name which exact effect was released.  Keying
    by template id gives every exact effect its own gate.  Both spellings
    are accepted so no existing caller changes.
    """

    # Durable domains intentionally use the v2 credential wire contract;
    # importing the in-memory v1 credential would erase context/epoch/expiry.
    from ..durable_secure import AttemptCredential

    if type(manifest) is not PolicyManifest or manifest.decision is not PolicyDecision.COMPILED:
        raise AgentDojoHarnessError("durable grants require a compiled manifest")
    if not isinstance(route_by_tool, Mapping):
        raise TypeError("route_by_tool must be a mapping")
    _identifier("agent_id", agent_id)
    _identifier("redeemer_id", redeemer_id)
    if type(signing_key) is not bytes or len(signing_key) < 16:
        raise AgentDojoHarnessError("signing key must contain at least 128 bits")
    context = getattr(domain, "credential_context", None)
    epoch = getattr(domain, "current_epoch", None)
    attempts_used = getattr(domain, "attempts_used", None)
    horizon = getattr(domain, "attempt_horizon", None)
    if type(context) is not str or type(epoch) is not int:
        raise AgentDojoHarnessError("durable domain does not expose v2 credential context")
    if type(attempts_used) is not int or type(horizon) is not int:
        raise AgentDojoHarnessError("durable domain does not expose attempt bounds")
    remaining = horizon - attempts_used
    if remaining < len(manifest.templates):
        raise AgentDojoHarnessError("durable domain horizon cannot fund all effect grants")
    grants: list[SecureEffectGrant] = []
    for offset, template in enumerate(manifest.templates, 1):
        if template.template_id in route_by_tool:
            route = route_by_tool[template.template_id]
        elif template.tool in route_by_tool:
            route = route_by_tool[template.tool]
        else:
            raise AgentDojoHarnessError("effect route registry is incomplete")
        provisional = SecureEffectGrant(
            workflow_id=manifest.workflow_id,
            episode_id=manifest.episode_id,
            template_id=template.template_id,
            tool=template.tool,
            exact_args=template.exact_args,
            agent_id=agent_id,
            redeemer_id=redeemer_id,
            route=route,
            credential=object(),
            capability=object(),
        )
        payload = provisional.payload()
        expiry = attempts_used + remaining
        capability = domain.issue_capability(
            route,
            payload=payload,
            redeemer_id=redeemer_id,
            expires_at_lifetime_attempt=expiry,
        )
        credential = AttemptCredential.sign(
            agent_id=agent_id,
            signing_key=signing_key,
            domain_context=context,
            expected_epoch=epoch,
            route=route,
            payload=payload,
            nonce=f"agentdojo-{offset}-{secrets.token_urlsafe(24)}",
            expires_at_lifetime_attempt=expiry,
        )
        grants.append(
            replace(provisional, credential=credential, capability=capability)
        )
    return tuple(grants)


@dataclass(frozen=True, slots=True)
class BrokerAuditRecord:
    sequence: int
    workflow_id: str
    episode_id: str
    call_id_sha256: str
    tool_sha256: str
    tool_kind: ToolKind | None
    args_sha256: str
    template_id: str | None
    outcome: BrokerOutcome
    authorized: bool
    executed: bool
    consumed_effect_count: int
    unused_effect_count: int


@dataclass(frozen=True, slots=True)
class BrokerResult:
    outcome: BrokerOutcome
    value: Any
    environment: Any


def _safe_args_digest(args: Mapping[str, Any]) -> str:
    try:
        return _digest(canonical_args(args).encode("utf-8"))
    except BaseException:
        # This value reveals neither invalid argument contents nor an exception.
        return _digest(b"sluice-agentdojo-invalid-arguments-v1")


def _audit_identifier_digest(domain: bytes, value: object) -> str:
    if type(value) is not str:
        return _digest(domain + b"\x00invalid")
    return _digest(domain + b"\x00" + value.encode("utf-8", errors="surrogatepass"))


def _contains_nested_request(value: Any, *, _seen: dict[int, Any] | None = None) -> bool:
    if type(value) is ToolRequest:
        return True
    if _seen is None:
        # A set of bare ids lets the address of a freed model_dump
        # temporary be reused and misread as a cycle; owning the objects
        # keeps every recorded address valid for the whole walk.
        _seen = {}
    identity = id(value)
    if identity in _seen:
        return True
    if isinstance(value, Mapping):
        _seen[identity] = value
        if not all(type(key) is str for key in value):
            return True
        keys = set(value)
        if {"function", "args"}.issubset(keys) or {
            "name",
            "arguments",
        }.issubset(keys):
            return True
        return any(_contains_nested_request(item, _seen=_seen) for item in value.values())
    if type(value) in (list, tuple):
        _seen[identity] = value
        return any(_contains_nested_request(item, _seen=_seen) for item in value)
    # AgentDojo FunctionCall is a Pydantic object with these static fields.
    if type(value) not in (str, int, float, bool, type(None)):
        _seen[identity] = value
        cls = type(value)
        instance_fields = getattr(value, "__dict__", None)
        if isinstance(instance_fields, Mapping) and {
            "function",
            "args",
        }.issubset(instance_fields):
            return True
        if inspect.getattr_static(cls, "function", _MISSING) is not _MISSING and inspect.getattr_static(
            cls, "args", _MISSING
        ) is not _MISSING:
            return True
        # Official tool results can be Pydantic models.  Convert them to their
        # JSON representation and recurse so a FunctionCall hidden inside an
        # otherwise innocuous result model cannot escape mediation.
        model_dump = inspect.getattr_static(cls, "model_dump", _MISSING)
        if model_dump is not _MISSING:
            dump = getattr(value, "model_dump", None)
            if not callable(dump):
                return True
            return _contains_nested_request(
                dump(mode="json", round_trip=True), _seen=_seen
            )
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return _contains_nested_request(dataclasses.asdict(value), _seen=_seen)
        if isinstance(instance_fields, Mapping):
            return any(
                _contains_nested_request(item, _seen=_seen)
                for item in instance_fields.values()
            )
        # An opaque object cannot be proven free of a latent call.
        return True
    return False


def _environment_wire(environment: Any) -> Any:
    if hasattr(environment, "model_dump") and callable(environment.model_dump):
        return environment.model_dump(mode="json", round_trip=True)
    if dataclasses.is_dataclass(environment) and not isinstance(environment, type):
        return dataclasses.asdict(environment)
    return environment


def _environment_digest(environment: Any) -> str:
    return _json_wire_digest(_environment_wire(environment))


def _runtime_schemas(runtime: object) -> tuple[StaticToolSchema, ...]:
    functions = getattr(runtime, "functions", None)
    if not isinstance(functions, Mapping):
        raise AgentDojoHarnessError("runtime functions registry is malformed")
    schemas: list[StaticToolSchema] = []
    for key in sorted(functions):
        if type(key) is not str:
            raise AgentDojoHarnessError("runtime tool name must be a string")
        function = functions[key]
        if getattr(function, "name", None) != key:
            raise AgentDojoHarnessError("runtime registry key/name mismatch")
        parameters = getattr(function, "parameters_schema", None)
        if parameters is None:
            model = getattr(function, "parameters", None)
            if model is None or not hasattr(model, "model_json_schema"):
                raise AgentDojoHarnessError("runtime tool schema is unavailable")
            parameters = model.model_json_schema()
        schemas.append(StaticToolSchema(key, parameters))
    return tuple(schemas)


class NonOracleToolBroker:
    """Fail-closed broker for the complete AgentDojo runtime registry."""

    def __init__(
        self,
        *,
        manifest: PolicyManifest,
        registry: ToolRegistry,
        tool_schemas: tuple[StaticToolSchema, ...],
        runtime: object,
        grants: tuple[SecureEffectGrant, ...],
        authorizer: object,
    ) -> None:
        if type(manifest) is not PolicyManifest:
            raise TypeError("manifest must be a PolicyManifest")
        if manifest.decision is not PolicyDecision.COMPILED:
            raise AgentDojoHarnessError("an abstained policy cannot start a broker")
        if type(registry) is not ToolRegistry:
            raise TypeError("registry must be a ToolRegistry")
        if manifest.suite_name != registry.suite_name:
            raise AgentDojoHarnessError("manifest and registry suites differ")
        if type(tool_schemas) is not tuple or any(
            type(item) is not StaticToolSchema for item in tool_schemas
        ):
            raise TypeError("tool_schemas must be a StaticToolSchema tuple")
        expected = {schema.name: schema for schema in tool_schemas}
        if set(expected) != set(registry.declared):
            raise AgentDojoHarnessError("tool schemas and registry differ")
        if _json_wire_digest([schema.wire() for schema in tool_schemas]) != manifest.tool_schema_sha256:
            raise AgentDojoHarnessError("manifest/tool schema digest mismatch")
        if type(grants) is not tuple or any(
            type(grant) is not SecureEffectGrant for grant in grants
        ):
            raise TypeError("grants must be a SecureEffectGrant tuple")
        templates = {template.template_id: template for template in manifest.templates}
        grant_map = {grant.template_id: grant for grant in grants}
        if len(grant_map) != len(grants) or set(grant_map) != set(templates):
            raise AgentDojoHarnessError("grant/template mismatch")
        for template_id, template in templates.items():
            grant = grant_map[template_id]
            if (
                grant.workflow_id != manifest.workflow_id
                or grant.episode_id != manifest.episode_id
                or grant.tool != template.tool
                or grant.exact_args != template.exact_args
            ):
                raise AgentDojoHarnessError("grant binding does not match the manifest")
        self._manifest = manifest
        self._registry = registry
        self._tool_schemas = tuple(tool_schemas)
        self._schema_by_name = expected
        self._runtime = runtime
        self._authorizer = authorizer
        self._grants = grant_map
        self._unused = set(grant_map)
        self._consumed: set[str] = set()
        self._audit: list[BrokerAuditRecord] = []
        self._audit_lock = threading.Lock()
        self._execution_lock = threading.Lock()
        self._local = threading.local()
        self._validate_runtime_registry()

    @property
    def audit_log(self) -> tuple[BrokerAuditRecord, ...]:
        with self._audit_lock:
            return tuple(self._audit)

    @property
    def unused_effect_count(self) -> int:
        return len(self._unused)

    @property
    def consumed_effect_count(self) -> int:
        return len(self._consumed)

    def _validate_runtime_registry(self) -> None:
        actual = _runtime_schemas(self._runtime)
        actual_names = frozenset(schema.name for schema in actual)
        if actual_names != self._registry.declared:
            raise AgentDojoHarnessError("runtime registry mismatch")
        if [schema.wire() for schema in actual] != [
            schema.wire() for schema in sorted(self._tool_schemas, key=lambda item: item.name)
        ]:
            raise AgentDojoHarnessError("runtime schema registry mismatch")

    def _append_audit(
        self,
        request: ToolRequest,
        *,
        args_sha256: str,
        kind: ToolKind | None,
        template_id: str | None,
        outcome: BrokerOutcome,
        authorized: bool,
        executed: bool,
    ) -> None:
        with self._audit_lock:
            self._audit.append(
                BrokerAuditRecord(
                    sequence=len(self._audit) + 1,
                    workflow_id=self._manifest.workflow_id,
                    episode_id=self._manifest.episode_id,
                    call_id_sha256=_audit_identifier_digest(
                        b"sluice-agentdojo-call-id-v1", request.call_id
                    ),
                    tool_sha256=_audit_identifier_digest(
                        b"sluice-agentdojo-tool-v1", request.function
                    ),
                    tool_kind=kind,
                    args_sha256=args_sha256,
                    template_id=template_id,
                    outcome=outcome,
                    authorized=authorized,
                    executed=executed,
                    consumed_effect_count=len(self._consumed),
                    unused_effect_count=len(self._unused),
                )
            )

    def _result(
        self,
        request: ToolRequest,
        environment: Any,
        *,
        args_sha256: str,
        outcome: BrokerOutcome,
        kind: ToolKind | None,
        template_id: str | None = None,
        authorized: bool = False,
        executed: bool = False,
        value: Any = None,
    ) -> BrokerResult:
        self._append_audit(
            request,
            args_sha256=args_sha256,
            kind=kind,
            template_id=template_id,
            outcome=outcome,
            authorized=authorized,
            executed=executed,
        )
        return BrokerResult(outcome=outcome, value=value, environment=environment)

    def _redeem(self, grant: SecureEffectGrant) -> AuthorizationOutcome:
        payload = grant.payload()
        try:
            redeem = getattr(self._authorizer, "redeem", None)
            if callable(redeem):
                outcome = redeem(grant, payload)
                if type(outcome) is not AuthorizationOutcome:
                    return AuthorizationOutcome.ERROR
                return outcome
            attempt = getattr(self._authorizer, "attempt", None)
            if not callable(attempt):
                return AuthorizationOutcome.ERROR
            event = attempt(
                grant.route,
                payload,
                credential=grant.credential,
                capability=grant.capability,
                redeemer_id=grant.redeemer_id,
            )
            raw_outcome = getattr(getattr(event, "outcome", None), "value", None)
            return (
                AuthorizationOutcome.RELEASED
                if raw_outcome == "released"
                else AuthorizationOutcome.DENIED
            )
        except BaseException:
            return AuthorizationOutcome.ERROR

    def _run_runtime(
        self, working: Any, function: str, args: Mapping[str, Any]
    ) -> tuple[bool, Any]:
        """Return a finite opaque success bit/value for every backend behavior."""

        try:
            response = self._runtime.run_function(
                working, function, args, raise_on_error=False
            )
        except BaseException:
            return False, None
        if type(response) is not tuple or len(response) != 2:
            return False, None
        value, error = response
        if error is not None:
            return False, None
        return True, value

    def execute(self, request: ToolRequest, environment: Any) -> BrokerResult:
        if type(request) is not ToolRequest:
            raise TypeError("request must be a ToolRequest")
        try:
            request_args = {
                key: copy.deepcopy(value) for key, value in request.args.items()
            }
            args_sha256 = _safe_args_digest(request_args)
        except BaseException:
            request_args = None
            args_sha256 = _digest(b"sluice-agentdojo-invalid-arguments-v1")
        if getattr(self._local, "active", False):
            return self._result(
                request,
                environment,
                args_sha256=args_sha256,
                outcome=BrokerOutcome.REENTRANT_CALL_DENIED,
                kind=None,
            )
        self._local.active = True
        try:
            with self._execution_lock:
                try:
                    self._validate_runtime_registry()
                except BaseException:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.REGISTRY_MISMATCH,
                        kind=None,
                    )
                if request.function not in self._registry.declared:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.UNKNOWN_TOOL,
                        kind=None,
                    )
                kind = self._registry.classify(request.function)
                try:
                    nested_input = request_args is None or _contains_nested_request(
                        request_args
                    )
                except BaseException:
                    nested_input = True
                if nested_input:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.NESTED_CALL_DENIED,
                        kind=kind,
                    )
                try:
                    assert request_args is not None
                    thawed_args = request_args
                    exact = canonical_args(thawed_args)
                except BaseException:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.ARGUMENT_SCHEMA_DENIED,
                        kind=kind,
                    )
                if not _arguments_match_schema(
                    thawed_args, self._schema_by_name[request.function]
                ):
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.ARGUMENT_SCHEMA_DENIED,
                        kind=kind,
                    )
                try:
                    before = _environment_digest(environment)
                    working = copy.deepcopy(environment)
                    if _environment_digest(working) != before:
                        raise AgentDojoHarnessError("copy changed environment")
                except BaseException:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.STATE_COPY_DENIED,
                        kind=kind,
                    )

                if kind is ToolKind.READ_ONLY:
                    succeeded, value = self._run_runtime(
                        working, request.function, thawed_args
                    )
                    if not succeeded:
                        return self._result(
                            request,
                            environment,
                            args_sha256=args_sha256,
                            outcome=BrokerOutcome.TOOL_ERROR,
                            kind=kind,
                            executed=True,
                        )
                    try:
                        nested_output = _contains_nested_request(value)
                    except BaseException:
                        nested_output = True
                    if nested_output:
                        return self._result(
                            request,
                            environment,
                            args_sha256=args_sha256,
                            outcome=BrokerOutcome.NESTED_CALL_DENIED,
                            kind=kind,
                            executed=True,
                        )
                    try:
                        after = _environment_digest(working)
                    except BaseException:
                        after = ""
                    if after != before:
                        return self._result(
                            request,
                            environment,
                            args_sha256=args_sha256,
                            outcome=BrokerOutcome.READ_ONLY_MUTATION,
                            kind=kind,
                            executed=True,
                        )
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.EXECUTED_READ_ONLY,
                        kind=kind,
                        executed=True,
                        value=value,
                    )

                template_id = next(
                    (
                        candidate
                        for candidate in sorted(self._unused)
                        if self._grants[candidate].tool == request.function
                        and self._grants[candidate].exact_args == exact
                    ),
                    None,
                )
                if template_id is None:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.NO_AUTHORIZED_TEMPLATE,
                        kind=kind,
                    )
                grant = self._grants[template_id]
                # Retirement precedes the first possibly ambiguous external
                # redemption step.  A denial, malformed reply, exception, or
                # BaseException can never make this local authority reusable.
                self._unused.remove(template_id)
                self._consumed.add(template_id)
                authorization = self._redeem(grant)
                if authorization is AuthorizationOutcome.ERROR:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.AUTHORIZER_ERROR,
                        kind=kind,
                        template_id=template_id,
                    )
                if authorization is not AuthorizationOutcome.RELEASED:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.AUTHORIZATION_DENIED,
                        kind=kind,
                        template_id=template_id,
                    )
                succeeded, value = self._run_runtime(
                    working, request.function, thawed_args
                )
                if not succeeded:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.TOOL_ERROR,
                        kind=kind,
                        template_id=template_id,
                        authorized=True,
                        executed=True,
                    )
                try:
                    nested_output = _contains_nested_request(value)
                except BaseException:
                    nested_output = True
                if nested_output:
                    return self._result(
                        request,
                        environment,
                        args_sha256=args_sha256,
                        outcome=BrokerOutcome.NESTED_CALL_DENIED,
                        kind=kind,
                        template_id=template_id,
                        authorized=True,
                        executed=True,
                    )
                return self._result(
                    request,
                    working,
                    args_sha256=args_sha256,
                    outcome=BrokerOutcome.EXECUTED_EFFECT,
                    kind=kind,
                    template_id=template_id,
                    authorized=True,
                    executed=True,
                    value=value,
                )
        finally:
            self._local.active = False


def audit_primary_source_for_oracle_access(path: str | Path) -> tuple[str, ...]:
    """Return obvious hidden-answer references in one source file.

    This AST lint is defense in depth, not a proof of non-oracle execution.
    The primary structural boundary is that the compiler accepts an exact,
    frozen ``PolicyInput`` DTO containing no task/scorer object and must run in
    the policy process, outside the post-episode scoring process.
    """

    source = Path(path)
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    forbidden = frozenset(
        {"".join(("ground", "_truth")), "".join(("GROUND", "_TRUTH_OUTPUT"))}
    )
    findings: list[str] = []

    def folded_string(node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = folded_string(node.left)
            right = folded_string(node.right)
            if left is not None and right is not None:
                return left + right
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for value in node.values:
                part = folded_string(value)
                if part is None:
                    return None
                parts.append(part)
            return "".join(parts)
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in forbidden:
            findings.append(f"attribute:{node.attr}:line:{node.lineno}")
        elif isinstance(node, ast.Name) and node.id in forbidden:
            findings.append(f"name:{node.id}:line:{node.lineno}")
        elif isinstance(node, (ast.Constant, ast.BinOp, ast.JoinedStr)):
            value = folded_string(node)
            if value in forbidden:
                findings.append(f"string:{value}:line:{node.lineno}")
    return tuple(sorted(findings))


__all__ = [
    "AGENTDOJO_COMMIT",
    "AGENTDOJO_TREE",
    "AGENTDOJO_VERSION",
    "BENCHMARK_VERSION",
    "MAX_POLICY_TEMPLATES",
    "AbstentionCategory",
    "AgentDojoHarnessError",
    "ArgumentBinding",
    "AuthorizationOutcome",
    "BrokerAuditRecord",
    "BrokerOutcome",
    "BrokerResult",
    "CallTemplate",
    "CallTemplateSpec",
    "EvaluationSplit",
    "NonOracleToolBroker",
    "OrganizationPolicy",
    "PolicyDecision",
    "PolicyInput",
    "PolicyManifest",
    "PolicyRule",
    "PinnedSourceSummary",
    "ScheduledRun",
    "SecureEffectGrant",
    "SplitManifest",
    "StaticToolSchema",
    "ToolKind",
    "ToolRegistry",
    "ToolRequest",
    "V122ValidationSummary",
    "V122_TOOL_REGISTRIES",
    "audit_primary_source_for_oracle_access",
    "canonical_args",
    "compile_static_policy",
    "generate_counterbalanced_schedule",
    "issue_durable_effect_grants",
    "static_tool_schemas_from_suite",
    "validate_pinned_checkout",
    "validate_v122_suites",
]
