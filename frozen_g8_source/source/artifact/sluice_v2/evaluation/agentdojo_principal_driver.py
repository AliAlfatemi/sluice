"""Data-only AgentDojo principal execution foundation.

The execution side consumes an authenticated immutable projection. It has no
official suite objects and cannot evaluate benchmark answers. The only
endpoint facility in this CPU foundation is an explicitly ineligible fake
probe used to test per-entry binding and evidence plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import threading
from types import MappingProxyType
from typing import Callable, Iterable, Mapping
import weakref

from ..durable_service import PeerIdentity
from .agentdojo_live import (
    EndpointAttestation,
    EndpointExpectation,
    EndpointObservation,
)


class PrincipalDriverError(ValueError):
    """A principal plan, prerequisite, or evidence operation failed closed."""


class PrincipalCondition(str, Enum):
    UNDEFENDED = "undefended"
    OFFICIAL_TOOL_FILTER = "official_tool_filter"
    SLUICE_NONORACLE = "sluice_nonoracle"


class PrincipalComparison(str, Enum):
    OFFICIAL_TOOL_FILTER_VS_UNDEFENDED = "official_tool_filter_vs_undefended"
    SLUICE_NONORACLE_VS_UNDEFENDED = "sluice_nonoracle_vs_undefended"


class EndpointProbeMode(str, Enum):
    CPU_FAKE = "cpu_fake"
    LIVE_VERIFIED = "live_verified"


class TerminationCategory(str, Enum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ENDPOINT_ERROR = "endpoint_error"
    MODEL_ERROR = "model_error"
    BROKER_ERROR = "broker_error"
    ISOLATION_ERROR = "isolation_error"
    HARNESS_ERROR = "harness_error"


PRINCIPAL_SEEDS = (104729, 130363, 155921, 196613, 262147)
PRINCIPAL_REPETITIONS_PER_SEED = 1
PINNED_PRINCIPAL_PLAN_SHA256 = (
    "49ccb6836e59471541746b5467afa55242d0ae053f29f4587bdda12e694e4200"
)

_PLAN_SCHEMA = "sluice-agentdojo-principal-plan-v1"
_SPLIT_SCHEMA = "sluice-agentdojo-policy-author-split-v1"
_UNIVERSE_SCHEMA = "sluice-agentdojo-principal-universe-v1"
_INSTANCE_SCHEMA = "sluice-agentdojo-principal-schedule-instance-v1"
_SCHEDULE_SCHEMA = "sluice-agentdojo-principal-schedule-v1"
_COUNTERBALANCE_SCHEMA = "sluice-agentdojo-counterbalanced-schedule-v1"
_BASELINE_SCHEMA = "sluice-agentdojo-official-tool-filter-v1"
_SPLIT_SEED = "sluice-agentdojo-policy-author-split-v1:8675309"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
_PRINCIPAL_PLAN_TOKEN = object()
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))
_LOADED_PRINCIPAL_PLANS: weakref.WeakValueDictionary[int, object] = (
    weakref.WeakValueDictionary()
)
_LOADED_PRINCIPAL_PLANS_LOCK = threading.RLock()

_SUITE_TASK_COUNTS: Mapping[str, tuple[int, int, int]] = MappingProxyType(
    {
        "banking": (16, 9, 0),
        "slack": (21, 5, 1),
        "travel": (20, 7, 0),
        "workspace": (40, 14, 0),
    }
)
_SUITE_PAIR_COUNTS: Mapping[str, int] = MappingProxyType(
    {"banking": 144, "slack": 105, "travel": 140, "workspace": 560}
)
_COMPARISONS: tuple[tuple[str, tuple[str, str]], ...] = (
    (
        PrincipalComparison.OFFICIAL_TOOL_FILTER_VS_UNDEFENDED.value,
        (
            PrincipalCondition.UNDEFENDED.value,
            PrincipalCondition.OFFICIAL_TOOL_FILTER.value,
        ),
    ),
    (
        PrincipalComparison.SLUICE_NONORACLE_VS_UNDEFENDED.value,
        (
            PrincipalCondition.UNDEFENDED.value,
            PrincipalCondition.SLUICE_NONORACLE.value,
        ),
    ),
)

_EXPECTED_SOURCE = {
    "schema_version": "sluice-agentdojo-official-source-v1",
    "version": "0.1.35",
    "commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
    "git_tree": "3c74b60f2bad4ff321d864e0c0483f256cc8f8d2",
    "python_file_count": 99,
    "python_tree_sha256": (
        "1d277192874c252ca21ece753b4ab10217958a1f41511b1f7175e919d9c01114"
    ),
    "loaded_asset_file_count": 112,
    "loaded_asset_tree_sha256": (
        "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
    ),
    "key_file_sha256": {
        "LICENSE": "4285a071f2d382338e52b4fb0a186d952984a34d43a33d8872e1a1d8cb43401e",
        "pyproject.toml": (
            "f69dde819258d5dc2c6dca13ecbb116e54904374879a5c921332db36474e0a3b"
        ),
        "uv.lock": "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330",
    },
}
_EXPECTED_REGISTRY = {
    "schema_version": "sluice-agentdojo-live-registry-v2",
    "source_assets_sha256": _EXPECTED_SOURCE["loaded_asset_tree_sha256"],
    "runtime_tool_count": 74,
    "suite_tool_counts": {
        "banking": 11,
        "slack": 11,
        "travel": 28,
        "workspace": 24,
    },
    "suite_tool_schema_sha256": {
        "banking": "f23fef04916f69a3e5ef875c66ceff729ecd685f4b790a5d8629401cf93be355",
        "slack": "d68133a16a3b80e2b53fb9db700f2ea57629e0683920a59cda24ec92de9275c4",
        "travel": "42291163f6f975cf674328c3697c19296843ac5e1f2130c3e2e2da93e88ead8a",
        "workspace": "b285f9ef2aa59b507e5c69768e98063ca0648cf8511ec7e7c0a9a2ccc48acda1",
    },
    "suite_object_sha256": (
        "49d55fd0bc01db8e2809f6f74a909bb3c90a99fea418ba6093f61fa64c499ea4"
    ),
    # Derived from V122_TOOL_REGISTRIES.  It changed when
    # slack.get_webpage was reclassified effectful (correction C2): the
    # pinned upstream implementation appends to web.web_requests.  The tool
    # NAME set, the per-suite counts and the four tool-SCHEMA digests above
    # are unchanged; only the read-only/effectful partition moved.
    "registry_sha256": (
        "dd4ee671601464f4d9825029378cc53a8d7a4de480f4ae0406747c9f26c1c993"
    ),
    "official_suite_objects_verified": True,
}
_EXPECTED_BASELINE = {
    "schema_version": _BASELINE_SCHEMA,
    "condition": PrincipalCondition.OFFICIAL_TOOL_FILTER.value,
    "config_value": "tool_filter",
    "pipeline_source_relative": "src/agentdojo/agent_pipeline/agent_pipeline.py",
    "pipeline_source_sha256": (
        "2b9b82b98cef3662733a8207dfed9e4386c41fb74e69531a6f0a36207f9695e9"
    ),
    "llm_source_relative": "src/agentdojo/agent_pipeline/llms/openai_llm.py",
    "llm_source_sha256": (
        "7f91178cb0bb354b89427650d7b8725d6aff8fe18d43fc85bf4b4fdc1ddf9574"
    ),
    "pipeline_element_qualname": (
        "agentdojo.agent_pipeline.llms.openai_llm.OpenAILLMToolFilter"
    ),
    "requires_official_openai_adapter": True,
}


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PrincipalDriverError("principal value is outside canonical JSON") from exc


def _validate_exact_json_domain(value: object, *, depth: int = 0) -> None:
    """Reject Python aliases that canonical JSON would silently normalize."""

    if depth > 64:
        raise PrincipalDriverError("principal JSON value exceeds its nesting bound")
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise PrincipalDriverError("principal JSON object keys must be exact text")
        for item in value.values():
            _validate_exact_json_domain(item, depth=depth + 1)
        return
    if type(value) is list:
        for item in value:
            _validate_exact_json_domain(item, depth=depth + 1)
        return
    if value is None or type(value) in (bool, int, str):
        return
    raise PrincipalDriverError("principal JSON uses a non-exact primitive or container")


def _digest_bytes(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + b"\0" + value).hexdigest()


def _digest_text(domain: bytes, value: str) -> str:
    return _digest_bytes(domain, value.encode("utf-8", errors="surrogatepass"))


def principal_plan_sha256(wire: object) -> str:
    """Digest one mapping while excluding only its own digest field."""

    if type(wire) is not dict:
        raise PrincipalDriverError("principal digest input must be an exact object")
    body = {key: value for key, value in wire.items() if key != "sha256"}
    return _digest_bytes(b"sluice-agentdojo-principal-wire-v1", _canonical_json(body))


def _sha256(name: str, value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise PrincipalDriverError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _revision(name: str, value: object) -> str:
    if type(value) is not str or _REVISION_RE.fullmatch(value) is None:
        raise PrincipalDriverError(f"{name} must be an exact lowercase 40-hex revision")
    return value


def _text(name: str, value: object, *, maximum: int = 2048) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise PrincipalDriverError(f"{name} must be a bounded nonempty string")
    return value


def _integer(name: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PrincipalDriverError(f"{name} must be an integer at least {minimum}")
    return value


def _validate_model_identity(
    model_id: object,
    model_revision: object,
    model_artifact_sha256: object,
    backend: object,
    backend_version: object,
    *,
    name: str,
) -> tuple[str, str, str, str, str]:
    identity = (
        _text(f"{name} model ID", model_id),
        _revision(f"{name} model revision", model_revision),
        _sha256(f"{name} model artifact digest", model_artifact_sha256),
        _text(f"{name} backend", backend),
        _text(f"{name} backend version", backend_version),
    )
    if identity[3] != "vllm":
        raise PrincipalDriverError(f"{name} backend must be the exact vllm adapter")
    return identity


def _manifest_model_identity(manifest: object) -> tuple[str, str, str, str, str]:
    return _validate_model_identity(
        getattr(manifest, "model_id", None),
        getattr(manifest, "model_revision", None),
        getattr(manifest, "model_artifact_sha256", None),
        getattr(manifest, "backend", None),
        getattr(manifest, "backend_version", None),
        name="dependency manifest",
    )


def _endpoint_model_identity(endpoint: object) -> tuple[str, str, str, str, str]:
    return _validate_model_identity(
        getattr(endpoint, "model_id", None),
        getattr(endpoint, "model_revision", None),
        getattr(endpoint, "model_artifact_sha256", None),
        getattr(endpoint, "backend", None),
        getattr(endpoint, "backend_version", None),
        name="endpoint attestation",
    )


def _exact_object(
    name: str, value: object, fields: frozenset[str]
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != fields:
        raise PrincipalDriverError(f"{name} has missing or unexpected fields")
    return value


def _verify_own_digest(name: str, wire: dict[str, object]) -> None:
    digest = _sha256(f"{name} digest", wire.get("sha256"))
    if digest != principal_plan_sha256(wire):
        raise PrincipalDriverError(f"{name} digest mismatch")


def _expected_split_ids() -> tuple[tuple[str, ...], tuple[str, ...]]:
    development: list[str] = []
    heldout: list[str] = []
    for suite_name in sorted(_SUITE_TASK_COUNTS):
        user_count = _SUITE_TASK_COUNTS[suite_name][0]
        task_ids = [f"{suite_name}:user_task_{index}" for index in range(user_count)]
        ordered = sorted(
            task_ids,
            key=lambda task_id: _digest_text(
                b"sluice-agentdojo-policy-author-split-order-v1",
                f"{_SPLIT_SEED}\0{task_id}",
            ),
        )
        development_count = user_count // 4
        development.extend(ordered[:development_count])
        heldout.extend(ordered[development_count:])
    return tuple(sorted(development)), tuple(sorted(heldout))


def _scenario_id(
    stratum: str,
    suite_name: str,
    user_task_id: str,
    injection_task_id: str | None,
) -> str:
    coordinate = (
        f"{stratum}\0{suite_name}\0{user_task_id}\0"
        f"{'' if injection_task_id is None else injection_task_id}"
    )
    return _digest_text(b"sluice-agentdojo-principal-scenario-v1", coordinate)


def _episode_id(
    stratum: str,
    suite_name: str,
    user_task_id: str,
    injection_task_id: str | None,
) -> str:
    suffix = "none" if injection_task_id is None else injection_task_id
    return f"{stratum}:{suite_name}:{user_task_id}:{suffix}"


def _pair_id(suite_name: str, user_task_id: str, injection_task_id: str) -> str:
    return _digest_text(
        b"sluice-agentdojo-pair-id-v1",
        f"{suite_name}\0{user_task_id}\0{injection_task_id}",
    )


@dataclass(frozen=True, slots=True)
class PolicyAuthorSplit:
    development_task_ids: tuple[str, ...]
    heldout_task_ids: tuple[str, ...]
    selection_seed: str
    sha256: str


@dataclass(frozen=True, slots=True)
class PrincipalScenario:
    scenario_id: str
    episode_id: str
    stratum: str
    suite_name: str
    user_task_id: str
    injection_task_id: str | None
    pair_id: str | None
    policy_partition: str
    principal_scoring_eligible: bool


@dataclass(frozen=True, slots=True)
class OfficialToolFilterBaseline:
    condition: str
    config_value: str
    pipeline_source_sha256: str
    llm_source_sha256: str
    pipeline_element_qualname: str
    requires_official_openai_adapter: bool
    sha256: str


@dataclass(frozen=True, slots=True)
class PrincipalScheduleEntry:
    entry_id: str
    instance_id: str
    comparison_id: str
    generation_seed: int
    repetition: int
    block: int
    order: int
    scenario_id: str
    episode_id: str
    stratum: str
    suite_name: str
    user_task_id: str
    injection_task_id: str | None
    pair_id: str | None
    policy_partition: str
    principal_scoring_eligible: bool
    condition: str


@dataclass(frozen=True, slots=True)
class PrincipalScheduleInstance:
    instance_id: str
    comparison_id: str
    conditions: tuple[str, str]
    generation_seed: int
    repetition: int
    entries: tuple[PrincipalScheduleEntry, ...]
    sha256: str


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PrincipalExecutionPlan:
    sha256: str
    conditions: tuple[str, ...]
    seeds: tuple[int, ...]
    repetitions_per_seed: int
    policy_author_split: PolicyAuthorSplit
    official_tool_filter: OfficialToolFilterBaseline
    attacked_pair_count: int
    benign_task_count: int
    suite_pair_counts: Mapping[str, int]
    suite_task_counts: Mapping[str, tuple[int, int]]
    scenarios: tuple[PrincipalScenario, ...]
    schedule_instances: tuple[PrincipalScheduleInstance, ...]
    entries: tuple[PrincipalScheduleEntry, ...]
    source_sha256: str
    registry_sha256: str
    principal_outcomes_present: bool
    _entry_index: Mapping[str, PrincipalScheduleEntry] = field(
        repr=False, compare=False
    )
    _validation_sha256: str = field(default="", repr=False, compare=False)
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Direct construction remains data-compatible for fail-closed callers,
        # but only the strict loader receives provenance.  This distinction lets
        # ScheduleBinding reject an exact-class object carrying copied digest
        # fields without treating Python's dataclass constructor as an
        # authentication boundary.
        if self._token is not _PRINCIPAL_PLAN_TOKEN:
            return
        observed = _principal_plan_state_sha256(self)
        if self._validation_sha256:
            _sha256("principal plan validation digest", self._validation_sha256)
            if self._validation_sha256 != observed:
                raise PrincipalDriverError("principal plan state changed during loading")
        else:
            object.__setattr__(self, "_validation_sha256", observed)

    def validate_provenance(self) -> None:
        """Authenticate the strict-loader capability and pinned plan identity."""
        if type(self) is not PrincipalExecutionPlan:
            raise PrincipalDriverError("principal plan subclasses are forbidden")
        if self._token is not _PRINCIPAL_PLAN_TOKEN:
            raise PrincipalDriverError("principal plan was not strict-loader minted")
        with _LOADED_PRINCIPAL_PLANS_LOCK:
            if _LOADED_PRINCIPAL_PLANS.get(id(self)) is not self:
                raise PrincipalDriverError(
                    "principal plan object is absent from the strict-loader registry"
                )
        if self.sha256 != PINNED_PRINCIPAL_PLAN_SHA256:
            raise PrincipalDriverError("principal plan is not the pinned committed plan")
        _sha256(
            "principal plan validation digest", self._validation_sha256
        )

    def revalidate(self) -> None:
        """Deeply authenticate the exact loader-minted immutable plan state."""

        self.validate_provenance()
        expected = self._validation_sha256
        if _principal_plan_state_sha256(self) != expected:
            raise PrincipalDriverError("principal plan immutable state drifted")

    @classmethod
    def load(
        cls, wire: object, *, expected_sha256: str
    ) -> "PrincipalExecutionPlan":
        return _load_principal_plan(wire, expected_sha256=expected_sha256)

    def entry(self, entry_id: str) -> PrincipalScheduleEntry:
        try:
            return self._entry_index[entry_id]
        except KeyError as exc:
            raise PrincipalDriverError("entry is absent from the principal plan") from exc

    @property
    def policy_author_split_sha256(self) -> str:
        return self.policy_author_split.sha256


def _exact_plan_text(name: str, value: object) -> str:
    if type(value) is not str:
        raise PrincipalDriverError(f"{name} must be exact text")
    return value


def _exact_plan_integer(name: str, value: object) -> int:
    if type(value) is not int:
        raise PrincipalDriverError(f"{name} must be an exact integer")
    return value


def _exact_plan_optional_text(name: str, value: object) -> str | None:
    if value is None:
        return None
    return _exact_plan_text(name, value)


def _principal_scenario_state(value: object) -> dict[str, object]:
    if type(value) is not PrincipalScenario:
        raise PrincipalDriverError("principal scenario type is not exact")
    if type(value.principal_scoring_eligible) is not bool:
        raise PrincipalDriverError("principal scenario eligibility must be Boolean")
    return {
        "episode_id": _exact_plan_text("scenario episode ID", value.episode_id),
        "injection_task_id": _exact_plan_optional_text(
            "scenario injection task ID", value.injection_task_id
        ),
        "pair_id": _exact_plan_optional_text("scenario pair ID", value.pair_id),
        "policy_partition": _exact_plan_text(
            "scenario policy partition", value.policy_partition
        ),
        "principal_scoring_eligible": value.principal_scoring_eligible,
        "scenario_id": _exact_plan_text("scenario ID", value.scenario_id),
        "stratum": _exact_plan_text("scenario stratum", value.stratum),
        "suite_name": _exact_plan_text("scenario suite", value.suite_name),
        "user_task_id": _exact_plan_text("scenario user task ID", value.user_task_id),
    }


def _principal_entry_state(value: object) -> dict[str, object]:
    if type(value) is not PrincipalScheduleEntry:
        raise PrincipalDriverError("principal schedule entry type is not exact")
    if type(value.principal_scoring_eligible) is not bool:
        raise PrincipalDriverError("schedule entry eligibility must be Boolean")
    return {
        "block": _exact_plan_integer("schedule block", value.block),
        "comparison_id": _exact_plan_text(
            "schedule comparison ID", value.comparison_id
        ),
        "condition": _exact_plan_text("schedule condition", value.condition),
        "entry_id": _exact_plan_text("schedule entry ID", value.entry_id),
        "episode_id": _exact_plan_text("schedule episode ID", value.episode_id),
        "generation_seed": _exact_plan_integer(
            "schedule generation seed", value.generation_seed
        ),
        "injection_task_id": _exact_plan_optional_text(
            "schedule injection task ID", value.injection_task_id
        ),
        "instance_id": _exact_plan_text("schedule instance ID", value.instance_id),
        "order": _exact_plan_integer("schedule order", value.order),
        "pair_id": _exact_plan_optional_text("schedule pair ID", value.pair_id),
        "policy_partition": _exact_plan_text(
            "schedule policy partition", value.policy_partition
        ),
        "principal_scoring_eligible": value.principal_scoring_eligible,
        "repetition": _exact_plan_integer("schedule repetition", value.repetition),
        "scenario_id": _exact_plan_text("schedule scenario ID", value.scenario_id),
        "stratum": _exact_plan_text("schedule stratum", value.stratum),
        "suite_name": _exact_plan_text("schedule suite", value.suite_name),
        "user_task_id": _exact_plan_text("schedule user task ID", value.user_task_id),
    }


def _principal_plan_state_wire(plan: PrincipalExecutionPlan) -> dict[str, object]:
    """Project every trusted plan coordinate into one exact canonical snapshot."""

    if type(plan) is not PrincipalExecutionPlan:
        raise PrincipalDriverError("principal plan state type is not exact")
    if type(plan.conditions) is not tuple or any(
        type(item) is not str for item in plan.conditions
    ):
        raise PrincipalDriverError("principal plan conditions are not exact")
    if type(plan.seeds) is not tuple or any(type(item) is not int for item in plan.seeds):
        raise PrincipalDriverError("principal plan seeds are not exact integers")
    if type(plan.principal_outcomes_present) is not bool:
        raise PrincipalDriverError("principal outcome flag must be Boolean")
    split = plan.policy_author_split
    if type(split) is not PolicyAuthorSplit:
        raise PrincipalDriverError("policy-author split type is not exact")
    if type(split.development_task_ids) is not tuple or type(
        split.heldout_task_ids
    ) is not tuple or any(
        type(item) is not str
        for item in split.development_task_ids + split.heldout_task_ids
    ):
        raise PrincipalDriverError("policy-author split IDs are not exact")
    baseline = plan.official_tool_filter
    if type(baseline) is not OfficialToolFilterBaseline:
        raise PrincipalDriverError("official tool-filter baseline type is not exact")
    if type(baseline.requires_official_openai_adapter) is not bool:
        raise PrincipalDriverError("tool-filter adapter requirement must be Boolean")
    if type(plan.suite_pair_counts) is not _MAPPING_PROXY_TYPE or any(
        type(key) is not str or type(value) is not int
        for key, value in plan.suite_pair_counts.items()
    ):
        raise PrincipalDriverError("suite pair counts are not an exact frozen mapping")
    if type(plan.suite_task_counts) is not _MAPPING_PROXY_TYPE:
        raise PrincipalDriverError("suite task counts are not an exact frozen mapping")
    suite_task_counts: dict[str, list[int]] = {}
    for key, value in plan.suite_task_counts.items():
        if (
            type(key) is not str
            or type(value) is not tuple
            or len(value) != 2
            or any(type(item) is not int for item in value)
        ):
            raise PrincipalDriverError("suite task-count coordinate is not exact")
        suite_task_counts[key] = list(value)
    if type(plan.scenarios) is not tuple or len(plan.scenarios) != 1_046:
        raise PrincipalDriverError("principal scenario population is not exact")
    scenario_state = [_principal_scenario_state(value) for value in plan.scenarios]
    if type(plan.entries) is not tuple or len(plan.entries) != 20_920:
        raise PrincipalDriverError("principal entry population is not exact")
    entry_state = [_principal_entry_state(value) for value in plan.entries]
    if type(plan.schedule_instances) is not tuple or len(plan.schedule_instances) != 10:
        raise PrincipalDriverError("principal schedule-instance population is not exact")
    flattened: list[PrincipalScheduleEntry] = []
    instance_state: list[dict[str, object]] = []
    for instance in plan.schedule_instances:
        if type(instance) is not PrincipalScheduleInstance:
            raise PrincipalDriverError("principal schedule instance type is not exact")
        if type(instance.conditions) is not tuple or len(instance.conditions) != 2 or any(
            type(item) is not str for item in instance.conditions
        ):
            raise PrincipalDriverError("schedule instance conditions are not exact")
        if type(instance.entries) is not tuple or len(instance.entries) != 2_092:
            raise PrincipalDriverError("schedule instance entry population is not exact")
        if any(type(item) is not PrincipalScheduleEntry for item in instance.entries):
            raise PrincipalDriverError("schedule instance entry type is not exact")
        flattened.extend(instance.entries)
        instance_state.append(
            {
                "comparison_id": _exact_plan_text(
                    "instance comparison ID", instance.comparison_id
                ),
                "conditions": list(instance.conditions),
                "entry_ids": [item.entry_id for item in instance.entries],
                "generation_seed": _exact_plan_integer(
                    "instance generation seed", instance.generation_seed
                ),
                "instance_id": _exact_plan_text("instance ID", instance.instance_id),
                "repetition": _exact_plan_integer(
                    "instance repetition", instance.repetition
                ),
                "sha256": _sha256("schedule instance digest", instance.sha256),
            }
        )
    if len(flattened) != len(plan.entries) or any(
        left is not right for left, right in zip(flattened, plan.entries, strict=True)
    ):
        raise PrincipalDriverError("flat entries are not identity-bound to instances")
    if type(plan._entry_index) is not _MAPPING_PROXY_TYPE or len(
        plan._entry_index
    ) != len(plan.entries):
        raise PrincipalDriverError("principal entry index is not an exact frozen mapping")
    for entry in plan.entries:
        if type(entry.entry_id) is not str or plan._entry_index.get(entry.entry_id) is not entry:
            raise PrincipalDriverError("principal entry index identity drifted")
    if any(type(key) is not str for key in plan._entry_index):
        raise PrincipalDriverError("principal entry index key type drifted")
    return {
        "attacked_pair_count": _exact_plan_integer(
            "attacked pair count", plan.attacked_pair_count
        ),
        "benign_task_count": _exact_plan_integer(
            "benign task count", plan.benign_task_count
        ),
        "conditions": list(plan.conditions),
        "entries": entry_state,
        "official_tool_filter": {
            "condition": _exact_plan_text("baseline condition", baseline.condition),
            "config_value": _exact_plan_text("baseline config", baseline.config_value),
            "llm_source_sha256": _sha256(
                "baseline LLM source", baseline.llm_source_sha256
            ),
            "pipeline_element_qualname": _exact_plan_text(
                "baseline pipeline element", baseline.pipeline_element_qualname
            ),
            "pipeline_source_sha256": _sha256(
                "baseline pipeline source", baseline.pipeline_source_sha256
            ),
            "requires_official_openai_adapter": (
                baseline.requires_official_openai_adapter
            ),
            "sha256": _sha256("baseline digest", baseline.sha256),
        },
        "plan_sha256": _sha256("principal plan digest", plan.sha256),
        "policy_author_split": {
            "development_task_ids": list(split.development_task_ids),
            "heldout_task_ids": list(split.heldout_task_ids),
            "selection_seed": _exact_plan_text("split seed", split.selection_seed),
            "sha256": _sha256("split digest", split.sha256),
        },
        "principal_outcomes_present": plan.principal_outcomes_present,
        "registry_sha256": _sha256("registry digest", plan.registry_sha256),
        "repetitions_per_seed": _exact_plan_integer(
            "repetitions per seed", plan.repetitions_per_seed
        ),
        "scenarios": scenario_state,
        "schedule_instances": instance_state,
        "seeds": list(plan.seeds),
        "source_sha256": _sha256("source digest", plan.source_sha256),
        "suite_pair_counts": dict(plan.suite_pair_counts),
        "suite_task_counts": suite_task_counts,
        "validation_schema": "sluice-agentdojo-loaded-plan-state-v1",
    }


def _principal_plan_state_sha256(plan: PrincipalExecutionPlan) -> str:
    return _digest_bytes(
        b"sluice-agentdojo-loaded-plan-state-v1",
        _canonical_json(_principal_plan_state_wire(plan)),
    )


def _load_split(value: object) -> PolicyAuthorSplit:
    wire = _exact_object(
        "policy-author split",
        value,
        frozenset(
            {
                "schema_version",
                "selection_seed",
                "development_task_ids",
                "heldout_task_ids",
                "sha256",
            }
        ),
    )
    if type(wire["schema_version"]) is not str or wire["schema_version"] != _SPLIT_SCHEMA:
        raise PrincipalDriverError("policy-author split schema mismatch")
    if wire["selection_seed"] != _SPLIT_SEED:
        raise PrincipalDriverError("policy-author split seed mismatch")
    _verify_own_digest("policy-author split", wire)
    if type(wire["development_task_ids"]) is not list or type(
        wire["heldout_task_ids"]
    ) is not list:
        raise PrincipalDriverError("policy-author split IDs must be lists")
    development = tuple(wire["development_task_ids"])
    heldout = tuple(wire["heldout_task_ids"])
    if any(type(item) is not str for item in development + heldout):
        raise PrincipalDriverError("policy-author split contains a nonstring ID")
    expected_development, expected_heldout = _expected_split_ids()
    if development != expected_development or heldout != expected_heldout:
        raise PrincipalDriverError("policy-author split is not the frozen 24/73 split")
    if len(development) != 24 or len(heldout) != 73:
        raise PrincipalDriverError("policy-author split cardinality mismatch")
    return PolicyAuthorSplit(
        development_task_ids=development,
        heldout_task_ids=heldout,
        selection_seed=_SPLIT_SEED,
        sha256=wire["sha256"],
    )


def _scenario_wire(
    *,
    stratum: str,
    suite_name: str,
    user_task_id: str,
    injection_task_id: str | None,
    split: PolicyAuthorSplit,
) -> dict[str, object]:
    qualified = f"{suite_name}:{user_task_id}"
    if qualified in split.development_task_ids:
        partition = "development"
    elif qualified in split.heldout_task_ids:
        partition = "heldout"
    else:
        raise PrincipalDriverError("universe task is absent from policy-author split")
    pair = (
        None
        if injection_task_id is None
        else _pair_id(suite_name, user_task_id, injection_task_id)
    )
    return {
        "scenario_id": _scenario_id(
            stratum, suite_name, user_task_id, injection_task_id
        ),
        "episode_id": _episode_id(
            stratum, suite_name, user_task_id, injection_task_id
        ),
        "stratum": stratum,
        "suite_name": suite_name,
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "pair_id": pair,
        "policy_partition": partition,
        "principal_scoring_eligible": partition == "heldout",
    }


def _load_universe(
    value: object, *, split: PolicyAuthorSplit
) -> tuple[
    tuple[PrincipalScenario, ...],
    Mapping[str, int],
    Mapping[str, tuple[int, int]],
]:
    wire = _exact_object(
        "principal universe",
        value,
        frozenset(
            {
                "schema_version",
                "attacked_pair_count",
                "benign_task_count",
                "suite_pair_counts",
                "suite_task_counts",
                "attacked_pairs",
                "benign_tasks",
                "sha256",
            }
        ),
    )
    if type(wire["schema_version"]) is not str or wire["schema_version"] != _UNIVERSE_SCHEMA:
        raise PrincipalDriverError("principal universe schema mismatch")
    _verify_own_digest("principal universe", wire)
    if (
        _integer("principal universe attacked-pair count", wire["attacked_pair_count"])
        != 949
        or _integer("principal universe benign-task count", wire["benign_task_count"])
        != 97
    ):
        raise PrincipalDriverError("principal universe must contain 949 and 97 units")
    expected_task_counts = {
        suite: [counts[0], counts[1]] for suite, counts in _SUITE_TASK_COUNTS.items()
    }
    if _canonical_json(wire["suite_pair_counts"]) != _canonical_json(
        dict(_SUITE_PAIR_COUNTS)
    ):
        raise PrincipalDriverError("principal universe suite pair counts mismatch")
    if _canonical_json(wire["suite_task_counts"]) != _canonical_json(
        expected_task_counts
    ):
        raise PrincipalDriverError("principal universe suite task counts mismatch")
    if type(wire["attacked_pairs"]) is not list or type(wire["benign_tasks"]) is not list:
        raise PrincipalDriverError("principal universe rows must be lists")

    expected_attacked: list[dict[str, object]] = []
    expected_benign: list[dict[str, object]] = []
    for suite_name in sorted(_SUITE_TASK_COUNTS):
        user_count, injection_count, injection_start = _SUITE_TASK_COUNTS[suite_name]
        for user_index in range(user_count):
            user_task_id = f"user_task_{user_index}"
            expected_benign.append(
                _scenario_wire(
                    stratum="benign",
                    suite_name=suite_name,
                    user_task_id=user_task_id,
                    injection_task_id=None,
                    split=split,
                )
            )
            for injection_index in range(
                injection_start, injection_start + injection_count
            ):
                expected_attacked.append(
                    _scenario_wire(
                        stratum="attacked",
                        suite_name=suite_name,
                        user_task_id=user_task_id,
                        injection_task_id=f"injection_task_{injection_index}",
                        split=split,
                    )
                )
    if _canonical_json(wire["attacked_pairs"]) != _canonical_json(expected_attacked):
        raise PrincipalDriverError("principal universe 949-pair projection mismatch")
    if _canonical_json(wire["benign_tasks"]) != _canonical_json(expected_benign):
        raise PrincipalDriverError("principal universe 97-task projection mismatch")

    rows = expected_attacked + expected_benign
    scenarios = tuple(PrincipalScenario(**row) for row in rows)
    if len({item.scenario_id for item in scenarios}) != 1_046:
        raise PrincipalDriverError("principal universe scenario IDs are not unique")
    if len({item.episode_id for item in scenarios}) != 1_046:
        raise PrincipalDriverError("principal universe episode IDs are not unique")
    return (
        scenarios,
        MappingProxyType(dict(_SUITE_PAIR_COUNTS)),
        MappingProxyType(
            {
                suite: (counts[0], counts[1])
                for suite, counts in _SUITE_TASK_COUNTS.items()
            }
        ),
    )


def _counterbalanced_schedule_rows(
    episode_ids: Iterable[str],
    *,
    arms: tuple[str, str],
    seed: str,
    block_offset: int,
) -> list[dict[str, object]]:
    episodes = tuple(episode_ids)
    if len(episodes) != len(set(episodes)):
        raise PrincipalDriverError("principal schedule repeats an episode")
    ordered = sorted(
        episodes,
        key=lambda episode: hashlib.sha256(
            f"{_COUNTERBALANCE_SCHEMA}\0{seed}\0{episode}".encode("utf-8")
        ).hexdigest(),
    )
    rows: list[dict[str, object]] = []
    for local_block, episode in enumerate(ordered):
        first, second = arms if local_block % 2 == 0 else (arms[1], arms[0])
        block = block_offset + local_block
        rows.append(
            {
                "block": block,
                "order": 1,
                "episode_id": episode,
                "condition": first,
            }
        )
        rows.append(
            {
                "block": block,
                "order": 2,
                "episode_id": episode,
                "condition": second,
            }
        )
    return rows


def _entry_id(
    *,
    instance_id: str,
    block: int,
    order: int,
    episode_id: str,
    condition: str,
) -> str:
    return _digest_text(
        b"sluice-agentdojo-principal-entry-v1",
        f"{instance_id}\0{block}\0{order}\0{episode_id}\0{condition}",
    )


def _load_schedule_instance(
    value: object,
    *,
    expected_seed: int,
    expected_repetition: int,
    expected_comparison_id: str,
    expected_conditions: tuple[str, str],
    scenario_by_episode: Mapping[str, PrincipalScenario],
    attacked_episode_ids: tuple[str, ...],
    benign_episode_ids: tuple[str, ...],
) -> PrincipalScheduleInstance:
    wire = _exact_object(
        "principal schedule instance",
        value,
        frozenset(
            {
                "schema_version",
                "instance_id",
                "comparison_id",
                "conditions",
                "generation_seed",
                "repetition",
                "attacked_seed_sha256",
                "benign_seed_sha256",
                "schedule",
                "sha256",
            }
        ),
    )
    if type(wire["schema_version"]) is not str or wire["schema_version"] != _INSTANCE_SCHEMA:
        raise PrincipalDriverError("principal schedule instance schema mismatch")
    _verify_own_digest("principal schedule instance", wire)
    if (
        wire["comparison_id"] != expected_comparison_id
        or wire["conditions"] != list(expected_conditions)
        or _integer("schedule instance generation seed", wire["generation_seed"])
        != expected_seed
        or _integer("schedule instance repetition", wire["repetition"])
        != expected_repetition
    ):
        raise PrincipalDriverError("principal schedule instance coordinate mismatch")
    instance_id = _digest_text(
        b"sluice-agentdojo-principal-instance-v1",
        f"{expected_seed}\0{expected_repetition}\0{expected_comparison_id}",
    )
    if wire["instance_id"] != instance_id:
        raise PrincipalDriverError("principal schedule instance ID mismatch")
    attacked_seed = (
        f"agentdojo-principal-v1:{expected_seed}:r{expected_repetition}:"
        f"{expected_comparison_id}:attacked"
    )
    benign_seed = (
        f"agentdojo-principal-v1:{expected_seed}:r{expected_repetition}:"
        f"{expected_comparison_id}:benign"
    )
    if wire["attacked_seed_sha256"] != _digest_text(
        b"sluice-agentdojo-principal-seed-v1", attacked_seed
    ) or wire["benign_seed_sha256"] != _digest_text(
        b"sluice-agentdojo-principal-seed-v1", benign_seed
    ):
        raise PrincipalDriverError("principal schedule seed binding mismatch")

    schedule = _exact_object(
        "principal schedule",
        wire["schedule"],
        frozenset({"schema_version", "entries", "sha256"}),
    )
    if (
        type(schedule["schema_version"]) is not str
        or schedule["schema_version"] != _SCHEDULE_SCHEMA
    ):
        raise PrincipalDriverError("principal schedule schema mismatch")
    _verify_own_digest("principal schedule", schedule)
    if type(schedule["entries"]) is not list:
        raise PrincipalDriverError("principal schedule entries must be an exact list")
    schedule_row_fields = frozenset({"block", "order", "episode_id", "condition"})
    for row_value in schedule["entries"]:
        row = _exact_object("principal schedule row", row_value, schedule_row_fields)
        _integer("principal schedule block", row["block"])
        _integer("principal schedule order", row["order"], minimum=1)
        _text("principal schedule episode ID", row["episode_id"])
        _text("principal schedule condition", row["condition"])
    expected_rows = _counterbalanced_schedule_rows(
        attacked_episode_ids,
        arms=expected_conditions,
        seed=attacked_seed,
        block_offset=0,
    )
    expected_rows.extend(
        _counterbalanced_schedule_rows(
            benign_episode_ids,
            arms=(expected_conditions[1], expected_conditions[0]),
            seed=benign_seed,
            block_offset=949,
        )
    )
    if _canonical_json(schedule["entries"]) != _canonical_json(expected_rows):
        raise PrincipalDriverError(
            "principal schedule condition, order, or counterbalance mismatch"
        )
    if len(expected_rows) != 2_092:
        raise PrincipalDriverError("principal schedule must contain 2,092 entries")
    first = [row["condition"] for row in expected_rows if row["order"] == 1]
    if abs(first.count(expected_conditions[0]) - first.count(expected_conditions[1])) > 1:
        raise PrincipalDriverError("principal schedule is not counterbalanced")

    entries: list[PrincipalScheduleEntry] = []
    for row in expected_rows:
        scenario = scenario_by_episode[row["episode_id"]]
        entries.append(
            PrincipalScheduleEntry(
                entry_id=_entry_id(
                    instance_id=instance_id,
                    block=row["block"],
                    order=row["order"],
                    episode_id=row["episode_id"],
                    condition=row["condition"],
                ),
                instance_id=instance_id,
                comparison_id=expected_comparison_id,
                generation_seed=expected_seed,
                repetition=expected_repetition,
                block=row["block"],
                order=row["order"],
                scenario_id=scenario.scenario_id,
                episode_id=scenario.episode_id,
                stratum=scenario.stratum,
                suite_name=scenario.suite_name,
                user_task_id=scenario.user_task_id,
                injection_task_id=scenario.injection_task_id,
                pair_id=scenario.pair_id,
                policy_partition=scenario.policy_partition,
                principal_scoring_eligible=scenario.principal_scoring_eligible,
                condition=row["condition"],
            )
        )
    return PrincipalScheduleInstance(
        instance_id=instance_id,
        comparison_id=expected_comparison_id,
        conditions=expected_conditions,
        generation_seed=expected_seed,
        repetition=expected_repetition,
        entries=tuple(entries),
        sha256=wire["sha256"],
    )


def _load_baseline(value: object) -> OfficialToolFilterBaseline:
    wire = _exact_object(
        "official tool-filter baseline",
        value,
        frozenset({*_EXPECTED_BASELINE, "sha256"}),
    )
    _verify_own_digest("official tool-filter baseline", wire)
    body = {key: value for key, value in wire.items() if key != "sha256"}
    if _canonical_json(body) != _canonical_json(_EXPECTED_BASELINE):
        raise PrincipalDriverError("official tool-filter pinned source mismatch")
    return OfficialToolFilterBaseline(
        condition=wire["condition"],
        config_value=wire["config_value"],
        pipeline_source_sha256=wire["pipeline_source_sha256"],
        llm_source_sha256=wire["llm_source_sha256"],
        pipeline_element_qualname=wire["pipeline_element_qualname"],
        requires_official_openai_adapter=wire["requires_official_openai_adapter"],
        sha256=wire["sha256"],
    )


def _load_principal_plan(
    value: object, *, expected_sha256: str
) -> PrincipalExecutionPlan:
    _validate_exact_json_domain(value)
    expected = _sha256("expected digest", expected_sha256)
    wire = _exact_object(
        "principal plan",
        value,
        frozenset(
            {
                "schema_version",
                "agentdojo_source",
                "registry",
                "conditions",
                "comparisons",
                "seeds",
                "repetitions_per_seed",
                "policy_author_split",
                "universe",
                "official_tool_filter",
                "schedule_instances",
                "planned_run_count",
                "principal_outcomes_present",
                "sha256",
            }
        ),
    )
    if type(wire["schema_version"]) is not str or wire["schema_version"] != _PLAN_SCHEMA:
        raise PrincipalDriverError("principal plan schema mismatch")
    embedded = _sha256("principal plan digest", wire["sha256"])
    computed = principal_plan_sha256(wire)
    if expected != embedded or embedded != computed:
        raise PrincipalDriverError("principal plan expected digest mismatch")
    if _canonical_json(wire["agentdojo_source"]) != _canonical_json(_EXPECTED_SOURCE):
        raise PrincipalDriverError("principal plan official source identity mismatch")
    if _canonical_json(wire["registry"]) != _canonical_json(_EXPECTED_REGISTRY):
        raise PrincipalDriverError("principal plan official registry identity mismatch")
    conditions = tuple(condition.value for condition in PrincipalCondition)
    if _canonical_json(wire["conditions"]) != _canonical_json(list(conditions)):
        raise PrincipalDriverError("principal plan condition set mismatch")
    expected_comparisons = [
        {"comparison_id": comparison_id, "conditions": list(pair)}
        for comparison_id, pair in _COMPARISONS
    ]
    if _canonical_json(wire["comparisons"]) != _canonical_json(expected_comparisons):
        raise PrincipalDriverError("principal plan comparison set mismatch")
    if _canonical_json(wire["seeds"]) != _canonical_json(list(PRINCIPAL_SEEDS)):
        raise PrincipalDriverError("principal plan seed set mismatch")
    if (
        _integer("principal repetition count", wire["repetitions_per_seed"], minimum=1)
        != PRINCIPAL_REPETITIONS_PER_SEED
    ):
        raise PrincipalDriverError("principal plan repetition count mismatch")
    if (
        _integer("principal planned run count", wire["planned_run_count"], minimum=1)
        != 20_920
    ):
        raise PrincipalDriverError("principal plan must contain 20,920 entries")
    if wire["principal_outcomes_present"] is not False:
        raise PrincipalDriverError("principal plan must not contain outcomes")

    split = _load_split(wire["policy_author_split"])
    scenarios, suite_pair_counts, suite_task_counts = _load_universe(
        wire["universe"], split=split
    )
    baseline = _load_baseline(wire["official_tool_filter"])
    scenario_by_episode = MappingProxyType(
        {scenario.episode_id: scenario for scenario in scenarios}
    )
    attacked_ids = tuple(
        scenario.episode_id for scenario in scenarios if scenario.stratum == "attacked"
    )
    benign_ids = tuple(
        scenario.episode_id for scenario in scenarios if scenario.stratum == "benign"
    )
    if type(wire["schedule_instances"]) is not list:
        raise PrincipalDriverError("principal schedule instances must be a list")
    expected_coordinates = [
        (seed, repetition, comparison_id, pair)
        for seed in PRINCIPAL_SEEDS
        for repetition in range(PRINCIPAL_REPETITIONS_PER_SEED)
        for comparison_id, pair in _COMPARISONS
    ]
    if len(wire["schedule_instances"]) != len(expected_coordinates):
        raise PrincipalDriverError("principal schedule instance count mismatch")
    instances = tuple(
        _load_schedule_instance(
            item,
            expected_seed=seed,
            expected_repetition=repetition,
            expected_comparison_id=comparison_id,
            expected_conditions=pair,
            scenario_by_episode=scenario_by_episode,
            attacked_episode_ids=attacked_ids,
            benign_episode_ids=benign_ids,
        )
        for item, (seed, repetition, comparison_id, pair) in zip(
            wire["schedule_instances"], expected_coordinates, strict=True
        )
    )
    entries = tuple(entry for instance in instances for entry in instance.entries)
    if len(entries) != 20_920 or len({entry.entry_id for entry in entries}) != 20_920:
        raise PrincipalDriverError("principal schedule entry cardinality or uniqueness mismatch")
    plan = PrincipalExecutionPlan(
        sha256=embedded,
        conditions=conditions,
        seeds=PRINCIPAL_SEEDS,
        repetitions_per_seed=PRINCIPAL_REPETITIONS_PER_SEED,
        policy_author_split=split,
        official_tool_filter=baseline,
        attacked_pair_count=949,
        benign_task_count=97,
        suite_pair_counts=suite_pair_counts,
        suite_task_counts=suite_task_counts,
        scenarios=scenarios,
        schedule_instances=instances,
        entries=entries,
        source_sha256=principal_plan_sha256(dict(_EXPECTED_SOURCE)),
        registry_sha256=_EXPECTED_REGISTRY["registry_sha256"],
        principal_outcomes_present=False,
        _entry_index=MappingProxyType({entry.entry_id: entry for entry in entries}),
        _token=_PRINCIPAL_PLAN_TOKEN,
    )
    with _LOADED_PRINCIPAL_PLANS_LOCK:
        _LOADED_PRINCIPAL_PLANS[id(plan)] = plan
    return plan


@dataclass(frozen=True, slots=True)
class PrincipalDependencyObservation:
    dependency_manifest_sha256: str
    python_version: str
    pydantic_version: str
    pyyaml_version: str
    model_id: str
    model_revision: str
    model_artifact_sha256: str
    backend: str
    backend_version: str
    mismatch_fields: tuple[str, ...]
    principal_eligible: bool
    sha256: str
    _manifest: "PrincipalDependencyManifest" = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self._manifest) is not PrincipalDependencyManifest:
            raise TypeError("dependency observation manifest binding is invalid")
        if self.dependency_manifest_sha256 != self._manifest.sha256:
            raise PrincipalDriverError("dependency observation manifest digest mismatch")
        _text("observed Python version", self.python_version)
        _text("observed Pydantic version", self.pydantic_version)
        _text("observed PyYAML version", self.pyyaml_version)
        _validate_model_identity(
            self.model_id,
            self.model_revision,
            self.model_artifact_sha256,
            self.backend,
            self.backend_version,
            name="dependency observation",
        )
        if _manifest_model_identity(self._manifest) != self.model_identity:
            raise PrincipalDriverError("dependency observation model binding mismatch")
        if type(self.mismatch_fields) is not tuple or any(
            item not in {"python", "pydantic", "pyyaml"}
            for item in self.mismatch_fields
        ):
            raise PrincipalDriverError("dependency mismatch fields are invalid")
        if self.principal_eligible is not (not self.mismatch_fields):
            raise PrincipalDriverError("dependency eligibility is inconsistent")
        _sha256("dependency observation digest", self.sha256)
        base = self.to_wire()
        base.pop("sha256")
        if self.sha256 != _digest_bytes(
            b"sluice-agentdojo-principal-dependency-observation-v1",
            _canonical_json(base),
        ):
            raise PrincipalDriverError("dependency observation digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": "sluice-agentdojo-principal-dependency-observation-v1",
            "dependency_manifest_sha256": self.dependency_manifest_sha256,
            "python_version": self.python_version,
            "pydantic_version": self.pydantic_version,
            "pyyaml_version": self.pyyaml_version,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "model_artifact_sha256": self.model_artifact_sha256,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "mismatch_fields": list(self.mismatch_fields),
            "principal_eligible": self.principal_eligible,
            "sha256": self.sha256,
        }

    @property
    def model_identity(self) -> tuple[str, str, str, str, str]:
        return (
            self.model_id,
            self.model_revision,
            self.model_artifact_sha256,
            self.backend,
            self.backend_version,
        )


@dataclass(frozen=True, slots=True)
class PrincipalDependencyManifest:
    python_version: str
    pydantic_version: str
    pyyaml_version: str
    model_id: str
    model_revision: str
    model_artifact_sha256: str
    backend: str
    backend_version: str
    sha256: str

    @classmethod
    def create(
        cls,
        *,
        python_version: str,
        model_id: str,
        model_revision: str,
        model_artifact_sha256: str,
        backend: str,
        backend_version: str,
    ) -> "PrincipalDependencyManifest":
        _text("Python version", python_version)
        _text("model ID", model_id)
        _revision("model revision", model_revision)
        _sha256("model artifact digest", model_artifact_sha256)
        _text("backend", backend)
        _text("backend version", backend_version)
        if backend != "vllm":
            raise PrincipalDriverError("principal backend must be the exact vllm adapter")
        base = {
            "schema_version": "sluice-agentdojo-principal-dependency-manifest-v1",
            "python_version": python_version,
            "pydantic_version": "2.11.4",
            "pyyaml_version": "6.0.2",
            "model_id": model_id,
            "model_revision": model_revision,
            "model_artifact_sha256": model_artifact_sha256,
            "backend": backend,
            "backend_version": backend_version,
        }
        return cls(
            python_version=python_version,
            pydantic_version="2.11.4",
            pyyaml_version="6.0.2",
            model_id=model_id,
            model_revision=model_revision,
            model_artifact_sha256=model_artifact_sha256,
            backend=backend,
            backend_version=backend_version,
            sha256=_digest_bytes(
                b"sluice-agentdojo-principal-dependency-manifest-v1",
                _canonical_json(base),
            ),
        )

    def __post_init__(self) -> None:
        _text("Python version", self.python_version)
        if self.pydantic_version != "2.11.4" or self.pyyaml_version != "6.0.2":
            raise PrincipalDriverError("principal dependency pins changed")
        _text("model ID", self.model_id)
        _revision("model revision", self.model_revision)
        _sha256("model artifact digest", self.model_artifact_sha256)
        if self.backend != "vllm":
            raise PrincipalDriverError("principal backend identity mismatch")
        _text("backend version", self.backend_version)
        _sha256("dependency manifest digest", self.sha256)
        base = self.to_wire()
        base.pop("sha256")
        if self.sha256 != _digest_bytes(
            b"sluice-agentdojo-principal-dependency-manifest-v1",
            _canonical_json(base),
        ):
            raise PrincipalDriverError("dependency manifest digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": "sluice-agentdojo-principal-dependency-manifest-v1",
            "python_version": self.python_version,
            "pydantic_version": self.pydantic_version,
            "pyyaml_version": self.pyyaml_version,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "model_artifact_sha256": self.model_artifact_sha256,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "sha256": self.sha256,
        }

    def observe(
        self,
        *,
        python_version: str | None = None,
        version_lookup: Callable[[str], str] = importlib.metadata.version,
    ) -> PrincipalDependencyObservation:
        if not callable(version_lookup):
            raise TypeError("version lookup must be callable")
        observed_python = platform.python_version() if python_version is None else python_version
        try:
            observed_pydantic = version_lookup("pydantic")
        except Exception:
            observed_pydantic = "unavailable"
        try:
            observed_pyyaml = version_lookup("PyYAML")
        except Exception:
            observed_pyyaml = "unavailable"
        _text("observed Python version", observed_python)
        _text("observed Pydantic version", observed_pydantic)
        _text("observed PyYAML version", observed_pyyaml)
        mismatches = tuple(
            name
            for name, actual, expected in (
                ("python", observed_python, self.python_version),
                ("pydantic", observed_pydantic, self.pydantic_version),
                ("pyyaml", observed_pyyaml, self.pyyaml_version),
            )
            if actual != expected
        )
        base = {
            "schema_version": "sluice-agentdojo-principal-dependency-observation-v1",
            "dependency_manifest_sha256": self.sha256,
            "python_version": observed_python,
            "pydantic_version": observed_pydantic,
            "pyyaml_version": observed_pyyaml,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "model_artifact_sha256": self.model_artifact_sha256,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "mismatch_fields": list(mismatches),
            "principal_eligible": not mismatches,
        }
        return PrincipalDependencyObservation(
            dependency_manifest_sha256=self.sha256,
            python_version=observed_python,
            pydantic_version=observed_pydantic,
            pyyaml_version=observed_pyyaml,
            model_id=self.model_id,
            model_revision=self.model_revision,
            model_artifact_sha256=self.model_artifact_sha256,
            backend=self.backend,
            backend_version=self.backend_version,
            mismatch_fields=mismatches,
            principal_eligible=not mismatches,
            sha256=_digest_bytes(
                b"sluice-agentdojo-principal-dependency-observation-v1",
                _canonical_json(base),
            ),
            _manifest=self,
        )


def _peer_digest(role: str, peer: PeerIdentity, nonce: str) -> str:
    return _digest_text(
        b"sluice-agentdojo-principal-peer-v1",
        f"{role}\0{peer.pid}\0{peer.uid}\0{peer.gid}\0{nonce}",
    )


@dataclass(frozen=True, slots=True)
class ProcessTopologyAttestation:
    monitor: PeerIdentity = field(repr=False)
    broker: PeerIdentity = field(repr=False)
    model_driver: PeerIdentity = field(repr=False)
    monitor_sha256: str
    broker_sha256: str
    model_driver_sha256: str
    session_sha256: str
    binding_sha256: str
    principal_eligible: bool
    mode: str
    _session_nonce: str = field(repr=False, compare=False)

    @classmethod
    def for_cpu_test(
        cls,
        *,
        monitor: PeerIdentity,
        broker: PeerIdentity,
        model_driver: PeerIdentity,
        session_nonce: str,
    ) -> "ProcessTopologyAttestation":
        for name, peer in (
            ("monitor", monitor),
            ("broker", broker),
            ("model driver", model_driver),
        ):
            if type(peer) is not PeerIdentity:
                raise TypeError(f"{name} peer must be an exact PeerIdentity")
        _text("topology session nonce", session_nonce)
        if len({monitor.pid, broker.pid, model_driver.pid}) != 3:
            raise PrincipalDriverError("topology roles require three distinct PIDs")
        role_hashes = {
            "monitor": _peer_digest("monitor", monitor, session_nonce),
            "broker": _peer_digest("broker", broker, session_nonce),
            "model_driver": _peer_digest("model_driver", model_driver, session_nonce),
        }
        session_sha = _digest_text(
            b"sluice-agentdojo-principal-session-v1", session_nonce
        )
        public = {
            "schema_version": "sluice-agentdojo-process-topology-v1",
            "mode": "cpu_contract",
            "role_sha256": role_hashes,
            "session_sha256": session_sha,
            "principal_eligible": False,
        }
        return cls(
            monitor=monitor,
            broker=broker,
            model_driver=model_driver,
            monitor_sha256=role_hashes["monitor"],
            broker_sha256=role_hashes["broker"],
            model_driver_sha256=role_hashes["model_driver"],
            session_sha256=session_sha,
            binding_sha256=_digest_bytes(
                b"sluice-agentdojo-process-topology-v1", _canonical_json(public)
            ),
            principal_eligible=False,
            mode="cpu_contract",
            _session_nonce=session_nonce,
        )

    def __post_init__(self) -> None:
        if any(
            type(peer) is not PeerIdentity
            for peer in (self.monitor, self.broker, self.model_driver)
        ):
            raise TypeError("topology peers must be exact PeerIdentity values")
        if len({self.monitor.pid, self.broker.pid, self.model_driver.pid}) != 3:
            raise PrincipalDriverError("topology roles require three distinct PIDs")
        if self.mode != "cpu_contract" or self.principal_eligible is not False:
            raise PrincipalDriverError("CPU topology cannot be principal eligible")
        expected_roles = {
            "monitor": _peer_digest("monitor", self.monitor, self._session_nonce),
            "broker": _peer_digest("broker", self.broker, self._session_nonce),
            "model_driver": _peer_digest(
                "model_driver", self.model_driver, self._session_nonce
            ),
        }
        if (
            self.monitor_sha256 != expected_roles["monitor"]
            or self.broker_sha256 != expected_roles["broker"]
            or self.model_driver_sha256 != expected_roles["model_driver"]
        ):
            raise PrincipalDriverError("topology role binding mismatch")
        if self.session_sha256 != _digest_text(
            b"sluice-agentdojo-principal-session-v1", self._session_nonce
        ):
            raise PrincipalDriverError("topology session binding mismatch")
        public = self.to_public_wire()
        public.pop("binding_sha256")
        if self.binding_sha256 != _digest_bytes(
            b"sluice-agentdojo-process-topology-v1", _canonical_json(public)
        ):
            raise PrincipalDriverError("topology binding digest mismatch")

    def to_public_wire(self) -> dict[str, object]:
        return {
            "schema_version": "sluice-agentdojo-process-topology-v1",
            "mode": self.mode,
            "role_sha256": {
                "monitor": self.monitor_sha256,
                "broker": self.broker_sha256,
                "model_driver": self.model_driver_sha256,
            },
            "session_sha256": self.session_sha256,
            "principal_eligible": self.principal_eligible,
            "binding_sha256": self.binding_sha256,
        }


@dataclass(frozen=True, slots=True)
class EndpointProbeReceipt:
    plan_sha256: str
    entry_id: str
    endpoint: EndpointAttestation
    topology_binding_sha256: str
    probe_mode: EndpointProbeMode
    monotonic_ns: int
    principal_eligible: bool
    sha256: str
    _plan: PrincipalExecutionPlan = field(repr=False, compare=False)
    _entry: PrincipalScheduleEntry = field(repr=False, compare=False)
    _topology: ProcessTopologyAttestation = field(repr=False, compare=False)

    @classmethod
    def for_cpu_test(
        cls,
        *,
        plan: PrincipalExecutionPlan,
        entry: PrincipalScheduleEntry,
        expectation: EndpointExpectation,
        probe: Callable[[str], EndpointObservation],
        topology: ProcessTopologyAttestation,
        monotonic_ns: int,
    ) -> "EndpointProbeReceipt":
        if type(plan) is not PrincipalExecutionPlan:
            raise TypeError("plan must be an exact PrincipalExecutionPlan")
        if type(entry) is not PrincipalScheduleEntry or plan.entry(entry.entry_id) is not entry:
            raise PrincipalDriverError("endpoint probe entry is not bound to this plan")
        if type(expectation) is not EndpointExpectation:
            raise TypeError("expectation must be an exact EndpointExpectation")
        if type(topology) is not ProcessTopologyAttestation:
            raise TypeError("topology must be an exact ProcessTopologyAttestation")
        _integer("endpoint probe monotonic time", monotonic_ns)
        endpoint = expectation.verify(probe)
        base = {
            "schema_version": "sluice-agentdojo-endpoint-probe-receipt-v1",
            "plan_sha256": plan.sha256,
            "entry_id": entry.entry_id,
            "endpoint": endpoint.to_wire(),
            "topology_binding_sha256": topology.binding_sha256,
            "probe_mode": EndpointProbeMode.CPU_FAKE.value,
            "monotonic_ns": monotonic_ns,
            "principal_eligible": False,
        }
        return cls(
            plan_sha256=plan.sha256,
            entry_id=entry.entry_id,
            endpoint=endpoint,
            topology_binding_sha256=topology.binding_sha256,
            probe_mode=EndpointProbeMode.CPU_FAKE,
            monotonic_ns=monotonic_ns,
            principal_eligible=False,
            sha256=_digest_bytes(
                b"sluice-agentdojo-endpoint-probe-receipt-v1",
                _canonical_json(base),
            ),
            _plan=plan,
            _entry=entry,
            _topology=topology,
        )

    def __post_init__(self) -> None:
        if type(self._plan) is not PrincipalExecutionPlan or type(
            self._entry
        ) is not PrincipalScheduleEntry:
            raise TypeError("endpoint receipt plan/entry binding is invalid")
        if self._plan.entry(self._entry.entry_id) is not self._entry:
            raise PrincipalDriverError("endpoint receipt entry object is not plan-bound")
        if self.entry_id != self._entry.entry_id or self.plan_sha256 != self._plan.sha256:
            raise PrincipalDriverError("endpoint receipt entry binding mismatch")
        if type(self.endpoint) is not EndpointAttestation:
            raise TypeError("endpoint receipt attestation is invalid")
        self.endpoint.revalidate()
        if type(self._topology) is not ProcessTopologyAttestation:
            raise TypeError("endpoint receipt topology is invalid")
        if self.topology_binding_sha256 != self._topology.binding_sha256:
            raise PrincipalDriverError("endpoint receipt topology binding mismatch")
        if self.probe_mode is not EndpointProbeMode.CPU_FAKE:
            raise PrincipalDriverError("CPU endpoint receipt has an invalid probe mode")
        if self.principal_eligible is not False:
            raise PrincipalDriverError("fake endpoint receipt cannot be principal eligible")
        _integer("endpoint probe monotonic time", self.monotonic_ns)
        _sha256("endpoint probe receipt digest", self.sha256)
        base = self.to_public_wire()
        base.pop("sha256")
        if self.sha256 != _digest_bytes(
            b"sluice-agentdojo-endpoint-probe-receipt-v1",
            _canonical_json(base),
        ):
            raise PrincipalDriverError("endpoint receipt entry digest mismatch")

    def to_public_wire(self) -> dict[str, object]:
        return {
            "schema_version": "sluice-agentdojo-endpoint-probe-receipt-v1",
            "plan_sha256": self.plan_sha256,
            "entry_id": self.entry_id,
            "endpoint": self.endpoint.to_wire(),
            "topology_binding_sha256": self.topology_binding_sha256,
            "probe_mode": self.probe_mode.value,
            "monotonic_ns": self.monotonic_ns,
            "principal_eligible": self.principal_eligible,
            "sha256": self.sha256,
        }


_ELIGIBILITY_TOKEN = object()
_PERMIT_TOKEN = object()


@dataclass(frozen=True, slots=True)
class PrincipalEligibilityAssessment:
    principal_eligible: bool
    failed_requirements: tuple[str, ...]
    dependency_observation_sha256: str
    topology_binding_sha256: str
    endpoint_receipt_sha256: str
    sha256: str
    _verification_token: object = field(repr=False, compare=False)

    @classmethod
    def assess(
        cls,
        *,
        dependencies: PrincipalDependencyObservation,
        clean_repository: object | None,
        isolation_review: object | None,
        live_launcher_review: object | None,
        topology: ProcessTopologyAttestation,
        endpoint_receipt: EndpointProbeReceipt,
    ) -> "PrincipalEligibilityAssessment":
        if type(dependencies) is not PrincipalDependencyObservation:
            raise TypeError("dependencies must be an exact observation")
        if type(topology) is not ProcessTopologyAttestation:
            raise TypeError("topology must be an exact attestation")
        if type(endpoint_receipt) is not EndpointProbeReceipt:
            raise TypeError("endpoint receipt must be exact")
        # This module deliberately has no constructor for a live repository,
        # isolation, or launcher review. Supplying truthy stand-ins cannot turn
        # the CPU foundation into a principal executor.
        del clean_repository, isolation_review, live_launcher_review
        failed: list[str] = []
        if not dependencies.principal_eligible:
            failed.append("exact_dependencies")
        if dependencies.model_identity != _endpoint_model_identity(
            endpoint_receipt.endpoint
        ):
            failed.append("manifest_endpoint_model_binding")
        failed.extend(("clean_commit", "reviewed_isolation", "reviewed_live_launcher"))
        if not topology.principal_eligible:
            failed.append("kernel_peer_bindings")
        if not endpoint_receipt.principal_eligible:
            failed.append("real_endpoint_probe")
        base = {
            "schema_version": "sluice-agentdojo-principal-eligibility-v1",
            "principal_eligible": False,
            "failed_requirements": failed,
            "dependency_observation_sha256": dependencies.sha256,
            "topology_binding_sha256": topology.binding_sha256,
            "endpoint_receipt_sha256": endpoint_receipt.sha256,
        }
        return cls(
            principal_eligible=False,
            failed_requirements=tuple(failed),
            dependency_observation_sha256=dependencies.sha256,
            topology_binding_sha256=topology.binding_sha256,
            endpoint_receipt_sha256=endpoint_receipt.sha256,
            sha256=_digest_bytes(
                b"sluice-agentdojo-principal-eligibility-v1", _canonical_json(base)
            ),
            _verification_token=_ELIGIBILITY_TOKEN,
        )

    def __post_init__(self) -> None:
        if self._verification_token is not _ELIGIBILITY_TOKEN:
            raise PrincipalDriverError("eligibility was not factory assessed")
        if self.principal_eligible is not (not self.failed_requirements):
            raise PrincipalDriverError("eligibility result is inconsistent")
        if self.principal_eligible:
            raise PrincipalDriverError("CPU foundation cannot assert principal eligibility")
        for name in (
            "dependency_observation_sha256",
            "topology_binding_sha256",
            "endpoint_receipt_sha256",
            "sha256",
        ):
            _sha256(name, getattr(self, name))
        base = self.to_wire()
        base.pop("sha256")
        if self.sha256 != _digest_bytes(
            b"sluice-agentdojo-principal-eligibility-v1", _canonical_json(base)
        ):
            raise PrincipalDriverError("eligibility digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "schema_version": "sluice-agentdojo-principal-eligibility-v1",
            "principal_eligible": self.principal_eligible,
            "failed_requirements": list(self.failed_requirements),
            "dependency_observation_sha256": self.dependency_observation_sha256,
            "topology_binding_sha256": self.topology_binding_sha256,
            "endpoint_receipt_sha256": self.endpoint_receipt_sha256,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class ScheduledLoopPermit:
    plan_sha256: str
    entry_id: str
    endpoint_receipt_sha256: str
    eligibility_sha256: str
    issued_monotonic_ns: int
    sha256: str
    _verification_token: object = field(repr=False, compare=False)

    @classmethod
    def issue(
        cls,
        *,
        plan: PrincipalExecutionPlan,
        entry: PrincipalScheduleEntry,
        endpoint_receipt: EndpointProbeReceipt,
        eligibility: PrincipalEligibilityAssessment,
        issued_monotonic_ns: int,
    ) -> "ScheduledLoopPermit":
        if type(eligibility) is not PrincipalEligibilityAssessment:
            raise TypeError("eligibility must be an exact assessment")
        if not eligibility.principal_eligible:
            raise PrincipalDriverError("principal scheduled loop is ineligible")
        # Unreachable in this CPU foundation; retained as the future live-loop
        # choke point so no caller can bypass the assessment.
        if type(plan) is not PrincipalExecutionPlan or type(entry) is not PrincipalScheduleEntry:
            raise TypeError("scheduled permit plan or entry is invalid")
        if plan.entry(entry.entry_id) is not entry:
            raise PrincipalDriverError("scheduled permit entry is not plan-bound")
        if endpoint_receipt.entry_id != entry.entry_id:
            raise PrincipalDriverError("scheduled permit endpoint entry mismatch")
        _integer("permit monotonic time", issued_monotonic_ns)
        base = {
            "schema_version": "sluice-agentdojo-scheduled-loop-permit-v1",
            "plan_sha256": plan.sha256,
            "entry_id": entry.entry_id,
            "endpoint_receipt_sha256": endpoint_receipt.sha256,
            "eligibility_sha256": eligibility.sha256,
            "issued_monotonic_ns": issued_monotonic_ns,
        }
        return cls(
            plan_sha256=plan.sha256,
            entry_id=entry.entry_id,
            endpoint_receipt_sha256=endpoint_receipt.sha256,
            eligibility_sha256=eligibility.sha256,
            issued_monotonic_ns=issued_monotonic_ns,
            sha256=_digest_bytes(
                b"sluice-agentdojo-scheduled-loop-permit-v1", _canonical_json(base)
            ),
            _verification_token=_PERMIT_TOKEN,
        )

    def __post_init__(self) -> None:
        raise PrincipalDriverError(
            "CPU foundation cannot construct a principal scheduled-loop permit"
        )


@dataclass(frozen=True, slots=True)
class PrincipalProvenanceRecord:
    plan_sha256: str
    entry_id: str
    instance_id: str
    comparison_id: str
    generation_seed: int
    repetition: int
    scenario_id: str
    episode_id: str
    stratum: str
    suite_name: str
    user_task_id: str
    injection_task_id: str | None
    pair_id: str | None
    policy_partition: str
    principal_scoring_eligible: bool
    condition: str
    endpoint_attestation_sha256: str
    endpoint_receipt_sha256: str
    dependency_manifest_sha256: str
    model_id: str
    model_revision: str
    model_artifact_sha256: str
    backend: str
    backend_version: str
    policy_manifest_sha256: str
    durable_binding_sha256: str
    topology_binding_sha256: str
    created_monotonic_ns: int
    principal_eligible: bool
    sha256: str
    _plan: PrincipalExecutionPlan = field(repr=False, compare=False)
    _entry: PrincipalScheduleEntry = field(repr=False, compare=False)
    _endpoint_receipt: EndpointProbeReceipt = field(repr=False, compare=False)
    _dependency_manifest: PrincipalDependencyManifest = field(
        repr=False, compare=False
    )

    @classmethod
    def create_contract_test(
        cls,
        *,
        plan: PrincipalExecutionPlan,
        entry: PrincipalScheduleEntry,
        endpoint_receipt: EndpointProbeReceipt,
        dependency_manifest: PrincipalDependencyManifest,
        policy_manifest_sha256: str,
        durable_binding_sha256: str,
        created_monotonic_ns: int,
    ) -> "PrincipalProvenanceRecord":
        if type(plan) is not PrincipalExecutionPlan:
            raise TypeError("provenance plan must be exact")
        if type(entry) is not PrincipalScheduleEntry or plan.entry(entry.entry_id) is not entry:
            raise PrincipalDriverError("provenance entry is not plan-bound")
        if type(endpoint_receipt) is not EndpointProbeReceipt:
            raise TypeError("provenance endpoint receipt must be exact")
        if (
            endpoint_receipt.plan_sha256 != plan.sha256
            or endpoint_receipt.entry_id != entry.entry_id
        ):
            raise PrincipalDriverError("provenance endpoint entry mismatch")
        if type(dependency_manifest) is not PrincipalDependencyManifest:
            raise TypeError("provenance dependency manifest must be exact")
        model_identity = _manifest_model_identity(dependency_manifest)
        if model_identity != _endpoint_model_identity(endpoint_receipt.endpoint):
            raise PrincipalDriverError(
                "provenance manifest and endpoint model identities differ"
            )
        _sha256("policy manifest digest", policy_manifest_sha256)
        _sha256("durable binding digest", durable_binding_sha256)
        _integer("provenance monotonic time", created_monotonic_ns)
        values = {
            "plan_sha256": plan.sha256,
            "entry_id": entry.entry_id,
            "instance_id": entry.instance_id,
            "comparison_id": entry.comparison_id,
            "generation_seed": entry.generation_seed,
            "repetition": entry.repetition,
            "scenario_id": entry.scenario_id,
            "episode_id": entry.episode_id,
            "stratum": entry.stratum,
            "suite_name": entry.suite_name,
            "user_task_id": entry.user_task_id,
            "injection_task_id": entry.injection_task_id,
            "pair_id": entry.pair_id,
            "policy_partition": entry.policy_partition,
            "principal_scoring_eligible": entry.principal_scoring_eligible,
            "condition": entry.condition,
            "endpoint_attestation_sha256": endpoint_receipt.endpoint.sha256,
            "endpoint_receipt_sha256": endpoint_receipt.sha256,
            "dependency_manifest_sha256": dependency_manifest.sha256,
            "model_id": model_identity[0],
            "model_revision": model_identity[1],
            "model_artifact_sha256": model_identity[2],
            "backend": model_identity[3],
            "backend_version": model_identity[4],
            "policy_manifest_sha256": policy_manifest_sha256,
            "durable_binding_sha256": durable_binding_sha256,
            "topology_binding_sha256": endpoint_receipt.topology_binding_sha256,
            "created_monotonic_ns": created_monotonic_ns,
            "principal_eligible": False,
        }
        base = {
            "schema_version": "sluice-agentdojo-principal-provenance-v1",
            **values,
        }
        return cls(
            **values,
            sha256=_digest_bytes(
                b"sluice-agentdojo-principal-provenance-v1", _canonical_json(base)
            ),
            _plan=plan,
            _entry=entry,
            _endpoint_receipt=endpoint_receipt,
            _dependency_manifest=dependency_manifest,
        )

    def __post_init__(self) -> None:
        if type(self._plan) is not PrincipalExecutionPlan or type(
            self._entry
        ) is not PrincipalScheduleEntry:
            raise TypeError("provenance plan/entry binding is invalid")
        if self._plan.entry(self._entry.entry_id) is not self._entry:
            raise PrincipalDriverError("provenance entry object is not plan-bound")
        if (
            self.plan_sha256 != self._plan.sha256
            or self.entry_id != self._entry.entry_id
            or self.condition != self._entry.condition
        ):
            raise PrincipalDriverError("provenance condition or entry binding mismatch")
        for name in (
            "instance_id",
            "comparison_id",
            "scenario_id",
            "episode_id",
            "stratum",
            "suite_name",
            "user_task_id",
            "policy_partition",
        ):
            if getattr(self, name) != getattr(self._entry, name):
                raise PrincipalDriverError("provenance entry coordinate mismatch")
        if (
            self.injection_task_id != self._entry.injection_task_id
            or self.pair_id != self._entry.pair_id
            or self.generation_seed != self._entry.generation_seed
            or self.repetition != self._entry.repetition
            or self.principal_scoring_eligible
            is not self._entry.principal_scoring_eligible
        ):
            raise PrincipalDriverError("provenance entry coordinate mismatch")
        if type(self._endpoint_receipt) is not EndpointProbeReceipt:
            raise TypeError("provenance endpoint binding is invalid")
        if (
            self.endpoint_receipt_sha256 != self._endpoint_receipt.sha256
            or self.endpoint_attestation_sha256
            != self._endpoint_receipt.endpoint.sha256
            or self.topology_binding_sha256
            != self._endpoint_receipt.topology_binding_sha256
        ):
            raise PrincipalDriverError("provenance endpoint binding mismatch")
        if type(self._dependency_manifest) is not PrincipalDependencyManifest or (
            self.dependency_manifest_sha256 != self._dependency_manifest.sha256
        ):
            raise PrincipalDriverError("provenance dependency binding mismatch")
        public_model_identity = _validate_model_identity(
            self.model_id,
            self.model_revision,
            self.model_artifact_sha256,
            self.backend,
            self.backend_version,
            name="provenance",
        )
        if (
            public_model_identity != _manifest_model_identity(self._dependency_manifest)
            or public_model_identity
            != _endpoint_model_identity(self._endpoint_receipt.endpoint)
        ):
            raise PrincipalDriverError(
                "provenance manifest and endpoint model binding mismatch"
            )
        if self.principal_eligible is not False:
            raise PrincipalDriverError("contract provenance cannot be principal eligible")
        _integer("provenance monotonic time", self.created_monotonic_ns)
        for name in (
            "policy_manifest_sha256",
            "durable_binding_sha256",
            "sha256",
        ):
            _sha256(name, getattr(self, name))
        base = self.to_public_wire()
        base.pop("sha256")
        if self.sha256 != _digest_bytes(
            b"sluice-agentdojo-principal-provenance-v1", _canonical_json(base)
        ):
            raise PrincipalDriverError("provenance digest mismatch")

    def to_public_wire(self) -> dict[str, object]:
        return {
            "schema_version": "sluice-agentdojo-principal-provenance-v1",
            "plan_sha256": self.plan_sha256,
            "entry_id": self.entry_id,
            "instance_id": self.instance_id,
            "comparison_id": self.comparison_id,
            "generation_seed": self.generation_seed,
            "repetition": self.repetition,
            "scenario_id": self.scenario_id,
            "episode_id": self.episode_id,
            "stratum": self.stratum,
            "suite_name": self.suite_name,
            "user_task_id": self.user_task_id,
            "injection_task_id": self.injection_task_id,
            "pair_id": self.pair_id,
            "policy_partition": self.policy_partition,
            "principal_scoring_eligible": self.principal_scoring_eligible,
            "condition": self.condition,
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "endpoint_receipt_sha256": self.endpoint_receipt_sha256,
            "dependency_manifest_sha256": self.dependency_manifest_sha256,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "model_artifact_sha256": self.model_artifact_sha256,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "policy_manifest_sha256": self.policy_manifest_sha256,
            "durable_binding_sha256": self.durable_binding_sha256,
            "topology_binding_sha256": self.topology_binding_sha256,
            "created_monotonic_ns": self.created_monotonic_ns,
            "principal_eligible": self.principal_eligible,
            "sha256": self.sha256,
        }


_JOURNAL_SCHEMA = "sluice-agentdojo-create-only-run-journal-v2"
_JOURNAL_SQL = """
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    planned INTEGER NOT NULL,
    attacked_planned INTEGER NOT NULL,
    benign_planned INTEGER NOT NULL
);
CREATE TABLE claims (
    run_id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL UNIQUE,
    plan_sha256 TEXT NOT NULL,
    provenance_sha256 TEXT NOT NULL UNIQUE,
    condition_name TEXT NOT NULL,
    stratum TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    claimed_monotonic_ns INTEGER NOT NULL
);
CREATE TABLE finalizations (
    run_id TEXT PRIMARY KEY REFERENCES claims(run_id),
    termination TEXT NOT NULL,
    model_call_count INTEGER NOT NULL,
    broker_record_count INTEGER NOT NULL,
    raw_evidence_sha256 TEXT NOT NULL
);
CREATE TABLE exports (
    run_id TEXT PRIMARY KEY REFERENCES finalizations(run_id),
    entry_id TEXT NOT NULL UNIQUE,
    canonical_path_sha256 TEXT NOT NULL UNIQUE,
    file_sha256 TEXT NOT NULL UNIQUE,
    record_sha256 TEXT NOT NULL UNIQUE,
    file_device INTEGER NOT NULL,
    file_inode INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    UNIQUE(file_device, file_inode)
);
CREATE TRIGGER metadata_no_update BEFORE UPDATE ON metadata
BEGIN SELECT RAISE(ABORT, 'append-only metadata'); END;
CREATE TRIGGER metadata_no_delete BEFORE DELETE ON metadata
BEGIN SELECT RAISE(ABORT, 'append-only metadata'); END;
CREATE TRIGGER claims_no_update BEFORE UPDATE ON claims
BEGIN SELECT RAISE(ABORT, 'append-only claims'); END;
CREATE TRIGGER claims_no_delete BEFORE DELETE ON claims
BEGIN SELECT RAISE(ABORT, 'append-only claims'); END;
CREATE TRIGGER finalizations_no_update BEFORE UPDATE ON finalizations
BEGIN SELECT RAISE(ABORT, 'append-only finalizations'); END;
CREATE TRIGGER finalizations_no_delete BEFORE DELETE ON finalizations
BEGIN SELECT RAISE(ABORT, 'append-only finalizations'); END;
CREATE TRIGGER exports_no_update BEFORE UPDATE ON exports
BEGIN SELECT RAISE(ABORT, 'append-only exports'); END;
CREATE TRIGGER exports_no_delete BEFORE DELETE ON exports
BEGIN SELECT RAISE(ABORT, 'append-only exports'); END;
"""


@dataclass(frozen=True, slots=True)
class RunJournalSummary:
    planned: int
    attacked_planned: int
    benign_planned: int
    claimed: int
    finalized: int
    unfinalized: int
    pending: int
    termination_counts: Mapping[str, int]


def _strict_regular_identity(file_stat: os.stat_result, *, name: str) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise PrincipalDriverError(f"{name} must be a regular file")
    if file_stat.st_nlink != 1:
        raise PrincipalDriverError(f"{name} must have exactly one link")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise PrincipalDriverError(f"{name} mode must be exactly 0600")


def _strict_regular_state(
    file_stat: os.stat_result,
    *,
    name: str,
    identity: tuple[int, int] | None = None,
    size: int | None = None,
) -> tuple[int, int]:
    _strict_regular_identity(file_stat, name=name)
    observed_identity = (file_stat.st_dev, file_stat.st_ino)
    if identity is not None and observed_identity != identity:
        raise PrincipalDriverError(f"{name} identity changed")
    if size is not None and file_stat.st_size != size:
        raise PrincipalDriverError(f"{name} size changed")
    return observed_identity


def _lexical_absolute_target(path: str | Path) -> Path:
    target = Path(path)
    if not target.name or target.name in {".", ".."}:
        raise PrincipalDriverError("evidence filename is invalid")
    if "\x00" in os.fspath(target):
        raise PrincipalDriverError("evidence path contains a NUL byte")
    if ".." in target.parts:
        raise PrincipalDriverError("evidence path must not contain parent traversal")
    if not target.is_absolute():
        target = Path(os.getcwd()) / target
    if not target.is_absolute() or ".." in target.parts:
        raise PrincipalDriverError("evidence path is not a lexical absolute path")
    return target


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise PrincipalDriverError(f"required open flag {name} is unavailable")
    return value


class _PinnedLexicalParent:
    """Pin every lexical parent component from `/` with descriptor-relative opens."""

    def __init__(self, path: Path, descriptors: list[int]) -> None:
        self.path = path
        self._components = path.parts[1:]
        self._descriptors = descriptors
        self._closed = False

    @classmethod
    def open(cls, path: Path, *, create: bool) -> "_PinnedLexicalParent":
        if not path.is_absolute():
            raise PrincipalDriverError("pinned parent path must be absolute")
        directory_flags = os.O_RDONLY | _required_open_flag("O_DIRECTORY")
        directory_flags |= _required_open_flag("O_NOFOLLOW")
        directory_flags |= _required_open_flag("O_CLOEXEC")
        descriptors = [os.open("/", directory_flags)]
        try:
            for component in path.parts[1:]:
                if component in {"", ".", ".."}:
                    raise PrincipalDriverError(
                        "pinned parent contains an invalid lexical component"
                    )
                try:
                    descriptor = os.open(
                        component,
                        directory_flags,
                        dir_fd=descriptors[-1],
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, 0o700, dir_fd=descriptors[-1])
                    except FileExistsError:
                        pass
                    descriptor = os.open(
                        component,
                        directory_flags,
                        dir_fd=descriptors[-1],
                    )
                component_stat = os.fstat(descriptor)
                if not stat.S_ISDIR(component_stat.st_mode):
                    os.close(descriptor)
                    raise PrincipalDriverError(
                        "pinned lexical parent component is not a directory"
                    )
                descriptors.append(descriptor)
            pinned = cls(path, descriptors)
            # This is a canonical/symlink assertion only. All opens above and all
            # later I/O remain descriptor-relative to the already pinned chain.
            resolved = path.resolve(strict=True)
            if resolved != path:
                raise PrincipalDriverError(
                    "pinned lexical parent is not its canonical path"
                )
            pinned.verify_rebound()
            return pinned
        except BaseException:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    @property
    def descriptor(self) -> int:
        if self._closed:
            raise PrincipalDriverError("pinned lexical parent is closed")
        return self._descriptors[-1]

    @property
    def identity(self) -> tuple[int, int]:
        current = os.fstat(self.descriptor)
        return (current.st_dev, current.st_ino)

    def verify_rebound(self) -> None:
        if self._closed:
            raise PrincipalDriverError("pinned lexical parent is closed")
        for index, component in enumerate(self._components, start=1):
            pinned = os.fstat(self._descriptors[index])
            rebound = os.stat(
                component,
                dir_fd=self._descriptors[index - 1],
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(pinned.st_mode) or not stat.S_ISDIR(
                rebound.st_mode
            ):
                raise PrincipalDriverError(
                    "pinned lexical parent component type changed"
                )
            if (pinned.st_dev, pinned.st_ino) != (
                rebound.st_dev,
                rebound.st_ino,
            ):
                raise PrincipalDriverError(
                    "pinned lexical parent component identity changed"
                )

    def close(self) -> None:
        if self._closed:
            return
        for descriptor in reversed(self._descriptors):
            os.close(descriptor)
        self._closed = True


@dataclass(frozen=True, slots=True)
class _EvidenceFileReceipt:
    canonical_path_sha256: str
    file_sha256: str
    device: int
    inode: int
    size: int


def _write_all(file_descriptor: int, payload: bytes) -> None:
    position = 0
    while position < len(payload):
        written = os.write(file_descriptor, payload[position:])
        if written <= 0:
            raise OSError("short create-only evidence write")
        position += written


def _read_bounded_descriptor(
    descriptor: int, *, maximum: int, name: str
) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1_048_576, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            raise PrincipalDriverError(f"{name} exceeds size bound")
        chunks.append(chunk)


def _rebound_file_state(
    parent: _PinnedLexicalParent,
    basename: str,
    *,
    name: str,
    identity: tuple[int, int],
    size: int,
) -> os.stat_result:
    rebound = os.stat(
        basename,
        dir_fd=parent.descriptor,
        follow_symlinks=False,
    )
    _strict_regular_state(
        rebound,
        name=name,
        identity=identity,
        size=size,
    )
    parent.verify_rebound()
    return rebound


def _file_receipt(target: Path, payload: bytes, state: os.stat_result) -> _EvidenceFileReceipt:
    return _EvidenceFileReceipt(
        canonical_path_sha256=_digest_text(
            b"sluice-agentdojo-canonical-evidence-path-v1", os.fspath(target)
        ),
        file_sha256=hashlib.sha256(payload).hexdigest(),
        device=state.st_dev,
        inode=state.st_ino,
        size=state.st_size,
    )


def _write_json_create_once(
    path: Path, value: Mapping[str, object]
) -> _EvidenceFileReceipt:
    target = _lexical_absolute_target(path)
    parent = _PinnedLexicalParent.open(target.parent, create=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= _required_open_flag("O_NOFOLLOW")
    flags |= _required_open_flag("O_CLOEXEC")
    descriptor = -1
    try:
        parent.verify_rebound()
        descriptor = os.open(target.name, flags, 0o600, dir_fd=parent.descriptor)
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        identity = _strict_regular_state(
            before, name="create-only evidence", size=0
        )
        payload = _canonical_json(dict(value)) + b"\n"
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        same_descriptor_payload = _read_bounded_descriptor(
            descriptor,
            maximum=16_777_216,
            name="create-only evidence",
        )
        if same_descriptor_payload != payload:
            raise PrincipalDriverError("create-only evidence content mismatch")
        after = os.fstat(descriptor)
        _strict_regular_state(
            after,
            name="create-only evidence",
            identity=identity,
            size=len(payload),
        )
        _rebound_file_state(
            parent,
            target.name,
            name="create-only evidence",
            identity=identity,
            size=len(payload),
        )
        os.fsync(parent.descriptor)
        final_payload = _read_bounded_descriptor(
            descriptor,
            maximum=16_777_216,
            name="create-only evidence",
        )
        if hashlib.sha256(final_payload).digest() != hashlib.sha256(payload).digest():
            raise PrincipalDriverError("create-only evidence final digest mismatch")
        final_state = os.fstat(descriptor)
        _strict_regular_state(
            final_state,
            name="create-only evidence",
            identity=identity,
            size=len(payload),
        )
        _rebound_file_state(
            parent,
            target.name,
            name="create-only evidence",
            identity=identity,
            size=len(payload),
        )
        return _file_receipt(target, payload, final_state)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        # A failed create is intentionally left in place. Removing by basename
        # after a replacement would risk deleting an object we did not create.
        parent.close()


def _read_regular_with_receipt(
    path: Path,
) -> tuple[bytes, _EvidenceFileReceipt]:
    target = _lexical_absolute_target(path)
    parent = _PinnedLexicalParent.open(target.parent, create=False)
    flags = os.O_RDONLY | _required_open_flag("O_NOFOLLOW")
    flags |= _required_open_flag("O_CLOEXEC")
    descriptor = -1
    try:
        parent.verify_rebound()
        descriptor = os.open(target.name, flags, dir_fd=parent.descriptor)
        before = os.fstat(descriptor)
        identity = _strict_regular_state(before, name="raw evidence record")
        payload = _read_bounded_descriptor(
            descriptor,
            maximum=16_777_216,
            name="raw evidence record",
        )
        after = os.fstat(descriptor)
        _strict_regular_state(
            after,
            name="raw evidence record",
            identity=identity,
            size=len(payload),
        )
        _rebound_file_state(
            parent,
            target.name,
            name="raw evidence record",
            identity=identity,
            size=len(payload),
        )
        return payload, _file_receipt(target, payload, after)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        parent.close()


def _read_regular_no_follow(path: Path) -> bytes:
    payload, _receipt = _read_regular_with_receipt(path)
    return payload


class CreateOnlyRunJournal:
    """A create-once SQLite file whose run data is insert-only."""

    def __init__(
        self,
        *,
        path: Path,
        plan: PrincipalExecutionPlan,
        connection: sqlite3.Connection,
        pinned_parent: _PinnedLexicalParent,
        database_identity: tuple[int, int],
    ) -> None:
        self.path = path
        self._plan = plan
        self._connection = connection
        self._pinned_parent = pinned_parent
        self._database_identity = database_identity
        self._closed = False

    @classmethod
    def create(
        cls, path: str | Path, *, plan: PrincipalExecutionPlan
    ) -> "CreateOnlyRunJournal":
        if type(plan) is not PrincipalExecutionPlan:
            raise TypeError("journal plan must be exact")
        target = _lexical_absolute_target(path)
        pinned_parent = _PinnedLexicalParent.open(target.parent, create=True)
        connection: sqlite3.Connection | None = None
        try:
            pinned_parent.verify_rebound()
            create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            create_flags |= _required_open_flag("O_NOFOLLOW")
            create_flags |= _required_open_flag("O_CLOEXEC")
            descriptor = os.open(
                target.name,
                create_flags,
                0o600,
                dir_fd=pinned_parent.descriptor,
            )
            try:
                os.fchmod(descriptor, 0o600)
                identity_stat = os.fstat(descriptor)
                database_identity = _strict_regular_state(
                    identity_stat, name="run journal", size=0
                )
            finally:
                os.close(descriptor)
            _rebound_file_state(
                pinned_parent,
                target.name,
                name="run journal",
                identity=database_identity,
                size=0,
            )
            os.fsync(pinned_parent.descriptor)
            proc_path = f"/proc/self/fd/{pinned_parent.descriptor}/{target.name}"
            connection = sqlite3.connect(proc_path, timeout=30.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(_JOURNAL_SQL)
            connection.execute(
                "INSERT INTO metadata VALUES (?, ?, ?, ?, ?, ?)",
                (1, _JOURNAL_SCHEMA, plan.sha256, 20_920, 18_980, 1_940),
            )
            journal = cls(
                path=target,
                plan=plan,
                connection=connection,
                pinned_parent=pinned_parent,
                database_identity=database_identity,
            )
            journal._validate_database_identity()
            os.fsync(pinned_parent.descriptor)
            return journal
        except BaseException:
            if connection is not None:
                connection.close()
            # Preserve a possibly replaced or partially initialized create-only
            # artifact. Basename cleanup is unsafe after any path-identity fault.
            pinned_parent.close()
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise PrincipalDriverError("run journal is closed")

    def _validate_database_identity(self) -> None:
        self._require_open()
        self._pinned_parent.verify_rebound()
        current = os.stat(
            self.path.name,
            dir_fd=self._pinned_parent.descriptor,
            follow_symlinks=False,
        )
        _strict_regular_state(
            current,
            name="run journal",
            identity=self._database_identity,
        )

    def claim_contract_test(self, provenance: PrincipalProvenanceRecord) -> str:
        self._validate_database_identity()
        if type(provenance) is not PrincipalProvenanceRecord:
            raise TypeError("journal claim requires exact provenance")
        if provenance._plan is not self._plan or (
            self._plan.entry(provenance.entry_id) is not provenance._entry
        ):
            raise PrincipalDriverError("journal provenance is not bound to its plan")
        run_id = _digest_text(
            b"sluice-agentdojo-principal-run-v1",
            f"{self._plan.sha256}\0{provenance.entry_id}\0{provenance.sha256}",
        )
        payload = _canonical_json(provenance.to_public_wire()).decode("ascii")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "INSERT INTO claims VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    provenance.entry_id,
                    provenance.plan_sha256,
                    provenance.sha256,
                    provenance.condition,
                    provenance.stratum,
                    payload,
                    provenance.created_monotonic_ns,
                ),
            )
            self._connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            self._connection.execute("ROLLBACK")
            raise PrincipalDriverError("principal entry was already claimed") from exc
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._validate_database_identity()
        return run_id

    def finalize_contract_test(
        self,
        run_id: str,
        *,
        termination: TerminationCategory,
        model_call_count: int,
        broker_record_count: int,
        raw_evidence_sha256: str,
    ) -> None:
        self._validate_database_identity()
        _sha256("run ID", run_id)
        if type(termination) is not TerminationCategory:
            raise TypeError("termination must use the finite category enum")
        _integer("model call count", model_call_count)
        _integer("broker record count", broker_record_count)
        _sha256("raw evidence digest", raw_evidence_sha256)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            cursor = self._connection.execute(
                "SELECT 1 FROM claims WHERE run_id = ?", (run_id,)
            )
            if cursor.fetchone() is None:
                raise PrincipalDriverError("cannot finalize an unclaimed run")
            self._connection.execute(
                "INSERT INTO finalizations VALUES (?, ?, ?, ?, ?)",
                (
                    run_id,
                    termination.value,
                    model_call_count,
                    broker_record_count,
                    raw_evidence_sha256,
                ),
            )
            self._connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            self._connection.execute("ROLLBACK")
            raise PrincipalDriverError("principal run was already finalized") from exc
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._validate_database_identity()

    def summary(self) -> RunJournalSummary:
        self._validate_database_identity()
        claimed = self._connection.execute("SELECT COUNT(*) FROM claims").fetchone()[0]
        finalized = self._connection.execute(
            "SELECT COUNT(*) FROM finalizations"
        ).fetchone()[0]
        counts = {category.value: 0 for category in TerminationCategory}
        for name, count in self._connection.execute(
            "SELECT termination, COUNT(*) FROM finalizations GROUP BY termination"
        ):
            if name not in counts:
                raise PrincipalDriverError("journal contains an unknown termination")
            counts[name] = count
        return RunJournalSummary(
            planned=20_920,
            attacked_planned=18_980,
            benign_planned=1_940,
            claimed=claimed,
            finalized=finalized,
            unfinalized=claimed - finalized,
            pending=20_920 - claimed,
            termination_counts=MappingProxyType(counts),
        )

    def assert_complete(self) -> None:
        summary = self.summary()
        if (
            summary.claimed != summary.planned
            or summary.finalized != summary.planned
            or summary.unfinalized != 0
            or summary.pending != 0
        ):
            raise PrincipalDriverError("principal journal is incomplete")

    def _raw_record_for_run(self, run_id: str) -> dict[str, object]:
        _sha256("run ID", run_id)
        row = self._connection.execute(
            "SELECT c.entry_id, c.plan_sha256, c.provenance_sha256, "
            "c.condition_name, c.stratum, c.provenance_json, "
            "f.termination, f.model_call_count, f.broker_record_count, "
            "f.raw_evidence_sha256 FROM claims c JOIN finalizations f "
            "ON c.run_id = f.run_id WHERE c.run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise PrincipalDriverError("raw record requires a finalized run")
        entry = self._plan.entry(row[0])
        if (
            row[1] != self._plan.sha256
            or row[3] != entry.condition
            or row[4] != entry.stratum
        ):
            raise PrincipalDriverError("journal claim plan/entry binding mismatch")
        expected_run_id = _digest_text(
            b"sluice-agentdojo-principal-run-v1",
            f"{self._plan.sha256}\0{entry.entry_id}\0{row[2]}",
        )
        if run_id != expected_run_id:
            raise PrincipalDriverError("journal run ID derivation mismatch")
        try:
            provenance = json.loads(row[5])
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise PrincipalDriverError("journal provenance JSON is invalid") from exc
        if type(provenance) is not dict:
            raise PrincipalDriverError("journal provenance must be an exact object")
        if _canonical_json(provenance).decode("ascii") != row[5]:
            raise PrincipalDriverError("journal provenance is not canonical")
        if (
            provenance.get("schema_version")
            != "sluice-agentdojo-principal-provenance-v1"
            or provenance.get("sha256") != row[2]
            or provenance.get("plan_sha256") != self._plan.sha256
            or provenance.get("entry_id") != entry.entry_id
            or provenance.get("condition") != entry.condition
            or provenance.get("stratum") != entry.stratum
            or provenance.get("principal_eligible") is not False
        ):
            raise PrincipalDriverError("journal provenance binding mismatch")
        provenance_body = dict(provenance)
        provenance_digest = _sha256(
            "journal provenance digest", provenance_body.pop("sha256", None)
        )
        if provenance_digest != _digest_bytes(
            b"sluice-agentdojo-principal-provenance-v1",
            _canonical_json(provenance_body),
        ):
            raise PrincipalDriverError("journal provenance digest mismatch")
        if row[6] not in {category.value for category in TerminationCategory}:
            raise PrincipalDriverError("journal termination category is invalid")
        _integer("journal model call count", row[7])
        _integer("journal broker record count", row[8])
        _sha256("journal raw evidence digest", row[9])
        record = {
            "schema_version": "sluice-agentdojo-principal-raw-record-v1",
            "plan_sha256": self._plan.sha256,
            "run_id": run_id,
            "entry_id": entry.entry_id,
            "condition": entry.condition,
            "stratum": entry.stratum,
            "termination": row[6],
            "model_call_count": row[7],
            "broker_record_count": row[8],
            "raw_evidence_sha256": row[9],
            "provenance": provenance,
            "principal_outcomes_present": False,
        }
        record["sha256"] = _digest_bytes(
            b"sluice-agentdojo-principal-raw-record-v1", _canonical_json(record)
        )
        return record

    def export_raw_record(self, path: str | Path, *, run_id: str) -> dict[str, object]:
        self._validate_database_identity()
        record = self._raw_record_for_run(run_id)
        receipt = _write_json_create_once(Path(path), record)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "INSERT INTO exports VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    record["entry_id"],
                    receipt.canonical_path_sha256,
                    receipt.file_sha256,
                    record["sha256"],
                    receipt.device,
                    receipt.inode,
                    receipt.size,
                ),
            )
            self._connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            self._connection.execute("ROLLBACK")
            raise PrincipalDriverError(
                "raw export run, entry, path, or content was already bound"
            ) from exc
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._validate_database_identity()
        return record

    def _validate_exported_record(
        self,
        *,
        record: dict[str, object],
        receipt: _EvidenceFileReceipt,
    ) -> None:
        self._validate_database_identity()
        run_id = _sha256("raw record run ID", record.get("run_id"))
        expected = self._raw_record_for_run(run_id)
        if record != expected:
            raise PrincipalDriverError(
                "raw evidence record differs from its journal-produced schema"
            )
        row = self._connection.execute(
            "SELECT entry_id, canonical_path_sha256, file_sha256, "
            "record_sha256, file_device, file_inode, file_size "
            "FROM exports WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise PrincipalDriverError("raw evidence record has no journal export binding")
        observed = (
            record["entry_id"],
            receipt.canonical_path_sha256,
            receipt.file_sha256,
            record["sha256"],
            receipt.device,
            receipt.inode,
            receipt.size,
        )
        if tuple(row) != observed:
            raise PrincipalDriverError("raw evidence export identity mismatch")
        self._validate_database_identity()

    def close(self) -> None:
        if self._closed:
            return
        self._connection.close()
        self._pinned_parent.close()
        self._closed = True

    def __enter__(self) -> "CreateOnlyRunJournal":
        self._require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class RawEvidenceHandoff:
    _RAW_RECORD_FIELDS = frozenset(
        {
            "schema_version",
            "plan_sha256",
            "run_id",
            "entry_id",
            "condition",
            "stratum",
            "termination",
            "model_call_count",
            "broker_record_count",
            "raw_evidence_sha256",
            "provenance",
            "principal_outcomes_present",
            "sha256",
        }
    )

    @staticmethod
    def create_once(
        path: str | Path,
        *,
        journal: CreateOnlyRunJournal,
        plan_sha256: str,
        raw_record_paths: Iterable[str | Path],
    ) -> dict[str, object]:
        if type(journal) is not CreateOnlyRunJournal:
            raise TypeError("raw evidence handoff requires the exact run journal")
        journal._validate_database_identity()
        _sha256("handoff plan digest", plan_sha256)
        if journal._plan.sha256 != plan_sha256:
            raise PrincipalDriverError("handoff journal and plan binding mismatch")
        paths = tuple(Path(item) for item in raw_record_paths)
        if not paths:
            raise PrincipalDriverError("raw evidence handoff must not be empty")
        file_digests: list[str] = []
        record_digests: list[str] = []
        path_digests: list[str] = []
        run_ids: list[str] = []
        entry_ids: list[str] = []
        for record_path in paths:
            payload, receipt = _read_regular_with_receipt(record_path)
            try:
                record = json.loads(payload)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise PrincipalDriverError("raw evidence record is not canonical JSON") from exc
            if (
                type(record) is not dict
                or frozenset(record) != RawEvidenceHandoff._RAW_RECORD_FIELDS
            ):
                raise PrincipalDriverError(
                    "raw evidence record has missing or unexpected schema fields"
                )
            if (
                record.get("schema_version")
                != "sluice-agentdojo-principal-raw-record-v1"
                or record.get("plan_sha256") != plan_sha256
            ):
                raise PrincipalDriverError("raw evidence record plan binding mismatch")
            if record.get("principal_outcomes_present") is not False:
                raise PrincipalDriverError("raw evidence handoff contains principal outcomes")
            if _canonical_json(record) + b"\n" != payload:
                raise PrincipalDriverError("raw evidence record is not canonical")
            claimed_record_digest = _sha256(
                "raw record digest", record.get("sha256")
            )
            digest_body = dict(record)
            digest_body.pop("sha256")
            if claimed_record_digest != _digest_bytes(
                b"sluice-agentdojo-principal-raw-record-v1",
                _canonical_json(digest_body),
            ):
                raise PrincipalDriverError("raw evidence record digest mismatch")
            run_id = _sha256("raw record ID", record.get("run_id"))
            entry_id = _sha256("raw record entry ID", record.get("entry_id"))
            journal._validate_exported_record(record=record, receipt=receipt)
            entry = journal._plan.entry(entry_id)
            if (
                record.get("condition") != entry.condition
                or record.get("stratum") != entry.stratum
            ):
                raise PrincipalDriverError("raw evidence record entry binding mismatch")
            run_ids.append(run_id)
            entry_ids.append(entry_id)
            path_digests.append(receipt.canonical_path_sha256)
            file_digests.append(receipt.file_sha256)
            record_digests.append(claimed_record_digest)
        for name, values in (
            ("canonical paths", path_digests),
            ("run IDs", run_ids),
            ("entry IDs", entry_ids),
            ("file digests", file_digests),
            ("record digests", record_digests),
        ):
            if len(set(values)) != len(values):
                raise PrincipalDriverError(
                    f"raw evidence handoff contains duplicate {name}"
                )
        summary = journal.summary()
        journal_complete = (
            summary.claimed == summary.planned
            and summary.finalized == summary.planned
            and summary.unfinalized == 0
            and summary.pending == 0
        )
        handoff = {
            "schema_version": "sluice-agentdojo-raw-evidence-handoff-v1",
            "plan_sha256": plan_sha256,
            "record_count": len(paths),
            "run_ids": run_ids,
            "entry_ids": entry_ids,
            "canonical_path_sha256": path_digests,
            "record_sha256": file_digests,
            "raw_record_digest": record_digests,
            "journal_complete": journal_complete,
            "evaluation_eligible": False,
            "principal_outcomes_present": False,
        }
        handoff["sha256"] = _digest_bytes(
            b"sluice-agentdojo-raw-evidence-handoff-v1", _canonical_json(handoff)
        )
        _write_json_create_once(Path(path), handoff)
        return handoff


__all__ = [
    "CreateOnlyRunJournal",
    "EndpointProbeMode",
    "EndpointProbeReceipt",
    "OfficialToolFilterBaseline",
    "PINNED_PRINCIPAL_PLAN_SHA256",
    "PRINCIPAL_REPETITIONS_PER_SEED",
    "PRINCIPAL_SEEDS",
    "PolicyAuthorSplit",
    "PrincipalComparison",
    "PrincipalCondition",
    "PrincipalDependencyManifest",
    "PrincipalDependencyObservation",
    "PrincipalDriverError",
    "PrincipalEligibilityAssessment",
    "PrincipalExecutionPlan",
    "PrincipalProvenanceRecord",
    "PrincipalScenario",
    "PrincipalScheduleEntry",
    "PrincipalScheduleInstance",
    "ProcessTopologyAttestation",
    "RawEvidenceHandoff",
    "RunJournalSummary",
    "ScheduledLoopPermit",
    "TerminationCategory",
    "principal_plan_sha256",
]
