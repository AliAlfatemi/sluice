"""CPU-only integration contract for a future isolated model endpoint.

The module exercises an in-process fake callable whose identity is restricted
to an already validated numeric-loopback URL.  It never opens a socket, loads a
model, touches CUDA, evaluates a task, invokes a detector, or admits a
principal result.  Its purpose is to bind the two committed principal plans to
one finite request/reply protocol before any live implementation is enabled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Mapping

from ..durable_service import PeerIdentity
from ..rocky_gpu_isolation import BACKEND_ID as ROCKY_BACKEND_ID
from ..rocky_gpu_isolation import MAX_PACKET_BYTES
from ..rocky_gpu_isolation import SCHEMA_VERSION as ROCKY_SCHEMA_VERSION
from ..runtime_staging import PROTOCOL_ID as RUNTIME_PROTOCOL_ID
from ..runtime_staging import SCHEMA_VERSION as RUNTIME_SCHEMA_VERSION
from .agentdojo_live import (
    EndpointAttestation,
    EndpointExpectation,
    EndpointObservation,
    LivePipelineError,
)
from .agentdojo_principal_driver import (
    PINNED_PRINCIPAL_PLAN_SHA256,
    PrincipalExecutionPlan as AgentDojoExecutionPlan,
    PrincipalScheduleEntry as AgentDojoScheduleEntry,
    ProcessTopologyAttestation,
)
from .agentleak_principal_driver import (
    ExecutionArm as AgentLeakExecutionArm,
    FrozenExecutionPlan as AgentLeakExecutionPlan,
)


PROTOCOL_ID = "sluice-principal-cpu-loopback-integration-v1"
TRANSPORT_MODE = "cpu_fake_loopback_callable_only"
PEER_IDENTITY_MODE = "synthetic_cpu_api_only"
MAX_ATTEMPTS = 2
CHRONOLOGY_HMAX = 16
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_.:-]{1,256}\Z")
_MODEL_ID_RE = re.compile(r"[A-Za-z0-9._/-]{1,512}\Z")
_SCHEDULE_TOKEN = object()
_SCHEDULE_SNAPSHOT_TOKEN = object()
_PERMIT_TOKEN = object()
_CHRONOLOGY_TOKEN = object()
_RECEIPT_TOKEN = object()
_EVIDENCE_TOKEN = object()

_ADMISSION_LOCK = threading.Lock()
_CLAIMED_SCHEDULE_BINDINGS: set[str] = set()


class LiveEndpointIntegrationError(ValueError):
    """The CPU-only endpoint integration contract failed closed."""


class BenchmarkKind(str, Enum):
    AGENTDOJO = "agentdojo"
    AGENTLEAK = "agentleak"


class EndpointRole(str, Enum):
    MONITOR = "monitor"
    BROKER = "broker"
    MODEL_DRIVER = "model_driver"


class FakeRetryPolicy(str, Enum):
    NEVER = "never"
    ONCE = "once"
    ALWAYS = "always"


class FakeReplyStatus(str, Enum):
    CPU_FAKE_ACK = "CPU_FAKE_ACK"
    CPU_FAKE_RETRYABLE = "CPU_FAKE_RETRYABLE"


class CpuExchangeStatus(str, Enum):
    CPU_FAKE_COMPLETED = "CPU_FAKE_COMPLETED"
    CPU_FAKE_RETRY_EXHAUSTED = "CPU_FAKE_RETRY_EXHAUSTED"


class ChronologyKind(str, Enum):
    PREFLIGHT = "PREFLIGHT"
    REQUEST = "REQUEST"
    REPLY = "REPLY"
    TERMINAL = "TERMINAL"
    PAD = "PAD"


def _canonical_json(value: object, *, maximum: int = MAX_PACKET_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise LiveEndpointIntegrationError("value is not finite canonical JSON") from exc
    if not encoded or len(encoded) > maximum:
        raise LiveEndpointIntegrationError("canonical JSON exceeds its finite bound")
    return encoded


def _digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + b"\0" + _canonical_json(value)).hexdigest()


def _digest_text(domain: bytes, value: str) -> str:
    return hashlib.sha256(domain + b"\0" + value.encode("utf-8")).hexdigest()


def _sha256(name: str, value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise LiveEndpointIntegrationError(f"{name} must be a lowercase SHA-256")
    return value


def _revision(name: str, value: object) -> str:
    if type(value) is not str or _REVISION_RE.fullmatch(value) is None:
        raise LiveEndpointIntegrationError(f"{name} must be a pinned 40-hex revision")
    return value


def _identifier(name: str, value: object) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise LiveEndpointIntegrationError(f"{name} is not a canonical identifier")
    return value


def _text(name: str, value: object, *, maximum: int = 512) -> str:
    if type(value) is not str:
        raise LiveEndpointIntegrationError(f"{name} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise LiveEndpointIntegrationError(f"{name} is not UTF-8") from exc
    if not encoded or len(encoded) > maximum or b"\0" in encoded or b"\n" in encoded:
        raise LiveEndpointIntegrationError(f"{name} has an invalid finite encoding")
    return value


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise LiveEndpointIntegrationError(f"{name} is outside its finite range")
    return value


def _literal(name: str, value: object, expected: str | int) -> str | int:
    if type(value) is not type(expected) or value != expected:
        raise LiveEndpointIntegrationError(f"{name} is not the exact protocol literal")
    return value


def _false(name: str, value: object) -> bool:
    if value is not False:
        raise LiveEndpointIntegrationError(f"{name} must be exact False")
    return False


def _true(name: str, value: object) -> bool:
    if value is not True:
        raise LiveEndpointIntegrationError(f"{name} must be exact True")
    return True


def _exact_object(name: str, value: object, fields: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise LiveEndpointIntegrationError(f"{name} must be an exact dictionary")
    if frozenset(value) != fields:
        raise LiveEndpointIntegrationError(f"{name} has missing or unexpected fields")
    return value


@dataclass(frozen=True, slots=True)
class PinnedModelIdentity:
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
        model_id: str,
        model_revision: str,
        model_artifact_sha256: str,
        backend: str,
        backend_version: str,
    ) -> "PinnedModelIdentity":
        if type(model_id) is not str or _MODEL_ID_RE.fullmatch(model_id) is None:
            raise LiveEndpointIntegrationError("model ID is not canonical")
        _revision("model revision", model_revision)
        _sha256("model artifact", model_artifact_sha256)
        _literal("backend", backend, "vllm")
        _text("backend version", backend_version)
        base = {
            "backend": backend,
            "backend_version": backend_version,
            "model_artifact_sha256": model_artifact_sha256,
            "model_id": model_id,
            "model_revision": model_revision,
            "schema_version": "sluice-pinned-model-identity-v1",
        }
        return cls(
            model_id=model_id,
            model_revision=model_revision,
            model_artifact_sha256=model_artifact_sha256,
            backend=backend,
            backend_version=backend_version,
            sha256=_digest(b"sluice-pinned-model-identity-v1", base),
        )

    def __post_init__(self) -> None:
        if type(self) is not PinnedModelIdentity:
            raise LiveEndpointIntegrationError("model identity subclasses are forbidden")
        if _MODEL_ID_RE.fullmatch(_text("model ID", self.model_id)) is None:
            raise LiveEndpointIntegrationError("model ID is not canonical")
        _revision("model revision", self.model_revision)
        _sha256("model artifact", self.model_artifact_sha256)
        _literal("backend", self.backend, "vllm")
        _text("backend version", self.backend_version)
        _sha256("model identity", self.sha256)
        if self.sha256 != _digest(
            b"sluice-pinned-model-identity-v1", self.to_wire_without_hash()
        ):
            raise LiveEndpointIntegrationError("model identity digest mismatch")

    def to_wire_without_hash(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "backend_version": self.backend_version,
            "model_artifact_sha256": self.model_artifact_sha256,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "schema_version": "sluice-pinned-model-identity-v1",
        }

    def to_wire(self) -> dict[str, object]:
        return {**self.to_wire_without_hash(), "sha256": self.sha256}

    @property
    def identity_tuple(self) -> tuple[str, str, str, str, str]:
        return (
            self.model_id,
            self.model_revision,
            self.model_artifact_sha256,
            self.backend,
            self.backend_version,
        )

    def expectation(self, endpoint_url: str) -> EndpointExpectation:
        try:
            return EndpointExpectation(
                endpoint_url=endpoint_url,
                model_id=self.model_id,
                model_revision=self.model_revision,
                model_artifact_sha256=self.model_artifact_sha256,
                backend=self.backend,
                backend_version=self.backend_version,
            )
        except (LivePipelineError, TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError("endpoint expectation is invalid") from exc


@dataclass(frozen=True, slots=True)
class RuntimeIsolationPins:
    runtime_protocol_id: str
    runtime_schema_version: int
    runtime_tree_sha256: str
    runtime_source_commit: str
    isolation_backend_id: str
    isolation_schema_version: int
    isolation_config_sha256: str
    node_local_xfs_verified: bool
    strict_isolation_verified: bool
    cuda_allocation_verified: bool
    model_execution_verified: bool
    principal_eligible: bool
    sha256: str

    @classmethod
    def for_cpu_test(
        cls,
        *,
        runtime_tree_sha256: str,
        runtime_source_commit: str,
        isolation_config_sha256: str,
    ) -> "RuntimeIsolationPins":
        _sha256("runtime tree", runtime_tree_sha256)
        _revision("runtime source commit", runtime_source_commit)
        _sha256("isolation config", isolation_config_sha256)
        base = {
            "cuda_allocation_verified": False,
            "isolation_backend_id": ROCKY_BACKEND_ID,
            "isolation_config_sha256": isolation_config_sha256,
            "isolation_schema_version": ROCKY_SCHEMA_VERSION,
            "model_execution_verified": False,
            "node_local_xfs_verified": False,
            "principal_eligible": False,
            "runtime_protocol_id": RUNTIME_PROTOCOL_ID,
            "runtime_schema_version": RUNTIME_SCHEMA_VERSION,
            "runtime_source_commit": runtime_source_commit,
            "runtime_tree_sha256": runtime_tree_sha256,
            "schema_version": "sluice-runtime-isolation-pins-v1",
            "strict_isolation_verified": False,
        }
        return cls(
            runtime_protocol_id=RUNTIME_PROTOCOL_ID,
            runtime_schema_version=RUNTIME_SCHEMA_VERSION,
            runtime_tree_sha256=runtime_tree_sha256,
            runtime_source_commit=runtime_source_commit,
            isolation_backend_id=ROCKY_BACKEND_ID,
            isolation_schema_version=ROCKY_SCHEMA_VERSION,
            isolation_config_sha256=isolation_config_sha256,
            node_local_xfs_verified=False,
            strict_isolation_verified=False,
            cuda_allocation_verified=False,
            model_execution_verified=False,
            principal_eligible=False,
            sha256=_digest(b"sluice-runtime-isolation-pins-v1", base),
        )

    def __post_init__(self) -> None:
        if type(self) is not RuntimeIsolationPins:
            raise LiveEndpointIntegrationError("runtime-pin subclasses are forbidden")
        _literal("runtime protocol ID", self.runtime_protocol_id, RUNTIME_PROTOCOL_ID)
        _literal(
            "runtime schema version",
            self.runtime_schema_version,
            RUNTIME_SCHEMA_VERSION,
        )
        _literal("isolation backend ID", self.isolation_backend_id, ROCKY_BACKEND_ID)
        _literal(
            "isolation schema version",
            self.isolation_schema_version,
            ROCKY_SCHEMA_VERSION,
        )
        _sha256("runtime tree", self.runtime_tree_sha256)
        _revision("runtime source commit", self.runtime_source_commit)
        _sha256("isolation config", self.isolation_config_sha256)
        flags = (
            self.node_local_xfs_verified,
            self.strict_isolation_verified,
            self.cuda_allocation_verified,
            self.model_execution_verified,
            self.principal_eligible,
        )
        if any(type(value) is not bool or value for value in flags):
            raise LiveEndpointIntegrationError("CPU pins cannot assert a live/GPU gate")
        _sha256("runtime/isolation pin", self.sha256)
        if self.sha256 != _digest(
            b"sluice-runtime-isolation-pins-v1", self.to_wire_without_hash()
        ):
            raise LiveEndpointIntegrationError("runtime/isolation pin digest mismatch")

    def to_wire_without_hash(self) -> dict[str, object]:
        return {
            "cuda_allocation_verified": self.cuda_allocation_verified,
            "isolation_backend_id": self.isolation_backend_id,
            "isolation_config_sha256": self.isolation_config_sha256,
            "isolation_schema_version": self.isolation_schema_version,
            "model_execution_verified": self.model_execution_verified,
            "node_local_xfs_verified": self.node_local_xfs_verified,
            "principal_eligible": self.principal_eligible,
            "runtime_protocol_id": self.runtime_protocol_id,
            "runtime_schema_version": self.runtime_schema_version,
            "runtime_source_commit": self.runtime_source_commit,
            "runtime_tree_sha256": self.runtime_tree_sha256,
            "schema_version": "sluice-runtime-isolation-pins-v1",
            "strict_isolation_verified": self.strict_isolation_verified,
        }

    def to_wire(self) -> dict[str, object]:
        return {**self.to_wire_without_hash(), "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class ScheduleBinding:
    benchmark: BenchmarkKind
    plan_sha256: str
    schedule_unit_sha256: str
    condition: str
    generation_seed: int
    binding_sha256: str
    _plan: object = field(repr=False, compare=False)
    _unit: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    @classmethod
    def for_agentdojo(
        cls, *, plan: AgentDojoExecutionPlan, entry: AgentDojoScheduleEntry
    ) -> "ScheduleBinding":
        if type(plan) is not AgentDojoExecutionPlan or type(entry) is not AgentDojoScheduleEntry:
            raise LiveEndpointIntegrationError("AgentDojo schedule types are not exact")
        try:
            plan.validate_provenance()
        except (TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError(
                "AgentDojo plan was not deeply authenticated"
            ) from exc
        if (
            plan.sha256 != PINNED_PRINCIPAL_PLAN_SHA256
            or plan.entry(entry.entry_id) is not entry
            or plan.principal_outcomes_present is not False
        ):
            raise LiveEndpointIntegrationError("AgentDojo entry is not plan-bound")
        unit_sha = _digest_text(b"sluice-schedule-unit-agentdojo-v1", entry.entry_id)
        base = {
            "benchmark": BenchmarkKind.AGENTDOJO.value,
            "condition": entry.condition,
            "generation_seed": entry.generation_seed,
            "plan_sha256": plan.sha256,
            "schedule_unit_sha256": unit_sha,
            "schema_version": "sluice-schedule-binding-v1",
        }
        return cls(
            benchmark=BenchmarkKind.AGENTDOJO,
            plan_sha256=plan.sha256,
            schedule_unit_sha256=unit_sha,
            condition=entry.condition,
            generation_seed=entry.generation_seed,
            binding_sha256=_digest(b"sluice-schedule-binding-v1", base),
            _plan=plan,
            _unit=entry,
            _token=_SCHEDULE_TOKEN,
        )

    @classmethod
    def for_agentleak(
        cls, *, plan: AgentLeakExecutionPlan, arm: AgentLeakExecutionArm
    ) -> "ScheduleBinding":
        if type(plan) is not AgentLeakExecutionPlan or type(arm) is not AgentLeakExecutionArm:
            raise LiveEndpointIntegrationError("AgentLeak schedule types are not exact")
        try:
            plan.__post_init__()
        except (TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError(
                "AgentLeak plan exact deep authentication failed"
            ) from exc
        if (
            type(plan.schema_version) is not str
            or type(plan.execution_mode) is not str
            or type(plan.scenario_count) is not int
            or type(plan.seeds) is not tuple
            or any(type(seed) is not int for seed in plan.seeds)
            or type(plan.model_revision) is not str
            or type(plan.frozen) is not bool
        ):
            raise LiveEndpointIntegrationError("AgentLeak plan fields are not exact built-ins")
        if not any(candidate is arm for block in plan.blocks for candidate in block.arms):
            raise LiveEndpointIntegrationError("AgentLeak arm is not object-bound to the plan")
        unit_sha = _digest_text(b"sluice-schedule-unit-agentleak-v1", arm.attempt_id)
        base = {
            "benchmark": BenchmarkKind.AGENTLEAK.value,
            "condition": arm.condition.value,
            "generation_seed": arm.seed,
            "plan_sha256": plan.plan_sha256,
            "schedule_unit_sha256": unit_sha,
            "schema_version": "sluice-schedule-binding-v1",
        }
        return cls(
            benchmark=BenchmarkKind.AGENTLEAK,
            plan_sha256=plan.plan_sha256,
            schedule_unit_sha256=unit_sha,
            condition=arm.condition.value,
            generation_seed=arm.seed,
            binding_sha256=_digest(b"sluice-schedule-binding-v1", base),
            _plan=plan,
            _unit=arm,
            _token=_SCHEDULE_TOKEN,
        )

    def __post_init__(self) -> None:
        if type(self) is not ScheduleBinding or self._token is not _SCHEDULE_TOKEN:
            raise LiveEndpointIntegrationError("schedule binding was not factory minted")
        self.revalidate()

    def revalidate(self) -> None:
        """Revalidate the immutable compact fields without walking a full plan."""
        if type(self) is not ScheduleBinding or self._token is not _SCHEDULE_TOKEN:
            raise LiveEndpointIntegrationError("schedule binding was not factory minted")
        if type(self.benchmark) is not BenchmarkKind:
            raise LiveEndpointIntegrationError("unknown benchmark binding")
        _sha256("plan", self.plan_sha256)
        _sha256("schedule unit", self.schedule_unit_sha256)
        _text("condition", self.condition)
        _integer("generation seed", self.generation_seed, minimum=0, maximum=2**63 - 1)
        _sha256("schedule binding", self.binding_sha256)
        if self.binding_sha256 != _digest(
            b"sluice-schedule-binding-v1", self.to_public_wire_without_hash()
        ):
            raise LiveEndpointIntegrationError("schedule binding digest mismatch")

    def revalidate_source(self) -> None:
        """Deeply revalidate the source plan once, immediately before admission."""
        self.revalidate()
        if self.benchmark is BenchmarkKind.AGENTDOJO:
            if (
                type(self._plan) is not AgentDojoExecutionPlan
                or type(self._unit) is not AgentDojoScheduleEntry
            ):
                raise LiveEndpointIntegrationError(
                    "AgentDojo schedule binding types drifted"
                )
            try:
                self._plan.revalidate()
            except (TypeError, ValueError) as exc:
                raise LiveEndpointIntegrationError(
                    "AgentDojo source plan failed deep reauthentication"
                ) from exc
            if (
                self._plan.sha256 != PINNED_PRINCIPAL_PLAN_SHA256
                or self._plan.entry(self._unit.entry_id) is not self._unit
                or self._plan.principal_outcomes_present is not False
                or self.plan_sha256 != self._plan.sha256
                or self.condition != self._unit.condition
                or self.generation_seed != self._unit.generation_seed
                or self.schedule_unit_sha256
                != _digest_text(b"sluice-schedule-unit-agentdojo-v1", self._unit.entry_id)
            ):
                raise LiveEndpointIntegrationError("AgentDojo schedule binding drifted")
        elif self.benchmark is BenchmarkKind.AGENTLEAK:
            if type(self._plan) is not AgentLeakExecutionPlan or type(
                self._unit
            ) is not AgentLeakExecutionArm:
                raise LiveEndpointIntegrationError("AgentLeak schedule binding types drifted")
            try:
                self._plan.__post_init__()
            except (TypeError, ValueError) as exc:
                raise LiveEndpointIntegrationError(
                    "AgentLeak source plan exact deep reauthentication failed"
                ) from exc
            if (
                type(self._plan.schema_version) is not str
                or type(self._plan.execution_mode) is not str
                or type(self._plan.scenario_count) is not int
                or type(self._plan.seeds) is not tuple
                or any(type(seed) is not int for seed in self._plan.seeds)
                or type(self._plan.model_revision) is not str
                or type(self._plan.frozen) is not bool
            ):
                raise LiveEndpointIntegrationError(
                    "AgentLeak source plan fields drifted from exact built-ins"
                )
            if (
                not any(
                    candidate is self._unit
                    for block in self._plan.blocks
                    for candidate in block.arms
                )
                or self.plan_sha256 != self._plan.plan_sha256
                or self.condition != self._unit.condition.value
                or self.generation_seed != self._unit.seed
                or self.schedule_unit_sha256
                != _digest_text(b"sluice-schedule-unit-agentleak-v1", self._unit.attempt_id)
            ):
                raise LiveEndpointIntegrationError("AgentLeak schedule binding drifted")
        else:
            raise LiveEndpointIntegrationError("unknown benchmark binding")

    def to_public_wire_without_hash(self) -> dict[str, object]:
        return {
            "benchmark": self.benchmark.value,
            "condition": self.condition,
            "generation_seed": self.generation_seed,
            "plan_sha256": self.plan_sha256,
            "schedule_unit_sha256": self.schedule_unit_sha256,
            "schema_version": "sluice-schedule-binding-v1",
        }

    def to_public_wire(self) -> dict[str, object]:
        return {**self.to_public_wire_without_hash(), "binding_sha256": self.binding_sha256}


@dataclass(frozen=True, slots=True)
class _ScheduleBindingSnapshot:
    benchmark: BenchmarkKind
    plan_sha256: str
    schedule_unit_sha256: str
    condition: str
    generation_seed: int
    binding_sha256: str
    _token: object = field(repr=False, compare=False)

    @classmethod
    def freeze(cls, binding: ScheduleBinding) -> "_ScheduleBindingSnapshot":
        if type(binding) is not ScheduleBinding:
            raise LiveEndpointIntegrationError("schedule snapshot source type is not exact")
        binding.revalidate()
        return cls(
            benchmark=binding.benchmark,
            plan_sha256=binding.plan_sha256,
            schedule_unit_sha256=binding.schedule_unit_sha256,
            condition=binding.condition,
            generation_seed=binding.generation_seed,
            binding_sha256=binding.binding_sha256,
            _token=_SCHEDULE_SNAPSHOT_TOKEN,
        )

    def __post_init__(self) -> None:
        self.revalidate()

    def revalidate(self) -> None:
        if (
            type(self) is not _ScheduleBindingSnapshot
            or self._token is not _SCHEDULE_SNAPSHOT_TOKEN
            or type(self.benchmark) is not BenchmarkKind
        ):
            raise LiveEndpointIntegrationError("schedule snapshot provenance is invalid")
        _sha256("snapshot plan", self.plan_sha256)
        _sha256("snapshot unit", self.schedule_unit_sha256)
        _text("snapshot condition", self.condition)
        _integer(
            "snapshot generation seed",
            self.generation_seed,
            minimum=0,
            maximum=2**63 - 1,
        )
        base = {
            "benchmark": self.benchmark.value,
            "condition": self.condition,
            "generation_seed": self.generation_seed,
            "plan_sha256": self.plan_sha256,
            "schedule_unit_sha256": self.schedule_unit_sha256,
            "schema_version": "sluice-schedule-binding-v1",
        }
        if self.binding_sha256 != _digest(b"sluice-schedule-binding-v1", base):
            raise LiveEndpointIntegrationError("schedule snapshot digest mismatch")


@dataclass(frozen=True, slots=True)
class CpuIntegrationPermit:
    session_sha256: str
    plan_sha256: str
    schedule_binding_sha256: str
    model_identity_sha256: str
    runtime_isolation_sha256: str
    topology_binding_sha256: str
    endpoint_attestation_sha256: str
    transport_mode: str
    peer_identity_mode: str
    principal_eligible: bool
    sha256: str
    _schedule: _ScheduleBindingSnapshot = field(repr=False, compare=False)
    _model: PinnedModelIdentity = field(repr=False, compare=False)
    _runtime: RuntimeIsolationPins = field(repr=False, compare=False)
    _topology: ProcessTopologyAttestation = field(repr=False, compare=False)
    _endpoint_attestation: EndpointAttestation = field(repr=False, compare=False)
    _expectation: EndpointExpectation = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not CpuIntegrationPermit or self._token is not _PERMIT_TOKEN:
            raise LiveEndpointIntegrationError("CPU integration permit was not verified")
        self.revalidate()

    def revalidate(self) -> None:
        for name in (
            "session_sha256",
            "plan_sha256",
            "schedule_binding_sha256",
            "model_identity_sha256",
            "runtime_isolation_sha256",
            "topology_binding_sha256",
            "endpoint_attestation_sha256",
        ):
            _sha256(name, getattr(self, name))
        _literal("permit transport mode", self.transport_mode, TRANSPORT_MODE)
        _literal("permit peer identity mode", self.peer_identity_mode, PEER_IDENTITY_MODE)
        _false("permit principal eligibility", self.principal_eligible)
        if type(self._schedule) is not _ScheduleBindingSnapshot:
            raise LiveEndpointIntegrationError("permit schedule snapshot type is not exact")
        self._schedule.revalidate()
        if type(self._model) is not PinnedModelIdentity:
            raise LiveEndpointIntegrationError("permit model type is not exact")
        self._model.__post_init__()
        if type(self._runtime) is not RuntimeIsolationPins:
            raise LiveEndpointIntegrationError("permit runtime type is not exact")
        self._runtime.__post_init__()
        if type(self._topology) is not ProcessTopologyAttestation:
            raise LiveEndpointIntegrationError("permit topology type is not exact")
        self._topology.__post_init__()
        if type(self._endpoint_attestation) is not EndpointAttestation:
            raise LiveEndpointIntegrationError("permit endpoint type is not exact")
        self._endpoint_attestation.revalidate()
        if type(self._expectation) is not EndpointExpectation:
            raise LiveEndpointIntegrationError("permit endpoint expectation is not exact")
        endpoint_identity = (
            self._endpoint_attestation.model_id,
            self._endpoint_attestation.model_revision,
            self._endpoint_attestation.model_artifact_sha256,
            self._endpoint_attestation.backend,
            self._endpoint_attestation.backend_version,
        )
        if endpoint_identity != self._model.identity_tuple:
            raise LiveEndpointIntegrationError("permit model/endpoint identity mismatch")
        if (
            self.plan_sha256 != self._schedule.plan_sha256
            or self.schedule_binding_sha256 != self._schedule.binding_sha256
            or self.model_identity_sha256 != self._model.sha256
            or self.runtime_isolation_sha256 != self._runtime.sha256
            or self.topology_binding_sha256 != self._topology.binding_sha256
            or self.endpoint_attestation_sha256 != self._endpoint_attestation.sha256
        ):
            raise LiveEndpointIntegrationError("CPU permit binding or false gate drifted")
        session_base = {
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "model_identity_sha256": self.model_identity_sha256,
            "peer_identity_mode": self.peer_identity_mode,
            "plan_sha256": self.plan_sha256,
            "runtime_isolation_sha256": self.runtime_isolation_sha256,
            "schedule_binding_sha256": self.schedule_binding_sha256,
            "topology_binding_sha256": self.topology_binding_sha256,
            "transport_mode": self.transport_mode,
        }
        if self.session_sha256 != _digest(b"sluice-cpu-loopback-session-v1", session_base):
            raise LiveEndpointIntegrationError("CPU session digest mismatch")
        _sha256("CPU permit", self.sha256)
        if self.sha256 != _digest(
            b"sluice-cpu-integration-permit-v1", self.to_public_wire_without_hash()
        ):
            raise LiveEndpointIntegrationError("CPU permit digest mismatch")

    def to_public_wire_without_hash(self) -> dict[str, object]:
        return {
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "model_identity_sha256": self.model_identity_sha256,
            "peer_identity_mode": self.peer_identity_mode,
            "plan_sha256": self.plan_sha256,
            "principal_eligible": self.principal_eligible,
            "runtime_isolation_sha256": self.runtime_isolation_sha256,
            "schedule_binding_sha256": self.schedule_binding_sha256,
            "schema_version": "sluice-cpu-integration-permit-v1",
            "session_sha256": self.session_sha256,
            "topology_binding_sha256": self.topology_binding_sha256,
            "transport_mode": self.transport_mode,
        }

    def to_public_wire(self) -> dict[str, object]:
        return {**self.to_public_wire_without_hash(), "sha256": self.sha256}


_REQUEST_FIELDS = frozenset(
    {
        "attempt_number",
        "endpoint_attestation_sha256",
        "input_commitment_sha256",
        "model_identity_sha256",
        "plan_sha256",
        "principal_outcome_count",
        "request_id",
        "role",
        "runtime_isolation_sha256",
        "schedule_binding_sha256",
        "schema_version",
        "session_sha256",
        "sha256",
        "transport_mode",
    }
)


def cpu_request_sha256(wire: Mapping[str, object]) -> str:
    if type(wire) is not dict:
        raise LiveEndpointIntegrationError("CPU request must be an exact dictionary")
    base = dict(wire)
    base.pop("sha256", None)
    return _digest(b"sluice-cpu-loopback-request-v1", base)


@dataclass(frozen=True, slots=True)
class CpuLoopbackRequest:
    schema_version: str
    transport_mode: str
    session_sha256: str
    plan_sha256: str
    schedule_binding_sha256: str
    model_identity_sha256: str
    runtime_isolation_sha256: str
    endpoint_attestation_sha256: str
    request_id: str
    attempt_number: int
    role: EndpointRole
    input_commitment_sha256: str
    principal_outcome_count: int
    sha256: str

    @classmethod
    def create(
        cls,
        *,
        permit: CpuIntegrationPermit,
        request_id: str,
        attempt_number: int,
        input_commitment_sha256: str,
    ) -> "CpuLoopbackRequest":
        if type(permit) is not CpuIntegrationPermit:
            raise LiveEndpointIntegrationError("request permit type is not exact")
        permit.revalidate()
        _identifier("request ID", request_id)
        _integer("attempt number", attempt_number, minimum=1, maximum=MAX_ATTEMPTS)
        _sha256("input commitment", input_commitment_sha256)
        base = {
            "attempt_number": attempt_number,
            "endpoint_attestation_sha256": permit.endpoint_attestation_sha256,
            "input_commitment_sha256": input_commitment_sha256,
            "model_identity_sha256": permit.model_identity_sha256,
            "plan_sha256": permit.plan_sha256,
            "principal_outcome_count": 0,
            "request_id": request_id,
            "role": EndpointRole.BROKER.value,
            "runtime_isolation_sha256": permit.runtime_isolation_sha256,
            "schedule_binding_sha256": permit.schedule_binding_sha256,
            "schema_version": "sluice-cpu-loopback-request-v1",
            "session_sha256": permit.session_sha256,
            "transport_mode": TRANSPORT_MODE,
        }
        return cls(
            schema_version=base["schema_version"],
            transport_mode=base["transport_mode"],
            session_sha256=base["session_sha256"],
            plan_sha256=base["plan_sha256"],
            schedule_binding_sha256=base["schedule_binding_sha256"],
            model_identity_sha256=base["model_identity_sha256"],
            runtime_isolation_sha256=base["runtime_isolation_sha256"],
            endpoint_attestation_sha256=base["endpoint_attestation_sha256"],
            request_id=base["request_id"],
            attempt_number=base["attempt_number"],
            role=EndpointRole.BROKER,
            input_commitment_sha256=base["input_commitment_sha256"],
            principal_outcome_count=0,
            sha256=_digest(b"sluice-cpu-loopback-request-v1", base),
        )

    def __post_init__(self) -> None:
        if type(self) is not CpuLoopbackRequest:
            raise LiveEndpointIntegrationError("CPU request subclasses are forbidden")
        _literal(
            "CPU request schema",
            self.schema_version,
            "sluice-cpu-loopback-request-v1",
        )
        _literal("CPU request transport", self.transport_mode, TRANSPORT_MODE)
        if self.role is not EndpointRole.BROKER:
            raise LiveEndpointIntegrationError("CPU request role is invalid")
        _integer(
            "CPU request principal outcome count",
            self.principal_outcome_count,
            minimum=0,
            maximum=0,
        )
        for name in (
            "session_sha256",
            "plan_sha256",
            "schedule_binding_sha256",
            "model_identity_sha256",
            "runtime_isolation_sha256",
            "endpoint_attestation_sha256",
            "input_commitment_sha256",
            "sha256",
        ):
            _sha256(name, getattr(self, name))
        _identifier("request ID", self.request_id)
        _integer("attempt number", self.attempt_number, minimum=1, maximum=MAX_ATTEMPTS)
        if self.sha256 != cpu_request_sha256(self.to_wire()):
            raise LiveEndpointIntegrationError("CPU request digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "attempt_number": self.attempt_number,
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "input_commitment_sha256": self.input_commitment_sha256,
            "model_identity_sha256": self.model_identity_sha256,
            "plan_sha256": self.plan_sha256,
            "principal_outcome_count": self.principal_outcome_count,
            "request_id": self.request_id,
            "role": self.role.value,
            "runtime_isolation_sha256": self.runtime_isolation_sha256,
            "schedule_binding_sha256": self.schedule_binding_sha256,
            "schema_version": self.schema_version,
            "session_sha256": self.session_sha256,
            "sha256": self.sha256,
            "transport_mode": self.transport_mode,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "CpuLoopbackRequest":
        value = _exact_object("CPU request", wire, _REQUEST_FIELDS)
        try:
            role = EndpointRole(_text("CPU request role", value["role"]))
        except (TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError("CPU request role is unknown") from exc
        return cls(
            schema_version=value["schema_version"],
            transport_mode=value["transport_mode"],
            session_sha256=value["session_sha256"],
            plan_sha256=value["plan_sha256"],
            schedule_binding_sha256=value["schedule_binding_sha256"],
            model_identity_sha256=value["model_identity_sha256"],
            runtime_isolation_sha256=value["runtime_isolation_sha256"],
            endpoint_attestation_sha256=value["endpoint_attestation_sha256"],
            request_id=value["request_id"],
            attempt_number=value["attempt_number"],
            role=role,
            input_commitment_sha256=value["input_commitment_sha256"],
            principal_outcome_count=value["principal_outcome_count"],
            sha256=value["sha256"],
        )

    def bind_to_permit(self, permit: CpuIntegrationPermit) -> None:
        if type(permit) is not CpuIntegrationPermit:
            raise LiveEndpointIntegrationError("CPU request permit is not exact")
        permit.revalidate()
        if (
            self.session_sha256 != permit.session_sha256
            or self.plan_sha256 != permit.plan_sha256
            or self.schedule_binding_sha256 != permit.schedule_binding_sha256
            or self.model_identity_sha256 != permit.model_identity_sha256
            or self.runtime_isolation_sha256 != permit.runtime_isolation_sha256
            or self.endpoint_attestation_sha256 != permit.endpoint_attestation_sha256
        ):
            raise LiveEndpointIntegrationError("CPU request binding differs from its permit")


_REPLY_FIELDS = frozenset(
    {
        "acknowledgement_sha256",
        "attempt_number",
        "endpoint_attestation_sha256",
        "plan_sha256",
        "principal_outcome_count",
        "request_id",
        "request_sha256",
        "retryable",
        "role",
        "schedule_binding_sha256",
        "schema_version",
        "session_sha256",
        "sha256",
        "status",
        "transport_mode",
    }
)


def cpu_reply_sha256(wire: Mapping[str, object]) -> str:
    if type(wire) is not dict:
        raise LiveEndpointIntegrationError("CPU reply must be an exact dictionary")
    base = dict(wire)
    base.pop("sha256", None)
    return _digest(b"sluice-cpu-loopback-reply-v1", base)


@dataclass(frozen=True, slots=True)
class CpuLoopbackReply:
    schema_version: str
    transport_mode: str
    session_sha256: str
    plan_sha256: str
    schedule_binding_sha256: str
    endpoint_attestation_sha256: str
    request_id: str
    attempt_number: int
    request_sha256: str
    role: EndpointRole
    status: FakeReplyStatus
    retryable: bool
    acknowledgement_sha256: str
    principal_outcome_count: int
    sha256: str

    @classmethod
    def create(
        cls,
        *,
        permit: CpuIntegrationPermit,
        request: CpuLoopbackRequest,
        status: FakeReplyStatus,
    ) -> "CpuLoopbackReply":
        if type(permit) is not CpuIntegrationPermit or type(request) is not CpuLoopbackRequest:
            raise LiveEndpointIntegrationError("CPU reply bindings are not exact")
        request.bind_to_permit(permit)
        if type(status) is not FakeReplyStatus:
            raise LiveEndpointIntegrationError("CPU reply status is not finite")
        retryable = status is FakeReplyStatus.CPU_FAKE_RETRYABLE
        ack = _digest_text(
            b"sluice-cpu-loopback-ack-v1", f"{request.sha256}\0{status.value}"
        )
        base = {
            "acknowledgement_sha256": ack,
            "attempt_number": request.attempt_number,
            "endpoint_attestation_sha256": permit.endpoint_attestation_sha256,
            "plan_sha256": permit.plan_sha256,
            "principal_outcome_count": 0,
            "request_id": request.request_id,
            "request_sha256": request.sha256,
            "retryable": retryable,
            "role": EndpointRole.MODEL_DRIVER.value,
            "schedule_binding_sha256": permit.schedule_binding_sha256,
            "schema_version": "sluice-cpu-loopback-reply-v1",
            "session_sha256": permit.session_sha256,
            "status": status.value,
            "transport_mode": TRANSPORT_MODE,
        }
        return cls(
            schema_version=base["schema_version"],
            transport_mode=base["transport_mode"],
            session_sha256=base["session_sha256"],
            plan_sha256=base["plan_sha256"],
            schedule_binding_sha256=base["schedule_binding_sha256"],
            endpoint_attestation_sha256=base["endpoint_attestation_sha256"],
            request_id=base["request_id"],
            attempt_number=base["attempt_number"],
            request_sha256=base["request_sha256"],
            role=EndpointRole.MODEL_DRIVER,
            status=status,
            retryable=retryable,
            acknowledgement_sha256=ack,
            principal_outcome_count=0,
            sha256=_digest(b"sluice-cpu-loopback-reply-v1", base),
        )

    def __post_init__(self) -> None:
        if type(self) is not CpuLoopbackReply:
            raise LiveEndpointIntegrationError("CPU reply subclasses are forbidden")
        _literal(
            "CPU reply schema",
            self.schema_version,
            "sluice-cpu-loopback-reply-v1",
        )
        _literal("CPU reply transport", self.transport_mode, TRANSPORT_MODE)
        if self.role is not EndpointRole.MODEL_DRIVER:
            raise LiveEndpointIntegrationError("CPU reply role is invalid")
        if type(self.status) is not FakeReplyStatus:
            raise LiveEndpointIntegrationError("CPU reply status is not finite")
        if type(self.retryable) is not bool or self.retryable is not (
            self.status is FakeReplyStatus.CPU_FAKE_RETRYABLE
        ):
            raise LiveEndpointIntegrationError("CPU reply retry flag is invalid")
        _integer(
            "CPU reply principal outcome count",
            self.principal_outcome_count,
            minimum=0,
            maximum=0,
        )
        for name in (
            "session_sha256",
            "plan_sha256",
            "schedule_binding_sha256",
            "endpoint_attestation_sha256",
            "request_sha256",
            "acknowledgement_sha256",
            "sha256",
        ):
            _sha256(name, getattr(self, name))
        _identifier("reply request ID", self.request_id)
        _integer("reply attempt", self.attempt_number, minimum=1, maximum=MAX_ATTEMPTS)
        expected_acknowledgement = _digest_text(
            b"sluice-cpu-loopback-ack-v1",
            f"{self.request_sha256}\0{self.status.value}",
        )
        if self.acknowledgement_sha256 != expected_acknowledgement:
            raise LiveEndpointIntegrationError(
                "CPU reply acknowledgement semantics mismatch"
            )
        if self.sha256 != cpu_reply_sha256(self.to_wire()):
            raise LiveEndpointIntegrationError("CPU reply digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "acknowledgement_sha256": self.acknowledgement_sha256,
            "attempt_number": self.attempt_number,
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "plan_sha256": self.plan_sha256,
            "principal_outcome_count": self.principal_outcome_count,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "retryable": self.retryable,
            "role": self.role.value,
            "schedule_binding_sha256": self.schedule_binding_sha256,
            "schema_version": self.schema_version,
            "session_sha256": self.session_sha256,
            "sha256": self.sha256,
            "status": self.status.value,
            "transport_mode": self.transport_mode,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "CpuLoopbackReply":
        value = _exact_object("CPU reply", wire, _REPLY_FIELDS)
        try:
            role = EndpointRole(_text("CPU reply role", value["role"]))
            status = FakeReplyStatus(_text("CPU reply status", value["status"]))
        except (TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError("CPU reply role or status is unknown") from exc
        return cls(
            schema_version=value["schema_version"],
            transport_mode=value["transport_mode"],
            session_sha256=value["session_sha256"],
            plan_sha256=value["plan_sha256"],
            schedule_binding_sha256=value["schedule_binding_sha256"],
            endpoint_attestation_sha256=value["endpoint_attestation_sha256"],
            request_id=value["request_id"],
            attempt_number=value["attempt_number"],
            request_sha256=value["request_sha256"],
            role=role,
            status=status,
            retryable=value["retryable"],
            acknowledgement_sha256=value["acknowledgement_sha256"],
            principal_outcome_count=value["principal_outcome_count"],
            sha256=value["sha256"],
        )

    def bind_to_request(
        self, *, permit: CpuIntegrationPermit, request: CpuLoopbackRequest
    ) -> None:
        if type(permit) is not CpuIntegrationPermit or type(request) is not CpuLoopbackRequest:
            raise LiveEndpointIntegrationError("CPU reply binding types are not exact")
        request.bind_to_permit(permit)
        if (
            self.session_sha256 != permit.session_sha256
            or self.plan_sha256 != permit.plan_sha256
            or self.schedule_binding_sha256 != permit.schedule_binding_sha256
            or self.endpoint_attestation_sha256 != permit.endpoint_attestation_sha256
            or self.request_id != request.request_id
            or self.attempt_number != request.attempt_number
            or self.request_sha256 != request.sha256
        ):
            raise LiveEndpointIntegrationError("CPU reply differs from request/permit binding")


class FakeLoopbackEndpoint:
    """Stateful fake packet peer; it hashes requests and never executes a model."""

    __slots__ = (
        "_observation",
        "_model_driver_peer",
        "_retry_policy",
        "_bound_permit",
        "_seen",
        "_expected_attempt",
        "_completed",
        "_accepted_packet_count",
        "_drift_after_first",
        "_lock",
    )

    def __init__(
        self,
        *,
        observation: EndpointObservation,
        model_driver_peer: PeerIdentity,
        retry_policy: FakeRetryPolicy,
    ) -> None:
        if type(observation) is not EndpointObservation:
            raise LiveEndpointIntegrationError("fake endpoint observation type is not exact")
        observation.__post_init__()
        if type(model_driver_peer) is not PeerIdentity:
            raise LiveEndpointIntegrationError("fake model peer type is not exact")
        if type(retry_policy) is not FakeRetryPolicy:
            raise LiveEndpointIntegrationError("fake retry policy type is not exact")
        self._observation = observation
        self._model_driver_peer = model_driver_peer
        self._retry_policy = retry_policy
        self._bound_permit: CpuIntegrationPermit | None = None
        self._seen: set[tuple[str, int]] = set()
        self._expected_attempt: dict[str, int] = {}
        self._completed: set[str] = set()
        self._accepted_packet_count = 0
        self._drift_after_first: EndpointObservation | None = None
        self._lock = threading.RLock()

    @property
    def model_driver_peer(self) -> PeerIdentity:
        return self._model_driver_peer

    @property
    def accepted_packet_count(self) -> int:
        with self._lock:
            return self._accepted_packet_count

    def probe(self, endpoint_url: str) -> EndpointObservation:
        _text("fake probe URL", endpoint_url, maximum=2_048)
        with self._lock:
            return self._observation

    def drift_observation_for_test(self, observation: EndpointObservation) -> None:
        if type(observation) is not EndpointObservation:
            raise LiveEndpointIntegrationError("drift observation type is not exact")
        observation.__post_init__()
        with self._lock:
            self._observation = observation

    def drift_after_first_reply_for_test(self, observation: EndpointObservation) -> None:
        if type(observation) is not EndpointObservation:
            raise LiveEndpointIntegrationError("deferred drift observation type is not exact")
        observation.__post_init__()
        with self._lock:
            self._drift_after_first = observation

    def _current_attestation(self, permit: CpuIntegrationPermit) -> EndpointAttestation:
        try:
            value = permit._expectation.verify(self.probe)
        except (LivePipelineError, TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError("fake endpoint identity probe failed") from exc
        if type(value) is not EndpointAttestation:
            raise LiveEndpointIntegrationError("fake endpoint attestation type is not exact")
        return value

    def bind_cpu_permit(self, permit: CpuIntegrationPermit) -> None:
        if type(permit) is not CpuIntegrationPermit:
            raise LiveEndpointIntegrationError("fake endpoint permit type is not exact")
        permit.revalidate()
        with self._lock:
            if self._bound_permit is not None:
                raise LiveEndpointIntegrationError("fake endpoint is already bound")
            if self._model_driver_peer != permit._topology.model_driver:
                raise LiveEndpointIntegrationError("fake endpoint model-driver peer mismatch")
            observed = self._current_attestation(permit)
            if observed.to_wire() != permit._endpoint_attestation.to_wire():
                raise LiveEndpointIntegrationError("fake endpoint identity drifted before bind")
            self._bound_permit = permit

    def handle(self, wire: object, *, observed_peer: PeerIdentity) -> dict[str, object]:
        if type(observed_peer) is not PeerIdentity:
            raise LiveEndpointIntegrationError("observed broker peer type is not exact")
        request = CpuLoopbackRequest.from_wire(wire)
        with self._lock:
            permit = self._bound_permit
            if type(permit) is not CpuIntegrationPermit:
                raise LiveEndpointIntegrationError("fake endpoint has no CPU permit")
            permit.revalidate()
            if observed_peer != permit._topology.broker:
                raise LiveEndpointIntegrationError("synthetic broker PID/UID/GID binding mismatch")
            if self._model_driver_peer != permit._topology.model_driver:
                raise LiveEndpointIntegrationError("synthetic model-driver peer binding mismatch")
            if self._current_attestation(permit).to_wire() != permit._endpoint_attestation.to_wire():
                raise LiveEndpointIntegrationError("fake endpoint identity drift detected")
            request.bind_to_permit(permit)
            key = (request.request_id, request.attempt_number)
            if key in self._seen:
                raise LiveEndpointIntegrationError("duplicate request attempt rejected")
            if request.request_id in self._completed:
                raise LiveEndpointIntegrationError("completed request replay rejected")
            expected = self._expected_attempt.get(request.request_id, 1)
            if request.attempt_number != expected:
                raise LiveEndpointIntegrationError("request retry order is invalid")
            self._seen.add(key)
            self._accepted_packet_count += 1
            retry = self._retry_policy is FakeRetryPolicy.ALWAYS or (
                self._retry_policy is FakeRetryPolicy.ONCE and request.attempt_number == 1
            )
            status = (
                FakeReplyStatus.CPU_FAKE_RETRYABLE
                if retry
                else FakeReplyStatus.CPU_FAKE_ACK
            )
            if retry:
                self._expected_attempt[request.request_id] = request.attempt_number + 1
            else:
                self._completed.add(request.request_id)
                self._expected_attempt.pop(request.request_id, None)
            reply = CpuLoopbackReply.create(
                permit=permit, request=request, status=status
            )
            if request.attempt_number == 1 and self._drift_after_first is not None:
                self._observation = self._drift_after_first
                self._drift_after_first = None
            return reply.to_wire()


_EVENT_FIELDS = frozenset(
    {
        "attempt_number",
        "kind",
        "principal_outcome_count",
        "reply_sha256",
        "request_id_sha256",
        "request_sha256",
        "schema_version",
        "sequence",
        "sha256",
        "status",
    }
)


def chronology_event_sha256(wire: Mapping[str, object]) -> str:
    if type(wire) is not dict:
        raise LiveEndpointIntegrationError("chronology event must be an exact dictionary")
    base = dict(wire)
    base.pop("sha256", None)
    return _digest(b"sluice-cpu-endpoint-chronology-event-v1", base)


@dataclass(frozen=True, slots=True)
class CpuChronologyEvent:
    schema_version: str
    sequence: int
    kind: ChronologyKind
    status: str
    request_id_sha256: str | None
    attempt_number: int | None
    request_sha256: str | None
    reply_sha256: str | None
    principal_outcome_count: int
    sha256: str

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        kind: ChronologyKind,
        status: str,
        request_id_sha256: str | None = None,
        attempt_number: int | None = None,
        request_sha256: str | None = None,
        reply_sha256: str | None = None,
    ) -> "CpuChronologyEvent":
        _integer("chronology sequence", sequence, minimum=1, maximum=CHRONOLOGY_HMAX)
        if type(kind) is not ChronologyKind:
            raise LiveEndpointIntegrationError("chronology kind is not finite")
        _identifier("chronology status", status)
        base = {
            "attempt_number": attempt_number,
            "kind": kind.value,
            "principal_outcome_count": 0,
            "reply_sha256": reply_sha256,
            "request_id_sha256": request_id_sha256,
            "request_sha256": request_sha256,
            "schema_version": "sluice-cpu-endpoint-chronology-event-v1",
            "sequence": sequence,
            "status": status,
        }
        return cls(
            schema_version=base["schema_version"],
            sequence=sequence,
            kind=kind,
            status=status,
            request_id_sha256=request_id_sha256,
            attempt_number=attempt_number,
            request_sha256=request_sha256,
            reply_sha256=reply_sha256,
            principal_outcome_count=0,
            sha256=_digest(b"sluice-cpu-endpoint-chronology-event-v1", base),
        )

    def __post_init__(self) -> None:
        if type(self) is not CpuChronologyEvent:
            raise LiveEndpointIntegrationError("chronology event subclasses are forbidden")
        _literal(
            "chronology event schema",
            self.schema_version,
            "sluice-cpu-endpoint-chronology-event-v1",
        )
        _integer("chronology sequence", self.sequence, minimum=1, maximum=CHRONOLOGY_HMAX)
        if type(self.kind) is not ChronologyKind:
            raise LiveEndpointIntegrationError("chronology kind is not finite")
        _identifier("chronology status", self.status)
        for name in ("request_id_sha256", "request_sha256", "reply_sha256"):
            value = getattr(self, name)
            if value is not None:
                _sha256(name, value)
        if self.attempt_number is not None:
            _integer("chronology attempt", self.attempt_number, minimum=1, maximum=MAX_ATTEMPTS)
        _integer(
            "chronology principal outcome count",
            self.principal_outcome_count,
            minimum=0,
            maximum=0,
        )
        _sha256("chronology event", self.sha256)
        if self.sha256 != chronology_event_sha256(self.to_wire()):
            raise LiveEndpointIntegrationError("chronology event digest mismatch")

    def to_wire(self) -> dict[str, object]:
        return {
            "attempt_number": self.attempt_number,
            "kind": self.kind.value,
            "principal_outcome_count": self.principal_outcome_count,
            "reply_sha256": self.reply_sha256,
            "request_id_sha256": self.request_id_sha256,
            "request_sha256": self.request_sha256,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "sha256": self.sha256,
            "status": self.status,
        }

    @classmethod
    def from_wire(cls, wire: object) -> "CpuChronologyEvent":
        value = _exact_object("chronology event", wire, _EVENT_FIELDS)
        try:
            kind = ChronologyKind(_text("chronology event kind", value["kind"]))
        except (TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError("chronology event kind is unknown") from exc
        return cls(
            schema_version=value["schema_version"],
            sequence=value["sequence"],
            kind=kind,
            status=value["status"],
            request_id_sha256=value["request_id_sha256"],
            attempt_number=value["attempt_number"],
            request_sha256=value["request_sha256"],
            reply_sha256=value["reply_sha256"],
            principal_outcome_count=value["principal_outcome_count"],
            sha256=value["sha256"],
        )


_CHRONOLOGY_FIELDS = frozenset(
    {
        "chronology_hmax",
        "chronology_sha256",
        "plan_sha256",
        "principal_outcome_count",
        "reply_count",
        "request_count",
        "schedule_binding_sha256",
        "schema_version",
        "session_sha256",
        "steps",
        "terminal_status",
        "transport_mode",
    }
)


def cpu_chronology_sha256(wire: Mapping[str, object]) -> str:
    if type(wire) is not dict:
        raise LiveEndpointIntegrationError("CPU chronology must be an exact dictionary")
    base = dict(wire)
    base.pop("chronology_sha256", None)
    return _digest(b"sluice-cpu-endpoint-chronology-v1", base)


@dataclass(frozen=True, slots=True)
class CpuEndpointChronology:
    session_sha256: str
    plan_sha256: str
    schedule_binding_sha256: str
    chronology_hmax: int
    request_count: int
    reply_count: int
    terminal_status: CpuExchangeStatus
    principal_outcome_count: int
    steps: tuple[CpuChronologyEvent, ...]
    chronology_sha256: str
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not CpuEndpointChronology or self._token is not _CHRONOLOGY_TOKEN:
            raise LiveEndpointIntegrationError("CPU chronology was not session minted")
        for name in ("session_sha256", "plan_sha256", "schedule_binding_sha256"):
            _sha256(name, getattr(self, name))
        _integer(
            "chronology Hmax",
            self.chronology_hmax,
            minimum=CHRONOLOGY_HMAX,
            maximum=CHRONOLOGY_HMAX,
        )
        _integer(
            "chronology request count",
            self.request_count,
            minimum=1,
            maximum=MAX_ATTEMPTS,
        )
        _integer(
            "chronology reply count",
            self.reply_count,
            minimum=1,
            maximum=MAX_ATTEMPTS,
        )
        _integer(
            "chronology principal outcome count",
            self.principal_outcome_count,
            minimum=0,
            maximum=0,
        )
        if (
            self.reply_count != self.request_count
            or type(self.terminal_status) is not CpuExchangeStatus
            or type(self.steps) is not tuple
            or len(self.steps) != CHRONOLOGY_HMAX
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, CHRONOLOGY_HMAX + 1))
        ):
            raise LiveEndpointIntegrationError("CPU chronology bounds are invalid")
        if any(type(step) is not CpuChronologyEvent for step in self.steps):
            raise LiveEndpointIntegrationError("CPU chronology step type is not exact")
        _sha256("chronology", self.chronology_sha256)
        if self.chronology_sha256 != cpu_chronology_sha256(self.to_wire()):
            raise LiveEndpointIntegrationError("CPU chronology digest mismatch")

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def to_wire(self) -> dict[str, object]:
        return {
            "chronology_hmax": self.chronology_hmax,
            "chronology_sha256": self.chronology_sha256,
            "plan_sha256": self.plan_sha256,
            "principal_outcome_count": self.principal_outcome_count,
            "reply_count": self.reply_count,
            "request_count": self.request_count,
            "schedule_binding_sha256": self.schedule_binding_sha256,
            "schema_version": "sluice-cpu-endpoint-chronology-v1",
            "session_sha256": self.session_sha256,
            "steps": [step.to_wire() for step in self.steps],
            "terminal_status": self.terminal_status.value,
            "transport_mode": TRANSPORT_MODE,
        }


@dataclass(frozen=True, slots=True)
class ValidatedCpuChronology:
    request_count: int
    reply_count: int
    terminal_status: CpuExchangeStatus
    step_count: int


def _build_chronology(
    *,
    permit: CpuIntegrationPermit,
    requests: tuple[CpuLoopbackRequest, ...],
    replies: tuple[CpuLoopbackReply, ...],
    terminal_status: CpuExchangeStatus,
) -> CpuEndpointChronology:
    sequence = 1
    steps = [
        CpuChronologyEvent.create(
            sequence=sequence,
            kind=ChronologyKind.PREFLIGHT,
            status="CPU_FAKE_ENDPOINT_VERIFIED",
        )
    ]
    for request, reply in zip(requests, replies, strict=True):
        request_id_sha = _digest_text(
            b"sluice-cpu-request-id-v1", request.request_id
        )
        sequence += 1
        steps.append(
            CpuChronologyEvent.create(
                sequence=sequence,
                kind=ChronologyKind.REQUEST,
                status="DISPATCHED",
                request_id_sha256=request_id_sha,
                attempt_number=request.attempt_number,
                request_sha256=request.sha256,
            )
        )
        sequence += 1
        steps.append(
            CpuChronologyEvent.create(
                sequence=sequence,
                kind=ChronologyKind.REPLY,
                status=reply.status.value,
                request_id_sha256=request_id_sha,
                attempt_number=reply.attempt_number,
                request_sha256=request.sha256,
                reply_sha256=reply.sha256,
            )
        )
    sequence += 1
    steps.append(
        CpuChronologyEvent.create(
            sequence=sequence,
            kind=ChronologyKind.TERMINAL,
            status=terminal_status.value,
        )
    )
    while len(steps) < CHRONOLOGY_HMAX:
        sequence += 1
        steps.append(
            CpuChronologyEvent.create(
                sequence=sequence,
                kind=ChronologyKind.PAD,
                status="PAD",
            )
        )
    base = {
        "chronology_hmax": CHRONOLOGY_HMAX,
        "plan_sha256": permit.plan_sha256,
        "principal_outcome_count": 0,
        "reply_count": len(replies),
        "request_count": len(requests),
        "schedule_binding_sha256": permit.schedule_binding_sha256,
        "schema_version": "sluice-cpu-endpoint-chronology-v1",
        "session_sha256": permit.session_sha256,
        "steps": [step.to_wire() for step in steps],
        "terminal_status": terminal_status.value,
        "transport_mode": TRANSPORT_MODE,
    }
    return CpuEndpointChronology(
        session_sha256=permit.session_sha256,
        plan_sha256=permit.plan_sha256,
        schedule_binding_sha256=permit.schedule_binding_sha256,
        chronology_hmax=CHRONOLOGY_HMAX,
        request_count=len(requests),
        reply_count=len(replies),
        terminal_status=terminal_status,
        principal_outcome_count=0,
        steps=tuple(steps),
        chronology_sha256=_digest(b"sluice-cpu-endpoint-chronology-v1", base),
        _token=_CHRONOLOGY_TOKEN,
    )


def validate_cpu_chronology_wire(
    *,
    wire: Mapping[str, object],
    permit: CpuIntegrationPermit,
    requests: tuple[CpuLoopbackRequest, ...],
    replies: tuple[CpuLoopbackReply, ...],
) -> ValidatedCpuChronology:
    body = _exact_object("CPU chronology", wire, _CHRONOLOGY_FIELDS)
    _literal(
        "CPU chronology schema",
        body["schema_version"],
        "sluice-cpu-endpoint-chronology-v1",
    )
    _literal("CPU chronology transport", body["transport_mode"], TRANSPORT_MODE)
    for name in ("session_sha256", "plan_sha256", "schedule_binding_sha256"):
        _sha256(name, body[name])
    _sha256("chronology wrapper", body["chronology_sha256"])
    _integer(
        "chronology Hmax",
        body["chronology_hmax"],
        minimum=CHRONOLOGY_HMAX,
        maximum=CHRONOLOGY_HMAX,
    )
    _integer(
        "chronology request count",
        body["request_count"],
        minimum=1,
        maximum=MAX_ATTEMPTS,
    )
    _integer(
        "chronology reply count",
        body["reply_count"],
        minimum=1,
        maximum=MAX_ATTEMPTS,
    )
    _integer(
        "chronology principal outcome count",
        body["principal_outcome_count"],
        minimum=0,
        maximum=0,
    )
    if type(permit) is not CpuIntegrationPermit:
        raise LiveEndpointIntegrationError("chronology permit type is not exact")
    permit.revalidate()
    if type(requests) is not tuple or type(replies) is not tuple:
        raise LiveEndpointIntegrationError("chronology request/reply collections must be tuples")
    if (
        not 1 <= len(requests) <= MAX_ATTEMPTS
        or len(replies) != len(requests)
        or any(type(value) is not CpuLoopbackRequest for value in requests)
        or any(type(value) is not CpuLoopbackReply for value in replies)
    ):
        raise LiveEndpointIntegrationError("chronology request/reply population is invalid")
    if cpu_chronology_sha256(body) != body["chronology_sha256"]:
        raise LiveEndpointIntegrationError("chronology wrapper digest mismatch")
    if type(body["steps"]) is not list or len(body["steps"]) != CHRONOLOGY_HMAX:
        raise LiveEndpointIntegrationError("chronology step array is not fixed at Hmax")
    parsed_steps = tuple(CpuChronologyEvent.from_wire(step) for step in body["steps"])
    if tuple(step.sequence for step in parsed_steps) != tuple(range(1, CHRONOLOGY_HMAX + 1)):
        raise LiveEndpointIntegrationError("chronology sequence is missing, duplicated, or reordered")
    request_ids = {request.request_id for request in requests}
    if len(request_ids) != 1:
        raise LiveEndpointIntegrationError("one schedule unit must use one request identity")
    input_commitments = {request.input_commitment_sha256 for request in requests}
    if len(input_commitments) != 1:
        raise LiveEndpointIntegrationError("retry changed the input commitment")
    for index, (request, reply) in enumerate(zip(requests, replies, strict=True), 1):
        request.bind_to_permit(permit)
        reply.bind_to_request(permit=permit, request=request)
        if request.attempt_number != index or reply.attempt_number != index:
            raise LiveEndpointIntegrationError("retry attempts are not contiguous")
    try:
        terminal = CpuExchangeStatus(
            _text("chronology terminal status", body["terminal_status"])
        )
    except (TypeError, ValueError) as exc:
        raise LiveEndpointIntegrationError("chronology terminal status is unknown") from exc
    if terminal is CpuExchangeStatus.CPU_FAKE_COMPLETED:
        if replies[-1].status is not FakeReplyStatus.CPU_FAKE_ACK or any(
            reply.status is not FakeReplyStatus.CPU_FAKE_RETRYABLE
            for reply in replies[:-1]
        ):
            raise LiveEndpointIntegrationError("completed chronology has an invalid retry chain")
    elif (
        len(replies) != MAX_ATTEMPTS
        or any(reply.status is not FakeReplyStatus.CPU_FAKE_RETRYABLE for reply in replies)
    ):
        raise LiveEndpointIntegrationError("retry-exhausted chronology is not exact")
    expected = _build_chronology(
        permit=permit,
        requests=requests,
        replies=replies,
        terminal_status=terminal,
    )
    if _canonical_json(expected.to_wire()) != _canonical_json(dict(body)):
        raise LiveEndpointIntegrationError("chronology semantics differ from request/reply evidence")
    return ValidatedCpuChronology(
        request_count=len(requests),
        reply_count=len(replies),
        terminal_status=terminal,
        step_count=CHRONOLOGY_HMAX,
    )


@dataclass(frozen=True, slots=True)
class CpuEndpointReceipt:
    permit_sha256: str
    session_sha256: str
    plan_sha256: str
    schedule_binding_sha256: str
    endpoint_attestation_sha256: str
    status: CpuExchangeStatus
    attempt_count: int
    chronology: CpuEndpointChronology
    restricted_requests: tuple[CpuLoopbackRequest, ...] = field(repr=False, compare=False)
    restricted_replies: tuple[CpuLoopbackReply, ...] = field(repr=False, compare=False)
    fake_endpoint_exercised: bool = True
    principal_eligible: bool = False
    model_executed: bool = False
    gpu_executed: bool = False
    scoring_executed: bool = False
    detector_executed: bool = False
    effectiveness_evidence: bool = False
    utility_evidence: bool = False
    principal_outcome_count: int = 0
    sha256: str = ""
    _permit: CpuIntegrationPermit = field(repr=False, compare=False, default=None)
    _token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if type(self) is not CpuEndpointReceipt or self._token is not _RECEIPT_TOKEN:
            raise LiveEndpointIntegrationError("CPU endpoint receipt was not session minted")
        if type(self._permit) is not CpuIntegrationPermit:
            raise LiveEndpointIntegrationError("CPU receipt permit type is not exact")
        self._permit.revalidate()
        for name in (
            "permit_sha256",
            "session_sha256",
            "plan_sha256",
            "schedule_binding_sha256",
            "endpoint_attestation_sha256",
        ):
            _sha256(name, getattr(self, name))
        _integer(
            "CPU receipt attempt count",
            self.attempt_count,
            minimum=1,
            maximum=MAX_ATTEMPTS,
        )
        _integer(
            "CPU receipt principal outcome count",
            self.principal_outcome_count,
            minimum=0,
            maximum=0,
        )
        if (
            self.permit_sha256 != self._permit.sha256
            or self.session_sha256 != self._permit.session_sha256
            or self.plan_sha256 != self._permit.plan_sha256
            or self.schedule_binding_sha256 != self._permit.schedule_binding_sha256
            or self.endpoint_attestation_sha256 != self._permit.endpoint_attestation_sha256
            or type(self.status) is not CpuExchangeStatus
            or self.attempt_count != len(self.restricted_requests)
            or self.attempt_count != len(self.restricted_replies)
            or not 1 <= self.attempt_count <= MAX_ATTEMPTS
            or type(self.chronology) is not CpuEndpointChronology
            or type(self.restricted_requests) is not tuple
            or type(self.restricted_replies) is not tuple
        ):
            raise LiveEndpointIntegrationError("CPU receipt binding is invalid")
        _true("CPU receipt fake endpoint flag", self.fake_endpoint_exercised)
        false_gates = (
            self.principal_eligible,
            self.model_executed,
            self.gpu_executed,
            self.scoring_executed,
            self.detector_executed,
            self.effectiveness_evidence,
            self.utility_evidence,
        )
        if any(type(value) is not bool or value for value in false_gates):
            raise LiveEndpointIntegrationError("CPU receipt cannot promote a live/result gate")
        validated = validate_cpu_chronology_wire(
            wire=self.chronology.to_wire(),
            permit=self._permit,
            requests=self.restricted_requests,
            replies=self.restricted_replies,
        )
        if validated.terminal_status is not self.status:
            raise LiveEndpointIntegrationError("CPU receipt/chronology status mismatch")
        _sha256("CPU receipt", self.sha256)
        if self.sha256 != _digest(
            b"sluice-cpu-endpoint-receipt-v1", self.to_public_wire_without_hash()
        ):
            raise LiveEndpointIntegrationError("CPU receipt digest mismatch")

    def to_public_wire_without_hash(self) -> dict[str, object]:
        return {
            "attempt_count": self.attempt_count,
            "chronology_sha256": self.chronology.chronology_sha256,
            "chronology_step_count": self.chronology.step_count,
            "detector_executed": self.detector_executed,
            "effectiveness_evidence": self.effectiveness_evidence,
            "endpoint_attestation_sha256": self.endpoint_attestation_sha256,
            "fake_endpoint_exercised": self.fake_endpoint_exercised,
            "gpu_executed": self.gpu_executed,
            "model_executed": self.model_executed,
            "peer_identity_mode": PEER_IDENTITY_MODE,
            "permit_sha256": self.permit_sha256,
            "plan_sha256": self.plan_sha256,
            "principal_eligible": self.principal_eligible,
            "principal_outcome_count": self.principal_outcome_count,
            "schedule_binding_sha256": self.schedule_binding_sha256,
            "schema_version": "sluice-cpu-endpoint-receipt-v1",
            "scoring_executed": self.scoring_executed,
            "session_sha256": self.session_sha256,
            "status": self.status.value,
            "transport_mode": TRANSPORT_MODE,
            "utility_evidence": self.utility_evidence,
        }

    def to_public_wire(self) -> dict[str, object]:
        return {**self.to_public_wire_without_hash(), "sha256": self.sha256}


def _mint_receipt(
    *,
    permit: CpuIntegrationPermit,
    status: CpuExchangeStatus,
    chronology: CpuEndpointChronology,
    requests: tuple[CpuLoopbackRequest, ...],
    replies: tuple[CpuLoopbackReply, ...],
) -> CpuEndpointReceipt:
    base = {
        "attempt_count": len(requests),
        "chronology_sha256": chronology.chronology_sha256,
        "chronology_step_count": chronology.step_count,
        "detector_executed": False,
        "effectiveness_evidence": False,
        "endpoint_attestation_sha256": permit.endpoint_attestation_sha256,
        "fake_endpoint_exercised": True,
        "gpu_executed": False,
        "model_executed": False,
        "peer_identity_mode": PEER_IDENTITY_MODE,
        "permit_sha256": permit.sha256,
        "plan_sha256": permit.plan_sha256,
        "principal_eligible": False,
        "principal_outcome_count": 0,
        "schedule_binding_sha256": permit.schedule_binding_sha256,
        "schema_version": "sluice-cpu-endpoint-receipt-v1",
        "scoring_executed": False,
        "session_sha256": permit.session_sha256,
        "status": status.value,
        "transport_mode": TRANSPORT_MODE,
        "utility_evidence": False,
    }
    return CpuEndpointReceipt(
        permit_sha256=permit.sha256,
        session_sha256=permit.session_sha256,
        plan_sha256=permit.plan_sha256,
        schedule_binding_sha256=permit.schedule_binding_sha256,
        endpoint_attestation_sha256=permit.endpoint_attestation_sha256,
        status=status,
        attempt_count=len(requests),
        chronology=chronology,
        restricted_requests=requests,
        restricted_replies=replies,
        fake_endpoint_exercised=True,
        principal_eligible=False,
        model_executed=False,
        gpu_executed=False,
        scoring_executed=False,
        detector_executed=False,
        effectiveness_evidence=False,
        utility_evidence=False,
        principal_outcome_count=0,
        sha256=_digest(b"sluice-cpu-endpoint-receipt-v1", base),
        _permit=permit,
        _token=_RECEIPT_TOKEN,
    )


class CpuLoopbackSession:
    __slots__ = ("permit", "_endpoint", "_used", "_lock")

    def __init__(self, *, permit: CpuIntegrationPermit, endpoint: FakeLoopbackEndpoint) -> None:
        if type(permit) is not CpuIntegrationPermit or type(endpoint) is not FakeLoopbackEndpoint:
            raise LiveEndpointIntegrationError("CPU session types are not exact")
        permit.revalidate()
        self.permit = permit
        self._endpoint = endpoint
        self._used = False
        self._lock = threading.Lock()

    def _claim_one_shot(self) -> None:
        with self._lock:
            if self._used:
                raise LiveEndpointIntegrationError(
                    "one-shot schedule unit rejects every second request, including novel IDs"
                )
            self._used = True

    def _assert_endpoint_stable(self) -> None:
        if self._endpoint.model_driver_peer != self.permit._topology.model_driver:
            raise LiveEndpointIntegrationError("model-driver peer drift detected")
        try:
            current = self.permit._expectation.verify(self._endpoint.probe)
        except (LivePipelineError, TypeError, ValueError) as exc:
            raise LiveEndpointIntegrationError("endpoint drift probe failed") from exc
        if current.to_wire() != self.permit._endpoint_attestation.to_wire():
            raise LiveEndpointIntegrationError("endpoint identity drift detected")

    def execute_cpu_fake(
        self,
        *,
        input_commitment_sha256: str,
        request_id: str,
        observed_broker_peer: PeerIdentity,
    ) -> CpuEndpointReceipt:
        _sha256("input commitment", input_commitment_sha256)
        _identifier("request ID", request_id)
        if type(observed_broker_peer) is not PeerIdentity:
            raise LiveEndpointIntegrationError("synthetic broker peer type is not exact")
        self._claim_one_shot()
        requests: list[CpuLoopbackRequest] = []
        replies: list[CpuLoopbackReply] = []
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._assert_endpoint_stable()
            request_value = CpuLoopbackRequest.create(
                permit=self.permit,
                request_id=request_id,
                attempt_number=attempt,
                input_commitment_sha256=input_commitment_sha256,
            )
            reply_value = CpuLoopbackReply.from_wire(
                self._endpoint.handle(
                    request_value.to_wire(), observed_peer=observed_broker_peer
                )
            )
            reply_value.bind_to_request(permit=self.permit, request=request_value)
            requests.append(request_value)
            replies.append(reply_value)
            if reply_value.status is FakeReplyStatus.CPU_FAKE_ACK:
                status = CpuExchangeStatus.CPU_FAKE_COMPLETED
                break
        else:
            status = CpuExchangeStatus.CPU_FAKE_RETRY_EXHAUSTED
        request_tuple = tuple(requests)
        reply_tuple = tuple(replies)
        chronology = _build_chronology(
            permit=self.permit,
            requests=request_tuple,
            replies=reply_tuple,
            terminal_status=status,
        )
        validate_cpu_chronology_wire(
            wire=chronology.to_wire(),
            permit=self.permit,
            requests=request_tuple,
            replies=reply_tuple,
        )
        return _mint_receipt(
            permit=self.permit,
            status=status,
            chronology=chronology,
            requests=request_tuple,
            replies=reply_tuple,
        )


def _mint_cpu_permit(
    *,
    schedule: _ScheduleBindingSnapshot,
    model: PinnedModelIdentity,
    runtime_isolation: RuntimeIsolationPins,
    topology: ProcessTopologyAttestation,
    endpoint_attestation: EndpointAttestation,
    expectation: EndpointExpectation,
) -> CpuIntegrationPermit:
    if type(schedule) is not _ScheduleBindingSnapshot:
        raise LiveEndpointIntegrationError("permit schedule snapshot type is not exact")
    schedule.revalidate()
    session_base = {
        "endpoint_attestation_sha256": endpoint_attestation.sha256,
        "model_identity_sha256": model.sha256,
        "peer_identity_mode": PEER_IDENTITY_MODE,
        "plan_sha256": schedule.plan_sha256,
        "runtime_isolation_sha256": runtime_isolation.sha256,
        "schedule_binding_sha256": schedule.binding_sha256,
        "topology_binding_sha256": topology.binding_sha256,
        "transport_mode": TRANSPORT_MODE,
    }
    session_sha = _digest(b"sluice-cpu-loopback-session-v1", session_base)
    base = {
        "endpoint_attestation_sha256": endpoint_attestation.sha256,
        "model_identity_sha256": model.sha256,
        "peer_identity_mode": PEER_IDENTITY_MODE,
        "plan_sha256": schedule.plan_sha256,
        "principal_eligible": False,
        "runtime_isolation_sha256": runtime_isolation.sha256,
        "schedule_binding_sha256": schedule.binding_sha256,
        "schema_version": "sluice-cpu-integration-permit-v1",
        "session_sha256": session_sha,
        "topology_binding_sha256": topology.binding_sha256,
        "transport_mode": TRANSPORT_MODE,
    }
    return CpuIntegrationPermit(
        session_sha256=session_sha,
        plan_sha256=schedule.plan_sha256,
        schedule_binding_sha256=schedule.binding_sha256,
        model_identity_sha256=model.sha256,
        runtime_isolation_sha256=runtime_isolation.sha256,
        topology_binding_sha256=topology.binding_sha256,
        endpoint_attestation_sha256=endpoint_attestation.sha256,
        transport_mode=TRANSPORT_MODE,
        peer_identity_mode=PEER_IDENTITY_MODE,
        principal_eligible=False,
        sha256=_digest(b"sluice-cpu-integration-permit-v1", base),
        _schedule=schedule,
        _model=model,
        _runtime=runtime_isolation,
        _topology=topology,
        _endpoint_attestation=endpoint_attestation,
        _expectation=expectation,
        _token=_PERMIT_TOKEN,
    )


def establish_cpu_loopback(
    *,
    schedule: ScheduleBinding,
    model: PinnedModelIdentity,
    runtime_isolation: RuntimeIsolationPins,
    topology: ProcessTopologyAttestation,
    endpoint: FakeLoopbackEndpoint,
    expected_endpoint_url: str,
) -> CpuLoopbackSession:
    if type(schedule) is not ScheduleBinding:
        raise LiveEndpointIntegrationError("schedule binding type is not exact")
    # Authenticate the complete committed plan and exact unit once at the
    # admission boundary.  Packet processing below retains only the compact,
    # tokenized binding snapshot and therefore remains O(1) in plan size.
    try:
        schedule.revalidate_source()
    except (TypeError, ValueError) as exc:
        raise LiveEndpointIntegrationError(
            "source plan drifted before endpoint admission"
        ) from exc
    schedule_snapshot = _ScheduleBindingSnapshot.freeze(schedule)
    if type(model) is not PinnedModelIdentity:
        raise LiveEndpointIntegrationError("model pin type is not exact")
    model.__post_init__()
    if type(runtime_isolation) is not RuntimeIsolationPins:
        raise LiveEndpointIntegrationError("runtime pin type is not exact")
    runtime_isolation.__post_init__()
    if type(topology) is not ProcessTopologyAttestation:
        raise LiveEndpointIntegrationError("topology type is not exact")
    topology.__post_init__()
    if topology.mode != "cpu_contract" or topology.principal_eligible is not False:
        raise LiveEndpointIntegrationError("peer identities must remain synthetic CPU API bindings")
    if type(endpoint) is not FakeLoopbackEndpoint:
        raise LiveEndpointIntegrationError("fake endpoint type is not exact")
    if endpoint.model_driver_peer != topology.model_driver:
        raise LiveEndpointIntegrationError("fake endpoint model-driver peer mismatch")
    expectation = model.expectation(expected_endpoint_url)
    try:
        endpoint_attestation = expectation.verify(endpoint.probe)
    except (LivePipelineError, TypeError, ValueError) as exc:
        raise LiveEndpointIntegrationError("endpoint/model preflight mismatch") from exc
    if (
        endpoint_attestation.model_id,
        endpoint_attestation.model_revision,
        endpoint_attestation.model_artifact_sha256,
        endpoint_attestation.backend,
        endpoint_attestation.backend_version,
    ) != model.identity_tuple:
        raise LiveEndpointIntegrationError("endpoint/model exact identity mismatch")
    # One execution process admits a schedule unit exactly once, independent
    # of endpoint object or request identifier.  A lock makes competing
    # establish calls linearizable.
    with _ADMISSION_LOCK:
        if schedule.binding_sha256 in _CLAIMED_SCHEDULE_BINDINGS:
            raise LiveEndpointIntegrationError("schedule binding is already admitted")
        _CLAIMED_SCHEDULE_BINDINGS.add(schedule.binding_sha256)
    endpoint_bound = False
    try:
        permit = _mint_cpu_permit(
            schedule=schedule_snapshot,
            model=model,
            runtime_isolation=runtime_isolation,
            topology=topology,
            endpoint_attestation=endpoint_attestation,
            expectation=expectation,
        )
        endpoint.bind_cpu_permit(permit)
        endpoint_bound = True
        return CpuLoopbackSession(permit=permit, endpoint=endpoint)
    except BaseException:
        # A failure before endpoint binding releases the tentative process-local
        # claim.  Once the permit has escaped into endpoint state, failure is
        # monotone: retain the claim so no second endpoint/session can admit it.
        if not endpoint_bound:
            with _ADMISSION_LOCK:
                _CLAIMED_SCHEDULE_BINDINGS.discard(schedule.binding_sha256)
        raise


@dataclass(frozen=True, slots=True, init=False)
class PrincipalEndpointPermit:
    def __new__(cls, *args: object, **kwargs: object) -> "PrincipalEndpointPermit":
        del args, kwargs
        raise LiveEndpointIntegrationError(
            "CPU/fake integration cannot directly construct a principal endpoint permit"
        )

    @classmethod
    def issue(cls, **claims: object) -> "PrincipalEndpointPermit":
        del claims
        raise LiveEndpointIntegrationError(
            "CPU/fake integration has no constructor for a principal endpoint permit"
        )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
    )


def _regular_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_lexical_directory(path: Path) -> tuple[int, tuple[tuple[int, ...], ...]]:
    if any(not hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        raise LiveEndpointIntegrationError("secure evidence path primitives are unavailable")
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = -1
    chain: list[tuple[int, ...]] = []
    try:
        descriptor = os.open(absolute.anchor, flags)
        chain.append(_directory_identity(os.fstat(descriptor)))
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise LiveEndpointIntegrationError("evidence parent path is noncanonical")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise LiveEndpointIntegrationError("evidence parent component is not a directory")
            chain.append(_directory_identity(metadata))
        return descriptor, tuple(chain)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, min(65_536, maximum + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > maximum:
            raise LiveEndpointIntegrationError("evidence exceeds its finite bound")
    return b"".join(chunks)


@dataclass(frozen=True, slots=True)
class CpuEvidenceReceipt:
    path: Path
    parent_path: Path
    sha256: str
    parent_chain: tuple[tuple[int, ...], ...]
    parent_identity: tuple[int, ...]
    file_identity: tuple[int, ...]
    _token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not CpuEvidenceReceipt or self._token is not _EVIDENCE_TOKEN:
            raise LiveEndpointIntegrationError("evidence receipt was not create-once minted")
        if (
            not self.path.is_absolute()
            or self.path.parent != self.parent_path
            or not self.parent_chain
            or self.parent_chain[-1] != self.parent_identity
        ):
            raise LiveEndpointIntegrationError("evidence receipt path binding is invalid")
        if (
            type(self.parent_chain) is not tuple
            or any(
                type(identity) is not tuple
                or any(type(coordinate) is not int for coordinate in identity)
                for identity in self.parent_chain
            )
            or type(self.parent_identity) is not tuple
            or any(type(coordinate) is not int for coordinate in self.parent_identity)
            or type(self.file_identity) is not tuple
            or any(type(coordinate) is not int for coordinate in self.file_identity)
        ):
            raise LiveEndpointIntegrationError("evidence receipt identity types are invalid")
        _sha256("evidence", self.sha256)


def write_cpu_receipt_create_once(
    *, path: str | Path, receipt: CpuEndpointReceipt
) -> CpuEvidenceReceipt:
    if type(receipt) is not CpuEndpointReceipt:
        raise LiveEndpointIntegrationError("evidence writer requires an exact CPU receipt")
    receipt.__post_init__()
    raw = _canonical_json(receipt.to_public_wire(), maximum=MAX_EVIDENCE_BYTES)
    target = Path(os.path.abspath(os.fspath(path)))
    if target.name in {"", ".", ".."} or Path(target.name).name != target.name:
        raise LiveEndpointIntegrationError("evidence target basename is invalid")
    parent_fd, parent_chain = _open_lexical_directory(target.parent)
    descriptor = -1
    rebound_parent_fd = -1
    rebound_file_fd = -1
    created_identity: tuple[int, int] | None = None
    success = False
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(target.name, flags, 0o600, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        created_identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 0
        ):
            raise LiveEndpointIntegrationError("new evidence file metadata is unsafe")
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise LiveEndpointIntegrationError("evidence write made no progress")
            view = view[count:]
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != created_identity
            or not stat.S_ISREG(final.st_mode)
            or final.st_uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_nlink != 1
            or final.st_size != len(raw)
            or _read_descriptor(descriptor, MAX_EVIDENCE_BYTES) != raw
        ):
            raise LiveEndpointIntegrationError("evidence same-descriptor authentication failed")
        stable = os.fstat(descriptor)
        if _regular_identity(stable) != _regular_identity(final):
            raise LiveEndpointIntegrationError("evidence changed during descriptor reread")
        rebound = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if _regular_identity(rebound) != _regular_identity(final):
            raise LiveEndpointIntegrationError("evidence basename binding changed")
        os.fsync(parent_fd)
        try:
            rebound_parent_fd, rebound_chain = _open_lexical_directory(target.parent)
        except (LiveEndpointIntegrationError, OSError) as exc:
            raise LiveEndpointIntegrationError(
                "evidence parent binding changed"
            ) from exc
        if rebound_chain != parent_chain:
            raise LiveEndpointIntegrationError("evidence parent binding changed")
        rebound_file_fd = os.open(
            target.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=rebound_parent_fd,
        )
        rebound_file = os.fstat(rebound_file_fd)
        if (
            _regular_identity(rebound_file) != _regular_identity(final)
            or _read_descriptor(rebound_file_fd, MAX_EVIDENCE_BYTES) != raw
            or _regular_identity(os.fstat(rebound_file_fd)) != _regular_identity(final)
        ):
            raise LiveEndpointIntegrationError("evidence rebound authentication failed")
        os.fsync(rebound_parent_fd)
        success = True
    except FileExistsError as exc:
        raise LiveEndpointIntegrationError("evidence output already exists") from exc
    except OSError as exc:
        raise LiveEndpointIntegrationError("evidence create-once write failed") from exc
    finally:
        if rebound_file_fd >= 0:
            os.close(rebound_file_fd)
        if rebound_parent_fd >= 0:
            os.close(rebound_parent_fd)
        if descriptor >= 0:
            os.close(descriptor)
        if created_identity is not None and not success:
            try:
                candidate = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                if (candidate.st_dev, candidate.st_ino) == created_identity:
                    os.unlink(target.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
    identity = _regular_identity(final)
    return CpuEvidenceReceipt(
        path=target,
        parent_path=target.parent,
        sha256=hashlib.sha256(raw).hexdigest(),
        parent_chain=parent_chain,
        parent_identity=parent_chain[-1],
        file_identity=identity,
        _token=_EVIDENCE_TOKEN,
    )


_PUBLIC_RECEIPT_FIELDS = frozenset(
    {
        "attempt_count",
        "chronology_sha256",
        "chronology_step_count",
        "detector_executed",
        "effectiveness_evidence",
        "endpoint_attestation_sha256",
        "fake_endpoint_exercised",
        "gpu_executed",
        "model_executed",
        "peer_identity_mode",
        "permit_sha256",
        "plan_sha256",
        "principal_eligible",
        "principal_outcome_count",
        "schedule_binding_sha256",
        "schema_version",
        "scoring_executed",
        "session_sha256",
        "sha256",
        "status",
        "transport_mode",
        "utility_evidence",
    }
)


def _validate_cpu_public_receipt_wire(value: object) -> dict[str, object]:
    body = _exact_object("CPU public receipt", value, _PUBLIC_RECEIPT_FIELDS)
    _literal(
        "CPU public receipt schema",
        body["schema_version"],
        "sluice-cpu-endpoint-receipt-v1",
    )
    _literal("CPU public receipt transport", body["transport_mode"], TRANSPORT_MODE)
    _literal(
        "CPU public receipt peer identity",
        body["peer_identity_mode"],
        PEER_IDENTITY_MODE,
    )
    for name in (
        "chronology_sha256",
        "endpoint_attestation_sha256",
        "permit_sha256",
        "plan_sha256",
        "schedule_binding_sha256",
        "session_sha256",
        "sha256",
    ):
        _sha256(name, body[name])
    attempt_count = _integer(
        "CPU public receipt attempt count",
        body["attempt_count"],
        minimum=1,
        maximum=MAX_ATTEMPTS,
    )
    _integer(
        "CPU public receipt chronology step count",
        body["chronology_step_count"],
        minimum=CHRONOLOGY_HMAX,
        maximum=CHRONOLOGY_HMAX,
    )
    _integer(
        "CPU public receipt principal outcome count",
        body["principal_outcome_count"],
        minimum=0,
        maximum=0,
    )
    _true("CPU public receipt fake endpoint flag", body["fake_endpoint_exercised"])
    for name in (
        "detector_executed",
        "effectiveness_evidence",
        "gpu_executed",
        "model_executed",
        "principal_eligible",
        "scoring_executed",
        "utility_evidence",
    ):
        _false(f"CPU public receipt {name}", body[name])
    try:
        status = CpuExchangeStatus(_text("CPU public receipt status", body["status"]))
    except ValueError as exc:
        raise LiveEndpointIntegrationError("CPU public receipt status is unknown") from exc
    if (
        status is CpuExchangeStatus.CPU_FAKE_RETRY_EXHAUSTED
        and attempt_count != MAX_ATTEMPTS
    ):
        raise LiveEndpointIntegrationError(
            "retry-exhausted public receipt has the wrong attempt count"
        )
    digest_body = dict(body)
    claimed = digest_body.pop("sha256")
    if claimed != _digest(b"sluice-cpu-endpoint-receipt-v1", digest_body):
        raise LiveEndpointIntegrationError("CPU public receipt digest mismatch")
    return body


def validate_cpu_evidence_receipt(receipt: CpuEvidenceReceipt) -> dict[str, object]:
    if type(receipt) is not CpuEvidenceReceipt:
        raise LiveEndpointIntegrationError("evidence receipt type is not exact")
    receipt.__post_init__()
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd, chain = _open_lexical_directory(receipt.parent_path)
        if chain != receipt.parent_chain or _directory_identity(
            os.fstat(parent_fd)
        ) != receipt.parent_identity:
            raise LiveEndpointIntegrationError("evidence parent identity changed")
        descriptor = os.open(
            receipt.path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if (
            _regular_identity(opened) != receipt.file_identity
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise LiveEndpointIntegrationError("evidence file identity changed")
        raw = _read_descriptor(descriptor, MAX_EVIDENCE_BYTES)
        if (
            _regular_identity(os.fstat(descriptor)) != receipt.file_identity
            or _regular_identity(
                os.stat(receipt.path.name, dir_fd=parent_fd, follow_symlinks=False)
            )
            != receipt.file_identity
            or hashlib.sha256(raw).hexdigest() != receipt.sha256
        ):
            raise LiveEndpointIntegrationError("evidence content/path binding changed")
    except LiveEndpointIntegrationError:
        raise
    except OSError as exc:
        raise LiveEndpointIntegrationError("evidence cannot be reopened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LiveEndpointIntegrationError("evidence JSON is malformed") from exc
    if type(value) is not dict or _canonical_json(value, maximum=MAX_EVIDENCE_BYTES) != raw:
        raise LiveEndpointIntegrationError("evidence JSON is not canonical")
    return _validate_cpu_public_receipt_wire(value)


__all__ = (
    "BenchmarkKind",
    "CHRONOLOGY_HMAX",
    "CpuEndpointChronology",
    "CpuEndpointReceipt",
    "CpuExchangeStatus",
    "CpuIntegrationPermit",
    "CpuLoopbackReply",
    "CpuLoopbackRequest",
    "CpuLoopbackSession",
    "EndpointRole",
    "FakeLoopbackEndpoint",
    "FakeReplyStatus",
    "FakeRetryPolicy",
    "LiveEndpointIntegrationError",
    "MAX_ATTEMPTS",
    "PEER_IDENTITY_MODE",
    "PROTOCOL_ID",
    "PinnedModelIdentity",
    "PrincipalEndpointPermit",
    "RuntimeIsolationPins",
    "ScheduleBinding",
    "TRANSPORT_MODE",
    "chronology_event_sha256",
    "cpu_chronology_sha256",
    "cpu_reply_sha256",
    "cpu_request_sha256",
    "establish_cpu_loopback",
    "validate_cpu_chronology_wire",
    "validate_cpu_evidence_receipt",
    "write_cpu_receipt_create_once",
)
