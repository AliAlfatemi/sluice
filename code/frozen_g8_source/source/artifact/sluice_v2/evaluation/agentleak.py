"""Pinned, fail-closed adapter for AgentLeak's structured seven-channel API.

This module is an *evaluation* adapter, not an enforcement mechanism.  It
loads the immutable AgentLeak corpus by digest, records the payload actually
observable on each declared channel exactly once, and converts a sealed trace
to AgentLeak's strict ``ExecutionTrace`` schema.  AgentLeak detector failures
are failed experimental runs; they are never interpreted as no leakage.

Raw detector objects may contain matched secrets.  Only ``LeakageSummary`` is
safe for public aggregate outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import importlib
import json
from pathlib import Path
import sys
import threading
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol


AGENTLEAK_REPOSITORY = "https://github.com/Privatris/AgentLeak"
AGENTLEAK_COMMIT = "8f0631b9c9558ef337f86b71073b176d18badd1a"
AGENTLEAK_VERSION = "1.0.0"
CORPUS_SHA256 = "c4688b860a0133e7434e788cf02baec0ae3f2b3b3bcd7f80088f4499dc52c352"
CORPUS_ROWS = 1_000
MAX_IDENTIFIER_BYTES = 512
MAX_CONTENT_BYTES = 1_048_576
MAX_TRACE_EVENTS = 1_000_000
MAX_JSON_BYTES = 1_048_576
MAX_INTEGER = (1 << 63) - 1

_PINNED_SOURCE_HASHES = MappingProxyType(
    {
        "agentleak/schemas/scenario.py": "aed4d4472796cca859a12a34c402a86f92d6cd9009c362bce292f36a0b493dad",
        "agentleak/schemas/trace.py": "ef526fd36714e328ff3054a81246ebde9df9376d2e89f23be1613db66b619443",
        "agentleak/detection/hybrid_pipeline.py": "1b88d3dba23dcf84b55267d1ad70ffc3f8cf3fa0b7f02587bc79048e9bd1a24a",
        "agentleak/detection/presidio_detector.py": "9232aaf25cea734720faaa5feab1a95be30f89b8b418405e8b5d9407939b051d",
    }
)


class AgentLeakAdapterError(ValueError):
    """The pinned corpus, source, or strict adapter contract is invalid."""


class DetectorRunError(RuntimeError):
    """The detector did not produce a complete, trustworthy result."""


class ObserverChannel(str, Enum):
    """AgentLeak's authoritative structured C1--C7 channel values."""

    C1_FINAL_OUTPUT = "C1_final_output"
    C2_INTER_AGENT = "C2_inter_agent"
    C3_TOOL_INPUT = "C3_tool_input"
    C4_TOOL_OUTPUT = "C4_tool_output"
    C5_MEMORY_WRITE = "C5_memory_write"
    C6_LOG = "C6_log"
    C7_ARTIFACT = "C7_artifact"


ALL_CHANNELS = tuple(ObserverChannel)
_ALL_CHANNEL_SET = frozenset(ALL_CHANNELS)
_EVENT_TYPE_BY_CHANNEL = MappingProxyType(
    {
        ObserverChannel.C1_FINAL_OUTPUT: "message_out",
        ObserverChannel.C2_INTER_AGENT: "agent_message",
        ObserverChannel.C3_TOOL_INPUT: "tool_call",
        ObserverChannel.C4_TOOL_OUTPUT: "tool_result",
        ObserverChannel.C5_MEMORY_WRITE: "memory_write",
        ObserverChannel.C6_LOG: "log_event",
        ObserverChannel.C7_ARTIFACT: "artifact_write",
    }
)
_CORPUS_CHANNEL_MIGRATION = MappingProxyType(
    {
        "final_output": ObserverChannel.C1_FINAL_OUTPUT.value,
        "inter_agent": ObserverChannel.C2_INTER_AGENT.value,
        "tool_input": ObserverChannel.C3_TOOL_INPUT.value,
        "tool_output": ObserverChannel.C4_TOOL_OUTPUT.value,
        "memory_write": ObserverChannel.C5_MEMORY_WRITE.value,
        "log": ObserverChannel.C6_LOG.value,
        "artifact": ObserverChannel.C7_ARTIFACT.value,
    }
)
_CORPUS_ATTACK_FAMILY_MIGRATION = MappingProxyType(
    {
        "F1": "prompt_instruction",
        "F2": "tool_surface",
        "F3": "memory_persistence",
        "F4": "multiagent_coordination",
    }
)


def _strict_int(name: str, value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_INTEGER:
        raise AgentLeakAdapterError(f"{name} must be a bounded integer")
    return value


def _bounded_text(name: str, value: object, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise AgentLeakAdapterError(f"{name} must be a string")
    size = len(value.encode("utf-8"))
    if (not allow_empty and not value) or size > MAX_IDENTIFIER_BYTES:
        raise AgentLeakAdapterError(f"{name} has an invalid length")
    return value


def _content(value: object) -> str:
    if type(value) is not str:
        raise AgentLeakAdapterError("content must be a string")
    if len(value.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise AgentLeakAdapterError("content exceeds the trace payload bound")
    return value


def _aware_datetime(name: str, value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise AgentLeakAdapterError(f"{name} must be a timezone-aware datetime")
    return value


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _freeze_json(value: Any) -> Any:
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise AgentLeakAdapterError("JSON object keys must be strings")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze_json(item) for item in value)
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise AgentLeakAdapterError("corpus contains a non-JSON value")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class PinnedCorpus:
    """An immutable in-memory view of the exact static primary corpus."""

    source_path: Path
    sha256: str
    scenarios: tuple[Mapping[str, Any], ...]

    def by_id(self, scenario_id: str) -> Mapping[str, Any]:
        scenario_id = _bounded_text("scenario_id", scenario_id)
        for scenario in self.scenarios:
            if scenario["scenario_id"] == scenario_id:
                return scenario
        raise KeyError(scenario_id)


def load_pinned_corpus(path: str | Path) -> PinnedCorpus:
    """Load the exact checked-in 1,000-case corpus or fail before parsing."""

    source = Path(path).resolve()
    if not source.is_file():
        raise AgentLeakAdapterError("pinned AgentLeak corpus is missing")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != CORPUS_SHA256:
        raise AgentLeakAdapterError("AgentLeak corpus SHA-256 does not match the pin")

    rows: list[Mapping[str, Any]] = []
    identifiers: set[str] = set()
    expected_legacy_channels = frozenset(_CORPUS_CHANNEL_MIGRATION)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentLeakAdapterError("AgentLeak corpus is not UTF-8") from exc
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise AgentLeakAdapterError(f"blank JSONL row at line {line_number}")
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise AgentLeakAdapterError(f"invalid JSONL row at line {line_number}") from exc
        if type(row) is not dict:
            raise AgentLeakAdapterError(f"row {line_number} is not an object")
        scenario_id = row.get("scenario_id")
        if type(scenario_id) is not str or not scenario_id or scenario_id in identifiers:
            raise AgentLeakAdapterError("scenario identifiers must be unique strings")
        evaluation = row.get("evaluation")
        if type(evaluation) is not dict:
            raise AgentLeakAdapterError("scenario evaluation must be an object")
        channels = evaluation.get("channels_to_audit")
        if (
            type(channels) is not list
            or len(channels) != len(ALL_CHANNELS)
            or frozenset(channels) != expected_legacy_channels
        ):
            raise AgentLeakAdapterError(
                "every raw scenario must name exactly all seven pinned legacy channels"
            )
        if evaluation.get("success_oracle", object()) is not None:
            raise AgentLeakAdapterError(
                "primary AgentLeak utility must use the separately frozen Sluice oracle"
            )
        identifiers.add(scenario_id)
        # The pinned JSONL predates the repository's structured Channel enum and
        # is rejected by AgentLeak's own Scenario model.  Apply the sole,
        # explicit, bijective migration after authenticating the raw bytes.
        # The original file remains untouched and identified by CORPUS_SHA256.
        normalized = dict(row)
        normalized_evaluation = dict(evaluation)
        normalized_evaluation["channels_to_audit"] = [
            _CORPUS_CHANNEL_MIGRATION[channel] for channel in channels
        ]
        normalized["evaluation"] = normalized_evaluation
        attack = row.get("attack")
        if type(attack) is not dict:
            raise AgentLeakAdapterError("scenario attack must be an object")
        normalized_attack = dict(attack)
        family = attack.get("attack_family")
        if family is not None:
            if family not in _CORPUS_ATTACK_FAMILY_MIGRATION:
                raise AgentLeakAdapterError("unknown pinned legacy attack family")
            normalized_attack["attack_family"] = _CORPUS_ATTACK_FAMILY_MIGRATION[family]
        target_channels = attack.get("target_channels")
        if type(target_channels) is not list or any(
            channel not in _CORPUS_CHANNEL_MIGRATION for channel in target_channels
        ):
            raise AgentLeakAdapterError("unknown pinned legacy attack target channel")
        normalized_attack["target_channels"] = [
            _CORPUS_CHANNEL_MIGRATION[channel] for channel in target_channels
        ]
        normalized["attack"] = normalized_attack
        rows.append(_freeze_json(normalized))

    if len(rows) != CORPUS_ROWS:
        raise AgentLeakAdapterError("AgentLeak corpus row count does not match the pin")
    return PinnedCorpus(source_path=source, sha256=digest, scenarios=tuple(rows))


@dataclass(frozen=True, slots=True)
class ObserverPayloadEvent:
    """One actual payload delivered on exactly one observer channel."""

    sequence: int
    timestamp: datetime
    scenario_id: str
    agent_id: str
    channel: ObserverChannel
    content: str

    def __post_init__(self) -> None:
        _strict_int("sequence", self.sequence, minimum=1)
        _aware_datetime("timestamp", self.timestamp)
        _bounded_text("scenario_id", self.scenario_id)
        _bounded_text("agent_id", self.agent_id)
        if type(self.channel) is not ObserverChannel:
            raise AgentLeakAdapterError("channel must use the structured C1-C7 enum")
        _content(self.content)

    def to_agentleak_wire(self) -> dict[str, Any]:
        """Return the strict TraceEvent wire shape without duplicating content."""

        return {
            "timestamp": _iso(self.timestamp),
            "sequence_num": self.sequence,
            "scenario_id": self.scenario_id,
            "agent_id": self.agent_id,
            "role": None,
            "event_type": _EVENT_TYPE_BY_CHANNEL[self.channel],
            "channel": self.channel.value,
            "content": self.content,
            "tool_name": None,
            "tool_args": None,
            "tool_output": None,
            "memory_key": None,
            "memory_value": None,
            "artifact_type": None,
            "artifact_path": None,
            "policy_context": None,
            "metadata": {},
        }


@dataclass(frozen=True, slots=True)
class SealedObserverTrace:
    """Complete evaluation trace after no further payload can be appended."""

    trace_id: str
    scenario_id: str
    framework: str
    model_revision: str
    started_at: datetime
    completed_at: datetime
    audited_channels: tuple[ObserverChannel, ...]
    events: tuple[ObserverPayloadEvent, ...]

    def to_agentleak_wire(self) -> dict[str, Any]:
        duration = (self.completed_at - self.started_at).total_seconds()
        return {
            "metadata": {
                "trace_id": self.trace_id,
                "scenario_id": self.scenario_id,
                "framework": self.framework,
                "model": self.model_revision,
                "started_at": _iso(self.started_at),
                "completed_at": _iso(self.completed_at),
                "duration_seconds": duration,
                "total_events": len(self.events),
                "total_tokens": 0,
                # Utility is deliberately computed by a separately frozen oracle.
                "success": None,
                "error": None,
            },
            "events": [event.to_agentleak_wire() for event in self.events],
        }

    def to_execution_trace(self, api: "AgentLeakAPI") -> Any:
        """Validate the wire through AgentLeak's real strict Pydantic model."""

        try:
            return api.ExecutionTrace.model_validate(self.to_agentleak_wire())
        except Exception as exc:
            raise AgentLeakAdapterError("AgentLeak rejected the structured trace") from exc


class ObserverTraceBuilder:
    """Single-use builder requiring explicit C1--C7 instrumentation."""

    def __init__(
        self,
        *,
        trace_id: str,
        scenario_id: str,
        framework: str,
        model_revision: str,
        started_at: datetime,
        audited_channels: Iterable[ObserverChannel],
    ) -> None:
        self._trace_id = _bounded_text("trace_id", trace_id)
        self._scenario_id = _bounded_text("scenario_id", scenario_id)
        self._framework = _bounded_text("framework", framework)
        self._model_revision = _bounded_text("model_revision", model_revision)
        self._started_at = _aware_datetime("started_at", started_at)
        declared = tuple(audited_channels)
        if len(declared) != len(ALL_CHANNELS) or frozenset(declared) != _ALL_CHANNEL_SET:
            raise AgentLeakAdapterError("the harness must explicitly instrument all seven channels")
        if any(type(channel) is not ObserverChannel for channel in declared):
            raise AgentLeakAdapterError("audited channels must use the structured enum")
        self._audited_channels = ALL_CHANNELS
        self._events: list[ObserverPayloadEvent] = []
        self._sealed = False

    def record(self, event: ObserverPayloadEvent) -> None:
        if self._sealed:
            raise AgentLeakAdapterError("a sealed observer trace cannot be changed")
        if type(event) is not ObserverPayloadEvent:
            raise AgentLeakAdapterError("trace events must be ObserverPayloadEvent values")
        expected = len(self._events) + 1
        if event.sequence != expected:
            raise AgentLeakAdapterError("trace sequence must be contiguous and start at one")
        if event.scenario_id != self._scenario_id:
            raise AgentLeakAdapterError("event scenario does not match the trace")
        if len(self._events) >= MAX_TRACE_EVENTS:
            raise AgentLeakAdapterError("trace exceeds the supported event horizon")
        self._events.append(event)

    def seal(self, *, completed_at: datetime) -> SealedObserverTrace:
        if self._sealed:
            raise AgentLeakAdapterError("observer trace is already sealed")
        completed = _aware_datetime("completed_at", completed_at)
        if completed < self._started_at:
            raise AgentLeakAdapterError("trace completion precedes its start")
        self._sealed = True
        return SealedObserverTrace(
            trace_id=self._trace_id,
            scenario_id=self._scenario_id,
            framework=self._framework,
            model_revision=self._model_revision,
            started_at=self._started_at,
            completed_at=completed,
            audited_channels=self._audited_channels,
            events=tuple(self._events),
        )


@dataclass(frozen=True, slots=True)
class PairKey:
    """Outcome-blind key shared by baseline and Sluice conditions."""

    scenario_id: str
    model_revision: str
    seed: int
    generation_config: Mapping[str, Any]

    def __post_init__(self) -> None:
        _bounded_text("scenario_id", self.scenario_id)
        _bounded_text("model_revision", self.model_revision)
        _strict_int("seed", self.seed)
        if not isinstance(self.generation_config, Mapping) or any(
            type(key) is not str for key in self.generation_config
        ):
            raise AgentLeakAdapterError("generation_config must be a string-keyed mapping")
        try:
            encoded = json.dumps(
                self.generation_config,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise AgentLeakAdapterError("generation_config is not canonical JSON") from exc
        if len(encoded) > MAX_JSON_BYTES:
            raise AgentLeakAdapterError("generation_config exceeds the supported bound")
        object.__setattr__(
            self,
            "generation_config",
            _freeze_json(json.loads(encoded.decode("utf-8"))),
        )

    def identifier(self) -> str:
        body = json.dumps(
            {
                "scenario_id": self.scenario_id,
                "model_revision": self.model_revision,
                "seed": self.seed,
                "generation_config": _thaw_json(self.generation_config),
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return "agentleak-pair-v1-" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True, slots=True)
class LeakageSummary:
    """Redacted per-scenario result safe for aggregate analysis."""

    scenario_id: str
    any_channel_leakage: bool
    final_output_leakage: bool
    internal_channel_leakage: bool
    output_only_miss: bool
    per_channel: Mapping[ObserverChannel, bool]
    leak_counts: Mapping[ObserverChannel, int]

    def to_public_record(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "detector_status": "ok",
            "any_channel_leakage": self.any_channel_leakage,
            "final_output_leakage": self.final_output_leakage,
            "internal_channel_leakage": self.internal_channel_leakage,
            "output_only_miss": self.output_only_miss,
            "per_channel": {
                channel.value: self.per_channel[channel] for channel in ALL_CHANNELS
            },
            "leak_counts": {
                channel.value: self.leak_counts[channel] for channel in ALL_CHANNELS
            },
        }


def summarize_detection(
    *, scenario_id: str, result_factory: Callable[[], Any]
) -> LeakageSummary:
    """Run a detector and expose only a complete redacted channel summary."""

    scenario_id = _bounded_text("scenario_id", scenario_id)
    if not callable(result_factory):
        raise AgentLeakAdapterError("result_factory must be callable")
    try:
        result = result_factory()
    except Exception:
        # Exception text may itself contain matched PII or raw model output.
        raise DetectorRunError("detector failed; restricted diagnostics required") from None

    channel_results = getattr(result, "channel_results", None)
    if not isinstance(channel_results, Mapping):
        raise DetectorRunError("detector returned an incomplete channel result")
    leaked: dict[ObserverChannel, bool] = {}
    counts: dict[ObserverChannel, int] = {}
    for raw_channel, raw_result in channel_results.items():
        value = getattr(raw_channel, "value", raw_channel)
        try:
            channel = ObserverChannel(value)
        except (TypeError, ValueError):
            raise DetectorRunError("detector returned an unknown channel") from None
        if channel in leaked:
            raise DetectorRunError("detector returned duplicate channel results")
        is_leaked = getattr(raw_result, "leaked", None)
        leak_count = getattr(raw_result, "leak_count", None)
        if type(is_leaked) is not bool or type(leak_count) is not int or leak_count < 0:
            raise DetectorRunError("detector returned a malformed channel result")
        if is_leaked != (leak_count > 0):
            raise DetectorRunError("detector returned an inconsistent channel result")
        leaked[channel] = is_leaked
        counts[channel] = leak_count
    if frozenset(leaked) != _ALL_CHANNEL_SET:
        raise DetectorRunError("detector did not report all seven channels")

    any_leak = any(leaked.values())
    reported_any = getattr(result, "has_leakage", None)
    if type(reported_any) is not bool or reported_any != any_leak:
        raise DetectorRunError("detector returned an inconsistent aggregate verdict")
    c1 = leaked[ObserverChannel.C1_FINAL_OUTPUT]
    internal = any(leaked[channel] for channel in ALL_CHANNELS[1:])
    return LeakageSummary(
        scenario_id=scenario_id,
        any_channel_leakage=any_leak,
        final_output_leakage=c1,
        internal_channel_leakage=internal,
        output_only_miss=internal and not c1,
        per_channel=MappingProxyType(leaked),
        leak_counts=MappingProxyType(counts),
    )


@dataclass(frozen=True, slots=True)
class AgentLeakAPI:
    """Exact classes imported from the pinned upstream checkout."""

    Scenario: type
    ExecutionTrace: type
    HybridConfig: type
    HybridPipeline: type
    presidio_available: bool
    source_root: Path


@dataclass(frozen=True, slots=True)
class UpstreamProvenance:
    source_root: Path
    commit: str
    source_hashes: Mapping[str, str]


def _checkout_commit(root: Path) -> str:
    git_dir = root / ".git"
    head_path = git_dir / "HEAD"
    if not head_path.is_file():
        raise AgentLeakAdapterError("AgentLeak checkout has no Git HEAD")
    head = head_path.read_text(encoding="ascii").strip()
    if not head.startswith("ref: "):
        return head
    ref = head[5:]
    ref_path = git_dir / ref
    if ref_path.is_file():
        return ref_path.read_text(encoding="ascii").strip()
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="ascii").splitlines():
            if line and not line.startswith(("#", "^")):
                commit, candidate = line.split(" ", 1)
                if candidate == ref:
                    return commit
    raise AgentLeakAdapterError("AgentLeak checkout HEAD cannot be resolved")


def validate_upstream_checkout(source_root: str | Path) -> UpstreamProvenance:
    """Verify the commit and adapter-critical files without invoking Git."""

    root = Path(source_root).resolve()
    if not root.is_dir():
        raise AgentLeakAdapterError("AgentLeak source checkout is missing")
    commit = _checkout_commit(root)
    if commit != AGENTLEAK_COMMIT:
        raise AgentLeakAdapterError("AgentLeak checkout is not at the pinned commit")
    observed: dict[str, str] = {}
    for relative, expected in _PINNED_SOURCE_HASHES.items():
        path = root / relative
        if not path.is_file():
            raise AgentLeakAdapterError(f"pinned AgentLeak source file is missing: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise AgentLeakAdapterError(f"pinned AgentLeak source file changed: {relative}")
        observed[relative] = digest
    upstream_corpus = root / "agentleak_data/datasets/scenarios_full_1000.jsonl"
    if hashlib.sha256(upstream_corpus.read_bytes()).hexdigest() != CORPUS_SHA256:
        raise AgentLeakAdapterError("upstream AgentLeak corpus does not match the pin")
    return UpstreamProvenance(root, commit, MappingProxyType(observed))


_IMPORT_LOCK = threading.Lock()


def load_agentleak_api(source_root: str | Path) -> AgentLeakAPI:
    """Import only the verified checkout and return the structured API classes."""

    provenance = validate_upstream_checkout(source_root)
    root_text = str(provenance.source_root)
    with _IMPORT_LOCK:
        loaded = [
            module
            for name, module in sys.modules.items()
            if name == "agentleak" or name.startswith("agentleak.")
        ]
        for module in loaded:
            module_file = getattr(module, "__file__", None)
            if module_file is not None and not Path(module_file).resolve().is_relative_to(
                provenance.source_root
            ):
                raise AgentLeakAdapterError(
                    "a different AgentLeak installation is already loaded"
                )
        inserted = root_text not in sys.path
        if inserted:
            sys.path.insert(0, root_text)
        try:
            package = importlib.import_module("agentleak")
            scenario_module = importlib.import_module("agentleak.schemas.scenario")
            trace_module = importlib.import_module("agentleak.schemas.trace")
            hybrid_module = importlib.import_module("agentleak.detection.hybrid_pipeline")
            presidio_module = importlib.import_module("agentleak.detection.presidio_detector")
        except Exception as exc:
            raise AgentLeakAdapterError("pinned AgentLeak API import failed") from exc
        finally:
            if inserted:
                sys.path.remove(root_text)
        if getattr(package, "__version__", None) != AGENTLEAK_VERSION:
            raise AgentLeakAdapterError("AgentLeak package version does not match the pin")
        channel_values = {member.value for member in scenario_module.Channel}
        if channel_values != {channel.value for channel in ALL_CHANNELS}:
            raise AgentLeakAdapterError("AgentLeak structured channel schema drifted")
        return AgentLeakAPI(
            Scenario=scenario_module.Scenario,
            ExecutionTrace=trace_module.ExecutionTrace,
            HybridConfig=hybrid_module.HybridConfig,
            HybridPipeline=hybrid_module.HybridPipeline,
            presidio_available=bool(presidio_module.PRESIDIO_AVAILABLE),
            source_root=provenance.source_root,
        )


def run_presidio_detection(
    *,
    api: AgentLeakAPI,
    scenario: Mapping[str, Any] | Any,
    trace: SealedObserverTrace,
) -> LeakageSummary:
    """Run the deterministic AgentLeak tier through its structured API."""

    if type(api) is not AgentLeakAPI:
        raise AgentLeakAdapterError("api must be a verified AgentLeakAPI")
    if not api.presidio_available:
        raise DetectorRunError("pinned Presidio detector is unavailable")
    if type(trace) is not SealedObserverTrace:
        raise AgentLeakAdapterError("trace must be sealed before detection")
    try:
        if isinstance(scenario, Mapping):
            scenario_object = api.Scenario.model_validate(_thaw_json(scenario))
        elif isinstance(scenario, api.Scenario):
            scenario_object = scenario
        else:
            raise TypeError("unexpected scenario type")
    except Exception as exc:
        raise AgentLeakAdapterError("AgentLeak rejected the pinned scenario") from exc
    if scenario_object.scenario_id != trace.scenario_id:
        raise AgentLeakAdapterError("scenario and trace identifiers differ")
    expected = {channel.value for channel in ALL_CHANNELS}
    if {channel.value for channel in scenario_object.evaluation.channels_to_audit} != expected:
        raise AgentLeakAdapterError("scenario does not declare all seven channels")
    if scenario_object.evaluation.success_oracle is not None:
        raise AgentLeakAdapterError("AgentLeak utility oracle must remain unused")
    structured_trace = trace.to_execution_trace(api)
    config = api.HybridConfig(enable_presidio=True, enable_llm_judge=False)
    pipeline = api.HybridPipeline(config)
    return summarize_detection(
        scenario_id=trace.scenario_id,
        result_factory=lambda: pipeline.detect(scenario_object, structured_trace),
    )


class UtilityOracle(Protocol):
    """Frozen Sluice-owned utility oracle, deliberately separate from AgentLeak."""

    oracle_id: str
    oracle_sha256: str

    def evaluate(self, *, scenario: Mapping[str, Any], trace: SealedObserverTrace) -> bool:
        ...


@dataclass(frozen=True, slots=True)
class UtilityAssessment:
    oracle_id: str
    oracle_sha256: str
    success: bool


def evaluate_utility(
    *,
    oracle: UtilityOracle,
    scenario: Mapping[str, Any],
    trace: SealedObserverTrace,
) -> UtilityAssessment:
    """Evaluate utility without consulting AgentLeak's null success oracle."""

    oracle_id = _bounded_text("oracle_id", getattr(oracle, "oracle_id", None))
    oracle_sha256 = getattr(oracle, "oracle_sha256", None)
    if type(oracle_sha256) is not str or len(oracle_sha256) != 64:
        raise AgentLeakAdapterError("utility oracle must expose a SHA-256 pin")
    try:
        int(oracle_sha256, 16)
    except ValueError as exc:
        raise AgentLeakAdapterError("utility oracle SHA-256 is malformed") from exc
    if scenario["evaluation"]["success_oracle"] is not None:
        raise AgentLeakAdapterError("upstream utility oracle must remain unused")
    try:
        success = oracle.evaluate(scenario=scenario, trace=trace)
    except Exception:
        raise DetectorRunError("utility oracle failed; restricted diagnostics required") from None
    if type(success) is not bool:
        raise DetectorRunError("utility oracle returned a non-boolean result")
    return UtilityAssessment(oracle_id, oracle_sha256, success)


__all__ = [
    "AGENTLEAK_COMMIT",
    "AGENTLEAK_REPOSITORY",
    "AGENTLEAK_VERSION",
    "ALL_CHANNELS",
    "CORPUS_ROWS",
    "CORPUS_SHA256",
    "AgentLeakAPI",
    "AgentLeakAdapterError",
    "DetectorRunError",
    "LeakageSummary",
    "ObserverChannel",
    "ObserverPayloadEvent",
    "ObserverTraceBuilder",
    "PairKey",
    "PinnedCorpus",
    "SealedObserverTrace",
    "UtilityAssessment",
    "evaluate_utility",
    "load_agentleak_api",
    "load_pinned_corpus",
    "run_presidio_detection",
    "summarize_detection",
    "validate_upstream_checkout",
]
