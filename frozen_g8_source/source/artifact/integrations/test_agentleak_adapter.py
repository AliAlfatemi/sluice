from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sluice_v2.evaluation.agentleak import (
    AGENTLEAK_COMMIT,
    CORPUS_SHA256,
    ALL_CHANNELS,
    AgentLeakAdapterError,
    DetectorRunError,
    ObserverChannel,
    ObserverPayloadEvent,
    ObserverTraceBuilder,
    PairKey,
    evaluate_utility,
    load_pinned_corpus,
    summarize_detection,
)


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
CORPUS = ARTIFACT_ROOT / "benchmarks" / "agentleak" / "scenarios_full_1000.jsonl"


def _builder() -> ObserverTraceBuilder:
    return ObserverTraceBuilder(
        trace_id="trace-1",
        scenario_id="agentleak_fin_00001",
        framework="sluice-isolated-v1",
        model_revision="model@0123456789abcdef",
        started_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
        audited_channels=ALL_CHANNELS,
    )


def test_pinned_source_and_corpus_constants() -> None:
    assert AGENTLEAK_COMMIT == "8f0631b9c9558ef337f86b71073b176d18badd1a"
    assert CORPUS_SHA256 == "c4688b860a0133e7434e788cf02baec0ae3f2b3b3bcd7f80088f4499dc52c352"
    assert tuple(channel.value for channel in ALL_CHANNELS) == (
        "C1_final_output",
        "C2_inter_agent",
        "C3_tool_input",
        "C4_tool_output",
        "C5_memory_write",
        "C6_log",
        "C7_artifact",
    )


def test_loader_accepts_only_the_exact_static_corpus() -> None:
    corpus = load_pinned_corpus(CORPUS)
    assert len(corpus.scenarios) == 1_000
    assert len({row["scenario_id"] for row in corpus.scenarios}) == 1_000
    assert corpus.sha256 == CORPUS_SHA256
    assert all(row["evaluation"]["success_oracle"] is None for row in corpus.scenarios)
    assert all(
        frozenset(row["evaluation"]["channels_to_audit"])
        == frozenset(channel.value for channel in ALL_CHANNELS)
        for row in corpus.scenarios
    )


def test_loader_rejects_modified_or_regenerated_input(tmp_path: Path) -> None:
    data = CORPUS.read_bytes()
    altered = tmp_path / "altered.jsonl"
    altered.write_bytes(data[:-1] + (b" " if data[-1:] != b" " else b"\n"))
    with pytest.raises(AgentLeakAdapterError, match="SHA-256"):
        load_pinned_corpus(altered)


def test_trace_requires_explicit_complete_channel_coverage() -> None:
    with pytest.raises(AgentLeakAdapterError, match="all seven"):
        ObserverTraceBuilder(
            trace_id="trace-1",
            scenario_id="agentleak_fin_00001",
            framework="sluice-isolated-v1",
            model_revision="model@0123456789abcdef",
            started_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
            audited_channels=frozenset({ObserverChannel.C1_FINAL_OUTPUT}),
        )


def test_trace_maps_every_channel_once_without_payload_duplication() -> None:
    builder = _builder()
    for sequence, channel in enumerate(ALL_CHANNELS, 1):
        builder.record(
            ObserverPayloadEvent(
                sequence=sequence,
                timestamp=datetime(2026, 8, 20, 0, 0, sequence, tzinfo=timezone.utc),
                scenario_id="agentleak_fin_00001",
                agent_id="A1",
                channel=channel,
                content=f"payload-{sequence}",
            )
        )
    sealed = builder.seal(completed_at=datetime(2026, 8, 20, 0, 1, tzinfo=timezone.utc))
    wire = sealed.to_agentleak_wire()
    assert [event["channel"] for event in wire["events"]] == [c.value for c in ALL_CHANNELS]
    assert [event["event_type"] for event in wire["events"]] == [
        "message_out",
        "agent_message",
        "tool_call",
        "tool_result",
        "memory_write",
        "log_event",
        "artifact_write",
    ]
    serialized = json.dumps(wire, sort_keys=True)
    for sequence in range(1, 8):
        assert serialized.count(f"payload-{sequence}") == 1


def test_trace_rejects_ambiguous_channel_sequence_and_post_seal_append() -> None:
    with pytest.raises(AgentLeakAdapterError, match="structured"):
        ObserverPayloadEvent(
            sequence=1,
            timestamp=datetime(2026, 8, 20, tzinfo=timezone.utc),
            scenario_id="agentleak_fin_00001",
            agent_id="A1",
            channel="C1_final_output",  # type: ignore[arg-type]
            content="x",
        )
    builder = _builder()
    event = ObserverPayloadEvent(
        sequence=2,
        timestamp=datetime(2026, 8, 20, tzinfo=timezone.utc),
        scenario_id="agentleak_fin_00001",
        agent_id="A1",
        channel=ObserverChannel.C1_FINAL_OUTPUT,
        content="x",
    )
    with pytest.raises(AgentLeakAdapterError, match="contiguous"):
        builder.record(event)
    builder.record(
        ObserverPayloadEvent(
            sequence=1,
            timestamp=datetime(2026, 8, 20, tzinfo=timezone.utc),
            scenario_id="agentleak_fin_00001",
            agent_id="A1",
            channel=ObserverChannel.C1_FINAL_OUTPUT,
            content="x",
        )
    )
    builder.seal(completed_at=datetime(2026, 8, 20, 0, 1, tzinfo=timezone.utc))
    with pytest.raises(AgentLeakAdapterError, match="sealed"):
        builder.record(
            ObserverPayloadEvent(
                sequence=2,
                timestamp=datetime(2026, 8, 20, tzinfo=timezone.utc),
                scenario_id="agentleak_fin_00001",
                agent_id="A1",
                channel=ObserverChannel.C2_INTER_AGENT,
                content="y",
            )
        )


def test_detector_exception_is_a_failed_run_and_public_summary_is_redacted() -> None:
    class BrokenPipeline:
        def detect(self, scenario, trace):
            raise RuntimeError("secret detector diagnostic: 123-45-6789")

    with pytest.raises(DetectorRunError, match="detector failed") as caught:
        summarize_detection(
            scenario_id="agentleak_fin_00001",
            result_factory=lambda: BrokenPipeline().detect(None, None),
        )
    assert "123-45-6789" not in str(caught.value)


def test_complete_detection_summary_exposes_indicators_not_secret_values() -> None:
    channel_results = {
        channel.value: SimpleNamespace(
            leaked=channel is ObserverChannel.C4_TOOL_OUTPUT,
            leak_count=1 if channel is ObserverChannel.C4_TOOL_OUTPUT else 0,
        )
        for channel in ALL_CHANNELS
    }
    result = SimpleNamespace(has_leakage=True, channel_results=channel_results)
    summary = summarize_detection(
        scenario_id="agentleak_fin_00001", result_factory=lambda: result
    )
    public = summary.to_public_record()
    assert public["any_channel_leakage"] is True
    assert public["final_output_leakage"] is False
    assert public["internal_channel_leakage"] is True
    assert public["output_only_miss"] is True
    assert public["per_channel"]["C4_tool_output"] is True
    assert "leaked_value" not in json.dumps(public)


@pytest.mark.parametrize("defect", ["missing", "count", "aggregate"])
def test_incomplete_or_inconsistent_detector_results_fail_closed(defect: str) -> None:
    channel_results = {
        channel.value: SimpleNamespace(leaked=False, leak_count=0)
        for channel in ALL_CHANNELS
    }
    has_leakage = False
    if defect == "missing":
        channel_results.pop(ObserverChannel.C7_ARTIFACT.value)
    elif defect == "count":
        channel_results[ObserverChannel.C2_INTER_AGENT.value] = SimpleNamespace(
            leaked=False, leak_count=1
        )
    else:
        has_leakage = True
    with pytest.raises(DetectorRunError):
        summarize_detection(
            scenario_id="agentleak_fin_00001",
            result_factory=lambda: SimpleNamespace(
                has_leakage=has_leakage, channel_results=channel_results
            ),
        )


def test_utility_oracle_is_separate_and_pinned() -> None:
    corpus = load_pinned_corpus(CORPUS)
    scenario = corpus.scenarios[0]
    sealed = _builder().seal(
        completed_at=datetime(2026, 8, 20, 0, 1, tzinfo=timezone.utc)
    )

    class FrozenOracle:
        oracle_id = "sluice-agentleak-utility-v1"
        oracle_sha256 = "a" * 64

        def evaluate(self, *, scenario, trace):
            assert scenario["evaluation"]["success_oracle"] is None
            assert trace is sealed
            return True

    result = evaluate_utility(oracle=FrozenOracle(), scenario=scenario, trace=sealed)
    assert result.success is True
    assert result.oracle_id == "sluice-agentleak-utility-v1"


def test_pair_key_excludes_condition_and_is_stable() -> None:
    mutable_config = {"temperature": 0.0, "max_tokens": 256}
    key = PairKey(
        scenario_id="agentleak_fin_00001",
        model_revision="model@0123456789abcdef",
        seed=104729,
        generation_config=mutable_config,
    )
    mutable_config["temperature"] = 1.0
    assert key.identifier() == PairKey(
        scenario_id="agentleak_fin_00001",
        model_revision="model@0123456789abcdef",
        seed=104729,
        generation_config={"max_tokens": 256, "temperature": 0.0},
    ).identifier()
    assert "baseline" not in key.identifier()
