#!/usr/bin/env python3
"""Offline validation of the pinned Sluice-to-AgentLeak structured seam.

This is a schema/detector integration smoke, not a security-effectiveness run.
It performs no model inference and makes no network request.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from typing import Any, Mapping


HERE = Path(__file__).resolve().parent
ARTIFACT_ROOT = HERE.parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2.evaluation.agentleak import (  # noqa: E402
    ALL_CHANNELS,
    CORPUS_SHA256,
    ObserverChannel,
    ObserverPayloadEvent,
    ObserverTraceBuilder,
    load_agentleak_api,
    load_pinned_corpus,
    run_presidio_detection,
)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--corpus",
        type=Path,
        default=HERE / "scenarios_full_1000.jsonl",
    )
    args = parser.parse_args()

    api = load_agentleak_api(args.source_root)
    corpus = load_pinned_corpus(args.corpus)
    parsed = [api.Scenario.model_validate(_thaw(row)) for row in corpus.scenarios]

    scenario = parsed[0]
    canaries = list(scenario.evaluation.canaries)
    if not canaries:
        raise RuntimeError("selected pinned scenario has no deterministic canary")
    target = canaries[0]
    started = datetime(2026, 8, 20, tzinfo=timezone.utc)
    builder = ObserverTraceBuilder(
        trace_id="agentleak-adapter-offline-smoke-v1",
        scenario_id=scenario.scenario_id,
        framework="sluice-offline-adapter-smoke-v1",
        model_revision="no-model-offline-smoke",
        started_at=started,
        audited_channels=ALL_CHANNELS,
    )
    benign = {
        ObserverChannel.C1_FINAL_OUTPUT: "Task completed; no private record is displayed.",
        ObserverChannel.C2_INTER_AGENT: "Coordination complete.",
        ObserverChannel.C3_TOOL_INPUT: "lookup_case(public_case_id)",
        ObserverChannel.C4_TOOL_OUTPUT: f"restricted tool result: {target}",
        ObserverChannel.C5_MEMORY_WRITE: "workflow_status=complete",
        ObserverChannel.C6_LOG: "event=workflow_complete",
        ObserverChannel.C7_ARTIFACT: "public summary persisted",
    }
    for sequence, channel in enumerate(ALL_CHANNELS, 1):
        builder.record(
            ObserverPayloadEvent(
                sequence=sequence,
                timestamp=started + timedelta(seconds=sequence),
                scenario_id=scenario.scenario_id,
                agent_id=scenario.agents[0].agent_id,
                channel=channel,
                content=benign[channel],
            )
        )
    trace = builder.seal(completed_at=started + timedelta(seconds=8))
    summary = run_presidio_detection(
        api=api,
        scenario=corpus.scenarios[0],
        trace=trace,
    )
    public = summary.to_public_record()
    if not public["per_channel"][ObserverChannel.C4_TOOL_OUTPUT.value]:
        raise RuntimeError("pinned detector missed the injected C4 canary")
    if public["final_output_leakage"] or not public["output_only_miss"]:
        raise RuntimeError("channel attribution or output-only miss accounting is wrong")
    result = {
        "status": "pass",
        "mode": "offline_structured_adapter_smoke_not_effectiveness_evidence",
        "upstream_commit": "8f0631b9c9558ef337f86b71073b176d18badd1a",
        "corpus_sha256": CORPUS_SHA256,
        "parsed_scenarios": len(parsed),
        "declared_channels": [channel.value for channel in ALL_CHANNELS],
        "redacted_detector_summary": public,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

