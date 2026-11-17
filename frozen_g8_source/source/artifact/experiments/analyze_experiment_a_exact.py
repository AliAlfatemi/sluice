#!/usr/bin/env python3
"""Run and analyze the exact CPU-only Experiment A known-answer corpus."""

from __future__ import annotations

from pathlib import Path
import sys


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2.evaluation.experiment_a_analyzer import analyze_traces
from sluice_v2.evaluation.experiment_a_freeze import canonical_json, validate_repository
from sluice_v2.evaluation.experiment_a_runner import generate_trace_records


def main() -> int:
    validate_repository(REPOSITORY_ROOT)
    report = analyze_traces(generate_trace_records())
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
