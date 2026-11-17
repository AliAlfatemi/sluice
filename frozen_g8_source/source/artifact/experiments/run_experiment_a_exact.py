#!/usr/bin/env python3
"""Emit the CPU-only exact 656-path Experiment A known-answer corpus."""

from __future__ import annotations

from pathlib import Path
import sys


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2.evaluation.experiment_a_freeze import validate_repository
from sluice_v2.evaluation.experiment_a_runner import generate_trace_records, trace_bytes


def main() -> int:
    validate_repository(REPOSITORY_ROOT)
    sys.stdout.buffer.write(trace_bytes(generate_trace_records()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
