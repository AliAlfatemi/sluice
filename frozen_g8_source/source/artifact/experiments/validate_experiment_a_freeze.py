#!/usr/bin/env python3
"""Self-locating structural validator for the Experiment A freeze."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2.evaluation.experiment_a_freeze import validate_repository


def main() -> int:
    report = validate_repository(REPOSITORY_ROOT)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
