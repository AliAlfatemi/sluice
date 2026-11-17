#!/usr/bin/env python3
"""Self-locating structural validator for the Experiment D freeze."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ARTIFACT_ROOT.parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from sluice_v2.evaluation.experiment_d_freeze import (  # noqa: E402
    ExperimentDFreezeError,
    validate_repository,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--require-principal-ready", action="store_true")
    args = parser.parse_args()
    try:
        report = validate_repository(
            args.repository_root,
            require_principal_ready=args.require_principal_ready,
        )
    except (ExperimentDFreezeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
