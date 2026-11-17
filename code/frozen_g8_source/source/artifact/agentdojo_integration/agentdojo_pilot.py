"""Compatibility entry point for the prospective corrected RQ6 harness.

Run ``python3 agentdojo_pilot.py`` from the artifact root in new workflows.
This wrapper contains no machine-specific path.  The archived measurements
predate the corrected bridge and remain invalidated; see INVALIDATED_RQ6.md.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
if str(ARTIFACT_ROOT) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_ROOT))

from agentdojo_pilot import EFFECTFUL_TOOLS_BY_SUITE, run  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit-user-tasks", type=int, default=0)
    parser.add_argument("--limit-injection-tasks", type=int, default=0)
    parser.add_argument("--out", default="agentdojo_banking_results.json")
    parser.add_argument("--suite", choices=sorted(EFFECTFUL_TOOLS_BY_SUITE), default="banking")
    args = parser.parse_args(argv)
    run(
        args.limit_user_tasks or None,
        args.limit_injection_tasks or None,
        args.out,
        args.suite,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
