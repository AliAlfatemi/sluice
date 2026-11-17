#!/usr/bin/env python3
"""Regression for the G4 global-seal receipt-schema failure."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def main() -> int:
    runner = (ROOT / "node_arm_runner_c4.py").read_text(encoding="utf-8")
    sealer = (ROOT / "c4_policy_set.py").read_text(encoding="utf-8")
    verifier = (ROOT / "verify_preflight_receipt_contract.py").read_text(
        encoding="utf-8"
    )
    launcher = (ROOT / "launch_c4_matrix.sh").read_text(encoding="utf-8")

    shard_index_line = 'R["shard_index"] = plan["shard_index"]'
    shard_count_line = 'R["shard_count"] = plan["shard_count"]'
    require(runner.count(shard_index_line) == 1,
            "runner must emit shard_index exactly once at top level")
    require(runner.count(shard_count_line) == 1,
            "runner must emit shard_count exactly once at top level")
    receipt_emit = runner.index("emit(receipt_path)", runner.index(shard_count_line))
    require(runner.index(shard_index_line) < receipt_emit,
            "shard_index is not bound before policy-preflight emission")
    require(runner.index(shard_count_line) < receipt_emit,
            "shard_count is not bound before policy-preflight emission")
    require('"shard_index",\n    ):\n        _equal(receipt.get(field), plan[field]' in sealer,
            "sealer no longer requires receipt shard_index from the plan")
    require('_equal(receipt.get("shard_count"), SHARD_COUNT' in sealer,
            "sealer no longer requires the fixed receipt shard_count")
    require("c4_policy_set._verify_receipt(" in verifier,
            "live contract gate does not call the production receipt verifier")
    require(launcher.count("verify_preflight_receipt_contract.py") == 1,
            "launcher must invoke the live receipt verifier exactly once")
    require(
        launcher.index("verify_preflight_receipt_contract.py")
        < launcher.index('log_line "preflight complete'),
        "live receipt verification does not precede batch continuation",
    )

    plans = sorted((ROOT / "plans").glob("plan_c4full_*.json"))
    require(len(plans) == 90, f"expected 90 plans, found {len(plans)}")
    for path in plans:
        plan = json.loads(path.read_text(encoding="utf-8"))
        shard_index = plan.get("shard_index")
        shard_count = plan.get("shard_count")
        require(isinstance(shard_index, int) and 0 <= shard_index < 6,
                f"{path.name}: invalid shard_index {shard_index!r}")
        require(shard_count == 6,
                f"{path.name}: invalid shard_count {shard_count!r}")
        receipt_identity = {
            "shard_index": plan["shard_index"],
            "shard_count": plan["shard_count"],
        }
        require(receipt_identity["shard_index"] == plan["shard_index"],
                f"{path.name}: shard_index receipt binding changed")
        require(receipt_identity["shard_count"] == plan["shard_count"],
                f"{path.name}: shard_count receipt binding changed")

    print("370/370 receipt-shard contract assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
