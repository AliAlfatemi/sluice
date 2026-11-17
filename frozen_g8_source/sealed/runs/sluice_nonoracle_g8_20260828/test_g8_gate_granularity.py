#!/usr/bin/env python3
"""Regression for G8 shard and six-receipt brokerage integrity."""

from __future__ import annotations

import copy
from pathlib import Path

import node_arm_runner_c4 as runner
from verify_c4_batch import verify_batch_binding_evidence


ROOT = Path(__file__).resolve().parent


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def receipt(shard: int, calls: int, bound: int) -> dict:
    return {
        "shard_index": shard,
        "sluice_arms_with_tool_calls": calls,
        "sluice_arms_bound_true": bound,
        "sluice_arms_toolcalling_but_unbound": [],
        "sluice_arms_bound_without_tool_call": [],
    }


def must_fail(rows: list[dict], needle: str) -> None:
    try:
        verify_batch_binding_evidence(rows)
    except ValueError as exc:
        require(needle in str(exc), f"wrong refusal for {needle!r}: {exc}")
    else:
        raise RuntimeError(f"invalid batch accepted: expected {needle!r}")


def main() -> int:
    zero_call_row = {
        "arm_id": "zero-call",
        "errored": False,
        "official_agentdojo_verdict_observed": True,
        "parsed_any_official_tool_call": False,
        "bound": False,
        "ledger_consistent": True,
    }
    empty_shard = runner.evaluate_sluice_binding_gates([zero_call_row])
    require(
        empty_shard["gates"]["sluice_every_toolcalling_arm_brokered"] is True,
        "zero-call shard did not satisfy the implication",
    )
    bound_row = {
        "arm_id": "bound",
        "errored": False,
        "official_agentdojo_verdict_observed": True,
        "parsed_any_official_tool_call": True,
        "bound": True,
        "ledger_consistent": True,
    }
    require(
        runner.evaluate_sluice_binding_gates([bound_row])["gates"]
        ["sluice_every_toolcalling_arm_brokered"] is True,
        "bound tool-calling arm failed",
    )
    unbound_row = dict(bound_row, arm_id="unbound", bound=False)
    require(
        runner.evaluate_sluice_binding_gates([unbound_row])["gates"]
        ["sluice_every_toolcalling_arm_brokered"] is False,
        "unbound tool-calling arm passed",
    )
    brokered_without_call = dict(
        zero_call_row, arm_id="brokered-without-call", bound=True
    )
    require(
        runner.evaluate_sluice_binding_gates([brokered_without_call])["gates"]
        ["sluice_no_arm_brokered_without_a_tool_call"] is False,
        "brokered-without-call arm passed",
    )
    inconsistent = dict(bound_row, arm_id="inconsistent", ledger_consistent=False)
    require(
        runner.evaluate_sluice_binding_gates([inconsistent])["gates"]
        ["sluice_effect_ledger_consistent_every_arm"] is False,
        "inconsistent effect ledger passed",
    )

    # Exact G6 Mistral seed-196613 brokerage projection.
    g6_projection = [
        receipt(0, 0, 0), receipt(1, 0, 0), receipt(2, 6, 6),
        receipt(3, 0, 0), receipt(4, 6, 6), receipt(5, 0, 0),
    ]
    require(verify_batch_binding_evidence(g6_projection) == {
        "sluice_toolcalling_arms": 12,
        "sluice_bound_arms": 12,
        "sluice_unbound_arms": 0,
    }, "exact G6 counterfactual did not pass 12/12")

    require(verify_batch_binding_evidence(
        [receipt(i, 0, 0) for i in range(6)]
    ) == {
        "sluice_toolcalling_arms": 0,
        "sluice_bound_arms": 0,
        "sluice_unbound_arms": 0,
    }, "exact G7 zero-call batch outcome did not pass 0/0")
    missing = g6_projection[:-1]
    must_fail(missing, "expected six receipts")
    duplicate = copy.deepcopy(g6_projection)
    duplicate[-1]["shard_index"] = 4
    must_fail(duplicate, "duplicate shard_index")
    unbound = copy.deepcopy(g6_projection)
    unbound[2]["sluice_arms_toolcalling_but_unbound"] = ["arm-x"]
    must_fail(unbound, "must be empty")
    without_call = copy.deepcopy(g6_projection)
    without_call[0]["sluice_arms_bound_without_tool_call"] = ["arm-y"]
    must_fail(without_call, "must be empty")
    mismatch = copy.deepcopy(g6_projection)
    mismatch[2]["sluice_arms_bound_true"] = 5
    must_fail(mismatch, "brokerage count mismatch")
    boolean = copy.deepcopy(g6_projection)
    boolean[2]["sluice_arms_with_tool_calls"] = True
    must_fail(boolean, "strict integer")
    negative = copy.deepcopy(g6_projection)
    negative[2]["sluice_arms_bound_true"] = -1
    must_fail(negative, "strict integer")
    floating = copy.deepcopy(g6_projection)
    floating[2]["sluice_arms_with_tool_calls"] = 6.0
    must_fail(floating, "strict integer")
    textual = copy.deepcopy(g6_projection)
    textual[2]["sluice_arms_bound_true"] = "6"
    must_fail(textual, "strict integer")
    missing_count = copy.deepcopy(g6_projection)
    del missing_count[2]["sluice_arms_bound_true"]
    must_fail(missing_count, "strict integer")

    launcher = (ROOT / "launch_c4_matrix.sh").read_text(encoding="utf-8")
    phase = launcher.index('log_line "phase=execute"')
    round_loop = launcher.index("for round in 0 1 2 3", phase)
    barrier = launcher.index('"$here/verify_c4_batch.py"', round_loop)
    matrix_pass = launcher.index('log_line "G1 matrix pass finished"', barrier)
    require(
        launcher.count('"$here/verify_c4_batch.py"') == 1,
        "launcher must invoke the batch verifier exactly once",
    )
    require(round_loop < barrier < matrix_pass,
            "batch verifier is not inside Phase E before matrix pass")
    require(
        '    done\n    if ! batch_summary="$("$py"' in launcher[round_loop:barrier],
        "batch verifier is not outside the retry-round loop",
    )
    require('mark_failed "execute_${label}_batch_verification"' in
            launcher[barrier:matrix_pass],
            "batch-verifier failure is not terminal")
    require(
        "mistral7b-v03 granite31-8b qwen25-3b" in launcher[:phase],
        "predecessor failure-class model is not first",
    )

    print("21/21 G8 gate-granularity assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
