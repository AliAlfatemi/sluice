#!/usr/bin/env python3
"""Fail closed unless one C4 model/seed batch has six valid receipts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat

import analyze_agentdojo_journals_c4 as analyzer
import c4_shard_status


def _strict_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative strict integer")
    return value


def _empty_string_list(value: object, label: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a list of strings")
    if value:
        raise ValueError(f"{label} must be empty")


def verify_batch_binding_evidence(receipts: list[dict]) -> dict[str, int]:
    """Authenticate brokerage integrity at complete model/seed batch scope."""

    if len(receipts) != 6:
        raise ValueError(f"expected six receipts, observed {len(receipts)}")
    observed_shards: set[int] = set()
    toolcalling = 0
    bound = 0
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise ValueError(f"receipt {index} is not an object")
        shard = _strict_nonnegative_int(
            receipt.get("shard_index"), f"receipt {index} shard_index"
        )
        if shard >= 6 or shard in observed_shards:
            raise ValueError(f"invalid or duplicate shard_index {shard}")
        observed_shards.add(shard)
        shard_toolcalling = _strict_nonnegative_int(
            receipt.get("sluice_arms_with_tool_calls"),
            f"shard {shard} sluice_arms_with_tool_calls",
        )
        shard_bound = _strict_nonnegative_int(
            receipt.get("sluice_arms_bound_true"),
            f"shard {shard} sluice_arms_bound_true",
        )
        _empty_string_list(
            receipt.get("sluice_arms_toolcalling_but_unbound"),
            f"shard {shard} sluice_arms_toolcalling_but_unbound",
        )
        _empty_string_list(
            receipt.get("sluice_arms_bound_without_tool_call"),
            f"shard {shard} sluice_arms_bound_without_tool_call",
        )
        if shard_bound != shard_toolcalling:
            raise ValueError(
                f"shard {shard} brokerage count mismatch: "
                f"toolcalling={shard_toolcalling} bound={shard_bound}"
            )
        toolcalling += shard_toolcalling
        bound += shard_bound
    if observed_shards != set(range(6)):
        raise ValueError(f"shard coverage mismatch: {sorted(observed_shards)}")
    if bound != toolcalling:
        raise ValueError(
            f"batch brokerage count mismatch: toolcalling={toolcalling} bound={bound}"
        )
    return {
        "sluice_toolcalling_arms": toolcalling,
        "sluice_bound_arms": bound,
        "sluice_unbound_arms": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    selected_receipts: list[Path] = []
    selected_receipt_values: list[dict] = []
    planned = terminal = errors = 0
    observed_set_hashes: set[str] = set()
    observed_seal_hashes: set[str] = set()
    observed_set_ids: set[str] = set()
    for shard in range(6):
        try:
            state = c4_shard_status.status(args.root, args.model, args.seed, shard)
        except Exception as exc:
            raise SystemExit(f"shard {shard}: {exc}") from exc
        if state != "complete":
            raise SystemExit(f"shard {shard}: incomplete; next attempt {state}")
        label = f"{args.model}_plan_c4full_{args.model}_s{args.seed}_s{shard}of6"
        plan_path = (
            args.root / "plans"
            / f"plan_c4full_{args.model}_s{args.seed}_s{shard}of6.json"
        )
        plan = json.loads(plan_path.read_bytes())
        policy_binding, policy_set_sha256, policy_seal_sha256 = (
            c4_shard_status.sealed_binding_for(args.root, plan_path)
        )
        observed_set_hashes.add(policy_set_sha256)
        observed_seal_hashes.add(policy_seal_sha256)
        observed_set_ids.add(str(policy_binding["policy_set_id"]))
        journal_path = args.root / "journals" / f"journal_{label}.jsonl"
        runner_journal = c4_shard_status.runner.Journal(journal_path)
        replay = runner_journal.replay()
        if not runner_journal.chain_ok:
            raise SystemExit(f"shard {shard}: invalid journal chain: {replay}")
        shard_planned = 2 * len(plan["rows"])
        candidates = []
        for path in (args.root / "receipts").glob(f"*_{label}_a*.json"):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise SystemExit(
                    f"shard {shard}: receipt is not a regular file: {path}"
                )
            receipt = json.loads(path.read_bytes())
            match = re.search(r"_a([0-9]+)\.json$", path.name)
            if match and c4_shard_status.receipt_certifies(
                receipt,
                receipt_path=path,
                plan=plan,
                plan_sha256=analyzer.file_sha256(plan_path),
                journal=runner_journal,
                journal_path=journal_path,
                planned=shard_planned,
                policy_binding=policy_binding,
                policy_set_sha256=policy_set_sha256,
                policy_seal_sha256=policy_seal_sha256,
                root=args.root,
            ):
                candidates.append((int(match.group(1)), path, receipt))
        if not candidates:
            raise SystemExit(f"shard {shard}: no journal-bound green receipt")
        _attempt, path, receipt = max(candidates)
        selected_receipts.append(path)
        selected_receipt_values.append(receipt)
        planned += int(receipt["planned_arm_count"])
        terminal += int(receipt["journal_completed_arms"])
        journal = analyzer.authenticate_journal(journal_path)
        errors += sum(arm.get("error") is not None for arm in journal.arms)
    try:
        brokerage = verify_batch_binding_evidence(selected_receipt_values)
    except ValueError as exc:
        raise SystemExit(f"batch brokerage barrier: {exc}") from exc
    if (
        len(observed_set_hashes) != 1
        or len(observed_seal_hashes) != 1
        or len(observed_set_ids) != 1
    ):
        raise SystemExit("batch shards do not share one exact C4 policy seal")
    if (planned, terminal) != (2092, 2092):
        raise SystemExit(
            f"batch count mismatch planned={planned} terminal={terminal}"
        )
    # Run the analysis-time authenticator after every batch, not only after
    # the entire 31,380-arm matrix.  It validates all completed journal rows
    # against their exact plans, frozen sequence, C4 arm IDs, sealed policy
    # bindings, Boolean outcomes, and context-overflow terminal semantics.
    all_plans = analyzer.load_plans(
        [args.root / "plans"], "plan_c4full_*_s*of6.json"
    )
    all_journals = analyzer.load_journals([args.root / "journals"])
    policy_context = analyzer.authenticate_c4_policy_context(
        args.root, all_journals, all_plans
    )
    authenticated_arms, schedule = analyzer.prepare_schedule(
        all_journals,
        all_plans,
        "sluice_nonoracle",
        "undefended",
        policy_context,
    )
    selected_observed = [
        arm
        for arm in authenticated_arms
        if arm.get("model_slug") == args.model
        and arm.get("generation_seed") == args.seed
        and not arm.get("_synthetic_missing")
    ]
    if len(selected_observed) != 2092:
        raise SystemExit(
            "analysis-time batch authentication count mismatch: "
            f"{len(selected_observed)}"
        )
    print(json.dumps({
        "model": args.model,
        "seed": args.seed,
        "planned_arms": planned,
        "terminal_arms": terminal,
        "errored_arms": errors,
        "policy_set_id": next(iter(observed_set_ids)),
        "policy_set_file_sha256": next(iter(observed_set_hashes)),
        "policy_seal_file_sha256": next(iter(observed_seal_hashes)),
        "matrix_observed_arms_authenticated": schedule["observed_arm_count"],
        "receipts": [path.name for path in selected_receipts],
        **brokerage,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
