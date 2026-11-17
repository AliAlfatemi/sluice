#!/usr/bin/env python3
"""Return ``complete`` or the next create-only attempt tag for one C4 shard."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Mapping

import c4_policy_set
import node_arm_runner_c4 as runner
import wrapper_completion_c5


PROVENANCE_FIELDS = (
    "expected_run_head",
    "expected_c4_manifest_sha256",
    "expected_launch_sha256",
    "expected_dispatch_sha256",
    "expected_wrapper_sha256",
    "expected_payload_sha256",
    "expected_plan_sums_sha256",
    "expected_harness_lib_sha256",
)

C4_RUN_ID = runner.C4_RUN_ID
EXECUTION_RECEIPT_SCHEMA = "sluice_agentdojo_c4_execution_receipt/1"
RUNNER_RECEIPT_SCHEMA = "sluice_agentdojo_arm_runner/1"
MATRIX_ACTIVE_FILENAME = "MATRIX_ACTIVE"
EXECUTION_ACTIVE_FILENAME = "C4_EXECUTION_ACTIVE"
AGENTDOJO_RUNTIME_MANIFEST_SHA256 = (
    "301db416517d7d0b32392ac7913c9a024ded713d77975c626d1f00b5ee94b996"
)
AGENTDOJO_LOADED_ASSET_TREE_SHA256 = (
    "9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a"
)
POLICY_BINDING_FIELDS = (
    "policy_preflight_id",
    "policy_bundle_id",
    "policy_request_file_sha256",
    "policy_bundle_file_sha256",
    "policy_request_sha256",
    "policy_bundle_sha256",
    "organization_policy_sha256",
    "split_manifest_sha256",
    "policy_author_split_sha256",
    "policy_manifest_count",
    "policy_episode_set_sha256",
    "policy_authoring_report_file_sha256",
    "policy_model_authored_task_count",
    "policy_context_overflow_fallback_task_count",
    "policy_fallback_unit_set_sha256",
)


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(f"{label} is not a regular non-symlink file: {path}")


def _regular_directory(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise RuntimeError(f"{label} is not a non-symlink directory: {path}")


def _load_json_object(path: Path, label: str) -> dict:
    _regular_file(path, label)

    def unique_object(pairs: list[tuple[str, object]]) -> dict:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError(f"{label} has duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(
            path.read_bytes().decode("utf-8"), object_pairs_hook=unique_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object: {path}")
    return value


def _marker(path: Path, label: str, expected_fields: set[str]) -> dict[str, str]:
    _regular_file(path, label)
    try:
        text = path.read_bytes().decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{label} is not ASCII") from exc
    if not text.endswith("\n"):
        raise RuntimeError(f"{label} has no final newline")
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator != "=" or not key or not value or key in values:
            raise RuntimeError(f"malformed {label} line: {line!r}")
        values[key] = value
    if set(values) != expected_fields:
        raise RuntimeError(
            f"{label} fields mismatch: observed={sorted(values)} "
            f"expected={sorted(expected_fields)}"
        )
    return values


def active_bindings_for(root: Path) -> dict[str, str]:
    """Authenticate the launch and execute markers for this immutable run."""

    matrix = _marker(
        root / MATRIX_ACTIVE_FILENAME,
        "C4 matrix-active marker",
        {
            "head",
            "manifest_sha256",
            "launch_sha256",
            "dispatch_sha256",
            "agentdojo_runtime_manifest_sha256",
            "agentdojo_loaded_asset_tree_sha256",
            "protocol",
            "started_utc",
        },
    )
    execution = _marker(
        root / EXECUTION_ACTIVE_FILENAME,
        "C4 execution-active marker",
        {
            "head",
            "manifest_sha256",
            "policy_set_file_sha256",
            "policy_seal_file_sha256",
            "started_utc",
        },
    )
    if matrix["protocol"] != (
        "all_90_policy_preflights_then_global_seal_then_execution"
    ):
        raise RuntimeError("C4 matrix-active protocol mismatch")
    if (
        matrix["agentdojo_runtime_manifest_sha256"]
        != AGENTDOJO_RUNTIME_MANIFEST_SHA256
    ):
        raise RuntimeError("C4 matrix-active AgentDojo runtime manifest mismatch")
    if (
        matrix["agentdojo_loaded_asset_tree_sha256"]
        != AGENTDOJO_LOADED_ASSET_TREE_SHA256
    ):
        raise RuntimeError("C4 matrix-active AgentDojo loaded asset tree mismatch")
    if execution["head"] != matrix["head"]:
        raise RuntimeError("C4 execution-active HEAD mismatch")
    if execution["manifest_sha256"] != matrix["manifest_sha256"]:
        raise RuntimeError("C4 execution-active manifest mismatch")
    for value, length, label in (
        (matrix["head"], 40, "C4 active HEAD"),
        (matrix["manifest_sha256"], 64, "C4 active manifest SHA-256"),
        (matrix["launch_sha256"], 64, "C4 active launcher SHA-256"),
        (matrix["dispatch_sha256"], 64, "C4 active dispatcher SHA-256"),
        (
            execution["policy_set_file_sha256"],
            64,
            "C4 active policy-set SHA-256",
        ),
        (
            execution["policy_seal_file_sha256"],
            64,
            "C4 active policy-seal SHA-256",
        ),
    ):
        if len(value) != length or any(c not in "0123456789abcdef" for c in value):
            raise RuntimeError(f"{label} is malformed")
    return {
        "expected_run_head": matrix["head"],
        "expected_c4_manifest_sha256": matrix["manifest_sha256"],
        "expected_launch_sha256": matrix["launch_sha256"],
        "expected_dispatch_sha256": matrix["dispatch_sha256"],
        "policy_set_file_sha256": execution["policy_set_file_sha256"],
        "policy_seal_file_sha256": execution["policy_seal_file_sha256"],
    }


def sealed_binding_for(root: Path, plan_path: Path) -> tuple[dict, str, str]:
    """Authenticate the global seal and return this plan's exact sealed entry."""

    set_path = root / c4_policy_set.POLICY_SET_FILENAME
    seal_path = root / c4_policy_set.PREFLIGHT_SEAL_FILENAME
    for path, label in ((set_path, "policy set"), (seal_path, "policy seal")):
        _regular_file(path, f"sealed C4 {label}")
    set_sha = sha256_file(set_path)
    seal_sha = sha256_file(seal_path)
    active = active_bindings_for(root)
    if active["policy_set_file_sha256"] != set_sha:
        raise RuntimeError("execution-active policy-set digest mismatch")
    if active["policy_seal_file_sha256"] != seal_sha:
        raise RuntimeError("execution-active policy-seal digest mismatch")
    binding = c4_policy_set.verify_execution_entry(
        root, plan_path, set_sha, seal_sha
    )
    return dict(binding), set_sha, seal_sha


def receipt_certifies(
    receipt: dict,
    *,
    plan: dict,
    plan_sha256: str,
    journal: "runner.Journal",
    journal_path: Path,
    planned: int,
    policy_binding: Mapping[str, object],
    policy_set_sha256: str,
    policy_seal_sha256: str,
    root: Path,
    receipt_path: Path | None = None,
) -> bool:
    """Require a green receipt to bind the exact complete journal and launch."""
    header = journal.header or {}
    required_gates = receipt.get("required_gate_names")
    gates = receipt.get("gates")
    receipt_binding = receipt.get("policy_seal_binding")
    sluice_binding = receipt.get("sluice_policy_bindings")
    gpu_probe = receipt.get("gpu_compute_process_probe_after_stop")
    if not (
        receipt.get("schema") == RUNNER_RECEIPT_SCHEMA
        and receipt.get("error") is None
        and receipt.get("all_gates_true") is True
        and receipt.get("all_required_gates_true") is True
        and receipt.get("phase") == "execute"
        and receipt.get("receipt_schema") == EXECUTION_RECEIPT_SCHEMA
        and receipt.get("c4_run_id") == C4_RUN_ID
        and required_gates == list(runner.EXECUTION_REQUIRED_GATES)
        and isinstance(gates, dict)
        and set(gates) == set(runner.GATES)
        and all(gates.get(name) is True for name in required_gates)
        and receipt_binding == policy_binding
        and isinstance(sluice_binding, dict)
        and isinstance(gpu_probe, dict)
        and gpu_probe.get("returncode") == 0
        and gpu_probe.get("stdout") == ""
        and isinstance(gpu_probe.get("stderr"), str)
        and gpu_probe.get("query_succeeded") is True
        and gpu_probe.get("no_compute_processes") is True
        and receipt.get("gpu_compute_procs_after_stop") == ""
        and receipt.get("plan_id") == plan.get("plan_id")
        and receipt.get("plan_sha256") == plan_sha256
        and receipt.get("model_slug") == plan.get("model_slug")
        and receipt.get("model_revision") == plan.get("model_revision")
        and receipt.get("generation_seed") == plan.get("generation_seed")
        and receipt.get("temperature") == plan.get("temperature")
        and receipt.get("provider") == plan.get("provider")
        and receipt.get("condition_schedule_sha256")
        == plan.get("condition_order_assignment", {}).get(
            "condition_schedule_sha256"
        )
        and receipt.get("shard_schedule_sha256")
        == plan.get("shard_schedule_sha256")
        and type(receipt.get("planned_arm_count")) is int
        and receipt.get("planned_arm_count") == planned
        and type(receipt.get("journal_completed_arms")) is int
        and receipt.get("journal_completed_arms") == planned
        and type(receipt.get("journal_records_total")) is int
        and receipt.get("journal_records_total") == journal.seq
        and journal.seq == 1 + 2 * planned
        and receipt.get("journal_terminal_self_sha256") == journal.prev
        and receipt.get("journal_file_sha256") == sha256_file(journal_path)
        and receipt.get("node_argument") == header.get("node")
        and receipt.get("physical_gpu_index") == header.get("physical_gpu_index")
        and receipt.get("expected_policy_set_file_sha256") == policy_set_sha256
        and receipt.get("expected_policy_seal_file_sha256") == policy_seal_sha256
        and header.get("c4_run_id") == C4_RUN_ID
        and header.get("policy_set_id") == policy_binding.get("policy_set_id")
        and header.get("policy_set_file_sha256") == policy_set_sha256
        and header.get("policy_seal_file_sha256") == policy_seal_sha256
        and header.get("preflight_receipt_sha256")
        == policy_binding.get("preflight_receipt_sha256")
        and sluice_binding.get("policy_preflight_id")
        == policy_binding.get("policy_preflight_id")
        and sluice_binding.get("policy_bundle_id")
        == policy_binding.get("policy_bundle_id")
        and sluice_binding.get("policy_bundle_sha256")
        == policy_binding.get("policy_bundle_sha256")
    ):
        return False
    if not all(receipt.get(field) == header.get(field) for field in PROVENANCE_FIELDS):
        return False
    active = active_bindings_for(root)
    for field in (
        "expected_run_head",
        "expected_c4_manifest_sha256",
        "expected_launch_sha256",
        "expected_dispatch_sha256",
    ):
        if receipt.get(field) != active[field] or header.get(field) != active[field]:
            return False
    if (
        active["policy_set_file_sha256"] != policy_set_sha256
        or active["policy_seal_file_sha256"] != policy_seal_sha256
    ):
        return False
    if set(sluice_binding) != set(POLICY_BINDING_FIELDS):
        return False
    if any(
        header.get(field) != sluice_binding.get(field)
        for field in POLICY_BINDING_FIELDS
    ):
        return False
    for arm in journal.arm_records:
        if not (
            arm.get("c4_run_id") == C4_RUN_ID
            and arm.get("policy_set_id") == policy_binding.get("policy_set_id")
            and arm.get("policy_set_file_sha256") == policy_set_sha256
            and arm.get("policy_seal_file_sha256") == policy_seal_sha256
            and arm.get("policy_preflight_id")
            == policy_binding.get("policy_preflight_id")
            and arm.get("policy_bundle_id")
            == policy_binding.get("policy_bundle_id")
            and arm.get("policy_bundle_sha256")
            == policy_binding.get("policy_bundle_sha256")
        ):
            return False
    log_relative = receipt.get("server_log_expected_archive_relative")
    if not isinstance(log_relative, str):
        return False
    relative_path = Path(log_relative)
    if (
        relative_path.is_absolute()
        or ".." in relative_path.parts
        or relative_path.parent != Path("logs")
        or not relative_path.name.startswith("vllm_execute_")
        or relative_path.suffix != ".log"
    ):
        return False
    log_path = root / relative_path
    try:
        log_mode = log_path.lstat().st_mode
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(log_mode) or not stat.S_ISREG(log_mode):
        return False
    if not (
        receipt.get("server_log_file_sha256") == sha256_file(log_path)
        and receipt.get("server_log_bytes") == log_path.stat().st_size
    ):
        return False
    if receipt_path is None:
        label = f"{plan.get('model_slug')}_plan_{plan.get('plan_id')}"
        matching_receipts: list[Path] = []
        for candidate in sorted((root / "receipts").glob(f"*_{label}_a*.json")):
            try:
                _regular_file(candidate, "C4 execution receipt")
                candidate_value = _load_json_object(
                    candidate, "C4 execution receipt"
                )
            except (OSError, RuntimeError, ValueError):
                return False
            if candidate_value == receipt:
                matching_receipts.append(candidate)
        if len(matching_receipts) != 1:
            return False
        receipt_path = matching_receipts[0]
    else:
        try:
            _regular_file(receipt_path, "C4 execution receipt")
            if _load_json_object(receipt_path, "C4 execution receipt") != receipt:
                return False
        except (OSError, RuntimeError, ValueError):
            return False
    try:
        wrapper_completion_c5.verify_wrapper_completion(
            root=root,
            phase="execute",
            plan_path=root / "plans" / f"plan_{plan.get('plan_id')}.json",
            receipt_path=receipt_path,
            expected_head=str(active["expected_run_head"]),
            expected_manifest=str(active["expected_c4_manifest_sha256"]),
        )
    except wrapper_completion_c5.WrapperCompletionError:
        return False
    return True


def status(root: Path, model: str, seed: int, shard: int) -> str:
    _regular_directory(root, "C4 run root")
    for name in (
        "plans",
        "journals",
        "receipts",
        "logs",
        "wrapper_cleanup_attestations",
        "wrapper_completions",
    ):
        _regular_directory(root / name, f"C4 {name} directory")
    plan_name = f"plan_c4full_{model}_s{seed}_s{shard}of6.json"
    plan_path = root / "plans" / plan_name
    _regular_file(plan_path, f"C4 plan {plan_name}")
    plan_value = _load_json_object(plan_path, f"C4 plan {plan_name}")
    plan_id = str(plan_value["plan_id"])
    plan_sha256 = sha256_file(plan_path)
    planned = 2 * len(plan_value["rows"])
    policy_binding, policy_set_sha256, policy_seal_sha256 = sealed_binding_for(
        root, plan_path
    )
    expected_arm_ids = {
        runner.arm_id_for(
            plan_id,
            str(plan_value["model_slug"]),
            str(plan_value["model_revision"]),
            row,
            condition,
            int(plan_value["generation_seed"]),
            float(plan_value["temperature"]),
            str(plan_value["provider"]),
            str(plan_value["condition_order_assignment"]["condition_schedule_sha256"]),
            C4_RUN_ID,
            str(policy_binding["policy_set_id"]),
        )
        for row in plan_value["rows"]
        for condition in row["condition_order"]
    }
    if len(expected_arm_ids) != planned:
        raise RuntimeError("frozen C4 plan produced duplicate expected arm IDs")
    label = f"{model}_{plan_path.stem}"
    journal_path = root / "journals" / f"journal_{label}.jsonl"
    receipts = sorted((root / "receipts").glob(f"*_{label}_a*.json"))
    attempts: list[int] = []
    for path in receipts:
        _regular_file(path, "C4 execution receipt")
        match = re.search(r"_a([0-9]+)\.json$", path.name)
        if not match:
            raise RuntimeError(f"malformed receipt attempt: {path.name}")
        attempts.append(int(match.group(1)))
    if len(attempts) != len(set(attempts)):
        raise RuntimeError("duplicate attempt number across shard receipts")

    terminal = 0
    if journal_path.exists() or journal_path.is_symlink():
        _regular_file(journal_path, "C4 execution journal")
        journal = runner.Journal(journal_path)
        replay = journal.replay()
        if not journal.chain_ok:
            raise RuntimeError(f"journal chain invalid: {replay}")
        if journal.header is not None:
            expected_header_fields = {
                "schema": "sluice_agentdojo_c4_execution_journal/1",
                "model_slug": plan_value.get("model_slug"),
                "model_revision": plan_value.get("model_revision"),
                "conditions": plan_value.get("conditions"),
                "generation_seed": plan_value.get("generation_seed"),
                "temperature": plan_value.get("temperature"),
                "provider": plan_value.get("provider"),
                "condition_schedule_sha256": plan_value.get(
                    "condition_order_assignment", {}
                ).get("condition_schedule_sha256"),
                "shard_schedule_sha256": plan_value.get(
                    "shard_schedule_sha256"
                ),
            }
            for field, expected_value in expected_header_fields.items():
                if journal.header.get(field) != expected_value:
                    raise RuntimeError(f"journal header mismatch: {field}")
            if journal.header.get("plan_id") != plan_id:
                raise RuntimeError("journal plan_id mismatch")
            if journal.header.get("plan_sha256") != plan_sha256:
                raise RuntimeError("journal plan digest mismatch")
            if journal.header.get("c4_run_id") != C4_RUN_ID:
                raise RuntimeError("journal C4 run identity mismatch")
            if journal.header.get("policy_set_id") != policy_binding.get(
                "policy_set_id"
            ):
                raise RuntimeError("journal policy-set identity mismatch")
            if journal.header.get("policy_set_file_sha256") != policy_set_sha256:
                raise RuntimeError("journal policy-set digest mismatch")
            if journal.header.get("policy_seal_file_sha256") != policy_seal_sha256:
                raise RuntimeError("journal policy-seal digest mismatch")
            if journal.header.get("preflight_receipt_sha256") != policy_binding.get(
                "preflight_receipt_sha256"
            ):
                raise RuntimeError("journal preflight-receipt digest mismatch")
        elif journal.arm_records:
            raise RuntimeError("journal has arms but no authenticated header")
        terminal = len(journal.arm_records)
        if terminal > planned:
            raise RuntimeError("journal has more terminal arms than planned")
        if not journal.done.issubset(expected_arm_ids):
            raise RuntimeError("journal contains terminal IDs outside the frozen plan")
        if not journal.started.issubset(expected_arm_ids):
            raise RuntimeError("journal contains started IDs outside the frozen plan")

    if terminal == planned:
        green = []
        for path in receipts:
            receipt = _load_json_object(path, "C4 execution receipt")
            if receipt_certifies(
                receipt,
                receipt_path=path,
                plan=plan_value,
                plan_sha256=plan_sha256,
                journal=journal,
                journal_path=journal_path,
                planned=planned,
                policy_binding=policy_binding,
                policy_set_sha256=policy_set_sha256,
                policy_seal_sha256=policy_seal_sha256,
                root=root,
            ):
                green.append(path)
        if green:
            return "complete"
        raise RuntimeError("terminal journal has no complete green receipt")

    if terminal:
        raise RuntimeError(
            "partial terminal journal cannot be resumed with publication-grade "
            "provenance; quarantine this matrix and refreeze a new run"
        )

    log_pattern = f"dispatch_{model}_s{seed}_s{shard}of6_a*.log"
    for path in (root / "logs").glob(log_pattern):
        _regular_file(path, "C4 dispatch log")
        match = re.search(r"_a([0-9]+)\.log$", path.name)
        if match:
            attempts.append(int(match.group(1)))
    next_attempt = max(attempts, default=-1) + 1
    if next_attempt > 99:
        raise RuntimeError("attempt namespace exhausted")
    return f"a{next_attempt}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--shard", required=True, type=int, choices=range(6))
    args = parser.parse_args()
    print(status(args.root, args.model, args.seed, args.shard))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
