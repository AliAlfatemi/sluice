#!/usr/bin/env python3
"""Run one generated preflight receipt through the production verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


CLASSIFIER_SHA256 = (
    "3d49759ef55355c9890b02f43885f7ffeb8ee1c74d85799bcfbe84a2d63fcdb7"
)
FALLBACK_SHA256 = (
    "ae60ab6b17f276cb450894f8342d2b1ed309757d09b428f36209b34629cfb81a"
)
MATRIX_FIELDS = {
    "head",
    "manifest_sha256",
    "launch_sha256",
    "dispatch_sha256",
    "agentdojo_runtime_manifest_sha256",
    "agentdojo_loaded_asset_tree_sha256",
    "protocol",
    "started_utc",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def matrix_bindings(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"MATRIX_ACTIVE is not a regular file: {path}")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if line.count("=") != 1:
            raise RuntimeError("MATRIX_ACTIVE contains a malformed line")
        key, value = line.split("=", 1)
        if key in result:
            raise RuntimeError(f"MATRIX_ACTIVE duplicate field: {key}")
        result[key] = value
    if set(result) != MATRIX_FIELDS:
        raise RuntimeError(
            f"MATRIX_ACTIVE fields mismatch: {sorted(result)}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    arguments = parser.parse_args()

    root = arguments.root.resolve(strict=True)
    plan_path = arguments.plan.resolve(strict=True)
    if plan_path.parent != root / "plans":
        raise RuntimeError("plan is not a direct child of root/plans")
    plan_wire = json.loads(plan_path.read_text(encoding="utf-8"))
    plan_id = plan_wire.get("plan_id")
    if not isinstance(plan_id, str):
        raise RuntimeError("plan has no string plan_id")

    sys.path.insert(0, str(root))
    import c4_policy_set  # pylint: disable=import-outside-toplevel

    active = matrix_bindings(root / "MATRIX_ACTIVE")
    provenance = {
        "schema": c4_policy_set.PROVENANCE_SCHEMA,
        "expected_run_head": active["head"],
        "expected_c4_manifest_sha256": active["manifest_sha256"],
        "expected_launch_sha256": active["launch_sha256"],
        "expected_dispatch_sha256": active["dispatch_sha256"],
        "expected_wrapper_sha256": sha256_file(root / "node_arm_runner_c4.sh"),
        "expected_payload_sha256": sha256_file(root / "node_arm_runner_c4.py"),
        "expected_plan_sums_sha256": sha256_file(
            root / "plans" / "PLAN_SHA256SUMS"
        ),
        "expected_harness_lib_sha256": sha256_file(
            root / "sluice_nonoracle_lib_c2.py"
        ),
        "context_overflow_classifier_sha256": CLASSIFIER_SHA256,
        "context_overflow_fallback_sha256": FALLBACK_SHA256,
    }
    canonical_provenance = c4_policy_set._validate_provenance(provenance)
    c4_policy_set._verify_provenance_files(root, canonical_provenance)
    plans, _ = c4_policy_set._load_plans(root)
    if plan_id not in plans:
        raise RuntimeError(f"plan is not in the frozen matrix: {plan_id}")
    entry = c4_policy_set._verify_receipt(
        root, plans[plan_id], canonical_provenance
    )
    print(
        json.dumps(
            {
                "plan_id": plan_id,
                "receipt_sha256": entry["receipt_sha256"],
                "shard_count": entry["shard_count"],
                "shard_index": entry["shard_index"],
                "status": "verified_by_production_receipt_contract",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
