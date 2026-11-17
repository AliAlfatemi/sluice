import hashlib
import json
from pathlib import Path
import stat
import sys

sys.path.insert(0, sys.argv[2])
import wrapper_completion_c5

plan_path = Path(sys.argv[1])
root = Path(sys.argv[2])
plan_id = sys.argv[3]
artifact = root / "policy_preflight" / "artifacts" / plan_id
journal = root / "policy_preflight" / "journals" / f"policy_preflight_{plan_id}.jsonl"
receipt = root / "policy_preflight" / "receipts" / f"policy_preflight_{plan_id}.json"
cleanup_attestation = (
    root / "policy_preflight" / "wrapper_cleanup_attestations"
    / f"wrapper_cleanup_{plan_id}.json"
)
completion = (
    root / "policy_preflight" / "wrapper_completions"
    / f"wrapper_completion_{plan_id}.json"
)
paths = (artifact, journal, receipt, cleanup_attestation, completion)
present = [path.exists() or path.is_symlink() for path in paths]
if not any(present):
    print("pending")
    raise SystemExit(0)
if not all(present):
    raise SystemExit(f"partial policy preflight for {plan_id}")
for path in (journal, receipt):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise SystemExit(f"non-regular policy preflight evidence: {path}")
if artifact.is_symlink() or not artifact.is_dir():
    raise SystemExit(f"invalid policy artifact directory: {artifact}")
plan = json.loads(plan_path.read_bytes())
value = json.loads(receipt.read_bytes())
checks = (
    value.get("phase") == "policy_preflight",
    value.get("receipt_schema") == "sluice_agentdojo_c4_policy_preflight_receipt/1",
    value.get("plan_id") == plan_id == plan.get("plan_id"),
    value.get("plan_sha256") == hashlib.sha256(plan_path.read_bytes()).hexdigest(),
    value.get("all_required_gates_true") is True,
    value.get("all_gates_true") is True,
    value.get("evaluated_arm_count") == 0,
    value.get("arm_journal_created") is False,
    value.get("trace_created") is False,
)
if not all(checks):
    raise SystemExit(f"red or malformed policy preflight receipt: {receipt}")
required = value.get("required_gate_names")
gates = value.get("gates")
if not isinstance(required, list) or not isinstance(gates, dict):
    raise SystemExit(f"missing phase-specific gates: {receipt}")
if not required or any(gates.get(name) is not True for name in required):
    raise SystemExit(f"failed phase-specific gate: {receipt}")
for name in (
    f"policy_request_{plan_id}.json",
    f"policy_bundle_{plan_id}.json",
    "authoring_report.json",
):
    path = artifact / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"missing policy artifact: {path}")
try:
    wrapper_completion_c5.verify_wrapper_completion(
        root=root,
        phase="policy_preflight",
        plan_path=plan_path,
        receipt_path=receipt,
        expected_head=sys.argv[4],
        expected_manifest=sys.argv[5],
    )
except wrapper_completion_c5.WrapperCompletionError as exc:
    raise SystemExit(f"red or missing wrapper completion: {exc}") from exc
print("complete")
