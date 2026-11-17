#!/bin/bash
# G8 sluice_nonoracle matrix launcher.
#
# Two irreversible phases, exactly as the C4 design specifies:
#   Phase P : 90 policy-preflight bundles (one per model x seed x shard),
#             then ONE global policy-set seal.
#   Phase E : the scheduled evaluated arms, under that frozen seal.
#
# Resumable: both phases skip work whose evidence is already complete and
# green, so this script may be re-invoked after an interruption.  It is NOT
# a retry of a failed identity -- a red preflight is still terminal, because
# policy authoring is single-attempt under a fixed identity.
#
# Scope control: set G1_MODELS to a space-separated subset to complete one
# model stratum at a time.  The global seal is only created once every
# scheduled preflight for the selected scope is green.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV
for v in "${!PYTHON@}"; do unset "$v"; done
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(cd "$here/../.." && pwd -P)"
py=/usr/bin/python3

nodes=(node001 node001 node002 node002 node003 node003)
gpus=(0 1 0 1 0 1)
ports=(18511 18512 18521 18522 18531 18532)
read -r -a models <<< "${G1_MODELS:-mistral7b-v03 granite31-8b qwen25-3b}"
# Operational order only: exercise the predecessor's failing model and seed
# first.  The frozen plans, model/seed set, within-plan condition order, and
# global policy barrier are unchanged. A mandatory six-receipt verifier
# authenticates complete model/seed batches and their brokerage integrity.
seeds=(196613 104729 130363 155921 262147)
execution_max_attempt="${G1_MAX_ATTEMPT:-3}"

stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log_line() { printf '%s %s\n' "$(stamp)" "$*"; }
mark_failed() {
  printf 'reason=%s\nfinished_utc=%s\n' "$1" "$(stamp)" > "$here/G1_FAILED.$1.txt"
  log_line "FAILED $1"
}

durable_helper="$here/durable_paths_c4.py"
durable_ensure() {
  "$py" -E -s -B "$durable_helper" --root "$here" ensure "$@"
}
durable_marker() {
  local path="$1"
  shift
  "$py" -E -s -B "$durable_helper" --root "$here" \
    create-lines "$path" "$@"
}

# ------------------------------------------------------------- static gates
expected_head="$(cat "$repo/.git/refs/heads/usenix-acceptance-revision")"
expected_manifest="$(sha256sum "$here/C4_SHA256SUMS" | cut -d ' ' -f 1)"
expected_launch="$(sha256sum "$here/launch_c4_matrix.sh" | cut -d ' ' -f 1)"
expected_dispatch="$(sha256sum "$here/dispatch_gpu_c4.sh" | cut -d ' ' -f 1)"

log_line "head=$expected_head"
log_line "manifest=$expected_manifest"
if ! (cd "$repo" && sha256sum -c "$here/C4_SHA256SUMS" >/dev/null); then
  mark_failed manifest_closure; exit 1
fi
log_line "manifest closure verified"

if ! "$py" -E -s -B "$here/verify_agentdojo_runtime_c6.py" \
     --run-root "$here" --repo "$repo" >/dev/null; then
  mark_failed agentdojo_runtime_verification; exit 1
fi
log_line "AgentDojo runtime closure verified"

durable_ensure "$here/logs" "$here/policy_preflight/artifacts" \
  "$here/policy_preflight/journals" "$here/policy_preflight/receipts" \
  "$here/policy_preflight/wrapper_completions" \
  "$here/policy_preflight/wrapper_cleanup_attestations" \
  "$here/journals" "$here/traces" "$here/receipts" \
  "$here/wrapper_completions" "$here/wrapper_cleanup_attestations"

if [ ! -e "$here/MATRIX_ACTIVE" ] && [ ! -L "$here/MATRIX_ACTIVE" ]; then
  durable_marker "$here/MATRIX_ACTIVE" \
    "head=$expected_head" \
    "manifest_sha256=$expected_manifest" \
    "launch_sha256=$expected_launch" \
    "dispatch_sha256=$expected_dispatch" \
    "agentdojo_runtime_manifest_sha256=301db416517d7d0b32392ac7913c9a024ded713d77975c626d1f00b5ee94b996" \
    "agentdojo_loaded_asset_tree_sha256=9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a" \
    "protocol=all_90_policy_preflights_then_global_seal_then_execution" \
    "started_utc=$(stamp)"
  log_line "MATRIX_ACTIVE created"
else
  if [ -L "$here/MATRIX_ACTIVE" ] || [ ! -f "$here/MATRIX_ACTIVE" ] \
    || [ "$(wc -l < "$here/MATRIX_ACTIVE")" -ne 8 ]; then
    mark_failed matrix_active_invalid; exit 1
  fi
  for binding in \
    "head=$expected_head" \
    "manifest_sha256=$expected_manifest" \
    "launch_sha256=$expected_launch" \
    "dispatch_sha256=$expected_dispatch" \
    "agentdojo_runtime_manifest_sha256=301db416517d7d0b32392ac7913c9a024ded713d77975c626d1f00b5ee94b996" \
    "agentdojo_loaded_asset_tree_sha256=9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a" \
    "protocol=all_90_policy_preflights_then_global_seal_then_execution"; do
    if [ "$(grep -Fxc "$binding" "$here/MATRIX_ACTIVE")" -ne 1 ]; then
      mark_failed matrix_active_binding_mismatch; exit 1
    fi
  done
  if ! grep -Eq '^started_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
       "$here/MATRIX_ACTIVE"; then
    mark_failed matrix_active_timestamp; exit 1
  fi
  log_line "MATRIX_ACTIVE already present (resuming)"
fi

preflight_state() {
  local plan="$1" plan_id="${1#plan_}"
  plan_id="${plan_id%.json}"
  "$py" -E -s -B "$here/g1_preflight_status.py" \
    "$here/plans/$plan" "$here" "$plan_id" "$expected_head" "$expected_manifest"
}

# ================================================================== PHASE P
log_line "phase=policy_preflight models=${models[*]}"
for model in "${models[@]}"; do
  for seed in "${seeds[@]}"; do
    label="${model}_s${seed}"
    pids=()
    for shard in 0 1 2 3 4 5; do
      plan="plan_c4full_${model}_s${seed}_s${shard}of6.json"
      if ! state="$(preflight_state "$plan")"; then
        mark_failed "preflight_${label}_s${shard}_red"; exit 1
      fi
      if [ "$state" = complete ]; then
        log_line "skip complete preflight $label s$shard"; continue
      fi
      log="$here/logs/policy_preflight_dispatch_${label}_s${shard}of6_a0.log"
      if [ -e "$log" ]; then
        mark_failed "preflight_${label}_s${shard}_ambiguous_attempt"; exit 1
      fi
      log_line "dispatch preflight $label s$shard -> ${nodes[$shard]} gpu${gpus[$shard]}"
      bash "$here/dispatch_gpu_c4.sh" \
        "$expected_head" "$expected_launch" "$expected_dispatch" "$expected_manifest" \
        "${nodes[$shard]}" "$model" "$plan" a0 \
        "${gpus[$shard]}" "${ports[$shard]}" policy_preflight - - > "$log" 2>&1 &
      pids+=("$!")
    done
    failed=0
    for pid in "${pids[@]:-}"; do [ -n "$pid" ] || continue; wait "$pid" || failed=1; done
    for shard in 0 1 2 3 4 5; do
      plan="plan_c4full_${model}_s${seed}_s${shard}of6.json"
      if ! state="$(preflight_state "$plan")" || [ "$state" != complete ]; then
        mark_failed "preflight_${label}_s${shard}_not_green"; exit 1
      fi
      if ! "$py" -E -s -B "$here/verify_preflight_receipt_contract.py" \
           --root "$here" --plan "$here/plans/$plan" >/dev/null; then
        mark_failed "preflight_${label}_s${shard}_receipt_contract"; exit 1
      fi
    done
    log_line "preflight complete $label (child_failures=$failed)"
  done
done

expected_bundles=$(( ${#models[@]} * 5 * 6 ))
receipt_count="$(find "$here/policy_preflight/receipts" -mindepth 1 -maxdepth 1 \
                 -type f -name 'policy_preflight_c4full_*.json' | wc -l)"
log_line "preflight receipts=$receipt_count expected_for_scope=$expected_bundles"

# ================================================================ GLOBAL SEAL
policy_set_path="$here/C4_POLICY_SET.json"
policy_seal_path="$here/C4_POLICY_PREFLIGHT_SEAL.json"
provenance_path="$here/C4_POLICY_PREFLIGHT_PROVENANCE.json"

if [ "$receipt_count" -ne 90 ]; then
  log_line "STOP: global seal requires all 90 preflight bundles; have $receipt_count"
  log_line "scope complete for models: ${models[*]}"
  exit 0
fi

if [ ! -f "$policy_set_path" ]; then
  wrapper_sha="$(sha256sum "$here/node_arm_runner_c4.sh" | cut -d ' ' -f 1)"
  payload_sha="$(sha256sum "$here/node_arm_runner_c4.py" | cut -d ' ' -f 1)"
  plan_sums_sha="$(sha256sum "$here/plans/PLAN_SHA256SUMS" | cut -d ' ' -f 1)"
  harness_lib_sha="$(sha256sum "$here/sluice_nonoracle_lib_c2.py" | cut -d ' ' -f 1)"
  "$py" -E -s -B - "$provenance_path" "$expected_head" "$expected_manifest" \
    "$expected_launch" "$expected_dispatch" "$wrapper_sha" "$payload_sha" \
    "$plan_sums_sha" "$harness_lib_sha" <<'PY'
import json, os, sys
from pathlib import Path
path = Path(sys.argv[1])
value = {
    "schema": "sluice_agentdojo_c4_policy_preflight_provenance/1",
    "expected_run_head": sys.argv[2],
    "expected_c4_manifest_sha256": sys.argv[3],
    "expected_launch_sha256": sys.argv[4],
    "expected_dispatch_sha256": sys.argv[5],
    "expected_wrapper_sha256": sys.argv[6],
    "expected_payload_sha256": sys.argv[7],
    "expected_plan_sums_sha256": sys.argv[8],
    "expected_harness_lib_sha256": sys.argv[9],
    "context_overflow_classifier_sha256":
        "3d49759ef55355c9890b02f43885f7ffeb8ee1c74d85799bcfbe84a2d63fcdb7",
    "context_overflow_fallback_sha256":
        "ae60ab6b17f276cb450894f8342d2b1ed309757d09b428f36209b34629cfb81a",
}
payload = json.dumps(value, ensure_ascii=True, allow_nan=False,
                     sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
if path.exists():
    if path.read_bytes() != payload:
        raise SystemExit("existing provenance does not match this launch")
else:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload); os.fsync(fd)
    finally:
        os.close(fd)
PY
  log_line "policy preflight provenance written"
  if ! "$py" -E -s -B "$here/c4_policy_set.py" --root "$here" \
       --provenance "$provenance_path"; then
    mark_failed global_policy_set_seal; exit 1
  fi
  log_line "global policy set + seal created"
fi

for path in "$policy_set_path" "$policy_seal_path"; do
  if [ ! -f "$path" ]; then mark_failed global_seal_missing; exit 1; fi
done
policy_set_sha256="$(sha256sum "$policy_set_path" | cut -d ' ' -f 1)"
policy_seal_sha256="$(sha256sum "$policy_seal_path" | cut -d ' ' -f 1)"
log_line "policy_set=$policy_set_sha256"
log_line "policy_seal=$policy_seal_sha256"

# Independently reopen the global seal before any principal evidence exists.
first_plan="$here/plans/plan_c4full_granite31-8b_s196613_s0of6.json"
if ! "$py" -E -s -B - "$here" "$first_plan" \
     "$policy_set_sha256" "$policy_seal_sha256" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import c4_policy_set
c4_policy_set.verify_execution_entry(
    Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
)
PY
then
  mark_failed global_policy_set_reverification; exit 1
fi

execution_active="$here/C4_EXECUTION_ACTIVE"
if [ ! -e "$execution_active" ] && [ ! -L "$execution_active" ]; then
  for arm_dir in journals traces receipts wrapper_cleanup_attestations \
                 wrapper_completions; do
    path="$here/$arm_dir"
    if [ -d "$path" ] \
      && [ -n "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      mark_failed execution_evidence_predates_execution_active; exit 1
    fi
  done
  durable_marker "$execution_active" \
    "head=$expected_head" \
    "manifest_sha256=$expected_manifest" \
    "policy_set_file_sha256=$policy_set_sha256" \
    "policy_seal_file_sha256=$policy_seal_sha256" \
    "started_utc=$(stamp)"
  log_line "C4_EXECUTION_ACTIVE created"
else
  if [ -L "$execution_active" ] || [ ! -f "$execution_active" ] \
    || [ "$(wc -l < "$execution_active")" -ne 5 ]; then
    mark_failed execution_active_invalid; exit 1
  fi
  for binding in \
    "head=$expected_head" \
    "manifest_sha256=$expected_manifest" \
    "policy_set_file_sha256=$policy_set_sha256" \
    "policy_seal_file_sha256=$policy_seal_sha256"; do
    if [ "$(grep -Fxc "$binding" "$execution_active")" -ne 1 ]; then
      mark_failed execution_active_binding_mismatch; exit 1
    fi
  done
  if ! grep -Eq '^started_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
       "$execution_active"; then
    mark_failed execution_active_timestamp; exit 1
  fi
  log_line "C4_EXECUTION_ACTIVE already present (resuming)"
fi

# ================================================================== PHASE E
log_line "phase=execute"
for model in "${models[@]}"; do
  for seed in "${seeds[@]}"; do
    label="${model}_s${seed}"
    for round in 0 1 2 3; do
      pids=(); launched=0
      for shard in 0 1 2 3 4 5; do
        plan="plan_c4full_${model}_s${seed}_s${shard}of6.json"
        if ! state="$("$py" -E -s -B "$here/c4_shard_status.py" \
             --root "$here" --model "$model" --seed "$seed" --shard "$shard")"; then
          mark_failed "execute_${label}_s${shard}_status"; exit 1
        fi
        [ "$state" = complete ] && continue
        attempt="$state"
        if [ "${attempt#a}" -gt "$execution_max_attempt" ]; then
          mark_failed "execute_${label}_s${shard}_retry_limit"; exit 1
        fi
        log="$here/logs/dispatch_${label}_s${shard}of6_${attempt}.log"
        [ -e "$log" ] && { mark_failed "execute_${label}_s${shard}_ambiguous"; exit 1; }
        log_line "dispatch execute $label s$shard $attempt -> ${nodes[$shard]} gpu${gpus[$shard]}"
        bash "$here/dispatch_gpu_c4.sh" \
          "$expected_head" "$expected_launch" "$expected_dispatch" "$expected_manifest" \
          "${nodes[$shard]}" "$model" "$plan" "$attempt" \
          "${gpus[$shard]}" "${ports[$shard]}" \
          execute "$policy_set_sha256" "$policy_seal_sha256" > "$log" 2>&1 &
        pids+=("$!"); launched=$((launched+1))
      done
      [ "$launched" -eq 0 ] && { log_line "execute complete $label"; break; }
      for pid in "${pids[@]:-}"; do [ -n "$pid" ] || continue; wait "$pid" || true; done
    done
    if ! batch_summary="$("$py" -E -s -B "$here/verify_c4_batch.py" \
         --root "$here" --model "$model" --seed "$seed")"; then
      mark_failed "execute_${label}_batch_verification"; exit 1
    fi
    log_line "batch verified $batch_summary"
  done
done

log_line "G1 matrix pass finished"
printf 'finished_utc=%s\n' "$(stamp)" > "$here/MATRIX_PASS_DONE"
