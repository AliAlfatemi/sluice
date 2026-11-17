#!/bin/bash
# Node-side fail-closed wrapper for definitive C4 AgentDojo policy preflight
# and arm execution (DerivedEffectAuthority, per-episode cross-binding ledger,
# corrected brokering gates, and a globally sealed policy set).
#
# Same contract as S1's node_arm_runner_f4.sh, with three differences:
#   * the payload is node_arm_runner_c4.py and the harness library is the C2
#     fork, both pinned by digest here AND re-asserted inside the runner;
#   * SLUICE_EXPECTED_HARNESS_LIB_SHA256 is exported so the runner's own
#     `sluice_forked_harness_digest_verified` gate can only pass when the
#     library that loaded is the library this wrapper authorised; and
#   * PYTHONNOUSERSITE=1, after this session found 208 packages belonging to
#     another project in ~/.local/lib/python3.11/site-packages, including an
#     editable `sluice` install pointing at work_20260817_multiagent.
#
# The unchanged S1 policy wire and policy process are still verified against
# S1_SHA256SUMS, so they keep their S1 identity.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV
for inherited_python_variable in "${!PYTHON@}"; do
  unset "$inherited_python_variable"
done
unset inherited_python_variable
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1

# Args: EXPECTED_HEAD C4_MANIFEST_SHA256 LAUNCH_SHA256 DISPATCH_SHA256
# WRAPPER_SHA256 NODE MODEL_KEY PLAN_BASENAME ATTEMPT PAYLOAD_SHA256
# SUMS_SHA256 GPU_INDEX PORT HARNESS_LIB_SHA256 PHASE POLICY_SET_SHA256
# POLICY_SEAL_SHA256
if [ "$#" -ne 17 ]; then
  printf 'refusing: expected 17 arguments, got %s\n' "$#"
  exit 64
fi
expected_head="$1"
expected_c4_manifest="$2"
expected_launch="$3"
expected_dispatch="$4"
expected_wrapper="$5"
expected_node="$6"
model_key="$7"
plan_base="$8"
attempt="$9"
expected_payload="${10}"
expected_sums="${11}"
gpu_index="${12}"
port="${13}"
expected_harness_lib="${14}"
phase="${15}"
policy_set_sha256="${16}"
policy_seal_sha256="${17}"

case "$expected_node" in node001|node002|node003) ;; *) exit 65 ;; esac
case "$expected_head" in *[!0-9a-f]*) printf "refusing: expected HEAD\n"; exit 66 ;; esac
if [ "${#expected_head}" -ne 40 ]; then printf "refusing: expected HEAD length\n"; exit 66; fi
for digest in "$expected_c4_manifest" "$expected_launch" "$expected_dispatch" \
              "$expected_wrapper" "$expected_payload" "$expected_sums" \
              "$expected_harness_lib"; do
  case "$digest" in *[!0-9a-f]*) printf "refusing: non-hex digest\n"; exit 66 ;; esac
  if [ "${#digest}" -ne 64 ]; then printf "refusing: digest length\n"; exit 66; fi
done
if [ "$(hostname)" != "$expected_node" ]; then printf "refusing: hostname mismatch\n"; exit 65; fi
case "$attempt" in a[0-9]|a[0-9][0-9]) ;; *) printf "refusing: attempt tag\n"; exit 66 ;; esac
case "$gpu_index" in 0|1) ;; *) printf "refusing: gpu index\n"; exit 66 ;; esac
case "$port" in 18[3-9][0-9][0-9]) ;; *) printf "refusing: port range\n"; exit 66 ;; esac
case "$plan_base" in *[!A-Za-z0-9._-]*) printf "refusing: plan name\n"; exit 66 ;; esac
case "$phase" in
  policy_preflight)
    phase_tag=p
    if [ "$attempt" != a0 ]; then
      printf "refusing: policy preflight is a single create-only attempt\n"; exit 66
    fi
    if [ "$policy_set_sha256" != - ] || [ "$policy_seal_sha256" != - ]; then
      printf "refusing: policy preflight received a set or seal digest\n"; exit 66
    fi
    ;;
  execute)
    phase_tag=e
    for digest in "$policy_set_sha256" "$policy_seal_sha256"; do
      case "$digest" in *[!0-9a-f]*) printf "refusing: policy seal digest\n"; exit 66 ;; esac
      if [ "${#digest}" -ne 64 ]; then printf "refusing: policy seal digest length\n"; exit 66; fi
    done
    ;;
  *) printf "refusing: unknown phase\n"; exit 66 ;;
esac

evidence="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(cd "$evidence/../.." && pwd -P)"
c4_manifest="$evidence/C4_SHA256SUMS"
s1="$repo/runs/sluice_nonoracle_19a3810_20260822_s1"
hf_home=/srv/review/USENIX27_SLUICE/code_data_model/model/hf_cache
hub="$hf_home/hub"
env_prefix=/srv/review/USENIX27_SLUICE/envs/sluice_agentdojo_v1
py="$env_prefix/bin/python"

freeze="$repo/runs/agentdojo_live_endpoint_19a3810_20260822_a1/sluice_agentdojo_v1_pip_freeze_after_abi_repair.txt"
expected_freeze=dd4ee6ac27529c6cbca61e88ed74b4a5a09400afac0921709d2e927b43ba6b47
wheels="$repo/runs/agentdojo_live_endpoint_19a3810_20260822_a1/sluice_agentdojo_v1_platform_wheels.txt"
expected_wheels=34e51a429095e7943c948120dde8affe9fa60517d39cb268e15e3dc1ac5945a8

payload="$evidence/node_arm_runner_c4.py"
sums="$evidence/plans/PLAN_SHA256SUMS"
plan="$evidence/plans/$plan_base"
durable_helper="$evidence/durable_paths_c4.py"
completion_helper="$evidence/wrapper_completion_c5.py"
agentdojo_runtime_verifier="$evidence/verify_agentdojo_runtime_c6.py"
expected_vllm_version=0.6.4.post1

# ------------------------------------------------------------- model table
case "$model_key" in
  qwen25-3b)
    repo_dir=models--Qwen--Qwen2.5-3B-Instruct
    revision=aa8e72537993ba99e69dfaafa59ed015b17504d1
    manifest="$repo/runs/cluster_access/qwen2.5-3b_snapshot_manifest.json"
    expected_manifest=32b9a1fddfa4435f52740e816bf5694e6b212f0101586a7530f022846e0825e2
    gpu_mem_util=0.55
    max_model_len=32768
    min_free_mib=30000
    ;;
  granite31-8b)
    repo_dir=models--ibm-granite--granite-3.1-8b-instruct
    revision=4009206d5fc95d2e65a7b7633e159d6e97e25d35
    manifest="$repo/runs/cluster_access/granite-3.1-8b_snapshot_manifest.json"
    expected_manifest=5689829a708bb078e5e8cf47f6f4dc6915bab792b3e756cdcc1ccba1f8a7afe3
    gpu_mem_util=0.90
    max_model_len=16384
    min_free_mib=30000
    ;;
  mistral7b-v03)
    repo_dir=models--mistralai--Mistral-7B-Instruct-v0.3
    revision=c170c708c41dac9275d15a8fff4eca08d52bab71
    manifest="$repo/runs/cluster_access/mistral-7b-v0.3_snapshot_manifest.json"
    expected_manifest=a55c5c5b86d791a0d75f64a15eb8f2b4a3d71328463a0cfa528afcfa4df184f4
    gpu_mem_util=0.90
    max_model_len=32768
    min_free_mib=30000
    ;;
  *) printf "refusing: unknown model key\n"; exit 66 ;;
esac

snapshot="$hub/$repo_dir/snapshots/$revision"
label="${model_key}_${plan_base%.json}"
plan_id="${plan_base#plan_}"
plan_id="${plan_id%.json}"
case "$plan_id" in c4full_*) ;; *) printf "refusing: non-C4 plan id\n"; exit 66 ;; esac
if [ "$phase" = policy_preflight ]; then
  receipt="$evidence/policy_preflight/receipts/policy_preflight_${plan_id}.json"
  completion_dir="$evidence/policy_preflight/wrapper_completions"
  completion="$completion_dir/wrapper_completion_${plan_id}.json"
  cleanup_attestation_dir="$evidence/policy_preflight/wrapper_cleanup_attestations"
  cleanup_attestation="$cleanup_attestation_dir/wrapper_cleanup_${plan_id}.json"
else
  receipt="$evidence/receipts/${expected_node}_gpu${gpu_index}_${label}_${attempt}.json"
  completion_dir="$evidence/wrapper_completions"
  completion="$completion_dir/wrapper_completion_$(basename "${receipt%.json}").json"
  cleanup_attestation_dir="$evidence/wrapper_cleanup_attestations"
  cleanup_attestation="$cleanup_attestation_dir/wrapper_cleanup_$(basename "${receipt%.json}").json"
fi
journal="$evidence/journals/journal_${label}.jsonl"
# Keep every Unix-domain socket generated by vLLM 0.6.4 inside Linux's
# 107-byte pathname payload limit.  vLLM appends "/<uuid>" and one of the
# four frozen suffixes below to VLLM_RPC_BASE_PATH; the previous descriptive
# scratch name was already one byte over the limit before any extra nesting.
local_base="/local/s5-${expected_node#node}-${gpu_index}-${phase_tag}-${port}-${attempt}-${expected_head:0:7}"
tmp_dir="$local_base/tmp"
rpc_base="$local_base/rpc"
prom_dir="$local_base/prom"
server_pgid_file="$local_base/server.pgid"
rpc_uuid=00000000-0000-0000-0000-000000000000
rpc_base_bytes="$(printf '%s' "$rpc_base" | wc -c)"
if [ "$rpc_base_bytes" -gt 56 ]; then
  printf 'refusing: VLLM_RPC_BASE_PATH is %s bytes (maximum 56)\n' \
    "$rpc_base_bytes"
  exit 69
fi
for rpc_suffix in _input_socket _output_socket _health_socket _data_socket; do
  rpc_candidate="$rpc_base/$rpc_uuid$rpc_suffix"
  rpc_candidate_bytes="$(printf '%s' "$rpc_candidate" | wc -c)"
  if [ "$rpc_candidate_bytes" -gt 107 ]; then
    printf 'refusing: vLLM IPC pathname is %s bytes (maximum 107): %s\n' \
      "$rpc_candidate_bytes" "$rpc_suffix"
    exit 69
  fi
done
unset rpc_candidate rpc_candidate_bytes rpc_suffix rpc_uuid

tracedir="$evidence/traces/$label"
server_log_archive="$evidence/logs/vllm_${phase}_${expected_node}_gpu${gpu_index}_${label}_${attempt}.log"
# Policy preflight may create only policy_preflight evidence.  In particular,
# do not create an arm receipt, journal, or trace path before the global set is
# sealed.  During execution the runner itself creates the trace directory only
# after it has verified the exact global set and seal.
for path in "$evidence/logs" "$evidence/policy_preflight" \
            "$evidence/policy_preflight/receipts" \
            "$evidence/policy_preflight/artifacts" \
            "$evidence/policy_preflight/journals" \
            "$evidence/policy_preflight/wrapper_cleanup_attestations" \
            "$evidence/policy_preflight/wrapper_completions" \
            "$evidence/receipts" "$evidence/journals" "$evidence/traces" \
            "$evidence/wrapper_cleanup_attestations" \
            "$evidence/wrapper_completions"; do
  if [ -L "$path" ]; then printf "refusing: evidence directory symlink\n"; exit 67; fi
done
if [ -e "$server_log_archive" ] || [ -L "$server_log_archive" ]; then
  printf "refusing: server-log archive exists (create-only)\n"; exit 67
fi
if [ -e "$completion" ] || [ -L "$completion" ]; then
  printf "refusing: wrapper completion exists (create-only)\n"; exit 67
fi
if [ -e "$cleanup_attestation" ] || [ -L "$cleanup_attestation" ]; then
  printf "refusing: wrapper cleanup attestation exists (create-only)\n"; exit 67
fi

if [ "$(cat "$repo/.git/HEAD")" != "ref: refs/heads/usenix-acceptance-revision" ]; then printf "refusing: HEAD ref\n"; exit 68; fi
if [ "$(cat "$repo/.git/refs/heads/usenix-acceptance-revision")" != "$expected_head" ]; then printf "refusing: HEAD commit\n"; exit 68; fi
if [ ! -f "$c4_manifest" ] || [ -L "$c4_manifest" ]; then printf "refusing: C4 manifest\n"; exit 68; fi
if [ "$(sha256sum "$c4_manifest" | cut -d ' ' -f 1)" != "$expected_c4_manifest" ]; then printf "refusing: C4 manifest digest\n"; exit 68; fi
if [ "$(sha256sum "$0" | cut -d ' ' -f 1)" != "$expected_wrapper" ]; then printf "refusing: wrapper self digest\n"; exit 68; fi
if ! (cd "$repo" && sha256sum -c "$c4_manifest"); then printf "refusing: C4 static manifest verification\n"; exit 68; fi
if [ "$(sha256sum "$manifest" | cut -d ' ' -f 1)" != "$expected_manifest" ]; then printf "refusing: model manifest digest\n"; exit 68; fi
if [ ! -f "$payload" ] || [ -L "$payload" ]; then printf "refusing: payload missing\n"; exit 68; fi
if [ "$(sha256sum "$payload" | cut -d ' ' -f 1)" != "$expected_payload" ]; then printf "refusing: payload digest\n"; exit 68; fi
if [ ! -f "$completion_helper" ] || [ -L "$completion_helper" ]; then printf "refusing: wrapper-completion helper missing\n"; exit 68; fi

# The forked harness library, pinned twice: here, and again inside the runner
# via SLUICE_EXPECTED_HARNESS_LIB_SHA256 after the module has actually loaded.
if [ "$(sha256sum "$evidence/sluice_nonoracle_lib_c2.py" | cut -d ' ' -f 1)" != "$expected_harness_lib" ]; then
  printf "refusing: forked harness library digest\n"; exit 68
fi
# effect_charging, the S1 policy manifest/files, the committed monitor, this
# wrapper, the runner, harness, and PLAN_SHA256SUMS are all authorized by the
# fixed C4 static manifest verified above.
# The UNCHANGED S1 policy path, still verified against S1's own manifest.
if [ ! -f "$s1/S1_SHA256SUMS" ] || [ -L "$s1/S1_SHA256SUMS" ]; then printf "refusing: S1 sums missing\n"; exit 68; fi
for f in sluice_policy_wire.py sluice_policy_process.py; do
  want="$(awk -v n="$f" '$2==n {print $1}' "$s1/S1_SHA256SUMS")"
  if [ -z "$want" ]; then printf "refusing: %s absent from S1 sums\n" "$f"; exit 68; fi
  if [ "$(sha256sum "$s1/$f" | cut -d ' ' -f 1)" != "$want" ]; then
    printf "refusing: %s digest\n" "$f"; exit 68
  fi
done

if [ ! -f "$sums" ] || [ -L "$sums" ]; then printf "refusing: plan sums missing\n"; exit 68; fi
if [ "$(sha256sum "$sums" | cut -d ' ' -f 1)" != "$expected_sums" ]; then printf "refusing: plan sums digest\n"; exit 68; fi
if [ ! -f "$plan" ] || [ -L "$plan" ]; then printf "refusing: plan missing\n"; exit 68; fi
plan_expected="$(awk -v n="$plan_base" '$2==n {print $1}' "$sums")"
if [ -z "$plan_expected" ]; then printf "refusing: plan absent from sums\n"; exit 68; fi
if [ "$(sha256sum "$plan" | cut -d ' ' -f 1)" != "$plan_expected" ]; then printf "refusing: plan digest\n"; exit 68; fi
if [ ! -f "$freeze" ] || [ "$(sha256sum "$freeze" | cut -d ' ' -f 1)" != "$expected_freeze" ]; then printf "refusing: environment freeze digest\n"; exit 68; fi
if [ ! -f "$wheels" ] || [ "$(sha256sum "$wheels" | cut -d ' ' -f 1)" != "$expected_wheels" ]; then printf "refusing: platform wheel-tag digest\n"; exit 68; fi
if [ "$(grep -c '^cryptography-50.0.0 cp39-abi3-manylinux_2_28_x86_64$' "$wheels")" != 1 ]; then printf "refusing: cryptography wheel variant is not node-compatible\n"; exit 68; fi
if [ ! -x "$py" ]; then printf "refusing: dedicated interpreter missing\n"; exit 68; fi
if [ ! -x /usr/bin/python3.11 ]; then printf "refusing: policy interpreter missing\n"; exit 68; fi
if [ "$(/usr/bin/python3.11 -E -s -B -c 'import platform;print(".".join(platform.python_version().split(".")[:2]))')" != "3.11" ]; then printf "refusing: policy interpreter is not 3.11\n"; exit 68; fi
if [ ! -d "$snapshot" ] || [ -L "$snapshot" ]; then printf "refusing: snapshot missing\n"; exit 68; fi
if [ -e "$receipt" ] || [ -L "$receipt" ]; then printf "refusing: receipt exists (create-only)\n"; exit 67; fi
if [ -L "$journal" ]; then printf "refusing: journal is a symlink\n"; exit 67; fi
if [ -e "$local_base" ] || [ -L "$local_base" ]; then printf "refusing: scratch exists\n"; exit 67; fi
if [ ! -f "$agentdojo_runtime_verifier" ] || [ -L "$agentdojo_runtime_verifier" ]; then
  printf "refusing: AgentDojo runtime verifier missing\n"; exit 68
fi
verify_agentdojo_runtime() {
  local observed expected
  if ! observed="$(
    "$py" -I -B "$agentdojo_runtime_verifier" \
      --run-root "$evidence" --repo "$repo" </dev/null
  )"; then
    return 1
  fi
  expected='{"directory_count_below_root":41,"file_count":115,"loaded_asset_file_count":112,"loaded_asset_tree_sha256":"9afe69717373f8b261bf65136a257737e3211c1a1a3af687ba58824068039c0a","manifest_sha256":"301db416517d7d0b32392ac7913c9a024ded713d77975c626d1f00b5ee94b996","official_commit":"a75aba7631d3ca5fb7ab938965c97ead2f9ff84b","official_git_tree":"3c74b60f2bad4ff321d864e0c0483f256cc8f8d2","python_file_count":99,"python_tree_sha256":"1d277192874c252ca21ece753b4ab10217958a1f41511b1f7175e919d9c01114","schema":"sluice_agentdojo_c6_runtime_verification/1","status":"PASS","version":"0.1.35"}'
  [ "$observed" = "$expected" ]
}
if ! verify_agentdojo_runtime; then
  printf "refusing: AgentDojo runtime closure proof mismatch\n"; exit 68
fi
if [ "$(findmnt -n -o FSTYPE -T /local)" != "xfs" ]; then printf "refusing: /local is not xfs\n"; exit 69; fi

procs="$(nvidia-smi --id="$gpu_index" --query-compute-apps=pid --format=csv,noheader | wc -l)"
free_mib="$(nvidia-smi --id="$gpu_index" --query-gpu=memory.free --format=csv,noheader,nounits)"
gpu_name="$(nvidia-smi --id="$gpu_index" --query-gpu=name --format=csv,noheader)"
printf 'node=%s\ngpu_index=%s\ngpu_name=%s\ngpu_compute_procs=%s\ngpu_free_mib=%s\n' \
  "$expected_node" "$gpu_index" "$gpu_name" "$procs" "$free_mib"
if [ "$procs" != 0 ]; then printf 'refusing: GPU already busy\n'; exit 71; fi
if [ "$free_mib" -lt "$min_free_mib" ]; then printf 'refusing: GPU low free memory\n'; exit 71; fi

# The static manifest (including this helper) and the GPU gates now passed.
# Persist every evidence parent before vLLM or the runner can start an
# irreversible request.  The launcher has already enforced the global
# Phase-P/Phase-E ordering; this node-local check makes the NFS entries durable.
if [ "$phase" = policy_preflight ]; then
  "$py" -E -s -B \
    "$durable_helper" --root "$evidence" ensure \
    "$evidence/policy_preflight" \
    "$evidence/policy_preflight/receipts" \
    "$evidence/policy_preflight/artifacts" \
    "$evidence/policy_preflight/journals" \
    "$evidence/policy_preflight/wrapper_cleanup_attestations" \
    "$evidence/policy_preflight/wrapper_completions" \
    "$evidence/logs"
else
  "$py" -E -s -B \
    "$durable_helper" --root "$evidence" ensure \
    "$evidence/receipts" "$evidence/journals" "$evidence/traces" \
    "$evidence/logs" "$evidence/wrapper_cleanup_attestations" \
    "$evidence/wrapper_completions"
fi

mkdir -m 700 "$local_base"
process_group_present() {
  local target_pgid="$1"
  kill -0 -- "-$target_pgid" 2>/dev/null
}

wait_process_group_gone() {
  local target_pgid="$1"
  local iterations="$2"
  local index
  for ((index=0; index<iterations; index++)); do
    if ! process_group_present "$target_pgid"; then
      return 0
    fi
    sleep 0.2
  done
  ! process_group_present "$target_pgid"
}

server_group_shell_intervention=no
cleanup_server_group() {
  local handed_off_pgid handoff_bytes handoff_mode_owner wrapper_pgid
  if [ ! -e "$server_pgid_file" ] && [ ! -L "$server_pgid_file" ]; then
    # The payload either never spawned vLLM or proved the saved process group
    # gone and durably removed its handoff file.
    return 0
  fi
  if [ -L "$server_pgid_file" ] || [ ! -f "$server_pgid_file" ]; then
    printf 'refusing cleanup: server PGID handoff is not a regular file\n'
    return 1
  fi
  handoff_mode_owner="$(stat -c '%a:%u:%h' "$server_pgid_file" 2>/dev/null)" || return 1
  if [ "$handoff_mode_owner" != "600:$(id -u):1" ]; then
    printf 'refusing cleanup: server PGID handoff metadata mismatch\n'
    return 1
  fi
  IFS= read -r handed_off_pgid < "$server_pgid_file" || return 1
  case "$handed_off_pgid" in
    ''|*[!0-9]*) printf 'refusing cleanup: invalid server PGID\n'; return 1 ;;
  esac
  if [ "${#handed_off_pgid}" -gt 10 ]; then
    printf 'refusing cleanup: overlong server PGID\n'
    return 1
  fi
  wrapper_pgid="$(ps -o pgid= -p "$$" | tr -d ' ')" || return 1
  case "$wrapper_pgid" in
    ''|*[!0-9]*) printf 'refusing cleanup: cannot attest wrapper PGID\n'; return 1 ;;
  esac
  if [ "$handed_off_pgid" -le 1 ] || [ "$handed_off_pgid" -eq "$$" ] \
    || [ "$handed_off_pgid" -eq "$wrapper_pgid" ]; then
    printf 'refusing cleanup: unsafe server PGID\n'
    return 1
  fi
  handoff_bytes="$(wc -c < "$server_pgid_file")"
  if [ "$handoff_bytes" -ne "$((${#handed_off_pgid} + 1))" ]; then
    printf 'refusing cleanup: non-canonical server PGID handoff\n'
    return 1
  fi

  if process_group_present "$handed_off_pgid"; then
    server_group_shell_intervention=yes
    kill -TERM -- "-$handed_off_pgid" 2>/dev/null || true
    if ! wait_process_group_gone "$handed_off_pgid" 600; then
      kill -KILL -- "-$handed_off_pgid" 2>/dev/null || true
      if ! wait_process_group_gone "$handed_off_pgid" 300; then
        printf 'refusing cleanup: vLLM process group %s survived SIGKILL\n' \
          "$handed_off_pgid"
        return 1
      fi
    fi
  fi
  rm -f -- "$server_pgid_file"
  return 0
}

cleanup() {
  local rc=$?
  local final_rc="$rc"
  local archive_ok=no
  local group_cleanup_ok=no
  local scratch_removed=no
  local gpu_final_query_rc=1
  local gpu_final_query_output=''
  set +e
  if cleanup_server_group; then
    group_cleanup_ok=yes
    if [ "$rc" -eq 0 ] && [ "$server_group_shell_intervention" = yes ]; then
      # A green payload must already have proved its saved group disappeared.
      # If the shell found a live group, the payload's zero status is invalid
      # even though the exact group was successfully contained here.
      final_rc=76
    fi
  else
    final_rc=75
  fi
  if [ -f "$local_base/server.log" ] && [ ! -L "$local_base/server.log" ] \
    && "$py" -E -s -B \
         "$evidence/archive_server_log_c4.py" \
         "$local_base/server.log" "$server_log_archive"; then
    archive_ok=yes
  fi
  if [ "$group_cleanup_ok" = yes ]; then
    rm -rf "$local_base" 2>/dev/null || true
    if [ ! -e "$local_base" ] && [ ! -L "$local_base" ]; then
      scratch_removed=yes
    else
      final_rc=78
    fi
  fi
  if [ "$rc" -eq 0 ] && [ "$archive_ok" != yes ]; then
    if [ "$group_cleanup_ok" = yes ] \
      && [ "$server_group_shell_intervention" != yes ]; then final_rc=74; fi
  fi

  # This query is mandatory even for a red payload: cleanup cannot silently
  # succeed when nvidia-smi failed or any process still owns the assigned GPU.
  gpu_final_query_output="$(nvidia-smi --id="$gpu_index" \
    --query-compute-apps=pid --format=csv,noheader 2>&1)"
  gpu_final_query_rc=$?
  if [ "$gpu_final_query_rc" -ne 0 ] \
    || [ -n "$(printf '%s' "$gpu_final_query_output" | tr -d '[:space:]')" ]; then
    final_rc=77
  fi

  printf 'server_process_group_cleanup_ok=%s\n' "$group_cleanup_ok"
  printf 'server_process_group_shell_intervention=%s\n' \
    "$server_group_shell_intervention"
  printf 'server_log_archive_ok=%s\n' "$archive_ok"
  printf 'scratch_removed=%s\n' "$scratch_removed"
  printf 'gpu_final_query_rc=%s\n' "$gpu_final_query_rc"
  printf 'gpu_compute_procs_after=%s\n' \
    "$([ -n "$(printf '%s' "$gpu_final_query_output" | tr -d '[:space:]')" ] && echo nonzero || echo 0)"
  printf 'payload_rc=%s\nwrapper_rc=%s\n' "$rc" "$final_rc"
  trap - EXIT

  # The node may create only a cleanup handoff.  The helper replaces this
  # shell, performs the second/final GPU query, durably writes the handoff,
  # emits no output, and exits.  The dispatcher creates the acceptance
  # completion only after SSH reports this exact remote wrapper rc=0.
  if [ "$rc" -eq 0 ] && [ "$final_rc" -eq 0 ] \
    && [ "$group_cleanup_ok" = yes ] \
    && [ "$server_group_shell_intervention" = no ] \
    && [ "$archive_ok" = yes ] && [ "$scratch_removed" = yes ]; then
    exec env -i PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
      "$py" -E -s -B "$completion_helper" cleanup \
      --root "$evidence" --phase "$phase" --plan "$plan" \
      --receipt "$receipt" --server-log "$server_log_archive" \
      --scratch "$local_base" --attempt "$attempt" --node "$expected_node" \
      --gpu "$gpu_index" --expected-head "$expected_head" \
      --expected-manifest "$expected_c4_manifest" \
      --expected-wrapper "$expected_wrapper" \
      --expected-payload "$expected_payload" \
      --payload-rc 0 --wrapper-rc 0 --cleanup-ok true \
      --intervention false --log-archive-ok true --scratch-removed true \
      --finalized-utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    exit 79
  fi
  exit "$final_rc"
}
trap cleanup EXIT
mkdir -m 700 "$tmp_dir" "$rpc_base" "$prom_dir"
mkdir -m 700 "$local_base/cache" "$local_base/triton" \
             "$local_base/vllm" "$local_base/outlines" "$local_base/pycache"

# The AF_UNIX suffix proof above is version-specific.  Authenticate both the
# imported module and installed distribution against the frozen 0.6.4.post1
# identity before the server command is reachable, using disposable isolation
# paths so this probe cannot contaminate the server's Prometheus directory.
# vLLM can write import diagnostics to stdout.  Redirect only that import's
# stdout so command substitution receives exactly the validated version line.
mkdir -m 700 "$local_base/version_tmp" "$local_base/version_prom"
if ! vllm_version="$(
  env -i \
    PATH=/usr/bin:/bin HOME="$local_base" \
    CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES="$gpu_index" \
    HF_HOME="$hf_home" HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    HF_DATASETS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 \
    TMPDIR="$local_base/version_tmp" \
    PROMETHEUS_MULTIPROC_DIR="$local_base/version_prom" \
    XDG_CACHE_HOME="$local_base/cache" TRITON_CACHE_DIR="$local_base/triton" \
    VLLM_CACHE_ROOT="$local_base/vllm" OUTLINES_CACHE_DIR="$local_base/outlines" \
    PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
    PYTHONPYCACHEPREFIX="$local_base/pycache" \
    "$py" -E -s -B -c \
    'import contextlib
import importlib.metadata
import sys
sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(sys.stderr):
    import vllm
import wrapper_completion_c5 as w
print(w.validate_vllm_versions(
    vllm.__version__,
    importlib.metadata.version("vllm"),
))' \
    "$evidence"
)" || [ "$vllm_version" != "$expected_vllm_version" ]; then
  printf 'refusing: dedicated vLLM version mismatch\n'
  exit 69
fi
rm -rf "$local_base/version_tmp" "$local_base/version_prom"
if ! version_probe_procs="$(nvidia-smi --id="$gpu_index" \
  --query-compute-apps=pid --format=csv,noheader)" \
  || [ -n "$(printf '%s' "$version_probe_procs" | tr -d '[:space:]')" ]; then
  printf 'refusing: vLLM version gate left GPU state nonempty or unqueryable\n'
  exit 71
fi
printf 'vllm_runtime_version=%s\n' "$vllm_version"

printf 'phase=%s\nmodel=%s\nplan=%s\nattempt=%s\ntimestamp_utc=%s\n' \
  "$phase" "$model_key" "$plan_base" "$attempt" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'snapshot=%s\njournal=%s\nport=%s\ngpu_memory_utilization=%s\nmax_model_len=%s\n' \
  "$snapshot" "$journal" "$port" "$gpu_mem_util" "$max_model_len"
printf 'harness_lib_sha256=%s\n' "$expected_harness_lib"

# Close the gap between the early static/GPU gates and the irreversible
# payload boundary: reauthenticate every AgentDojo byte after vLLM probing and
# immediately before the runner can import the benchmark or author a policy.
if ! verify_agentdojo_runtime; then
  printf 'refusing: AgentDojo runtime drifted before payload\n'
  exit 68
fi

set +e
timeout --signal=TERM --kill-after=180s 86000s \
  env -i \
  PATH=/usr/bin:/bin \
  HOME="$local_base" \
  CUDA_DEVICE_ORDER=PCI_BUS_ID \
  CUDA_VISIBLE_DEVICES="$gpu_index" \
  SLUICE_GPU_INDEX="$gpu_index" \
  SLUICE_EXPECTED_RUN_HEAD="$expected_head" \
  SLUICE_EXPECTED_C4_MANIFEST_SHA256="$expected_c4_manifest" \
  SLUICE_EXPECTED_LAUNCH_SHA256="$expected_launch" \
  SLUICE_EXPECTED_DISPATCH_SHA256="$expected_dispatch" \
  SLUICE_EXPECTED_WRAPPER_SHA256="$expected_wrapper" \
  SLUICE_EXPECTED_PAYLOAD_SHA256="$expected_payload" \
  SLUICE_EXPECTED_PLAN_SUMS_SHA256="$expected_sums" \
  SLUICE_EXPECTED_HARNESS_LIB_SHA256="$expected_harness_lib" \
  HF_HOME="$hf_home" \
  HF_HUB_OFFLINE=1 \
  TRANSFORMERS_OFFLINE=1 \
  HF_DATASETS_OFFLINE=1 \
  HF_HUB_DISABLE_TELEMETRY=1 \
  TOKENIZERS_PARALLELISM=false \
  TMPDIR="$tmp_dir" \
  VLLM_RPC_BASE_PATH="$rpc_base" \
  PROMETHEUS_MULTIPROC_DIR="$prom_dir" \
  SLUICE_SERVER_PGID_FILE="$server_pgid_file" \
  XDG_CACHE_HOME="$local_base/cache" \
  TRITON_CACHE_DIR="$local_base/triton" \
  VLLM_CACHE_ROOT="$local_base/vllm" \
  OUTLINES_CACHE_DIR="$local_base/outlines" \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONNOUSERSITE=1 \
  PYTHONPYCACHEPREFIX="$local_base/pycache" \
  OMP_NUM_THREADS=8 \
  VLLM_LOGGING_LEVEL=INFO \
  VLLM_NO_USAGE_STATS=1 \
  DO_NOT_TRACK=1 \
  NO_COLOR=1 \
  TERM=dumb \
  "$py" -E -s -B "$payload" "$snapshot" "$manifest" "$receipt" "$expected_node" \
        "$port" "$gpu_mem_util" "$max_model_len" \
        "$tracedir" "$local_base/server.log" "$plan" "$journal" \
        "$phase" "$policy_set_sha256" "$policy_seal_sha256"
payload_rc=$?
set -e
printf 'payload_rc=%s\n' "$payload_rc"
exit "$payload_rc"
