#!/bin/bash
# Hash-gated two-hop dispatcher for the G1 sluice_nonoracle matrix.
#
# Design note (see G1_ROOT_CAUSE.md): this dispatcher deliberately follows the
# proven F1 contract -- pin, by digest, every artefact that is routed, then
# route -- instead of the C10..C15 "sealed historical checkout root" contract.
# The C-series dispatcher additionally required that N previously *failed*
# attempts still be present on disk with exact 0444/0555 modes and Git-omitted
# empty directories.  That set grew as 1+2+...+n (C12=2, C13=6, C14=10, C15=15)
# and every member had to be hand-pinned correctly before arm #1 could run.
# G1 carries no failure-provenance capsules, so that entire class is absent by
# construction rather than by a narrower patch.
#
# Every integrity property that protects the *science* is retained in full:
# committed HEAD, complete manifest closure, per-artefact digests, and both
# SSH trust roots are all verified here, on cluster-login, before any node command.
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

if [ "$#" -ne 13 ]; then
  printf 'usage: EXPECTED_HEAD LAUNCH_SHA256 DISPATCH_SHA256 MANIFEST_SHA256 NODE MODEL_KEY PLAN_BASENAME ATTEMPT GPU_INDEX PORT PHASE POLICY_SET_SHA256 POLICY_SEAL_SHA256\n'
  exit 64
fi
expected_head="$1"; expected_launch="$2"; expected_dispatch="$3"; expected_manifest="$4"
node="$5"; model_key="$6"; plan_base="$7"; attempt="$8"; gpu_index="$9"; port="${10}"
phase="${11}"; policy_set_sha256="${12}"; policy_seal_sha256="${13}"

evidence="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo="$(cd "$evidence/../.." && pwd -P)"
g1_rel=runs/sluice_nonoracle_g8_20260828

cis_known="$repo/runs/isolation/runtime_staging_independent_reaudit_1fd8c2d_20260821/ciscluster_known_hosts"
node_known="$repo/runs/cluster_access/node_known_hosts_20260820"
expected_cis_known=e8608f585e7ef86debfbd8395db3ed16d4457e083f0a80abf54c95b9f0e3ca1b
expected_node_known=b370d131cf0b31661a2188d9b8863d060ffe56467df53d311a4e1c37df141eed

target="$evidence/node_arm_runner_c4.sh"
manifest="$evidence/C4_SHA256SUMS"

# ------------------------------------------------------------ argument gates
case "$node" in node001|node002|node003) ;; *) printf 'refusing: node\n'; exit 65 ;; esac
case "$model_key" in qwen25-3b|granite31-8b|mistral7b-v03) ;; *) printf 'refusing: model\n'; exit 65 ;; esac
case "$gpu_index" in 0|1) ;; *) printf 'refusing: gpu\n'; exit 65 ;; esac
case "$attempt" in a[0-9]|a[0-9][0-9]) ;; *) printf 'refusing: attempt\n'; exit 65 ;; esac
case "$port" in 18[3-9][0-9][0-9]|185[0-9][0-9]) ;; *) printf 'refusing: port\n'; exit 65 ;; esac
case "$plan_base" in *[!A-Za-z0-9._-]*) printf 'refusing: plan name\n'; exit 65 ;; esac
case "$expected_head" in *[!0-9a-f]*) exit 65 ;; esac
if [ "${#expected_head}" -ne 40 ]; then exit 65; fi
for digest in "$expected_launch" "$expected_dispatch" "$expected_manifest"; do
  case "$digest" in *[!0-9a-f]*) exit 65 ;; esac
  if [ "${#digest}" -ne 64 ]; then exit 65; fi
done
case "$phase" in
  policy_preflight)
    if [ "$attempt" != a0 ]; then printf 'refusing: preflight attempt\n'; exit 65; fi
    if [ "$policy_set_sha256" != - ] || [ "$policy_seal_sha256" != - ]; then
      printf 'refusing: preflight seal digests\n'; exit 65
    fi
    ;;
  execute)
    for digest in "$policy_set_sha256" "$policy_seal_sha256"; do
      case "$digest" in *[!0-9a-f]*) exit 65 ;; esac
      if [ "${#digest}" -ne 64 ]; then exit 65; fi
    done
    ;;
  *) printf 'refusing: phase\n'; exit 65 ;;
esac

# -------------------------------------------------------------- host + HEAD
if [ "$(hostname -f)" != login.review.invalid ]; then printf 'refusing: host\n'; exit 67; fi
if [ "$(cat "$repo/.git/HEAD")" != "ref: refs/heads/usenix-acceptance-revision" ]; then
  printf 'refusing: branch\n'; exit 68
fi
if [ "$(cat "$repo/.git/refs/heads/usenix-acceptance-revision")" != "$expected_head" ]; then
  printf 'refusing: HEAD\n'; exit 68
fi

# ------------------------------------------------------------- trust anchors
for f in "$cis_known" "$node_known" "$manifest" "$target" "$evidence/plans/$plan_base"; do
  if [ ! -f "$f" ] || [ -L "$f" ]; then printf 'refusing: missing %s\n' "$f"; exit 68; fi
done
if [ "$(sha256sum "$cis_known" | cut -d ' ' -f 1)" != "$expected_cis_known" ]; then exit 68; fi
if [ "$(sha256sum "$node_known" | cut -d ' ' -f 1)" != "$expected_node_known" ]; then exit 68; fi

# --------------------------------------------------- manifest + full closure
if [ "$(sha256sum "$manifest" | cut -d ' ' -f 1)" != "$expected_manifest" ]; then
  printf 'refusing: manifest digest\n'; exit 68
fi
if ! (cd "$repo" && sha256sum -c "$manifest" >/dev/null); then
  printf 'refusing: manifest closure\n'; exit 68
fi

# ------------------------------------------------- routed artefact digests
wrapper_sha="$(awk -v n="$g1_rel/node_arm_runner_c4.sh" '$2==n {print $1}' "$manifest")"
payload_sha="$(awk -v n="$g1_rel/node_arm_runner_c4.py" '$2==n {print $1}' "$manifest")"
sums_sha="$(awk -v n="$g1_rel/plans/PLAN_SHA256SUMS" '$2==n {print $1}' "$manifest")"
harness_lib_sha="$(awk -v n="$g1_rel/sluice_nonoracle_lib_c2.py" '$2==n {print $1}' "$manifest")"
for digest in "$wrapper_sha" "$payload_sha" "$sums_sha" "$harness_lib_sha"; do
  if [ "${#digest}" -ne 64 ]; then printf 'refusing: manifest row\n'; exit 68; fi
done
if [ "$(sha256sum "$target" | cut -d ' ' -f 1)" != "$wrapper_sha" ]; then exit 68; fi
if [ "$(stat -c %a "$target")" != 700 ]; then printf 'refusing: runner mode\n'; exit 68; fi
if ! awk -v n="$plan_base" '$2==n {found=1} END {exit !found}' "$evidence/plans/PLAN_SHA256SUMS"; then
  printf 'refusing: plan not in PLAN_SHA256SUMS\n'; exit 68
fi

# ----------------------------------------------------------------- two hops
printf 'routing phase=%s node=%s model=%s plan=%s attempt=%s gpu=%s port=%s\n' \
  "$phase" "$node" "$model_key" "$plan_base" "$attempt" "$gpu_index" "$port"

plan_id="${plan_base#plan_}"
plan_id="${plan_id%.json}"
if [ "$phase" = policy_preflight ]; then
  receipt="$evidence/policy_preflight/receipts/policy_preflight_${plan_id}.json"
else
  receipt="$evidence/receipts/${node}_gpu${gpu_index}_${model_key}_${plan_base%.json}_${attempt}.json"
fi

inner="exec ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o UserKnownHostsFile=$node_known -o GlobalKnownHostsFile=/dev/null $node bash $target $expected_head $expected_manifest $expected_launch $expected_dispatch $wrapper_sha $node $model_key $plan_base $attempt $payload_sha $sums_sha $gpu_index $port $harness_lib_sha $phase $policy_set_sha256 $policy_seal_sha256"

set +e
timeout --signal=TERM --kill-after=300s 86400s \
  ssh -F /dev/null \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  -o StrictHostKeyChecking=yes \
  -o UpdateHostKeys=no \
  -o UserKnownHostsFile="$cis_known" \
  -o GlobalKnownHostsFile=/dev/null \
  -o ServerAliveInterval=60 \
  -o ServerAliveCountMax=10 \
  ciscluster "$inner"
observed_wrapper_rc=$?
set -e
if [ "$observed_wrapper_rc" -ne 0 ]; then
  exit "$observed_wrapper_rc"
fi

# Terminal action: the remote wrapper can create only a cleanup handoff.  This
# helper verifies that handoff and creates the acceptance completion only after
# the two-hop command above returned exactly zero.
exec env -i PATH=/usr/bin:/bin PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -E -s -B "$evidence/wrapper_completion_c5.py" complete \
  --root "$evidence" --phase "$phase" \
  --plan "$evidence/plans/$plan_base" \
  --receipt "$receipt" \
  --expected-head "$expected_head" \
  --expected-manifest "$expected_manifest" \
  --observed-wrapper-rc "$observed_wrapper_rc"
