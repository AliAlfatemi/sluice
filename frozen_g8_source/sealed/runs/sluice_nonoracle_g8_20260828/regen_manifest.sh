#!/bin/bash
# Regenerate C4_SHA256SUMS for the G8 evidence tree.
# Rows = (a) the 134 external science dependencies carried over from the C15
# manifest verbatim, and (b) every static file in this evidence directory.
# Runtime output directories are deliberately excluded: they are created by the
# run itself and are covered by the journal hash chain, not by this manifest.
set -euo pipefail
R=/srv/review/USENIX27_SLUICE/sluice_usenix_revision
REL=runs/sluice_nonoracle_g8_20260828
D=$R/$REL
C15=$R/runs/sluice_definitive_a8950e2_20260824_c15/C4_SHA256SUMS
cd "$R"
grep -v " runs/sluice_definitive_a8950e2_20260824_c15/" "$C15" > /tmp/g1_ext.sums
find "$REL" -type f ! -name C4_SHA256SUMS \
  ! -path "*/logs/*" ! -path "*/receipts/*" ! -path "*/journals/*" \
  ! -path "*/traces/*" ! -path "*/policy_preflight/*" ! -path "*/probe/*" \
  ! -path "*/wrapper_completions/*" ! -path "*/wrapper_cleanup_attestations/*" \
  ! -name "MATRIX_*" ! -name "G1_FAILED*" ! -name "C4_POLICY_*" \
  | LC_ALL=C sort > /tmp/g1_own.list
xargs -a /tmp/g1_own.list sha256sum > /tmp/g1_own.sums
cat /tmp/g1_ext.sums /tmp/g1_own.sums | LC_ALL=C sort -k2 > "$D/C4_SHA256SUMS"
printf "rows=%s\n" "$(wc -l < "$D/C4_SHA256SUMS")"
sha256sum -c "$D/C4_SHA256SUMS" > /tmp/g1_check.out 2>&1 || true
printf "ok=%s bad=%s\n" "$(grep -c ": OK" /tmp/g1_check.out)" "$(grep -vc ": OK" /tmp/g1_check.out)"
grep -v ": OK" /tmp/g1_check.out | head -5 || true
