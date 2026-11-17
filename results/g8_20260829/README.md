# Authenticated compact G8 result set

This directory is the compact local publication set for the completed G8 run.

- `c4_primary.json`: frozen analysis output, SHA-256
  `64dc91bd5288c20bdd01969d6b07a7e59f2a8111d57dddc0ef662dcc19e57cdc`
- `c4_primary.tex`: analyzer-generated paper macros, SHA-256
  `bfa2f13653fadf339622fdd2db5a5decc9be8efe8aaaf5071b57f2f19e53e132`
- `C4_RESULT_SHA256SUMS`: create-only 48,341-entry evidence inventory,
  SHA-256 `74302265b3dd9b2168652630b03e754fd21872a5d2ad899c73558ec98cd6c5c3`
- `G8_EXECUTION.json` and `G8_GATE_CORRECTION.md`: fresh execution identity
  and the only outcome-classification correction from G7
- `C4_POLICY_SET.json`, `C4_POLICY_PREFLIGHT_SEAL.json`, and
  `C4_POLICY_PREFLIGHT_PROVENANCE.json`: authenticated policy publication
- `MATRIX_PASS_DONE`: final 31,380-arm launcher pass marker

The raw evidence tree is 2.2 GB and remains at:

`/srv/review/USENIX27_SLUICE/sluice_usenix_revision/runs/sluice_nonoracle_g8_20260828`

This compact directory is sufficient to reproduce the reported publication
values and authenticate the frozen outputs themselves. Full verification of
all 48,341 inventory entries requires the manifest-bound raw evidence tree.

The 90 sealed policy bundles and 90 authoring reports are included under
`policy_preflight/artifacts/`. All 180 original file hashes matched the
published policy-set inventory before review anonymization. Their full
journals/server logs and per-arm cryptographic evidence remain in the raw
archive. The path-free terminal CSV permits exact endpoint re-aggregation.
