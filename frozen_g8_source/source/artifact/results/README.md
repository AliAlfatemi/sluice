# Result files and evidentiary status

This directory intentionally distinguishes preserved results from valid
effectiveness evidence.

- `rq1_expanded_final_results.json` is a 25-case run: five cases from the
  preserved base driver plus 20 newly worded reconstruction cases. The exact
  original 25-case driver was lost, so this is a deterministic mechanism
  smoke test, not a frozen-corpus effectiveness estimate.
- `rq2_multiobject_interleaved.json` is the 2026-08-20 CPU rerun. Its greedy
  schedule branches on a prior public B outcome (`BBAA` 96 times and `BAAB`
  32 times); the round-robin schedule is `ABAB` for all 128 pairs.
- `rq4_matched_sweep_summary.json` and
  `rq4_matched_sweep_samples.jsonl.gz` contain the real 500,000-sample,
  20-configuration, five-repetition WAL/DELETE sweep. Only the identifying
  host token inside the run ID was replaced by `anonymous`; all measurements
  are unchanged. The unmodified source summary SHA-256 is
  `94989a0e1c9d29e7a3fb90c25489d2e2c5571cf9e9e0ad30f5bc722ce5895ba8`;
  the unmodified compressed raw-sample SHA-256 is
  `1012f1bf0c01c26ad3b184ab44582ab7fa3a4f50bb4639f9840b548ca91493a5`,
  and the sanitized compressed sample file SHA-256 is
  `8db937c479b6b5112badb28032b23f5229b44f8efd577df1349b3dcdce055830`.
- `rq5_cross_model_aggregate.json` records overall totals, immutable resolved
  model revisions, and hashes attributed to five source runs. Those source
  traces are absent from this bundle, so the non-adversarial/adversarial
  splits, per-technique grid, and audit-linkage totals cannot be independently
  recomputed from the package. It is a deterministic compatibility pilot with
  one generation per case; the constrained grammar makes out-of-alphabet
  output impossible in this arm.
- `real_llm_multiagent_workflow.json` is one preserved seven-case run after
  prompt tuning on the same cases. It is development-set workflow evidence,
  not a held-out generalization result.
- `agentdojo_non_oracle_*.json` and `camel_baseline_banking.json` are retained
  for auditability only. The AgentDojo pilot is invalidated by incomplete
  mediation and gate reuse; the CaMeL file is a compatibility smoke test on a
  pair that was not vulnerable in the undefended arm.

Large model weights, monitor databases, the five full RQ5 traces, and the
invalidated full AgentDojo matrix are not in the anonymous bundle. No claim in
the revised paper depends on the omitted invalidated AgentDojo rows.
