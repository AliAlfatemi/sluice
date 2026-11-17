# Pinned AgentLeak evaluation seam

This directory carries the exact synthetic 1,000-scenario corpus from
Privatris/AgentLeak commit
`8f0631b9c9558ef337f86b71073b176d18badd1a`, together with the upstream MIT
notice.  The raw JSONL SHA-256 is
`c4688b860a0133e7434e788cf02baec0ae3f2b3b3bcd7f80088f4499dc52c352`.

The upstream JSONL uses the legacy channel strings `final_output` through
`artifact`, while the same commit's strict `Scenario` schema accepts only the
structured values `C1_final_output` through `C7_artifact`.  The Sluice adapter
authenticates the raw bytes first, then applies one explicit bijective mapping
in memory.  The same schema drift occurs in attack target channels and in the
legacy `F1`--`F4` family labels; those are mapped to the enum values declared by
the pinned source.  No other migration is accepted.  The adapter never rewrites
or regenerates the corpus.

`sluice_v2.evaluation.agentleak` is evaluation-only.  It is not in the policy
or enforcement path.  It requires explicit C1--C7 instrumentation, writes each
actual observed payload into `TraceEvent.content` once, uses AgentLeak's strict
`ExecutionTrace`, rejects incomplete detector output, and treats every detector
exception as a failed run.  Public summaries contain per-channel indicators
and counts, never matched text.  Benign utility comes from a separately pinned
Sluice oracle because every upstream `success_oracle` is null.

From the revision root, the offline integration smoke is:

```bash
tools/agentleak-smoke-venv/bin/python3 \
  source/artifact/benchmarks/agentleak/validate_adapter.py \
  --source-root external/agentleak
```

The smoke parses all 1,000 rows through the pinned upstream Pydantic model and
checks that a canary present only in C4 is detected as an internal-channel leak
and an output-only miss.  It performs no model inference and is not a defense
effectiveness result.

## Secret-independent codebooks and launch ordering

`codebooks_full_1000_v1/` is the concrete create-only finite-corpus bundle:
one canonical manifest for 16 public templates, 112 private route codebooks
(exact C1--C7 per template), a construction report, and an exact
`SHA256SUMS`. `public_schedule_full_1000_v1.json` is the authenticated public
projection used to compile the policy DTO before the protected corpus opens.
Both are built through the shared authenticated construction-only projector:
the codebook path reads only declared allowed-field values, and the schedule
path never accesses the vault. Neither path executes the general evaluation
loader's attack/evaluation normalization.

The schedule is also create-once at the filesystem boundary: its writer pins
every lexical parent directory without following links, creates only through
the pinned parent descriptor, requires a one-link regular `0600` file, and
re-reads/hashes the opened file before verifying the lexical parent and output
identity. Parent rename, symlink or directory replacement, output replacement,
a pre-existing basename, or a missing required primitive fails closed.

The CPU-only ordering check is:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=source/artifact \
python3 -m sluice_v2.evaluation.agentleak_isolated_launch \
  --repository-root . \
  --scenario-id agentleak_cor_00751
```

It authenticates the exact schedule, corpus, builders/loaders, complete
codebook inventory, ObserverSpec, and harness source; seals all seven routes;
compiles `PolicyAuthorInput`; and only then permits protected-state attachment.
It performs no model inference or evaluation. Exact construction commands,
hashes, fail-first evidence, and the evidence boundary are in
`analysis/AGENTLEAK_CODEBOOK_CONSTRUCTION_AND_LAUNCH.md`.
