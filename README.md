# Sluice

Capability-Based Mediation with Conditional Information-Flow Bounds for LLM Agents.

The current implementation and submission artifact are in **[code/](code/)**.
Its README documents the exact evidence boundaries and reproduction commands.
The anonymous review link is:

**https://anonymous.4open.science/r/sluice-34EC/**

The review mirror is pinned to the separate `review-snapshot-20261117`
snapshot commit with automatic updates disabled. That snapshot has anonymous
commit metadata and no parent history. Changes to this repository's `main`
branch do not change the pinned review content. Use the anonymous link in the
submission; this personal GitHub repository identifies its owner.

## Current artifact

- `code/sluice_v2/`, `code/integrations/`, `code/tests/`: the corrected
  reference implementation and 120 passing CPU regression/workflow cases.
- `code/formal/`: the TLA+ model/configuration and logs; 184,016 distinct
  bounded states, depth 13, no invariant or temporal-property violation.
- `code/results/g8_20260829/`: compact G8 analysis, 31,380 terminal records,
  sealed policy bundles/reports and the original raw-evidence inventory.
- `code/frozen_g8_source/`: the distinct archived G8 monitor/runner and
  checksum-bound source closure. Do not substitute the root monitor for it.
- `code/results/native_agentdojo_20261116/`: the separate 144-episode
  native-Qwen four-condition pilot. It is descriptive and not pooled with G8.
- `code/results/supplement_20261116_validated/`: constructed live-effect
  and private-document Release field-validation checks.
- `code/paper/`: anonymous paper source and compiled 18-page PDF.
- `code/validation/`, `code/claim_evidence.csv`: completed checks and
  evidence/limitation mapping.

```sh
cd code
./run_all_tests.sh
python3 experiments/reconstruct_g8.py --output reconstructed.json
python3 experiments/audit_policy_bundles.py --output policy_audit.json
```

GPU runs need the pinned external software and model weights documented in
the artifact. The complete 2.2 GB raw G8 tree is not bundled. This repository
does not claim every study can be reproduced from one source revision.

## Historical evidence

The pre-revision files under **[results/](results/)** are preserved unchanged.
They are archival data, not automatically valid effectiveness evidence for
the current submission. In particular, the early RQ6 bridge was invalidated;
the paper's G8 study is a different execution. `LEGACY_CHECKSUMS.txt` is the
old inventory and is not a checksum list for the updated repository.
Earlier implementation/proof versions remain in git history.

The current artifact explicitly records weak comparator utility, fallback
sensitivity, incomplete historical provenance, restrictive Release premises,
and the absence of a faithful independent-defense/adaptive-attacker study.
See `code/EXPERIMENT_STATUS.md` before interpreting any result.

`code/MANIFEST.sha256` covers the review-copy artifact bytes. Its redaction
manifest distinguishes archival hashes from anonymized files. External
software/model licenses continue to apply; no model weights are distributed.
