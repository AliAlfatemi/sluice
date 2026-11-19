# Sluice

Capability-based mediation with conditional information-flow bounds for LLM
agents. The reference implementation combines a capability monitor,
transactional ledger, action validation, workflow integrations, and a TLA+ model.

## Quick start

The implementation and reproduction guide are in [code/](code/).

```bash
cd code
./run_all_tests.sh
```

The CPU suite covers security regressions and workflow contracts. GPU experiments
use the external software and model configuration documented in the
[implementation guide](code/README.md).

## Project structure

| Path | Purpose |
|---|---|
| [code/sluice_v2/](code/sluice_v2/) | Reference monitor and transactional ledger |
| [code/integrations/](code/integrations/) | Agent-framework and workflow integrations |
| [code/tests/](code/tests/) | Experiment-harness contract tests |
| [code/formal/](code/formal/) | TLA+ specification, configuration, and model-checking records |
| [code/frozen_g8_source/](code/frozen_g8_source/) | Checksum-bound source for the archived G8 execution |
| [code/results/](code/results/) | Study records and analysis inputs |
| [code/validation/](code/validation/) | Validation records and evidence mapping |

## Evaluation and provenance

The current implementation and the archived G8 execution have distinct source
lineages. Use the checksum-bound G8 source when interpreting that study.
The native-Qwen pilot is a separate descriptive experiment and is not pooled
with G8. Historical RQ6 bridge records were invalidated.

[EXPERIMENT_STATUS.md](code/EXPERIMENT_STATUS.md) documents comparator utility,
fallback sensitivity, historical provenance gaps, conditional Release premises,
and the remaining independent-defense/adaptive-attacker evaluation boundary.
Earlier records are retained under [results/](results/);
[LEGACY_CHECKSUMS.txt](LEGACY_CHECKSUMS.txt) applies to that historical inventory.

Reconstruct and audit the G8 analysis from `code/`:

```bash
python experiments/reconstruct_g8.py --output reconstructed.json
python experiments/audit_policy_bundles.py --output policy_audit.json
```

## Review artifact

The [anonymous review mirror](https://anonymous.4open.science/r/sluice-34EC/)
is pinned to `review-snapshot-20261117-formatting`. Its snapshot is independent
of this repository's `main` branch. [code/MANIFEST.sha256](code/MANIFEST.sha256)
records the review artifact checksums.
