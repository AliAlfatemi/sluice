# Sluice artifact

This source snapshot accompanies the anonymous submission *Sluice:
Capability-Based, Budgeted Mediation for Multi-Agent LLM Systems*. It
contains the reference monitor, automated security regressions, the TLA+
model, experiment drivers, selected aggregate outputs, the full compressed
RQ4 sample table, and prospective integration code. It is not a complete
archive of every raw run: model weights, full audit databases, and model
inference traces are not included.

The snapshot was sanitized for anonymous review. Experiment drivers redact
the local hostname and working directory by default; RQ1/RQ2/RQ4 expose an
explicit `--include-host-provenance` opt-in for a non-anonymous archival run.
This directory makes no claim about unseen version-control history. No
license file is included, so review access should not be read as a grant to
redistribute the code.

## Quick start: automated suite

The dependency lock was frozen from a passing CPython 3.11.2 environment;
the final artifact was also validated with CPython 3.14.0. From this directory:

```sh
./run_all_tests.sh
```

The runner uses `python3`, clears and recreates `.venv`, installs the exact
versions in `requirements-lock.txt` plus pinned build tools, checks the
environment with `pip check`, verifies that `sluice_v2` imports outside the
source directory, and executes all configured pytest paths together. It
exits nonzero for a failure, collection error, skip, xfail, xpass, or any
total other than exactly **120 passed**. `SKIP_INSTALL=1 ./run_all_tests.sh`
may be used only to reuse the runner-created environment.

The 120 cases are:

- **111 RQ3 regression/security cases:** 91 under `sluice_v2/tests/`, nine
  LangGraph integration cases in `integrations/test_langgraph_integration.py`,
  and 11 experiment-harness contract cases in
  `tests/test_redesigned_experiments.py`.
- **9 RQ7 workflow cases:**
  `integrations/test_multiagent_security_triage.py`.

These are deterministic CPU tests and do not invoke a live model endpoint.
The seven-case live RQ7 driver is
`integrations/real_llm_multiagent_workflow.py`; its regression file contains
nine security/contract cases, so the two counts should not be conflated.

## Layout

- `sluice_v2/`: package-qualified reference-monitor implementation and core
  tests. `monitor.py` authors and invokes gates; `store.py` implements the
  SQLite ledger and atomic claim/reserve transaction; `actions.py` validates
  action arguments/effects; `backends_transformers.py` is the optional live
  classifier adapter.
- `integrations/`: LangGraph and multi-agent workflows, deterministic tests,
  the restored seven-input real-model RQ7 driver, and live-model provenance
  notes.
- `experiments/`: drivers and contract fixtures for RQ1, RQ2, RQ4, and RQ5.
- `formal/`: TLA+ specification/configuration, an archived TLC log, a concrete
  implementation counterexample, and the formal self-review.
- `results/`: selected aggregate JSON plus the compressed 500,000-row RQ4
  sample table; see `results/README.md` for evidentiary status and hashes.
- `agentdojo_integration/` and `agentdojo_pilot.py`: the historical invalidated
  RQ6 bridge plus a prospective work-in-progress bridge/driver. See the warning
  below before using any bundled RQ6 output.
- `camel_baseline_adapter/` and `camel_baseline_run.py`: a documented adapter
  and historical comparison driver requiring external CaMeL/AgentDojo code.

## TLA+ model checking

The model was checked with TLA+ tools **v1.7.4** (TLC2 2.19, revision
`5a47802`). Obtain the release jar from:

```text
https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
```

Required SHA-256:

```text
936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
```

With Java 11 or newer, run from `formal/`:

```sh
java -XX:+UseParallelGC -jar tla2tools.jar \
  -workers auto -config Sluice.cfg Sluice.tla
```

The bounded configuration should finish with no invariant error and report
1,035,371 generated states, 184,016 distinct states, zero states left on the
queue, and search depth 13. The archived transcript is
`formal/tlc_run/tlc_full_log.txt`; `formal/SHA256SUMS` records checksums for
the model, configuration, log, counterexample, and review. TLC's invariants
cover the modeled transactional and sequencing properties. They are not a
machine-checked proof of the paper's information-theoretic theorem; in
particular, the theorem separately assumes public-history-determined routing.

The implementation-level routing counterexample can be rerun with:

```sh
python3 formal/counterexamples/free_route_leak_repro.py
```

It demonstrates why a success-only selection charge does not make
secret-dependent gate selection safe.

## Experiments and included outputs

Each driver supports `--help`. Representative deterministic commands are:

```sh
python3 experiments/rq1_undefended_vs_sluice.py
python3 experiments/rq1_expanded.py
python3 experiments/rq2_bound_tightness.py
python3 experiments/rq2_multiobject_interleaved.py
python3 experiments/rq2_correlated_secrets.py
python3 experiments/rq4_overhead.py \
  --persistent-root /path/to/an/existing/persistent-filesystem
```

The exact available RQ4 switches are authoritative in `--help`; a valid
matched measurement requires explicitly choosing a persistent filesystem
distinct from the tmpfs profile. `--allow-same-filesystem` exists only for a
diagnostic smoke run and does not produce a valid paper measurement.

`results/` includes the 25-case RQ1 reconstruction output, an RQ2 multi-object
run, the RQ4 matched-sweep summary and all 500,000 compressed raw samples, a
five-model RQ5 aggregate, the seven-case live RQ7 output, historical
AgentDojo pilot JSON, and the historical CaMeL comparison. The RQ5 aggregate
records hashes of five preserved source result files, but those full traces
are not bundled. See `results/README.md` for per-file status and checksums.

### RQ1 reconstruction caveat

The original 25-case RQ1 driver was not preserved. The surviving aggregate
JSON is included, and `experiments/rq1_expanded.py` is a later reconstruction
with newly worded cases across the same stated categories. It reproduces the
reported aggregate under the same mechanism, but it is **not** an exact-input
re-execution of the lost driver. Its module docstring documents the boundary.

### RQ6 invalidation and required rerun

The bundled RQ6/AgentDojo JSON is invalid as defense-effectiveness evidence.
The measured bridge classified only 19 of 27 AgentDojo v1 mutators and reused
one one-time gate across multi-effect episodes. Consequently, some mutators
could bypass mediation while legitimate later effects could be rejected as
replays. `agentdojo_integration/INVALIDATED_RQ6.md` records this finding.

`agentdojo_integration/exact_effect_bridge.py` and the root
`agentdojo_pilot.py` are a prospective work in progress: they require an exhaustive
read-only/effectful registry partition and create one exact-argument,
single-use authorization per trusted effect, reject nested function calls,
pin the imported AgentDojo source tree, and alternate paired arm order. They
have not yet produced a
replacement result. RQ6 requires a fresh, paired undefended/Sluice benchmark
run with frozen AgentDojo, model-server, model-weight, CUDA, and container
provenance before any effectiveness claim can be made. AgentDojo and vLLM are
external dependencies and are deliberately not installed by
`run_all_tests.sh`.

### Live-model revision attestation

The RQ7, historical RQ6, and CaMeL drivers accept or record a model revision,
but the clients cannot query an OpenAI-compatible endpoint for the loaded
weight commit. The field is therefore operator-attested, not endpoint-verified.
Preserve the server command/log and a Hugging Face cache manifest with any
new evidence. `integrations/REAL_MODEL_EVIDENCE.md` describes the setup and
its limitations. The default local endpoint port in the restored RQ7 driver
is 18101; the documented CaMeL adapter defaults to port 8101 and honors an
explicit `SLUICE_LOCAL_BASE_URL` override.

## Reproducibility boundary

What can be reproduced from this directory alone is the 120-case CPU suite,
the deterministic experiment drivers that need only the locked Python
environment, the implementation counterexample, and (after separately
obtaining the checksum-pinned jar) the bounded TLA+ run. The included RQ4 raw
table can be re-aggregated without external data. Fresh RQ5/RQ7 model runs,
the corrected RQ6 rerun, and the CaMeL comparison require external software,
weights, compute, and provenance records. The artifact therefore does not
claim that every paper experiment is independently executable from a fresh
checkout with one command.
