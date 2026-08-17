# Sluice: Capability-Based, Budgeted Mediation for Multi-Agent LLM Systems

Anonymized artifact accompanying the submission "Sluice: Capability-Based,
Budgeted Mediation for Multi-Agent LLM Systems." This package contains the
frozen implementation, the formal model, and raw results for every
evaluation (RQ1--RQ6) reported in the paper, with checksums.

## What this is and is not

This is the **evidence artifact**: the code that produced the paper's
numbers, and the raw, unaggregated output of every run. It is not a
one-command reproduction pipeline for the GPU-based studies (RQ5, RQ6),
which require downloading five open-weight models (tens of GB) and a
multi-GPU vLLM setup; those are documented well enough to rerun, but are
not lightweight. RQ1--RQ4 and the formal model run on CPU in seconds to
minutes and are the easiest to independently re-execute end to end.

## Structure.

```
code/
  sluice_v2/            Core reference monitor: monitor.py, store.py,
                         actions.py, and the test suites (49 + 7 = 56
                         tests: test_v2_attacks.py, test_v3_security_
                         regressions.py, test_v4_sequencing.py, plus
                         test_real_backend_pilot.py, 8 tests).
  formal/                TLA+ model (Sluice.tla, Sluice.cfg) and the
                         bounded-search state directory referenced by the
                         paper's mechanization claim (242,922 states
                         generated, 50,344 distinct, depth 12, no error).
                         tools/tla2tools.jar is the TLC model checker.
  experiments/            RQ1, RQ2, RQ4 driver scripts.
  integrations/
    langgraph_email_triage.py, langgraph_tools.py,
    test_langgraph_integration.py   RQ1's mediated LangGraph pipeline and
                                     its forged/replayed-capability tests
                                     (9 tests; combined with
                                     tests/test_redesigned_experiments.py's
                                     11, this is the paper's "combined
                                     LangGraph and experiment-harness"
                                     command, 20/20).
    agentdojo/                       RQ6's independent second framework
                                     integration -- see its own README.md
                                     for the AgentDojo dependency, the one
                                     patch it requires, and per-model
                                     results.
  SECURITY_PROOF.md       Extended technical report referenced by the
                         paper's Security Analysis section (full theorem
                         statement, non-claims, TCB declaration).
  pyproject.toml

results/
  rq1/    rq1.json (original 5-case), rq1_extended.json (25-case,
          reported in the paper).
  rq2/    rq2.json (12-config enumeration), rq2_multiobject_interleaved/
          (cross-object adaptive-attacker runs at caps 2/3/4/6/8, both
          verified and unverified passes).
  rq4/    Two timestamped runs, each with manifest.json (execution order,
          checksums), summary.json (aggregated latencies), and
          samples.jsonl.gz (raw per-call nanosecond samples). One run is
          the WAL benchmark profile; the other is the DELETE/FULL
          production-default profile reported in the paper's second RQ4
          table.
  rq5/    Nine timestamped real-model pilot runs (results.json,
          events.jsonl, SHA256SUMS.json where present) across the five
          models and expanded/original corpora reported in the paper.
  rq6/    The five (model, suite) AgentDojo runs reported in the paper:
          full_banking_granite.json, full_banking_mistral.json,
          full_workspace_granite.json, full_travel_granite.json,
          full_slack_mistral.json.

CHECKSUMS.txt   SHA-256 of every file in this artifact.
```

## Reproducing RQ1--RQ4 (CPU only)

```bash
cd code
python -m venv .venv && source .venv/bin/activate
pip install -e .
cd sluice_v2 && PYTHONPATH=. python -m pytest tests/ -q   # 56 tests
cd ../.. && PYTHONPATH=code:code/sluice_v2 python code/experiments/rq1_undefended_vs_sluice.py
PYTHONPATH=code:code/sluice_v2 python code/experiments/rq2_bound_tightness.py
PYTHONPATH=code:code/sluice_v2 python code/experiments/rq4_overhead.py
```

Exact package versions used for the results in `results/`: Python 3.9.18,
SQLite 3.50.2 (see the paper's Evaluation section). Later or earlier
versions of these packages have not been verified to reproduce identical
numbers, only the same qualitative behavior.

## Reproducing the formal model

```bash
cd code/formal
java -jar ../tools/tla2tools.jar -config Sluice.cfg Sluice.tla
```

## Reproducing RQ5 / RQ6 (GPU, open-weight models)

Requires downloading the five open-weight models used in the paper
(Qwen2.5-3B-Instruct, Phi-3.5-mini-instruct, Mistral-7B-Instruct-v0.3,
OLMo-2-1124-7B-Instruct, granite-3.1-8b-instruct) from Hugging Face, and a
GPU host running vLLM behind an OpenAI-compatible endpoint. See
`code/integrations/agentdojo/README.md` for the exact vLLM version,
per-model tool-call-parser configuration, and the one upstream AgentDojo
patch RQ6 requires; RQ5's real-model pilot driver is
`code/experiments/real_pilot_v2.py` / `real_pilot_v2_expanded.py`.

## What was deliberately left out of this package

- **AgentDojo itself** is not vendored (a ~40MB third-party repository,
  MIT-licensed, publicly available at
  github.com/ethz-spylab/agentdojo). Install it separately and apply the
  one patch documented in `code/integrations/agentdojo/README.md`.
- **Model weights** are not bundled. All five are public on Hugging Face
  under their own licenses; the paper and this artifact reference them by
  model ID, not by redistributing the checkpoints.
- **RQ5's raw SQLite audit databases** (`monitor.sqlite3` per run) are
  withheld from this anonymized package. Their hash-chained audit-log rows
  embed the GPU node identifier used to produce them as part of the
  chained hash input (by design -- see the paper's Design section on
  hash-linked storage); redacting the identifier after the fact would
  require recomputing the entire hash chain, and we chose not to risk
  silently corrupting the one piece of evidence whose entire purpose is
  tamper-evidence. The equivalent aggregated `results.json` /
  `events.jsonl` per run, which contain everything needed to verify the
  paper's RQ5 numbers, are included and unredacted.

## Anonymization note

Absolute paths, hostnames, and the operator username originally present in
this evidence (recorded automatically by the experiment scripts as
provenance metadata) have been replaced with generic placeholders
(`<HOME>`, `eval-host-a`, `gpu-node-1`/`2`/`3`, `researcher`) throughout
this package, in both file contents and file/directory names. This is a
mechanical redaction for double-blind review; it does not change any
numeric result, timestamp, or checksum of the underlying measurement data
itself.
