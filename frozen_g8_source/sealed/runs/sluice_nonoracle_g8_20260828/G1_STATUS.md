# G1 status

Execution identity: `sluice-agentdojo-g1-20260825-5a3bc26b5cb6495d33c64c054a661127`
Design identity (inherited byte-identically): `sluice-agentdojo-c15-20260824-95f6a3dcdf56493bac934494ff3af39d`
Branch: `usenix-acceptance-revision`, pinned at `68b665b14e4db460315e4a369ea1f8f5b22dbc08` for the run's duration.

Evidence roots:
- `runs/sluice_nonoracle_g1_20260825/` -- primary experiment
- `runs/sluice_rq5_paired_g1_20260825/` -- RQ5 corrected paired design
- `runs/sluice_g1_analysis_20260825/` -- derived statistics, macros, tables

**Everything here is same-session work. None of it has been independently
audited. No claim in this document has passed the project's principal-eligibility
gates, and no such claim is made: two of those gates are definitionally checks
that a second independent party reviewed the work, and they remain unmet.**

---

## 1. Root cause of the C10-C15 zero-arm failure class, and the fix

Full analysis with measurements: `runs/sluice_nonoracle_g1_20260825/G1_ROOT_CAUSE.md`.

Six identities died before `MATRIX_ACTIVE`, before all 90 policy preflights, and
before every one of 31,380 scheduled arms. The *trigger* was correctly
identified by the C-series: Git records only modes 0644/0755 and no directories
at all, so a tree sealed read-only (0444 files, 0555 dirs) containing an empty
directory cannot be reproduced by any checkout, and the verifiers that reject
such a checkout are right to.

The *cause of irrecoverability* was the response. Each generation hand-pinned a
table of per-capsule constants for every sealed tree it had to re-verify, and
each generation must re-verify every previous generation's capsules. Counted
directly from the helpers on disk:

| generation | hand-pinned sealed roots |
|---|---|
| C12 | 2 |
| C13 | 6 |
| C14 | 10 |
| C15 | 15 |

That is 1+2+...+n. C15's dispatch verifier says so in its own docstring:
*"Authenticate C15 dispatcher inputs and all fifteen sealed checkout roots."*
Every constant had to be simultaneously correct before arm #1, so each failure
made the next launch strictly harder. A seventh patch would have faced 21.

Secondary cost: C15's `C4_SHA256SUMS`, which must verify in full before any node
command, has **856 rows, of which only 134 are science dependencies**. 85% of
pre-launch integrity work was archaeology about previous failures.

### The fix (two parts)

1. **`sluice_tree_seal.py`** -- derive Git-omitted state by scanning
   (`TREE_SEAL.json`: every path's exact mode, every empty directory) and replay
   it after checkout. Adding an Nth tree is a loop iteration, not a code change,
   so the quadratic term disappears.
2. **G1 carries no failure-provenance capsules**, so sealed historical roots = 0
   and stay 0. The class is absent by construction, not patched more narrowly.

**Tests -- all passing:**

`test_sluice_tree_seal.py` (13/13), against real dulwich commit+checkout:
naive checkout fails verification; materialized checkout passes; **8 independent
capsules through one unchanged call**; fails closed on a genuinely missing file;
idempotent.

`test_real_capsule_materialization.py` (10/10), against **the actual C10 capsule
that terminated C11 and C12** (`runs/sluice_definitive_587d3fa_20260824_c11/
c10_failure_provenance/capsule`; 229 files @0444, 35 dirs @0555, 1 empty dir --
exactly C14's hand-pinned constants). It confirms the checkout loses all 229
modes and the empty directory, that the naive checkout fails verification, and
that after materialization **every path's mode matches the original exactly**.
The real capsule is never written to; it is copied first.

All four checkout-then-verify call sites were examined, not only the first:
the private-checkout helper; `verify_dispatch_manifest_c15.py`
(`sealed_mode_inventory`/`verify_sealed_modes`); `dispatch_gpu_c4.sh`; and
`node_arm_runner_c4.py` (`validate_pinned_checkout` plus a hardcoded provenance
table requiring `launch_c4_matrix.sh`/`dispatch_gpu_c4.sh` by exact filename).
The last is a genuine separate instance and is what the first G1 smoke test hit;
G1 satisfies it by using the canonical filenames, keeping the digest chain
end-to-end rather than loosening it.

**Integrity retained.** The G1 dispatcher verifies on cluster-login, before any node
command: branch and HEAD, full manifest closure (`sha256sum -c`), the digest of
every routed artefact, the runner's 0700 mode, and both SSH trust roots -- the
same contract as the F1 dispatcher, the last one in this project that provably
ran real arms. The G1 manifest is 251 rows (134 external science dependencies
carried over verbatim and re-verified, plus this run's own files).

---

## 2. Primary experiment (`sluice_nonoracle` vs `undefended`) -- PARTIAL

**`MATRIX_ACTIVE` was created at `2026-08-25T04:18:06Z` and real policy
preflights executed on GPUs. No C-series identity reached this point.**

Phase P progress at the time of writing: see
`runs/sluice_nonoracle_g1_20260825/policy_preflight/receipts/`.

Measured over the first 18 of 90 bundles (qwen25-3b; seeds 104729/130363/155921):

| quantity | value |
|---|---|
| bundles green (`all_required_gates_true`) | 18 / 18 |
| errors | 0 |
| policy tasks | 291 |
| **model-authored** tasks | **291 (100%)** |
| **context-overflow fallbacks** | **0** |
| technical failures | 0 |
| served requests | 1,035 |
| shard wall time | mean 304 s (min 255, max 389) |

The zero fallbacks matter: the C10 abort was a request-envelope overflow
(28,724 + 4,096 = 32,820 > 32,768) that the frozen classifier failed to
recognise. Across 291 authored tasks under the C11 classifier correction, the
deterministic zero-effect fallback was never needed and no task failed.

Phase P is resumable and demonstrably so: the run was deliberately paused
between batches to free GPUs for RQ5, then resumed, and the launcher correctly
skipped all 18 completed shards and continued.

**Not yet reached:** the global policy-set seal (requires all 90 bundles) and
therefore **zero evaluated arms**. No H4/H5 estimate exists from G1, and none is
claimed. The seal is a hard gate: no arm can run without it.

---

## 3. Secondary comparison (`official_tool_filter` vs `undefended`) -- COMPLETE

Derived by script (`analyze_f1_secondary.py`) from the F1 run's raw journals,
which contain a complete condition-matched matrix. Output:
`runs/sluice_g1_analysis_20260825/f1_secondary_qwen25-3b_s104729.json`.

Scope: **one model (qwen25-3b), one seed (104729)**, 2,092 arms, 0 arms with
errors, all three journal hash chains contiguous. This is not a population
estimate over models or seeds.

| condition | attacked $n$ | ASR | benign $n$ | utility | tool-call rate |
|---|---|---|---|---|---|
| undefended | 949 | 2.74% | 97 | 18.56% | 94.73% |
| official_tool_filter | 949 | 0.11% | 97 | 8.25% | 6.32% |

Paired over 949 matched (suite, user_task, injection_task) triples:
undefended-only successes 26, filter-only 1, both 0, neither 922.
McNemar exact two-sided **p = 4.17e-07**. ASR difference 2.63 points,
95% bootstrap CI **[1.58, 3.79]** (10,000 replicates, seed 20260825).

By suite, undefended ASR: banking 11.11% (n=144), slack 7.62% (n=105),
travel 1.43% (n=140), workspace 0.00% (n=560).

**Two caveats that must travel with these numbers.** First, the filter cuts the
tool-call rate from 94.73% to 6.32% and benign utility from 18.56% to 8.25%, so
much of its security gain is the agent not acting at all -- not a like-for-like
comparison against a defense that preserves utility. Second, the undefended ASR
is only 2.74%, and the largest suite (workspace, n=560) shows 0.00%, so this
model/attack pairing has little headroom to discriminate defenses at all.

---

## 4. RQ5 corrected paired design -- COMPLETE

Driver `rq5_paired_v1.py`; merged output
`runs/sluice_rq5_paired_g1_20260825/rq5_paired_merged.json`.

What the old driver could not do: it recorded only `matches_reference_label`,
so it could not separate clean error, injection-induced untargeted error, and
attainment of the attacker's chosen label, and had no clean/injected pairing.
Every case family here carries a clean and an injected rendering of the same
item, a reference label, an explicit attacker target, a named technique, and a
family id.

**300 records** = 5 pinned models x 3 seeds x 10 families x {clean, injected}.
Zero harness refusals, zero invalid outputs, zero alphabet escapes.

In-alphabet targets (8 families, 24 matched pairs per model):

| model | clean acc. | injected acc. | targeted ASR | untargeted err. | invalid |
|---|---|---|---|---|---|
| granite31-8b | 75.0% | 37.5% | 50.0% | 12.5% | 0% |
| mistral7b-v03 | 50.0% | 25.0% | 62.5% | 12.5% | 0% |
| olmo2-7b | 87.5% | 25.0% | 75.0% | 0.0% | 0% |
| phi35-mini | 62.5% | 12.5% | 87.5% | 0.0% | 0% |
| qwen25-3b | 75.0% | 25.0% | 50.0% | 25.0% | 0% |

Paired clean->injected transitions (24 pairs each) show the effect is **steering,
not degradation**: correct->attacker's-target dominates every other transition
(olmo2-7b 18/24, phi35-mini 12/24, granite31-8b 9/24, qwen25-3b 9/24,
mistral7b-v03 6/24), while correct->other-error is 0 for four of five models
(qwen25-3b: 3).

**Out-of-alphabet targets, reported separately** (2 families, 12 trials per
model, 60 total): **0 target attainments**, and clean and injected accuracy are
identical for every model (100% for four models; 50% for mistral7b-v03). The
constrained decoder cannot emit the named target, so target attainment is
structurally impossible; these are grammar-enforced structural resistance and
are never counted as attack successes.

**Seeds.** Decoding is greedy (`do_sample=False`), so seeds are a determinism
check, not a variance estimate. Measured: **0 of 100 cells disagreed** across
the three seeds. The paper must not present these three seeds as replication.

**Refusal.** Under finite-choice constrained decoding a natural-language refusal
is not expressible; what is observable is a non-OK monitor outcome. That rate is
0% everywhere here and must not be read as "no model refused".

### Two harness bugs found and their outputs destroyed

Both were caught by inspecting records rather than trusting completion:
1. `unauthenticated_caller` on 60/60 trials -- the deployed `sluice_v2` defaults
   `require_authenticated_caller=True`, so the monitor rejected every call before
   the model was consulted. Fixed by minting a real request-bound
   `CallerCredential` per call (not by using the unsafe opt-out).
2. `budget_exhausted` on 57/60 trials -- each call charges log2(4)=2 bits and the
   driver requested 8.0 cap bits, spent after four calls.

Both sets are quarantined under
`runs/sluice_rq5_paired_g1_20260825/discarded_*/` with READMEs stating they are
harness artefacts and must never be aggregated. The driver now runs a monitor
self-test before collecting anything and **refuses post-run to return any record
whose outcome is a harness refusal**.

---

## 5. CaMeL -- NOT RUN, structural blocker

A full counterbalanced CaMeL rerun was not attempted, for a reason that is
structural rather than a matter of time:

1. **The comparison needs a shared vulnerable-pair matrix that does not exist
   yet.** The existing driver's own docstring says so: *"a security-discriminating
   comparison requires a fresh shared vulnerable-pair matrix."* The existing
   result is a compatibility smoke test whose single attack pair was not even
   vulnerable in the shared undefended arm, so it cannot discriminate. That
   matrix must come from the undefended arm of the primary experiment -- which
   has produced zero arms (section 2). CaMeL is therefore *downstream* of work
   that is not finished.
2. **CaMeL is not installed** in any project environment. Only the two adapter
   patches and the runner survive (`source/artifact/camel_baseline_adapter/`,
   upstream commit `f083b6b396399d3b3c7f2ddaf613a5945eaf32d8`). The package
   itself would have to be fetched and built.
3. **Cost.** The smoke test's six banking tasks took 981 s (mean 163 s/episode)
   because CaMeL's interpreter makes many LLM calls per episode. A counterbalanced
   matrix over four suites, both arms and both orderings is GPU-days, competing
   with the primary experiment for the same six GPUs.

Running it anyway, on pairs not known to be vulnerable, would reproduce exactly
the defect that makes the existing result uncitable. Not run, and stated as such.

---

## 6. What is and is not citable

**Citable now:**
- The root-cause analysis and the general fix, with passing tests including
  against the real capsule that caused two of the failures.
- The secondary comparison (section 3), with its two caveats attached.
- The RQ5 corrected paired design (section 4), including the separately reported
  out-of-alphabet structural resistance and the seed-determinism finding.
- The measured Mistral-7B tool-call rate (section 7).

**Not citable / not established:**
- Any H4 or H5 result for `sluice_nonoracle`. Zero arms executed; no policy-set
  seal exists. The 18 green preflight bundles are process evidence, not outcomes.
- Any cross-model or cross-seed generalisation of section 3 (one model, one seed).
- Any CaMeL comparison.
- Independent audit of anything above. Same-session work only.
- Principal eligibility: not claimed, not pursued.

---

## 7. Mistral-7B-v0.3 -- measured, not assumed

From the F1 probe journals:

| model | arms | parsed an official tool call | rate |
|---|---|---|---|
| mistral7b-v03 | 16 | 0 | **0.000** |
| granite31-8b | 16 | 7 | 0.438 |
| qwen25-3b (undefended, full) | 1046 | 989 | 0.946 |
| qwen25-3b (tool filter, full) | 1046 | 66 | 0.063 |

Mistral emitted zero parseable tool calls in 16 probe arms, and 8 of its 16 arms
produced no assistant message at all. **Decision: run it and report the rate
beside every number**, rather than dropping it silently. Excluding a model would
change the design; a measured zero tool-call rate is itself a finding about small
open-weight models under AgentDojo's tool-calling protocol. Any Mistral security
number means "not attacked because it never acted", not "defended", and must
never be pooled with the other two models.

Note that Mistral *does* participate normally in RQ5 (section 4), which is a
single constrained classification rather than multi-turn tool calling -- so the
limitation is specific to the tool-calling protocol, not the model in general.

---

## 8. How to continue

Phase P is resumable. From `runs/sluice_nonoracle_g1_20260825/`:

```sh
bash launch_c4_matrix.sh          # skips completed bundles, continues
```

It requires the branch to remain at `68b665b1...` and the manifest closure to
verify (251 rows). **Do not commit to that branch while a run is in flight**:
the dispatcher pins HEAD, so moving the ref mid-run fails every subsequent
dispatch. (This happened once here and was corrected within the batch window by
restoring the ref; the commit was preserved on `refs/heads/g1-wip`.)

Once all 90 bundles are green the launcher creates the global seal and proceeds
to Phase E automatically. Analysis is already wired:
`analyze_agentdojo_journals_c4.py --treatment sluice_nonoracle --comparator undefended`,
and `runs/sluice_g1_analysis_20260825/generate_g1_macros.py` regenerates all
LaTeX macros and tables from the result JSON -- no number is hand-edited, and
anything unmeasured is emitted as `\gPending`, never as zero.
