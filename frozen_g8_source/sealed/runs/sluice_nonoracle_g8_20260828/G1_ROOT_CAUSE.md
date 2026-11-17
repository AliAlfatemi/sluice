# G1 root cause: why C10-C15 never executed a single arm

Status: same-session engineering analysis. Not independently audited.

## Summary

Six consecutive launch identities (C10, C11, C12, C13, C14, C15) terminated
before `MATRIX_ACTIVE`, before the 90 policy preflights, and before any of the
31,380 scheduled arms. Each generation diagnosed its own predecessor's death as
a local defect and shipped a narrower patch. The defect is not local. It is a
property of the evidence architecture itself, and it is divergent: the work
required for a clean launch grows faster than any single generation can close.

The trigger is real and correctly identified by the C-series:

> Git records only two file modes (0644, 0755) plus symlinks and gitlinks, and
> records no directories at all. A tree sealed read-only on disk (0444 files,
> 0555 directories) that also contains a deliberately empty directory therefore
> cannot be reproduced by any checkout.

That is true, and the launch-time verifiers that reject such a checkout are
correct to reject it. But that trigger alone would be a one-time fix. What made
it unfixable was the *response*: each generation hand-pinned a table of
per-capsule constants describing every sealed tree it had to re-verify -- and
every generation must re-verify every previous generation's capsules.

## The measured growth

`SealedTreeSpec` instantiations in each generation's checkout helper
(`create_sluice_c*_secure_checkout_*.py`), counted directly on the server:

| generation | sealed roots | matches |
|---|---|---|
| C12 | 2  | 1+1 |
| C13 | 6  | 1+2+3 |
| C14 | 10 | 1+2+3+4 |
| C15 | 15 | 1+2+3+4+5 |

C15's dispatch verifier states this in its own docstring: *"Authenticate C15
dispatcher inputs and all fifteen sealed checkout roots."*

The `historical_replays` array in `C*_RUNTIME_READ_SEALED_TREE_CONTRACT.json`
grows linearly alongside it (C13=2, C14=3, C15=4); each entry re-runs a prior
generation's verifier against a prior generation's physical checkout.

The verifier source grew accordingly:
`verify_c*_runtime_successor.py` went 10.9 KB (C7) -> 25.5 KB (C10) ->
51.0 KB (C11) -> 76.3 KB (C12); `verify_dispatch_manifest_c*.py` went
25.0 KB (C9) -> 38.7 KB (C15).

Every one of those `files=`, `directories=` and `digest=` constants had to be
hand-computed and exactly correct *before arm #1 could run*. So with each
failed attempt the number of things that must be simultaneously right grew
quadratically, while each new failure added yet another capsule to the set.
That is why the death moved every time and never converged:

- **C10** -- real science defect: a pinned-vLLM request-envelope overflow
  (28,724 prompt + 4,096 completion = 32,820 > 32,768). Correctly fixed.
- **C11** -- checkout did not preserve the capsule's 0444/0555 seal or its one
  empty directory.
- **C12** -- fixed that for its *own* capsule, then failed replaying a
  historical proof against a *second*, separately checked-out archive
  (`runs/sluice_definitive_587d3fa_20260824_c11`) that still had native
  0644/0700 modes.
- **C13** -- exit 67 at `latch_installed`: *"checkout parent changed after
  authentication."* The anti-TOCTOU latch watches `run_checkouts/`, a directory
  the C-series itself keeps adding siblings to.
- **C14** -- exit 68 at `helper_terminal`: *"C14 manifest does not bind capsule
  manifest: runs/sluice_definitive_587d3fa_20260824_c11/..."*
- **C15** -- frozen and committed at `68b665b1`, never launched.

A seventh narrow patch would have had to get 15 hand-pinned sealed roots and 4
historical replays right at once, and an eighth would have had 21 and 5.

## The second, quieter cost

`C4_SHA256SUMS` -- the manifest that must verify in full before any node
command is issued -- contains 856 rows in C15. Only 134 of them are the actual
science dependencies (AgentDojo v0.1.35, `sluice_v2`, model snapshot
manifests, the S1 policy modules). The other 722 are records of previous
failures. 85% of the pre-launch integrity work was archaeology.

## The general fix

Two parts, and the second is the one that closes the class.

**1. Stop hand-writing Git-omitted state; derive it.**
`sluice_tree_seal.py` scans a tree and emits `TREE_SEAL.json` recording every
path's exact mode plus every empty directory, then replays that after a
checkout. Adding an Nth sealed tree needs no new code and no new constants, so
the quadratic term disappears. `test_sluice_tree_seal.py` proves this against a
real dulwich commit+checkout round trip:

- a naive checkout **fails** verification (0444 -> 0644, empty dir absent),
- the same checkout **passes** after materialization,
- **8 independent capsules** materialize through one unchanged call,
- materialization **fails closed** if a sealed file is genuinely absent -- it
  restores modes, it never invents evidence.

13/13 assertions pass.

**2. Do not accumulate failure capsules into the launch path at all.**
The G1 run carries no failure-provenance capsules, so the number of sealed
historical roots is zero and stays zero. This is what makes the fix general
rather than a sixth narrower patch: the failure mode is absent by construction,
not merely handled better.

Every integrity property that protects the *science* is retained in full. The
G1 dispatcher still verifies, on cluster-login, before any node command: the committed
branch and HEAD, the complete manifest closure (`sha256sum -c`), the digest of
every routed artefact (runner, payload, plan sums, harness library), the
runner's 0700 mode, and both SSH trust roots. That is the same contract as the
F1 dispatcher, which is the last dispatcher in this project that provably ran
real arms end to end (2,092 arms on 2026-08-22).

The G1 manifest is 246-249 rows: 134 external science dependencies carried over
verbatim from the C15 manifest (all re-verified) plus this run's own static
files. Same guarantee, no archaeology.

## Call sites checked

Checkout-then-verify appears at four distinct layers. All four were examined,
not just the one that failed first:

1. `create_sluice_c*_secure_checkout_*.py` -- the private-checkout helper
   (`_materialize_sealed_trees`, `_git_omitted_checkout_directories`,
   `_assert_exact_git_checkout`). Quadratic hand-pinned specs. **Root cause.**
2. `verify_dispatch_manifest_c15.py` -- `sealed_mode_inventory` /
   `verify_sealed_modes` against a JSON mode contract enumerating 15 roots.
3. `dispatch_gpu_c4.sh` -- invokes (2) plus a vendored-Dulwich blob check.
4. `node_arm_runner_c4.py` -- `validate_pinned_checkout(CHECKOUT)` on
   `external/agentdojo-v0.1.35`, plus a hardcoded provenance-file table
   requiring `launch_c4_matrix.sh` and `dispatch_gpu_c4.sh` by exact filename.

(4) is a genuine, separate instance of the same class and it is what the first
G1 smoke test tripped on: the payload demands those two canonical filenames in
the evidence directory and hashes them against what the dispatcher passed. G1
satisfies it honestly, by using the canonical names, so the digest chain stays
end-to-end intact rather than being loosened.
