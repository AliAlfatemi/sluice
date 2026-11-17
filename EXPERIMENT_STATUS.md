# Evidence status for the November revision

The root monitor, the archived G8 monitor, and the new native-Qwen frontend
are different source snapshots. They must not be treated as one frozen
implementation or one pooled experiment.

## Completed evidence

- Root CPU suite: 120 passed (111 regression/integration/harness cases plus
  9 workflow cases); no live model inference in this count.
- Bounded TLC recheck: 1,035,371 generated states, 184,016 distinct, depth 13,
  zero queued states, no invariant/temporal violation. Two objects, five
  gates, epochs 0..2, cap 7, charge 3, reauthorization caps 2 and 4. No
  agent/channel variables; no Python refinement proof.
- G8 archival verification: all 48,341 raw-result inventory entries and all
  260 source-manifest entries passed. Complete raw evidence is not bundled.
- G8 statistical reconstruction: all 31,380 terminals unique; both primary
  point estimates and exact 10,000-bootstrap intervals match the preserved
  analysis. The derived export does not prove raw chain integrity itself.
- Reference-trace mutation audit: 60/97 official reference solutions contain
  a mutating call. This does not show that every valid solution needs one.
- Fresh Qwen2.5 classifier runs: 3B 18/24 and 7B 15/24 label accuracy; 72
  valid linked audit entries each, no alphabet/runtime failure. These are
  constructed classifier cases, not a tool-agent benchmark.
- Structured effect diagnostic: eight fixed cases per model/condition,
  four conditions, 64 scored episodes. Full Sluice reached 4/8 utility for
  each model and blocked all observed scope/repeat violations. The 7B full
  arm recorded 12 replay and 2 budget denials; the 3B full arm 26 replay
  and zero budget denials. One task was deliberately over capacity.
- Structured Release diagnostic: two models, 256 uniform private-byte
  secrets, one control and 11 constructed extra-field scenarios each.
  Controls reveal exactly 2 bits; extra-field scenarios reveal zero in the
  declared non-timing observer view. Requests are generated only from public
  history and inserted by the harness. The restrictive wrapper rejects
  extra fields before loading the private document. This is not autonomous
  exfiltration search or production isolation validation.
- Native AgentDojo v3: fixed nine tasks per model, two models, benign and
  attacked, four conditions, 144 scored episodes; all six model/suite cells
  are required before the paper table is generated. Exact per-cell outcomes,
  authoring failures and model calls are retained. Do not pool with G8.

## Development attempts excluded from security comparisons

1. The initial unconstrained effect/Release diagnostic produced malformed
   3B requests and a zero-leakage control. It is development data; the final
   structured diagnostic uses one syntactic request grammar shared by every
   arm. The successful classifiers in the same directory are separately
   valid classifier runs.
2. Native AgentDojo v1 duplicated XML tool calls in assistant history. It
   was stopped and excluded.
3. Native v2 corrected history serialization but used a pipeline name the
   official attack factory rejected. It was stopped and excluded.
4. Native v3 validates attack construction for every scheduled task before
   model allocation. All three suite preflights and a real-tokenizer
   single-serialization check passed. The final traces contain no complete
   tool-call XML duplicated in assistant content; incomplete generated tags
   remain visible and malformed calls can terminate a rollout without an
   execution exception (generation limit: 256 tokens/step). The task/model/condition schedule did
   not change across these frontend corrections. No v1/v2 episode enters
   the final native table. The failed attempts and launch logs remain in
   the private audit folder/server archive.

The archived backend required Outlines 1.x but the base GPU environment had
0.0.46. The structured/classifier runs used the separately recorded 1.3.3
overlay. The new fail-fast API guard rejects the old API before loading
model weights. Native AgentDojo does not use Outlines.

## Questions still open

- No four-condition G8 rerun or faithful CaMeL/Progent common-harness
  comparison was completed. The two small new comparisons do not replace it.
- Static injections plus a defender reacting to feedback are not an
  adaptive attacker optimizing its prompts. Planner-policy poisoning is
  untested.
- The native 7B pilot is too small and its undefended utility too limited
  to establish effectiveness for broadly capable agents.
- The private-document Release wrapper does not validate secret-bearing
  authentication credentials, arbitrary egress, timing, native crashes, or
  an isolated OS broker. The library's deployment obligations remain.
- No complete historical account of design choices informed by all 7,800
  development arms was recovered. They remain excluded from held-out
  estimates.
- An independent mathematical review and an implementation/model
  refinement or trace-conformance argument remain outstanding.
- The anonymous link is https://anonymous.4open.science/r/sluice-34EC/ .
  It serves a pinned review snapshot, not the complete 2.2 GB raw archive.

## Reproduction entry points

```sh
./run_all_tests.sh
python3 experiments/reconstruct_g8.py --output reconstructed.json
python3 experiments/submission_diagnostics.py --help
python3 experiments/agentdojo_native_extension.py --help
python3 experiments/audit_reference_mutations.py --help
```

Obtain external GPU dependencies/weights and the checksum-pinned TLC jar
as described in README. GPU `plan.json` files record exact model revisions
and driver hashes. Archived source/runtime manifests describe G8 separately.

Anonymization changes paths and provenance text in the review copy. The
fresh manifest covers those bytes; historical manifests cover the original
archive. Neither is a substitute for the other.
