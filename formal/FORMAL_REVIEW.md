# Formal review: the `free_route_leak` counterexample and its fix

## What this document is, and is not

This is a rigorous **adversarial self-review**, performed by the same
agent that authored the fix, immediately after making it, in the same
working session. It is not independent third-party review, and it is not
a substitute for one. A genuine external formal-methods reviewer — a
second author, or someone outside the project entirely — should still
check this before submission. What follows is the record of what was
checked, so that reviewer's job is verifying and extending this, not
starting from nothing.

No claim in this document has been fabricated or asserted without the
executable evidence cited alongside it. Where a claim could not be
verified in this session, it is listed under "Not verified" rather than
asserted.

## 0. Superseding 2026-08-20 theorem/interface audit

Sections 1--4 below preserve the earlier routing-counterexample review. A
later full interface audit found additional defects in the old paper proof;
therefore Section 6's historical statement that the routing-premise edit by
itself "restores soundness" is superseded by this section and by the revised
paper theorem.

The implementation's observable interface contains more than gate ID,
claim/denial, and typed outcome: caller and redeemer identities, credential
fields and clear SHA-256 content/argument digests, authorized arguments,
capability data, effects, and audit metadata are also observable. Any one of
these can carry uncharged information unless it is explicitly constrained to
be secret-independent given public history. A concrete zero-cost example is
an exhausted gate invoked by caller A when a secret bit is zero and caller B
when it is one: the denial and charge are identical, but the public audit row
reveals `caller_id`.

Authenticated invocation also hashes content and arguments while verifying a
credential before `claim_and_reserve_gate`. Thus "reserve before first read"
was false; the accurate implementation property is reserve before backend
decoding. A clear digest can be a dictionary oracle for low-entropy secret
content. The information-theoretic theorem can cover this implementation only
under an explicit premise that pre-claim authentication fields/outcomes are
secret-independent (or hidden from the stated observer). The code does not
enforce that premise.

The old appendix additionally omitted branch probabilities, silently
strengthened a metadata conditional-independence premise after conditioning on
the typed output, and summed epochs without one global chain rule. The revised
proof instead fixes a public finite horizon, pads stopped attempts, enumerates
the typed view `X_i=(G_i,A_i,Q_i,Y_i,M_i)`, and applies the chain rule in that
order. It conditions on the entire earlier transcript and bounds only the
charged padded result. All other fields are theorem premises, not mechanism
guarantees. The attempt horizon, secret/provenance labeling, metadata
independence, and decoder containment remain unenforced deployment
obligations.

Finally, the same-process Python adapter/runtime is part of the trusted
computing base. Only the model's candidate symbol is treated as adversarial;
the shipped code does not confine arbitrary backend code with OS isolation.
TLC checks the bounded transaction/sequencing model, not any of these mutual-
information premises.

## 1. The counterexample, reproduced

**Report as supplied**: after a predecessor declares successors `{A,B}`,
leaving insufficient budget, selecting `A` or `B` from a secret bit
exposes different gate IDs while both attempts return `BUDGET_EXHAUSTED`
with zero added spend.

**Verified**: `formal/counterexamples/free_route_leak_repro.py`, run
against the actual `ReferenceMonitor`/`DurableStore` implementation (not
a model of it), on 2026-08-18. Setup: predecessor `P` on object `victim`
declares successors `{A, B}`; `P` is claimed successfully; the remaining
budget is too small for either `A`'s or `B`'s own (content + selection)
charge. Two independent runs from byte-identical initial state, secret
bit 0 invokes `A`, secret bit 1 invokes `B`. Captured output
(`formal/counterexamples/free_route_leak_repro_output.txt`, SHA-256
`d3049d59c343256aca9caac430cd6d2d0ce287f840c3d8f64d2c89a8d06fbf77`):

```
secret_bit=0: outcome=budget_exhausted charged_bits=0.0, audit seq=6 gate_id=A
secret_bit=1: outcome=budget_exhausted charged_bits=0.0, audit seq=6 gate_id=B
free_route_leak counterexample confirmed: True
```

Both branches: `BUDGET_EXHAUSTED`, `charged_bits=0.0`. The audit log
distinguishes them (`gate_id='A'` vs `gate_id='B'`) — a free, repeatable
1-bit leak whenever route selection depends on the secret. This is a real
property of the shipped code, not a hypothetical.

## 2. Root cause: where the old proof's logic actually broke

The pre-fix proof's Step 0 claimed
$I(S;G_i\mid H_i)\le\log_2(\mathrm{fanout}_i)$ was "exactly the microbit
charge... reserved in the same transaction," and that this closed the
public-schedule gap for declared-successor chains. This is true only on
the branch where the claim succeeds ($D_i=1$): `store.py`'s
`claim_and_reserve_gate` computes `total_units = cost_units +
selection_units` unconditionally, but only adds it to `spent_units` when
the budget check passes (verified by direct reading of `store.py` lines
946–958 and confirmed by the counterexample's `spent_before ==
spent_after` on both branches). On the `D_i=0` branch, nothing is
charged, yet `G_i` — which specific gate was named — is fixed in the
public audit record via `_reject()`'s unconditional
`append_audit(handle.gate_id, ...)` call, before `D_i` is even
determined. The claimed bound conflated "reserved in the same
transaction" with "charged on every path"; they are different, and the
proof needed the latter but only had the former.

## 3. Why the narrower fix (Option A) was chosen over the stronger one (Option B)

Option B — reserve `log2(fanout)` unconditionally the moment a route is
named, never refund it on downstream denial, and prove a theorem that
allows secret-dependent routing under that mechanism — is the more
capable fix. It was not attempted here. Implementing it correctly
requires re-deriving the reserve invariant under a charge that is no
longer conditioned on `D_i`, re-verifying the TLA+ model, and re-checking
every interaction (does a route charge interact with `entry_fanout`?
Does never refunding it change the atomicity argument for
`AtMostOneSuccessorClaimed`? Does it hold across multiple sequential
routing decisions in one chain?) — each a plausible source of a new,
subtler error under time pressure, which is a worse outcome than an
honest, narrower theorem. Option A only requires the routing choice to be
public, which is what an unmodified, already-shown-correct argument
(Steps 1–4 below) already assumes for everything else in the transcript.
This matches the standing instruction to never fabricate or rush an
unverified strengthening; Option B is recorded as explicit future work,
not implemented or claimed (paper `main.tex`, Limitations).

## 4. What was checked in the corrected proof

- **Generality, not just the declared-successor case**: `_reject()`
  logs `handle.gate_id` unconditionally on every rejection path,
  regardless of whether the gate has any predecessor or declared
  successors at all (`monitor.py`, confirmed by direct reading). The gap
  is therefore general to *any* secret-dependent choice of which gate to
  invoke, not specific to `allowed_successor_gates`. The corrected
  premise — $I(S;G_i\mid H_i)=0$, unconditional, for every step — is
  stated at that general level, not patched narrowly to the
  two-successor case the counterexample happens to use.
- **$Z_i$'s zero-contribution claim, checked against all six denial
  reasons**: `EXPIRED`, `UNAUTHORIZED_CALLER`, `REPLAYED`,
  `STALE_EPOCH`, `BUDGET_EXHAUSTED`, `UNAUTHORIZED_SUCCESSOR` are each a
  deterministic function of already-public state (expiration timestamp,
  permitted-caller set, consumed flag, epoch counter, declared-successor
  set, spent-vs-cap comparison) *given* that $G_i$ and all prior $G_j$
  are public — which the corrected premise now supplies unconditionally,
  closing what would otherwise be a circular dependency (spent_units at
  step $i$ depends on the history of prior successful claims, which
  depends on prior $G_j$ being public).
- **Premise 3 needed $G_i$ added to its conditioning.** The pre-fix
  appendix conditioned "secret-independent public metadata" on
  $(H_i,D_i)$ only; since $G_i$ is revealed at step $i$, not part of
  $H_i$, and the content-charge argument (Step 1) conditions on
  $(H_i,G_i,D_i{=}1)$, premise 3's conditioning was inconsistent with
  its own use downstream. Fixed to condition on $(H_i,G_i,D_i{=}1)$.
- **Steps 1–2 of the old six-step appendix proof were redundant** with
  the corrected Step 0 (both re-derived $I(S;D_i\mid H_i)=0$ and the
  $D_i=0$ branch's zero contribution, using an $O_i$ that conflated the
  rejection and content branches). Folded into Step 0's $Z_i$/$O_i$
  split; the remaining four steps (alphabet bound, recombination, sum,
  reserve invariant) are unchanged in substance, renumbered, and
  re-verified to still compose correctly into $I(S;T)\le C/10^6\le B$.
- **The retained selection charge $r_i$ does not weaken the bound.**
  The code still reserves $q_i=c_i+r_i$ on a successful declared-successor
  claim and enforces $\sum_iD_i\widehat q_i\le C$. Since $q_i\ge c_i$
  (as $r_i\ge0$), this still implies $\sum_iD_ic_i\le C/10^6$, so keeping
  the existing code behavior unchanged is sound under the corrected
  proof — no code change was required for this fix, only the paper's
  claim about what the code's existing behavior proves.
- **Unbounded free-probe repetition is a separate, already-acknowledged
  gap**, not newly introduced or newly closed by this fix. The
  pre-existing "the theorem does not yet bound an unbounded number of
  free probes" paragraph (`main.tex`, Sec. 5) already states that a
  fixed, public, finite total-attempt bound is required and not enforced
  by the implementation; the corrected routing premise does not change
  this, and the two limitations are complementary (one bounds what a
  single probe can reveal about routing, the other bounds how many
  probes an attacker gets in total — neither implies the other).

## 5. Not verified

- No third-party human has reviewed this proof. This is the single most
  important open item before submission.
- The TLA+ model (`formal/Sluice.tla`) was not re-run against this
  proof's corrected premises in this session; `AtMostOneSuccessorClaimed`
  and the other existing invariants concern atomicity/mutual-exclusion of
  successor claims, not confidentiality, and are unaffected by this
  change, but this has not been independently re-checked against the
  current `.cfg`.
- Whether any other paper section (RQ7's multi-agent workflow, the RQ2
  correlated-secrets experiment, or the AgentDojo integration) implicitly
  relied on the retracted "selection charge closes the gap" claim has not
  been separately audited case by case; a search for other occurrences of
  "closes the gap" / "selection charge" language in `main.tex` was
  performed and all matches were corrected in this session, but a
  second, independent pass is recommended.

## 6. Historical routing-item verdict (superseded in scope by Section 0)

The route counterexample is real, reproduced, and root-caused. Option A (an
unconditional public-routing premise) repairs that specific proof step without
changing the implementation. It does not discharge the additional typed-view,
pre-claim-digest, finite-horizon, provenance, or containment obligations in
Section 0. Option B (a route-charging mechanism strong enough to cover
secret-dependent routing) remains open. The route bug is closed as a
documented premise correction; end-to-end confidentiality remains conditional
and needs independent expert review plus enforcement evidence before it should
be advertised as a deployment guarantee.
