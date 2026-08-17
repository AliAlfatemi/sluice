# Security Argument — Sluice v2

## 1. Scope and status

This document makes one information-theoretic claim: under the assumptions in
§5, a `RELEASE` workflow bounds the mutual information carried by the
reference monitor's post-decode observations during one policy epoch. The
bound is a confidentiality statement.

`ENDORSE` uses the same gate, accounting, replay, and action-policy machinery,
but the confidentiality theorem does **not** turn that machinery into an
integrity theorem. For `ENDORSE`, the budget limits the capacity and number of
mediated decisions that untrusted content can influence. It does not show that
those decisions are correct, truthful, or safe. Section 7 states the narrower
integrity interpretation.

The TLA+ model in `formal/Sluice.tla` checks the transactional safety
properties on which the accounting argument relies. TLC does not prove the
mutual-information theorem; that theorem is the mathematical argument in §6.

## 2. Gate and observation model

Fix a protected object `obj`, policy epoch `e`, and an authored gate `g`.
The gate record binds, under the monitor's authenticated digest:

- its gate, workflow, protected-object, and epoch identifiers;
- direction (`RELEASE` or `ENDORSE`);
- a nonempty set of `K_g` successful symbols `Σ_g`;
- the action template associated with each symbol;
- permitted callers, expiration, and the policy-authored effect ceiling; and
- a fixed authorized cost determined before decoding.

The caller cannot supply an alphabet, cardinality, protected-object name,
epoch, or cost to `invoke()`.

### 2.1 Charged post-decode support

An invocation that passes its public preconditions and atomically claims its
gate can produce one of these typed security results, denoted `Y_g`:

```text
A_decode(g) = {(OK, s) : s ∈ Σ_g}
              ∪ {(SCHEMA_VIOLATION, ⊥),
                 (BACKEND_ERROR, ⊥),
                 (ARG_INVALID, ⊥),
                 (EFFECT_TOO_STRONG, ⊥)}.
```

Thus

```text
|A_decode(g)| = K_g + 4
c_g = log2(K_g + 4).
```

The implementation uses integer microbit accounting units. It rounds every
gate charge upward (`ceil(10^6 c_g)`) and every configured cap downward
(`floor(10^6 B)`). The authoritative SQLite columns are `INTEGER`, and spend
is accumulated by exact integer addition; the adjacent `REAL` columns are
human-readable mirrors and are never consulted for an authorization
decision. Writing `ĉ_g` for the resulting charged value, this gives
`ĉ_g ≥ c_g` while ensuring that the effective cap is no larger than the
configured cap. The TLA+ model uses the same natural-number accounting
semantics at a smaller illustrative scale.

The support is typed. For example, successful release of a symbol whose text
is `"schema_violation"` is distinct from the generic schema-failure outcome.
On every non-`OK` observation, both `value` and `action` are absent. On `OK`,
the action and authorized arguments are deterministic functions of the
selected symbol, public gate record, and public invocation inputs. A one-time
action-capability identifier is fresh randomness independent of the secret;
its authentication tag is a deterministic function of that independent
randomness and the already counted observation. These fields therefore add no
mutual information about the secret conditioned on the typed outcome. They
would invalidate the theorem if generated from, or allowed to encode, an
uncharged view of the secret.

Formally, write the full returned observation as `O_g = (Y_g, M_g)`, where
`M_g` contains fixed public record fields, public authorized arguments, and
the independent capability material. The required condition is
`I(S; M_g | H, Y_g) = 0`; the full observation need not itself have only
`K_g+4` syntactic encodings.

The backend is not trusted to honor the symbol set. An out-of-alphabet or
noncanonical return becomes `SCHEMA_VIOLATION`. An ordinary backend exception,
including a timeout represented as an exception, becomes the single generic
`BACKEND_ERROR` outcome. Exception types, messages, invalid raw values, and
argument values are not returned or placed in an observer-visible audit log.
Consequently an exception does not create an unbounded string-valued channel.

### 2.2 Pre-decode outcomes

Expiration, caller authorization, stale policy epoch, replay, and budget
exhaustion are checked without reading protected content. These outcomes are
uncharged only under the public-schedule assumption in §5: conditioned on the
observer's prior transcript and public inputs, the selected gate, call
occurrence, caller identity, time bucket, consumed state, current epoch, and
ledger state must already be determined.

This qualification matters. If, for example, secret-dependent control flow
silently consumes a gate and another party later probes it, `REPLAYED` could
reveal the hidden control flow. Such a deployment violates the theorem's
public-schedule assumption; the fact that replay checking occurs before
decode does not make an arbitrary schedule public.

There is no free, implicit `STOP` outcome in the theorem. Secret-dependent
termination must be represented by an explicit ordinary symbol in `Σ_g` and
therefore counted in `K_g`. Alternatively, stopping must be a deterministic
function of public history.

## 3. Transactional enforcement invariants

The reference monitor and durable store are intended to enforce the following
state-machine properties.

1. **Immutable gate resolution.** The monitor loads the server-side record,
   verifies its digest before interpreting security-sensitive fields, and
   derives the charged support and cost from that record.

2. **Atomic claim and reserve.** One SQLite `BEGIN IMMEDIATE` transaction
   checks that the gate is fresh and belongs to the current epoch, checks that
   its entire fixed cost fits, marks the gate consumed, and adds that cost to
   epoch spend. There is no state in which the gate is claimed but uncharged,
   or charged but still available to another invocation.

3. **Reserve before decode.** The backend is called only after the claim and
   reservation transaction commits. A failed reservation returns without
   reading protected content.

4. **No refund based on outcome.** Every member of `A_decode(g)`, including
   `BACKEND_ERROR`, retains the same reservation `ĉ_g`. A backend exception or
   schema failure consumes the gate; retrying the same handle cannot run the
   backend again.

5. **No overspend.** A claim succeeds only if
   `spent[obj,e] + ĉ_g ≤ cap[obj,e]`. Therefore spend never exceeds the cap.

6. **Monotonic reauthorization.** A valid, single-use grant is verified only
   with a key registered in the monitor's trusted authorizer registry. The
   signed grant names the expected prior epoch and exactly its successor.
   Redemption requires `previous_epoch = current_epoch` and
   `new_epoch = current_epoch + 1`, inserts a new budget row, and never uses
   replacement semantics. Historical spend and caps remain unchanged, and
   gates from an older epoch are stale.

These are safety properties. A crash after claim and before backend completion
may leave a charged, consumed gate with an incomplete outcome audit. That is a
conservative loss of availability, not a free release. Process crashes and
their timing remain outside the confidentiality theorem unless separately
mediated as stated in §5.

## 4. Transcript

For one protected object and epoch, let `H_i` be the complete public history
before attempted invocation `i`. It includes all prior monitor observations
and the public scheduling metadata listed in §5. Let `D_i` indicate that the
invocation passed its preconditions, successfully claimed its gate, reserved
its cost, and therefore may read protected content. Let `Y_i` be its typed
security result, `M_i` its remaining public metadata, and
`O_i = (Y_i, M_i)` the complete returned observation.

When `D_i = 1`, `Y_i` is supported on `A_decode(g_i)` and `M_i` is
conditionally independent of the secret given `(H_i, Y_i)`. When `D_i = 0`,
`O_i` is a deterministic function of `H_i` and public inputs under the
assumptions below.

The transcript `T` contains both charged and uncharged observations in order.
For a variable-length workflow, one can equivalently pad the transcript after
public stopping with a fixed public symbol. A secret-dependent decision to
stop is not eligible for such padding: it must itself be a charged symbol.

## 5. Assumptions and trusted computing base

The bound in §6 requires all of the following.

1. **Complete mediation.** Every value observable by the less-trusted
   recipient that may depend on the protected secret passes through
   `invoke()`. There is no unmediated file, socket, shared-memory, model-log,
   exception, direct-tool, or other output path.

2. **Public adaptive schedule.** Gate identity, gate cardinality, invocation
   occurrence and order, caller identity, retry behavior, stopping, and
   reauthorization behavior may adapt to prior public observations, but may
   not depend directly on the secret except through already charged
   observations. Equivalently, conditioned on `H_i` and public randomness,
   `g_i`, `D_i`, and every uncharged pre-decode result are independent of the
   secret. A fixed public upper bound on attempted calls is assumed; an
   infinite stream of free probes is not part of the theorem.

3. **Public policy records.** Gate records and their costs are authored from
   policy and public history, not selected using an uncharged view of the
   secret. Runtime action arguments are public inputs independent of the
   protected secret, or are separately mediated and charged. Fresh capability
   identifiers are sampled independently of the secret.

4. **Authenticated identities and keys.** The integration authenticates
   `caller_id`. Gate-authoring authority, the monitor's gate-digest key, and
   the configured reauthorization keys are trusted. A caller-chosen key is
   never accepted as a verification root.

5. **Sanitized observations.** Backend exception details, invalid raw output,
   argument values, and trusted diagnostic logs are not visible to the
   adversary. The adversary sees only the finite outcomes in §2 and public
   metadata.

6. **Timing exclusion.** Wall-clock latency, CPU/GPU contention, process
   termination, and microarchitectural behavior are not included in `T`.
   A timing-inclusive claim would require a finite timing alphabet, enforced
   quantization, and corresponding cost.

7. **Reauthorization boundary.** The theorem is per epoch. Approval or denial,
   the selected new cap, and the time of reauthorization are public-policy
   decisions independent of the secret, or must be included as separately
   charged observations. An authorizer that observes the secret and signals
   through grant behavior creates an additional channel not bounded here.

8. **Backend containment.** Ordinary backend exceptions are caught and
   collapsed to `BACKEND_ERROR`. Native crashes, forced process exit, and
   resource-exhaustion effects require process isolation to satisfy complete
   mediation and the timing exclusion.

These are deployment obligations, not properties established merely by
importing the Python library.

## 6. RELEASE confidentiality theorem

Let `S` be a protected secret and `T` the transcript for protected object
`obj` during one epoch. Suppose the assumptions in §5 hold and every possible
execution path has total committed charge at most `B` in that epoch.

Then

```text
I(S ; T) ≤ B.
```

### Proof

Order the attempted invocations and apply the conditional chain rule. For a
fixed history `H_i`, first expose the claim indicator `D_i`:

```text
I(S ; O_i | H_i)
  ≤ I(S ; D_i, O_i | H_i)
  = I(S ; D_i | H_i)
    + I(S ; O_i | H_i, D_i).
```

By the public-schedule assumption, `D_i` is determined by public history, so
`I(S ; D_i | H_i) = 0`. If `D_i = 0`, the returned pre-decode outcome is also
public-history-determined, so its conditional mutual information is zero. If
`D_i = 1`, decompose the full observation:

```text
I(S ; O_i | H_i, D_i=1)
  = I(S ; Y_i | H_i, D_i=1)
    + I(S ; M_i | H_i, D_i=1, Y_i)
  = I(S ; Y_i | H_i, D_i=1)
  ≤ H(Y_i | H_i, D_i=1)
  ≤ log2 |A_decode(g_i)|
  = log2(K_i + 4)
  ≤ ĉ_i.
```

The metadata term is zero by the conditional-independence requirements in
§§2 and 5.

This argument does not require backend outputs or successive observations to
be independent. Summing the conditional bounds gives

```text
I(S ; T)
  ≤ E[Σ_i D_i ĉ_i]
  ≤ B,
```

because `D_i ĉ_i` is committed before the corresponding protected decode and
the atomic store invariant prevents pathwise committed spend from exceeding
`B`.

The theorem is an upper bound on authorized channel capacity, not a statement
that exactly `B` bits are leaked and not an estimator of posterior guessing
probability. Tightness or empirical leakage requires a separate experiment
with a stated prior and a measured joint transcript distribution.

### Multiple epochs

Reauthorization does not erase information already released. If epochs
`0..m` have respective pathwise caps `B_0..B_m` and the reauthorization
assumptions hold, composition yields at most `Σ_e B_e`, not `B_m`. A lifetime
bound requires a separate lifetime cap. The durable lifetime-spend query is
an audit aid; by itself it does not enforce such a cap.

## 7. What ENDORSE does and does not establish

For `ENDORSE`, the input is attacker-controlled content and the selected
symbol may influence a trusted decision. The same finite support and budget
limit the number and variety of mediated selections, but they do not establish
semantic integrity:

- an attacker may be able to force any declared symbol while budget remains;
- a low-bandwidth symbol can still select a high-impact action;
- an `OK` classification is not evidence that its proposition is true; and
- `I(S;T)` is not an integrity metric merely because the direction field says
  `ENDORSE`.

Action templates, argument validation, recipient/resource scopes, and the
policy-authored effect ceiling are separate safety controls. They restrict
which effects a selected symbol may authorize. Their presence does not prove
that the selected effect is desirable, and the bandwidth budget does not
replace those controls.

Accordingly, **conditional on an OS-isolated broker satisfying complete
mediation**, the defensible ENDORSE claim is **budgeted mediated decision
bandwidth under an explicit effect policy**, not “bounded integrity loss” or
“prompt-injection prevention.” The provided same-process Python integration
demonstrates API-path integrity only; object privacy and underscore-prefixed
attributes are not a security boundary.

## 8. TLA+ mechanization

`formal/Sluice.tla` models two protected objects, durable budget rows across
epochs, single-use gates, atomic claim-and-reserve, abstract backend
completion, and strict next-epoch reauthorization. The configured backend
support has two successful symbols plus the four charged failure classes.
Each modeled claim charges three illustrative conservative integer units,
corresponding to rounding `log2(2+4)` upward in this finite abstraction. The
Python implementation uses the same rule at a scale of one million units per
bit.

TLC checks these state invariants:

- `NoOverspend`: every existing historical budget row stays within its cap;
- `SpendMatchesAtomicClaims`: spend equals the sum of costs of charged gates;
- `ClaimAndChargeAtomic`: a gate is consumed iff its charge committed;
- `GateLifecycleOK` and `BackendOutcomeWasCharged`: backend completion follows
  a charged claim and cannot reopen a gate;
- `ReauthHasConcreteCause`: a reauthorization latch has either an exact-cap
  charge or a concrete denied-reservation witness, replacing the old vacuous
  invariant that merely repeated no-overspend;
- `NoBudgetOverwrite`, `EpochRowsAreContiguous`, and
  `BudgetRowsWellFormed`: epochs are created once, in order, without resetting
  historical rows.

It also checks temporal properties that epochs never decrease, consumed gates
never become fresh, and budget rows never disappear.

With `formal/Sluice.cfg`, TLC 2.19 exhaustively generated 242,922 states,
found 50,344 distinct states at depth 12, left zero states on the queue, and
reported no invariant, temporal-property, or deadlock error. The check was
run locally with one worker on 2026-08-11; the same command is:

```bash
cd formal
java -jar ../tools/tla2tools.jar -deadlock -workers 1 \
  -config Sluice.cfg Sluice.tla
```

The model abstracts cryptographic verification as an authorization
precondition, represents costs as natural-number accounting units, and treats
the backend only as a nondeterministic choice from the finite `K+4` support.
It does not model SQLite internals, HMAC security, Python exception mechanics,
timing, complete mediation, or mutual information. Those limitations are why
the TLA+ result supports the store-safety premises of §6 rather than serving
as a proof of §6 itself.
