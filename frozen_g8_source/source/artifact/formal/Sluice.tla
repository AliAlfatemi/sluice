---- MODULE Sluice ----
(***************************************************************************
 * Sluice v2 safety model.
 *
 * This module models the transactional part of the reference monitor, not
 * the information-theoretic theorem itself.  In particular it checks that:
 *
 *   1. claiming a single-use gate and reserving its full, fixed cost are one
 *      atomic transition;
 *   2. a claimed gate can produce exactly one abstract post-decode outcome,
 *      chosen from K successful symbols plus the four charged failure
 *      classes used by the implementation;
 *   3. spend in every historical epoch remains within that epoch's cap;
 *   4. reauthorization creates exactly the next epoch and never overwrites
 *      an existing budget row;
 *   5. consumed gates and created budget rows never become fresh again; and
 *   6. successor-sequencing: predecessor lookup, successor-membership
 *      authorization, fanout computation, the resulting selection charge,
 *      the budget claim, and the sequencing-pointer update are one atomic
 *      transition, so that when two gates are both declared successors of
 *      the same predecessor, at most one of them can ever be consumed --
 *      including under the interleavings TLC explores between two
 *      concurrent claim attempts, which is exactly the race an earlier,
 *      non-atomic revision of this mechanism did not close.
 *
 * GateCost is expressed in the implementation's normalized accounting
 * units.  For a gate with K successful symbols, that value conservatively
 * represents log_2(K + 4), where the additional outcomes are
 * SCHEMA_VIOLATION, BACKEND_ERROR, ARG_INVALID, and EFFECT_TOO_STRONG.
 * SelectionCost is the analogous charge for fanout-many declared
 * successors, computed the same way in the implementation
 * (ceil(1e6*log2(fanout))) but modeled here as an abstract cost function of
 * the fanout alone, since TLC checks the *transactional* property, not the
 * numeric log2 table (that is checked separately by
 * test_selection_cost_units_table_matches_log2_formula in the Python test
 * suite).
 *************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Objects,
  Gates,
  Object1,
  Object2,
  Object1Gates,
  Epoch0Gates,
  Epoch1Gates,
  Epoch2Gates,
  ChargedCost,
  InitialCap,
  NewCaps,
  MaxEpoch,
  SuccessfulOutcomes,
  RacePredecessor,  \* the one gate this model gives a nonempty successor set
  RaceSuccessorA,   \* declared successor #1 of RacePredecessor
  RaceSuccessorB,   \* declared successor #2 of RacePredecessor -- races against A
  SelectionCost     \* [1..Cardinality(Gates) -> Nat]; SelectionCost[1] = 0 below

(***************************************************************************
 * SuccessorsOf and EntryFanout are derived, not raw configuration
 * constants: SuccessorsOf must name specific gates (RaceSuccessorA/B), the
 * same way Object1/Object2 already name specific elements of Objects, so
 * expressing it as an opaque CONSTANT function -- which the .cfg would
 * have no way to point at named model values with -- does not fit TLC's
 * usual pattern here. Every gate other than RacePredecessor declares no
 * successors (backward-compatible default); every gate's own EntryFanout
 * is 1 (the interesting fanout > 1 case in this model comes entirely from
 * RacePredecessor's declared successor set, not from any gate's own entry
 * fanout).
 *************************************************************************)
SuccessorsOf(g) ==
  IF g = RacePredecessor THEN {RaceSuccessorA, RaceSuccessorB} ELSE {}

EntryFanout(g) == 1

\* TLC's .cfg grammar cannot parse an inline function-constructor expression
\* for a CONSTANT assignment; SelectionCost is instead pointed at this
\* named definition via "SelectionCost <- SelectionCostDef" in Sluice.cfg.
SelectionCostDef == [n \in 1..5 |-> IF n = 1 THEN 0 ELSE 1]

Epochs == 0..MaxEpoch

GateObject(g) == IF g \in Object1Gates THEN Object1 ELSE Object2

GateEpoch(g) ==
  IF g \in Epoch0Gates
  THEN 0
  ELSE IF g \in Epoch1Gates THEN 1 ELSE 2

GateCost(g) == ChargedCost

NoGate == "no_gate"  \* sequencing-pointer sentinel: "no predecessor yet"

FailureOutcomes ==
  {"schema_violation", "backend_error", "arg_invalid", "effect_too_strong"}

PostDecodeOutcomes == SuccessfulOutcomes \cup FailureOutcomes
NoOutcome == "no_outcome"

ASSUME
  /\ Objects # {}
  /\ Gates # {}
  /\ Object1 # Object2
  /\ Objects = {Object1, Object2}
  /\ Object1Gates \subseteq Gates
  /\ Epoch0Gates \cup Epoch1Gates \cup Epoch2Gates = Gates
  /\ Epoch0Gates \cap Epoch1Gates = {}
  /\ Epoch0Gates \cap Epoch2Gates = {}
  /\ Epoch1Gates \cap Epoch2Gates = {}
  /\ MaxEpoch = 2
  /\ ChargedCost \in Nat \ {0}
  /\ InitialCap \in Nat
  /\ NewCaps \subseteq Nat
  /\ NewCaps # {}
  /\ IsFiniteSet(SuccessfulOutcomes)
  /\ SuccessfulOutcomes # {}
  /\ SuccessfulOutcomes \cap FailureOutcomes = {}
  /\ NoOutcome \notin PostDecodeOutcomes
  /\ Cardinality(FailureOutcomes) = 4
  /\ NoGate \notin Gates
  /\ RacePredecessor \in Gates
  /\ RaceSuccessorA \in Gates
  /\ RaceSuccessorB \in Gates
  /\ RaceSuccessorA # RaceSuccessorB
  /\ RaceSuccessorA # RacePredecessor
  /\ RaceSuccessorB # RacePredecessor
  \* Declared successors of g must live on the same (object, epoch) as g,
  \* matching the implementation's scoping ("for the same protected object
  \* and epoch") -- a chain never authorizes a successor on a different
  \* object or a different epoch. Checked directly on the two named race
  \* gates, since SuccessorsOf(g) is {} for every other gate by definition.
  /\ GateObject(RaceSuccessorA) = GateObject(RacePredecessor)
  /\ GateEpoch(RaceSuccessorA) = GateEpoch(RacePredecessor)
  /\ GateObject(RaceSuccessorB) = GateObject(RacePredecessor)
  /\ GateEpoch(RaceSuccessorB) = GateEpoch(RacePredecessor)
  /\ SelectionCost \in [1..Cardinality(Gates) -> Nat]
  /\ SelectionCost[1] = 0

VARIABLES
  spent,                \* spent[object][epoch]
  cap,                  \* immutable after an epoch row is created
  reauthRequired,       \* latched on exact exhaustion or denied reserve
  deniedCost,           \* witness for a reserve that did not fit
  budgetExists,         \* durable budget-row existence
  capWriteCount,        \* ghost state: number of creations of each row
  currentEpoch,
  consumed,
  charged,              \* ghost state paired atomically with consumed
  pendingBackend,
  outcome,
  lastGate,             \* lastGate[object][epoch]: sequencing pointer, or NoGate
  chainOptedIn,         \* chainOptedIn[object][epoch]: sticky "real branch happened" flag
  gateCharge            \* gateCharge[g]: the total charged to g at claim time, fixed thereafter

vars ==
  <<spent, cap, reauthRequired, deniedCost, budgetExists, capWriteCount,
    currentEpoch, consumed, charged, pendingBackend, outcome,
    lastGate, chainOptedIn, gateCharge>>

TypeOK ==
  /\ spent \in [Objects -> [Epochs -> Nat]]
  /\ cap \in [Objects -> [Epochs -> Nat]]
  /\ reauthRequired \in [Objects -> [Epochs -> BOOLEAN]]
  /\ deniedCost \in [Objects -> [Epochs -> Nat]]
  /\ budgetExists \in [Objects -> [Epochs -> BOOLEAN]]
  /\ capWriteCount \in [Objects -> [Epochs -> Nat]]
  /\ currentEpoch \in [Objects -> Epochs]
  /\ consumed \in [Gates -> BOOLEAN]
  /\ charged \in [Gates -> BOOLEAN]
  /\ pendingBackend \in [Gates -> BOOLEAN]
  /\ outcome \in [Gates -> (PostDecodeOutcomes \cup {NoOutcome})]
  /\ gateCharge \in [Gates -> Nat]
  /\ lastGate \in [Objects -> [Epochs -> (Gates \cup {NoGate})]]
  /\ chainOptedIn \in [Objects -> [Epochs -> BOOLEAN]]

Init ==
  /\ spent = [o \in Objects |-> [e \in Epochs |-> 0]]
  /\ cap = [o \in Objects |-> [e \in Epochs |-> IF e = 0 THEN InitialCap ELSE 0]]
  /\ reauthRequired = [o \in Objects |-> [e \in Epochs |-> FALSE]]
  /\ deniedCost = [o \in Objects |-> [e \in Epochs |-> 0]]
  /\ budgetExists = [o \in Objects |-> [e \in Epochs |-> e = 0]]
  /\ capWriteCount = [o \in Objects |-> [e \in Epochs |-> IF e = 0 THEN 1 ELSE 0]]
  /\ currentEpoch = [o \in Objects |-> 0]
  /\ consumed = [g \in Gates |-> FALSE]
  /\ charged = [g \in Gates |-> FALSE]
  /\ pendingBackend = [g \in Gates |-> FALSE]
  /\ outcome = [g \in Gates |-> NoOutcome]
  /\ lastGate = [o \in Objects |-> [e \in Epochs |-> NoGate]]
  /\ chainOptedIn = [o \in Objects |-> [e \in Epochs |-> FALSE]]
  /\ gateCharge = [g \in Gates |-> 0]

CanAttempt(g) ==
  LET o == GateObject(g)
      e == GateEpoch(g)
  IN
    /\ ~consumed[g]
    /\ e = currentEpoch[o]
    /\ budgetExists[o][e]
    /\ ~reauthRequired[o][e]

(***************************************************************************
 * Successor authorization, resolved against the *current* sequencing
 * pointer. Mirrors claim_and_reserve_gate's predecessor lookup: no
 * predecessor means the gate's own EntryFanout applies; a predecessor that
 * declares successors means membership in that set is required and the
 * fanout is its cardinality; a predecessor that declares no successors
 * means unconstrained fanout 1 *unless* the chain has already opted in
 * (chainOptedIn), in which case it is a declared leaf and nothing may
 * follow it.
 *************************************************************************)
Predecessor(g) == lastGate[GateObject(g)][GateEpoch(g)]

(***************************************************************************
 * A gate that some other gate names in its allowed_successor_gates is
 * reserved: it exists to be reached only via that declared relationship,
 * never as a free-standing entry point. Without this check, IsAuthorized's
 * p = NoGate branch would authorize g2/g5 the instant they are attempted
 * with no predecessor recorded yet -- which is *always* true the first time
 * either is attempted, since lastGate only ever names g1 after g1 itself is
 * consumed. That let a caller skip RacePredecessor entirely and claim a
 * declared successor at its own EntryFanout (1), defeating chain-entry
 * eligibility and successor mutual exclusion. TLC found this by violating
 * AtMostOneSuccessorClaimed with RacePredecessor never consumed at all.
 * This check and the success-only fanout charge do not make a
 * secret-dependent route safe; confidentiality separately assumes the
 * attempted gate schedule is a function of public history.
 *************************************************************************)
ReservedAsSuccessor(g) == \E p \in Gates : g \in SuccessorsOf(p)

IsAuthorized(g) ==
  LET p == Predecessor(g)
      o == GateObject(g)
      e == GateEpoch(g)
  IN
    IF p = NoGate
    THEN ~ReservedAsSuccessor(g)
    ELSE IF SuccessorsOf(p) # {}
         THEN g \in SuccessorsOf(p)
         ELSE ~chainOptedIn[o][e]

Fanout(g) ==
  LET p == Predecessor(g)
  IN
    IF p = NoGate
    THEN EntryFanout(g)
    ELSE IF SuccessorsOf(p) # {}
         THEN Cardinality(SuccessorsOf(p))
         ELSE 1

TotalCost(g) == GateCost(g) + SelectionCost[Fanout(g)]

(***************************************************************************
 * Successful reserve.  consumed, charged, spent, the sequencing pointer,
 * and chainOptedIn all change in the same action -- the fix this model
 * exists to check. The backend has not run yet; it is represented by
 * pendingBackend.
 *************************************************************************)
ClaimAndReserve(g) ==
  LET o == GateObject(g)
      e == GateEpoch(g)
      c == TotalCost(g)
      f == Fanout(g)
      newSpent == spent[o][e] + c
  IN
    /\ CanAttempt(g)
    /\ IsAuthorized(g)
    /\ newSpent <= cap[o][e]
    /\ consumed' = [consumed EXCEPT ![g] = TRUE]
    /\ charged' = [charged EXCEPT ![g] = TRUE]
    /\ pendingBackend' = [pendingBackend EXCEPT ![g] = TRUE]
    /\ spent' = [spent EXCEPT ![o][e] = newSpent]
    /\ reauthRequired' =
         [reauthRequired EXCEPT ![o][e] = (newSpent = cap[o][e])]
    /\ lastGate' = [lastGate EXCEPT ![o][e] = g]
    /\ chainOptedIn' =
         [chainOptedIn EXCEPT ![o][e] = @ \/ (f > 1)]
    \* Recorded once, here, from the pre-transition (unprimed) lastGate --
    \* not recomputed later. TotalCost(g)/Fanout(g) are functions of the
    \* *current* sequencing pointer, which later claims go on to change;
    \* SumGateCosts must check against what was actually reserved at claim
    \* time, not against what Fanout(g) would evaluate to now.
    /\ gateCharge' = [gateCharge EXCEPT ![g] = c]
    /\ UNCHANGED
         <<cap, deniedCost, budgetExists, capWriteCount, currentEpoch,
           outcome>>

(***************************************************************************
 * A reserve that would exceed the cap does not consume or charge the gate,
 * and does not touch the sequencing pointer.  Only reachable when the gate
 * is already authorized -- an unauthorized gate is rejected for free by
 * RejectForUnauthorizedSuccessor below, before budget is ever considered,
 * matching the implementation's ordering.
 *************************************************************************)
RejectForBudget(g) ==
  LET o == GateObject(g)
      e == GateEpoch(g)
      c == TotalCost(g)
  IN
    /\ CanAttempt(g)
    /\ IsAuthorized(g)
    /\ spent[o][e] + c > cap[o][e]
    /\ reauthRequired' = [reauthRequired EXCEPT ![o][e] = TRUE]
    /\ deniedCost' = [deniedCost EXCEPT ![o][e] = c]
    /\ UNCHANGED
         <<spent, cap, budgetExists, capWriteCount, currentEpoch,
           consumed, charged, pendingBackend, outcome, lastGate,
           chainOptedIn, gateCharge>>

(***************************************************************************
 * Free, pre-decode rejection: g is not the declared successor the current
 * predecessor authorizes (or the predecessor is a declared leaf on an
 * opted-in chain). No state changes at all -- not even reauthRequired --
 * since this is decided entirely from already-public state and must not
 * cost anything, matching UNAUTHORIZED_SUCCESSOR's zero charge.
 *************************************************************************)
RejectForUnauthorizedSuccessor(g) ==
  /\ CanAttempt(g)
  /\ ~IsAuthorized(g)
  /\ UNCHANGED vars

(***************************************************************************
 * Backend completion is abstract: TLC explores every member of the complete
 * K+4 post-decode support.  The reservation is never refunded, including for
 * BACKEND_ERROR and the other generic failure outcomes.
 *************************************************************************)
FinishBackend(g, result) ==
  /\ pendingBackend[g]
  /\ result \in PostDecodeOutcomes
  /\ pendingBackend' = [pendingBackend EXCEPT ![g] = FALSE]
  /\ outcome' = [outcome EXCEPT ![g] = result]
  /\ UNCHANGED
       <<spent, cap, reauthRequired, deniedCost, budgetExists,
         capWriteCount, currentEpoch, consumed, charged, lastGate,
         chainOptedIn, gateCharge>>

(***************************************************************************
 * A valid reauthorization creates exactly currentEpoch+1.  The target row
 * must not exist and its write count must be zero.  Historical spend, caps,
 * flags, and gate states are unchanged. The new epoch's sequencing state
 * starts fresh (NoGate, not opted in), matching that a fresh epoch row has
 * no predecessor of its own -- composition across epochs relies on this.
 *************************************************************************)
Reauthorize(o, newCap) ==
  LET nextEpoch == currentEpoch[o] + 1
  IN
    /\ currentEpoch[o] < MaxEpoch
    /\ newCap \in NewCaps
    /\ ~budgetExists[o][nextEpoch]
    /\ capWriteCount[o][nextEpoch] = 0
    /\ currentEpoch' = [currentEpoch EXCEPT ![o] = nextEpoch]
    /\ budgetExists' = [budgetExists EXCEPT ![o][nextEpoch] = TRUE]
    /\ cap' = [cap EXCEPT ![o][nextEpoch] = newCap]
    /\ capWriteCount' = [capWriteCount EXCEPT ![o][nextEpoch] = @ + 1]
    /\ UNCHANGED
         <<spent, reauthRequired, deniedCost, consumed, charged,
           pendingBackend, outcome, lastGate, chainOptedIn, gateCharge>>

Idle == UNCHANGED vars

Next ==
  \/ \E g \in Gates : ClaimAndReserve(g)
  \/ \E g \in Gates : RejectForBudget(g)
  \/ \E g \in Gates : RejectForUnauthorizedSuccessor(g)
  \/ \E g \in Gates, result \in PostDecodeOutcomes : FinishBackend(g, result)
  \/ \E o \in Objects, newCap \in NewCaps : Reauthorize(o, newCap)
  \/ Idle

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * Recursive sum over gates.  Unlike summing a set of costs, this counts two
 * different charged gates even when they have the same GateCost. Uses the
 * recorded gateCharge[g], not a recomputed TotalCost(g): TotalCost/Fanout/
 * Predecessor read the *current* lastGate, which later claims can and do
 * change, so recomputing here would silently re-derive a different fanout
 * (and hence a different charge) than what was actually reserved at the
 * moment g was claimed -- exactly the bug an earlier draft of this model
 * had, caught by TLC failing this very invariant.
 *************************************************************************)
RECURSIVE SumGateCosts(_, _, _)

SumGateCosts(gs, o, e) ==
  IF gs = {}
  THEN 0
  ELSE
    LET g == CHOOSE x \in gs : TRUE
        thisCost ==
          IF charged[g] /\ GateObject(g) = o /\ GateEpoch(g) = e
          THEN gateCharge[g]
          ELSE 0
    IN thisCost + SumGateCosts(gs \ {g}, o, e)

NoOverspend ==
  \A o \in Objects, e \in Epochs :
    budgetExists[o][e] => spent[o][e] <= cap[o][e]

SpendMatchesAtomicClaims ==
  \A o \in Objects, e \in Epochs :
    spent[o][e] = SumGateCosts(Gates, o, e)

ClaimAndChargeAtomic ==
  \A g \in Gates : consumed[g] = charged[g]

GateLifecycleOK ==
  \A g \in Gates :
    /\ pendingBackend[g] => consumed[g] /\ outcome[g] = NoOutcome
    /\ outcome[g] # NoOutcome => consumed[g] /\ ~pendingBackend[g]
    /\ ~consumed[g] => ~pendingBackend[g] /\ outcome[g] = NoOutcome

BackendOutcomeWasCharged ==
  \A g \in Gates : outcome[g] # NoOutcome => charged[g]

(***************************************************************************
 * Non-vacuous characterization of the reauthorization latch.  A true flag
 * has either an exact-cap successful charge or a concrete denied-cost
 * witness that would have exceeded the cap.  The old model's implication
 * "reauthRequired => spent <= cap" merely repeated NoOverspend.
 *************************************************************************)
ReauthHasConcreteCause ==
  \A o \in Objects, e \in Epochs :
    reauthRequired[o][e] =>
      /\ budgetExists[o][e]
      /\ \/ spent[o][e] = cap[o][e]
         \/ /\ deniedCost[o][e] > 0
            /\ spent[o][e] + deniedCost[o][e] > cap[o][e]

NoBudgetOverwrite ==
  \A o \in Objects, e \in Epochs : capWriteCount[o][e] <= 1

EpochRowsAreContiguous ==
  \A o \in Objects, e \in Epochs :
    budgetExists[o][e] = (e <= currentEpoch[o])

BudgetRowsWellFormed ==
  \A o \in Objects, e \in Epochs :
    IF budgetExists[o][e]
    THEN
      /\ capWriteCount[o][e] = 1
      /\ IF e = 0 THEN cap[o][e] = InitialCap ELSE cap[o][e] \in NewCaps
    ELSE
      /\ capWriteCount[o][e] = 0
      /\ cap[o][e] = 0
      /\ spent[o][e] = 0
      /\ ~reauthRequired[o][e]
      /\ deniedCost[o][e] = 0

(***************************************************************************
 * The successor-sequencing safety property this model was extended for:
 * for any gate p that declares a nonempty successor set, at most one
 * element of that set can ever be consumed. This is exactly "two mutually
 * incompatible successors race after the same predecessor; exactly one
 * may succeed" -- checked here as a state invariant (true in every
 * reachable state, not just as a single scripted test run), so it holds
 * under every interleaving TLC explores between ClaimAndReserve actions on
 * distinct declared siblings, not only the one interleaving a Python
 * thread-timing test happens to exercise.
 *************************************************************************)
AtMostOneSuccessorClaimed ==
  \A p \in Gates :
    SuccessorsOf(p) # {} =>
      Cardinality({s \in SuccessorsOf(p) : consumed[s]}) <= 1

(***************************************************************************
 * The sequencing pointer only ever names a gate that has actually been
 * consumed on that (object, epoch) -- it cannot point at a gate that was
 * merely attempted, rejected, or never invoked.
 *************************************************************************)
LastGateWasConsumed ==
  \A o \in Objects, e \in Epochs :
    lastGate[o][e] # NoGate =>
      /\ consumed[lastGate[o][e]]
      /\ GateObject(lastGate[o][e]) = o
      /\ GateEpoch(lastGate[o][e]) = e

(***************************************************************************
 * chainOptedIn is sticky: once TRUE for an (object, epoch), it is never
 * set back to FALSE by any action other than a fresh epoch's Init-like
 * reset via Reauthorize (which this property does not need to state,
 * since Reauthorize only ever writes chainOptedIn for a nextEpoch that
 * did not exist before, i.e. a value that was implicitly FALSE).
 *************************************************************************)
ChainOptedInIsSticky ==
  [][\A o \in Objects, e \in Epochs :
       chainOptedIn[o][e] => chainOptedIn'[o][e]]_vars

(***************************************************************************
 * Temporal monotonicity properties.  These are checked as PROPERTY entries,
 * not smuggled into TypeOK, so a transition that clears consumption,
 * deletes a budget row, or decrements an epoch produces a counterexample.
 *************************************************************************)
EpochNeverDecreases ==
  [][\A o \in Objects : currentEpoch'[o] >= currentEpoch[o]]_vars

ConsumedNeverClears ==
  [][\A g \in Gates : consumed[g] => consumed'[g]]_vars

BudgetRowsNeverDisappear ==
  [][\A o \in Objects, e \in Epochs :
       budgetExists[o][e] => budgetExists'[o][e]]_vars

====
