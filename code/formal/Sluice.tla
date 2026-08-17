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
 *      an existing budget row; and
 *   5. consumed gates and created budget rows never become fresh again.
 *
 * GateCost is expressed in the implementation's normalized accounting
 * units.  For a gate with K successful symbols, that value conservatively
 * represents log_2(K + 4), where the additional outcomes are
 * SCHEMA_VIOLATION, BACKEND_ERROR, ARG_INVALID, and EFFECT_TOO_STRONG.
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
  SuccessfulOutcomes

Epochs == 0..MaxEpoch

GateObject(g) == IF g \in Object1Gates THEN Object1 ELSE Object2

GateEpoch(g) ==
  IF g \in Epoch0Gates
  THEN 0
  ELSE IF g \in Epoch1Gates THEN 1 ELSE 2

GateCost(g) == ChargedCost

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
  outcome

vars ==
  <<spent, cap, reauthRequired, deniedCost, budgetExists, capWriteCount,
    currentEpoch, consumed, charged, pendingBackend, outcome>>

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

CanAttempt(g) ==
  LET o == GateObject(g)
      e == GateEpoch(g)
  IN
    /\ ~consumed[g]
    /\ e = currentEpoch[o]
    /\ budgetExists[o][e]
    /\ ~reauthRequired[o][e]

(***************************************************************************
 * Successful reserve.  consumed, charged, and spent change in the same
 * action.  The backend has not run yet; it is represented by pendingBackend.
 *************************************************************************)
ClaimAndReserve(g) ==
  LET o == GateObject(g)
      e == GateEpoch(g)
      c == GateCost(g)
      newSpent == spent[o][e] + c
  IN
    /\ CanAttempt(g)
    /\ newSpent <= cap[o][e]
    /\ consumed' = [consumed EXCEPT ![g] = TRUE]
    /\ charged' = [charged EXCEPT ![g] = TRUE]
    /\ pendingBackend' = [pendingBackend EXCEPT ![g] = TRUE]
    /\ spent' = [spent EXCEPT ![o][e] = newSpent]
    /\ reauthRequired' =
         [reauthRequired EXCEPT ![o][e] = (newSpent = cap[o][e])]
    /\ UNCHANGED
         <<cap, deniedCost, budgetExists, capWriteCount, currentEpoch,
           outcome>>

(***************************************************************************
 * A reserve that would exceed the cap does not consume or charge the gate.
 * It latches reauthorization and records the attempted cost as a witness;
 * no backend observation can occur on this transition.
 *************************************************************************)
RejectForBudget(g) ==
  LET o == GateObject(g)
      e == GateEpoch(g)
      c == GateCost(g)
  IN
    /\ CanAttempt(g)
    /\ spent[o][e] + c > cap[o][e]
    /\ reauthRequired' = [reauthRequired EXCEPT ![o][e] = TRUE]
    /\ deniedCost' = [deniedCost EXCEPT ![o][e] = c]
    /\ UNCHANGED
         <<spent, cap, budgetExists, capWriteCount, currentEpoch,
           consumed, charged, pendingBackend, outcome>>

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
         capWriteCount, currentEpoch, consumed, charged>>

(***************************************************************************
 * A valid reauthorization creates exactly currentEpoch+1.  The target row
 * must not exist and its write count must be zero.  Historical spend, caps,
 * flags, and gate states are unchanged.
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
           pendingBackend, outcome>>

Idle == UNCHANGED vars

Next ==
  \/ \E g \in Gates : ClaimAndReserve(g)
  \/ \E g \in Gates : RejectForBudget(g)
  \/ \E g \in Gates, result \in PostDecodeOutcomes : FinishBackend(g, result)
  \/ \E o \in Objects, newCap \in NewCaps : Reauthorize(o, newCap)
  \/ Idle

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * Recursive sum over gates.  Unlike summing a set of costs, this counts two
 * different charged gates even when they have the same GateCost.
 *************************************************************************)
RECURSIVE SumGateCosts(_, _, _)

SumGateCosts(gs, o, e) ==
  IF gs = {}
  THEN 0
  ELSE
    LET g == CHOOSE x \in gs : TRUE
        thisCost ==
          IF charged[g] /\ GateObject(g) = o /\ GateEpoch(g) = e
          THEN GateCost(g)
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
