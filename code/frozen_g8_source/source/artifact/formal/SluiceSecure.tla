---- MODULE SluiceSecure ----
(***************************************************************************
 * Acceptance-revision safety model for Sluice's enforced secure domain.
 *
 * This module is additive.  It does not replace the historical Sluice.tla
 * model, and it does not claim that TLC has verified the Python program.
 * FORMAL_CORRESPONDENCE.md states the abstraction boundary and the exact
 * transition record that a later implementation trace checker must validate.
 *
 * One model transition represents one durable transaction, except Finalize,
 * which represents deterministic completion/recovery of a previously
 * committed RESERVED attempt.  All observer-visible operations reserve a
 * fixed transcript charge before validation.  Successful claims atomically
 * consume their authorization material, one gate, their budget/attempt slot,
 * and one audit-start row.  Failed claims consume the budget/attempt slot but
 * no credential, delegation, gate, or capability.  Backend failure after a
 * committed claim never resurrects authorization.
 *************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Domains, Objects, Workflows, Agents, Nonces, Delegations, ReauthGrants,
  Gates, Capabilities, Redeemers,

  DomainOne, DomainTwo,
  ObjectOne, ObjectTwo, ObjectThree,
  WorkflowOne, WorkflowTwo,
  AgentOne, AgentTwo,
  DelegationOne, DelegationTwo,
  ReauthOne, ReauthTwo,
  RacePredecessor, RaceSuccessorA, RaceSuccessorB, CrossDomainSuccessor,
  SharedObjectGate, DomainTwoGate, EpochOneGate,
  CapabilityOne, CapabilityTwo,
  RedeemerOne, RedeemerTwo,

  InitialBudget, InitialHorizon, EventCharge,
  ReauthBudgetIncrement, ReauthAttemptIncrement, MaxEpoch

NoGate == "NO_GATE"
NoRedeemer == "NO_REDEEMER"

Epochs == 0..MaxEpoch
CredentialKeys == Agents \X Nonces
Scopes == Domains \X Workflows \X Objects \X Epochs

(***************************************************************************
 * Static, trusted configuration.  Two differently protected objects share
 * DomainOne.  CrossDomainSuccessor is deliberately named by the predecessor
 * but has a different complete scope; attempts to use it exercise fail-closed
 * scope validation.  RaceSuccessorA/B are the non-vacuous same-scope race.
 *************************************************************************)
GateDomain(g) ==
  IF g \in {RacePredecessor, RaceSuccessorA, RaceSuccessorB,
             SharedObjectGate, EpochOneGate}
  THEN DomainOne
  ELSE DomainTwo

GateObject(g) ==
  CASE g \in {RacePredecessor, RaceSuccessorA, RaceSuccessorB,
               EpochOneGate} -> ObjectOne
    [] g = SharedObjectGate -> ObjectTwo
    [] OTHER -> ObjectThree

GateWorkflow(g) ==
  IF g \in {CrossDomainSuccessor, DomainTwoGate}
  THEN WorkflowTwo
  ELSE WorkflowOne

GateEpoch(g) == IF g = EpochOneGate THEN 1 ELSE 0

GateScope(g) ==
  <<GateDomain(g), GateWorkflow(g), GateObject(g), GateEpoch(g)>>

SuccessorsOf(g) ==
  IF g = RacePredecessor
  THEN {RaceSuccessorA, RaceSuccessorB, CrossDomainSuccessor}
  ELSE {}

ReservedSuccessor(g) == \E p \in Gates : g \in SuccessorsOf(p)

ScopeCompatible(p, g) ==
  /\ GateDomain(p) = GateDomain(g)
  /\ GateWorkflow(p) = GateWorkflow(g)
  /\ GateObject(p) = GateObject(g)
  /\ GateEpoch(p) = GateEpoch(g)

DelegationAgent(gr) == IF gr = DelegationOne THEN AgentOne ELSE AgentTwo
DelegationGate(gr) ==
  IF gr = DelegationOne THEN RacePredecessor ELSE CrossDomainSuccessor

ReauthDomain(rg) == IF rg = ReauthOne THEN DomainOne ELSE DomainTwo

CapabilityGate(c) == IF c = CapabilityOne THEN SharedObjectGate ELSE DomainTwoGate
CapabilityRedeemer(c) == IF c = CapabilityOne THEN RedeemerOne ELSE RedeemerTwo
GateNeedsCapability(g) == g \in {SharedObjectGate, DomainTwoGate}

ASSUME
  /\ Domains = {DomainOne, DomainTwo}
  /\ DomainOne # DomainTwo
  /\ Objects = {ObjectOne, ObjectTwo, ObjectThree}
  /\ Cardinality(Objects) = 3
  /\ Workflows = {WorkflowOne, WorkflowTwo}
  /\ WorkflowOne # WorkflowTwo
  /\ Agents = {AgentOne, AgentTwo}
  /\ AgentOne # AgentTwo
  /\ Nonces # {}
  /\ IsFiniteSet(Nonces)
  /\ Delegations = {DelegationOne, DelegationTwo}
  /\ DelegationOne # DelegationTwo
  /\ ReauthGrants = {ReauthOne, ReauthTwo}
  /\ ReauthOne # ReauthTwo
  /\ Gates = {RacePredecessor, RaceSuccessorA, RaceSuccessorB,
               CrossDomainSuccessor, SharedObjectGate, DomainTwoGate,
               EpochOneGate}
  /\ Cardinality(Gates) = 7
  /\ Capabilities = {CapabilityOne, CapabilityTwo}
  /\ CapabilityOne # CapabilityTwo
  /\ Redeemers = {RedeemerOne, RedeemerTwo}
  /\ RedeemerOne # RedeemerTwo
  /\ NoGate \notin Gates
  /\ NoRedeemer \notin Redeemers
  /\ MaxEpoch = 1
  /\ InitialBudget \in Nat \ {0}
  /\ InitialHorizon \in Nat \ {0}
  /\ EventCharge \in Nat \ {0}
  /\ ReauthBudgetIncrement \in Nat \ {0}
  /\ ReauthAttemptIncrement \in Nat \ {0}
  /\ InitialBudget = InitialHorizon * EventCharge
  /\ ReauthBudgetIncrement = ReauthAttemptIncrement * EventCharge
  /\ GateScope(RaceSuccessorA) = GateScope(RacePredecessor)
  /\ GateScope(RaceSuccessorB) = GateScope(RacePredecessor)
  /\ ~ScopeCompatible(RacePredecessor, CrossDomainSuccessor)
  /\ GateDomain(SharedObjectGate) = GateDomain(RacePredecessor)
  /\ GateObject(SharedObjectGate) # GateObject(RacePredecessor)

VARIABLES
  lifetimeSpent, lifetimeBudget, epochSpent,
  attempts, horizon, currentEpoch, epochAdvanceCount, closed,
  gateClaims, nonceUses, delegationUses, reauthUses, capabilityUses,
  nonceClaimGate, delegationClaimGate, capabilityClaimGate,
  capabilityRedeemedBy, claimPredecessor,
  pending, finalized, auditStarts, gateCharge, lastGate,
  visibleEvents, paddingEvents,
  authorizationVersion, lastWasFailedClaim, failureAuthorizationVersion,
  delegatedRollbackWitness, rejectedReauthorizationWitness

vars ==
  <<lifetimeSpent, lifetimeBudget, epochSpent,
    attempts, horizon, currentEpoch, epochAdvanceCount, closed,
    gateClaims, nonceUses, delegationUses, reauthUses, capabilityUses,
    nonceClaimGate, delegationClaimGate, capabilityClaimGate,
    capabilityRedeemedBy, claimPredecessor,
    pending, finalized, auditStarts, gateCharge, lastGate,
    visibleEvents, paddingEvents,
    authorizationVersion, lastWasFailedClaim, failureAuthorizationVersion,
    delegatedRollbackWitness, rejectedReauthorizationWitness>>

TypeOK ==
  /\ lifetimeSpent \in [Domains -> Nat]
  /\ lifetimeBudget \in [Domains -> Nat]
  /\ epochSpent \in [Domains -> [Epochs -> Nat]]
  /\ attempts \in [Domains -> Nat]
  /\ horizon \in [Domains -> Nat]
  /\ currentEpoch \in [Domains -> Epochs]
  /\ epochAdvanceCount \in [Domains -> Nat]
  /\ closed \in [Domains -> BOOLEAN]
  /\ gateClaims \in [Gates -> Nat]
  /\ nonceUses \in [CredentialKeys -> Nat]
  /\ delegationUses \in [Delegations -> Nat]
  /\ reauthUses \in [ReauthGrants -> Nat]
  /\ capabilityUses \in [Capabilities -> Nat]
  /\ nonceClaimGate \in [CredentialKeys -> (Gates \cup {NoGate})]
  /\ delegationClaimGate \in [Delegations -> (Gates \cup {NoGate})]
  /\ capabilityClaimGate \in [Capabilities -> (Gates \cup {NoGate})]
  /\ capabilityRedeemedBy \in [Capabilities -> (Redeemers \cup {NoRedeemer})]
  /\ claimPredecessor \in [Gates -> (Gates \cup {NoGate})]
  /\ pending \in [Gates -> BOOLEAN]
  /\ finalized \in [Gates -> BOOLEAN]
  /\ auditStarts \in [Gates -> Nat]
  /\ gateCharge \in [Gates -> Nat]
  /\ lastGate \in [Scopes -> (Gates \cup {NoGate})]
  /\ visibleEvents \in [Domains -> Nat]
  /\ paddingEvents \in [Domains -> Nat]
  /\ authorizationVersion \in Nat
  /\ lastWasFailedClaim \in BOOLEAN
  /\ failureAuthorizationVersion \in Nat
  /\ delegatedRollbackWitness \in BOOLEAN
  /\ rejectedReauthorizationWitness \in BOOLEAN

Init ==
  /\ lifetimeSpent = [d \in Domains |-> 0]
  /\ lifetimeBudget = [d \in Domains |-> InitialBudget]
  /\ epochSpent = [d \in Domains |-> [e \in Epochs |-> 0]]
  /\ attempts = [d \in Domains |-> 0]
  /\ horizon = [d \in Domains |-> InitialHorizon]
  /\ currentEpoch = [d \in Domains |-> 0]
  /\ epochAdvanceCount = [d \in Domains |-> 0]
  /\ closed = [d \in Domains |-> FALSE]
  /\ gateClaims = [g \in Gates |-> 0]
  /\ nonceUses = [k \in CredentialKeys |-> 0]
  /\ delegationUses = [gr \in Delegations |-> 0]
  /\ reauthUses = [rg \in ReauthGrants |-> 0]
  /\ capabilityUses = [c \in Capabilities |-> 0]
  /\ nonceClaimGate = [k \in CredentialKeys |-> NoGate]
  /\ delegationClaimGate = [gr \in Delegations |-> NoGate]
  /\ capabilityClaimGate = [c \in Capabilities |-> NoGate]
  /\ capabilityRedeemedBy = [c \in Capabilities |-> NoRedeemer]
  /\ claimPredecessor = [g \in Gates |-> NoGate]
  /\ pending = [g \in Gates |-> FALSE]
  /\ finalized = [g \in Gates |-> FALSE]
  /\ auditStarts = [g \in Gates |-> 0]
  /\ gateCharge = [g \in Gates |-> 0]
  /\ lastGate = [s \in Scopes |-> NoGate]
  /\ visibleEvents = [d \in Domains |-> 0]
  /\ paddingEvents = [d \in Domains |-> 0]
  /\ authorizationVersion = 0
  /\ lastWasFailedClaim = FALSE
  /\ failureAuthorizationVersion = 0
  /\ delegatedRollbackWitness = FALSE
  /\ rejectedReauthorizationWitness = FALSE

CanReserve(d) ==
  /\ ~closed[d]
  /\ attempts[d] < horizon[d]
  /\ lifetimeSpent[d] + EventCharge <= lifetimeBudget[d]

AtCurrentEpoch(g) == GateEpoch(g) = currentEpoch[GateDomain(g)]

CurrentPredecessor(g) == lastGate[GateScope(g)]

SuccessorAuthorized(g) ==
  IF ReservedSuccessor(g)
  THEN
    /\ CurrentPredecessor(g) \in Gates
    /\ g \in SuccessorsOf(CurrentPredecessor(g))
    /\ ScopeCompatible(CurrentPredecessor(g), g)
  ELSE CurrentPredecessor(g) = NoGate

ReserveAttempt(d) ==
  /\ attempts' = [attempts EXCEPT ![d] = @ + 1]
  /\ lifetimeSpent' = [lifetimeSpent EXCEPT ![d] = @ + EventCharge]
  /\ epochSpent' =
       [epochSpent EXCEPT ![d][currentEpoch[d]] = @ + EventCharge]

(***************************************************************************
 * Common portion of an atomic successful claim.  The wrappers below add the
 * direct, delegated, or capability authorization state in the same step.
 *************************************************************************)
CommitClaimBase(g, a, n) ==
  LET d == GateDomain(g)
      k == <<a, n>>
      p == CurrentPredecessor(g)
  IN
    /\ CanReserve(d)
    /\ AtCurrentEpoch(g)
    /\ gateClaims[g] = 0
    /\ nonceUses[k] = 0
    /\ SuccessorAuthorized(g)
    /\ ReserveAttempt(d)
    /\ gateClaims' = [gateClaims EXCEPT ![g] = @ + 1]
    /\ nonceUses' = [nonceUses EXCEPT ![k] = @ + 1]
    /\ nonceClaimGate' = [nonceClaimGate EXCEPT ![k] = g]
    /\ claimPredecessor' = [claimPredecessor EXCEPT ![g] = p]
    /\ pending' = [pending EXCEPT ![g] = TRUE]
    /\ finalized' = finalized
    /\ auditStarts' = [auditStarts EXCEPT ![g] = @ + 1]
    /\ gateCharge' = [gateCharge EXCEPT ![g] = EventCharge]
    /\ lastGate' = [lastGate EXCEPT ![GateScope(g)] = g]
    /\ lastWasFailedClaim' = FALSE

CommitDirect(g, a, n) ==
  /\ ~GateNeedsCapability(g)
  /\ CommitClaimBase(g, a, n)
  /\ delegationUses' = delegationUses
  /\ reauthUses' = reauthUses
  /\ capabilityUses' = capabilityUses
  /\ delegationClaimGate' = delegationClaimGate
  /\ capabilityClaimGate' = capabilityClaimGate
  /\ capabilityRedeemedBy' = capabilityRedeemedBy
  /\ authorizationVersion' = authorizationVersion + 2
  /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                 closed, visibleEvents, paddingEvents,
                 failureAuthorizationVersion, delegatedRollbackWitness,
                 rejectedReauthorizationWitness>>

CommitDelegated(g, a, n, gr) ==
  /\ ~GateNeedsCapability(g)
  /\ DelegationAgent(gr) = a
  /\ DelegationGate(gr) = g
  /\ delegationUses[gr] = 0
  /\ CommitClaimBase(g, a, n)
  /\ delegationUses' = [delegationUses EXCEPT ![gr] = @ + 1]
  /\ delegationClaimGate' = [delegationClaimGate EXCEPT ![gr] = g]
  /\ reauthUses' = reauthUses
  /\ capabilityUses' = capabilityUses
  /\ capabilityClaimGate' = capabilityClaimGate
  /\ capabilityRedeemedBy' = capabilityRedeemedBy
  /\ authorizationVersion' = authorizationVersion + 3
  /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                 closed, visibleEvents, paddingEvents,
                 failureAuthorizationVersion, delegatedRollbackWitness,
                 rejectedReauthorizationWitness>>

CommitEffect(g, a, n, c, r) ==
  /\ GateNeedsCapability(g)
  /\ CapabilityGate(c) = g
  /\ CapabilityRedeemer(c) = r
  /\ capabilityUses[c] = 0
  /\ CommitClaimBase(g, a, n)
  /\ capabilityUses' = [capabilityUses EXCEPT ![c] = @ + 1]
  /\ capabilityClaimGate' = [capabilityClaimGate EXCEPT ![c] = g]
  /\ capabilityRedeemedBy' = [capabilityRedeemedBy EXCEPT ![c] = r]
  /\ delegationUses' = delegationUses
  /\ reauthUses' = reauthUses
  /\ delegationClaimGate' = delegationClaimGate
  /\ authorizationVersion' = authorizationVersion + 3
  /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                 closed, visibleEvents, paddingEvents,
                 failureAuthorizationVersion, delegatedRollbackWitness,
                 rejectedReauthorizationWitness>>

(***************************************************************************
 * Failed authorization/claim paths are still complete transcript attempts:
 * they reserve and immediately finalize one fixed-charge slot.  They leave
 * every one-use authorization counter unchanged.  failureAuthorizationVersion
 * is a transition-local ghost witness for that rollback behavior.
 *************************************************************************)
RejectScopedDirect(g, a, n) ==
  LET d == GateDomain(g)
      k == <<a, n>>
  IN
    /\ CanReserve(d)
    /\ AtCurrentEpoch(g)
    /\ gateClaims[g] = 0
    /\ nonceUses[k] = 0
    /\ ~GateNeedsCapability(g)
    /\ ~SuccessorAuthorized(g)
    /\ ReserveAttempt(d)
    /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
    /\ lastWasFailedClaim' = TRUE
    /\ failureAuthorizationVersion' = authorizationVersion
    /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                   closed, gateClaims, nonceUses, delegationUses, reauthUses,
                   capabilityUses, nonceClaimGate, delegationClaimGate,
                   capabilityClaimGate, capabilityRedeemedBy,
                   claimPredecessor, pending, finalized, auditStarts,
                   gateCharge, lastGate, paddingEvents, authorizationVersion,
                   delegatedRollbackWitness, rejectedReauthorizationWitness>>

RejectScopedDelegated(g, a, n, gr) ==
  LET d == GateDomain(g)
      k == <<a, n>>
  IN
    /\ CanReserve(d)
    /\ AtCurrentEpoch(g)
    /\ gateClaims[g] = 0
    /\ nonceUses[k] = 0
    /\ delegationUses[gr] = 0
    /\ DelegationAgent(gr) = a
    /\ DelegationGate(gr) = g
    /\ ~GateNeedsCapability(g)
    /\ ~SuccessorAuthorized(g)
    /\ ReserveAttempt(d)
    /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
    /\ lastWasFailedClaim' = TRUE
    /\ failureAuthorizationVersion' = authorizationVersion
    /\ delegatedRollbackWitness' = TRUE
    /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                   closed, gateClaims, nonceUses, delegationUses, reauthUses,
                   capabilityUses, nonceClaimGate, delegationClaimGate,
                   capabilityClaimGate, capabilityRedeemedBy,
                   claimPredecessor, pending, finalized, auditStarts,
                   gateCharge, lastGate, paddingEvents, authorizationVersion,
                   rejectedReauthorizationWitness>>

RejectCapabilityBinding(g, a, n, c, r) ==
  LET d == GateDomain(g)
      k == <<a, n>>
  IN
    /\ CanReserve(d)
    /\ AtCurrentEpoch(g)
    /\ gateClaims[g] = 0
    /\ nonceUses[k] = 0
    /\ GateNeedsCapability(g)
    /\ SuccessorAuthorized(g)
    /\ capabilityUses[c] = 0
    /\ \/ CapabilityGate(c) # g
       \/ CapabilityRedeemer(c) # r
    /\ ReserveAttempt(d)
    /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
    /\ lastWasFailedClaim' = TRUE
    /\ failureAuthorizationVersion' = authorizationVersion
    /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                   closed, gateClaims, nonceUses, delegationUses, reauthUses,
                   capabilityUses, nonceClaimGate, delegationClaimGate,
                   capabilityClaimGate, capabilityRedeemedBy,
                   claimPredecessor, pending, finalized, auditStarts,
                   gateCharge, lastGate, paddingEvents, authorizationVersion,
                   delegatedRollbackWitness, rejectedReauthorizationWitness>>

RejectStaleEpoch(g, a, n) ==
  LET d == GateDomain(g)
      k == <<a, n>>
  IN
    /\ CanReserve(d)
    /\ gateClaims[g] = 0
    /\ nonceUses[k] = 0
    /\ GateEpoch(g) # currentEpoch[d]
    /\ ReserveAttempt(d)
    /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
    /\ lastWasFailedClaim' = TRUE
    /\ failureAuthorizationVersion' = authorizationVersion
    /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                   closed, gateClaims, nonceUses, delegationUses, reauthUses,
                   capabilityUses, nonceClaimGate, delegationClaimGate,
                   capabilityClaimGate, capabilityRedeemedBy,
                   claimPredecessor, pending, finalized, auditStarts,
                   gateCharge, lastGate, paddingEvents, authorizationVersion,
                   delegatedRollbackWitness, rejectedReauthorizationWitness>>

(***************************************************************************
 * Completion/recovery publishes exactly one typed event for a committed
 * RESERVED claim.  Authorization remains consumed on every backend outcome.
 *************************************************************************)
Finalize(g) ==
  LET d == GateDomain(g)
  IN
    /\ pending[g]
    /\ pending' = [pending EXCEPT ![g] = FALSE]
    /\ finalized' = [finalized EXCEPT ![g] = TRUE]
    /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
    /\ lastWasFailedClaim' = FALSE
    /\ UNCHANGED <<lifetimeSpent, lifetimeBudget, epochSpent,
                   attempts, horizon, currentEpoch, epochAdvanceCount, closed,
                   gateClaims, nonceUses, delegationUses, reauthUses,
                   capabilityUses, nonceClaimGate, delegationClaimGate,
                   capabilityClaimGate, capabilityRedeemedBy,
                   claimPredecessor, auditStarts, gateCharge, lastGate,
                   paddingEvents, authorizationVersion,
                   failureAuthorizationVersion, delegatedRollbackWitness,
                   rejectedReauthorizationWitness>>

Continue(d) ==
  /\ CanReserve(d)
  /\ ReserveAttempt(d)
  /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
  /\ lastWasFailedClaim' = FALSE
  /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                 closed, gateClaims, nonceUses, delegationUses, reauthUses,
                 capabilityUses, nonceClaimGate, delegationClaimGate,
                 capabilityClaimGate, capabilityRedeemedBy,
                 claimPredecessor, pending, finalized, auditStarts,
                 gateCharge, lastGate, paddingEvents, authorizationVersion,
                 failureAuthorizationVersion, delegatedRollbackWitness,
                 rejectedReauthorizationWitness>>

Reauthorize(d, rg) ==
  /\ ReauthDomain(rg) = d
  /\ reauthUses[rg] = 0
  /\ currentEpoch[d] < MaxEpoch
  /\ CanReserve(d)
  /\ ReserveAttempt(d)
  /\ lifetimeBudget' =
       [lifetimeBudget EXCEPT ![d] = @ + ReauthBudgetIncrement]
  /\ horizon' = [horizon EXCEPT ![d] = @ + ReauthAttemptIncrement]
  /\ currentEpoch' = [currentEpoch EXCEPT ![d] = @ + 1]
  /\ epochAdvanceCount' = [epochAdvanceCount EXCEPT ![d] = @ + 1]
  /\ reauthUses' = [reauthUses EXCEPT ![rg] = @ + 1]
  /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
  /\ authorizationVersion' = authorizationVersion + 1
  /\ lastWasFailedClaim' = FALSE
  /\ UNCHANGED <<closed, gateClaims, nonceUses, delegationUses,
                 capabilityUses, nonceClaimGate, delegationClaimGate,
                 capabilityClaimGate, capabilityRedeemedBy,
                 claimPredecessor, pending, finalized, auditStarts,
                 gateCharge, lastGate, paddingEvents,
                 failureAuthorizationVersion, delegatedRollbackWitness,
                 rejectedReauthorizationWitness>>

RejectReauthorization(d, rg) ==
  /\ ReauthDomain(rg) = d
  /\ reauthUses[rg] = 1
  /\ CanReserve(d)
  /\ ReserveAttempt(d)
  /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + 1]
  /\ lastWasFailedClaim' = FALSE
  /\ rejectedReauthorizationWitness' = TRUE
  /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                 closed, gateClaims, nonceUses, delegationUses, reauthUses,
                 capabilityUses, nonceClaimGate, delegationClaimGate,
                 capabilityClaimGate, capabilityRedeemedBy,
                 claimPredecessor, pending, finalized, auditStarts,
                 gateCharge, lastGate, paddingEvents, authorizationVersion,
                 failureAuthorizationVersion, delegatedRollbackWitness>>

NoPendingForDomain(d) ==
  \A g \in Gates : GateDomain(g) = d => ~pending[g]

StopAndPad(d) ==
  LET remaining == horizon[d] - attempts[d]
  IN
    /\ CanReserve(d)
    /\ NoPendingForDomain(d)
    /\ remaining > 0
    /\ lifetimeSpent[d] + (remaining * EventCharge) <= lifetimeBudget[d]
    /\ attempts' = [attempts EXCEPT ![d] = horizon[d]]
    /\ lifetimeSpent' =
         [lifetimeSpent EXCEPT ![d] = @ + (remaining * EventCharge)]
    /\ epochSpent' =
         [epochSpent EXCEPT
            ![d][currentEpoch[d]] = @ + (remaining * EventCharge)]
    /\ visibleEvents' = [visibleEvents EXCEPT ![d] = @ + remaining]
    /\ paddingEvents' = [paddingEvents EXCEPT ![d] = @ + (remaining - 1)]
    /\ closed' = [closed EXCEPT ![d] = TRUE]
    /\ lastWasFailedClaim' = FALSE
    /\ UNCHANGED <<lifetimeBudget, horizon, currentEpoch, epochAdvanceCount,
                   gateClaims, nonceUses, delegationUses, reauthUses,
                   capabilityUses, nonceClaimGate, delegationClaimGate,
                   capabilityClaimGate, capabilityRedeemedBy,
                   claimPredecessor, pending, finalized, auditStarts,
                   gateCharge, lastGate, authorizationVersion,
                   failureAuthorizationVersion, delegatedRollbackWitness,
                   rejectedReauthorizationWitness>>

CloseAtHorizon(d) ==
  /\ ~closed[d]
  /\ attempts[d] = horizon[d]
  /\ NoPendingForDomain(d)
  /\ closed' = [closed EXCEPT ![d] = TRUE]
  /\ lastWasFailedClaim' = FALSE
  /\ UNCHANGED <<lifetimeSpent, lifetimeBudget, epochSpent,
                 attempts, horizon, currentEpoch, epochAdvanceCount,
                 gateClaims, nonceUses, delegationUses, reauthUses,
                 capabilityUses, nonceClaimGate, delegationClaimGate,
                 capabilityClaimGate, capabilityRedeemedBy,
                 claimPredecessor, pending, finalized, auditStarts,
                 gateCharge, lastGate, visibleEvents, paddingEvents,
                 authorizationVersion, failureAuthorizationVersion,
                 delegatedRollbackWitness, rejectedReauthorizationWitness>>

Next ==
  \/ \E g \in Gates, a \in Agents, n \in Nonces : CommitDirect(g, a, n)
  \/ \E g \in Gates, a \in Agents, n \in Nonces, gr \in Delegations :
       CommitDelegated(g, a, n, gr)
  \/ \E g \in Gates, a \in Agents, n \in Nonces,
        c \in Capabilities, r \in Redeemers : CommitEffect(g, a, n, c, r)
  \/ \E g \in Gates, a \in Agents, n \in Nonces : RejectScopedDirect(g, a, n)
  \/ \E g \in Gates, a \in Agents, n \in Nonces, gr \in Delegations :
       RejectScopedDelegated(g, a, n, gr)
  \/ \E g \in Gates, a \in Agents, n \in Nonces,
        c \in Capabilities, r \in Redeemers : RejectCapabilityBinding(g, a, n, c, r)
  \/ \E g \in Gates, a \in Agents, n \in Nonces : RejectStaleEpoch(g, a, n)
  \/ \E g \in Gates : Finalize(g)
  \/ \E d \in Domains : Continue(d)
  \/ \E d \in Domains, rg \in ReauthGrants : Reauthorize(d, rg)
  \/ \E d \in Domains, rg \in ReauthGrants : RejectReauthorization(d, rg)
  \/ \E d \in Domains : StopAndPad(d)
  \/ \E d \in Domains : CloseAtHorizon(d)

Spec == Init /\ [][Next]_vars

\* The two-domain product is bounded only for exhaustive TLC enumeration.
\* A bound of three total reserved slots is enough to reach every transition
\* family, the predecessor-plus-successor race, reauthorization-plus-epoch-1
\* claims, STOP plus deterministic padding, and cross-domain rejection.  It
\* is an explicit model-checking scope, not an implementation limit.
ModelStateConstraint ==
  attempts[DomainOne] + attempts[DomainTwo] <= 3

(***************************************************************************
 * Required acceptance-revision invariants.
 *************************************************************************)
NoBudgetOverspend ==
  \A d \in Domains : lifetimeSpent[d] <= lifetimeBudget[d]

NoDoubleGateClaim == \A g \in Gates : gateClaims[g] <= 1

NoDoubleNonceConsumption ==
  \A k \in CredentialKeys : nonceUses[k] <= 1

NoDoubleDelegationRedemption ==
  \A gr \in Delegations : delegationUses[gr] <= 1

AuthorizationConsumedOnlyWithSuccessfulClaim ==
  /\ \A k \in CredentialKeys :
       /\ (nonceUses[k] = 0) = (nonceClaimGate[k] = NoGate)
       /\ nonceUses[k] = 1 =>
            /\ nonceClaimGate[k] \in Gates
            /\ gateClaims[nonceClaimGate[k]] = 1
  /\ \A gr \in Delegations :
       /\ (delegationUses[gr] = 0) = (delegationClaimGate[gr] = NoGate)
       /\ delegationUses[gr] = 1 =>
            /\ delegationClaimGate[gr] \in Gates
            /\ gateClaims[delegationClaimGate[gr]] = 1
  /\ \A g \in Gates : gateClaims[g] = 1 =>
       Cardinality({k \in CredentialKeys : nonceClaimGate[k] = g}) = 1

NoCrossDomainSuccessorAuthorization ==
  \A g \in Gates :
    gateClaims[g] = 1 /\ claimPredecessor[g] # NoGate =>
      /\ claimPredecessor[g] \in Gates
      /\ g \in SuccessorsOf(claimPredecessor[g])
      /\ ScopeCompatible(claimPredecessor[g], g)

SuccessorMutualExclusion ==
  gateClaims[RaceSuccessorA] + gateClaims[RaceSuccessorB] <= 1

AttemptHorizonRespected ==
  \A d \in Domains : attempts[d] <= horizon[d]

CapabilityRedeemedAtMostOnce ==
  \A c \in Capabilities : capabilityUses[c] <= 1

RedeemerBindingPreserved ==
  \A c \in Capabilities :
    /\ (capabilityUses[c] = 0) =
         /\ capabilityClaimGate[c] = NoGate
         /\ capabilityRedeemedBy[c] = NoRedeemer
    /\ capabilityUses[c] = 1 =>
         /\ capabilityClaimGate[c] = CapabilityGate(c)
         /\ gateClaims[capabilityClaimGate[c]] = 1
         /\ capabilityRedeemedBy[c] = CapabilityRedeemer(c)

EpochMonotonicity ==
  \A d \in Domains :
    /\ epochAdvanceCount[d] = currentEpoch[d]
    /\ currentEpoch[d] <= MaxEpoch

UsedReauthorizations(d) ==
  Cardinality({rg \in ReauthGrants :
                 ReauthDomain(rg) = d /\ reauthUses[rg] = 1})

EpochSpendTotal(d) == epochSpent[d][0] + epochSpent[d][1]

LifetimeBudgetComposition ==
  \A d \in Domains :
    /\ lifetimeSpent[d] = EpochSpendTotal(d)
    /\ lifetimeSpent[d] = attempts[d] * EventCharge
    /\ lifetimeBudget[d] =
         InitialBudget + UsedReauthorizations(d) * ReauthBudgetIncrement
    /\ horizon[d] =
         InitialHorizon + UsedReauthorizations(d) * ReauthAttemptIncrement

AuditStartExistsForEveryCommittedClaim ==
  \A g \in Gates :
    /\ gateClaims[g] = auditStarts[g]
    /\ gateClaims[g] = 1 => auditStarts[g] = 1

(***************************************************************************
 * Supporting invariants make atomicity, fixed charging, rollback, and
 * recovery explicit rather than relying on type membership alone.
 *************************************************************************)
AtomicClaimChargeAndAudit ==
  \A g \in Gates :
    /\ gateClaims[g] = 0 =>
         /\ gateCharge[g] = 0
         /\ ~pending[g]
         /\ ~finalized[g]
         /\ claimPredecessor[g] = NoGate
    /\ gateClaims[g] = 1 =>
         /\ gateCharge[g] = EventCharge
         /\ pending[g] \/ finalized[g]
         /\ ~(pending[g] /\ finalized[g])
         /\ auditStarts[g] = 1

FailedClaimRollsBackAuthorization ==
  lastWasFailedClaim => authorizationVersion = failureAuthorizationVersion

AuthorizationVersionConsistent ==
  authorizationVersion =
      Cardinality({g \in Gates : gateClaims[g] = 1})
    + Cardinality({k \in CredentialKeys : nonceUses[k] = 1})
    + Cardinality({gr \in Delegations : delegationUses[gr] = 1})
    + Cardinality({rg \in ReauthGrants : reauthUses[rg] = 1})
    + Cardinality({c \in Capabilities : capabilityUses[c] = 1})

EveryAttemptHasFixedCharge ==
  \A d \in Domains :
    attempts[d] =
      visibleEvents[d]
      + Cardinality({g \in Gates : GateDomain(g) = d /\ pending[g]})

NoReauthorizationReplay ==
  \A rg \in ReauthGrants : reauthUses[rg] <= 1

SharedDomainAccounting ==
  /\ GateDomain(SharedObjectGate) = GateDomain(RacePredecessor)
  /\ GateObject(SharedObjectGate) # GateObject(RacePredecessor)
  /\ gateClaims[SharedObjectGate] = 1 =>
       gateCharge[SharedObjectGate] <= lifetimeSpent[DomainOne]

ClosedDomainsAreFullyAccounted ==
  \A d \in Domains : closed[d] =>
    /\ attempts[d] = horizon[d]
    /\ visibleEvents[d] = attempts[d]
    /\ NoPendingForDomain(d)

\* Temporal monotonicity checks complement the state invariants above.  They
\* catch any future action that clears a consumed token or decreases an epoch
\* while preserving a same-state ghost equality.
EpochNeverDecreases ==
  [][\A d \in Domains : currentEpoch'[d] >= currentEpoch[d]]_vars

BudgetsAndHorizonsNeverDecrease ==
  [][\A d \in Domains :
       /\ lifetimeBudget'[d] >= lifetimeBudget[d]
       /\ horizon'[d] >= horizon[d]]_vars

ConsumedAuthorizationsNeverClear ==
  [][ /\ \A g \in Gates : gateClaims'[g] >= gateClaims[g]
     /\ \A k \in CredentialKeys : nonceUses'[k] >= nonceUses[k]
     /\ \A gr \in Delegations : delegationUses'[gr] >= delegationUses[gr]
     /\ \A rg \in ReauthGrants : reauthUses'[rg] >= reauthUses[rg]
     /\ \A c \in Capabilities : capabilityUses'[c] >= capabilityUses[c] ]_vars

=============================================================================
