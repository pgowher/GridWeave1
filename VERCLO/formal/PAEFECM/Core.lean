/-!
# PAE-FECM observer-relative core

This file formalises the central definitions from PAE-FM-2.2.  It deliberately
contains no physical-truth field: closure is a function of an observer view.
-/

namespace PAEFECM

inductive Visibility where
  | declared
  | discoverable
  | hidden
  deriving DecidableEq, Repr

inductive Disposition where
  | erased
  | cryptoErased
  | approvedTransform
  | failed
  | refused
  | unreachable
  deriving DecidableEq, Repr

inductive Grade where
  | e0
  | e1
  | e2
  | e3
  | e4
  | e5
  deriving DecidableEq, Repr

def Grade.rank : Grade → Nat
  | .e0 => 0
  | .e1 => 1
  | .e2 => 2
  | .e3 => 3
  | .e4 => 4
  | .e5 => 5

structure Edge (Asset Time : Type) where
  source : Asset
  target : Asset
  visibility : Visibility
  authenticated : Bool
  disclosedAt : Option Time

/-- Equation (11), stated over any totally ordered time domain. -/
def VisibleAt {Asset Time : Type} [LE Time]
    (edge : Edge Asset Time) (evalTime : Time) : Prop :=
  edge.visibility = .declared ∨
    (edge.visibility = .discoverable ∧ edge.authenticated = true ∧
      ∃ disclosed, edge.disclosedAt = some disclosed ∧ disclosed ≤ evalTime)

/-- The authenticated, observer-visible edge relation at an evaluation time. -/
def VisibleRelation {Asset Time : Type} [LE Time]
    (edges : List (Edge Asset Time)) (evalTime : Time) (source target : Asset) : Prop :=
  ∃ edge, edge ∈ edges ∧ edge.source = source ∧ edge.target = target ∧
    edge.authenticated = true ∧ VisibleAt edge evalTime

/-- Equations (12)--(13) as the least relation closed under visible edges. -/
inductive Reachable {Asset : Type} (root : Asset → Prop)
    (edge : Asset → Asset → Prop) : Asset → Prop where
  | root {asset} : root asset → Reachable root edge asset
  | step {source target} :
      Reachable root edge source → edge source target → Reachable root edge target

structure Obligation where
  obligationId : String
  custodianId : String
  deadline : Nat
  minimumGrade : Grade
  permitted : List Disposition
  deriving Repr

structure Evidence where
  obligationId : String
  issuerId : String
  disposition : Disposition
  eventTime : Nat
  grade : Grade
  authenticated : Bool
  bindingValid : Bool
  integrityValid : Bool
  orderingValid : Bool
  chainAuthenticated : Bool
  sequenceContiguous : Bool
  predecessorsAvailable : Bool
  deriving Repr

/-- Equations (21)--(22), after backend checks have returned their Booleans. -/
def Admissible (evidence : Evidence) (obligation : Obligation)
    (evalTime : Nat) : Prop :=
  evidence.obligationId = obligation.obligationId ∧
  evidence.issuerId = obligation.custodianId ∧
  evidence.eventTime ≤ evalTime ∧
  evidence.authenticated = true ∧
  evidence.bindingValid = true ∧
  evidence.integrityValid = true ∧
  evidence.orderingValid = true ∧
  obligation.minimumGrade.rank ≤ evidence.grade.rank ∧
  evidence.chainAuthenticated = true ∧
  evidence.sequenceContiguous = true ∧
  evidence.predecessorsAvailable = true

/-- Equations (24)--(25): admissible, policy-permitted, timely success. -/
def TimelySuccess (evidence : Evidence) (obligation : Obligation)
    (evalTime : Nat) : Prop :=
  Admissible evidence obligation evalTime ∧
  evidence.disposition ∈ obligation.permitted ∧
  evidence.eventTime ≤ obligation.deadline

structure ExceptionClaim where
  coveredObligations : List String
  authorityAdmitted : Bool
  authenticated : Bool
  basisPresent : Bool
  effectiveAt : Nat
  expiresAt : Nat
  deriving Repr

/-- Equation (26), with authority lookup and basis validation already decided. -/
def ValidException (claim : ExceptionClaim) (obligation : Obligation)
    (evalTime : Nat) : Prop :=
  obligation.obligationId ∈ claim.coveredObligations ∧
  claim.authorityAdmitted = true ∧
  claim.authenticated = true ∧
  claim.basisPresent = true ∧
  claim.effectiveAt ≤ obligation.deadline ∧
  claim.effectiveAt ≤ evalTime ∧
  evalTime < claim.expiresAt

structure ObligationStatus where
  successful : Bool
  excepted : Bool
  deriving DecidableEq, Repr

def resolved (status : ObligationStatus) : Bool :=
  status.successful || status.excepted

def allSuccessful (statuses : List ObligationStatus) : Bool :=
  statuses.all (fun status => status.successful)

def allResolved (statuses : List ObligationStatus) : Bool :=
  statuses.all resolved

def anyException (statuses : List ObligationStatus) : Bool :=
  statuses.any (fun status => status.excepted)

def anyResolved (statuses : List ObligationStatus) : Bool :=
  statuses.any resolved

inductive Outcome where
  | inProgress
  | closed
  | closedWithExceptions
  | partiallyClosed
  | open
  | disputed
  | unverifiable
  deriving DecidableEq, Repr

structure DecisionInput where
  ready : Bool
  baselineVerifiable : Bool
  conflictOrChallenge : Bool
  statuses : List ObligationStatus
  deriving DecidableEq, Repr

/-- Equation (32), including the pre-decision `IN_PROGRESS` guard. -/
def decide (input : DecisionInput) : Outcome :=
  if !input.ready then .inProgress
  else if !input.baselineVerifiable then .unverifiable
  else if input.conflictOrChallenge then .disputed
  else if allSuccessful input.statuses then .closed
  else if allResolved input.statuses && anyException input.statuses then
    .closedWithExceptions
  else if anyResolved input.statuses then .partiallyClosed
  else .open

/-- Evaluator-only state is carried by a world but is absent from `decide`. -/
structure World where
  observer : DecisionInput
  hiddenReplicaCount : Nat
  physicalTruthTag : Nat
  deriving DecidableEq, Repr

def evaluateWorld (world : World) : Outcome :=
  decide world.observer

end PAEFECM
