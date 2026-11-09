import PAEFECM.Core

/-!
# PAE-FECM safety theorems

The theorems are unbounded: they quantify over arbitrary status lists, asset
types, roots, edge relations, and hidden-world values.
-/

namespace PAEFECM

theorem not_ready_is_in_progress (input : DecisionInput)
    (h : input.ready = false) : decide input = .inProgress := by
  simp [decide, h]

theorem invalid_baseline_is_unverifiable (input : DecisionInput)
    (hready : input.ready = true)
    (hbaseline : input.baselineVerifiable = false) :
    decide input = .unverifiable := by
  simp [decide, hready, hbaseline]

theorem conflict_is_disputed (input : DecisionInput)
    (hready : input.ready = true)
    (hbaseline : input.baselineVerifiable = true)
    (hconflict : input.conflictOrChallenge = true) :
    decide input = .disputed := by
  simp [decide, hready, hbaseline, hconflict]

theorem closed_implies_ready (input : DecisionInput)
    (h : decide input = .closed) : input.ready = true := by
  cases hready : input.ready <;> simp [decide, hready] at h ⊢

theorem closed_implies_baseline (input : DecisionInput)
    (h : decide input = .closed) : input.baselineVerifiable = true := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    simp [decide, hready, hbaseline] at h ⊢

theorem closed_implies_contradiction_free (input : DecisionInput)
    (h : decide input = .closed) : input.conflictOrChallenge = false := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    cases hconflict : input.conflictOrChallenge <;>
    simp [decide, hready, hbaseline, hconflict] at h ⊢

theorem closed_implies_all_successful (input : DecisionInput)
    (h : decide input = .closed) : allSuccessful input.statuses = true := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    cases hconflict : input.conflictOrChallenge <;>
    cases hsuccess : allSuccessful input.statuses <;>
    cases hresolved : allResolved input.statuses <;>
    cases hexception : anyException input.statuses <;>
    cases hany : anyResolved input.statuses <;>
    simp [decide, hready, hbaseline, hconflict, hsuccess, hresolved,
      hexception, hany] at h ⊢

theorem exception_closure_implies_full_resolution (input : DecisionInput)
    (h : decide input = .closedWithExceptions) :
    allResolved input.statuses = true ∧ anyException input.statuses = true := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    cases hconflict : input.conflictOrChallenge <;>
    cases hsuccess : allSuccessful input.statuses <;>
    cases hresolved : allResolved input.statuses <;>
    cases hexception : anyException input.statuses <;>
    cases hany : anyResolved input.statuses <;>
    simp [decide, hready, hbaseline, hconflict, hsuccess, hresolved,
      hexception, hany] at h ⊢

theorem exception_closure_not_all_successful (input : DecisionInput)
    (h : decide input = .closedWithExceptions) :
    allSuccessful input.statuses = false := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    cases hconflict : input.conflictOrChallenge <;>
    cases hsuccess : allSuccessful input.statuses <;>
    cases hresolved : allResolved input.statuses <;>
    cases hexception : anyException input.statuses <;>
    cases hany : anyResolved input.statuses <;>
    simp [decide, hready, hbaseline, hconflict, hsuccess, hresolved,
      hexception, hany] at h ⊢

theorem partial_closure_implies_some_resolution (input : DecisionInput)
    (h : decide input = .partiallyClosed) : anyResolved input.statuses = true := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    cases hconflict : input.conflictOrChallenge <;>
    cases hsuccess : allSuccessful input.statuses <;>
    cases hresolved : allResolved input.statuses <;>
    cases hexception : anyException input.statuses <;>
    cases hany : anyResolved input.statuses <;>
    simp [decide, hready, hbaseline, hconflict, hsuccess, hresolved,
      hexception, hany] at h ⊢

theorem resolved_without_exceptions_is_successful
    (statuses : List ObligationStatus)
    (hresolved : allResolved statuses = true)
    (hexception : anyException statuses = false) :
    allSuccessful statuses = true := by
  simp [allResolved, anyException, allSuccessful, resolved] at hresolved hexception ⊢
  intro status hmember
  have hr := hresolved status hmember
  have he := hexception status hmember
  cases hsuccess : status.successful <;>
    cases hexcepted : status.excepted <;>
    simp [hsuccess, hexcepted] at hr he ⊢

theorem partial_closure_implies_unresolved_obligation (input : DecisionInput)
    (h : decide input = .partiallyClosed) :
    allResolved input.statuses = false := by
  cases hresolved : allResolved input.statuses
  · rfl
  · have hnoexception : anyException input.statuses = false := by
      cases hready : input.ready <;>
        cases hbaseline : input.baselineVerifiable <;>
        cases hconflict : input.conflictOrChallenge <;>
        cases hsuccess : allSuccessful input.statuses <;>
        cases hexception : anyException input.statuses <;>
        simp [decide, hready, hbaseline, hconflict, hsuccess, hresolved,
          hexception] at h ⊢
    have hsuccess := resolved_without_exceptions_is_successful
      input.statuses hresolved hnoexception
    cases hready : input.ready <;>
      cases hbaseline : input.baselineVerifiable <;>
      cases hconflict : input.conflictOrChallenge <;>
      simp [decide, hready, hbaseline, hconflict, hsuccess] at h

theorem open_implies_no_resolution (input : DecisionInput)
    (h : decide input = .open) : anyResolved input.statuses = false := by
  cases hready : input.ready <;>
    cases hbaseline : input.baselineVerifiable <;>
    cases hconflict : input.conflictOrChallenge <;>
    cases hsuccess : allSuccessful input.statuses <;>
    cases hresolved : allResolved input.statuses <;>
    cases hexception : anyException input.statuses <;>
    cases hany : anyResolved input.statuses <;>
    simp [decide, hready, hbaseline, hconflict, hsuccess, hresolved,
      hexception, hany] at h ⊢

theorem reachability_monotone {Asset : Type}
    {root : Asset → Prop} {smaller larger : Asset → Asset → Prop}
    (hsub : ∀ source target, smaller source target → larger source target)
    {asset : Asset} (hreach : Reachable root smaller asset) :
    Reachable root larger asset := by
  induction hreach with
  | root hroot => exact .root hroot
  | step hsource hedge ih => exact .step ih (hsub _ _ hedge)

theorem hidden_state_noninterference (left right : World)
    (hobserver : left.observer = right.observer) :
    evaluateWorld left = evaluateWorld right := by
  simp [evaluateWorld, hobserver]

theorem hidden_values_irrelevant (observer : DecisionInput)
    (hiddenLeft hiddenRight physicalLeft physicalRight : Nat) :
    evaluateWorld ⟨observer, hiddenLeft, physicalLeft⟩ =
      evaluateWorld ⟨observer, hiddenRight, physicalRight⟩ := by
  rfl

theorem decision_deterministic (input : DecisionInput) :
    decide input = decide input := by
  rfl

theorem decision_outcome_exhaustive (input : DecisionInput) :
    decide input = .inProgress ∨
    decide input = .closed ∨
    decide input = .closedWithExceptions ∨
    decide input = .partiallyClosed ∨
    decide input = .open ∨
    decide input = .disputed ∨
    decide input = .unverifiable := by
  cases houtcome : decide input <;> simp

theorem decision_outcome_exclusive (input : DecisionInput) (left right : Outcome)
    (hleft : decide input = left) (hright : decide input = right) :
    left = right := by
  exact hleft.symm.trans hright

end PAEFECM
