from __future__ import annotations

import unittest
from dataclasses import replace

from pae_fecm import (
    Asset,
    Baseline,
    Challenge,
    Disposition,
    Evidence,
    ExceptionClaim,
    Grade,
    Lineage,
    ObserverView,
    Outcome,
    Policy,
    Replica,
    Visibility,
    dependency_closure,
    evaluate,
)
from worked_cases import conformance_report


class PAEFECMTests(unittest.TestCase):
    def setUp(self) -> None:
        policy = Policy(
            applicable_asset_kinds=frozenset({"SOURCE", "DERIVATIVE"}),
            applicable_replica_classes=frozenset({"PRIMARY", "DERIVED_INSTANCE"}),
            allowed_dispositions=frozenset(
                {Disposition.ERASED, Disposition.CRYPTO_ERASED}
            ),
            minimum_grade=Grade.E3,
            exception_authorities=frozenset({"authority"}),
        )
        self.view = ObserverView(
            evaluation_time=20,
            case_deadline=15,
            root_asset_ids=frozenset({"a0"}),
            policy=policy,
            baseline=Baseline(),
            assets=(Asset("a0", "SOURCE"), Asset("a1", "DERIVATIVE")),
            lineage=(Lineage("a0", "a1"),),
            replicas=(
                Replica("i0", "a0", "r0", "c0", "PRIMARY"),
                Replica("i1", "a1", "r1", "c1", "DERIVED_INSTANCE"),
            ),
        )

    @staticmethod
    def receipt(
        evidence_id: str, obligation: str, issuer: str, disposition=Disposition.ERASED
    ):
        return Evidence(
            evidence_id=evidence_id,
            obligation_id=obligation,
            issuer_id=issuer,
            disposition=disposition,
            event_time=10,
            grade=Grade.E3,
        )

    def test_all_six_terminal_outcomes_and_in_progress(self) -> None:
        receipts = (
            self.receipt("e0", "OBL::a0::i0", "c0"),
            self.receipt("e1", "OBL::a1::i1", "c1"),
        )
        self.assertIs(
            evaluate(replace(self.view, evidence=receipts)).outcome, Outcome.CLOSED
        )

        exception = ExceptionClaim(
            "x1", frozenset({"OBL::a1::i1"}), "authority", "sha256:b", 12, 30
        )
        cwe = replace(self.view, evidence=receipts[:1], exceptions=(exception,))
        self.assertIs(evaluate(cwe).outcome, Outcome.CLOSED_WITH_EXCEPTIONS)
        self.assertIs(
            evaluate(replace(self.view, evidence=receipts[:1])).outcome,
            Outcome.PARTIALLY_CLOSED,
        )
        self.assertIs(evaluate(self.view).outcome, Outcome.OPEN)

        conflict = self.receipt(
            "e2", "OBL::a0::i0", "c0", disposition=Disposition.FAILED
        )
        disputed = replace(self.view, evidence=receipts + (conflict,))
        self.assertIs(evaluate(disputed).outcome, Outcome.DISPUTED)
        unverifiable = replace(
            self.view,
            baseline=replace(self.view.baseline, obligation_commitment_valid=False),
        )
        self.assertIs(evaluate(unverifiable).outcome, Outcome.UNVERIFIABLE)
        in_progress = replace(self.view, evaluation_time=12, evidence=receipts[:1])
        self.assertIs(evaluate(in_progress).outcome, Outcome.IN_PROGRESS)

    def test_unverifiable_and_disputed_precedence(self) -> None:
        challenged = replace(
            self.view,
            baseline=replace(self.view.baseline, scope_commitment_valid=False),
            challenges=(Challenge("q", True, False),),
        )
        self.assertIs(evaluate(challenged).outcome, Outcome.UNVERIFIABLE)

    def test_hidden_lineage_is_not_in_the_observer_closure(self) -> None:
        hidden = replace(
            self.view,
            lineage=(Lineage("a0", "a1", Visibility.HIDDEN, False),),
            replicas=(
                self.view.replicas[0],
                replace(
                    self.view.replicas[1],
                    visibility=Visibility.HIDDEN,
                    authenticated=False,
                ),
            ),
            evidence=(self.receipt("e0", "OBL::a0::i0", "c0"),),
        )
        result = evaluate(hidden)
        self.assertEqual(result.discovered_assets, frozenset({"a0"}))
        self.assertIs(result.outcome, Outcome.CLOSED)
        no_hidden_world = replace(
            hidden,
            assets=(hidden.assets[0],),
            lineage=(),
            replicas=(hidden.replicas[0],),
        )
        self.assertEqual(result, evaluate(no_hidden_world))

    def test_authenticated_disclosure_monotonically_expands_scope(self) -> None:
        before = dependency_closure(
            {"a0"},
            (Lineage("a0", "a1", Visibility.DISCOVERABLE, True, 21),),
            at=20,
        )
        after = dependency_closure(
            {"a0"},
            (Lineage("a0", "a1", Visibility.DISCOVERABLE, True, 21),),
            at=21,
        )
        self.assertLess(before, after)

    def test_late_and_below_grade_evidence_cannot_close(self) -> None:
        late = replace(self.receipt("late", "OBL::a0::i0", "c0"), event_time=16)
        weak = replace(self.receipt("weak", "OBL::a1::i1", "c1"), grade=Grade.E2)
        self.assertIs(
            evaluate(replace(self.view, evidence=(late, weak))).outcome, Outcome.OPEN
        )

    def test_empty_scope_fails_closed_without_authenticated_determination(self) -> None:
        empty = replace(
            self.view,
            policy=replace(self.view.policy, applicable_asset_kinds=frozenset()),
        )
        self.assertIs(evaluate(empty).outcome, Outcome.UNVERIFIABLE)
        admitted = replace(
            empty,
            baseline=replace(empty.baseline, no_applicable_determination_valid=True),
        )
        self.assertIs(evaluate(admitted).outcome, Outcome.CLOSED)

    def test_permutation_invariance(self) -> None:
        receipts = (
            self.receipt("e0", "OBL::a0::i0", "c0"),
            self.receipt("e1", "OBL::a1::i1", "c1"),
        )
        original = replace(self.view, evidence=receipts)
        reversed_view = replace(
            original,
            assets=tuple(reversed(original.assets)),
            lineage=tuple(reversed(original.lineage)),
            replicas=tuple(reversed(original.replicas)),
            evidence=tuple(reversed(original.evidence)),
        )
        self.assertEqual(evaluate(original), evaluate(reversed_view))

    def test_evidence_accumulation_can_expose_a_dispute(self) -> None:
        receipts = (
            self.receipt("e0", "OBL::a0::i0", "c0"),
            self.receipt("e1", "OBL::a1::i1", "c1"),
        )
        closed = replace(self.view, evidence=receipts)
        conflict = self.receipt(
            "e2", "OBL::a0::i0", "c0", disposition=Disposition.FAILED
        )
        self.assertIs(evaluate(closed).outcome, Outcome.CLOSED)
        self.assertIs(
            evaluate(replace(closed, evidence=receipts + (conflict,))).outcome,
            Outcome.DISPUTED,
        )

    def test_normative_worked_cases_match_manual_evaluation(self) -> None:
        report = conformance_report()
        self.assertEqual("PASS", report["status"])
        self.assertEqual(16, report["cases"])


if __name__ == "__main__":
    unittest.main()
