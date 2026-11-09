"""Case-level federated closure evaluation over observer-visible metadata."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from analytics.closure_report import (
    ClosureClass,
    FederatedClosureReport,
    ObligationCategory,
    ObligationEvaluation,
)
from disputes.models import DisputeClosureOutcome, DisputeClosureState
from evidence.models import CustodianReceipt, ExceptionValidation
from proof.evidence_grade_evaluator import BundleStatus, EvidenceGradeEvaluator
from verclo.models import ErasureCase, ExceptionAssertion, Obligation
from verclo.policy import PolicyRegistry


class FederatedClosureEvaluator:
    def __init__(self, grade_evaluator: EvidenceGradeEvaluator, policies: PolicyRegistry, *, receipt_matching: str = "indexed") -> None:
        self.grade_evaluator = grade_evaluator
        self.policies = policies
        if receipt_matching not in {"scan", "indexed"}:
            raise ValueError("receipt_matching must be scan or indexed")
        self.receipt_matching = receipt_matching

    def evaluate(
        self,
        case: ErasureCase,
        receipts: Iterable[CustodianReceipt],
        evaluation_time: datetime,
        *,
        exception_validations: Iterable[ExceptionValidation] = (),
        open_challenge_ids: Iterable[str] = (),
        dispute_state: DisputeClosureState | None = None,
    ) -> FederatedClosureReport:
        if dispute_state is not None and dispute_state.case_id != case.case_id:
            raise ValueError("dispute state is bound to a different case")
        if case.graph is None:
            return self._report(
                case, ClosureClass.UNVERIFIABLE, (), ("OBLIGATION_GRAPH_UNAVAILABLE",),
                "Closure cannot be evaluated because the authenticated obligation graph is unavailable.",
                ("OBLIGATION_GRAPH_UNAVAILABLE",),
            )

        graph = case.graph
        visibility_reasons = tuple(sorted(graph.baseline_reason_codes))
        visibility_limitation = "CLOSURE_RELATIVE_TO_AUTHENTICATED_OBSERVABLE_SCOPE"
        if not graph.baseline_verifiable:
            reasons = tuple(sorted(set(visibility_reasons) | {"BASELINE_NOT_VERIFIABLE"}))
            return self._report(
                case, ClosureClass.UNVERIFIABLE, (), reasons,
                "Closure is unverifiable because the authenticated observable baseline is incomplete or invalid.",
                visibility_reasons, visibility_limitation,
            )

        if dispute_state is not None and dispute_state.terminal_outcome == DisputeClosureOutcome.UNVERIFIABLE:
            reasons = tuple(sorted(set(dispute_state.reason_codes) | {"DISPUTE_BASELINE_UNVERIFIABLE"}))
            return self._report(
                case, ClosureClass.UNVERIFIABLE, (), reasons,
                "Closure is unverifiable because an upheld or timed-out dispute prevents an authenticated baseline determination.",
                visibility_reasons, visibility_limitation,
            )

        rejected_evidence = set(() if dispute_state is None else dispute_state.rejected_evidence_refs)
        # Hash partitioning is a conventional optimization, retained alongside
        # the old nested-scan baseline for measured comparisons.
        from .receipt_partition import ReceiptPartition
        if isinstance(receipts, ReceiptPartition):
            receipt_rows = ()
            partition = receipts
        else:
            receipt_rows = tuple(row for row in receipts if row.receipt_id not in rejected_evidence)
            partition = ReceiptPartition.from_rows(receipt_rows) if self.receipt_matching == "indexed" else None
        exception_checks = {row.exception_id: row for row in exception_validations}
        exceptions = {row.obligation_id: row for row in graph.exceptions}
        policy = self.policies.get(case.policy_profile_id)
        results: list[ObligationEvaluation] = []
        for obligation in sorted(graph.obligations, key=lambda row: row.obligation_id):
            exception = exceptions.get(obligation.obligation_id)
            matching = (partition.matching(obligation.obligation_id, rejected_evidence) if partition is not None
                else tuple(row for row in receipt_rows if row.obligation_id == obligation.obligation_id))
            evidence = self.grade_evaluator.evaluate(obligation, matching, evaluation_time)
            receipt_ids = tuple(sorted(row.receipt_id for row in matching))
            # Model v1 gives contradiction precedence over every positive closure
            # path, including an otherwise valid exception. Evaluate conflicts
            # before resolving the obligation through the exception assertion.
            if evidence.status == BundleStatus.DISPUTED:
                results.append(ObligationEvaluation(
                    obligation.obligation_id, ObligationCategory.CONTRADICTORY, evidence.grade,
                    obligation.minimum_evidence_grade, evidence.disposition,
                    receipt_ids, ("CONFLICTING_ADMISSIBLE_EVIDENCE",), evidence,
                ))
                continue
            if exception is not None and self._valid_exception(
                exception, exception_checks.get(exception.exception_id), obligation,
                evaluation_time, set(policy.exception_authority_ids),
            ):
                results.append(ObligationEvaluation(
                    obligation.obligation_id, ObligationCategory.EXCEPTED, None,
                    obligation.minimum_evidence_grade, None, (), ("VALID_EXCEPTION",), None,
                ))
                continue

            if evidence.closure_admissible:
                category = ObligationCategory.COVERED
                reasons = ()
            elif evidence.primary_receipt_id is not None and not evidence.timely:
                category = ObligationCategory.LATE
                reasons = ("LATE_FOR_OBLIGATION",)
            elif not matching:
                category = ObligationCategory.MISSING
                reasons = ("MISSING_TERMINAL_EVIDENCE",)
            else:
                category = ObligationCategory.INVALID
                reasons = tuple(sorted(set(evidence.downgrade_reasons) | ({evidence.reason} if evidence.reason else set())))
            results.append(ObligationEvaluation(
                obligation.obligation_id, category, evidence.grade,
                obligation.minimum_evidence_grade, evidence.disposition,
                receipt_ids, reasons, evidence,
            ))

        challenge_ids = set(open_challenge_ids)
        dispute_blocks_closure = False
        if dispute_state is not None:
            challenge_ids.update(dispute_state.open_challenge_ids)
            dispute_blocks_closure = (
                bool(dispute_state.open_dispute_ids)
                or dispute_state.terminal_outcome == DisputeClosureOutcome.DISPUTED
            )
        challenge_ids = tuple(sorted(challenge_ids))
        categories = {row.category for row in results}
        all_resolved = all(row.category in {ObligationCategory.COVERED, ObligationCategory.EXCEPTED} for row in results)
        ready = self._ready(graph.obligations, evaluation_time, policy.early_closure_allowed, all_resolved)
        if challenge_ids or dispute_blocks_closure or ObligationCategory.CONTRADICTORY in categories:
            closure_class = ClosureClass.DISPUTED
            reasons = tuple(sorted(
                {"OPEN_CHALLENGE_OR_CONTRADICTION"}
                | (set(dispute_state.reason_codes) if dispute_state is not None else set())
            ))
        elif not ready:
            closure_class = ClosureClass.IN_PROGRESS
            reasons = ("DECISION_TIME_NOT_REACHED",)
        elif all_resolved:
            has_exception = ObligationCategory.EXCEPTED in categories
            closure_class = ClosureClass.CLOSED_WITH_EXCEPTIONS if has_exception else ClosureClass.CLOSED
            reasons = ("ALL_OBLIGATIONS_RESOLVED",)
        elif any(row.category in {ObligationCategory.COVERED, ObligationCategory.EXCEPTED} for row in results):
            closure_class = ClosureClass.PARTIALLY_CLOSED
            reasons = ("SOME_OBLIGATIONS_UNRESOLVED",)
        else:
            closure_class = ClosureClass.OPEN
            reasons = ("NO_OBLIGATION_RESOLVED",)

        counts = {category: sum(row.category == category for row in results) for category in ObligationCategory}
        explanation = (
            f"{closure_class}: {counts[ObligationCategory.COVERED]} covered, "
            f"{counts[ObligationCategory.EXCEPTED]} excepted, "
            f"{counts[ObligationCategory.MISSING]} missing, "
            f"{counts[ObligationCategory.INVALID]} invalid, "
            f"{counts[ObligationCategory.LATE]} late, and "
            f"{counts[ObligationCategory.CONTRADICTORY]} contradictory obligations; "
            "the result is limited to the authenticated observable scope."
        )
        return self._report(
            case, closure_class, tuple(results), reasons, explanation,
            visibility_reasons, visibility_limitation,
        )

    @staticmethod
    def _valid_exception(
        exception: ExceptionAssertion,
        validation: ExceptionValidation | None,
        obligation: Obligation,
        evaluation_time: datetime,
        authorities: set[str],
    ) -> bool:
        return bool(
            validation is not None
            and validation.exception_id == exception.exception_id
            and validation.authenticated
            and validation.basis_integrity_valid
            and validation.authority_admitted
            and exception.authority_principal_id in authorities
            and exception.obligation_id == obligation.obligation_id
            and len(exception.basis_commitment) == 64
            and all(char in "0123456789abcdef" for char in exception.basis_commitment.lower())
            and exception.effective_at <= obligation.deadline
            and evaluation_time <= exception.expires_at
        )

    @staticmethod
    def _ready(
        obligations: tuple[Obligation, ...], evaluation_time: datetime,
        early_closure_allowed: bool, all_resolved: bool,
    ) -> bool:
        if not obligations:
            return True
        if evaluation_time >= max(row.deadline for row in obligations):
            return True
        return early_closure_allowed and all_resolved

    @staticmethod
    def _report(
        case: ErasureCase,
        closure_class: ClosureClass,
        results: tuple[ObligationEvaluation, ...],
        reasons: tuple[str, ...],
        explanation: str,
        visibility_reasons: tuple[str, ...],
        visibility_limitation: str = "OBLIGATION_GRAPH_NOT_AVAILABLE",
    ) -> FederatedClosureReport:
        def ids(category: ObligationCategory) -> tuple[str, ...]:
            return tuple(row.obligation_id for row in results if row.category == category)
        return FederatedClosureReport(
            case_id=case.case_id,
            closure_class=closure_class,
            evaluated_revision=case.revision,
            obligation_results=results,
            covered_obligation_ids=ids(ObligationCategory.COVERED),
            missing_obligation_ids=ids(ObligationCategory.MISSING),
            excepted_obligation_ids=ids(ObligationCategory.EXCEPTED),
            invalid_obligation_ids=ids(ObligationCategory.INVALID),
            late_obligation_ids=ids(ObligationCategory.LATE),
            contradictory_obligation_ids=ids(ObligationCategory.CONTRADICTORY),
            visibility_limitation=visibility_limitation,
            visibility_reason_codes=visibility_reasons,
            reason_codes=tuple(sorted(reasons)),
            explanation=explanation,
        )
