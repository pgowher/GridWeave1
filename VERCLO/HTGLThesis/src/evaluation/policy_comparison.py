"""Alternative verification policies evaluated over identical observable inputs."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from analytics.closure_report import ClosureClass
from erasure.federated_closure_evaluator import FederatedClosureEvaluator
from evidence.models import (
    CustodianReceipt,
    ExceptionValidation,
    ReceiptStatus,
    ReceiptValidationBackend,
)
from evidence.receipt_verifier import CustodianReceiptVerifier
from proof.evidence_grade_evaluator import BundleStatus, EvidenceGradeEvaluator
from verclo.models import ErasureCase, Obligation
from verclo.policy import PolicyRegistry


class ComparisonPolicy(StrEnum):
    RECEIPT_PRESENCE = "receipt-presence"
    AUTHENTICATED_RECEIPT = "authenticated-receipt"
    EVIDENCE_GRADE = "evidence-grade"
    VERCLO = "verclo"


@dataclass(frozen=True)
class ComparisonDecision:
    policy: ComparisonPolicy
    accepted_closed: bool
    raw_decision: str
    reason_codes: tuple[str, ...]


_TERMINAL_TYPES = {
    "hmac",
    "signature",
    "deletion_acknowledgement",
    "replica_attestation",
    "audit_finding",
}


class PolicyComparator:
    """Runs intentionally explicit baselines and VERCLO on one scenario."""

    def __init__(self, policies: PolicyRegistry | None = None) -> None:
        self.policies = policies or PolicyRegistry.load()

    def evaluate(
        self,
        case: ErasureCase,
        receipts: Iterable[CustodianReceipt],
        evaluation_time: datetime,
        backend: ReceiptValidationBackend,
        *,
        exception_validations: Iterable[ExceptionValidation] = (),
        open_challenge_ids: Iterable[str] = (),
    ) -> tuple[ComparisonDecision, ...]:
        receipt_rows = tuple(receipts)
        exceptions = tuple(exception_validations)
        challenges = tuple(open_challenge_ids)
        verifier = CustodianReceiptVerifier(backend)
        grader = EvidenceGradeEvaluator(verifier)
        obligations = () if case.graph is None else case.graph.obligations

        presence = self._all_obligations(
            obligations,
            lambda obligation: any(
                row.obligation_id == obligation.obligation_id
                and row.evidence_type in _TERMINAL_TYPES
                and row.disposition in obligation.permitted_dispositions
                for row in receipt_rows
            ),
        )
        authenticated = self._all_obligations(
            obligations,
            lambda obligation: any(
                verification.status == ReceiptStatus.GRADED
                and verification.closure_admissible
                for verification in (
                    verifier.verify(row, obligation, evaluation_time)
                    for row in receipt_rows
                    if row.obligation_id == obligation.obligation_id
                )
            ),
        )
        graded = self._all_obligations(
            obligations,
            lambda obligation: self._grade_accepts(
                grader, obligation, receipt_rows, evaluation_time
            ),
        )
        report = FederatedClosureEvaluator(grader, self.policies).evaluate(
            case,
            receipt_rows,
            evaluation_time,
            exception_validations=exceptions,
            open_challenge_ids=challenges,
        )
        verclo_closed = report.closure_class in {
            ClosureClass.CLOSED,
            ClosureClass.CLOSED_WITH_EXCEPTIONS,
        }
        return (
            self._binary(ComparisonPolicy.RECEIPT_PRESENCE, presence),
            self._binary(ComparisonPolicy.AUTHENTICATED_RECEIPT, authenticated),
            self._binary(ComparisonPolicy.EVIDENCE_GRADE, graded),
            ComparisonDecision(
                ComparisonPolicy.VERCLO,
                verclo_closed,
                str(report.closure_class),
                report.reason_codes,
            ),
        )

    @staticmethod
    def _all_obligations(obligations: tuple[Obligation, ...], predicate) -> bool:
        return all(predicate(row) for row in obligations)

    @staticmethod
    def _grade_accepts(
        grader: EvidenceGradeEvaluator,
        obligation: Obligation,
        receipts: tuple[CustodianReceipt, ...],
        evaluation_time: datetime,
    ) -> bool:
        matching = tuple(
            row for row in receipts if row.obligation_id == obligation.obligation_id
        )
        result = grader.evaluate(obligation, matching, evaluation_time)
        return result.status == BundleStatus.GRADED and result.closure_admissible

    @staticmethod
    def _binary(policy: ComparisonPolicy, accepted: bool) -> ComparisonDecision:
        return ComparisonDecision(
            policy=policy,
            accepted_closed=accepted,
            raw_decision="ACCEPT_CLOSED" if accepted else "REJECT_CLOSED",
            reason_codes=(),
        )
