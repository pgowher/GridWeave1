"""Capability-based E0-E5 evaluation for verified evidence bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Iterable

from evidence.models import CustodianReceipt, ReceiptStatus, ReceiptVerification
from evidence.receipt_verifier import CustodianReceiptVerifier
from verclo.models import Obligation


GRADE_ORDER = {f"E{level}": level for level in range(6)}


class BundleStatus(StrEnum):
    GRADED = "GRADED"
    REJECTED = "REJECTED"
    DISPUTED = "DISPUTED"


@dataclass(frozen=True)
class EvidenceBundleEvaluation:
    obligation_id: str
    status: BundleStatus
    grade: str | None
    required_grade: str
    conclusion: str | None
    primary_receipt_id: str | None
    support_receipt_ids: tuple[str, ...]
    invalid_receipt_ids: tuple[str, ...]
    missing_receipt_ids: tuple[str, ...]
    contradictory_receipt_ids: tuple[str, ...]
    downgrade_reasons: tuple[str, ...]
    reason: str | None
    closure_admissible: bool
    timely: bool
    disposition: str | None
    physical_destruction_concluded: bool = False


class EvidenceGradeEvaluator:
    def __init__(self, receipt_verifier: CustodianReceiptVerifier) -> None:
        self.receipt_verifier = receipt_verifier

    def evaluate(
        self,
        obligation: Obligation,
        receipts: Iterable[CustodianReceipt],
        evaluation_time: datetime,
        *,
        primary_receipt_id: str | None = None,
        support_receipt_ids: Iterable[str] | None = None,
        required_grade: str | None = None,
        required_corroborators: int = 2,
        required_independent_domains: int = 2,
    ) -> EvidenceBundleEvaluation:
        required = required_grade or obligation.minimum_evidence_grade
        if required not in GRADE_ORDER:
            raise ValueError(f"unknown evidence grade: {required}")
        receipt_map = {row.receipt_id: row for row in receipts if row.obligation_id == obligation.obligation_id}
        requested_support = tuple(sorted(set(support_receipt_ids or ())))
        missing = tuple(row_id for row_id in requested_support if row_id not in receipt_map)
        selected_ids = set(receipt_map) if support_receipt_ids is None else set(requested_support)
        if primary_receipt_id is not None:
            selected_ids.add(primary_receipt_id)
        selected = [receipt_map[row_id] for row_id in sorted(selected_ids) if row_id in receipt_map]
        verified = [self.receipt_verifier.verify(row, obligation, evaluation_time) for row in selected]
        admissible = [row for row in verified if row.status == ReceiptStatus.GRADED]
        invalid = tuple(sorted(row.receipt.receipt_id for row in verified if row.status == ReceiptStatus.REJECTED))

        if primary_receipt_id is None:
            terminal = [row for row in admissible if row.terminal_assertion]
            primary = max(terminal, key=self._rank, default=None)
        else:
            primary = next((row for row in admissible if row.receipt.receipt_id == primary_receipt_id), None)

        conflicts = self._conflicts(admissible)
        if conflicts:
            return self._result(
                obligation, BundleStatus.DISPUTED, None, required, primary, admissible,
                invalid, missing, conflicts, (), "CONFLICTING_ADMISSIBLE_EVIDENCE", False,
            )

        if primary is None:
            if primary_receipt_id is None and not selected:
                grade = "E0"
                status = BundleStatus.GRADED if GRADE_ORDER[required] == 0 else BundleStatus.REJECTED
                return EvidenceBundleEvaluation(
                    obligation.obligation_id, status, grade, required,
                    "CASE_OR_REQUEST_RECORDED", None, (), invalid, missing, (),
                    () if status == BundleStatus.GRADED else ("INSUFFICIENT_GRADE_FOR_OBLIGATION",),
                    None if status == BundleStatus.GRADED else "INSUFFICIENT_GRADE_FOR_OBLIGATION",
                    False, False, None,
                )
            return self._result(
                obligation, BundleStatus.REJECTED, None, required, None, admissible,
                invalid, missing, (), ("NO_ADMISSIBLE_TERMINAL_EVIDENCE",),
                "NO_ADMISSIBLE_TERMINAL_EVIDENCE", False,
            )

        grade = primary.grade or "E0"
        downgrades = set(primary.downgrade_reasons)
        support = [row for row in admissible if row.receipt.receipt_id != primary.receipt.receipt_id]

        if GRADE_ORDER[grade] == 2 and any(GRADE_ORDER[row.grade or "E0"] >= 3 for row in support):
            grade = "E3"
            downgrades.discard("ORDERING_SUPPORT_MISSING")
        if missing and GRADE_ORDER[required] >= 3:
            downgrades.add("ORDERING_SUPPORT_MISSING")
        if GRADE_ORDER[grade] >= 4:
            corroborators = [
                row for row in support
                if row.receipt.evidence_type in {"signature", "audit_finding"}
                and row.receipt.disposition == primary.receipt.disposition
                and row.receipt.issuer_principal_id != primary.receipt.issuer_principal_id
            ]
            primary_domain = (primary.receipt.trust_domain, primary.receipt.fault_domain)
            independent_domains = {
                (row.receipt.trust_domain, row.receipt.fault_domain) for row in corroborators
                if (row.receipt.trust_domain, row.receipt.fault_domain) != primary_domain
            }
            corroboration_requested = required_corroborators > 0 or required_independent_domains > 0
            if (
                corroboration_requested
                and len(corroborators) >= required_corroborators
                and len(independent_domains) >= required_independent_domains
            ):
                grade = "E5"
            elif required == "E5":
                if len(corroborators) < required_corroborators:
                    downgrades.add("CORROBORATION_BELOW_QUORUM")
                elif len(independent_domains) < required_independent_domains:
                    downgrades.add("CORROBORATION_NOT_INDEPENDENT")

        sufficient = GRADE_ORDER[grade] >= GRADE_ORDER[required]
        if missing or not sufficient:
            downgrades.add("INSUFFICIENT_GRADE_FOR_OBLIGATION")
        status = BundleStatus.GRADED if sufficient and not missing else BundleStatus.REJECTED
        reason = None if status == BundleStatus.GRADED else "INSUFFICIENT_GRADE_FOR_OBLIGATION"
        closure_admissible = status == BundleStatus.GRADED and primary.closure_admissible
        return EvidenceBundleEvaluation(
            obligation_id=obligation.obligation_id,
            status=status,
            grade=grade,
            required_grade=required,
            conclusion=self._conclusion(grade, primary.conclusion),
            primary_receipt_id=primary.receipt.receipt_id,
            support_receipt_ids=tuple(sorted(row.receipt.receipt_id for row in support)),
            invalid_receipt_ids=invalid,
            missing_receipt_ids=missing,
            contradictory_receipt_ids=(),
            downgrade_reasons=tuple(sorted(downgrades)),
            reason=reason,
            closure_admissible=closure_admissible,
            timely=primary.timely,
            disposition=primary.receipt.disposition,
        )

    @staticmethod
    def _rank(row: ReceiptVerification) -> tuple[int, int, str]:
        return (GRADE_ORDER[row.grade or "E0"], int(row.closure_admissible), row.receipt.receipt_id)

    @staticmethod
    def _conflicts(rows: list[ReceiptVerification]) -> tuple[str, ...]:
        terminal = [row for row in rows if row.terminal_assertion]
        dispositions = {row.receipt.disposition for row in terminal}
        if len(dispositions) <= 1:
            return ()
        return tuple(sorted(row.receipt.receipt_id for row in terminal))

    @staticmethod
    def _conclusion(grade: str, fallback: str | None) -> str | None:
        if grade == "E3":
            return "ORDERED_AUTHENTICATED_ASSERTION"
        if grade == "E5":
            return "INDEPENDENTLY_CORROBORATED_MECHANISM_ASSERTION_UNDER_ASSUMPTIONS"
        return fallback

    @staticmethod
    def _result(
        obligation: Obligation, status: BundleStatus, grade: str | None, required: str,
        primary: ReceiptVerification | None, admissible: list[ReceiptVerification],
        invalid: tuple[str, ...], missing: tuple[str, ...], conflicts: tuple[str, ...],
        downgrades: tuple[str, ...], reason: str, closure_admissible: bool,
    ) -> EvidenceBundleEvaluation:
        return EvidenceBundleEvaluation(
            obligation.obligation_id, status, grade, required,
            None if primary is None or status == BundleStatus.DISPUTED else primary.conclusion,
            None if primary is None else primary.receipt.receipt_id,
            tuple(sorted(row.receipt.receipt_id for row in admissible if row is not primary)),
            invalid, missing, conflicts, tuple(sorted(downgrades)), reason,
            closure_admissible, False if primary is None else primary.timely,
            None if primary is None else primary.receipt.disposition,
        )
