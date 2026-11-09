"""Stable, machine-readable closure reports returned by VERCLO."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from proof.evidence_grade_evaluator import EvidenceBundleEvaluation


class ClosureClass(StrEnum):
    CLOSED = "CLOSED"
    CLOSED_WITH_EXCEPTIONS = "CLOSED_WITH_EXCEPTIONS"
    PARTIALLY_CLOSED = "PARTIALLY_CLOSED"
    OPEN = "OPEN"
    DISPUTED = "DISPUTED"
    UNVERIFIABLE = "UNVERIFIABLE"
    IN_PROGRESS = "IN_PROGRESS"


class ObligationCategory(StrEnum):
    COVERED = "COVERED"
    MISSING = "MISSING"
    EXCEPTED = "EXCEPTED"
    INVALID = "INVALID"
    LATE = "LATE"
    CONTRADICTORY = "CONTRADICTORY"


@dataclass(frozen=True)
class ObligationEvaluation:
    obligation_id: str
    category: ObligationCategory
    evidence_grade: str | None
    required_grade: str
    disposition: str | None
    receipt_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    evidence: EvidenceBundleEvaluation | None


@dataclass(frozen=True)
class FederatedClosureReport:
    case_id: str
    closure_class: ClosureClass
    evaluated_revision: int
    obligation_results: tuple[ObligationEvaluation, ...]
    covered_obligation_ids: tuple[str, ...]
    missing_obligation_ids: tuple[str, ...]
    excepted_obligation_ids: tuple[str, ...]
    invalid_obligation_ids: tuple[str, ...]
    late_obligation_ids: tuple[str, ...]
    contradictory_obligation_ids: tuple[str, ...]
    visibility_limitation: str
    visibility_reason_codes: tuple[str, ...]
    reason_codes: tuple[str, ...]
    explanation: str
    physical_destruction_concluded: bool = False
