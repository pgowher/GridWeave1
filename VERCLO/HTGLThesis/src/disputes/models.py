"""Immutable challenge and dispute metadata for VERCLO."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class ChallengeKind(StrEnum):
    SCOPE = "SCOPE"
    AUTHORITY = "AUTHORITY"
    EXCEPTION = "EXCEPTION"
    EVIDENCE = "EVIDENCE"
    DEADLINE = "DEADLINE"
    OTHER = "OTHER"


class ChallengeResolution(StrEnum):
    UPHELD = "UPHELD"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class ResponseDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    CONTESTED = "CONTESTED"
    UNAVAILABLE = "UNAVAILABLE"


class ConflictClass(StrEnum):
    DISPOSITION = "DISPOSITION"
    TARGET = "TARGET"
    ISSUER = "ISSUER"
    ORDERING = "ORDERING"
    EQUIVOCATION = "EQUIVOCATION"
    OTHER = "OTHER"


class RecordStatus(StrEnum):
    OPEN = "OPEN"
    RESPONDED = "RESPONDED"
    RESOLVED = "RESOLVED"
    TIMED_OUT = "TIMED_OUT"


class DisputeClosureOutcome(StrEnum):
    DISPUTED = "DISPUTED"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class DisputePolicy:
    policy_id: str
    version: str
    challenge_timeout_hours: Mapping[ChallengeKind, int]
    dispute_timeout_hours: int
    terminal_retention_days: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "challenge_timeout_hours", MappingProxyType(dict(self.challenge_timeout_hours)))
        if set(self.challenge_timeout_hours) != set(ChallengeKind):
            raise ValueError("challenge timeout policy must cover every challenge kind")
        if any(value <= 0 for value in self.challenge_timeout_hours.values()):
            raise ValueError("challenge timeouts must be positive")
        if self.dispute_timeout_hours <= 0 or self.terminal_retention_days <= 0:
            raise ValueError("dispute timeout and retention must be positive")

    def challenge_deadline(self, kind: ChallengeKind, opened_at: datetime) -> datetime:
        return opened_at + timedelta(hours=self.challenge_timeout_hours[kind])

    def dispute_deadline(self, opened_at: datetime) -> datetime:
        return opened_at + timedelta(hours=self.dispute_timeout_hours)


@dataclass(frozen=True)
class CustodianResponse:
    response_id: str
    challenge_id: str
    custodian_principal_id: str
    disposition: ResponseDisposition
    evidence_refs: tuple[str, ...]
    response_commitment: str
    responded_at: datetime


@dataclass(frozen=True)
class ChallengeRecord:
    challenge_id: str
    case_id: str
    kind: ChallengeKind
    target_ref: str
    challenger_principal_id: str
    grounds_commitment: str
    opened_at: datetime
    deadline: datetime
    status: RecordStatus
    responses: tuple[CustodianResponse, ...] = ()
    resolution: ChallengeResolution | None = None
    resolution_evidence_refs: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    terminal_at: datetime | None = None
    retention_until: datetime | None = None
    terminal_outcome: DisputeClosureOutcome | None = None


@dataclass(frozen=True)
class DisputeRecord:
    dispute_id: str
    case_id: str
    obligation_id: str | None
    conflict_class: ConflictClass
    evidence_refs: tuple[str, ...]
    challenge_refs: tuple[str, ...]
    opened_by_principal_id: str
    opened_at: datetime
    deadline: datetime
    baseline_blocking: bool
    status: RecordStatus
    accepted_evidence_refs: tuple[str, ...] = ()
    rejected_evidence_refs: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    terminal_at: datetime | None = None
    retention_until: datetime | None = None
    terminal_outcome: DisputeClosureOutcome | None = None


@dataclass(frozen=True)
class DisputeEvent:
    event_id: str
    case_id: str
    record_id: str
    sequence: int
    event_type: str
    actor_principal_id: str
    recorded_at: datetime
    payload_commitment: str
    reference_ids: tuple[str, ...]
    predecessor_event_id: str | None
    event_commitment: str


@dataclass(frozen=True)
class DisputeClosureState:
    case_id: str
    open_challenge_ids: tuple[str, ...]
    open_dispute_ids: tuple[str, ...]
    terminal_outcome: DisputeClosureOutcome | None
    accepted_evidence_refs: tuple[str, ...]
    rejected_evidence_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
