"""Append-only challenge/dispute journal with deterministic timeouts."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
from typing import Iterable, Mapping

from verclo.canonical import commitment, content_id

from .models import (
    ChallengeKind,
    ChallengeRecord,
    ChallengeResolution,
    ConflictClass,
    CustodianResponse,
    DisputeClosureOutcome,
    DisputeClosureState,
    DisputeEvent,
    DisputePolicy,
    DisputeRecord,
    RecordStatus,
    ResponseDisposition,
)


HEX_256 = re.compile(r"^[0-9a-f]{64}$")
CONFIG_FILE = Path(__file__).with_name("configs") / "verclo_dispute_policy_v1.json"


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")


class ChallengeDisputeService:
    """Builds immutable aggregates by appending commitment-linked metadata events."""

    def __init__(self, policy: DisputePolicy) -> None:
        self.policy = policy
        self._challenges: dict[str, ChallengeRecord] = {}
        self._disputes: dict[str, DisputeRecord] = {}
        self._events: dict[str, tuple[DisputeEvent, ...]] = {}

    @classmethod
    def from_config(cls, path: str | Path = CONFIG_FILE) -> "ChallengeDisputeService":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("config_format") != "verclo.dispute-policy.v1":
            raise ValueError("unsupported dispute policy format")
        timeouts = {ChallengeKind(key): int(value) for key, value in payload["challenge_timeout_hours"].items()}
        return cls(DisputePolicy(
            policy_id=str(payload["policy_id"]), version=str(payload["version"]),
            challenge_timeout_hours=timeouts,
            dispute_timeout_hours=int(payload["dispute_timeout_hours"]),
            terminal_retention_days=int(payload["terminal_retention_days"]),
        ))

    def issue_challenge(
        self, *, case_id: str, challenge_id: str, kind: ChallengeKind,
        target_ref: str, challenger_principal_id: str, grounds_commitment: str,
        opened_at: datetime, known_target_refs: Iterable[str],
    ) -> ChallengeRecord:
        _aware(opened_at)
        self._require_ids(case_id, challenge_id, target_ref, challenger_principal_id)
        if target_ref not in set(known_target_refs):
            raise KeyError(f"unknown challenge target: {target_ref}")
        if not HEX_256.fullmatch(grounds_commitment):
            raise ValueError("challenge grounds commitment must be SHA-256 hex")
        created = ChallengeRecord(
            challenge_id, case_id, kind, target_ref, challenger_principal_id,
            grounds_commitment, opened_at, self.policy.challenge_deadline(kind, opened_at),
            RecordStatus.OPEN,
        )
        prior = self._challenges.get(challenge_id)
        if prior is not None:
            if prior == created:
                return prior
            raise ValueError(f"challenge identifier already used: {challenge_id}")
        self._challenges[challenge_id] = created
        self._append(case_id, challenge_id, "CHALLENGE_OPEN", challenger_principal_id, opened_at,
                     asdict(created), (target_ref,))
        return created

    def record_custodian_response(
        self, challenge_id: str, *, response_id: str, custodian_principal_id: str,
        disposition: ResponseDisposition, evidence_refs: Iterable[str],
        response_commitment: str, responded_at: datetime,
    ) -> ChallengeRecord:
        challenge = self.get_challenge(challenge_id)
        _aware(responded_at)
        self._require_ids(response_id, custodian_principal_id)
        if challenge.status not in {RecordStatus.OPEN, RecordStatus.RESPONDED}:
            raise ValueError("challenge is not open for response")
        if responded_at < challenge.opened_at or responded_at > challenge.deadline:
            raise ValueError("custodian response is outside the challenge response window")
        refs = tuple(sorted(set(evidence_refs)))
        if disposition != ResponseDisposition.UNAVAILABLE and not refs:
            raise ValueError("available custodian response requires evidence")
        if not HEX_256.fullmatch(response_commitment):
            raise ValueError("response commitment must be SHA-256 hex")
        response = CustodianResponse(
            response_id, challenge_id, custodian_principal_id, disposition,
            refs, response_commitment, responded_at,
        )
        existing = next((row for row in challenge.responses if row.response_id == response_id), None)
        if existing is not None:
            if existing == response:
                return challenge
            raise ValueError(f"response identifier already used: {response_id}")
        updated = replace(
            challenge,
            responses=challenge.responses + (response,),
            status=RecordStatus.RESPONDED,
        )
        self._challenges[challenge_id] = updated
        self._append(challenge.case_id, challenge_id, "CUSTODIAN_RESPONSE", custodian_principal_id,
                     responded_at, asdict(response), refs)
        return updated

    def resolve_challenge(
        self, challenge_id: str, *, resolver_principal_id: str,
        resolution: ChallengeResolution, evidence_refs: Iterable[str],
        reason_codes: Iterable[str], resolved_at: datetime,
    ) -> ChallengeRecord:
        challenge = self.get_challenge(challenge_id)
        _aware(resolved_at)
        if challenge.status == RecordStatus.RESOLVED:
            same = (
                challenge.resolution == resolution
                and challenge.resolution_evidence_refs == tuple(sorted(set(evidence_refs)))
                and challenge.reason_codes == tuple(sorted(set(reason_codes)))
                and challenge.terminal_at == resolved_at
            )
            if same:
                return challenge
            raise ValueError("challenge already resolved")
        if challenge.status == RecordStatus.TIMED_OUT:
            raise ValueError("challenge timed out and is terminal")
        latest_response = max((row.responded_at for row in challenge.responses), default=challenge.opened_at)
        if resolved_at < latest_response:
            raise ValueError("challenge resolution precedes the opening or latest response")
        if resolved_at > challenge.deadline:
            raise ValueError("challenge resolution arrived after deadline; apply timeout")
        refs = tuple(sorted(set(evidence_refs)))
        reasons = tuple(sorted(set(reason_codes)))
        if not refs or not reasons:
            raise ValueError("challenge resolution requires evidence and reason codes")
        outcome = self._upheld_outcome(challenge.kind) if resolution == ChallengeResolution.UPHELD else None
        updated = replace(
            challenge, status=RecordStatus.RESOLVED, resolution=resolution,
            resolution_evidence_refs=refs, reason_codes=reasons, terminal_at=resolved_at,
            retention_until=resolved_at + timedelta(days=self.policy.terminal_retention_days),
            terminal_outcome=outcome,
        )
        self._challenges[challenge_id] = updated
        self._append(challenge.case_id, challenge_id, "CHALLENGE_RESOLVE", resolver_principal_id,
                     resolved_at, asdict(updated), refs)
        return updated

    def record_contradiction(
        self, *, case_id: str, dispute_id: str, conflict_class: ConflictClass,
        evidence_refs: Iterable[str], opened_by_principal_id: str, opened_at: datetime,
        known_evidence_refs: Iterable[str], obligation_id: str | None = None,
        challenge_refs: Iterable[str] = (), baseline_blocking: bool = False,
    ) -> DisputeRecord:
        _aware(opened_at)
        self._require_ids(case_id, dispute_id, opened_by_principal_id)
        refs = tuple(sorted(set(evidence_refs)))
        if len(refs) < 2:
            raise ValueError("contradiction requires at least two evidence references")
        if not set(refs) <= set(known_evidence_refs):
            raise KeyError("contradiction contains unknown evidence reference")
        challenges = tuple(sorted(set(challenge_refs)))
        if any(self.get_challenge(row).case_id != case_id for row in challenges):
            raise ValueError("challenge/dispute case binding mismatch")
        created = DisputeRecord(
            dispute_id, case_id, obligation_id, conflict_class, refs, challenges,
            opened_by_principal_id, opened_at, self.policy.dispute_deadline(opened_at),
            baseline_blocking, RecordStatus.OPEN,
        )
        prior = self._disputes.get(dispute_id)
        if prior is not None:
            if prior == created:
                return prior
            raise ValueError(f"dispute identifier already used: {dispute_id}")
        self._disputes[dispute_id] = created
        self._append(case_id, dispute_id, "DISPUTE_OPEN", opened_by_principal_id, opened_at,
                     asdict(created), refs + challenges)
        return created

    def resolve_dispute(
        self, dispute_id: str, *, resolver_principal_id: str,
        accepted_evidence_refs: Iterable[str], rejected_evidence_refs: Iterable[str],
        reason_codes: Iterable[str], resolved_at: datetime,
    ) -> DisputeRecord:
        dispute = self.get_dispute(dispute_id)
        _aware(resolved_at)
        if dispute.status == RecordStatus.RESOLVED:
            accepted = tuple(sorted(set(accepted_evidence_refs)))
            rejected = tuple(sorted(set(rejected_evidence_refs)))
            reasons = tuple(sorted(set(reason_codes)))
            if (accepted, rejected, reasons, resolved_at) == (
                dispute.accepted_evidence_refs, dispute.rejected_evidence_refs,
                dispute.reason_codes, dispute.terminal_at,
            ):
                return dispute
            raise ValueError("dispute already resolved")
        if dispute.status == RecordStatus.TIMED_OUT:
            raise ValueError("dispute timed out and is terminal")
        if resolved_at < dispute.opened_at:
            raise ValueError("dispute resolution precedes dispute opening")
        if resolved_at > dispute.deadline:
            raise ValueError("dispute resolution arrived after deadline; apply timeout")
        accepted = tuple(sorted(set(accepted_evidence_refs)))
        rejected = tuple(sorted(set(rejected_evidence_refs)))
        reasons = tuple(sorted(set(reason_codes)))
        if set(accepted) & set(rejected):
            raise ValueError("accepted and rejected evidence sets must be disjoint")
        if set(accepted) | set(rejected) != set(dispute.evidence_refs):
            raise ValueError("resolution must account for every disputed evidence reference")
        if not accepted or not reasons:
            raise ValueError("dispute resolution requires accepted evidence and reasons")
        updated = replace(
            dispute, status=RecordStatus.RESOLVED,
            accepted_evidence_refs=accepted, rejected_evidence_refs=rejected,
            reason_codes=reasons, terminal_at=resolved_at,
            retention_until=resolved_at + timedelta(days=self.policy.terminal_retention_days),
        )
        self._disputes[dispute_id] = updated
        self._append(dispute.case_id, dispute_id, "DISPUTE_RESOLVE", resolver_principal_id,
                     resolved_at, asdict(updated), accepted + rejected)
        return updated

    def apply_timeouts(self, as_of: datetime, *, actor_principal_id: str = "VERCLO-TIMEOUT-SERVICE") -> int:
        _aware(as_of)
        changed = 0
        for challenge_id, challenge in tuple(sorted(self._challenges.items())):
            if challenge.status in {RecordStatus.OPEN, RecordStatus.RESPONDED} and as_of >= challenge.deadline:
                outcome = self._upheld_outcome(challenge.kind)
                updated = replace(
                    challenge, status=RecordStatus.TIMED_OUT,
                    reason_codes=("CHALLENGE_RESPONSE_TIMEOUT",), terminal_at=challenge.deadline,
                    retention_until=challenge.deadline + timedelta(days=self.policy.terminal_retention_days),
                    terminal_outcome=outcome,
                )
                self._challenges[challenge_id] = updated
                self._append(challenge.case_id, challenge_id, "CHALLENGE_TIMEOUT", actor_principal_id,
                             challenge.deadline, asdict(updated), ())
                changed += 1
        for dispute_id, dispute in tuple(sorted(self._disputes.items())):
            if dispute.status == RecordStatus.OPEN and as_of >= dispute.deadline:
                outcome = DisputeClosureOutcome.UNVERIFIABLE if dispute.baseline_blocking else DisputeClosureOutcome.DISPUTED
                updated = replace(
                    dispute, status=RecordStatus.TIMED_OUT,
                    reason_codes=("DISPUTE_RESOLUTION_TIMEOUT",), terminal_at=dispute.deadline,
                    retention_until=dispute.deadline + timedelta(days=self.policy.terminal_retention_days),
                    terminal_outcome=outcome,
                )
                self._disputes[dispute_id] = updated
                self._append(dispute.case_id, dispute_id, "DISPUTE_TIMEOUT", actor_principal_id,
                             dispute.deadline, asdict(updated), dispute.evidence_refs)
                changed += 1
        return changed

    def closure_state(self, case_id: str, as_of: datetime) -> DisputeClosureState:
        _aware(as_of)
        self.apply_timeouts(as_of)
        challenges = [row for row in self._challenges.values() if row.case_id == case_id and row.opened_at <= as_of]
        disputes = [row for row in self._disputes.values() if row.case_id == case_id and row.opened_at <= as_of]
        open_challenges = tuple(sorted(
            row.challenge_id for row in challenges
            if row.terminal_at is None or row.terminal_at > as_of
        ))
        open_disputes = tuple(sorted(
            row.dispute_id for row in disputes
            if row.terminal_at is None or row.terminal_at > as_of
        ))
        terminal = [
            row.terminal_outcome for row in (*challenges, *disputes)
            if row.terminal_outcome is not None and row.terminal_at is not None and row.terminal_at <= as_of
        ]
        resolved_disputes = [
            row for row in disputes
            if row.status == RecordStatus.RESOLVED and row.terminal_at is not None and row.terminal_at <= as_of
        ]
        accepted_set = {ref for row in resolved_disputes for ref in row.accepted_evidence_refs}
        rejected_set = {ref for row in resolved_disputes for ref in row.rejected_evidence_refs}
        conflicting_resolutions = accepted_set & rejected_set
        if DisputeClosureOutcome.UNVERIFIABLE in terminal:
            outcome = DisputeClosureOutcome.UNVERIFIABLE
        elif open_challenges or open_disputes or conflicting_resolutions or DisputeClosureOutcome.DISPUTED in terminal:
            outcome = DisputeClosureOutcome.DISPUTED
        else:
            outcome = None
        accepted = tuple(sorted(accepted_set))
        rejected = tuple(sorted(rejected_set))
        reasons_set = {
            reason for row in (*challenges, *disputes)
            if row.terminal_at is not None and row.terminal_at <= as_of
            for reason in row.reason_codes
        }
        if conflicting_resolutions:
            reasons_set.add("CONFLICTING_DISPUTE_RESOLUTIONS")
        reasons = tuple(sorted(reasons_set))
        return DisputeClosureState(case_id, open_challenges, open_disputes, outcome, accepted, rejected, reasons)

    def audit_events(self, case_id: str, as_of: datetime) -> tuple[DisputeEvent, ...]:
        """Return only records still inside their configured metadata-retention window."""
        _aware(as_of)
        retained_ids = {
            row.challenge_id for row in self._challenges.values()
            if row.case_id == case_id and (row.retention_until is None or as_of < row.retention_until)
        } | {
            row.dispute_id for row in self._disputes.values()
            if row.case_id == case_id and (row.retention_until is None or as_of < row.retention_until)
        }
        return tuple(
            row for row in self._events.get(case_id, ())
            if row.record_id in retained_ids and row.recorded_at <= as_of
        )

    def verify_journal(self, case_id: str) -> bool:
        """Verify sequence, predecessor, identifier and commitment linkage."""
        predecessor: str | None = None
        for sequence, event in enumerate(self._events.get(case_id, ()), start=1):
            body = {
                "case_id": event.case_id, "record_id": event.record_id,
                "sequence": event.sequence, "event_type": event.event_type,
                "actor_principal_id": event.actor_principal_id,
                "recorded_at": event.recorded_at,
                "payload_commitment": event.payload_commitment,
                "reference_ids": event.reference_ids,
                "predecessor_event_id": event.predecessor_event_id,
            }
            if (
                event.case_id != case_id
                or event.sequence != sequence
                or event.predecessor_event_id != predecessor
                or event.event_id != content_id("DSE", "verclo-dispute-event-id-v1", body)
                or event.event_commitment != commitment("verclo-dispute-event-v1", body)
            ):
                return False
            predecessor = event.event_id
        return True

    def get_challenge(self, challenge_id: str) -> ChallengeRecord:
        try:
            return self._challenges[challenge_id]
        except KeyError as exc:
            raise KeyError(f"unknown challenge: {challenge_id}") from exc

    def get_dispute(self, dispute_id: str) -> DisputeRecord:
        try:
            return self._disputes[dispute_id]
        except KeyError as exc:
            raise KeyError(f"unknown dispute: {dispute_id}") from exc

    def _append(
        self, case_id: str, record_id: str, event_type: str, actor: str,
        recorded_at: datetime, payload: Mapping[str, object], references: Iterable[str],
    ) -> DisputeEvent:
        prior = self._events.get(case_id, ())
        predecessor = prior[-1].event_id if prior else None
        sequence = len(prior) + 1
        payload_digest = commitment("verclo-dispute-event-payload-v1", payload)
        event_body = {
            "case_id": case_id, "record_id": record_id, "sequence": sequence,
            "event_type": event_type, "actor_principal_id": actor,
            "recorded_at": recorded_at, "payload_commitment": payload_digest,
            "reference_ids": tuple(sorted(set(references))), "predecessor_event_id": predecessor,
        }
        event = DisputeEvent(
            event_id=content_id("DSE", "verclo-dispute-event-id-v1", event_body),
            event_commitment=commitment("verclo-dispute-event-v1", event_body),
            **event_body,
        )
        self._events[case_id] = prior + (event,)
        return event

    @staticmethod
    def _upheld_outcome(kind: ChallengeKind) -> DisputeClosureOutcome:
        if kind in {ChallengeKind.SCOPE, ChallengeKind.AUTHORITY}:
            return DisputeClosureOutcome.UNVERIFIABLE
        return DisputeClosureOutcome.DISPUTED

    @staticmethod
    def _require_ids(*values: str) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError("non-empty identifiers are required")
