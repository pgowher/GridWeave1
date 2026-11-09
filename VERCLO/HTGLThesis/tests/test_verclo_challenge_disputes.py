from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analytics import ClosureClass  # noqa: E402
from disputes import (  # noqa: E402
    ChallengeDisputeService, ChallengeKind, ChallengeResolution, ConflictClass,
    DisputeClosureOutcome, RecordStatus, ResponseDisposition,
)
from erasure import FederatedClosureEvaluator  # noqa: E402
from evidence import CustodianReceipt, CustodianReceiptVerifier, ExceptionValidation  # noqa: E402
from proof import DeterministicValidationBackend, EvidenceGradeEvaluator  # noqa: E402
from verclo.models import (  # noqa: E402
    CasePhase, ErasureCase, ExceptionAssertion, Obligation, ObligationGraph,
)
from verclo.policy import PolicyRegistry  # noqa: E402


UTC = timezone.utc
OPENED = datetime(2026, 9, 16, 10, 0, tzinfo=UTC)
OBLIGATION_DEADLINE = datetime(2026, 9, 15, tzinfo=UTC)


def make_case(case_id: str, *, baseline: bool = True, exception: bool = False) -> ErasureCase:
    obligation = Obligation(
        obligation_id="OBL-1", case_id=case_id, dataset_id="DATASET-1", correlation_id="CORR-1",
        asset_id="ASSET-1", replica_id="REPLICA-1", repository_id="REPO-1",
        custodian_principal_id="CUSTODIAN-1", deadline=OBLIGATION_DEADLINE,
        minimum_evidence_grade="E2", permitted_dispositions=("ERASED", "CRYPTO_ERASED"),
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE", policy_version="1.0.0",
    )
    exceptions = ()
    if exception:
        exceptions = (ExceptionAssertion(
            exception_id="EX-1", obligation_id="OBL-1",
            authority_principal_id="AUTHORITY-RETENTION-REVIEW", basis_commitment="a" * 64,
            effective_at=OBLIGATION_DEADLINE, expires_at=OPENED + timedelta(days=30),
        ),)
    graph = ObligationGraph(
        case_id=case_id, dataset_id="DATASET-1", correlation_id="CORR-1", scope_version=1,
        root_asset_ids=("ASSET-1",), discovered_asset_ids=("ASSET-1",), relationship_ids=(),
        obligations=(obligation,), exceptions=exceptions, custodians=("CUSTODIAN-1",),
        scope_commitment="b" * 64, obligation_commitment="c" * 64,
        baseline_verifiable=baseline,
        baseline_reason_codes=() if baseline else ("DECLARED_SCOPE_INCOMPLETE",),
    )
    return ErasureCase(
        case_id=case_id, run_id="RUN-1", dataset_id="DATASET-1", correlation_id="CORR-1",
        request_id="REQ-1", requester_principal_id="REQUESTER-1", root_asset_ids=("ASSET-1",),
        policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE", accepted_at=OPENED - timedelta(days=30),
        phase=CasePhase.OBLIGATIONS_ACTIVE, revision=1, graph=graph,
    )


def receipt(case: ErasureCase, receipt_id: str, disposition: str = "ERASED", *, event_time=None) -> CustodianReceipt:
    obligation = case.graph.obligations[0]
    when = event_time or OBLIGATION_DEADLINE - timedelta(hours=1)
    return CustodianReceipt(
        receipt_id=receipt_id, case_id=case.case_id, obligation_id=obligation.obligation_id,
        asset_id=obligation.asset_id, replica_id=obligation.replica_id,
        repository_id=obligation.repository_id, issuer_principal_id="CUSTODIAN-1",
        issuer_role="CUSTODIAN", trust_domain="TD-1", fault_domain="FD-1",
        evidence_type="signature", disposition=disposition, event_time=when,
        submitted_at=when, not_before=when - timedelta(days=1), provenance_refs=("PROV-1",),
    )


def closure_service(validations=None) -> FederatedClosureEvaluator:
    backend = DeterministicValidationBackend(validations, allow_unlisted_for_tests=True)
    grades = EvidenceGradeEvaluator(CustodianReceiptVerifier(backend))
    return FederatedClosureEvaluator(grades, PolicyRegistry.load())


class ChallengeDisputeTests(unittest.TestCase):
    def test_challenge_deadline_response_resolution_and_retention_are_deterministic(self) -> None:
        service = ChallengeDisputeService.from_config()
        opened = service.issue_challenge(
            case_id="CASE-1", challenge_id="CH-1", kind=ChallengeKind.EVIDENCE,
            target_ref="OBL-1", challenger_principal_id="AUDITOR-1",
            grounds_commitment="a" * 64, opened_at=OPENED, known_target_refs=("OBL-1",),
        )
        self.assertEqual(OPENED + timedelta(hours=120), opened.deadline)
        self.assertEqual(opened, service.issue_challenge(
            case_id="CASE-1", challenge_id="CH-1", kind=ChallengeKind.EVIDENCE,
            target_ref="OBL-1", challenger_principal_id="AUDITOR-1",
            grounds_commitment="a" * 64, opened_at=OPENED, known_target_refs=("OBL-1",),
        ))
        first_event = service.audit_events("CASE-1", OPENED)[0]
        responded = service.record_custodian_response(
            "CH-1", response_id="RESP-1", custodian_principal_id="CUSTODIAN-1",
            disposition=ResponseDisposition.CONTESTED, evidence_refs=("R-1",),
            response_commitment="b" * 64, responded_at=OPENED + timedelta(hours=1),
        )
        self.assertEqual(RecordStatus.RESPONDED, responded.status)
        terminal = service.resolve_challenge(
            "CH-1", resolver_principal_id="COORDINATOR-1",
            resolution=ChallengeResolution.REJECTED, evidence_refs=("R-1",),
            reason_codes=("CHALLENGE_NOT_SUBSTANTIATED",), resolved_at=OPENED + timedelta(hours=2),
        )
        events = service.audit_events("CASE-1", terminal.terminal_at)
        self.assertEqual(3, len(events))
        self.assertEqual(first_event, events[0])
        self.assertEqual(events[0].event_id, events[1].predecessor_event_id)
        self.assertEqual(events[1].event_id, events[2].predecessor_event_id)
        self.assertTrue(service.verify_journal("CASE-1"))
        self.assertEqual(terminal.terminal_at + timedelta(days=365), terminal.retention_until)
        self.assertEqual((), service.audit_events("CASE-1", terminal.retention_until))

    def test_absent_custodian_timeout_is_disputed_even_when_receipt_would_cover(self) -> None:
        case = make_case("CASE-ABSENT")
        service = ChallengeDisputeService.from_config()
        challenge = service.issue_challenge(
            case_id=case.case_id, challenge_id="CH-ABSENT", kind=ChallengeKind.EVIDENCE,
            target_ref="OBL-1", challenger_principal_id="AUDITOR-1",
            grounds_commitment="a" * 64, opened_at=OPENED, known_target_refs=("OBL-1",),
        )
        self.assertEqual(1, service.apply_timeouts(challenge.deadline))
        state = service.closure_state(case.case_id, challenge.deadline)
        self.assertEqual(DisputeClosureOutcome.DISPUTED, state.terminal_outcome)
        report = closure_service().evaluate(
            case, (receipt(case, "R-COVERED"),), challenge.deadline, dispute_state=state,
        )
        self.assertEqual(ClosureClass.DISPUTED, report.closure_class)

    def test_scope_timeout_and_baseline_blocking_dispute_are_unverifiable(self) -> None:
        for use_dispute in (False, True):
            with self.subTest(use_dispute=use_dispute):
                case = make_case(f"CASE-SCOPE-{use_dispute}")
                service = ChallengeDisputeService.from_config()
                if use_dispute:
                    record = service.record_contradiction(
                        case_id=case.case_id, dispute_id="DSP-SCOPE", conflict_class=ConflictClass.TARGET,
                        evidence_refs=("R-1", "R-2"), opened_by_principal_id="VALIDATOR-1",
                        opened_at=OPENED, known_evidence_refs=("R-1", "R-2"), baseline_blocking=True,
                    )
                else:
                    record = service.issue_challenge(
                        case_id=case.case_id, challenge_id="CH-SCOPE", kind=ChallengeKind.SCOPE,
                        target_ref="SCOPE-1", challenger_principal_id="AUDITOR-1",
                        grounds_commitment="a" * 64, opened_at=OPENED,
                        known_target_refs=("SCOPE-1",),
                    )
                service.apply_timeouts(record.deadline)
                state = service.closure_state(case.case_id, record.deadline)
                report = closure_service().evaluate(case, (), record.deadline, dispute_state=state)
                self.assertEqual(ClosureClass.UNVERIFIABLE, report.closure_class)

    def test_equivocation_stays_disputed_until_evidenced_resolution_filters_rejected_receipt(self) -> None:
        case = make_case("CASE-EQUIVOCATION")
        good = receipt(case, "R-GOOD")
        bad = receipt(case, "R-BAD", "FAILED")
        service = ChallengeDisputeService.from_config()
        dispute = service.record_contradiction(
            case_id=case.case_id, dispute_id="DSP-1", conflict_class=ConflictClass.EQUIVOCATION,
            obligation_id="OBL-1", evidence_refs=(good.receipt_id, bad.receipt_id),
            opened_by_principal_id="VALIDATOR-1", opened_at=OPENED,
            known_evidence_refs=(good.receipt_id, bad.receipt_id),
        )
        open_report = closure_service().evaluate(
            case, (good, bad), OPENED, dispute_state=service.closure_state(case.case_id, OPENED),
        )
        self.assertEqual(ClosureClass.DISPUTED, open_report.closure_class)
        service.resolve_dispute(
            dispute.dispute_id, resolver_principal_id="COORDINATOR-1",
            accepted_evidence_refs=(good.receipt_id,), rejected_evidence_refs=(bad.receipt_id,),
            reason_codes=("EQUIVOCATION_PROVEN",), resolved_at=OPENED + timedelta(hours=2),
        )
        resolved_report = closure_service().evaluate(
            case, (good, bad), OPENED + timedelta(hours=2),
            dispute_state=service.closure_state(case.case_id, OPENED + timedelta(hours=2)),
        )
        self.assertEqual(ClosureClass.CLOSED, resolved_report.closure_class)
        self.assertEqual(("OBL-1",), resolved_report.covered_obligation_ids)

    def test_invalid_exception_challenge_cannot_produce_closed_with_exceptions(self) -> None:
        case = make_case("CASE-INVALID-EXCEPTION", exception=True)
        service = ChallengeDisputeService.from_config()
        service.issue_challenge(
            case_id=case.case_id, challenge_id="CH-EX", kind=ChallengeKind.EXCEPTION,
            target_ref="EX-1", challenger_principal_id="AUDITOR-1",
            grounds_commitment="d" * 64, opened_at=OPENED, known_target_refs=("EX-1",),
        )
        service.resolve_challenge(
            "CH-EX", resolver_principal_id="AUTHORITY-RETENTION-REVIEW",
            resolution=ChallengeResolution.UPHELD, evidence_refs=("AUDIT-EX-1",),
            reason_codes=("INVALID_EXCEPTION_AUTHENTICATION",), resolved_at=OPENED + timedelta(hours=1),
        )
        report = closure_service().evaluate(
            case, (), OPENED + timedelta(hours=1),
            exception_validations=(ExceptionValidation("EX-1", False, True),),
            dispute_state=service.closure_state(case.case_id, OPENED + timedelta(hours=1)),
        )
        self.assertEqual(ClosureClass.DISPUTED, report.closure_class)
        self.assertNotEqual(ClosureClass.CLOSED_WITH_EXCEPTIONS, report.closure_class)

    def test_late_evidence_remains_late_after_rejected_challenge(self) -> None:
        case = make_case("CASE-LATE")
        late = receipt(case, "R-LATE", event_time=OBLIGATION_DEADLINE + timedelta(seconds=1))
        service = ChallengeDisputeService.from_config()
        service.issue_challenge(
            case_id=case.case_id, challenge_id="CH-LATE", kind=ChallengeKind.DEADLINE,
            target_ref="R-LATE", challenger_principal_id="AUDITOR-1",
            grounds_commitment="e" * 64, opened_at=OPENED, known_target_refs=("R-LATE",),
        )
        service.record_custodian_response(
            "CH-LATE", response_id="RESP-LATE", custodian_principal_id="CUSTODIAN-1",
            disposition=ResponseDisposition.CONTESTED, evidence_refs=("R-LATE",),
            response_commitment="f" * 64, responded_at=OPENED + timedelta(hours=1),
        )
        service.resolve_challenge(
            "CH-LATE", resolver_principal_id="COORDINATOR-1",
            resolution=ChallengeResolution.REJECTED, evidence_refs=("R-LATE",),
            reason_codes=("DEADLINE_STANDS",), resolved_at=OPENED + timedelta(hours=2),
        )
        report = closure_service().evaluate(
            case, (late,), OPENED + timedelta(hours=2),
            dispute_state=service.closure_state(case.case_id, OPENED + timedelta(hours=2)),
        )
        self.assertEqual(ClosureClass.OPEN, report.closure_class)
        self.assertEqual(("OBL-1",), report.late_obligation_ids)


if __name__ == "__main__":
    unittest.main()
