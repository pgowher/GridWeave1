"""Deterministic receipt admissibility and standalone evidence grading."""

from __future__ import annotations

from datetime import datetime

from verclo.models import Obligation

from .models import (
    BackendValidation,
    CustodianReceipt,
    ReceiptStatus,
    ReceiptValidationBackend,
    ReceiptVerification,
)


_RECEIPT_TYPES = {
    # grade, terminal, requires_key, requires_anchor, conclusion
    "digest": ("E1", False, False, False, "PAYLOAD_COMMITMENT_PRESENT"),
    "hmac": ("E2", True, True, False, "AUTHENTICATED_SHARED_SECRET_ASSERTION"),
    "signature": ("E2", True, True, False, "AUTHENTICATED_SIGNATURE_ASSERTION"),
    "inclusion_proof": ("E3", False, False, True, "ORDERED_INCLUSION"),
    "deletion_acknowledgement": ("E2", True, True, False, "CUSTODIAN_DELETION_ASSERTION"),
    "replica_attestation": ("E2", True, True, False, "REPLICA_STATE_ASSERTION"),
    "audit_finding": ("E2", True, True, False, "AUTHENTICATED_AUDITOR_FINDING"),
    "merkle_anchor": ("E3", False, False, True, "ANCHORED_BATCH_INCLUSION"),
    "notification_receipt": ("E2", False, True, False, "AUTHENTICATED_DELIVERY_ASSERTION"),
}


class CustodianReceiptVerifier:
    """Checks observable receipt facts in the Model v1 rejection precedence."""

    def __init__(self, backend: ReceiptValidationBackend) -> None:
        self.backend = backend

    def verify(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> ReceiptVerification:
        result = self.backend.validate(receipt, obligation, evaluation_time)
        rejection = self._rejection_reason(receipt, obligation, evaluation_time, result)
        profile = _RECEIPT_TYPES.get(receipt.evidence_type)
        if rejection is not None or profile is None:
            return ReceiptVerification(
                receipt=receipt,
                status=ReceiptStatus.REJECTED,
                grade=None,
                terminal_assertion=False if profile is None else profile[1],
                closure_admissible=False,
                timely=receipt.event_time <= obligation.deadline,
                conclusion=None,
                rejection_reason=rejection or "UNKNOWN_RECEIPT_TYPE",
                downgrade_reasons=(),
                backend_name=result.backend_name,
                backend_validation=result,
            )

        grade, terminal, _, _, conclusion = profile
        downgrades: list[str] = []
        if grade == "E2" and result.ordering_support_valid:
            grade = "E3"
        elif grade == "E2":
            downgrades.append("ORDERING_SUPPORT_MISSING")

        if grade == "E3" and result.mechanism_present:
            mechanism_current = (
                result.mechanism_valid
                and (result.mechanism_expires_at is None or evaluation_time < result.mechanism_expires_at)
            )
            if mechanism_current:
                grade = "E4"
                conclusion = "MECHANISM_EXECUTION_ASSERTION_UNDER_ASSUMPTIONS"
            elif result.mechanism_valid:
                downgrades.append("MECHANISM_ATTESTATION_EXPIRED")
                conclusion = "ORDERED_AUTHENTICATED_ASSERTION"
            else:
                downgrades.append("MECHANISM_ATTESTATION_MISSING")
        elif grade == "E3":
            downgrades.append("MECHANISM_ATTESTATION_MISSING")

        timely = receipt.event_time <= obligation.deadline
        disposition_ok = receipt.disposition in obligation.permitted_dispositions
        if not timely:
            downgrades.append("LATE_FOR_OBLIGATION")
        return ReceiptVerification(
            receipt=receipt,
            status=ReceiptStatus.GRADED,
            grade=grade,
            terminal_assertion=terminal,
            closure_admissible=terminal and timely and disposition_ok,
            timely=timely,
            conclusion=conclusion,
            rejection_reason=None,
            downgrade_reasons=tuple(sorted(set(downgrades))),
            backend_name=result.backend_name,
            backend_validation=result,
        )

    @staticmethod
    def _rejection_reason(
        receipt: CustodianReceipt,
        obligation: Obligation,
        evaluation_time: datetime,
        validation: BackendValidation,
    ) -> str | None:
        if receipt.evidence_type not in _RECEIPT_TYPES:
            return "UNKNOWN_RECEIPT_TYPE"
        if not receipt.canonical_payload_valid:
            return "MALFORMED_CANONICAL_PAYLOAD"
        if receipt.submitted_at < receipt.event_time:
            return "MALFORMED_CANONICAL_PAYLOAD"
        binding = (
            receipt.obligation_bound
            and receipt.case_id == obligation.case_id
            and receipt.obligation_id == obligation.obligation_id
            and receipt.asset_id == obligation.asset_id
            and receipt.replica_id == obligation.replica_id
            and receipt.repository_id == obligation.repository_id
        )
        if not binding:
            return "UNRESOLVED_OBLIGATION_BINDING"
        if not receipt.provenance_refs:
            return "MISSING_PROVENANCE"
        if evaluation_time < max(receipt.not_before, receipt.event_time, receipt.submitted_at):
            return "RECEIPT_NOT_YET_VALID"
        if receipt.expires_at is not None and evaluation_time >= receipt.expires_at:
            return "RECEIPT_EXPIRED"
        if not validation.verification_material_available or not validation.assumptions_valid:
            return "VERIFICATION_MATERIAL_UNAVAILABLE"
        requires_key = _RECEIPT_TYPES[receipt.evidence_type][2]
        if requires_key and not validation.credential_valid_at_event:
            return "CREDENTIAL_INVALID_AT_EVENT"
        if requires_key and not validation.authenticator_valid:
            return "INVALID_AUTHENTICATOR"
        if _RECEIPT_TYPES[receipt.evidence_type][3] and not validation.anchor_valid:
            return "INVALID_OR_MISSING_ANCHOR"
        return None
