"""Observer-visible evidence records and verification results for VERCLO."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from verclo.models import Obligation


class ReceiptStatus(StrEnum):
    GRADED = "GRADED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class CustodianReceipt:
    receipt_id: str
    case_id: str
    obligation_id: str
    asset_id: str
    replica_id: str
    repository_id: str
    issuer_principal_id: str
    issuer_role: str
    trust_domain: str
    fault_domain: str
    evidence_type: str
    disposition: str
    event_time: datetime
    submitted_at: datetime
    not_before: datetime
    expires_at: datetime | None = None
    provenance_refs: tuple[str, ...] = ()
    canonical_payload_valid: bool = True
    obligation_bound: bool = True
    claim_commitment: str = ""


@dataclass(frozen=True)
class BackendValidation:
    backend_name: str
    verification_material_available: bool = True
    credential_valid_at_event: bool = True
    authenticator_valid: bool = True
    anchor_valid: bool = False
    ordering_support_valid: bool = False
    mechanism_present: bool = False
    mechanism_valid: bool = False
    mechanism_expires_at: datetime | None = None
    assumptions_valid: bool = True
    diagnostics: tuple[str, ...] = ()


class ReceiptValidationBackend(Protocol):
    """Replaceable boundary for local, anchored, or consensus validation."""

    @property
    def name(self) -> str: ...

    def validate(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> BackendValidation: ...


@dataclass(frozen=True)
class ReceiptVerification:
    receipt: CustodianReceipt
    status: ReceiptStatus
    grade: str | None
    terminal_assertion: bool
    closure_admissible: bool
    timely: bool
    conclusion: str | None
    rejection_reason: str | None
    downgrade_reasons: tuple[str, ...]
    backend_name: str
    backend_validation: BackendValidation
    physical_destruction_concluded: bool = False


@dataclass(frozen=True)
class ExceptionValidation:
    exception_id: str
    authenticated: bool
    basis_integrity_valid: bool
    authority_admitted: bool = True
    diagnostics: tuple[str, ...] = ()
