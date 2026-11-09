"""Deterministic PBFT certificate client with explicit distributed faults."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from evidence.models import CustodianReceipt
from proof.validation_backend import PBFTValidationBackend, PBFTValidationCertificate
from verclo.models import Obligation


@dataclass(frozen=True)
class PBFTFaultProfile:
    crashed_validator_ids: tuple[str, ...] = ()
    partitioned_validator_ids: tuple[str, ...] = ()
    withholding_validator_ids: tuple[str, ...] = ()
    byzantine_validator_ids: tuple[str, ...] = ()
    commitment_equivocation: bool = False
    duplicate_validator_identity: bool = False


class SimulatedPBFTClient:
    """Produces certificates after deterministic crash/partition/equivocation faults.

    This is a certificate-boundary simulator, not a network or consensus
    implementation. Byzantine validators that approve the correct commitment
    remain eligible approvers; withholding is represented separately.
    """

    def __init__(
        self,
        validator_ids: tuple[str, ...],
        fault_profile: PBFTFaultProfile | None = None,
        *,
        authenticator_valid: bool = True,
        credential_valid_at_event: bool = True,
        anchor_valid: bool = True,
        ordering_support_valid: bool = True,
        mechanism_present: bool = False,
        mechanism_valid: bool = False,
        mechanism_expires_at: datetime | None = None,
    ) -> None:
        if not validator_ids:
            raise ValueError("validator_ids cannot be empty")
        if len(set(validator_ids)) != len(validator_ids):
            raise ValueError("configured validator_ids must be unique")
        fault_profile = fault_profile or PBFTFaultProfile()
        declared = set(validator_ids)
        referenced = (
            set(fault_profile.crashed_validator_ids)
            | set(fault_profile.partitioned_validator_ids)
            | set(fault_profile.withholding_validator_ids)
            | set(fault_profile.byzantine_validator_ids)
        )
        unknown = tuple(sorted(referenced - declared))
        if unknown:
            raise ValueError(f"fault profile references unknown validators: {unknown}")
        self.validator_ids = validator_ids
        self.fault_profile = fault_profile
        self.authenticator_valid = authenticator_valid
        self.credential_valid_at_event = credential_valid_at_event
        self.anchor_valid = anchor_valid
        self.ordering_support_valid = ordering_support_valid
        self.mechanism_present = mechanism_present
        self.mechanism_valid = mechanism_valid
        self.mechanism_expires_at = mechanism_expires_at

    def validate_receipt(
        self,
        receipt: CustodianReceipt,
        obligation: Obligation,
        evaluation_time: datetime,
    ) -> PBFTValidationCertificate:
        del obligation, evaluation_time
        profile = self.fault_profile
        unavailable = (
            set(profile.crashed_validator_ids)
            | set(profile.partitioned_validator_ids)
            | set(profile.withholding_validator_ids)
        )
        approvals = tuple(row for row in self.validator_ids if row not in unavailable)
        validators = self.validator_ids
        if profile.duplicate_validator_identity and len(validators) > 1:
            validators = validators[:-1] + (validators[-2],)
        receipt_commitment = PBFTValidationBackend.receipt_commitment(receipt)
        if profile.commitment_equivocation:
            receipt_commitment = "0" * 64
        return PBFTValidationCertificate(
            receipt_commitment=receipt_commitment,
            validator_ids=validators,
            approving_validator_ids=approvals,
            authenticator_valid=self.authenticator_valid,
            credential_valid_at_event=self.credential_valid_at_event,
            anchor_valid=self.anchor_valid,
            ordering_support_valid=self.ordering_support_valid,
            mechanism_present=self.mechanism_present,
            mechanism_valid=self.mechanism_valid,
            mechanism_expires_at=self.mechanism_expires_at,
        )
