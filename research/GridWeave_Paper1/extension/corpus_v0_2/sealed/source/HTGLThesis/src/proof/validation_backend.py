"""Replaceable validation backends, including a PBFT certificate adapter."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import base64
import hashlib
import json
from typing import Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from evidence.models import BackendValidation, CustodianReceipt
from verclo.canonical import commitment
from verclo.models import Obligation
from .decision_wire import decision_to_wire, decision_digest


class DeterministicValidationBackend:
    """A reproducible backend for conformance tests and offline verification."""

    name = "deterministic-local-v1"

    def __init__(
        self,
        validations: Mapping[str, BackendValidation] | None = None,
        *,
        allow_unlisted_for_tests: bool = False,
    ) -> None:
        self._validations = dict(validations or {})
        self._allow_unlisted_for_tests = allow_unlisted_for_tests

    def validate(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> BackendValidation:
        del obligation, evaluation_time
        supplied = self._validations.get(receipt.receipt_id)
        if supplied is None:
            if self._allow_unlisted_for_tests:
                return BackendValidation(
                    backend_name=self.name,
                    diagnostics=("EXPLICIT_TEST_ONLY_DEFAULT",),
                )
            return BackendValidation(
                backend_name=self.name,
                verification_material_available=False,
                assumptions_valid=False,
                diagnostics=("VALIDATION_RECORD_NOT_FOUND",),
            )
        return BackendValidation(
            backend_name=self.name,
            verification_material_available=supplied.verification_material_available,
            credential_valid_at_event=supplied.credential_valid_at_event,
            authenticator_valid=supplied.authenticator_valid,
            anchor_valid=supplied.anchor_valid,
            ordering_support_valid=supplied.ordering_support_valid,
            mechanism_present=supplied.mechanism_present,
            mechanism_valid=supplied.mechanism_valid,
            mechanism_expires_at=supplied.mechanism_expires_at,
            assumptions_valid=supplied.assumptions_valid,
            diagnostics=supplied.diagnostics,
        )


def committee_digest(keys: Mapping[str, bytes]) -> str:
    if not keys or any(type(k) is not str or not k or type(v) is not bytes or len(v) != 32
                       for k, v in keys.items()):
        raise ValueError("invalid committee public keys")
    payload = {k: base64.urlsafe_b64encode(v).rstrip(b"=").decode() for k, v in keys.items()}
    return hashlib.sha256(b"VERCLO-PBFT-COMMITTEE-v2\x00" +
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class PBFTSignedVote:
    """An authenticated PBFT vote bound to one proposal and result."""

    validator_id: str
    phase: str
    view: int
    sequence: int
    receipt_commitment: str
    decision_commitment: str
    signature: str
    membership_epoch: str = ""
    committee_digest: str = ""

    def signing_bytes(self) -> bytes:
        payload = {
            "decision_commitment": self.decision_commitment,
            "membership_epoch": self.membership_epoch,
            "committee_digest": self.committee_digest,
            "phase": self.phase,
            "receipt_commitment": self.receipt_commitment,
            "sequence": self.sequence,
            "validator_id": self.validator_id,
            "view": self.view,
        }
        return b"VERCLO-PBFT-VOTE-v2\x00" + json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


@dataclass(frozen=True)
class PBFTValidationCertificate:
    receipt_commitment: str
    validator_ids: tuple[str, ...]
    approving_validator_ids: tuple[str, ...]
    authenticator_valid: bool
    credential_valid_at_event: bool
    anchor_valid: bool
    ordering_support_valid: bool
    mechanism_present: bool = False
    mechanism_valid: bool = False
    mechanism_expires_at: datetime | None = None
    view: int = 0
    sequence: int = 0
    membership_epoch: str = ""
    signed_commit_votes: tuple[PBFTSignedVote, ...] = ()
    verification_material_available: bool = True
    assumptions_valid: bool = True
    diagnostics: tuple[str, ...] = ()
    signed_finalize_votes: tuple[PBFTSignedVote, ...] = ()


class PBFTValidationClient(Protocol):
    def validate_receipt(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> PBFTValidationCertificate: ...


class PBFTValidationBackend:
    """Adapts PBFT voting to the same evidence-validation boundary.

    The adapter validates the standard n >= 3f+1 assumption, unique validator
    identities, a 2f+1 quorum, and receipt commitment agreement before exposing
    any cryptographic result to the evidence layer.
    """

    name = "pbft-certificate-v2"

    def __init__(
        self,
        client: PBFTValidationClient,
        validator_count: int,
        fault_tolerance: int,
        *,
        validator_public_keys: Mapping[str, bytes] | None = None,
        membership_epoch: str | None = None,
        require_signed_votes: bool = False,
    ) -> None:
        if fault_tolerance < 0 or validator_count < 1:
            raise ValueError("validator_count and fault_tolerance must be non-negative")
        self.client = client
        self.validator_count = validator_count
        self.fault_tolerance = fault_tolerance
        self.validator_public_keys = dict(validator_public_keys or {})
        self.membership_epoch = membership_epoch
        self.require_signed_votes = require_signed_votes
        if require_signed_votes or self.validator_public_keys:
            committee_digest(self.validator_public_keys)
            if len(set(self.validator_public_keys.values())) != len(self.validator_public_keys):
                raise ValueError("committee signing keys must be distinct")
            if validator_count != 3 * fault_tolerance + 1:
                raise ValueError("signed PBFT requires n = 3f + 1")
            if type(membership_epoch) is not str or not membership_epoch:
                raise ValueError("signed PBFT requires an expected epoch")

    @staticmethod
    def receipt_commitment(receipt: CustodianReceipt) -> str:
        return commitment("verclo-custodian-receipt-v1", receipt)

    @staticmethod
    def decision_commitment(certificate: PBFTValidationCertificate) -> str:
        return decision_digest(decision_to_wire(certificate))

    def _signed_votes_valid(
        self, certificate: PBFTValidationCertificate, validators: set[str]
    ) -> tuple[bool, tuple[str, ...]]:
        votes = certificate.signed_commit_votes
        if not votes:
            if self.require_signed_votes or self.validator_public_keys:
                return False, ("PBFT_SIGNED_VOTES_MISSING",)
            return True, ()
        diagnostics: list[str] = []
        expected_decision = self.decision_commitment(certificate)
        vote_ids = [vote.validator_id for vote in votes]
        if len(vote_ids) != len(set(vote_ids)):
            diagnostics.append("PBFT_DUPLICATE_SIGNED_VOTE")
        if set(vote_ids) != set(certificate.approving_validator_ids):
            diagnostics.append("PBFT_APPROVAL_VOTE_SET_MISMATCH")
        if not self.validator_public_keys or set(self.validator_public_keys) != validators:
            diagnostics.append("PBFT_MEMBERSHIP_KEYS_INVALID")
        if self.membership_epoch is not None and certificate.membership_epoch != self.membership_epoch:
            diagnostics.append("PBFT_MEMBERSHIP_EPOCH_MISMATCH")
        expected_committee = committee_digest(self.validator_public_keys) if self.validator_public_keys else ""
        if not certificate.membership_epoch:
            diagnostics.append("PBFT_MEMBERSHIP_EPOCH_MISSING")
        if type(certificate.view) is not int or certificate.view < 0 or type(certificate.sequence) is not int or certificate.sequence < 1:
            diagnostics.append("PBFT_CERTIFICATE_POSITION_INVALID")
        for vote in votes:
            if (
                type(vote.view) is not int or type(vote.sequence) is not int
                or vote.membership_epoch != certificate.membership_epoch
                or vote.committee_digest != expected_committee
                or vote.phase != "COMMIT"
                or vote.view != certificate.view
                or vote.sequence != certificate.sequence
                or vote.receipt_commitment != certificate.receipt_commitment
                or vote.decision_commitment != expected_decision
                or vote.validator_id not in validators
            ):
                diagnostics.append("PBFT_VOTE_BINDING_INVALID")
                continue
            key_bytes = self.validator_public_keys.get(vote.validator_id)
            if key_bytes is None:
                continue
            try:
                if "=" in vote.signature:
                    raise ValueError("non-canonical signature")
                signature = base64.b64decode(
                    vote.signature + "=" * (-len(vote.signature) % 4),
                    altchars=b"-_",
                    validate=True,
                )
                encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
                if encoded != vote.signature:
                    raise ValueError("non-canonical signature")
                Ed25519PublicKey.from_public_bytes(key_bytes).verify(
                    signature, vote.signing_bytes()
                )
            except (InvalidSignature, ValueError):
                diagnostics.append("PBFT_VOTE_SIGNATURE_INVALID")
        return not diagnostics, tuple(dict.fromkeys(diagnostics))

    def _finalization_valid(self, certificate: PBFTValidationCertificate) -> bool:
        if not self.require_signed_votes and not certificate.signed_commit_votes and not self.validator_public_keys:
            return True  # Explicit offline certificate model, never the network mode.
        votes = certificate.signed_finalize_votes
        quorum = 2 * self.fault_tolerance + 1
        seen: set[str] = set()
        expected = self.decision_commitment(certificate)
        context = committee_digest(self.validator_public_keys) if self.validator_public_keys else ""
        for vote in votes:
            if (type(vote.view) is not int or type(vote.sequence) is not int
                or vote.validator_id in seen or vote.validator_id not in self.validator_public_keys
                or vote.phase != "FINALIZE" or vote.view != certificate.view
                or vote.sequence != certificate.sequence
                or vote.membership_epoch != certificate.membership_epoch
                or vote.committee_digest != context
                or vote.receipt_commitment != certificate.receipt_commitment
                or vote.decision_commitment != expected):
                return False
            try:
                if "=" in vote.signature:
                    return False
                raw = base64.b64decode(vote.signature + "=" * (-len(vote.signature) % 4), altchars=b"-_", validate=True)
                if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != vote.signature:
                    return False
                Ed25519PublicKey.from_public_bytes(self.validator_public_keys[vote.validator_id]).verify(raw, vote.signing_bytes())
            except (ValueError, InvalidSignature):
                return False
            seen.add(vote.validator_id)
        return len(seen) >= quorum

    def validate(
        self, receipt: CustodianReceipt, obligation: Obligation, evaluation_time: datetime
    ) -> BackendValidation:
        assumptions_valid = self.validator_count >= (3 * self.fault_tolerance + 1)
        if not assumptions_valid:
            return BackendValidation(
                backend_name=self.name,
                verification_material_available=False,
                assumptions_valid=False,
                diagnostics=("PBFT_N_LT_3F_PLUS_1",),
            )
        certificate = self.client.validate_receipt(receipt, obligation, evaluation_time)
        try:
            decision_to_wire(certificate)
        except (ValueError, TypeError, AttributeError):
            return BackendValidation(self.name, verification_material_available=False,
                assumptions_valid=False, diagnostics=("PBFT_DECISION_INVALID",))
        validators = set(certificate.validator_ids)
        approvals = set(certificate.approving_validator_ids)
        quorum = 2 * self.fault_tolerance + 1
        commitment_matches = certificate.receipt_commitment == self.receipt_commitment(receipt)
        identities_valid = (
            len(validators) == len(certificate.validator_ids)
            and len(validators) == self.validator_count
            and len(approvals) == len(certificate.approving_validator_ids)
            and approvals <= validators
        )
        signed_votes_valid, signed_vote_diagnostics = self._signed_votes_valid(
            certificate, validators
        )
        finalization_valid = self._finalization_valid(certificate)
        certificate_valid = (
            identities_valid
            and len(approvals) >= quorum
            and commitment_matches
            and signed_votes_valid
            and finalization_valid
        )
        diagnostics: list[str] = []
        if not identities_valid:
            diagnostics.append("PBFT_VALIDATOR_SET_INVALID")
        if len(approvals) < quorum:
            diagnostics.append("PBFT_QUORUM_NOT_REACHED")
        if not commitment_matches:
            diagnostics.append("PBFT_RECEIPT_COMMITMENT_MISMATCH")
        diagnostics.extend(signed_vote_diagnostics)
        if not finalization_valid:
            diagnostics.append("PBFT_DURABLE_FINALIZATION_QUORUM_MISSING")
        diagnostics.extend(certificate.diagnostics)
        return BackendValidation(
            backend_name=self.name,
            verification_material_available=certificate_valid and certificate.verification_material_available,
            credential_valid_at_event=certificate.credential_valid_at_event,
            authenticator_valid=certificate.authenticator_valid,
            anchor_valid=certificate.anchor_valid,
            ordering_support_valid=certificate.ordering_support_valid,
            mechanism_present=certificate.mechanism_present,
            mechanism_valid=certificate.mechanism_valid,
            mechanism_expires_at=certificate.mechanism_expires_at,
            assumptions_valid=assumptions_valid and certificate.assumptions_valid,
            diagnostics=tuple(diagnostics),
        )
