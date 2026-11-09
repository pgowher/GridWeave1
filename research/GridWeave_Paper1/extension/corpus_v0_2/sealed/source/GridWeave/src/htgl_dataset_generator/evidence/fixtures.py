"""Typed evaluator-only fixtures supporting locked evidence receipt rows."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MerkleProofStep:
    sibling_digest: str
    sibling_position: str


@dataclass(frozen=True)
class SyntheticKeyFixture:
    key_id: str
    key_role: str
    subject_actor_id: str
    primitive: str
    algorithm: str
    public_key_hex: str | None
    secret_material_sha256: str


@dataclass(frozen=True)
class SyntheticAnchorFixture:
    anchor_id: str
    anchor_profile_id: str
    algorithm: str
    root_digest: str
    leaf_count: int


@dataclass(frozen=True)
class EvidenceReceiptFixture:
    receipt_id: str
    case_type: str
    coverage_member_id: str
    canonical_payload_hex: str
    authenticator_hex: str
    claimed_key_id: str | None
    actual_key_id: str | None
    merkle_path: tuple[MerkleProofStep, ...]
    contradiction_group_id: str | None


@dataclass(frozen=True)
class AdversarialReceiptCase:
    case_id: str
    case_type: str
    obligation_id: str
    coverage_member_id: str
    receipt_ids: tuple[str, ...]
    omission_reason: str | None

