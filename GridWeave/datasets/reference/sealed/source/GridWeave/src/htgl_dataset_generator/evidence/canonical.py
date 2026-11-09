"""Domain-separated, schema-bound canonical receipt payload serialization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping, Sequence
import unicodedata

from htgl_dataset_generator.schemas import ContractSpec

from .profiles import ReceiptProfile, ReceiptProfileBundle


CANONICAL_MAGIC = b"HTGL-CANONICAL-TLV-UTC-US-v1\x00"


class CanonicalEvidenceError(ValueError):
    """Raised when canonical evidence facts are ambiguous or unsupported."""


@dataclass(frozen=True)
class ReceiptPayloadFacts:
    receipt_id: str
    obligation_id: str
    evidenced_event_id: str
    triggering_event_id: str
    policy_rule_id: str
    subject_object_id: str
    responsible_actor_id: str
    issuer_actor_id: str
    evidence_type: str
    issued_at: str
    due_at: str
    coverage_scope: str
    covers_replica_ids: tuple[str, ...]


def normalize_utc_timestamp(value: str | datetime) -> str:
    """Return an aware timestamp at stable UTC microsecond precision."""

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CanonicalEvidenceError(f"invalid timestamp {value!r}") from exc
    else:
        raise CanonicalEvidenceError(f"timestamp must be str or datetime, got {type(value).__name__}")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CanonicalEvidenceError("timestamp must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_receipt_payload(
    facts: ReceiptPayloadFacts,
    *,
    profile: ReceiptProfile,
    bundle: ReceiptProfileBundle,
    contract: ContractSpec,
) -> bytes:
    """Serialize all receipt semantics with explicit domain and contract binding."""

    if facts.evidence_type != profile.evidence_type:
        raise CanonicalEvidenceError("receipt evidence type does not match selected profile")
    receipt_table = contract.table("evidence_receipt")
    obligation_table = contract.table("evidence_obligation")
    coverage = _sorted_unique(facts.covers_replica_ids, "covers_replica_ids")
    body = {
        "binding": {
            "canonicalization_profile_id": bundle.canonicalization_profile_id,
            "contract_fingerprint": contract.contract_fingerprint,
            "contract_id": contract.contract_id,
            "contract_version": contract.contract_version,
            "evidence_obligation_schema_fingerprint": obligation_table.schema_fingerprint,
            "evidence_obligation_schema_id": obligation_table.schema_id,
            "evidence_receipt_schema_fingerprint": receipt_table.schema_fingerprint,
            "evidence_receipt_schema_id": receipt_table.schema_id,
            "evidence_receipt_schema_version": receipt_table.schema_version,
            "receipt_profile_bundle_id": bundle.bundle_id,
            "receipt_profile_bundle_sha256": bundle.bundle_sha256,
            "receipt_profile_bundle_version": bundle.version,
            "receipt_profile_id": profile.profile_id,
        },
        "domain": profile.domain,
        "receipt": {
            "coverage_scope": facts.coverage_scope,
            "covers_replica_ids": list(coverage),
            "due_at": normalize_utc_timestamp(facts.due_at),
            "evidence_type": facts.evidence_type,
            "evidenced_event_id": facts.evidenced_event_id,
            "issued_at": normalize_utc_timestamp(facts.issued_at),
            "issuer_actor_id": facts.issuer_actor_id,
            "obligation_id": facts.obligation_id,
            "policy_rule_id": facts.policy_rule_id,
            "receipt_id": facts.receipt_id,
            "responsible_actor_id": facts.responsible_actor_id,
            "subject_object_id": facts.subject_object_id,
            "triggering_event_id": facts.triggering_event_id,
        },
    }
    return CANONICAL_MAGIC + _encode(body)


def canonical_digest(payload: bytes) -> str:
    """Return the SHA-256 digest of exactly the detached canonical bytes."""

    return hashlib.sha256(payload).hexdigest()


def _encode(value: Any) -> bytes:
    if value is None:
        return _frame(b"N", b"")
    if isinstance(value, bool):
        return _frame(b"T" if value else b"F", b"")
    if isinstance(value, int):
        return _frame(b"I", str(value).encode("ascii"))
    if isinstance(value, bytes):
        return _frame(b"B", value)
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        return _frame(b"S", normalized.encode("utf-8"))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        payload = len(value).to_bytes(8, "big") + b"".join(_encode(item) for item in value)
        return _frame(b"L", payload)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) or not key for key in value):
            raise CanonicalEvidenceError("canonical mapping keys must be non-empty strings")
        normalized_keys = [(unicodedata.normalize("NFC", key), key) for key in value]
        if len({item[0] for item in normalized_keys}) != len(normalized_keys):
            raise CanonicalEvidenceError("mapping keys collide after NFC normalization")
        ordered = sorted(normalized_keys, key=lambda item: item[0].encode("utf-8"))
        payload = len(ordered).to_bytes(8, "big")
        for normalized, original in ordered:
            payload += _encode(normalized) + _encode(value[original])
        return _frame(b"M", payload)
    raise CanonicalEvidenceError(f"unsupported canonical type {type(value).__name__}")


def _frame(type_code: bytes, payload: bytes) -> bytes:
    return type_code + len(payload).to_bytes(8, "big") + payload


def _sorted_unique(values: Sequence[str], label: str) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value for value in values):
        raise CanonicalEvidenceError(f"{label} must contain non-empty strings")
    result = tuple(sorted(values))
    if len(set(result)) != len(result):
        raise CanonicalEvidenceError(f"{label} contains duplicates")
    return result
