"""Versioned, lossless validation facts shared by network and certificate paths.

The transport's backend name is deliberately not a decision fact. Every other
BackendValidation field is authenticated, including negative facts and diagnostics.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import Mapping

from evidence.models import BackendValidation

SCHEMA = "verclo.validation-decision.v2"
BOOLEAN_FIELDS = (
    "verification_material_available", "credential_valid_at_event",
    "authenticator_valid", "anchor_valid", "ordering_support_valid",
    "mechanism_present", "mechanism_valid", "assumptions_valid",
)
FIELDS = frozenset((*BOOLEAN_FIELDS, "schema", "mechanism_expires_at", "diagnostics"))


def decision_from_wire(name: str, value: Mapping[str, object]) -> BackendValidation:
    if not isinstance(value, Mapping) or set(value) != FIELDS or value.get("schema") != SCHEMA:
        raise ValueError("unsupported or incomplete validation decision")
    if any(type(value[field]) is not bool for field in BOOLEAN_FIELDS):
        raise ValueError("validation decision requires JSON booleans")
    diagnostics = value["diagnostics"]
    if not isinstance(diagnostics, list) or any(type(v) is not str for v in diagnostics):
        raise ValueError("validation diagnostics must be strings")
    expires = value["mechanism_expires_at"]
    if expires is not None and type(expires) is not str:
        raise ValueError("invalid validation expiry")
    parsed = datetime.fromisoformat(expires) if expires is not None else None
    if parsed is not None and parsed.utcoffset() is None:
        raise ValueError("validation expiry must carry a timezone")
    return BackendValidation(name, **{field: value[field] for field in BOOLEAN_FIELDS},
        mechanism_expires_at=parsed, diagnostics=tuple(diagnostics))


def decision_to_wire(decision: object) -> dict[str, object]:
    expires = getattr(decision, "mechanism_expires_at")
    if expires is not None and not isinstance(expires, datetime):
        raise ValueError("invalid validation expiry")
    diagnostics = getattr(decision, "diagnostics")
    if not isinstance(diagnostics, (list, tuple)):
        raise ValueError("invalid validation diagnostics")
    value = {"schema": SCHEMA,
        **{field: getattr(decision, field) for field in BOOLEAN_FIELDS},
        "mechanism_expires_at": expires.isoformat() if expires is not None else None,
        "diagnostics": list(diagnostics)}
    decision_from_wire("wire-check", value)
    return value


def decision_digest(value: Mapping[str, object]) -> str:
    decision_from_wire("wire-check", value)
    return hashlib.sha256(b"VERCLO-VALIDATION-DECISION-v2\x00" +
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
