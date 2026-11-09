"""Canonical JSON helpers used for exchange commitments."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Any


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical timestamps must be timezone-aware")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(child) for child in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """Return stable UTF-8 JSON with no insignificant whitespace."""

    return (
        json.dumps(
            _json_value(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    """Hash a document using the PaEForge canonical representation."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def domain_digest(domain: str, value: Any) -> str:
    """Domain-separate semantic commitments from raw file hashes."""

    material = domain.encode("utf-8") + b"\x00" + canonical_json_bytes(value)
    return hashlib.sha256(material).hexdigest()


def _verclo_json_value(value: Any) -> Any:
    """Match the frozen VERCLO v1 identifier canonicalization exactly."""

    if is_dataclass(value):
        return _verclo_json_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("VERCLO identifier timestamps must be timezone-aware")
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {
            str(key): _verclo_json_value(child)
            for key, child in sorted(value.items())
        }
    if isinstance(value, (list, tuple)):
        return [_verclo_json_value(child) for child in value]
    return value


def verclo_content_id(prefix: str, domain: str, value: Any) -> str:
    """Create a protocol identifier compatible with frozen VERCLO v1."""

    encoded = json.dumps(
        _verclo_json_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(domain.encode("utf-8") + b"\x00" + encoded).hexdigest()
    return f"{prefix}-{digest[:32].upper()}"


def verclo_obligation_id(
    *,
    case_id: str,
    dataset_id: str,
    correlation_id: str,
    asset_id: str,
    replica_id: str,
    repository_id: str,
    custodian_principal_id: str,
    policy_profile_id: str,
    policy_version: str,
) -> str:
    """Create the shared non-oracular obligation binding used by receipts."""

    return verclo_content_id(
        "OBL",
        "verclo-obligation-v1",
        {
            "case_id": case_id,
            "dataset_id": dataset_id,
            "correlation_id": correlation_id,
            "asset_id": asset_id,
            "replica_id": replica_id,
            "repository_id": repository_id,
            "custodian_principal_id": custodian_principal_id,
            "policy_profile_id": policy_profile_id,
            "policy_version": policy_version,
        },
    )
