"""Deterministic identifiers and commitments over metadata-only structures."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Any


def _normalise(value: Any) -> Any:
    if is_dataclass(value):
        return _normalise(asdict(value))
    if isinstance(value, dict):
        return {str(key): _normalise(child) for key, child in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_normalise(child) for child in value]
    if isinstance(value, datetime):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_normalise(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def commitment(domain: str, value: Any) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(canonical_bytes(value))
    return digest.hexdigest()


def content_id(prefix: str, domain: str, value: Any) -> str:
    return f"{prefix}-{commitment(domain, value)[:32].upper()}"
