"""Canonical artifact construction shared by PaEGen boundary modules."""

from __future__ import annotations

from typing import Any, Mapping

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex

from .models import PaEGenArtifact


def artifact(schema_id: str, payload: Mapping[str, Any]) -> PaEGenArtifact:
    normalized = dict(payload)
    return PaEGenArtifact(
        schema_id=schema_id,
        payload=normalized,
        sha256=sha256_hex(canonical_json_bytes(normalized)),
    )

