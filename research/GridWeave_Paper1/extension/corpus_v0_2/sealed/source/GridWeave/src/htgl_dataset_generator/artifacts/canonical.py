"""Canonical byte, digest, and Parquet metadata utilities for S15."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

from htgl_dataset_generator._atomic import atomic_replace
from typing import Any, Mapping

from .models import ArtifactIntegrityError


DIGEST_DOMAIN_PREFIX = b"HTGL-DATASET-GENERATOR\x00S15\x00"


def normalize_canonical_value(value: Any) -> Any:
    if is_dataclass(value):
        return normalize_canonical_value(asdict(value))
    if isinstance(value, Mapping):
        return {
            str(key): normalize_canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [normalize_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [normalize_canonical_value(item) for item in value]
        return sorted(normalized, key=canonical_json_text)
    if isinstance(value, bytes):
        return {"__bytes_hex__": value.hex()}
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ArtifactIntegrityError("canonical timestamps must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ArtifactIntegrityError("canonical payloads cannot contain NaN or infinity")
        return 0.0 if value == 0.0 else value
    return value


def canonical_json_text(value: Any) -> str:
    return json.dumps(
        normalize_canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_json_bytes(value: Any) -> bytes:
    return (canonical_json_text(value) + "\n").encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def domain_sha256(domain: str, value: Any) -> str:
    if not domain or "\x00" in domain:
        raise ValueError("digest domain must be non-empty and cannot contain NUL")
    hasher = hashlib.sha256()
    hasher.update(DIGEST_DOMAIN_PREFIX)
    hasher.update(domain.encode("ascii"))
    hasher.update(b"\x00")
    hasher.update(canonical_json_bytes(value))
    return hasher.hexdigest()


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        atomic_replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def read_parquet_metadata(path: Path) -> tuple[str, str, int, int]:
    """Return schema ID, fingerprint, rows, and encoded uncompressed bytes."""

    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ArtifactIntegrityError(
            "pyarrow is required to inspect authoritative Parquet artifacts"
        ) from exc
    parquet_file = pq.ParquetFile(path)
    try:
        metadata = parquet_file.schema_arrow.metadata or {}
        schema_id = (
            metadata.get(b"schema_id") or metadata.get(b"htgl.schema_id") or b""
        ).decode("utf-8")
        fingerprint = (
            metadata.get(b"schema_fingerprint")
            or metadata.get(b"htgl.schema_fingerprint")
            or b""
        ).decode("utf-8")
        if not schema_id or not fingerprint:
            raise ArtifactIntegrityError(
                f"Parquet artifact {path} lacks schema ID or schema fingerprint metadata"
            )
        uncompressed = 0
        for row_group_index in range(parquet_file.metadata.num_row_groups):
            row_group = parquet_file.metadata.row_group(row_group_index)
            for column_index in range(row_group.num_columns):
                column = row_group.column(column_index)
                if column.compression != "ZSTD":
                    raise ArtifactIntegrityError(
                        f"Parquet artifact {path} contains non-ZSTD column compression"
                    )
                uncompressed += int(column.total_uncompressed_size)
        return schema_id, fingerprint, int(parquet_file.metadata.num_rows), uncompressed
    finally:
        parquet_file.close()


def fsync_directory(path: Path) -> None:
    """Persist a directory entry on platforms that expose directory fsync."""

    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
