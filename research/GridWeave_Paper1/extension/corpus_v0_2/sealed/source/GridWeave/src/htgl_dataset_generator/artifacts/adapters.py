"""Deterministic Parquet writer for sanitized observer release views."""

from __future__ import annotations

from datetime import datetime
import hashlib
import os
from pathlib import Path
import re
from typing import Any, Mapping

from htgl_dataset_generator.observers import ObserverReleaseView

from .canonical import canonical_json_text


SAFE_PROFILE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def write_observer_projection_parquet(
    view_key: str,
    view: ObserverReleaseView,
    root: Path,
    *,
    compression_level: int,
) -> Path:
    """Write one sanitized observer release as deterministic Parquet/ZSTD."""

    pa, pq = _require_pyarrow()
    token = _view_token(view_key)
    output = root / "observers" / view.access_class / token / "observer_release.parquet"
    output.parent.mkdir(parents=True, exist_ok=True)
    base_schema = pa.schema(
        [
            pa.field("observer_record_id", pa.string(), nullable=False),
            pa.field("observer_ref", pa.string(), nullable=False),
            pa.field("projection_profile_id", pa.string(), nullable=False),
            pa.field("visible_timestamp", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("visibility_class", pa.dictionary(pa.int32(), pa.string()), nullable=False),
            pa.field("redacted_field_paths", pa.list_(pa.string()), nullable=False),
            pa.field("schema_profile_id", pa.string(), nullable=False),
            pa.field("payload_json", pa.string(), nullable=False),
            pa.field("projection_digest", pa.binary(32), nullable=False),
        ]
    )
    fingerprint = hashlib.sha256(base_schema.serialize().to_pybytes()).hexdigest()
    schema_id = f"htgl.observer.release.{view.schema_profile_id}"
    schema = base_schema.with_metadata(
        {
            b"htgl.schema_id": schema_id.encode("ascii"),
            b"htgl.schema_version": b"1.0.0",
            b"htgl.schema_fingerprint": fingerprint.encode("ascii"),
            b"htgl.privacy_class": view.access_class.encode("ascii"),
            b"htgl.compression": b"ZSTD",
        }
    )
    rows = sorted((_release_row(record) for record in view.records), key=lambda row: row["observer_record_id"])
    table = pa.Table.from_pylist(rows, schema=schema)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        pq.write_table(
            table,
            temporary,
            compression="ZSTD",
            compression_level=compression_level,
            version="2.6",
            data_page_version="1.0",
            use_dictionary=True,
            write_statistics=True,
            use_compliant_nested_type=True,
        )
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        temporary.replace(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return output


def _release_row(record: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "observer_record_id",
        "observer_ref",
        "projection_profile_id",
        "visible_timestamp",
        "visibility_class",
        "redacted_field_paths",
        "schema_profile_id",
        "payload",
        "projection_digest",
    }
    if set(record) != expected:
        raise ValueError(
            f"sanitized observer release fields mismatch missing={sorted(expected-set(record))} extra={sorted(set(record)-expected)}"
        )
    digest = bytes.fromhex(str(record["projection_digest"]))
    if len(digest) != 32:
        raise ValueError("observer projection digest must contain 32 bytes")
    timestamp = datetime.fromisoformat(str(record["visible_timestamp"]).replace("Z", "+00:00"))
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("observer visible_timestamp must be timezone-aware")
    return {
        "observer_record_id": str(record["observer_record_id"]),
        "observer_ref": str(record["observer_ref"]),
        "projection_profile_id": str(record["projection_profile_id"]),
        "visible_timestamp": timestamp,
        "visibility_class": str(record["visibility_class"]),
        "redacted_field_paths": list(record["redacted_field_paths"]),
        "schema_profile_id": str(record["schema_profile_id"]),
        "payload_json": canonical_json_text(record["payload"]),
        "projection_digest": digest,
    }


def _view_token(value: str) -> str:
    if not SAFE_PROFILE.fullmatch(value):
        raise ValueError(f"unsafe observer view key {value!r}")
    return value.replace(":", "__")


def _require_pyarrow():
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("pyarrow is required for observer projection Parquet output") from exc
    return pa, pq
