"""Atomic ZSTD Parquet writer for S11 protected truth and release projections."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.observers import ObserverBuild
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract

from .parquet import ParquetDependencyError, write_parquet_table


VIEW_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
RELEASE_COLUMNS = (
    "observer_record_id",
    "observer_ref",
    "projection_profile_id",
    "visible_timestamp",
    "visibility_class",
    "redacted_field_paths",
    "schema_profile_id",
    "payload_json",
    "projection_digest",
)
FORBIDDEN_RELEASE_COLUMNS = frozenset(
    {
        "actor_id",
        "anomaly_instance_id",
        "data_object_id",
        "decision_id",
        "event_id",
        "local_database_id",
        "obligation_id",
        "protected_pair_id",
        "receipt_id",
        "replica_id",
        "source_event_id",
        "workflow_instance_id",
    }
)


@dataclass(frozen=True)
class ObserverViewWriteResult:
    root: Path
    manifest_path: Path
    manifest_sha256: str
    files: Mapping[str, Path]


def write_observer_evaluator_sidecars(
    build: ObserverBuild,
    output_dir: str | os.PathLike[str],
) -> Mapping[str, Path]:
    """Write only S11 evaluator mappings and diagnostics as typed Parquet/ZSTD."""

    root = Path(output_dir)
    specifications = {
        "projection_source_mapping.parquet": (
            _source_mapping_schema(),
            [asdict(item) for item in build.source_mappings],
        ),
        "omission_oracle_truth.parquet": (
            _omission_truth_schema(),
            [asdict(item) for item in build.omission_truth],
        ),
        "task_sufficiency.parquet": (
            _task_result_schema(),
            [asdict(item) for item in build.task_results],
        ),
        "profile_diagnostics.parquet": (
            _diagnostics_schema(),
            [asdict(item) for _, item in sorted(build.diagnostics.items())],
        ),
    }
    written: dict[str, Path] = {}
    for relative, (schema, rows) in sorted(specifications.items()):
        path = root / relative
        ordered = sorted(rows, key=canonical_json)
        _write_custom_parquet(path, schema, ordered)
        written[relative] = path
    return dict(sorted(written.items()))


def write_observer_view_bundle(
    build: ObserverBuild,
    output_dir: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
) -> ObserverViewWriteResult:
    """Write release views separately from evaluator-only projection mappings."""

    if not build.leakage_diagnostics.passed:
        raise ValueError("observer release bundle cannot be written after a non-leakage failure")
    if not build.omission_diagnostics.passed:
        raise ValueError("observer release bundle cannot be written after an omission-oracle failure")
    if any(item.status == "fail" for item in build.task_results):
        raise ValueError("observer release bundle cannot be written after a task-sufficiency failure")

    schema_contract = contract if contract is not None else load_contract()
    root = Path(output_dir) / "observers"
    files: dict[str, Path] = {}

    protected_tables = {
        "evaluator_only/observer_event.parquet": (
            "observer_event",
            build.observer_events,
        ),
        "metrics/run_metric.parquet": ("run_metric", build.run_metrics),
    }
    for relative, (table_name, records) in sorted(protected_tables.items()):
        path = write_parquet_table(
            table_name,
            records,
            root / relative,
            contract=schema_contract,
            compression="ZSTD",
        )
        files[relative] = path

    custom_tables = {
        "evaluator_only/projection_source_mapping.parquet": (
            _source_mapping_schema(),
            [asdict(item) for item in build.source_mappings],
        ),
        "evaluator_only/omission_oracle_truth.parquet": (
            _omission_truth_schema(),
            [asdict(item) for item in build.omission_truth],
        ),
        "evaluator_only/task_sufficiency.parquet": (
            _task_result_schema(),
            [asdict(item) for item in build.task_results],
        ),
        "evaluator_only/profile_diagnostics.parquet": (
            _diagnostics_schema(),
            [asdict(item) for _, item in sorted(build.diagnostics.items())],
        ),
    }
    for relative, (schema, records) in sorted(custom_tables.items()):
        path = root / relative
        _write_custom_parquet(path, schema, records)
        files[relative] = path

    release_inventory: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for view_key, view in sorted(build.release_views.items()):
        if not VIEW_KEY_PATTERN.fullmatch(view_key):
            raise ValueError(f"unsafe observer view key {view_key!r}")
        path_token = view_key.replace(":", "__")
        relative = f"profiles/{path_token}/observer_release.parquet"
        if relative in seen_paths:
            raise ValueError(f"observer view path collision for {view_key!r}")
        seen_paths.add(relative)
        rows = [_release_row(record) for record in view.records]
        path = root / relative
        _write_custom_parquet(path, _release_schema(view.schema_profile_id), rows)
        files[relative] = path
        release_inventory.append(
            {
                "view_key": view_key,
                "profile_id": view.profile_id,
                "access_class": view.access_class,
                "schema_profile_id": view.schema_profile_id,
                "record_count": len(rows),
                "path": relative,
            }
        )

    file_entries = [
        {
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for relative, path in sorted(files.items())
    ]
    manifest = {
        "format": "htgl.observer.projection-bundle.v1",
        "authoritative_storage": "parquet_zstd",
        "json_authority": False,
        "profile_bundle_sha256": build.profile_bundle_sha256,
        "frozen_truth_digest": build.frozen_truth_digest,
        "evaluator_mapping_access_class": "evaluator_only",
        "release_views": release_inventory,
        "non_leakage": {
            "passed": True,
            "scanned_record_count": build.leakage_diagnostics.scanned_record_count,
            "finding_count": len(build.leakage_diagnostics.findings),
        },
        "omission_oracle": {
            "passed": True,
            "evaluated_record_count": build.omission_diagnostics.evaluated_record_count,
        },
        "claim_boundary": (
            "Observer projections and evaluator-only mappings are synthetic benchmark "
            "artifacts; they do not establish deployment visibility, legal compliance, "
            "physical deletion, or operational HTGL capacity."
        ),
        "files": file_entries,
    }
    manifest_path = root / "manifest.json"
    manifest_bytes = _canonical_json_bytes(manifest)
    _atomic_write(manifest_path, manifest_bytes)
    return ObserverViewWriteResult(
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        files=dict(sorted(files.items())),
    )


def _release_row(record: Mapping[str, Any]) -> dict[str, Any]:
    expected = set(RELEASE_COLUMNS) - {"payload_json"}
    if set(record) != expected - {"payload_json"} | {"payload"}:
        raise ValueError(
            f"observer release record fields={sorted(record)} expected={sorted((expected - {'payload_json'}) | {'payload'})}"
        )
    forbidden = set(record) & FORBIDDEN_RELEASE_COLUMNS
    if forbidden:
        raise ValueError(f"observer release record exposes forbidden columns {sorted(forbidden)}")
    projection_digest = str(record["projection_digest"])
    try:
        digest_bytes = bytes.fromhex(projection_digest)
    except ValueError as exc:
        raise ValueError("observer release projection_digest is not hexadecimal") from exc
    if len(digest_bytes) != 32:
        raise ValueError("observer release projection_digest must contain 32 bytes")
    payload_json = canonical_json(record["payload"])
    return {
        "observer_record_id": str(record["observer_record_id"]),
        "observer_ref": str(record["observer_ref"]),
        "projection_profile_id": str(record["projection_profile_id"]),
        "visible_timestamp": _timestamp(str(record["visible_timestamp"])),
        "visibility_class": str(record["visibility_class"]),
        "redacted_field_paths": list(record["redacted_field_paths"]),
        "schema_profile_id": str(record["schema_profile_id"]),
        "payload_json": payload_json,
        "projection_digest": digest_bytes,
    }


def _release_schema(schema_profile_id: str):
    pa, _ = _require_pyarrow()
    return _with_metadata(
        pa.schema(
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
        ),
        f"htgl.observer.release.{schema_profile_id}",
        "public_or_institutional_projection",
    )


def _source_mapping_schema():
    pa, _ = _require_pyarrow()
    string_list = pa.list_(pa.string())
    return _with_metadata(
        pa.schema(
            [
                pa.field("observer_record_id", pa.string(), nullable=False),
                pa.field("observer_actor_id", pa.string(), nullable=False),
                pa.field("projection_profile_id", pa.string(), nullable=False),
                pa.field("source_event_id", pa.string(), nullable=False),
                pa.field("source_workflow_id", pa.string(), nullable=False),
                pa.field("base_visibility_class", pa.string(), nullable=False),
                pa.field("final_visibility_class", pa.string(), nullable=False),
                pa.field("omission_reason", pa.string(), nullable=True),
                pa.field("delay_seconds", pa.int64(), nullable=False),
                pa.field("clock_offset_seconds", pa.int64(), nullable=False),
                pa.field("source_obligation_ids", string_list, nullable=False),
                pa.field("source_receipt_ids", string_list, nullable=False),
                pa.field("independently_valid_receipt_ids", string_list, nullable=False),
                pa.field("source_anomaly_instance_ids", string_list, nullable=False),
                pa.field("protected_pair_ids", string_list, nullable=False),
                pa.field("collusion_member_record_ids", string_list, nullable=False),
                pa.field("source_event_digest", pa.string(), nullable=False),
            ]
        ),
        "htgl.observer.projection-source-mapping.v1",
        "evaluator_only",
    )


def _omission_truth_schema():
    pa, _ = _require_pyarrow()
    return _with_metadata(
        pa.schema(
            [
                pa.field("observer_record_id", pa.string(), nullable=False),
                pa.field("projection_profile_id", pa.string(), nullable=False),
                pa.field("source_event_id", pa.string(), nullable=False),
                pa.field("expected_visibility_class", pa.string(), nullable=False),
                pa.field("observed_visibility_class", pa.string(), nullable=False),
                pa.field("expected_omission_reason", pa.string(), nullable=True),
                pa.field("observed_omission_reason", pa.string(), nullable=True),
                pa.field("expected_visible_timestamp", pa.string(), nullable=False),
                pa.field("observed_visible_timestamp", pa.string(), nullable=False),
                pa.field("matches", pa.bool_(), nullable=False),
            ]
        ),
        "htgl.observer.omission-oracle-truth.v1",
        "evaluator_only",
    )


def _task_result_schema():
    pa, _ = _require_pyarrow()
    return _with_metadata(
        pa.schema(
            [
                pa.field("scenario_id", pa.string(), nullable=False),
                pa.field("replicate_id", pa.int64(), nullable=False),
                pa.field("task_id", pa.string(), nullable=False),
                pa.field("profile_id", pa.string(), nullable=False),
                pa.field("metric_name", pa.string(), nullable=False),
                pa.field("value", pa.float64(), nullable=False),
                pa.field("required_threshold", pa.float64(), nullable=False),
                pa.field("status", pa.string(), nullable=False),
                pa.field("reason", pa.string(), nullable=False),
            ]
        ),
        "htgl.observer.task-sufficiency.v1",
        "evaluator_only",
    )


def _diagnostics_schema():
    pa, _ = _require_pyarrow()
    integer_fields = {
        "replicate_id",
        "source_event_count",
        "visible_event_count",
        "omitted_event_count",
        "projection_payload_bytes",
        "sealed_truth_leakage_count",
    }
    string_fields = {"scenario_id", "profile_id", "mode", "observer_actor_id"}
    ordered_names = (
        "scenario_id", "replicate_id", "profile_id", "mode", "observer_actor_id",
        "source_event_count", "visible_event_count", "omitted_event_count",
        "weighted_visible_event_coverage", "visible_edge_coverage", "evidence_recoverability",
        "anomaly_event_recoverability", "mean_delay_seconds", "p95_delay_seconds",
        "maximum_delay_seconds", "transport_loss_rate", "adversarial_omission_rate",
        "overall_omission_rate", "mean_time_to_detection_seconds", "projection_payload_bytes",
        "collusion_gain", "sealed_truth_leakage_count", "task_sufficiency_rate",
    )
    arrow_fields = []
    for name in ordered_names:
        if name in string_fields:
            data_type = pa.string()
        elif name in integer_fields:
            data_type = pa.int64()
        else:
            data_type = pa.float64()
        arrow_fields.append(pa.field(name, data_type, nullable=False))
    return _with_metadata(
        pa.schema(arrow_fields),
        "htgl.observer.profile-diagnostics.v1",
        "evaluator_only",
    )


def _with_metadata(schema: Any, schema_id: str, privacy_class: str):
    fingerprint = hashlib.sha256(schema.serialize().to_pybytes()).hexdigest()
    return schema.with_metadata(
        {
            b"htgl.schema_id": schema_id.encode("ascii"),
            b"htgl.schema_version": b"1.0.0",
            b"htgl.schema_fingerprint": fingerprint.encode("ascii"),
            b"htgl.privacy_class": privacy_class.encode("ascii"),
            b"htgl.compression": b"ZSTD",
        }
    )


def _write_custom_parquet(path: Path, schema: Any, records: Sequence[Mapping[str, Any]]) -> None:
    pa, pq = _require_pyarrow()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        table = pa.Table.from_pylist(list(records), schema=schema)
    except Exception as exc:
        raise ValueError(f"cannot construct observer sidecar {path.name}: {exc}") from exc
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        pq.write_table(
            table,
            temporary,
            compression="ZSTD",
            compression_level=9,
            version="2.6",
            data_page_version="1.0",
            use_dictionary=True,
            write_statistics=True,
            use_compliant_nested_type=True,
        )
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        atomic_replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _require_pyarrow():
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ParquetDependencyError(
            "pyarrow is required for authoritative observer Parquet output"
        ) from exc
    return pa, pq


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"observer release timestamp is not timezone-aware: {value!r}")
    return parsed


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
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
from htgl_dataset_generator._atomic import atomic_replace
