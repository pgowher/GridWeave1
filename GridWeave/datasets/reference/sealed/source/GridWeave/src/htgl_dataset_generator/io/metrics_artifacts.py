"""Atomic Parquet/ZSTD writer for S14 metrics and statistical sidecars."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.metrics import (
    MetricsBuild,
    PairedMetricComparison,
    ReplicateMetricAggregate,
    validate_metrics_build,
)
from htgl_dataset_generator.schemas import ContractSpec, load_contract

from .parquet import ParquetDependencyError, write_parquet_table


@dataclass(frozen=True)
class MetricsArtifactWriteResult:
    root: Path
    metadata_path: Path
    metadata_sha256: str
    files: Mapping[str, Path]


def write_metrics_artifact_bundle(
    per_replicate: Iterable[MetricsBuild],
    aggregates: Iterable[ReplicateMetricAggregate],
    paired_comparisons: Iterable[PairedMetricComparison],
    output_dir: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
) -> MetricsArtifactWriteResult:
    """Write final run metrics, provenance, execution, replicate, and CRN tables."""

    builds = tuple(per_replicate)
    aggregate_rows = tuple(aggregates)
    comparison_rows = tuple(paired_comparisons)
    if not builds:
        raise ValueError("metrics artifact bundle requires at least one per-replicate build")
    schema_contract = contract if contract is not None else load_contract()
    for build in builds:
        validate_metrics_build(build, contract=schema_contract)
    registry_ids = {(build.registry.registry_id, build.registry.version, build.registry.sha256) for build in builds}
    if len(registry_ids) != 1:
        raise ValueError("metrics artifact bundle cannot mix metric registry versions")
    registry_id, registry_version, registry_sha256 = next(iter(registry_ids))
    run_metrics = tuple(row for build in builds for row in build.run_metrics)
    if len({str(row["metric_id"]) for row in run_metrics}) != len(run_metrics):
        raise ValueError("combined metrics artifact contains duplicate metric IDs")
    root = Path(output_dir) / "metrics"
    files: dict[str, Path] = {}
    files["run_metric.parquet"] = write_parquet_table(
        "run_metric",
        sorted(run_metrics, key=lambda row: str(row["metric_id"])),
        root / "run_metric.parquet",
        contract=schema_contract,
        compression="ZSTD",
    )
    custom = {
        "observation_provenance.parquet": (
            _provenance_schema(),
            [asdict(item) for build in builds for item in build.provenance],
        ),
        "metric_execution.parquet": (
            _execution_schema(),
            [asdict(item) for build in builds for item in build.execution_records],
        ),
        "replicate_summary.parquet": (
            _aggregate_schema(),
            [asdict(item) for item in aggregate_rows],
        ),
        "baselines.parquet": (
            _comparison_schema(),
            [asdict(item) for item in comparison_rows],
        ),
    }
    for relative, (schema, records) in sorted(custom.items()):
        path = root / relative
        _write_custom_parquet(path, schema, records)
        files[relative] = path
    inventory = [
        {
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for relative, path in sorted(files.items())
    ]
    status_counts: dict[str, int] = {}
    for build in builds:
        for record in build.execution_records:
            status_counts[record.status] = status_counts.get(record.status, 0) + 1
    metadata = {
        "format": "htgl.metrics.artifact-bundle.v1",
        "authoritative_storage": "parquet_zstd",
        "json_authority": False,
        "metric_registry_id": registry_id,
        "metric_registry_version": registry_version,
        "metric_registry_sha256": registry_sha256,
        "replicate_count": len(builds),
        "run_metric_count": len(run_metrics),
        "replicate_aggregate_count": len(aggregate_rows),
        "paired_comparison_count": len(comparison_rows),
        "execution_status_counts": dict(sorted(status_counts.items())),
        "uncertainty_contract": (
            "Per-replicate rows retain design-based uncertainty when available; independent "
            "full-pipeline replicate uncertainty is stored in replicate_summary.parquet."
        ),
        "claim_boundary": (
            "Metrics describe generated benchmark artifacts and declared external measurements. "
            "They do not establish legal compliance, real deletion, operational HTGL execution, "
            "ledger anchoring, utility deployment, or materialization of represented population N."
        ),
        "files": inventory,
    }
    payload = (
        json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    metadata_path = root / "metrics_metadata.json"
    _atomic_write(metadata_path, payload)
    return MetricsArtifactWriteResult(
        root=root,
        metadata_path=metadata_path,
        metadata_sha256=hashlib.sha256(payload).hexdigest(),
        files=dict(sorted(files.items())),
    )


def _provenance_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.metrics.observation-provenance.v1",
        "restricted",
        [
            ("metric_id", pa.string(), False), ("metric_key", pa.string(), False),
            ("definition_id", pa.string(), False), ("registry_id", pa.string(), False),
            ("registry_version", pa.string(), False), ("registry_sha256", pa.string(), False),
            ("run_id", pa.string(), False), ("scenario_id", pa.string(), False),
            ("replicate_id", pa.int32(), False), ("scope_id", pa.string(), False),
            ("scope_json", pa.string(), False), ("numerator", pa.float64(), True),
            ("denominator", pa.float64(), True), ("denominator_unit", pa.string(), False),
            ("estimator", pa.string(), False), ("weighting", pa.string(), False),
            ("baseline_id", pa.string(), True), ("replicate_set", pa.list_(pa.int32()), False),
            ("uncertainty_status", pa.string(), False), ("uncertainty_reason", pa.string(), False),
            ("reference_id", pa.string(), True), ("publication_eligible", pa.bool_(), False),
            ("execution_evidence_digest", pa.string(), False),
        ],
    )


def _execution_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.metrics.execution-ledger.v1",
        "restricted",
        [
            ("run_id", pa.string(), False), ("scenario_id", pa.string(), False),
            ("replicate_id", pa.int32(), False), ("metric_key", pa.string(), False),
            ("status", pa.string(), False), ("reason", pa.string(), False),
            ("output_metric_ids", pa.list_(pa.string()), False),
        ],
    )


def _aggregate_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.metrics.replicate-summary.v1",
        "public",
        [
            ("aggregate_id", pa.string(), False), ("run_id", pa.string(), False),
            ("scenario_id", pa.string(), False), ("metric_key", pa.string(), False),
            ("metric_domain", pa.string(), False), ("scope_id", pa.string(), False),
            ("baseline_id", pa.string(), True), ("unit", pa.string(), False),
            ("estimator", pa.string(), False), ("weighting", pa.string(), False),
            ("replicate_ids", pa.list_(pa.int32()), False), ("replicate_count", pa.int32(), False),
            ("mean_value", pa.float64(), False), ("empirical_standard_error", pa.float64(), True),
            ("ci_lower", pa.float64(), True), ("ci_upper", pa.float64(), True),
            ("confidence_level", pa.float64(), False), ("uncertainty_method", pa.string(), False),
            ("uncertainty_status", pa.string(), False), ("uncertainty_reason", pa.string(), False),
        ],
    )


def _comparison_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.metrics.paired-comparison.v1",
        "public",
        [
            ("comparison_id", pa.string(), False), ("metric_key", pa.string(), False),
            ("metric_domain", pa.string(), False), ("scope_id", pa.string(), False),
            ("unit", pa.string(), False), ("estimator", pa.string(), False),
            ("weighting", pa.string(), False), ("common_random_group", pa.string(), False),
            ("baseline_condition_id", pa.string(), False), ("treatment_condition_id", pa.string(), False),
            ("treatment_role", pa.string(), False), ("paired_replicate_ids", pa.list_(pa.int32()), False),
            ("pair_count", pa.int32(), False), ("mean_difference", pa.float64(), False),
            ("empirical_standard_error", pa.float64(), True), ("ci_lower", pa.float64(), True),
            ("ci_upper", pa.float64(), True), ("standardized_effect_size", pa.float64(), True),
            ("effect_size_method", pa.string(), False), ("confidence_level", pa.float64(), False),
            ("uncertainty_method", pa.string(), False), ("status", pa.string(), False),
            ("reason", pa.string(), False),
        ],
    )


def _schema(
    pa: Any,
    schema_id: str,
    privacy_class: str,
    fields: Sequence[tuple[str, Any, bool]],
):
    base = pa.schema([pa.field(name, data_type, nullable=nullable) for name, data_type, nullable in fields])
    fingerprint = hashlib.sha256(base.serialize().to_pybytes()).hexdigest()
    return base.with_metadata(
        {
            b"htgl.schema_id": schema_id.encode("ascii"),
            b"htgl.schema_version": b"1.0.0",
            b"htgl.schema_fingerprint": fingerprint.encode("ascii"),
            b"htgl.privacy_class": privacy_class.encode("ascii"),
            b"htgl.compression": b"ZSTD",
        }
    )


def _write_custom_parquet(
    path: Path,
    schema: Any,
    records: Sequence[Mapping[str, Any]],
) -> None:
    pa, pq = _require_pyarrow()
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(list(records), schema=schema)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as handle:
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
        raise ParquetDependencyError("pyarrow is required for authoritative S14 metric output") from exc
    return pa, pq


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as handle:
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
