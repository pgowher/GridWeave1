"""Atomic Parquet/ZSTD writer for executable P8 comparison artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.baselines.models import BaselineStudyBuild

from .parquet import ParquetDependencyError


@dataclass(frozen=True)
class BaselineArtifactWriteResult:
    files: Mapping[str, Path]
    metadata_overrides: Mapping[str, Mapping[str, Any]]


def write_baseline_artifact_bundle(
    build: BaselineStudyBuild,
    output_dir: str | os.PathLike[str],
) -> BaselineArtifactWriteResult:
    """Write non-empty condition, metric, comparison, and evaluator sample ledgers."""

    if not build.conditions or not build.metrics or not build.comparisons or not build.output_samples:
        raise ValueError("baseline artifact bundle requires complete non-empty study ledgers")
    root = Path(output_dir)
    definitions = (
        (
            "metrics/baseline_conditions.parquet",
            _condition_schema(),
            [asdict(item) for item in build.conditions],
            "restricted",
            False,
        ),
        (
            "metrics/baseline_metrics.parquet",
            _metric_schema(),
            [asdict(item) for item in build.metrics],
            "public",
            True,
        ),
        (
            "metrics/baseline_comparisons.parquet",
            _comparison_schema(),
            [asdict(item) for item in build.comparisons],
            "public",
            True,
        ),
        (
            "truth/evaluator_only/baselines/baseline_output_samples.parquet",
            _sample_schema(),
            [asdict(item) for item in build.output_samples],
            "evaluator_only",
            False,
        ),
    )
    files: dict[str, Path] = {}
    overrides: dict[str, Mapping[str, Any]] = {}
    for relative, schema, records, privacy, publication_eligible in definitions:
        path = root / relative
        _write_custom_parquet(path, schema, records)
        files[relative] = path
        overrides[relative] = {
            "privacy_class": privacy,
            "generation_stage": "P8_baselines_and_ablations",
            "publication_eligible": publication_eligible,
        }
    registry_payload = {
        "format": "htgl.baseline-profile-registry.release-view.v1",
        "registry_id": build.registry.registry_id,
        "version": build.registry.version,
        "source": build.registry.source,
        "source_sha256": build.registry.sha256,
        "profile_count": len(build.registry.profiles),
        "profiles": [asdict(item) for _, item in sorted(build.registry.profiles.items())],
        "negative_control_claim_eligible": False,
        "authoritative_storage": "parquet_zstd",
        "json_authority": False,
    }
    registry_relative = "metrics/baseline_registry.json"
    registry_path = root / registry_relative
    _atomic_write(registry_path, _canonical_json_bytes(registry_payload))
    files[registry_relative] = registry_path
    overrides[registry_relative] = {
        "privacy_class": "public",
        "generation_stage": "P8_baselines_and_ablations",
        "publication_eligible": True,
    }
    metadata_payload = {
        "format": "htgl.baseline-artifact-bundle.v1",
        "registry_id": build.registry.registry_id,
        "registry_sha256": build.registry.sha256,
        "condition_count": len(build.conditions),
        "metric_count": len(build.metrics),
        "paired_comparison_count": len(build.comparisons),
        "evaluator_sample_count": len(build.output_samples),
        "authoritative_storage": "parquet_zstd",
        "json_authority": False,
        "pairing_contract": "common_random_group_and_independent_full_pipeline_replicate_id",
        "claim_boundary": (
            "Controls compare generated benchmark artifacts. They do not establish legal "
            "compliance, physical deletion, operational HTGL execution, or materialization "
            "of represented population N. Ineligible sampling controls emit no population estimate."
        ),
        "files": [
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "stored_bytes": path.stat().st_size,
            }
            for relative, path in sorted(files.items())
        ],
    }
    metadata_relative = "metrics/baseline_metadata.json"
    metadata_path = root / metadata_relative
    _atomic_write(metadata_path, _canonical_json_bytes(metadata_payload))
    files[metadata_relative] = metadata_path
    overrides[metadata_relative] = {
        "privacy_class": "public",
        "generation_stage": "P8_baselines_and_ablations",
        "publication_eligible": True,
    }
    return BaselineArtifactWriteResult(
        files=dict(sorted(files.items())),
        metadata_overrides=dict(sorted(overrides.items())),
    )


def _condition_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.baselines.condition-output.v1",
        "restricted",
        [
            ("condition_output_id", pa.string(), False), ("run_id", pa.string(), False),
            ("scenario_id", pa.string(), False), ("replicate_id", pa.int32(), False),
            ("profile_id", pa.string(), False), ("family", pa.string(), False),
            ("role", pa.string(), False), ("mechanism", pa.string(), False),
            ("common_random_group", pa.string(), False), ("seed_stream_name", pa.string(), False),
            ("registry_id", pa.string(), False), ("registry_version", pa.string(), False),
            ("registry_sha256", pa.string(), False), ("represented_population", pa.int64(), False),
            ("materialized_row_budget", pa.int64(), False), ("executed_operation_count", pa.int64(), True),
            ("source_record_count", pa.int64(), False), ("output_record_count", pa.int64(), False),
            ("output_digest", pa.string(), False), ("claim_eligible", pa.bool_(), False),
            ("exclusion_reason", pa.string(), True), ("parameters_json", pa.string(), False),
            ("diagnostics_json", pa.string(), False),
        ],
    )


def _metric_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.baselines.metric-observation.v1",
        "public",
        [
            ("metric_observation_id", pa.string(), False), ("run_id", pa.string(), False),
            ("scenario_id", pa.string(), False), ("replicate_id", pa.int32(), False),
            ("profile_id", pa.string(), False), ("family", pa.string(), False),
            ("role", pa.string(), False), ("metric_name", pa.string(), False),
            ("value", pa.float64(), False), ("unit", pa.string(), False),
            ("numerator", pa.float64(), True), ("denominator", pa.float64(), True),
            ("estimator", pa.string(), False), ("weighting", pa.string(), False),
            ("common_random_group", pa.string(), False), ("claim_eligible", pa.bool_(), False),
            ("uncertainty_status", pa.string(), False), ("uncertainty_reason", pa.string(), False),
        ],
    )


def _comparison_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.baselines.paired-comparison.v1",
        "public",
        [
            ("comparison_id", pa.string(), False), ("run_id", pa.string(), False),
            ("scenario_id", pa.string(), False), ("family", pa.string(), False),
            ("metric_name", pa.string(), False), ("unit", pa.string(), False),
            ("common_random_group", pa.string(), False), ("comparator_profile_id", pa.string(), False),
            ("proposed_profile_id", pa.string(), False), ("comparator_role", pa.string(), False),
            ("paired_replicate_ids", pa.list_(pa.int32()), False), ("pair_count", pa.int32(), False),
            ("mean_difference", pa.float64(), False), ("empirical_standard_error", pa.float64(), True),
            ("ci_lower", pa.float64(), True), ("ci_upper", pa.float64(), True),
            ("standardized_effect_size", pa.float64(), True), ("confidence_level", pa.float64(), False),
            ("uncertainty_method", pa.string(), False), ("status", pa.string(), False),
            ("reason", pa.string(), False),
        ],
    )


def _sample_schema() -> Any:
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.baselines.evaluator-output-sample.v1",
        "evaluator_only",
        [
            ("sample_id", pa.string(), False), ("run_id", pa.string(), False),
            ("scenario_id", pa.string(), False), ("replicate_id", pa.int32(), False),
            ("profile_id", pa.string(), False), ("family", pa.string(), False),
            ("output_type", pa.string(), False), ("ordinal", pa.int32(), False),
            ("record_json", pa.string(), False), ("evaluator_only", pa.bool_(), False),
        ],
    )


def _schema(
    pa: Any,
    schema_id: str,
    privacy_class: str,
    fields: Sequence[tuple[str, Any, bool]],
) -> Any:
    base = pa.schema(
        [pa.field(name, data_type, nullable=nullable) for name, data_type, nullable in fields]
    )
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


def _write_custom_parquet(path: Path, schema: Any, records: Sequence[Mapping[str, Any]]) -> None:
    if not records:
        raise ValueError(f"baseline comparison artifact {path.name} must not be empty")
    pa, pq = _require_pyarrow()
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(
        records,
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
    )
    table = pa.Table.from_pylist(ordered, schema=schema)
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


def _require_pyarrow() -> tuple[Any, Any]:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ParquetDependencyError(
            "pyarrow is required for P8 Parquet/ZSTD comparison artifacts"
        ) from exc
    return pa, pq


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


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
