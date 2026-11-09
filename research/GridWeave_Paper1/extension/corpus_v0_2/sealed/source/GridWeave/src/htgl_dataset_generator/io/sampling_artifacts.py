"""Atomic Parquet writer for S12 sampling truth, provenance, and diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.sampling.models import SamplingBuild
from htgl_dataset_generator.schemas import ContractSpec, load_contract

from .parquet import ParquetDependencyError, write_parquet_table


@dataclass(frozen=True)
class SamplingArtifactWriteResult:
    root: Path
    manifest_path: Path
    manifest_sha256: str
    files: Mapping[str, Path]


def write_sampling_artifact_bundle(
    build: SamplingBuild,
    output_dir: str | os.PathLike[str],
    *,
    contract: ContractSpec | None = None,
) -> SamplingArtifactWriteResult:
    """Write authoritative tables and evaluator-only S12 sidecars as ZSTD Parquet."""

    if any(not item.passed for item in build.known_total_diagnostics):
        raise ValueError("sampling artifacts cannot be written after known-total gate failure")
    if any(item.estimator_eligible for item in build.baselines):
        raise ValueError("ineligible controls cannot be promoted into sampling truth")
    schema_contract = contract if contract is not None else load_contract()
    root = Path(output_dir) / "sampling"
    files: dict[str, Path] = {}
    authoritative = {
        "sampling_design.parquet": ("sampling_design", build.sampling_designs),
        "evaluator_only/sample_membership.parquet": (
            "sample_membership",
            build.sample_memberships,
        ),
        "metrics/run_metric.parquet": ("run_metric", build.run_metrics),
    }
    for relative, (table_name, records) in sorted(authoritative.items()):
        path = write_parquet_table(
            table_name,
            records,
            root / relative,
            contract=schema_contract,
            compression="ZSTD",
        )
        files[relative] = path

    sidecars = {
        "evaluator_only/closure_provenance.parquet": (
            _closure_schema(),
            [asdict(item) for item in build.closure_provenance],
        ),
        "diagnostics/known_total_simulation.parquet": (
            _known_total_schema(),
            [asdict(item) for item in build.known_total_diagnostics],
        ),
        "diagnostics/design_diagnostics.parquet": (
            _design_diagnostics_schema(),
            [asdict(item) for _, item in sorted(build.diagnostics.items())],
        ),
        "baselines/ineligible_controls.parquet": (
            _baseline_schema(),
            [asdict(item) for item in build.baselines],
        ),
    }
    for relative, (schema, records) in sorted(sidecars.items()):
        path = root / relative
        _write_custom_parquet(path, schema, records)
        files[relative] = path

    file_entries = [
        {
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for relative, path in sorted(files.items())
    ]
    manifest = {
        "format": "htgl.sampling.artifact-bundle.v1",
        "authoritative_storage": "parquet_zstd",
        "json_authority": False,
        "frozen_input_digest": build.frozen_input_digest,
        "scale_semantics": dict(build.scale_semantics),
        "sampling_design_count": len(build.sampling_designs),
        "sample_membership_count": len(build.sample_memberships),
        "known_total_gate_passed": True,
        "closure_provenance_access_class": "evaluator_only",
        "population_estimate_policy": (
            "Population estimates exist only for memberships with positive exact "
            "first-order inclusion probabilities and estimator_eligible=true."
        ),
        "claim_boundary": (
            "N is represented population, n is materialized target, and q is only "
            "operations replayed into a downstream implementation when explicitly declared. "
            "Sampling artifacts do not demonstrate HTGL execution or deployment capacity."
        ),
        "files": file_entries,
    }
    manifest_path = root / "manifest.json"
    manifest_bytes = _canonical_json_bytes(manifest)
    _atomic_write(manifest_path, manifest_bytes)
    return SamplingArtifactWriteResult(
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        files=dict(sorted(files.items())),
    )


def _closure_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.sampling.closure-provenance.v1",
        "evaluator_only",
        [
            ("sample_design_id", pa.string()),
            ("unit_id", pa.string()),
            ("unit_type", pa.string()),
            ("selected_causing_primary_unit_ids", pa.list_(pa.string())),
            ("eligible_causing_primary_unit_ids", pa.list_(pa.string())),
            ("closure_policy", pa.string()),
        ],
    )


def _known_total_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.sampling.known-total-diagnostics.v1",
        "restricted",
        [
            ("sample_design_id", pa.string()),
            ("analysis_domain", pa.string()),
            ("estimator_family", pa.string()),
            ("repetitions", pa.int64()),
            ("truth_total", pa.float64()),
            ("actual_estimate", pa.float64()),
            ("mean_estimate", pa.float64()),
            ("empirical_standard_deviation", pa.float64()),
            ("relative_bias", pa.float64()),
            ("relative_rmse", pa.float64()),
            ("ci_coverage", pa.float64()),
            ("confidence_level", pa.float64()),
            ("passed", pa.bool_()),
        ],
    )


def _design_diagnostics_schema():
    pa, _ = _require_pyarrow()
    integer_names = {
        "replicate_id",
        "population_primary_unit_count",
        "selected_primary_unit_count",
        "membership_count",
        "closure_added_count",
        "exact_induced_probability_count",
        "ineligible_membership_count",
    }
    string_names = {
        "sample_design_id",
        "scenario_id",
        "design_type",
        "primary_unit_type",
        "estimator_family",
    }
    names = (
        "sample_design_id", "scenario_id", "replicate_id", "design_type",
        "primary_unit_type", "estimator_family", "population_primary_unit_count",
        "selected_primary_unit_count", "membership_count", "closure_added_count",
        "closure_expansion_factor", "effective_sample_size", "design_effect",
        "minimum_inclusion_probability", "maximum_inclusion_probability",
        "exact_induced_probability_count", "ineligible_membership_count",
    )
    fields = []
    for name in names:
        data_type = pa.string() if name in string_names else pa.int64() if name in integer_names else pa.float64()
        fields.append((name, data_type))
    return _schema(
        pa,
        "htgl.sampling.design-diagnostics.v1",
        "restricted",
        fields,
    )


def _baseline_schema():
    pa, _ = _require_pyarrow()
    return _schema(
        pa,
        "htgl.sampling.ineligible-baselines.v1",
        "restricted",
        [
            ("baseline_id", pa.string()),
            ("scenario_id", pa.string()),
            ("primary_unit_type", pa.string()),
            ("selected_unit_count", pa.int64()),
            ("raw_relative_error", pa.float64()),
            ("estimator_eligible", pa.bool_()),
            ("exclusion_reason", pa.string()),
        ],
    )


def _schema(pa: Any, schema_id: str, privacy_class: str, fields: Sequence[tuple[str, Any]]):
    base = pa.schema([pa.field(name, data_type, nullable=False) for name, data_type in fields])
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
    pa, pq = _require_pyarrow()
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(list(records), schema=schema)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        pq.write_table(table, temporary, compression="ZSTD")
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
            "pyarrow is required for authoritative sampling Parquet output"
        ) from exc
    return pa, pq


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
