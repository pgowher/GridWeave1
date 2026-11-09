"""Production workflow API for deterministic, claim-aware generator operation."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, replace
import csv
import io
import json
import math
from pathlib import Path
import platform
import re
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

from htgl_dataset_generator.artifacts import (
    ArtifactCompilerOptions,
    ArtifactIntegrityError,
    ArtifactReleaseResult,
    RELEASE_EVIDENCE_PATH,
    ReleaseEvidence,
    compile_and_publish_artifacts,
    read_release_evidence,
)
from htgl_dataset_generator.artifacts.canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    domain_sha256,
    sha256_hex,
)
from htgl_dataset_generator.artifacts.manifest import verify_manifest_closure
from htgl_dataset_generator.artifacts.reports import (
    CLAIM_MATRIX_COLUMNS,
    validate_publication_wording,
)
from htgl_dataset_generator.artifacts.transaction import (
    ReleaseTransaction,
)
from htgl_dataset_generator.config import (
    ResolvedConfig,
    build_run_plan,
    resolve_config_file,
)
from htgl_dataset_generator.experiments import (
    DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    DEFAULT_MEMORY_BUDGET_BYTES,
    FactorialStudyPlan,
    FinalReleaseGateError,
    PrecisionJustification,
    ParallelExecutionPolicy,
    StudyPackageOptions,
    build_factorial_study_plan,
    compile_condition_config,
    compile_study_evidence_package,
    default_study_resource_budget,
    execute_factorial_study,
    orchestrate_pipeline_through_metrics,
    orchestrate_pipeline_through_sampling,
    orchestrate_pipeline_through_validation,
    planned_study_execution,
    resolve_execution_capacity,
    require_complete_publication_selection,
)
from htgl_dataset_generator.io import (
    ParquetWriteReport,
    write_metrics_artifact_bundle,
    write_parquet_table_with_report,
    write_validation_artifact_bundle,
)
from htgl_dataset_generator.schemas import load_contract
from htgl_dataset_generator.seeds import (
    canonical_records_digest,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.validation import (
    PerformanceObservation,
    StagePerformanceObservation,
)
from htgl_dataset_generator.validation.engine import build_run_scenario_record


EventSink = Callable[["WorkflowEvent"], None]
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._-]+")


class WorkflowApiError(RuntimeError):
    """Base error for production CLI/API workflow failures."""


class WorkspaceStateError(WorkflowApiError):
    """Raised when a command workspace is missing, modified, or inconsistent."""


class ScientificClaimError(WorkflowApiError):
    """Raised when a requested mode would produce an unsupported scientific claim."""


class MeasurementEvidenceError(WorkflowApiError):
    """Raised when publication resource evidence cannot be measured honestly."""


class ReproducibilityError(WorkflowApiError):
    """Raised when a clean reproduction differs from its immutable source release."""


class AdapterExportError(WorkflowApiError):
    """Raised when an adapter export violates mapping, privacy, or manifest controls."""


@dataclass(frozen=True)
class ResourceUsage:
    elapsed_seconds: float
    peak_resident_memory_bytes: int
    generated_row_count: int
    stored_bytes: int


@dataclass(frozen=True)
class WorkflowEvent:
    sequence: int
    level: str
    run_id: str
    scenario_id: str
    replicate_id: int | None
    stage: str
    component: str
    event: str
    status: str
    deterministic_status: str
    resource_usage: ResourceUsage | None = None
    details: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ResolvedConfigResult:
    resolved: ResolvedConfig
    output_path: Path
    explanation: Mapping[str, Any]


@dataclass(frozen=True)
class StageExecutionResult:
    command: str
    run_id: str
    stage_root: Path
    manifest_sha256: str
    semantic_digest: str
    record_counts: Mapping[str, int]
    validation_status_counts: Mapping[str, int]
    publication_eligible: bool
    resource_usage: ResourceUsage


@dataclass(frozen=True)
class CompilationWorkflowResult:
    release: ArtifactReleaseResult
    resource_usage: ResourceUsage
    publication_eligible: bool


@dataclass(frozen=True)
class ReproductionWorkflowResult:
    source_release: Path
    reproduced_release: Path
    semantic_digest_match: bool
    byte_digest_match: bool
    manifest_sha256_match: bool


@dataclass(frozen=True)
class AdapterExportResult:
    adapter_id: str
    source_release: Path
    export_root: Path
    source_release_byte_digest: str
    exported_file_count: int
    export_digest: str


@dataclass(frozen=True)
class ClaimReportResult:
    source_release: Path
    report_root: Path
    claim_count: int
    status_counts: Mapping[str, int]
    supported_claim_ids: tuple[str, ...]
    unsupported_claim_ids: tuple[str, ...]


@dataclass(frozen=True)
class StudyWorkflowResult:
    study_id: str
    package_root: Path
    manifest_sha256: str
    publication_eligible: bool
    publication_blockers: tuple[str, ...]
    selected_condition_count: int
    full_factorial_condition_count: int


class _EventEmitter:
    def __init__(self, resolved: ResolvedConfig, sink: EventSink | None) -> None:
        self.resolved = resolved
        self.sink = sink
        self.sequence = 0

    def emit(
        self,
        *,
        stage: str,
        component: str,
        event: str,
        status: str,
        scenario_id: str | None = None,
        replicate_id: int | None = None,
        deterministic: bool = True,
        resources: ResourceUsage | None = None,
        details: Mapping[str, Any] | None = None,
        level: str = "info",
    ) -> None:
        item = WorkflowEvent(
            sequence=self.sequence,
            level=level,
            run_id=self.resolved.run.run_id,
            scenario_id=scenario_id or self.resolved.run.scenario_id,
            replicate_id=replicate_id,
            stage=stage,
            component=component,
            event=event,
            status=status,
            deterministic_status=(
                "deterministic" if deterministic else "measured_nonsemantic"
            ),
            resource_usage=resources,
            details=None if details is None else dict(sorted(details.items())),
        )
        self.sequence += 1
        if self.sink is not None:
            self.sink(item)


def resolve_config_contract(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    collision_policy: str = "reuse_identical",
    event_sink: EventSink | None = None,
) -> ResolvedConfigResult:
    """Resolve, explain, and transactionally persist an immutable config contract."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    emitter.emit(
        stage="S00",
        component="config_resolver",
        event="resolve_config_started",
        status="running",
    )
    explanation = explain_workflow(resolved, "resolve-config")

    def writer(root: Path) -> None:
        atomic_write_bytes(
            root / "config" / "config_resolved.json",
            canonical_json_bytes(resolved.as_dict()),
        )
        atomic_write_bytes(
            root / "config" / "claim_eligibility.json",
            canonical_json_bytes(explanation),
        )

    stage = _publish_command_stage(
        resolved,
        Path(output_dir),
        "resolve-config",
        collision_policy=collision_policy,
        semantic_digest=resolved.config_sha256,
        writer=writer,
        metadata={"command": "resolve-config", "authoritative_bulk_storage": "none"},
    )
    output_path = stage / "config" / "config_resolved.json"
    emitter.emit(
        stage="S00",
        component="config_resolver",
        event="resolve_config_completed",
        status="passed",
        details={"config_sha256": resolved.config_sha256, "output": str(output_path)},
    )
    return ResolvedConfigResult(resolved, output_path, explanation)


def generate_dataset(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
    collision_policy: str = "reuse_identical",
    event_sink: EventSink | None = None,
) -> StageExecutionResult:
    """Run S00-S12 and persist authoritative generated tables as Parquet/ZSTD."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    _require_positive_workers(worker_count)
    emitter.emit(
        stage="S00-S12",
        component="pipeline",
        event="generation_started",
        status="running",
        details={"worker_count": worker_count},
    )
    started = time.perf_counter()
    policy = _parallel_policy(
        worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
    )
    results = orchestrate_pipeline_through_sampling(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
        checkpoint_dir=checkpoint_dir,
        resume=resume,
    )
    tables_by_run = _prevalidation_tables_from_sampling(resolved, results)
    semantic_digest = _prevalidation_semantic_digest(tables_by_run)
    counts = _table_record_counts(tables_by_run)
    stage_holder: dict[str, Any] = {}

    def writer(root: Path) -> None:
        stored = _write_tables_by_run(
            root / "authoritative",
            tables_by_run,
            row_group_target_bytes=resolved.output.row_group_target_bytes,
        )
        stage_holder["stored_bytes"] = stored
        atomic_write_bytes(
            root / "generation_metadata.json",
            canonical_json_bytes(
                {
                    "format": "htgl.cli-generation-stage.v1",
                    "run_id": resolved.run.run_id,
                    "config_sha256": resolved.config_sha256,
                    "semantic_digest": semantic_digest,
                    "record_counts": counts,
                    "replicate_count": len(results),
                    "authoritative_storage": "parquet_zstd",
                    "jsonl_authority": False,
                    "publication_eligible": False,
                    "claim_boundary": (
                        "S00-S12 generated benchmark artifacts only; no publication, legal, "
                        "physical-deletion, or operational-capacity claim"
                    ),
                }
            ),
        )

    stage_root = _publish_command_stage(
        resolved,
        Path(output_dir),
        "generate",
        collision_policy=collision_policy,
        semantic_digest=semantic_digest,
        writer=writer,
        metadata={"command": "generate", "stage": "S00-S12"},
    )
    resources = ResourceUsage(
        elapsed_seconds=time.perf_counter() - started,
        peak_resident_memory_bytes=_peak_resident_memory_bytes(),
        generated_row_count=sum(counts.values()),
        stored_bytes=int(stage_holder["stored_bytes"]),
    )
    for result in results:
        emitter.emit(
            stage="S00-S12",
            component="replicate_pipeline",
            event="replicate_generated",
            status="passed",
            scenario_id=result.run_plan.scenario_id,
            replicate_id=result.run_plan.replicate_id,
            details={
                "seed_stream_digest": result.seed_stream_digest,
                "table_count": len(tables_by_run[_run_key(result.run_plan)]),
            },
        )
    emitter.emit(
        stage="S00-S12",
        component="pipeline",
        event="generation_completed",
        status="passed",
        deterministic=False,
        resources=resources,
        details={"semantic_digest": semantic_digest, "stage_root": str(stage_root)},
    )
    return _stage_result(
        "generate",
        resolved,
        stage_root,
        semantic_digest,
        counts,
        {},
        False,
        resources,
    )


def validate_dataset(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
    collision_policy: str = "reuse_identical",
    event_sink: EventSink | None = None,
) -> StageExecutionResult:
    """Run the complete S13 registry and retain honest publication blockers."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    _require_positive_workers(worker_count)
    emitter.emit(
        stage="S13",
        component="validation_engine",
        event="validation_started",
        status="running",
    )
    started = time.perf_counter()
    policy = _parallel_policy(
        worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
    )
    results = orchestrate_pipeline_through_validation(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
        checkpoint_dir=checkpoint_dir,
        resume=resume,
    )
    prevalidation = {
        _run_key(result.run_plan): result.artifacts.prevalidation_table_records()
        for result in results
    }
    source_digest = _prevalidation_semantic_digest(prevalidation)
    _verify_prior_stage_if_present(
        resolved,
        Path(output_dir),
        "generate",
        source_digest,
    )
    validation_rows = tuple(
        row
        for result in results
        for row in result.artifacts.validation.validation_issues
    )
    status_counts = dict(
        sorted(Counter(str(row["status"]) for row in validation_rows).items())
    )
    semantic_digest = domain_sha256(
        "cli-validation-stage-v1",
        {
            "source_semantic_digest": source_digest,
            "validation": [
                canonical_records_digest(result.artifacts.validation.validation_issues)
                for result in results
            ],
        },
    )
    stored_holder: dict[str, int] = {}

    def writer(root: Path) -> None:
        before = _directory_stored_bytes(root)
        for result in results:
            run_root = _run_output_root(root, result.run_plan)
            write_validation_artifact_bundle(
                result.artifacts.validation,
                run_root,
            )
        atomic_write_bytes(
            root / "validation_summary.json",
            canonical_json_bytes(
                {
                    "format": "htgl.cli-validation-stage.v1",
                    "run_id": resolved.run.run_id,
                    "config_sha256": resolved.config_sha256,
                    "source_semantic_digest": source_digest,
                    "validation_semantic_digest": semantic_digest,
                    "status_counts": status_counts,
                    "release_eligible": all(
                        result.artifacts.validation.release_eligible
                        for result in results
                    ),
                    "publication_checks_without_S15_evidence_remain_not_executed": True,
                }
            ),
        )
        stored_holder["value"] = _directory_stored_bytes(root) - before

    stage_root = _publish_command_stage(
        resolved,
        Path(output_dir),
        "validate",
        collision_policy=collision_policy,
        semantic_digest=semantic_digest,
        writer=writer,
        metadata={"command": "validate", "stage": "S13"},
    )
    resources = ResourceUsage(
        time.perf_counter() - started,
        _peak_resident_memory_bytes(),
        len(validation_rows),
        stored_holder["value"],
    )
    release_eligible = all(
        result.artifacts.validation.release_eligible for result in results
    )
    emitter.emit(
        stage="S13",
        component="validation_engine",
        event="validation_completed",
        status="passed" if release_eligible else "completed_with_publication_blockers",
        deterministic=False,
        resources=resources,
        details={"status_counts": status_counts, "release_eligible": release_eligible},
    )
    return _stage_result(
        "validate",
        resolved,
        stage_root,
        semantic_digest,
        {"validation_issue": len(validation_rows)},
        status_counts,
        release_eligible,
        resources,
    )


def compute_metrics(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    checkpoint_dir: str | Path | None = None,
    resume: bool = False,
    collision_policy: str = "reuse_identical",
    event_sink: EventSink | None = None,
) -> StageExecutionResult:
    """Run S14 and persist metric, provenance, execution, and uncertainty ledgers."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    _require_positive_workers(worker_count)
    emitter.emit(
        stage="S14",
        component="metrics_engine",
        event="metrics_started",
        status="running",
    )
    started = time.perf_counter()
    policy = _parallel_policy(
        worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
    )
    group = orchestrate_pipeline_through_metrics(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
        checkpoint_dir=checkpoint_dir,
        resume=resume,
    )
    prevalidation = {
        _run_key(result.run_plan): result.artifacts.through_validation.prevalidation_table_records()
        for result in group.replicates
    }
    source_digest = _prevalidation_semantic_digest(prevalidation)
    _verify_prior_stage_if_present(
        resolved,
        Path(output_dir),
        "generate",
        source_digest,
    )
    builds = tuple(result.artifacts.metrics for result in group.replicates)
    metric_rows = tuple(row for build in builds for row in build.run_metrics)
    semantic_digest = domain_sha256(
        "cli-metrics-stage-v1",
        {
            "source_semantic_digest": source_digest,
            "run_metrics": canonical_records_digest(metric_rows),
            "aggregates": [asdict(item) for item in group.aggregates],
            "paired_comparisons": [asdict(item) for item in group.paired_comparisons],
        },
    )
    stored_holder: dict[str, int] = {}

    def writer(root: Path) -> None:
        before = _directory_stored_bytes(root)
        write_metrics_artifact_bundle(
            builds,
            group.aggregates,
            group.paired_comparisons,
            root,
        )
        atomic_write_bytes(
            root / "metrics_stage_summary.json",
            canonical_json_bytes(
                {
                    "format": "htgl.cli-metrics-stage.v1",
                    "run_id": resolved.run.run_id,
                    "config_sha256": resolved.config_sha256,
                    "source_semantic_digest": source_digest,
                    "metrics_semantic_digest": semantic_digest,
                    "run_metric_count": len(metric_rows),
                    "aggregate_count": len(group.aggregates),
                    "paired_comparison_count": len(group.paired_comparisons),
                    "publication_eligible_metric_count": sum(
                        item.publication_eligible
                        for build in builds
                        for item in build.provenance
                    ),
                    "external_evidence_metrics_may_remain_not_executed": True,
                }
            ),
        )
        stored_holder["value"] = _directory_stored_bytes(root) - before

    stage_root = _publish_command_stage(
        resolved,
        Path(output_dir),
        "metrics",
        collision_policy=collision_policy,
        semantic_digest=semantic_digest,
        writer=writer,
        metadata={"command": "metrics", "stage": "S14"},
    )
    status_counts = dict(
        sorted(
            Counter(
                record.status
                for build in builds
                for record in build.execution_records
            ).items()
        )
    )
    resources = ResourceUsage(
        time.perf_counter() - started,
        _peak_resident_memory_bytes(),
        len(metric_rows),
        stored_holder["value"],
    )
    emitter.emit(
        stage="S14",
        component="metrics_engine",
        event="metrics_completed",
        status="passed",
        deterministic=False,
        resources=resources,
        details={"execution_status_counts": status_counts},
    )
    return _stage_result(
        "metrics",
        resolved,
        stage_root,
        semantic_digest,
        {"run_metric": len(metric_rows)},
        status_counts,
        False,
        resources,
    )


def compile_artifact_release(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    publication: bool,
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    collision_policy: str = "fail",
    release_evidence: ReleaseEvidence | None = None,
    event_sink: EventSink | None = None,
) -> CompilationWorkflowResult:
    """Run required gates and atomically compile an S15 publication release."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    if not publication:
        raise ScientificClaimError(
            "compile-artifacts requires publication=True because S15 emits a claim-bearing release"
        )
    _require_positive_workers(worker_count)
    policy = _parallel_policy(
        worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
    )
    capacity = resolve_execution_capacity(
        resolved,
        policy,
        task_count=len(build_run_plan(resolved)),
    )
    emitter.emit(
        stage="S00-S15",
        component="artifact_workflow",
        event="publication_compilation_started",
        status="running",
        details={"worker_count": worker_count},
    )
    serial_elapsed: float | None = None
    serial_group = None
    if release_evidence is None and capacity.effective_worker_count > 1:
        serial_policy = replace(policy, worker_count=1, max_in_flight=1, backend="serial")
        serial_started = time.perf_counter()
        serial_group = orchestrate_pipeline_through_metrics(
            resolved,
            worker_count=1,
            execution_policy=serial_policy,
            profile_stages=True,
        )
        serial_elapsed = time.perf_counter() - serial_started
    started = time.perf_counter()
    primary = orchestrate_pipeline_through_metrics(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
        profile_stages=release_evidence is None,
    )
    measured_elapsed = time.perf_counter() - started
    clean = orchestrate_pipeline_through_metrics(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
    )
    deterministic_match = _group_prevalidation_digest(primary) == _group_prevalidation_digest(clean)
    if serial_group is not None:
        deterministic_match = deterministic_match and (
            _group_prevalidation_digest(primary)
            == _group_prevalidation_digest(serial_group)
        )
    if not deterministic_match:
        raise ReproducibilityError(
            "primary and separately orchestrated clean rerun differ before S15"
        )
    _verify_prior_stage_if_present(
        resolved,
        Path(output_dir),
        "generate",
        _group_prevalidation_digest(primary),
    )
    if release_evidence is None:
        release_evidence, measured = _measure_release_evidence(
            resolved,
            primary,
            elapsed_seconds=measured_elapsed,
            deterministic_digest_equal=deterministic_match,
            requested_worker_count=worker_count,
            effective_worker_count=capacity.effective_worker_count,
            serial_elapsed_seconds=serial_elapsed,
            serial_group=serial_group,
        )
    else:
        measured = _resource_usage_from_evidence(release_evidence)
    release = compile_and_publish_artifacts(
        resolved,
        primary,
        clean,
        Path(output_dir) / "releases",
        evidence=release_evidence,
        options=ArtifactCompilerOptions(collision_policy=collision_policy),
    )
    emitter.emit(
        stage="S15",
        component="artifact_compiler",
        event="publication_compilation_completed",
        status="passed",
        deterministic=False,
        resources=measured,
        details={
            "release_root": str(release.release_root),
            "bundle_roots": {
                access: str(bundle.release_root)
                for access, bundle in sorted(release.bundles.items())
            },
            "manifest_sha256": release.manifest_sha256,
            "release_byte_digest": release.byte_digest,
        },
    )
    return CompilationWorkflowResult(release, measured, True)


def reproduce_release(
    config_path: str | Path,
    source_release: str | Path,
    output_dir: str | Path,
    *,
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    collision_policy: str = "fail",
    event_sink: EventSink | None = None,
) -> ReproductionWorkflowResult:
    """Rebuild a release with its persisted external evidence and require equality."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    requested_source = Path(source_release).resolve()
    source_bundles = _verify_release_bundle_set(requested_source)
    source, source_manifest, _ = source_bundles["public"]
    if source_manifest.get("config_sha256") != resolved.config_sha256:
        raise ReproducibilityError(
            "source release config digest differs from the explicit reproduction config"
        )
    restricted_root = source_bundles["restricted"][0]
    evidence_path = restricted_root / RELEASE_EVIDENCE_PATH
    if not evidence_path.is_file():
        raise ReproducibilityError(
            f"source release lacks restricted reproduction evidence {RELEASE_EVIDENCE_PATH}"
        )
    evidence = read_release_evidence(
        evidence_path,
        expected_run_id=resolved.run.run_id,
        expected_config_sha256=resolved.config_sha256,
    )
    emitter.emit(
        stage="S00-S15",
        component="reproduction_workflow",
        event="reproduction_started",
        status="running",
    )
    policy = _parallel_policy(
        worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
    )
    primary = orchestrate_pipeline_through_metrics(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
    )
    clean = orchestrate_pipeline_through_metrics(
        resolved,
        worker_count=worker_count,
        execution_policy=policy,
    )
    reproduced = compile_and_publish_artifacts(
        resolved,
        primary,
        clean,
        Path(output_dir) / "reproductions",
        evidence=evidence,
        options=ArtifactCompilerOptions(collision_policy=collision_policy),
    )
    semantic_match = all(
        str(manifest["release_semantic_digest"]) == reproduced.semantic_digest
        for _, manifest, _ in source_bundles.values()
    )
    source_bundle_set_digest = domain_sha256(
        "release-bundle-set-byte-inventory-v1",
        {
            access: str(source_bundles[access][1]["release_byte_digest"])
            for access in sorted(source_bundles)
        },
    )
    byte_match = source_bundle_set_digest == reproduced.byte_digest
    manifest_match = all(
        sha256_hex((source_bundles[access][0] / "manifest.json").read_bytes())
        == reproduced.bundle(access).manifest_sha256
        for access in sorted(source_bundles)
    )
    if not (semantic_match and byte_match and manifest_match):
        raise ReproducibilityError(
            "release reproduction mismatch "
            f"semantic={semantic_match} bytes={byte_match} manifest={manifest_match}"
        )
    emitter.emit(
        stage="S15",
        component="reproduction_workflow",
        event="reproduction_completed",
        status="passed",
        details={"source_release": str(source), "reproduced_release": str(reproduced.release_root)},
    )
    return ReproductionWorkflowResult(
        source,
        reproduced.release_root,
        semantic_match,
        byte_match,
        manifest_match,
    )


def export_adapter(
    config_path: str | Path,
    source_release: str | Path,
    output_dir: str | Path,
    *,
    adapter_id: str,
    access_class: str = "public",
    collision_policy: str = "reuse_identical",
    event_sink: EventSink | None = None,
) -> AdapterExportResult:
    """Export one verified adapter projection from canonical S15 output."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    requested_source = Path(source_release).resolve()
    source_bundles = _verify_release_bundle_set(requested_source)
    source, root_manifest, artifact_rows = source_bundles["public"]
    if root_manifest.get("config_sha256") != resolved.config_sha256:
        raise AdapterExportError("adapter source release does not match explicit config")
    if adapter_id not in resolved.output.adapters:
        raise AdapterExportError(
            f"adapter {adapter_id!r} is not configured; configured={resolved.output.adapters}"
        )
    if access_class not in {"public", "restricted"}:
        raise AdapterExportError("access_class must be public or restricted")
    conformance_path = source / "publication" / "adapters" / "conformance.json"
    conformance = json.loads(conformance_path.read_text(encoding="utf-8"))
    if conformance.get("format") != "htgl.adapter-conformance.v1":
        raise AdapterExportError("adapter conformance format is missing or unsupported")
    entries = [
        item
        for item in conformance.get("entries", ())
        if item.get("adapter_id") == adapter_id
    ]
    if len(entries) != 1 or not bool(entries[0].get("passed")):
        raise AdapterExportError(
            f"adapter {adapter_id!r} lacks one passed conformance record"
        )
    projection_paths = tuple(
        str(path) for path in entries[0]["output_relative_paths"]
    )
    expected_projection_digests = tuple(
        str(value) for value in entries[0]["output_sha256"]
    )
    if len(projection_paths) != len(expected_projection_digests):
        raise AdapterExportError(
            f"adapter {adapter_id!r} conformance paths and digests do not reconcile"
        )
    support_paths = (
        "publication/adapters/conformance.json",
        "publication/adapters/mapping/field_mapping.parquet",
        "publication/adapters/mapping/mapping_registry.json",
        "publication/adapters/unmapped_fields.json",
        "publication/adapters/loss_report.json",
    )
    source_paths = tuple(sorted(set(projection_paths + support_paths)))
    manifest_by_path = {str(row["relative_path"]): row for row in artifact_rows}
    for relative in source_paths:
        row = manifest_by_path.get(relative)
        if row is None:
            raise AdapterExportError(f"adapter output is absent from artifact manifest: {relative}")
        privacy = str(row["privacy_class"])
        if access_class == "public" and (
            privacy != "public" or not bool(row["publication_eligible"])
        ):
            raise AdapterExportError(
                f"adapter {adapter_id!r} output {relative} is {privacy} and cannot be publicly exported"
            )
    for relative, expected_digest in zip(
        projection_paths,
        expected_projection_digests,
        strict=True,
    ):
        actual_digest = sha256_hex((source / relative).read_bytes())
        if actual_digest != expected_digest:
            raise AdapterExportError(
                f"adapter {adapter_id!r} conformance digest mismatch for {relative}"
            )
    digest = domain_sha256(
        "cli-adapter-export-v1",
        {
            "adapter_id": adapter_id,
            "source_release_byte_digest": root_manifest["release_byte_digest"],
            "files": [(path, manifest_by_path[path]["sha256"]) for path in source_paths],
        },
    )

    def writer(root: Path) -> None:
        for relative in source_paths:
            source_path = source / Path(relative)
            target = root / "adapter" / Path(relative).relative_to(
                Path("publication/adapters")
            )
            atomic_write_bytes(target, source_path.read_bytes())
        atomic_write_bytes(
            root / "adapter_export_manifest.json",
            canonical_json_bytes(
                {
                    "format": "htgl.adapter-export.v1",
                    "adapter_id": adapter_id,
                    "access_class": access_class,
                    "source_release_byte_digest": root_manifest["release_byte_digest"],
                    "export_digest": digest,
                    "source_paths": source_paths,
                    "field_mapping_and_loss_reports_included": True,
                }
            ),
        )

    export_root = _publish_command_stage(
        resolved,
        Path(output_dir) / "exports",
        f"export-{_safe_token(adapter_id)}",
        collision_policy=collision_policy,
        semantic_digest=digest,
        writer=writer,
        metadata={"command": "export-adapter", "adapter_id": adapter_id},
    )
    emitter.emit(
        stage="S15",
        component="adapter_exporter",
        event="adapter_export_completed",
        status="passed",
        details={"adapter_id": adapter_id, "file_count": len(source_paths)},
    )
    return AdapterExportResult(
        adapter_id,
        source,
        export_root,
        str(root_manifest["release_byte_digest"]),
        len(source_paths),
        digest,
    )


def report_claims(
    config_path: str | Path,
    source_release: str | Path,
    output_dir: str | Path,
    *,
    statuses: Iterable[str] = ("supported", "not_supported", "diagnostic_only"),
    collision_policy: str = "reuse_identical",
    event_sink: EventSink | None = None,
) -> ClaimReportResult:
    """Verify, filter, and transactionally report an immutable claim matrix."""

    resolved = resolve_config_file(config_path)
    emitter = _EventEmitter(resolved, event_sink)
    requested_source = Path(source_release).resolve()
    source_bundles = _verify_release_bundle_set(requested_source)
    source, root_manifest, _ = source_bundles["public"]
    artifact_rows = tuple(
        row
        for access in sorted(source_bundles)
        for row in source_bundles[access][2]
    )
    if root_manifest.get("config_sha256") != resolved.config_sha256:
        raise ScientificClaimError("claim source release does not match explicit config")
    allowed = tuple(sorted(set(statuses)))
    recognized = {"supported", "not_supported", "diagnostic_only"}
    if not allowed or not set(allowed) <= recognized:
        raise ScientificClaimError(
            f"claim statuses must be a non-empty subset of {sorted(recognized)}"
        )
    claim_path = source / "publication" / "reports" / "claim_matrix.csv"
    with claim_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != CLAIM_MATRIX_COLUMNS:
            raise ScientificClaimError("claim matrix columns do not match Appendix D contract")
        all_claims = tuple(dict(row) for row in reader)
    if not all_claims or len({row["claim_id"] for row in all_claims}) != len(all_claims):
        raise ScientificClaimError("claim matrix must contain unique stable claim IDs")
    manifest_ids = {str(row["artifact_id"]) for row in artifact_rows}
    for row in all_claims:
        validate_publication_wording(str(row["claim_text"]))
        cited = {
            token.split("|", 1)[0]
            for token in str(row["artifact_ids"]).split(";")
            if token and not token.startswith("external:")
        }
        if not cited <= manifest_ids:
            raise ScientificClaimError(
                f"claim {row['claim_id']} cites artifacts absent from final manifest"
            )
    selected = tuple(
        row for row in all_claims if str(row["claim_status"]) in allowed
    )
    digest = domain_sha256(
        "cli-claim-report-v1",
        {
            "source_release_byte_digest": root_manifest["release_byte_digest"],
            "statuses": allowed,
            "claim_ids": [row["claim_id"] for row in selected],
        },
    )

    def writer(root: Path) -> None:
        buffer = io.StringIO(newline="")
        csv_writer = csv.DictWriter(
            buffer,
            fieldnames=CLAIM_MATRIX_COLUMNS,
            lineterminator="\n",
        )
        csv_writer.writeheader()
        csv_writer.writerows(selected)
        atomic_write_bytes(
            root / "claims" / "claim_matrix.csv",
            buffer.getvalue().encode("utf-8"),
        )
        counts = dict(
            sorted(Counter(str(row["claim_status"]) for row in selected).items())
        )
        atomic_write_bytes(
            root / "claims" / "claim_summary.json",
            canonical_json_bytes(
                {
                    "format": "htgl.claim-report.v1",
                    "source_release_byte_digest": root_manifest["release_byte_digest"],
                    "claim_report_digest": digest,
                    "selected_statuses": allowed,
                    "status_counts": counts,
                    "supported_claim_ids": sorted(
                        row["claim_id"]
                        for row in selected
                        if row["claim_status"] == "supported"
                    ),
                    "unsupported_claim_ids": sorted(
                        row["claim_id"]
                        for row in selected
                        if row["claim_status"] != "supported"
                    ),
                    "N_n_q_are_distinct": True,
                }
            ),
        )

    report_root = _publish_command_stage(
        resolved,
        Path(output_dir) / "claim-reports",
        "report-claims",
        collision_policy=collision_policy,
        semantic_digest=digest,
        writer=writer,
        metadata={"command": "report-claims", "statuses": allowed},
    )
    counts = dict(sorted(Counter(row["claim_status"] for row in selected).items()))
    supported = tuple(
        sorted(row["claim_id"] for row in selected if row["claim_status"] == "supported")
    )
    unsupported = tuple(
        sorted(row["claim_id"] for row in selected if row["claim_status"] != "supported")
    )
    emitter.emit(
        stage="S15",
        component="claim_reporter",
        event="claim_report_completed",
        status="passed",
        details={"claim_count": len(selected), "status_counts": counts},
    )
    return ClaimReportResult(
        source,
        report_root,
        len(selected),
        counts,
        supported,
        unsupported,
    )


def run_factorial_study(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    study_id: str,
    design_mode: str = "pairwise_covering",
    repetitions: int = 30,
    condition_ids: Iterable[str] = (),
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    publication: bool = False,
    precision_justification: PrecisionJustification | None = None,
    maximum_conditions: int = 512,
    maximum_replicates: int = 15_360,
    maximum_rows_per_replicate: int = 1_000_000,
    maximum_total_rows: int = 2_000_000_000,
    enable_10m_materialization: bool = False,
    collision_policy: str = "fail",
    event_sink: EventSink | None = None,
) -> StudyWorkflowResult:
    """Plan or execute the P8 study with explicit diagnostic/publication semantics."""

    base = resolve_config_file(config_path)
    emitter = _EventEmitter(base, event_sink)
    policy = _parallel_policy(
        worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
    )
    plan = _build_study_plan(
        study_id,
        design_mode=design_mode,
        repetitions=repetitions,
        precision_justification=precision_justification,
        maximum_conditions=maximum_conditions,
        maximum_replicates=maximum_replicates,
        maximum_rows_per_replicate=maximum_rows_per_replicate,
        maximum_total_rows=maximum_total_rows,
        enable_10m_materialization=enable_10m_materialization,
    )
    selected = tuple(condition_ids)
    emitter.emit(
        stage="P8",
        component="study_runner",
        event="study_plan_resolved",
        status="passed",
        details={
            "design_mode": plan.design_mode,
            "full_factorial_condition_count": plan.full_factorial_condition_count,
            "selected_design_condition_count": plan.selected_condition_count,
            "requested_execution_condition_count": len(selected),
            "publication": publication,
        },
    )
    if publication:
        if not selected:
            raise ScientificClaimError(
                "publication study execution requires explicit condition_ids; an implicit multi-million-cell execution is forbidden"
            )
        try:
            selected = require_complete_publication_selection(plan, selected)
        except FinalReleaseGateError as exc:
            raise ScientificClaimError(str(exc)) from exc
    if selected:
        publication_evidence: dict[str, ReleaseEvidence] = {}
        if publication:
            by_id = {condition.condition_id: condition for condition in plan.conditions}
            for condition_id in selected:
                if condition_id not in by_id:
                    raise ScientificClaimError(f"unknown study condition {condition_id}")
                condition_config = compile_condition_config(
                    base,
                    by_id[condition_id],
                    study_id=plan.study_id,
                )
                capacity = resolve_execution_capacity(
                    condition_config,
                    policy,
                    task_count=len(build_run_plan(condition_config)),
                )
                serial_elapsed: float | None = None
                serial_group = None
                if capacity.effective_worker_count > 1:
                    serial_policy = replace(
                        policy,
                        worker_count=1,
                        max_in_flight=1,
                        backend="serial",
                    )
                    serial_started = time.perf_counter()
                    serial_group = orchestrate_pipeline_through_metrics(
                        condition_config,
                        worker_count=1,
                        execution_policy=serial_policy,
                        profile_stages=True,
                    )
                    serial_elapsed = time.perf_counter() - serial_started
                measurement_started = time.perf_counter()
                measurement_group = orchestrate_pipeline_through_metrics(
                    condition_config,
                    worker_count=worker_count,
                    execution_policy=policy,
                    profile_stages=True,
                )
                measurement_elapsed = time.perf_counter() - measurement_started
                clean_measurement = orchestrate_pipeline_through_metrics(
                    condition_config,
                    worker_count=worker_count,
                    execution_policy=policy,
                )
                deterministic_equal = (
                    _group_prevalidation_digest(measurement_group)
                    == _group_prevalidation_digest(clean_measurement)
                )
                if serial_group is not None:
                    deterministic_equal = deterministic_equal and (
                        _group_prevalidation_digest(measurement_group)
                        == _group_prevalidation_digest(serial_group)
                    )
                publication_evidence[condition_id], _ = _measure_release_evidence(
                    condition_config,
                    measurement_group,
                    elapsed_seconds=measurement_elapsed,
                    deterministic_digest_equal=deterministic_equal,
                    requested_worker_count=worker_count,
                    effective_worker_count=capacity.effective_worker_count,
                    serial_elapsed_seconds=serial_elapsed,
                    serial_group=serial_group,
                )
        build = execute_factorial_study(
            base,
            plan,
            condition_ids=selected,
            worker_count=worker_count,
            execution_policy=policy,
            publication_evidence_by_condition=publication_evidence or None,
            condition_release_output_root=(
                Path(output_dir) / "condition-releases" if publication else None
            ),
            artifact_options=ArtifactCompilerOptions(
                collision_policy="reuse_identical"
            ),
        )
    else:
        build = planned_study_execution(base, plan)
    try:
        package = compile_study_evidence_package(
            build,
            output_dir,
            options=StudyPackageOptions(
                package_kind="publication" if publication else "diagnostic",
                collision_policy=collision_policy,
                condition_release_root=(
                    Path(output_dir) / "condition-releases" if publication else None
                ),
            ),
        )
    except FinalReleaseGateError as exc:
        raise ScientificClaimError(str(exc)) from exc
    emitter.emit(
        stage="P8",
        component="study_runner",
        event="study_package_completed",
        status="passed" if build.publication_eligible else "completed_with_publication_blockers",
        details={
            "package_root": str(package.package_root),
            "publication_blockers": build.publication_blockers,
        },
    )
    return StudyWorkflowResult(
        plan.study_id,
        package.package_root,
        package.manifest_sha256,
        build.publication_eligible,
        tuple(build.publication_blockers),
        plan.selected_condition_count,
        plan.full_factorial_condition_count,
    )


def run_final_release_gate(
    config_path: str | Path,
    output_dir: str | Path,
    *,
    study_id: str,
    condition_ids: Iterable[str],
    design_mode: str = "pairwise_covering",
    repetitions: int = 30,
    worker_count: int = 1,
    max_in_flight: int | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    estimated_bytes_per_materialized_row: int = DEFAULT_ESTIMATED_BYTES_PER_MATERIALIZED_ROW,
    precision_justification: PrecisionJustification | None = None,
    maximum_conditions: int = 512,
    maximum_replicates: int = 15_360,
    maximum_rows_per_replicate: int = 1_000_000,
    maximum_total_rows: int = 2_000_000_000,
    enable_10m_materialization: bool = False,
    collision_policy: str = "fail",
    event_sink: EventSink | None = None,
) -> StudyWorkflowResult:
    """Execute the exact declared design and atomically publish only after the final gate."""

    return run_factorial_study(
        config_path,
        output_dir,
        study_id=study_id,
        design_mode=design_mode,
        repetitions=repetitions,
        condition_ids=condition_ids,
        worker_count=worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
        publication=True,
        precision_justification=precision_justification,
        maximum_conditions=maximum_conditions,
        maximum_replicates=maximum_replicates,
        maximum_rows_per_replicate=maximum_rows_per_replicate,
        maximum_total_rows=maximum_total_rows,
        enable_10m_materialization=enable_10m_materialization,
        collision_policy=collision_policy,
        event_sink=event_sink,
    )


def explain_study_plan(
    config_path: str | Path,
    *,
    study_id: str,
    design_mode: str = "pairwise_covering",
    repetitions: int = 30,
    precision_justification: PrecisionJustification | None = None,
    maximum_conditions: int = 512,
    maximum_replicates: int = 15_360,
    maximum_rows_per_replicate: int = 1_000_000,
    maximum_total_rows: int = 2_000_000_000,
    enable_10m_materialization: bool = False,
    workflow_command: str = "run-study",
) -> dict[str, Any]:
    """Resolve the exact P8 plan without executing conditions or writing artifacts."""

    resolved = resolve_config_file(config_path)
    plan = _build_study_plan(
        study_id,
        design_mode=design_mode,
        repetitions=repetitions,
        precision_justification=precision_justification,
        maximum_conditions=maximum_conditions,
        maximum_replicates=maximum_replicates,
        maximum_rows_per_replicate=maximum_rows_per_replicate,
        maximum_total_rows=maximum_total_rows,
        enable_10m_materialization=enable_10m_materialization,
    )
    explanation = explain_workflow(resolved, workflow_command)
    return {
        **explanation,
        "study_plan": {
            "study_id": plan.study_id,
            "plan_sha256": plan.plan_sha256,
            "registry_id": plan.registry.registry_id,
            "registry_sha256": plan.registry.sha256,
            "design_mode": plan.design_mode,
            "design_scope_statement": plan.design_scope_statement,
            "full_factorial_condition_count": plan.full_factorial_condition_count,
            "selected_condition_count": plan.selected_condition_count,
            "pairwise_requirement_count": plan.pairwise_requirement_count,
            "pairwise_covered_count": plan.pairwise_covered_count,
            "requested_repetitions": plan.requested_repetitions,
            "required_repetitions": plan.required_repetitions,
            "precision_justification": (
                None
                if plan.precision_justification is None
                else asdict(plan.precision_justification)
            ),
            "conditions": [asdict(condition) for condition in plan.conditions],
        },
    }


def explain_workflow(resolved: ResolvedConfig, command: str) -> dict[str, Any]:
    """Return a deterministic explanation without executing or writing artifacts."""

    command_stages = {
        "resolve-config": ("S00",),
        "generate": ("S00-S12",),
        "validate": ("S00-S13",),
        "metrics": ("S00-S14",),
        "compile-artifacts": ("S00-S15",),
        "run-study": ("P8",),
        "release-gate": ("P8-final-release",),
        "reproduce": ("S00-S15",),
        "export-adapter": ("S15-adapter-projection",),
        "report-claims": ("S15-claim-report",),
    }
    if command not in command_stages:
        raise WorkflowApiError(f"unknown workflow command {command!r}")
    scale = resolved.claim_scale
    blockers: list[str] = []
    if scale.represented_population >= 450_000_000 and not scale.scale_claim_allowed:
        blockers.append("represented-scale claims are disabled by resolved config")
    if not scale.estimator_eligible:
        blockers.append("population estimators are config-ineligible")
    if scale.executed_operation_target is not None:
        blockers.append("executed_operation_target is a target, not observed q")
    if scale.operational_claim_allowed:
        blockers.append("operational wording still requires measured downstream replay evidence")
    return {
        "format": "htgl.workflow-explanation.v1",
        "command": command,
        "run_id": resolved.run.run_id,
        "config_sha256": resolved.config_sha256,
        "stages": command_stages[command],
        "run_plans": [asdict(item) for item in build_run_plan(resolved)],
        "represented_population_N": scale.represented_population,
        "materialized_row_target_n": scale.materialized_row_target,
        "executed_operation_target_not_observed_q": scale.executed_operation_target,
        "estimator_eligible": scale.estimator_eligible,
        "scale_claim_allowed": scale.scale_claim_allowed,
        "operational_claim_allowed": scale.operational_claim_allowed,
        "publication_required_gates": (
            "complete fail-closed validation",
            "complete metrics and provenance",
            "observer leakage checks",
            "final-byte manifest closure",
            "clean-rerun reproducibility",
            "Appendix-D claim matrix",
        ),
        "claim_eligibility_notes": tuple(blockers),
        "generator_boundary": (
            "benchmark artifacts and optional replay workloads only; no HTGL consensus, "
            "ledger, physical erasure, legal enforcement, or utility deployment"
        ),
    }


def explain_config_path(config_path: str | Path, command: str) -> dict[str, Any]:
    return explain_workflow(resolve_config_file(config_path), command)


def _build_study_plan(
    study_id: str,
    *,
    design_mode: str,
    repetitions: int,
    precision_justification: PrecisionJustification | None,
    maximum_conditions: int,
    maximum_replicates: int,
    maximum_rows_per_replicate: int,
    maximum_total_rows: int,
    enable_10m_materialization: bool,
) -> FactorialStudyPlan:
    budget = default_study_resource_budget()
    capabilities = set(budget.capabilities)
    maximum_rows = maximum_rows_per_replicate
    if enable_10m_materialization:
        capabilities.add("materialize_1e7_rows")
        maximum_rows = max(maximum_rows, 10_000_000)
    budget = replace(
        budget,
        maximum_conditions=maximum_conditions,
        maximum_replicates=maximum_replicates,
        maximum_materialized_rows_per_replicate=maximum_rows,
        maximum_total_materialized_rows=maximum_total_rows,
        capabilities=frozenset(capabilities),
    )
    return build_factorial_study_plan(
        study_id,
        design_mode=design_mode,
        requested_repetitions=repetitions,
        precision_justification=precision_justification,
        resource_budget=budget,
    )


def _prevalidation_tables_from_sampling(
    resolved: ResolvedConfig,
    results: Sequence[Any],
) -> dict[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]]:
    contract = load_contract()
    output: dict[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]] = {}
    for result in results:
        tables = dict(result.artifacts.authoritative_table_records())
        tables["run_scenario"] = (
            build_run_scenario_record(resolved, result.run_plan, contract=contract),
        )
        seed_rows = tuple(
            dict(row)
            for row in seed_stream_records_for_plan(
                resolved,
                result.run_plan,
                contract=contract,
            )
        )
        if canonical_records_digest(seed_rows) != result.seed_stream_digest:
            raise WorkspaceStateError(
                f"scenario={result.run_plan.scenario_id} replicate={result.run_plan.replicate_id}: seed stream digest mismatch"
            )
        tables["seed_stream"] = seed_rows
        output[_run_key(result.run_plan)] = dict(sorted(tables.items()))
    return dict(sorted(output.items()))


def _write_tables_by_run(
    root: Path,
    tables_by_run: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    *,
    reports: dict[tuple[str, int, str], ParquetWriteReport] | None = None,
    row_group_target_bytes: int | None = None,
) -> int:
    contract = load_contract()
    for (scenario_id, replicate_id), tables in sorted(tables_by_run.items()):
        run_root = (
            root
            / f"scenario_id={_safe_token(scenario_id)}"
            / f"replicate_id={replicate_id}"
        )
        for table_name, rows in sorted(tables.items()):
            report = write_parquet_table_with_report(
                table_name,
                rows,
                run_root / f"{table_name}.parquet",
                contract=contract,
                compression="ZSTD",
                compression_level=9,
                canonical_sort=True,
                row_group_target_bytes=row_group_target_bytes,
            )
            if reports is not None:
                reports[(scenario_id, replicate_id, table_name)] = report
    return _directory_stored_bytes(root)


def _publish_command_stage(
    resolved: ResolvedConfig,
    output_dir: Path,
    stage_id: str,
    *,
    collision_policy: str,
    semantic_digest: str,
    writer: Callable[[Path], None],
    metadata: Mapping[str, Any],
) -> Path:
    contract = load_contract()
    run_id = f"{resolved.run.run_id}-{_safe_token(stage_id)}"
    transaction = ReleaseTransaction(
        output_dir / "workspaces",
        run_id=run_id,
        config_sha256=resolved.config_sha256,
        contract_fingerprint=contract.contract_fingerprint,
        collision_policy=collision_policy,
    )
    transaction.begin()
    try:
        writer(transaction.staging)
        transaction.record_phase("command_payload_written", command=stage_id)
        transaction.seal_owner_marker()
        entries = _stage_payload_entries(transaction.staging)
        byte_digest = domain_sha256(
            "cli-command-stage-byte-inventory-v1",
            [(item["relative_path"], item["sha256"]) for item in entries],
        )
        manifest = {
            "format": "htgl.cli-command-stage-manifest.v1",
            "run_id": resolved.run.run_id,
            "stage_id": stage_id,
            "config_sha256": resolved.config_sha256,
            "contract_fingerprint": contract.contract_fingerprint,
            "semantic_digest": semantic_digest,
            "release_byte_digest": byte_digest,
            "authoritative_storage": "typed_arrow_parquet_zstd",
            "jsonl_authority": False,
            "publication_eligible": False,
            "metadata": dict(sorted(metadata.items())),
            "artifacts": entries,
        }
        atomic_write_bytes(
            transaction.staging / "manifest.json",
            canonical_json_bytes(manifest),
        )
        transaction.record_phase(
            "command_manifest_written",
            release_byte_digest=byte_digest,
        )
        transaction.promote(byte_digest)
        _verify_command_stage(transaction.target)
        return transaction.target
    except Exception as exc:
        try:
            transaction.record_phase(
                "command_stage_failed",
                exception_type=type(exc).__name__,
                message=str(exc),
            )
        finally:
            transaction.release_lock()
        raise


def _stage_payload_entries(root: Path) -> list[dict[str, Any]]:
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative == "manifest.json" or path.name.endswith(".tmp"):
            continue
        payload = path.read_bytes()
        entries.append(
            {
                "relative_path": relative,
                "stored_bytes": len(payload),
                "sha256": sha256_hex(payload),
            }
        )
    return entries


def _verify_command_stage(root: Path) -> dict[str, Any]:
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except Exception as exc:
        raise WorkspaceStateError(f"cannot read command-stage manifest {root}: {exc}") from exc
    if manifest.get("format") != "htgl.cli-command-stage-manifest.v1":
        raise WorkspaceStateError(f"unsupported command-stage manifest at {root}")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list):
        raise WorkspaceStateError("command-stage artifacts must be an array")
    expected_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    observed_paths = {str(item["relative_path"]) for item in entries}
    if expected_paths != observed_paths or len(observed_paths) != len(entries):
        raise WorkspaceStateError(
            f"command-stage closure mismatch missing={sorted(expected_paths-observed_paths)} extra={sorted(observed_paths-expected_paths)}"
        )
    for item in entries:
        path = root / Path(str(item["relative_path"]))
        payload = path.read_bytes()
        if len(payload) != int(item["stored_bytes"]) or sha256_hex(payload) != item["sha256"]:
            raise WorkspaceStateError(
                f"command-stage payload digest mismatch for {item['relative_path']}"
            )
    digest = domain_sha256(
        "cli-command-stage-byte-inventory-v1",
        [(item["relative_path"], item["sha256"]) for item in entries],
    )
    if digest != manifest.get("release_byte_digest"):
        raise WorkspaceStateError("command-stage byte digest does not reconcile")
    return manifest


def _verify_prior_stage_if_present(
    resolved: ResolvedConfig,
    output_dir: Path,
    stage_id: str,
    expected_semantic_digest: str,
) -> None:
    root = (
        output_dir
        / "workspaces"
        / f"run_{resolved.run.run_id}-{_safe_token(stage_id)}"
    )
    if not root.exists():
        return
    manifest = _verify_command_stage(root)
    if manifest.get("config_sha256") != resolved.config_sha256:
        raise WorkspaceStateError(
            f"existing {stage_id} workspace belongs to a different resolved config"
        )
    if manifest.get("semantic_digest") != expected_semantic_digest:
        raise WorkspaceStateError(
            f"deterministic rerun disagrees with existing {stage_id} workspace"
        )


def _verify_release(root: Path) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ArtifactIntegrityError("pyarrow is required to verify a release") from exc
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    raw_rows = pq.read_table(root / "artifact_manifest.parquet").to_pylist()
    rows = tuple(
        {
            **dict(row),
            "sha256": (
                row["sha256"].hex()
                if isinstance(row.get("sha256"), (bytes, bytearray))
                else str(row["sha256"])
            ),
        }
        for row in raw_rows
    )
    verify_manifest_closure(root, rows=rows, contract=load_contract())
    return manifest, rows


def _verify_release_bundle_set(
    requested_root: Path,
) -> dict[str, tuple[Path, dict[str, Any], tuple[dict[str, Any], ...]]]:
    """Resolve and verify every physically separated bundle in one release set."""

    root = requested_root.resolve()
    descriptor_path = root / "bundle_descriptor.json"
    if not descriptor_path.is_file():
        raise ArtifactIntegrityError(
            f"release bundle lacks bundle_descriptor.json: {root}"
        )
    try:
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactIntegrityError(
            f"release bundle descriptor is unreadable: {descriptor_path}"
        ) from exc
    if descriptor.get("format") != "htgl.release-bundle-descriptor.v1":
        raise ArtifactIntegrityError("release bundle descriptor format is unsupported")
    expected_access = {"public", "evaluator_only", "restricted"}
    siblings = descriptor.get("sibling_bundle_directories")
    if not isinstance(siblings, dict) or set(siblings) != expected_access:
        raise ArtifactIntegrityError(
            "release bundle descriptor must name public, evaluator_only, and restricted siblings"
        )
    parent = root.parent.resolve()
    bundle_set_id = str(descriptor.get("bundle_set_id", ""))
    if not bundle_set_id:
        raise ArtifactIntegrityError("release bundle descriptor lacks bundle_set_id")
    verified: dict[
        str, tuple[Path, dict[str, Any], tuple[dict[str, Any], ...]]
    ] = {}
    seen_roots: set[Path] = set()
    for access in sorted(expected_access):
        sibling_name = siblings[access]
        if not isinstance(sibling_name, str) or not sibling_name:
            raise ArtifactIntegrityError(
                f"release bundle descriptor has invalid {access} sibling name"
            )
        candidate = (parent / sibling_name).resolve()
        if candidate.parent != parent or candidate in seen_roots:
            raise ArtifactIntegrityError(
                f"release bundle descriptor has unsafe or duplicate {access} sibling path"
            )
        seen_roots.add(candidate)
        manifest, rows = _verify_release(candidate)
        sibling_descriptor = json.loads(
            (candidate / "bundle_descriptor.json").read_text(encoding="utf-8")
        )
        if (
            manifest.get("bundle_set_id") != bundle_set_id
            or manifest.get("bundle_access_class") != access
            or sibling_descriptor.get("bundle_set_id") != bundle_set_id
            or sibling_descriptor.get("bundle_access_class") != access
            or sibling_descriptor.get("sibling_bundle_directories") != siblings
        ):
            raise ArtifactIntegrityError(
                f"{access} bundle identity does not match the release bundle set"
            )
        verified[access] = (candidate, manifest, rows)
    if root not in seen_roots:
        raise ArtifactIntegrityError(
            "requested release directory is not one of its declared bundle siblings"
        )
    config_digests = {
        str(manifest.get("config_sha256")) for _, manifest, _ in verified.values()
    }
    semantic_digests = {
        str(manifest.get("release_semantic_digest"))
        for _, manifest, _ in verified.values()
    }
    if len(config_digests) != 1 or len(semantic_digests) != 1:
        raise ArtifactIntegrityError(
            "release bundle set disagrees on config or semantic digest"
        )
    return dict(sorted(verified.items()))


def _measure_release_evidence(
    resolved: ResolvedConfig,
    group: Any,
    *,
    elapsed_seconds: float,
    deterministic_digest_equal: bool,
    requested_worker_count: int = 1,
    effective_worker_count: int = 1,
    serial_elapsed_seconds: float | None = None,
    serial_group: Any | None = None,
) -> tuple[ReleaseEvidence, ResourceUsage]:
    if not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
        raise MeasurementEvidenceError("measured generation elapsed time must be positive")
    if requested_worker_count < 1 or effective_worker_count < 1:
        raise MeasurementEvidenceError("measured worker counts must be positive")
    if effective_worker_count > requested_worker_count:
        raise MeasurementEvidenceError(
            "effective_worker_count cannot exceed requested_worker_count"
        )
    if effective_worker_count > 1 and serial_elapsed_seconds is None:
        raise MeasurementEvidenceError(
            "parallel efficiency requires a separately measured serial elapsed time"
        )
    if serial_elapsed_seconds is not None and (
        not math.isfinite(serial_elapsed_seconds) or serial_elapsed_seconds <= 0
    ):
        raise MeasurementEvidenceError("serial elapsed time must be positive and finite")
    parallel_efficiency = (
        serial_elapsed_seconds / (elapsed_seconds * effective_worker_count)
        if serial_elapsed_seconds is not None
        else 1.0
    )
    if not math.isfinite(parallel_efficiency) or parallel_efficiency <= 0:
        raise MeasurementEvidenceError("computed parallel efficiency must be positive")
    tables_by_run = {
        _run_key(result.run_plan): result.artifacts.authoritative_table_records()
        for result in group.replicates
    }
    stages_by_run = {
        _run_key(result.run_plan): tuple(result.stage_performance)
        for result in group.replicates
    }
    serial_stages_by_run = (
        {
            _run_key(result.run_plan): tuple(result.stage_performance)
            for result in serial_group.replicates
        }
        if serial_group is not None
        else {}
    )
    with tempfile.TemporaryDirectory(prefix="htgl-performance-measurement-") as temporary:
        root = Path(temporary)
        stored_by_run: dict[tuple[str, int], int] = {}
        reports: dict[tuple[str, int, str], ParquetWriteReport] = {}
        for key, tables in sorted(tables_by_run.items()):
            before = _directory_stored_bytes(root)
            _write_tables_by_run(
                root / f"run-{_safe_token(key[0])}-{key[1]}",
                {key: tables},
                reports=reports,
                row_group_target_bytes=resolved.output.row_group_target_bytes,
            )
            stored_by_run[key] = _directory_stored_bytes(root) - before
    peak = _peak_resident_memory_bytes()
    performance: dict[tuple[str, int], PerformanceObservation] = {}
    total_rows = 0
    total_stored = 0
    for key, tables in sorted(tables_by_run.items()):
        rows = sum(len(records) for records in tables.values())
        stored = stored_by_run[key]
        if rows <= 0 or stored <= 0:
            raise MeasurementEvidenceError(
                f"performance measurement key={key} produced no rows or stored bytes"
            )
        total_rows += rows
        total_stored += stored
        performance[key] = PerformanceObservation(
            measurement_profile_id=resolved.validation.metric_threshold_profile_id,
            generated_row_count=rows,
            elapsed_seconds=elapsed_seconds,
            rows_per_second=rows / elapsed_seconds,
            peak_memory_bytes=peak,
            stored_bytes=stored,
            bytes_per_row=stored / rows,
            parallel_efficiency=parallel_efficiency,
            deterministic_digest_equal=deterministic_digest_equal,
            requested_worker_count=requested_worker_count,
            effective_worker_count=effective_worker_count,
            serial_elapsed_seconds=serial_elapsed_seconds,
            stage_observations=_enrich_stage_observations(
                key,
                stages_by_run.get(key, ()),
                reports,
                effective_worker_count=effective_worker_count,
                serial_stages=serial_stages_by_run.get(key, ()),
            ),
        )
    usage = ResourceUsage(elapsed_seconds, peak, total_rows, total_stored)
    return ReleaseEvidence(performance_by_run=performance), usage


def _enrich_stage_observations(
    key: tuple[str, int],
    stages: Sequence[StagePerformanceObservation],
    reports: Mapping[tuple[str, int, str], ParquetWriteReport],
    *,
    effective_worker_count: int,
    serial_stages: Sequence[StagePerformanceObservation],
) -> tuple[StagePerformanceObservation, ...]:
    serial_by_id = {item.stage_id: item for item in serial_stages}
    enriched: list[StagePerformanceObservation] = []
    for stage in stages:
        stage_reports = tuple(
            reports[(key[0], key[1], table_name)]
            for table_name, _ in stage.table_record_digests
            if (key[0], key[1], table_name) in reports
        )
        efficiencies = tuple(
            report.row_group_efficiency
            for report in stage_reports
            if report.row_group_efficiency is not None
        )
        if effective_worker_count > 1:
            serial_stage = serial_by_id.get(stage.stage_id)
            if serial_stage is None:
                raise MeasurementEvidenceError(
                    f"parallel stage {stage.stage_id} lacks a matching serial observation"
                )
            stage_serial_elapsed = serial_stage.elapsed_seconds
            stage_parallel_efficiency = stage_serial_elapsed / (
                stage.elapsed_seconds * effective_worker_count
            )
        else:
            stage_serial_elapsed = stage.elapsed_seconds
            stage_parallel_efficiency = 1.0
        enriched.append(
            replace(
                stage,
                stored_bytes=sum(report.stored_bytes for report in stage_reports),
                row_group_count=sum(report.row_group_count for report in stage_reports),
                row_group_efficiency=(
                    sum(efficiencies) / len(efficiencies) if efficiencies else None
                ),
                artifact_sha256=tuple(
                    (report.table_name, report.sha256)
                    for report in stage_reports
                ),
                serial_elapsed_seconds=stage_serial_elapsed,
                parallel_efficiency=stage_parallel_efficiency,
            )
        )
    return tuple(enriched)


def _resource_usage_from_evidence(evidence: ReleaseEvidence) -> ResourceUsage:
    if not evidence.performance_by_run:
        raise MeasurementEvidenceError("release evidence has no performance observations")
    values = tuple(evidence.performance_by_run.values())
    return ResourceUsage(
        elapsed_seconds=max(item.elapsed_seconds for item in values),
        peak_resident_memory_bytes=max(item.peak_memory_bytes for item in values),
        generated_row_count=sum(item.generated_row_count for item in values),
        stored_bytes=sum(item.stored_bytes for item in values),
    )


def _group_prevalidation_digest(group: Any) -> str:
    tables = {
        _run_key(result.run_plan): result.artifacts.through_validation.prevalidation_table_records()
        for result in group.replicates
    }
    return _prevalidation_semantic_digest(tables)


def _prevalidation_semantic_digest(
    tables_by_run: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
) -> str:
    return domain_sha256(
        "cli-prevalidation-semantic-inventory-v1",
        {
            f"{key[0]}:{key[1]}": {
                table_name: canonical_records_digest(rows)
                for table_name, rows in sorted(tables.items())
            }
            for key, tables in sorted(tables_by_run.items())
        },
    )


def _table_record_counts(
    tables_by_run: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for tables in tables_by_run.values():
        for table_name, rows in tables.items():
            counts[table_name] += len(rows)
    return dict(sorted(counts.items()))


def _stage_result(
    command: str,
    resolved: ResolvedConfig,
    stage_root: Path,
    semantic_digest: str,
    record_counts: Mapping[str, int],
    validation_status_counts: Mapping[str, int],
    publication_eligible: bool,
    resources: ResourceUsage,
) -> StageExecutionResult:
    manifest_sha = sha256_hex((stage_root / "manifest.json").read_bytes())
    return StageExecutionResult(
        command,
        resolved.run.run_id,
        stage_root,
        manifest_sha,
        semantic_digest,
        dict(sorted(record_counts.items())),
        dict(sorted(validation_status_counts.items())),
        publication_eligible,
        resources,
    )


def _run_key(run_plan: Any) -> tuple[str, int]:
    return str(run_plan.scenario_id), int(run_plan.replicate_id)


def _run_output_root(root: Path, run_plan: Any) -> Path:
    return (
        root
        / "runs"
        / f"scenario_id={_safe_token(run_plan.scenario_id)}"
        / f"replicate_id={int(run_plan.replicate_id)}"
    )


def _safe_token(value: Any) -> str:
    token = str(value)
    if _SAFE_TOKEN.fullmatch(token) is None or token in {".", ".."}:
        raise WorkflowApiError(f"unsafe path token {token!r}")
    return token


def _directory_stored_bytes(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _require_positive_workers(worker_count: int) -> None:
    if worker_count < 1:
        raise WorkflowApiError("worker_count must be positive")


def _parallel_policy(
    worker_count: int,
    *,
    max_in_flight: int | None,
    memory_budget_bytes: int,
    estimated_bytes_per_materialized_row: int,
) -> ParallelExecutionPolicy:
    _require_positive_workers(worker_count)
    return ParallelExecutionPolicy(
        worker_count=worker_count,
        max_in_flight=max_in_flight,
        memory_budget_bytes=memory_budget_bytes,
        estimated_bytes_per_materialized_row=estimated_bytes_per_materialized_row,
        backend="serial" if worker_count == 1 else "thread",
    )


def _peak_resident_memory_bytes() -> int:
    """Return the OS-reported process peak RSS; never synthesize a fallback."""

    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = (
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                )

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32.GetCurrentProcess.argtypes = ()
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = (
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            )
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            process = kernel32.GetCurrentProcess()
            succeeded = psapi.GetProcessMemoryInfo(
                process,
                ctypes.byref(counters),
                counters.cb,
            )
            if not succeeded or counters.PeakWorkingSetSize <= 0:
                raise OSError("GetProcessMemoryInfo returned no peak working set")
            return int(counters.PeakWorkingSetSize)
        except Exception as exc:
            raise MeasurementEvidenceError(
                f"cannot obtain Windows peak resident memory: {exc}"
            ) from exc
    try:
        import resource

        peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        if system == "Darwin":
            return peak
        return peak * 1024
    except Exception as exc:
        raise MeasurementEvidenceError(
            f"cannot obtain process peak resident memory: {exc}"
        ) from exc
