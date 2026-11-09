"""S15 artifact compiler, final release gate, and atomic publisher."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.adapters import compile_interoperability_adapters
from htgl_dataset_generator.baselines.study import build_baseline_study
from htgl_dataset_generator.config import (
    CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE,
    DEFERRED_EXTERNAL_PHYSICAL_BACKENDS,
    ResolvedConfig,
    build_run_plan,
    validate_resolved_release_profile,
)
from htgl_dataset_generator.provenance import build_source_registry
from htgl_dataset_generator.experiments.orchestration import (
    PipelineMetricsRunGroupResult,
    PipelineThroughMetricsResult,
    PipelineThroughSamplingResult,
    PipelineThroughValidationResult,
    build_metrics_for_validation_result,
    build_validation_for_sampling_result,
)
from htgl_dataset_generator.io import (
    write_metrics_artifact_bundle,
    write_baseline_artifact_bundle,
    write_observer_evaluator_sidecars,
    write_parquet_table,
)
from htgl_dataset_generator.metrics import (
    MetricConditionSeries,
    MetricsBuild,
    PairedMetricComparison,
    ReplicateMetricAggregate,
    aggregate_replicate_metrics,
    build_paired_crn_comparisons,
    validate_metric_execution_for_publication,
)
from htgl_dataset_generator.schemas import export_arrow_schema, load_contract
from htgl_dataset_generator.seeds import canonical_records_digest
from htgl_dataset_generator.validation import (
    ArtifactVerificationInput,
    ReplicateExecutionEvidence,
    validate_publication_gate,
)

from .adapters import write_observer_projection_parquet
from .canonical import (
    atomic_write_bytes,
    canonical_json_bytes,
    domain_sha256,
    sha256_hex,
)
from .layout import partition_relative_path, table_partition_groups
from .manifest import (
    inventory_release_payloads,
    manifest_rows,
    verify_manifest_closure,
    write_manifest_controls,
)
from .models import (
    ArtifactCompilerError,
    ArtifactCompilerOptions,
    ArtifactIntegrityError,
    ArtifactReleaseResult,
    ReleaseBundleResult,
    ReleaseEvidence,
    StoredArtifact,
)
from .reports import (
    build_claim_matrix,
    validate_claim_trace_closure,
    write_reports,
)
from .release_evidence import write_release_evidence
from .transaction import (
    BUNDLE_ACCESS_CLASSES,
    OWNER_MARKER,
    ReleaseBundleSetTransaction,
)


FINALIZED_LATE_TABLES = frozenset(
    {"validation_issue", "artifact_manifest"}
)


def compile_and_publish_artifacts(
    resolved: ResolvedConfig,
    primary: PipelineMetricsRunGroupResult,
    clean_rerun: PipelineMetricsRunGroupResult,
    output_root: str | Path,
    *,
    evidence: ReleaseEvidence,
    options: ArtifactCompilerOptions | None = None,
    paired_baseline: MetricConditionSeries | None = None,
    current_condition_id: str | None = None,
    current_condition_role: str = "treatment",
    current_common_random_group: str | None = None,
) -> ArtifactReleaseResult:
    """Compile, gate, and atomically publish one deterministic S15 release.

    ``clean_rerun`` must be a separately orchestrated run-group object. Runtime
    and memory values must be supplied as externally measured observations;
    this function never turns its own wall-clock into generation semantics.
    """

    settings = options if options is not None else ArtifactCompilerOptions()
    contract = load_contract()
    release_profile = validate_resolved_release_profile(resolved)
    source_registry = build_source_registry(resolved, release_profile)
    _validate_resolved_output_contract(resolved, contract)
    primary_by_key = _index_group(primary, resolved, label="primary")
    clean_by_key = _index_group(clean_rerun, resolved, label="clean_rerun")
    if primary is clean_rerun or any(
        primary_by_key[key] is clean_by_key[key] for key in primary_by_key
    ):
        raise ArtifactCompilerError(
            "clean-rerun evidence must come from separately orchestrated pipeline result objects"
        )
    expected_keys = set(primary_by_key)
    performance_keys = set(evidence.performance_by_run)
    if performance_keys != expected_keys:
        raise ArtifactCompilerError(
            f"performance evidence must cover every run exactly missing={sorted(expected_keys-performance_keys)} extra={sorted(performance_keys-expected_keys)}"
        )
    if primary.paired_comparisons and paired_baseline is None:
        raise ArtifactCompilerError(
            "provisional paired comparisons cannot be published after S13/S14 finalization; supply the paired baseline series for deterministic recomputation"
        )

    transaction = ReleaseBundleSetTransaction(
        Path(output_root),
        run_id=resolved.run.run_id,
        config_sha256=resolved.config_sha256,
        contract_fingerprint=contract.contract_fingerprint,
        collision_policy=settings.collision_policy,
    )
    transaction.begin()
    _checkpoint(settings, "after_staging_created", transaction.staging)
    try:
        _write_contract_support(
            transaction.staging,
            resolved,
            contract,
            release_profile=release_profile,
            source_registry=source_registry,
        )
        write_release_evidence(
            transaction.staging,
            evidence,
            run_id=resolved.run.run_id,
            config_sha256=resolved.config_sha256,
        )
        primary_prevalidation = {
            key: result.artifacts.through_validation.prevalidation_table_records()
            for key, result in primary_by_key.items()
        }
        clean_prevalidation = {
            key: result.artifacts.through_validation.prevalidation_table_records()
            for key, result in clean_by_key.items()
        }
        semantic_reproducibility = _compare_semantic_rerun(
            primary_prevalidation, clean_prevalidation
        )
        primary_static_paths = _write_static_tables(
            transaction.staging,
            resolved,
            primary_prevalidation,
            contract=contract,
            options=settings,
        )
        byte_reproducibility = _compare_byte_rerun(
            resolved,
            clean_prevalidation,
            primary_static_paths,
            primary_root=transaction.staging,
            contract=contract,
            options=settings,
            parent=transaction.output_root,
        )
        if settings.require_byte_reproducibility and not byte_reproducibility["byte_match"]:
            raise ArtifactIntegrityError(
                f"clean-rerun Parquet bytes differ for {byte_reproducibility['mismatched_paths']}"
            )
        transaction.record_phase(
            "core_tables_written",
            artifact_count=len(primary_static_paths),
            semantic_match=True,
            byte_match=byte_reproducibility["byte_match"],
        )
        _checkpoint(settings, "after_core_tables", transaction.staging)

        core_artifacts = _core_artifacts(
            transaction.staging,
            primary_static_paths,
            contract=contract,
        )
        core_rows = manifest_rows(
            core_artifacts,
            run_id=resolved.run.run_id,
            contract=contract,
        )
        core_verification = _verification_input(
            transaction.staging, core_artifacts, core_rows
        )
        validations, metrics = _finalize_validation_and_metrics(
            resolved,
            primary_by_key,
            clean_prevalidation,
            core_verification,
            evidence,
        )
        _remove_provisional_run_metrics(
            transaction.staging,
            primary_static_paths,
        )
        aggregates = aggregate_replicate_metrics(metrics.values(), resolved)
        comparisons = _finalize_paired_comparisons(
            metrics,
            resolved,
            paired_baseline=paired_baseline,
            current_condition_id=current_condition_id,
            current_condition_role=current_condition_role,
            current_common_random_group=current_common_random_group,
        )
        _write_final_validation_and_metrics(
            transaction.staging,
            validations,
            metrics,
            aggregates,
            comparisons,
            contract=contract,
        )
        baseline_study = build_baseline_study(resolved, primary_by_key.values())
        clean_baseline_study = build_baseline_study(resolved, clean_by_key.values())
        baseline_semantic_digest = _baseline_semantic_digest(baseline_study)
        clean_baseline_semantic_digest = _baseline_semantic_digest(clean_baseline_study)
        if baseline_semantic_digest != clean_baseline_semantic_digest:
            raise ArtifactIntegrityError(
                "clean-rerun P8 baseline/ablation semantic digest differs"
            )
        baseline_artifacts = write_baseline_artifact_bundle(
            baseline_study,
            transaction.staging,
        )
        combined_views = _write_observer_outputs(
            transaction.staging,
            primary_by_key,
            compression_level=settings.compression_level,
        )
        tables_by_run = {
            key: _final_table_records(primary_by_key[key], validations[key], metrics[key])
            for key in sorted(primary_by_key)
        }
        adapter_build = compile_interoperability_adapters(
            combined_views,
            tables_by_run,
            resolved.output.adapters,
            transaction.staging,
        )
        reproducibility = {
            **semantic_reproducibility,
            **byte_reproducibility,
            "comparison_scope": "S00-S12 schema-bound authoritative tables before final S13/S14 evidence closure",
            "clean_rerun_is_distinct_result": True,
            "baseline_semantic_match": True,
            "baseline_semantic_digest": baseline_semantic_digest,
        }
        _write_reproducibility_provenance(
            transaction.staging, resolved, reproducibility
        )
        payload_metadata_overrides = {
            **adapter_build.metadata_overrides,
            **baseline_artifacts.metadata_overrides,
        }
        report_source_artifacts = inventory_release_payloads(
            transaction.staging,
            contract=contract,
            metadata_overrides=payload_metadata_overrides,
        )
        report_source_rows = manifest_rows(
            report_source_artifacts,
            run_id=resolved.run.run_id,
            contract=contract,
        )
        claim_matrix = build_claim_matrix(
            resolved,
            tables_by_run,
            downstream_replay_by_run=evidence.downstream_replay_by_run,
        )
        report_build = write_reports(
            transaction.staging / "publication",
            artifact_root=transaction.staging,
            resolved=resolved,
            claim_matrix=claim_matrix,
            source_artifacts=report_source_artifacts,
            source_manifest_rows=report_source_rows,
            downstream_replay_by_run=evidence.downstream_replay_by_run,
        )
        transaction.record_phase(
            "release_payloads_compiled",
            validation_replicates=len(validations),
            metric_replicates=len(metrics),
            baseline_conditions=len(baseline_study.conditions),
            baseline_comparisons=len(baseline_study.comparisons),
        )
        atomic_write_bytes(
            transaction.staging / "provenance" / "recovery_log.json",
            canonical_json_bytes(transaction.recovery_snapshot()),
        )
        _checkpoint(settings, "before_manifest", transaction.staging)

        final_artifacts = inventory_release_payloads(
            transaction.staging,
            contract=contract,
            metadata_overrides={
                **payload_metadata_overrides,
                "provenance/recovery_log.json": {
                    "privacy_class": "restricted",
                    "generation_stage": "S15_transaction_recovery",
                    "publication_eligible": False,
                },
            },
        )
        final_rows = manifest_rows(
            final_artifacts,
            run_id=resolved.run.run_id,
            contract=contract,
        )
        validate_claim_trace_closure(report_build, final_rows)
        semantic_digest = _release_semantic_digest(tables_by_run)
        _run_publication_gates(
            primary_by_key,
            validations,
            metrics,
            final_rows,
            claim_matrix,
            contract=contract,
        )
        bundle_metadata = _compile_privacy_bundles(
            transaction,
            final_artifacts,
            resolved=resolved,
            contract=contract,
            semantic_digest=semantic_digest,
        )
        release_byte_digest = domain_sha256(
            "release-bundle-set-byte-inventory-v1",
            {
                access: metadata["byte_digest"]
                for access, metadata in sorted(bundle_metadata.items())
            },
        )
        transaction.record_phase(
            "bundle_manifests_and_publication_gate_passed",
            artifact_count=len(final_rows),
            bundle_set_byte_digest=release_byte_digest,
        )
        _checkpoint(settings, "after_manifest_verified", transaction.staging)
        _checkpoint(settings, "before_promotion", transaction.staging)
        reused = transaction.promote(
            {
                access: str(metadata["byte_digest"])
                for access, metadata in bundle_metadata.items()
            }
        )
        bundle_results: dict[str, ReleaseBundleResult] = {}
        for access, metadata in sorted(bundle_metadata.items()):
            release_root = transaction.targets[access]
            root_manifest = json.loads(
                (release_root / "manifest.json").read_text(encoding="utf-8")
            )
            rows = tuple(metadata["rows"])
            verify_manifest_closure(release_root, rows=rows, contract=contract)
            bundle_results[access] = ReleaseBundleResult(
                bundle_id=str(root_manifest["bundle_set_id"]),
                access_class=access,
                release_root=release_root,
                manifest_path=release_root / "manifest.json",
                manifest_sha256=sha256_hex(
                    (release_root / "manifest.json").read_bytes()
                ),
                artifact_manifest_path=release_root / "artifact_manifest.parquet",
                artifact_manifest_sha256=str(root_manifest["artifact_manifest_sha256"]),
                byte_digest=str(root_manifest["release_byte_digest"]),
                artifact_count=int(
                    root_manifest["artifact_count_excluding_root_manifest"]
                ),
                total_stored_bytes=int(
                    root_manifest["total_stored_bytes_excluding_root_manifest"]
                ),
            )
        public = bundle_results["public"]
        return ArtifactReleaseResult(
            release_root=public.release_root,
            manifest_path=public.manifest_path,
            manifest_sha256=public.manifest_sha256,
            artifact_manifest_path=public.artifact_manifest_path,
            artifact_manifest_sha256=public.artifact_manifest_sha256,
            semantic_digest=semantic_digest,
            byte_digest=release_byte_digest,
            artifact_count=sum(item.artifact_count for item in bundle_results.values()),
            total_stored_bytes=sum(
                item.total_stored_bytes for item in bundle_results.values()
            ),
            reused_existing_release=reused,
            final_validation_by_run={
                key: tuple(dict(row) for row in build.validation_issues)
                for key, build in sorted(validations.items())
            },
            final_metrics_by_run={
                key: tuple(dict(row) for row in build.run_metrics)
                for key, build in sorted(metrics.items())
            },
            bundles=dict(sorted(bundle_results.items())),
        )
    except Exception as exc:
        try:
            transaction.record_phase(
                "compilation_failed",
                exception_type=type(exc).__name__,
                message=str(exc),
            )
        except Exception as recovery_exc:
            exc.add_note(
                f"S15 recovery-log update also failed: {type(recovery_exc).__name__}: {recovery_exc}"
            )
        transaction.abort()
        raise


def _index_group(
    group: PipelineMetricsRunGroupResult,
    resolved: ResolvedConfig,
    *,
    label: str,
) -> dict[tuple[str, int], PipelineThroughMetricsResult]:
    indexed: dict[tuple[str, int], PipelineThroughMetricsResult] = {}
    for result in group.replicates:
        key = (result.run_plan.scenario_id, result.run_plan.replicate_id)
        if key in indexed:
            raise ArtifactCompilerError(f"{label} contains duplicate replicate key {key}")
        if result.run_plan.run_id != resolved.run.run_id:
            raise ArtifactCompilerError(f"{label} run ID does not match resolved config")
        indexed[key] = result
    expected = {
        (plan.scenario_id, plan.replicate_id) for plan in build_run_plan(resolved)
    }
    if set(indexed) != expected:
        raise ArtifactCompilerError(
            f"{label} replicate coverage mismatch missing={sorted(expected-set(indexed))} extra={sorted(set(indexed)-expected)}"
        )
    return dict(sorted(indexed.items()))


def _validate_resolved_output_contract(resolved: ResolvedConfig, contract: Any) -> None:
    if resolved.output.parquet_compression != "ZSTD":
        raise ArtifactCompilerError("authoritative S15 output requires Parquet/ZSTD")
    if resolved.output.manifest_policy != "final_bytes_sha256_schema_bound":
        raise ArtifactCompilerError("unsupported manifest policy")
    if resolved.output.archive_policy != "deterministic_atomic_release":
        raise ArtifactCompilerError("unsupported non-transactional archive policy")
    if resolved.output.schema_contract_fingerprint != contract.contract_fingerprint:
        raise ArtifactCompilerError("resolved output schema fingerprint does not match loaded contract")
    configured = set(resolved.output.table_schema_ids)
    expected = {table.schema_id for table in contract.tables}
    if configured != expected:
        raise ArtifactCompilerError(
            f"resolved schema inventory mismatch missing={sorted(expected-configured)} extra={sorted(configured-expected)}"
        )


def _write_contract_support(
    root: Path,
    resolved: ResolvedConfig,
    contract: Any,
    *,
    release_profile: Any,
    source_registry: Any,
) -> None:
    atomic_write_bytes(
        root / "config" / "config_resolved.json",
        canonical_json_bytes(resolved.as_dict()),
    )
    contract_payload = json.loads(contract.path.read_text(encoding="utf-8"))
    atomic_write_bytes(
        root / "schemas" / "htgl_contract_v1.json",
        canonical_json_bytes(contract_payload),
    )
    for table in sorted(contract.tables, key=lambda item: item.table_name):
        atomic_write_bytes(
            root / "schemas" / "arrow" / f"{table.table_name}.schema.json",
            canonical_json_bytes(export_arrow_schema(table)),
        )
    atomic_write_bytes(
        root / "provenance" / "sources.json",
        canonical_json_bytes(source_registry.as_dict()),
    )
    atomic_write_bytes(
        root / "publication" / "provenance" / "source_registry.json",
        canonical_json_bytes(source_registry.as_dict()),
    )
    atomic_write_bytes(
        root / "provenance" / "release_profile.json",
        canonical_json_bytes(
            {
                **release_profile.as_dict(),
                "code_version": resolved.run.code_version,
                "container_version": resolved.run.container_version,
                "contract_version": resolved.run.contract_version,
                "config_sha256": resolved.config_sha256,
                "source_registry_sha256": source_registry.registry_sha256,
                "source_labels": dict(sorted(resolved.source_labels.items())),
                "resolved_references": dict(sorted(resolved.resolved_references.items())),
                "physical_profile_class": "controlled_procedural_synthetic",
                "external_physical_integration_executed": False,
                "external_power_flow_solver_executed": False,
                "calibrated_physical_fidelity_claim_eligible": False,
                "physical_validity_scope": CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE,
                "deferred_external_physical_backends": sorted(
                    DEFERRED_EXTERNAL_PHYSICAL_BACKENDS
                ),
                "proof_limit_statement": resolved.evidence.proof_limit_statement,
                "generator_boundary": (
                    "generates workloads, truth, evidence fixtures, projections, samples and validated benchmark artifacts only"
                ),
            }
        ),
    )


def _write_static_tables(
    root: Path,
    resolved: ResolvedConfig,
    tables_by_run: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    *,
    contract: Any,
    options: ArtifactCompilerOptions,
) -> dict[str, tuple[str, int]]:
    written: dict[str, tuple[str, int]] = {}
    for (scenario_id, replicate_id), tables in sorted(tables_by_run.items()):
        for table_name, raw_rows in sorted(tables.items()):
            if table_name in FINALIZED_LATE_TABLES:
                continue
            if table_name not in contract.table_names:
                raise ArtifactCompilerError(
                    f"pipeline exposed non-contract authoritative table {table_name!r}"
                )
            rows = tuple(dict(row) for row in raw_rows)
            groups = table_partition_groups(
                table_name,
                rows,
                scenario_id=scenario_id,
                replicate_id=replicate_id,
                configured_partition_keys=resolved.output.partition_keys,
                fact_partition_minimum_rows=options.fact_partition_minimum_rows,
                region_partition_minimum_rows=options.region_partition_minimum_rows,
                minimum_rows_per_region_partition=options.minimum_rows_per_region_partition,
            )
            for index, (partition, group_rows) in enumerate(groups):
                relative = partition_relative_path(
                    table_name, partition, part_index=index
                )
                if relative in written:
                    raise ArtifactCompilerError(f"table partition path collision {relative}")
                write_parquet_table(
                    table_name,
                    group_rows,
                    root / relative,
                    contract=contract,
                    compression="ZSTD",
                    compression_level=options.compression_level,
                    canonical_sort=True,
                    row_group_target_bytes=resolved.output.row_group_target_bytes,
                )
                written[relative] = (table_name, len(group_rows))
    return dict(sorted(written.items()))


def _compare_semantic_rerun(
    primary: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
    clean: Mapping[tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]],
) -> dict[str, Any]:
    primary_digests = {
        f"{key[0]}:{key[1]}:{table_name}": canonical_records_digest(rows)
        for key, tables in sorted(primary.items())
        for table_name, rows in sorted(tables.items())
    }
    clean_digests = {
        f"{key[0]}:{key[1]}:{table_name}": canonical_records_digest(rows)
        for key, tables in sorted(clean.items())
        for table_name, rows in sorted(tables.items())
    }
    mismatched = sorted(
        set(primary_digests) ^ set(clean_digests)
        | {
            key
            for key in set(primary_digests) & set(clean_digests)
            if primary_digests[key] != clean_digests[key]
        }
    )
    if mismatched:
        raise ArtifactIntegrityError(
            f"clean-rerun semantic table digests differ for {mismatched}"
        )
    return {
        "semantic_match": True,
        "semantic_table_count": len(primary_digests),
        "semantic_inventory_digest": domain_sha256(
            "clean-rerun-semantic-inventory-v1", primary_digests
        ),
    }


def _compare_byte_rerun(
    resolved: ResolvedConfig,
    clean_tables: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    primary_paths: Mapping[str, tuple[str, int]],
    *,
    primary_root: Path,
    contract: Any,
    options: ArtifactCompilerOptions,
    parent: Path,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=".htgl-clean-rerun-", dir=parent) as temporary:
        clean_root = Path(temporary)
        clean_paths = _write_static_tables(
            clean_root,
            resolved,
            clean_tables,
            contract=contract,
            options=options,
        )
        if set(clean_paths) != set(primary_paths):
            mismatched = sorted(set(clean_paths) ^ set(primary_paths))
            return {
                "byte_match": False,
                "byte_artifact_count": len(primary_paths),
                "mismatched_paths": mismatched,
                "byte_inventory_digest": "",
            }
        clean_digests = {
            relative: sha256_hex((clean_root / relative).read_bytes())
            for relative in clean_paths
        }
    primary_digests = {
        relative: sha256_hex((primary_root / relative).read_bytes())
        for relative in primary_paths
    }
    mismatched = sorted(
        relative
        for relative in primary_digests
        if primary_digests[relative] != clean_digests[relative]
    )
    return {
        "byte_match": not mismatched,
        "byte_artifact_count": len(primary_digests),
        "mismatched_paths": mismatched,
        "byte_inventory_digest": domain_sha256(
            "clean-rerun-byte-inventory-v1", primary_digests
        ),
    }


def _core_artifacts(
    root: Path,
    static_paths: Mapping[str, tuple[str, int]],
    *,
    contract: Any,
) -> tuple[StoredArtifact, ...]:
    inventory = inventory_release_payloads(root, contract=contract)
    by_path = {item.relative_path: item for item in inventory}
    if set(static_paths) - set(by_path):
        raise ArtifactIntegrityError("static Parquet inventory is incomplete")
    return tuple(by_path[path] for path in sorted(static_paths))


def _remove_provisional_run_metrics(
    root: Path,
    static_paths: Mapping[str, tuple[str, int]],
) -> None:
    """Remove S12 provisional metric bytes after S13 has verified its input set."""

    metric_paths = [
        relative
        for relative, (table_name, _) in static_paths.items()
        if table_name == "run_metric"
    ]
    if not metric_paths:
        raise ArtifactIntegrityError("S13 manifest scope omitted provisional run_metric")
    for relative in metric_paths:
        path = root / relative
        if not path.is_file():
            raise ArtifactIntegrityError(
                f"provisional run_metric payload disappeared before S14 finalization: {relative}"
            )
        path.unlink()


def _verification_input(
    root: Path,
    artifacts: Sequence[StoredArtifact],
    rows: Sequence[Mapping[str, Any]],
) -> ArtifactVerificationInput:
    if any(item.schema_id is None or item.record_count is None for item in artifacts):
        raise ArtifactIntegrityError(
            "S13 core verification can contain only schema-bound Parquet payloads"
        )
    return ArtifactVerificationInput(
        artifact_payloads={
            item.relative_path: (root / item.relative_path).read_bytes()
            for item in artifacts
        },
        manifest_rows=tuple(rows),
        expected_record_counts={
            item.relative_path: int(item.record_count) for item in artifacts
        },
        expected_schema_ids={
            item.relative_path: item.schema_id for item in artifacts
        },
    )


def _finalize_validation_and_metrics(
    resolved: ResolvedConfig,
    primary: Mapping[tuple[str, int], PipelineThroughMetricsResult],
    clean_prevalidation: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
    verification: ArtifactVerificationInput,
    evidence: ReleaseEvidence,
) -> tuple[dict[tuple[str, int], Any], dict[tuple[str, int], MetricsBuild]]:
    replicate_evidence = tuple(
        ReplicateExecutionEvidence(
            scenario_id=result.run_plan.scenario_id,
            replicate_id=result.run_plan.replicate_id,
            seed_stream_digest=result.seed_stream_digest,
            retained_metric_count=len(
                result.artifacts.through_validation.through_sampling.authoritative_table_records().get(
                    "run_metric", ()
                )
            ),
        )
        for _, result in sorted(primary.items())
    )
    physical_inputs = evidence.physical_reference_by_run or {}
    privacy_inputs = evidence.privacy_reference_by_run or {}
    validations: dict[tuple[str, int], Any] = {}
    metrics: dict[tuple[str, int], MetricsBuild] = {}
    for key, result in sorted(primary.items()):
        through_sampling = result.artifacts.through_validation.through_sampling
        sampling_result = PipelineThroughSamplingResult(
            run_plan=result.run_plan,
            seed_stream_digest=result.seed_stream_digest,
            artifacts=through_sampling,
            table_digests={
                name: canonical_records_digest(rows)
                for name, rows in through_sampling.authoritative_table_records().items()
            },
        )
        reference_digests = {
            name: canonical_records_digest(rows)
            for name, rows in sorted(clean_prevalidation[key].items())
        }
        validation_build = build_validation_for_sampling_result(
            resolved,
            sampling_result,
            replicate_evidence=replicate_evidence,
            artifact_verification=verification,
            reproducibility_reference_digests=reference_digests,
            performance_observation=evidence.performance_by_run[key],
        )
        validation_result = PipelineThroughValidationResult(
            run_plan=result.run_plan,
            seed_stream_digest=result.seed_stream_digest,
            artifacts=validation_build,
            table_digests={
                name: canonical_records_digest(rows)
                for name, rows in validation_build.authoritative_table_records().items()
            },
        )
        metrics_build = build_metrics_for_validation_result(
            resolved,
            validation_result,
            physical_reference=physical_inputs.get(key),
            privacy_reference=privacy_inputs.get(key),
            artifact_verification=verification,
            reproducibility_reference_digests=reference_digests,
            performance_observation=evidence.performance_by_run[key],
        ).metrics
        if not validation_build.validation.release_eligible:
            unresolved = [
                {
                    "check_id": row["check_id"],
                    "status": row["status"],
                    "message": row["message"],
                    "observed_value": row["observed_value"],
                }
                for row in validation_build.validation.validation_issues
                if row["status"] not in {"pass", "not_applicable"}
            ]
            raise ArtifactCompilerError(
                f"scenario={key[0]} replicate={key[1]} failed final validation checks {unresolved}"
            )
        validations[key] = validation_build.validation
        metrics[key] = metrics_build
    return dict(sorted(validations.items())), dict(sorted(metrics.items()))


def _finalize_paired_comparisons(
    metrics: Mapping[tuple[str, int], MetricsBuild],
    resolved: ResolvedConfig,
    *,
    paired_baseline: MetricConditionSeries | None,
    current_condition_id: str | None,
    current_condition_role: str,
    current_common_random_group: str | None,
) -> tuple[PairedMetricComparison, ...]:
    if paired_baseline is None:
        return ()
    if not current_condition_id or not current_common_random_group:
        raise ArtifactCompilerError(
            "paired final metrics require current_condition_id and current_common_random_group"
        )
    current = MetricConditionSeries(
        condition_id=current_condition_id,
        condition_role=current_condition_role,
        common_random_group=current_common_random_group,
        metrics=tuple(row for build in metrics.values() for row in build.run_metrics),
        provenance=tuple(item for build in metrics.values() for item in build.provenance),
    )
    return build_paired_crn_comparisons(paired_baseline, (current,), resolved)


def _write_final_validation_and_metrics(
    root: Path,
    validations: Mapping[tuple[str, int], Any],
    metrics: Mapping[tuple[str, int], MetricsBuild],
    aggregates: Sequence[ReplicateMetricAggregate],
    comparisons: Sequence[PairedMetricComparison],
    *,
    contract: Any,
) -> None:
    validation_rows = tuple(
        row
        for _, build in sorted(validations.items())
        for row in build.validation_issues
    )
    write_parquet_table(
        "validation_issue",
        validation_rows,
        root / "validation" / "validation_issue.parquet",
        contract=contract,
        compression="ZSTD",
        compression_level=9,
        canonical_sort=True,
    )
    status_counts = Counter(str(row["status"]) for row in validation_rows)
    atomic_write_bytes(
        root / "validation" / "validation_metadata.json",
        canonical_json_bytes(
            {
                "format": "htgl.validation.release-bundle.v1",
                "replicate_count": len(validations),
                "status_counts": dict(sorted(status_counts.items())),
                "release_eligible": all(build.release_eligible for build in validations.values()),
                "threshold_profiles": sorted(
                    {
                        (build.threshold_profile_id, build.threshold_profile_sha256)
                        for build in validations.values()
                    }
                ),
                "claim_boundary": "benchmark release checks only; not legal compliance or physical deletion verification",
            }
        ),
    )
    write_metrics_artifact_bundle(
        tuple(metrics[key] for key in sorted(metrics)),
        aggregates,
        comparisons,
        root,
        contract=contract,
    )


def _write_observer_outputs(
    root: Path,
    primary: Mapping[tuple[str, int], PipelineThroughMetricsResult],
    *,
    compression_level: int,
) -> dict[str, Any]:
    combined: dict[str, Any] = {}
    for key, result in sorted(primary.items()):
        observers = (
            result.artifacts.through_validation.through_sampling.through_observers.observers
        )
        sidecar_root = (
            root
            / "observers"
            / "evaluator_only"
            / f"scenario_id={key[0]}"
            / f"replicate_id={key[1]}"
        )
        write_observer_evaluator_sidecars(observers, sidecar_root)
        for view_key, view in sorted(observers.release_views.items()):
            combined_key = f"{key[0]}:replicate-{key[1]}:{view_key}"
            if combined_key in combined:
                raise ArtifactCompilerError(
                    f"observer release view collision {combined_key}"
                )
            write_observer_projection_parquet(
                combined_key,
                view,
                root,
                compression_level=compression_level,
            )
            combined[combined_key] = view
    return dict(sorted(combined.items()))


def _write_reproducibility_provenance(
    root: Path,
    resolved: ResolvedConfig,
    reproducibility: Mapping[str, Any],
) -> None:
    atomic_write_bytes(
        root / "provenance" / "reproducibility.json",
        canonical_json_bytes(
            {
                "format": "htgl.reproducibility-evidence.v1",
                "run_id": resolved.run.run_id,
                "config_sha256": resolved.config_sha256,
                **dict(reproducibility),
                "common_random_numbers_are_independent_replicates": False,
            }
        ),
    )


def _final_table_records(
    result: PipelineThroughMetricsResult,
    validation: Any,
    metrics: MetricsBuild,
) -> dict[str, tuple[Mapping[str, Any], ...]]:
    tables = dict(result.artifacts.through_validation.prevalidation_table_records())
    tables["validation_issue"] = validation.validation_issues
    tables["run_metric"] = metrics.run_metrics
    return dict(sorted(tables.items()))


def _release_semantic_digest(
    tables_by_run: Mapping[
        tuple[str, int], Mapping[str, Sequence[Mapping[str, Any]]]
    ],
) -> str:
    inventory = {
        f"{key[0]}:{key[1]}:{table_name}": canonical_records_digest(rows)
        for key, tables in sorted(tables_by_run.items())
        for table_name, rows in sorted(tables.items())
    }
    return domain_sha256("release-semantic-inventory-v1", inventory)


def _baseline_semantic_digest(build: Any) -> str:
    return domain_sha256(
        "P8-baseline-study-semantic-v1",
        {
            "registry_sha256": build.registry.sha256,
            "conditions": [asdict(item) for item in build.conditions],
            "metrics": [asdict(item) for item in build.metrics],
            "comparisons": [asdict(item) for item in build.comparisons],
            "output_samples": [asdict(item) for item in build.output_samples],
        },
    )


def _compile_privacy_bundles(
    transaction: ReleaseBundleSetTransaction,
    artifacts: Sequence[StoredArtifact],
    *,
    resolved: ResolvedConfig,
    contract: Any,
    semantic_digest: str,
) -> dict[str, dict[str, Any]]:
    """Copy validated payloads into three non-overlapping access-class roots."""

    allowed_privacy = {
        "public": {"public"},
        "evaluator_only": {"public", "evaluator_only", "sealed"},
        "restricted": {"public", "restricted"},
    }
    assigned: dict[str, str] = {}
    for artifact in artifacts:
        if artifact.privacy_class == "public":
            target_access = "public"
        elif artifact.privacy_class == "restricted":
            target_access = "restricted"
        elif artifact.privacy_class in {"evaluator_only", "sealed"}:
            target_access = "evaluator_only"
        else:
            raise ArtifactIntegrityError(
                f"unroutable artifact privacy class {artifact.privacy_class!r}"
            )
        assigned[artifact.relative_path] = target_access
        _copy_bundle_payload(
            transaction.staging / artifact.relative_path,
            transaction.bundle_staging(target_access) / artifact.relative_path,
        )
        if artifact.relative_path.startswith("schemas/"):
            for access in BUNDLE_ACCESS_CLASSES:
                if access == target_access:
                    continue
                _copy_bundle_payload(
                    transaction.staging / artifact.relative_path,
                    transaction.bundle_staging(access) / artifact.relative_path,
                )
    if set(assigned) != {item.relative_path for item in artifacts}:
        raise ArtifactIntegrityError("privacy bundle routing omitted staged artifacts")

    for access in BUNDLE_ACCESS_CLASSES:
        descriptor = {
            "format": "htgl.release-bundle-descriptor.v1",
            "bundle_set_id": transaction.bundle_set_id,
            "run_id": resolved.run.run_id,
            "config_sha256": resolved.config_sha256,
            "release_profile_id": resolved.output.release_profile_id,
            "bundle_access_class": access,
            "permitted_privacy_classes": sorted(allowed_privacy[access]),
            "sibling_bundle_directories": {
                key: value.name for key, value in sorted(transaction.targets.items())
            },
            "physical_separation_required": True,
            "combined_archive_permitted": False,
        }
        atomic_write_bytes(
            transaction.bundle_staging(access) / "bundle_descriptor.json",
            canonical_json_bytes(descriptor),
        )
        transaction.seal_bundle_owner_marker(access)

    result: dict[str, dict[str, Any]] = {}
    artifact_by_path = {item.relative_path: item for item in artifacts}
    for access in BUNDLE_ACCESS_CLASSES:
        root = transaction.bundle_staging(access)
        overrides = {
            relative: {
                "privacy_class": artifact.privacy_class,
                "generation_stage": artifact.generation_stage,
                "publication_eligible": artifact.publication_eligible,
            }
            for relative, artifact in artifact_by_path.items()
            if (root / relative).is_file()
        }
        overrides.update({
            OWNER_MARKER: {
                "privacy_class": access,
                "generation_stage": "S15_bundle_set_owner",
                "publication_eligible": False,
            },
            "bundle_descriptor.json": {
                "privacy_class": access,
                "generation_stage": "S15_bundle_set_descriptor",
                "publication_eligible": access == "public",
            },
        })
        bundle_artifacts = inventory_release_payloads(
            root,
            contract=contract,
            metadata_overrides=overrides,
        )
        invalid = sorted(
            item.relative_path
            for item in bundle_artifacts
            if item.privacy_class not in allowed_privacy[access]
        )
        if invalid:
            raise ArtifactIntegrityError(
                f"{access} bundle contains disallowed privacy classes at {invalid[:16]}"
            )
        rows = manifest_rows(
            bundle_artifacts,
            run_id=resolved.run.run_id,
            contract=contract,
        )
        (
            artifact_manifest_path,
            manifest_path,
            manifest_sha256,
            byte_digest,
        ) = write_manifest_controls(
            root,
            artifacts=bundle_artifacts,
            rows=rows,
            run_id=resolved.run.run_id,
            config_sha256=resolved.config_sha256,
            contract=contract,
            stable_release_timestamp=resolved.run.horizon_end,
            semantic_digest=semantic_digest,
            bundle_set_id=transaction.bundle_set_id,
            bundle_access_class=access,
        )
        result[access] = {
            "artifact_manifest_path": artifact_manifest_path,
            "manifest_path": manifest_path,
            "manifest_sha256": manifest_sha256,
            "byte_digest": byte_digest,
            "artifact_count": len(rows) + 1,
            "rows": rows,
        }
    return dict(sorted(result.items()))


def _copy_bundle_payload(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise ArtifactIntegrityError(f"bundle source payload disappeared: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256_hex(destination.read_bytes()) != sha256_hex(source.read_bytes()):
            raise ArtifactIntegrityError(
                f"bundle payload collision with different bytes: {destination}"
            )
        return
    shutil.copy2(source, destination)


def _run_publication_gates(
    primary: Mapping[tuple[str, int], PipelineThroughMetricsResult],
    validations: Mapping[tuple[str, int], Any],
    metrics: Mapping[tuple[str, int], MetricsBuild],
    artifact_rows: Sequence[Mapping[str, Any]],
    claim_matrix: Mapping[str, Any],
    *,
    contract: Any,
) -> None:
    for key, result in sorted(primary.items()):
        validate_metric_execution_for_publication(metrics[key])
        memberships = (
            result.artifacts.through_validation.through_sampling.sampling.sample_memberships
        )
        validate_publication_gate(
            {
                "validation_issue": validations[key].validation_issues,
                "run_metric": metrics[key].run_metrics,
                "artifact_manifest": tuple(artifact_rows),
                "sample_membership": memberships,
            },
            claim_matrix=claim_matrix,
            contract=contract,
        )


def _checkpoint(
    options: ArtifactCompilerOptions,
    phase: str,
    staging: Path,
) -> None:
    if options.failure_injector is not None:
        options.failure_injector(phase, staging)
