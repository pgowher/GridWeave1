"""Execute P8 study cells and bind scale claims to retained pipeline evidence."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from statistics import NormalDist, fmean, stdev
from typing import Iterable, Mapping

from htgl_dataset_generator.artifacts import (
    ArtifactCompilerOptions,
    ReleaseEvidence,
    compile_and_publish_artifacts,
)
from htgl_dataset_generator.artifacts.canonical import canonical_json_text, domain_sha256
from htgl_dataset_generator.config import ResolvedConfig

from .condition_config import compile_condition_config
from .execution import ParallelExecutionPolicy
from .orchestration import PipelineMetricsRunGroupResult, orchestrate_pipeline_through_metrics
from .study_models import (
    DownstreamReplayEvidence,
    FactorialStudyPlan,
    ReplicateStudyEvidence,
    ScaleClaim,
    StudyCondition,
    StudyExecutionBuild,
)


class StudyExecutionError(RuntimeError):
    """Raised when execution evidence is inconsistent with a resolved study plan."""


def execute_factorial_study(
    base_config: ResolvedConfig,
    plan: FactorialStudyPlan,
    *,
    condition_ids: Iterable[str] | None = None,
    worker_count: int = 1,
    execution_policy: ParallelExecutionPolicy | None = None,
    publication_evidence_by_condition: Mapping[str, ReleaseEvidence] | None = None,
    condition_release_output_root: str | Path | None = None,
    artifact_options: ArtifactCompilerOptions | None = None,
    downstream_replay_evidence: Iterable[DownstreamReplayEvidence] = (),
) -> StudyExecutionBuild:
    """Execute selected eligible cells; absent evidence remains explicitly unresolved.

    Conditions supplied with ``ReleaseEvidence`` are independently rerun and passed
    through S15. Conditions without it are diagnostic S00-S14 executions and cannot
    support publication claims.
    """

    if worker_count < 1:
        raise StudyExecutionError("worker_count must be positive")
    by_id = {condition.condition_id: condition for condition in plan.conditions}
    if condition_ids is None:
        selected = tuple(
            condition.condition_id
            for condition in plan.conditions
            if condition.feasibility_status == "eligible"
        )
    else:
        selected = tuple(condition_ids)
        if len(selected) != len(set(selected)):
            raise StudyExecutionError("condition_ids must be unique")
    unknown = sorted(set(selected) - set(by_id))
    if unknown:
        raise StudyExecutionError(f"unknown condition IDs {unknown}")
    non_executable = sorted(
        condition_id
        for condition_id in selected
        if by_id[condition_id].feasibility_status != "eligible"
    )
    if non_executable:
        raise StudyExecutionError(f"selected conditions are blocked by the plan: {non_executable}")
    publication_inputs = publication_evidence_by_condition or {}
    unknown_publication = sorted(set(publication_inputs) - set(selected))
    if unknown_publication:
        raise StudyExecutionError(
            f"publication evidence supplied for unselected conditions {unknown_publication}"
        )
    if publication_inputs and condition_release_output_root is None:
        raise StudyExecutionError(
            "condition_release_output_root is required when S15 publication evidence is supplied"
        )
    replay_by_key = _index_replay_evidence(downstream_replay_evidence, by_id)
    rows_by_key: dict[tuple[str, int], ReplicateStudyEvidence] = {}
    metric_rows: list[Mapping[str, object]] = []
    factor_metric_rows: list[Mapping[str, object]] = []
    aggregate_rows: list[Mapping[str, object]] = []
    validation_rows: list[Mapping[str, object]] = []

    for condition_id in selected:
        condition = by_id[condition_id]
        resolved = compile_condition_config(base_config, condition, study_id=plan.study_id)
        release_evidence = publication_inputs.get(condition_id)
        try:
            performance = release_evidence.performance_by_run if release_evidence else {}
            primary = orchestrate_pipeline_through_metrics(
                resolved,
                worker_count=worker_count,
                execution_policy=execution_policy,
                physical_reference_by_run=(
                    release_evidence.physical_reference_by_run if release_evidence else None
                ),
                privacy_reference_by_run=(
                    release_evidence.privacy_reference_by_run if release_evidence else None
                ),
                performance_observation_by_run=performance,
                current_condition_id=condition.condition_id,
                current_common_random_group=condition.common_random_group,
            )
            release_manifest_sha256: str | None = None
            release_finalized = False
            condition_metrics, condition_validations = _provisional_ledgers(
                condition, primary
            )
            if release_evidence is not None:
                clean = orchestrate_pipeline_through_metrics(
                    resolved,
                    worker_count=worker_count,
                    execution_policy=execution_policy,
                )
                release_result = compile_and_publish_artifacts(
                    resolved,
                    primary,
                    clean,
                    Path(condition_release_output_root),
                    evidence=release_evidence,
                    options=artifact_options
                    or ArtifactCompilerOptions(collision_policy="reuse_identical"),
                    current_condition_id=condition.condition_id,
                    current_common_random_group=condition.common_random_group,
                )
                release_manifest_sha256 = release_result.manifest_sha256
                release_finalized = True
                condition_metrics, condition_validations = _final_release_ledgers(
                    condition, release_result
                )
            metric_rows.extend(condition_metrics)
            validation_rows.extend(condition_validations)
            for result in primary.replicates:
                factor_metric_rows.extend(
                    _factor_metrics_for_result(condition, result)
                )
            for aggregate in primary.aggregates:
                aggregate_rows.append(
                    {
                        "condition_id": condition.condition_id,
                        "aggregate_kind": "S14_registered_metric",
                        "represented_population_N": condition.represented_population_N,
                        "materialized_row_target_n": condition.materialized_row_target_n,
                        "executed_operation_target_q": condition.executed_operation_target_q,
                        **asdict(aggregate),
                    }
                )
            for result in primary.replicates:
                key = (condition_id, result.run_plan.replicate_id)
                replay = replay_by_key.get(
                    (condition_id, result.run_plan.scenario_id, result.run_plan.replicate_id)
                )
                rows_by_key[key] = _replicate_evidence_from_result(
                    condition,
                    result,
                    performance.get(
                        (result.run_plan.scenario_id, result.run_plan.replicate_id)
                    ),
                    release_manifest_sha256=release_manifest_sha256,
                    release_finalized=release_finalized,
                    replay=replay,
                )
        except Exception as exc:
            for replicate_id in range(condition.repetitions):
                rows_by_key[(condition_id, replicate_id)] = ReplicateStudyEvidence(
                    condition_id=condition_id,
                    run_id=f"{plan.study_id}-{condition_id}",
                    scenario_id=base_config.run.scenario_id,
                    replicate_id=replicate_id,
                    execution_status="failed",
                    represented_population_N=condition.represented_population_N,
                    materialized_row_target_n=condition.materialized_row_target_n,
                    materialized_governance_event_rows_n=None,
                    materialized_total_table_rows=None,
                    executed_operations_q=None,
                    seed_stream_digest=None,
                    canonical_table_digest=None,
                    retained_metric_count=0,
                    validation_status="failed",
                    known_total_status="not_executed",
                    maximum_absolute_relative_bias=None,
                    relative_rmse=None,
                    minimum_ci_coverage=None,
                    resource_status="not_measured",
                    generated_rows=None,
                    elapsed_seconds=None,
                    rows_per_second=None,
                    peak_resident_memory_bytes=None,
                    stored_bytes=None,
                    artifact_manifest_sha256=None,
                    clean_rerun_digest_match=None,
                    failure_code=type(exc).__name__,
                    failure_message=str(exc) or repr(exc),
                )

    all_rows = _complete_execution_ledger(base_config, plan, rows_by_key)
    consumed_replay_keys = {
        (row.condition_id, row.scenario_id, row.replicate_id)
        for row in all_rows
        if row.executed_operations_q is not None
    }
    unused_replay = sorted(set(replay_by_key) - consumed_replay_keys)
    if unused_replay:
        raise StudyExecutionError(
            f"downstream replay evidence was not bound to successful generator replicates {unused_replay}"
        )
    aggregate_rows.extend(_aggregate_factor_metrics(factor_metric_rows))
    claims = tuple(_scale_claim(condition, all_rows, plan) for condition in plan.conditions)
    blockers = _publication_blockers(plan, all_rows, claims)
    execution_payload = {
        "plan_sha256": plan.plan_sha256,
        "replicate_evidence": [asdict(row) for row in all_rows],
        "run_metrics": metric_rows,
        "factor_metrics": factor_metric_rows,
        "metric_aggregates": aggregate_rows,
        "validation_issues": validation_rows,
        "scale_claims": [asdict(claim) for claim in claims],
        "publication_blockers": blockers,
    }
    return StudyExecutionBuild(
        plan=plan,
        replicate_evidence=all_rows,
        run_metrics=tuple(
            sorted(
                metric_rows,
                key=lambda row: (
                    str(row["condition_id"]),
                    str(row["scenario_id"]),
                    int(row["replicate_id"]),
                    str(row["metric_id"]),
                ),
            )
        ),
        factor_metrics=tuple(
            sorted(
                factor_metric_rows,
                key=lambda row: (
                    str(row["condition_id"]),
                    str(row["scenario_id"]),
                    int(row["replicate_id"]),
                    str(row["axis_id"]),
                    str(row["metric_name"]),
                ),
            )
        ),
        metric_aggregates=tuple(
            sorted(
                aggregate_rows,
                key=lambda row: (
                    str(row["condition_id"]),
                    str(row["aggregate_kind"]),
                    str(row.get("metric_key", row.get("metric_name", ""))),
                    str(row.get("scope_id", row.get("axis_id", ""))),
                ),
            )
        ),
        validation_issues=tuple(
            sorted(
                validation_rows,
                key=lambda row: (
                    str(row["condition_id"]),
                    str(row["scenario_id"]),
                    int(row["replicate_id"]),
                    str(row["check_id"]),
                ),
            )
        ),
        scale_claims=claims,
        execution_sha256=domain_sha256("P8-factorial-study-execution", execution_payload),
        publication_eligible=not blockers,
        publication_blockers=blockers,
    )


OBSERVER_PROFILE_BY_LEVEL = {
    "full": "OBS-FULL-EVALUATOR",
    "role_based": "OBS-DSO-DIRECT",
    "delayed": "OBS-AUDITOR-DELAYED",
    "lossy": "OBS-PUBLIC-LOSSY",
    "adversarial_omission": "OBS-ADVERSARIAL-OMISSION",
    "collusion": "OBS-COLLUSION-UTILITY-AUDITOR",
}

EVIDENCE_TYPES_BY_LEVEL = {
    "digest": frozenset({"digest"}),
    "hmac_signature": frozenset(
        {"hmac", "signature", "deletion_acknowledgement", "audit_finding", "notification_receipt"}
    ),
    "merkle": frozenset({"inclusion_proof", "merkle_anchor"}),
    "replica_attestation": frozenset({"replica_attestation"}),
    "mixed": frozenset(
        {
            "digest", "hmac", "signature", "inclusion_proof", "deletion_acknowledgement",
            "replica_attestation", "audit_finding", "merkle_anchor", "notification_receipt",
        }
    ),
}


def _factor_metrics_for_result(
    condition: StudyCondition,
    result: object,
) -> list[Mapping[str, object]]:
    artifacts = result.artifacts
    through_sampling = artifacts.through_validation.through_sampling
    through_observers = through_sampling.through_observers
    through_evidence = through_observers.through_anomalies.through_evidence
    metrics: list[Mapping[str, object]] = []
    visibility_level = str(condition.factor_values["visibility_profile"])
    profile_id = OBSERVER_PROFILE_BY_LEVEL[visibility_level]
    diagnostic = through_observers.observers.diagnostics[profile_id]
    observer_fields = (
        ("visible_event_coverage", diagnostic.weighted_visible_event_coverage, "fraction", diagnostic.weighted_visible_event_coverage * diagnostic.source_event_count, diagnostic.source_event_count),
        ("evidence_recoverability", diagnostic.evidence_recoverability, "fraction", None, None),
        ("omission_rate", diagnostic.overall_omission_rate, "fraction", diagnostic.omitted_event_count, diagnostic.source_event_count),
        ("mean_delay_seconds", diagnostic.mean_delay_seconds, "seconds", None, diagnostic.visible_event_count),
        ("collusion_gain", diagnostic.collusion_gain, "fraction", None, None),
        ("sealed_truth_leakage", float(diagnostic.sealed_truth_leakage_count), "count", float(diagnostic.sealed_truth_leakage_count), diagnostic.visible_event_count),
    )
    for name, value, unit, numerator, denominator in observer_fields:
        metrics.append(
            _factor_metric(
                condition, result, axis_id="visibility_profile", level_id=condition.factor_level_ids["visibility_profile"],
                metric_name=name, value=float(value), unit=unit, numerator=numerator,
                denominator=float(denominator) if denominator is not None else None,
                estimator="frozen_truth_observer_profile_measure_v1", weighting="analytic",
                claim_eligible=True, scope={"observer_profile_id": profile_id},
            )
        )

    evidence_level = str(condition.factor_values["evidence_profile"])
    selected_types = EVIDENCE_TYPES_BY_LEVEL[evidence_level]
    receipt_rows = tuple(
        row
        for row in through_evidence.evidence_receipts.evidence_receipts
        if str(row["evidence_type"]) in selected_types
    )
    truth_by_id = {
        item.receipt_id: item
        for item in through_evidence.evidence_receipts.verification.truth
    }
    selected_truth = tuple(truth_by_id[str(row["receipt_id"])] for row in receipt_rows)
    metrics.append(
        _factor_metric(
            condition, result, axis_id="evidence_profile", level_id=condition.factor_level_ids["evidence_profile"],
            metric_name="selected_receipt_count", value=float(len(receipt_rows)), unit="receipts",
            numerator=float(len(receipt_rows)), denominator=None,
            estimator="selected_evidence_profile_census_v1", weighting="unweighted",
            claim_eligible=True, scope={"evidence_types": sorted(selected_types)},
        )
    )
    if selected_truth:
        valid = sum(item.expected_status == "valid" for item in selected_truth)
        timely = sum(item.timely for item in selected_truth)
        dependency_complete = sum(item.dependency_complete for item in selected_truth)
        for name, numerator in (
            ("receipt_validity_rate", valid),
            ("receipt_timeliness_rate", timely),
            ("receipt_dependency_completeness_rate", dependency_complete),
        ):
            metrics.append(
                _factor_metric(
                    condition, result, axis_id="evidence_profile", level_id=condition.factor_level_ids["evidence_profile"],
                    metric_name=name, value=numerator / len(selected_truth), unit="fraction",
                    numerator=float(numerator), denominator=float(len(selected_truth)),
                    estimator="independent_selected_receipt_verifier_census_v1", weighting="unweighted",
                    claim_eligible=True, scope={"evidence_types": sorted(selected_types)},
                )
            )

    sampling_level = str(condition.factor_values["sampling_profile"])
    if sampling_level == "naive_srs_truncation":
        for baseline in through_sampling.sampling.baselines:
            metrics.append(
                _factor_metric(
                    condition, result, axis_id="sampling_profile", level_id=condition.factor_level_ids["sampling_profile"],
                    metric_name=f"{baseline.baseline_id}.raw_relative_error",
                    value=float(baseline.raw_relative_error), unit="fraction", numerator=None, denominator=None,
                    estimator="none_ineligible_control", weighting="none", claim_eligible=False,
                    scope={"primary_unit_type": baseline.primary_unit_type, "exclusion_reason": baseline.exclusion_reason},
                )
            )
    else:
        selected_designs = {"cluster", "PPS"} if sampling_level == "cluster_pps" else {"stratified"}
        for diagnostic in through_sampling.sampling.diagnostics.values():
            if diagnostic.design_type not in selected_designs:
                continue
            for name, value, unit in (
                ("effective_sample_size", diagnostic.effective_sample_size, "units"),
                ("design_effect", diagnostic.design_effect, "ratio"),
                ("closure_expansion", diagnostic.closure_expansion_factor, "ratio"),
            ):
                metrics.append(
                    _factor_metric(
                        condition, result, axis_id="sampling_profile", level_id=condition.factor_level_ids["sampling_profile"],
                        metric_name=name, value=float(value), unit=unit, numerator=None, denominator=None,
                        estimator=diagnostic.estimator_family, weighting="design_weight",
                        claim_eligible=True,
                        scope={"design_type": diagnostic.design_type, "primary_unit_type": diagnostic.primary_unit_type},
                    )
                )
    return metrics


def _factor_metric(
    condition: StudyCondition,
    result: object,
    *,
    axis_id: str,
    level_id: str,
    metric_name: str,
    value: float,
    unit: str,
    numerator: float | None,
    denominator: float | None,
    estimator: str,
    weighting: str,
    claim_eligible: bool,
    scope: Mapping[str, object],
) -> Mapping[str, object]:
    metric_id = domain_sha256(
        "P8-factor-projection-metric-id",
        {
            "condition_id": condition.condition_id,
            "scenario_id": result.run_plan.scenario_id,
            "replicate_id": result.run_plan.replicate_id,
            "axis_id": axis_id,
            "level_id": level_id,
            "metric_name": metric_name,
            "scope": scope,
        },
    )[:32]
    return {
        "factor_metric_id": metric_id,
        "condition_id": condition.condition_id,
        "run_id": result.run_plan.run_id,
        "scenario_id": result.run_plan.scenario_id,
        "replicate_id": result.run_plan.replicate_id,
        "axis_id": axis_id,
        "level_id": level_id,
        "metric_name": metric_name,
        "value": value,
        "unit": unit,
        "numerator": numerator,
        "denominator": denominator,
        "estimator": estimator,
        "weighting": weighting,
        "claim_eligible": claim_eligible,
        "uncertainty_status": "requires_replicate_aggregate",
        "scope_json": canonical_json_text(scope),
        "represented_population_N": condition.represented_population_N,
        "materialized_row_target_n": condition.materialized_row_target_n,
        "executed_operation_target_q": condition.executed_operation_target_q,
    }


def _aggregate_factor_metrics(
    rows: Iterable[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    groups: dict[tuple[str, str, str, str, str, str, bool], list[Mapping[str, object]]] = {}
    for row in rows:
        key = (
            str(row["condition_id"]), str(row["axis_id"]), str(row["level_id"]),
            str(row["metric_name"]), str(row["unit"]), str(row["estimator"]), bool(row["claim_eligible"]),
        )
        groups.setdefault(key, []).append(row)
    output: list[Mapping[str, object]] = []
    z_score = NormalDist().inv_cdf(0.975)
    for key, members in sorted(groups.items()):
        condition_id, axis_id, level_id, metric_name, unit, estimator, eligible = key
        values = [float(item["value"]) for item in members]
        mean = fmean(values)
        if len(values) >= 2:
            standard_error = stdev(values) / len(values) ** 0.5
            lower = mean - z_score * standard_error
            upper = mean + z_score * standard_error
            uncertainty_status = "estimated_from_independent_replicates"
            uncertainty_reason = "normal_95_percent_interval_over_full_pipeline_replicates"
        else:
            standard_error = lower = upper = None
            uncertainty_status = "not_available"
            uncertainty_reason = "fewer_than_two_executed_replicates"
        first = members[0]
        output.append(
            {
                "condition_id": condition_id,
                "aggregate_kind": "factor_projection_metric",
                "represented_population_N": int(first["represented_population_N"]),
                "materialized_row_target_n": int(first["materialized_row_target_n"]),
                "executed_operation_target_q": first["executed_operation_target_q"],
                "aggregate_id": domain_sha256("P8-factor-metric-aggregate-id", {"key": key})[:32],
                "axis_id": axis_id,
                "level_id": level_id,
                "metric_name": metric_name,
                "metric_key": metric_name,
                "metric_domain": axis_id,
                "scope_id": level_id,
                "baseline_id": None,
                "unit": unit,
                "estimator": estimator,
                "weighting": str(first["weighting"]),
                "replicate_ids": sorted(int(item["replicate_id"]) for item in members),
                "replicate_count": len(values),
                "mean_value": mean,
                "empirical_standard_error": standard_error,
                "ci_lower": lower,
                "ci_upper": upper,
                "confidence_level": 0.95,
                "uncertainty_method": "normal_independent_replicate_interval_v1",
                "uncertainty_status": uncertainty_status,
                "uncertainty_reason": uncertainty_reason,
                "claim_eligible": eligible,
            }
        )
    return output


def _provisional_ledgers(
    condition: StudyCondition,
    group: PipelineMetricsRunGroupResult,
) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]]]:
    metrics: list[Mapping[str, object]] = []
    validations: list[Mapping[str, object]] = []
    for result in group.replicates:
        for row in result.artifacts.metrics.run_metrics:
            metrics.append(
                {
                    "condition_id": condition.condition_id,
                    "evidence_phase": "provisional_S14",
                    **dict(row),
                }
            )
        for row in result.artifacts.through_validation.validation.validation_issues:
            validations.append(
                {
                    "condition_id": condition.condition_id,
                    "scenario_id": result.run_plan.scenario_id,
                    "replicate_id": result.run_plan.replicate_id,
                    "evidence_phase": "provisional_S13",
                    **dict(row),
                }
            )
    return metrics, validations


def _final_release_ledgers(
    condition: StudyCondition,
    release_result: object,
) -> tuple[list[Mapping[str, object]], list[Mapping[str, object]]]:
    if not release_result.final_metrics_by_run or not release_result.final_validation_by_run:
        raise StudyExecutionError("S15 result omits keyed final metric or validation ledgers")
    metrics: list[Mapping[str, object]] = []
    validations: list[Mapping[str, object]] = []
    for (scenario_id, replicate_id), rows in sorted(
        release_result.final_metrics_by_run.items()
    ):
        for row in rows:
            if str(row["scenario_id"]) != scenario_id or int(row["replicate_id"]) != replicate_id:
                raise StudyExecutionError("S15 final metric key disagrees with metric row identity")
            metrics.append(
                {
                    "condition_id": condition.condition_id,
                    "evidence_phase": "final_S15",
                    **row,
                }
            )
    for (scenario_id, replicate_id), rows in sorted(
        release_result.final_validation_by_run.items()
    ):
        for row in rows:
            validations.append(
                {
                    "condition_id": condition.condition_id,
                    "scenario_id": scenario_id,
                    "replicate_id": replicate_id,
                    "evidence_phase": "final_S15",
                    **row,
                }
            )
    return metrics, validations


def planned_study_execution(
    base_config: ResolvedConfig,
    plan: FactorialStudyPlan,
) -> StudyExecutionBuild:
    """Create a truthful non-executed ledger for planning and budget review."""

    return execute_factorial_study(base_config, plan, condition_ids=())


def _complete_execution_ledger(
    base: ResolvedConfig,
    plan: FactorialStudyPlan,
    observed: Mapping[tuple[str, int], ReplicateStudyEvidence],
) -> tuple[ReplicateStudyEvidence, ...]:
    rows: list[ReplicateStudyEvidence] = []
    for condition in plan.conditions:
        for replicate_id in range(condition.repetitions):
            key = (condition.condition_id, replicate_id)
            if key in observed:
                rows.append(observed[key])
                continue
            blocked = condition.feasibility_status != "eligible"
            rows.append(
                ReplicateStudyEvidence(
                    condition_id=condition.condition_id,
                    run_id=f"{plan.study_id}-{condition.condition_id}",
                    scenario_id=base.run.scenario_id,
                    replicate_id=replicate_id,
                    execution_status="blocked_by_plan" if blocked else "not_executed",
                    represented_population_N=condition.represented_population_N,
                    materialized_row_target_n=condition.materialized_row_target_n,
                    materialized_governance_event_rows_n=None,
                    materialized_total_table_rows=None,
                    executed_operations_q=None,
                    seed_stream_digest=None,
                    canonical_table_digest=None,
                    retained_metric_count=0,
                    validation_status="not_executed",
                    known_total_status="not_executed",
                    maximum_absolute_relative_bias=None,
                    relative_rmse=None,
                    minimum_ci_coverage=None,
                    resource_status="not_measured",
                    generated_rows=None,
                    elapsed_seconds=None,
                    rows_per_second=None,
                    peak_resident_memory_bytes=None,
                    stored_bytes=None,
                    artifact_manifest_sha256=None,
                    clean_rerun_digest_match=None,
                    failure_code=("PLAN_BLOCKED" if blocked else None),
                    failure_message=(";".join(condition.feasibility_reasons) if blocked else None),
                )
            )
    return tuple(sorted(rows, key=lambda row: (row.condition_id, row.replicate_id)))


def _replicate_evidence_from_result(
    condition: StudyCondition,
    result: object,
    performance: object | None,
    *,
    release_manifest_sha256: str | None,
    release_finalized: bool,
    replay: DownstreamReplayEvidence | None,
) -> ReplicateStudyEvidence:
    artifacts = result.artifacts
    tables = artifacts.authoritative_table_records()
    sampling = artifacts.through_validation.through_sampling.sampling
    known = tuple(sampling.known_total_diagnostics)
    max_bias = max((abs(item.relative_bias) for item in known), default=None)
    max_rmse = max((item.relative_rmse for item in known), default=None)
    min_coverage = min((item.ci_coverage for item in known), default=None)
    known_status = "pass" if known and all(item.passed for item in known) else ("missing" if not known else "fail")
    metric_count = len(artifacts.metrics.run_metrics)
    table_digest = domain_sha256(
        "P8-replicate-authoritative-table-digests",
        dict(sorted(result.table_digests.items())),
    )
    if performance is None:
        resource_status = "not_measured"
        generated_rows = elapsed = throughput = memory = stored = None
    else:
        resource_status = "measured"
        generated_rows = int(performance.generated_row_count)
        elapsed = float(performance.elapsed_seconds)
        throughput = float(performance.rows_per_second)
        memory = int(performance.peak_memory_bytes)
        stored = int(performance.stored_bytes)
    actual_q = replay.executed_operation_count_q if replay is not None else None
    return ReplicateStudyEvidence(
        condition_id=condition.condition_id,
        run_id=result.run_plan.run_id,
        scenario_id=result.run_plan.scenario_id,
        replicate_id=result.run_plan.replicate_id,
        execution_status="executed",
        represented_population_N=condition.represented_population_N,
        materialized_row_target_n=condition.materialized_row_target_n,
        materialized_governance_event_rows_n=len(tables.get("governance_event", ())),
        materialized_total_table_rows=sum(len(rows) for rows in tables.values()),
        executed_operations_q=actual_q,
        seed_stream_digest=result.seed_stream_digest,
        canonical_table_digest=table_digest,
        retained_metric_count=metric_count,
        validation_status="release_pass" if release_finalized else "not_finalized",
        known_total_status=known_status,
        maximum_absolute_relative_bias=max_bias,
        relative_rmse=max_rmse,
        minimum_ci_coverage=min_coverage,
        resource_status=resource_status,
        generated_rows=generated_rows,
        elapsed_seconds=elapsed,
        rows_per_second=throughput,
        peak_resident_memory_bytes=memory,
        stored_bytes=stored,
        artifact_manifest_sha256=release_manifest_sha256,
        clean_rerun_digest_match=True if release_finalized else None,
        failure_code=None,
        failure_message=None,
    )


def _index_replay_evidence(
    evidence: Iterable[DownstreamReplayEvidence],
    conditions: Mapping[str, StudyCondition],
) -> Mapping[tuple[str, str, int], DownstreamReplayEvidence]:
    indexed: dict[tuple[str, str, int], DownstreamReplayEvidence] = {}
    for item in evidence:
        condition = conditions.get(item.condition_id)
        if condition is None:
            raise StudyExecutionError(
                f"downstream replay evidence names unknown condition {item.condition_id!r}"
            )
        if (
            condition.executed_operation_target_q is None
            or condition.executed_operation_target_q != item.executed_operation_count_q
        ):
            raise StudyExecutionError(
                "downstream replay evidence does not match any declared q target; "
                "targets are not execution evidence"
            )
        if item.replicate_id < 0 or item.replicate_id >= condition.repetitions:
            raise StudyExecutionError(
                f"downstream replay replicate_id={item.replicate_id} is outside condition repetitions={condition.repetitions}"
            )
        if not item.scenario_id.strip():
            raise StudyExecutionError("downstream replay evidence requires a scenario_id")
        if item.executed_operation_count_q < 0 or not all(
            value.strip()
            for value in (
                item.workload_digest,
                item.result_digest,
                item.implementation_id,
                item.hardware_profile_id,
            )
        ):
            raise StudyExecutionError("downstream replay evidence is incomplete")
        key = (item.condition_id, item.scenario_id, item.replicate_id)
        if key in indexed:
            raise StudyExecutionError(f"duplicate downstream replay evidence {key}")
        indexed[key] = item
    return dict(sorted(indexed.items()))


def _scale_claim(
    condition: StudyCondition,
    ledger: tuple[ReplicateStudyEvidence, ...],
    plan: FactorialStudyPlan,
) -> ScaleClaim:
    rows = tuple(row for row in ledger if row.condition_id == condition.condition_id)
    executed = tuple(row for row in rows if row.execution_status == "executed")
    materialized = tuple(
        row.materialized_governance_event_rows_n
        for row in executed
        if row.materialized_governance_event_rows_n is not None
    )
    q_values = tuple(
        row.executed_operations_q
        for row in executed
        if row.executed_operations_q is not None
    )
    validation_gate = (
        "pass" if len(executed) == condition.repetitions and all(row.validation_status == "release_pass" for row in executed)
        else "not_satisfied"
    )
    statistical_gate = (
        "pass"
        if condition.estimator_eligible
        and len(executed) == condition.repetitions
        and all(row.known_total_status == "pass" for row in executed)
        else ("estimator_ineligible" if not condition.estimator_eligible else "not_satisfied")
    )
    artifact_gate = (
        "pass" if len(executed) == condition.repetitions and all(row.artifact_manifest_sha256 for row in executed)
        else "not_satisfied"
    )
    reproducibility_gate = (
        "pass" if len(executed) == condition.repetitions and all(row.clean_rerun_digest_match is True for row in executed)
        else "not_satisfied"
    )
    repetition_gate = len(executed) >= plan.required_repetitions
    supported = (
        condition.feasibility_status == "eligible"
        and repetition_gate
        and validation_gate == statistical_gate == artifact_gate == reproducibility_gate == "pass"
        and all(row.resource_status == "measured" for row in executed)
    )
    if supported:
        status = "supported_represented_scale"
    elif condition.feasibility_status != "eligible":
        status = "blocked_by_declared_feasibility"
    elif not condition.estimator_eligible:
        status = "diagnostic_only_estimator_ineligible"
    else:
        status = "not_supported_missing_execution_evidence"
    q_statement = (
        f"Downstream replay evidence records q={sum(q_values)} operations across retained replicates."
        if len(q_values) == len(executed) and executed
        else "No downstream operation count q is evidenced by this generator study."
    )
    actual_range = (
        f"actual governance-event n ranged from {min(materialized)} to {max(materialized)}"
        if materialized
        else "actual materialized n is not available because execution evidence is incomplete"
    )
    statement = (
        f"This benchmark condition represents N={condition.represented_population_N}; "
        f"its configured materialization target is n={condition.materialized_row_target_n}, and {actual_range}. "
        f"{q_statement} Status={status}."
    )
    _validate_generated_claim_text(statement, condition)
    return ScaleClaim(
        claim_id=domain_sha256(
            "P8-scale-claim-id",
            {"plan": plan.plan_sha256, "condition": condition.condition_id},
        )[:32],
        condition_id=condition.condition_id,
        claim_class="represented_scale",
        represented_population_N=condition.represented_population_N,
        materialized_row_target_n=condition.materialized_row_target_n,
        materialized_rows_min_n=min(materialized) if materialized else None,
        materialized_rows_max_n=max(materialized) if materialized else None,
        executed_operations_sum_q=sum(q_values) if len(q_values) == len(executed) and executed else None,
        retained_repetitions=len(executed),
        required_repetitions=plan.required_repetitions,
        validation_gate=validation_gate,
        statistical_gate=statistical_gate,
        artifact_gate=artifact_gate,
        reproducibility_gate=reproducibility_gate,
        claim_status=status,
        claim_statement=statement,
        prohibited_interpretation=(
            "Represented N is not a materialized user count, executed workload, legal-compliance finding, "
            "physical-deletion proof, or deployment-capacity measurement."
        ),
    )


def _publication_blockers(
    plan: FactorialStudyPlan,
    rows: tuple[ReplicateStudyEvidence, ...],
    claims: tuple[ScaleClaim, ...],
) -> tuple[str, ...]:
    blockers: list[str] = []
    resource_blocked = tuple(
        condition.condition_id
        for condition in plan.conditions
        if condition.feasibility_status == "blocked"
        and any(reason != "materialized_target_n_exceeds_represented_population_N" for reason in condition.feasibility_reasons)
    )
    if resource_blocked:
        blockers.append(f"resource_or_capability_blocked_conditions={len(resource_blocked)}")
    eligible_ids = {
        condition.condition_id
        for condition in plan.conditions
        if condition.feasibility_status == "eligible"
    }
    incomplete = {
        row.condition_id
        for row in rows
        if row.condition_id in eligible_ids and row.execution_status != "executed"
    }
    if incomplete:
        blockers.append(f"eligible_conditions_not_fully_executed={len(incomplete)}")
    finalized = {
        row.condition_id
        for row in rows
        if row.condition_id in eligible_ids
        and (row.validation_status != "release_pass" or not row.artifact_manifest_sha256)
    }
    if finalized:
        blockers.append(f"conditions_without_final_S15_release={len(finalized)}")
    represented_450m = tuple(
        claim
        for claim in claims
        if claim.represented_population_N == 450_000_000
        and claim.claim_status == "supported_represented_scale"
    )
    if not represented_450m:
        blockers.append("no_supported_450m_represented_scale_condition")
    if plan.pairwise_covered_count != plan.pairwise_requirement_count:
        blockers.append("factor_pair_coverage_incomplete")
    return tuple(sorted(set(blockers)))


def _validate_generated_claim_text(text: str, condition: StudyCondition) -> None:
    lowered = text.lower()
    prohibited = (
        "users executed",
        "450m users",
        "physical deletion proved",
        "legally compliant",
        "operational capacity",
    )
    hits = tuple(token for token in prohibited if token in lowered)
    if hits:
        raise StudyExecutionError(f"generated claim contains prohibited interpretations {hits}")
    for required in ("N=", "n=", "q"):
        if required not in text:
            raise StudyExecutionError(
                f"scale claim for condition {condition.condition_id} omits {required} semantics"
            )
