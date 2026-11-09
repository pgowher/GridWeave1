"""S14 registry-bound per-replicate metric computation.

The engine emits only observations supported by executed evidence. Missing
calibration, source-comparison, manifest, clean-rerun, or process telemetry is
recorded as ``not_executed`` in the metric execution ledger and never replaced
with a zero, one, or other plausible-looking value.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime
import hashlib
import json
import math
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.config.resolver import (
    ALLOWED_SOURCE_LABELS,
    CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES,
)
from htgl_dataset_generator.evidence.sufficiency import evaluate_evidence_sufficiency
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import content_id

from .models import (
    MetricExecutionRecord,
    MetricObservationProvenance,
    MetricRegistry,
    MetricsBuild,
    MetricsInput,
    PhysicalCalibrationReference,
    PrivacySourceReference,
)
from .registry import load_metric_registry
from .statistics import (
    MetricStatisticsError,
    autocorrelation,
    f1_from_labels,
    weighted_ks_2sample,
    weighted_wasserstein_1d,
)


FULL_OBSERVER_PROFILE_ID = "OBS-FULL-EVALUATOR"
COMPUTED = "computed"
NOT_EXECUTED = "not_executed"
NOT_APPLICABLE = "not_applicable"
FAILED = "failed"


class MetricsEngineError(ValueError):
    """Raised when a metric cannot be computed without weakening its contract."""


class _MetricEmitter:
    def __init__(
        self,
        data: MetricsInput,
        registry: MetricRegistry,
        contract: ContractSpec,
    ) -> None:
        self.data = data
        self.registry = registry
        self.contract = contract
        self.rows: list[dict[str, Any]] = []
        self.provenance: list[MetricObservationProvenance] = []
        self.statuses: dict[str, tuple[str, str]] = {}
        self.metric_ids_by_key: dict[str, list[str]] = defaultdict(list)

    def emit(
        self,
        metric_key: str,
        value: float,
        *,
        scope: Mapping[str, Any],
        numerator: float | None,
        denominator: float | None,
        denominator_unit: str,
        standard_error: float | None = None,
        ci_lower: float | None = None,
        ci_upper: float | None = None,
        baseline_id: str | None = None,
        reference_id: str | None = None,
        uncertainty_status: str | None = None,
        uncertainty_reason: str | None = None,
        execution_evidence: Any = None,
        publication_eligible: bool = True,
    ) -> None:
        definition = self.registry.definition(metric_key)
        numeric = [value]
        numeric.extend(
            item
            for item in (standard_error, ci_lower, ci_upper, numerator, denominator)
            if item is not None
        )
        if any(not math.isfinite(float(item)) for item in numeric):
            raise MetricsEngineError(f"{metric_key}: metric values must be finite")
        if denominator is not None and denominator <= 0:
            raise MetricsEngineError(f"{metric_key}: denominator must be positive when present")
        if (ci_lower is None) != (ci_upper is None):
            raise MetricsEngineError(f"{metric_key}: confidence interval bounds must be both set or both null")
        if ci_lower is not None and not ci_lower <= value <= ci_upper:
            raise MetricsEngineError(f"{metric_key}: value lies outside its confidence interval")
        scope_json = _canonical_json(scope)
        scope_id = content_id("metric_scope", {"metric_key": metric_key, "scope": scope})
        metric_id = content_id(
            "run_metric",
            {
                "baseline_id": baseline_id,
                "metric_key": metric_key,
                "replicate_id": self.data.run_plan.replicate_id,
                "run_id": self.data.run_plan.run_id,
                "scenario_id": self.data.run_plan.scenario_id,
                "scope_id": scope_id,
            },
        )
        if metric_id in {str(row["metric_id"]) for row in self.rows}:
            raise MetricsEngineError(f"duplicate metric observation for {metric_key} scope={scope_json}")
        if uncertainty_status is None or uncertainty_reason is None:
            uncertainty_status, uncertainty_reason = _per_replicate_uncertainty(
                definition.uncertainty_policy,
                self.data.resolved.run.replicate_count,
                standard_error,
            )
        row = {
            "metric_id": metric_id,
            "run_id": self.data.run_plan.run_id,
            "scenario_id": self.data.run_plan.scenario_id,
            "replicate_id": self.data.run_plan.replicate_id,
            "metric_domain": definition.domain,
            "metric_name": metric_key,
            "value": float(value),
            "unit": definition.unit,
            "standard_error": None if standard_error is None else float(standard_error),
            "ci_lower": None if ci_lower is None else float(ci_lower),
            "ci_upper": None if ci_upper is None else float(ci_upper),
            "estimator": definition.estimator,
            "weighting": definition.weighting,
            "baseline_id": baseline_id,
        }
        validate_record(self.contract, "run_metric", row)
        evidence_digest = _digest_payload(
            execution_evidence
            if execution_evidence is not None
            else {"numerator": numerator, "denominator": denominator, "scope": scope}
        )
        self.rows.append(row)
        self.provenance.append(
            MetricObservationProvenance(
                metric_id=metric_id,
                metric_key=metric_key,
                definition_id=f"{self.registry.registry_id}:{metric_key}",
                registry_id=self.registry.registry_id,
                registry_version=self.registry.version,
                registry_sha256=self.registry.sha256,
                run_id=self.data.run_plan.run_id,
                scenario_id=self.data.run_plan.scenario_id,
                replicate_id=self.data.run_plan.replicate_id,
                scope_id=scope_id,
                scope_json=scope_json,
                numerator=None if numerator is None else float(numerator),
                denominator=None if denominator is None else float(denominator),
                denominator_unit=denominator_unit,
                estimator=definition.estimator,
                weighting=definition.weighting,
                baseline_id=baseline_id,
                replicate_set=(self.data.run_plan.replicate_id,),
                uncertainty_status=uncertainty_status,
                uncertainty_reason=uncertainty_reason,
                reference_id=reference_id,
                publication_eligible=publication_eligible,
                execution_evidence_digest=evidence_digest,
            )
        )
        self.metric_ids_by_key[metric_key].append(metric_id)
        self.statuses[metric_key] = (COMPUTED, "metric computed from the declared executed evidence")

    def unavailable(self, metric_key: str, status: str, reason: str) -> None:
        if status not in {NOT_EXECUTED, NOT_APPLICABLE, FAILED}:
            raise MetricsEngineError(f"{metric_key}: invalid unavailable status {status!r}")
        if not reason.strip():
            raise MetricsEngineError(f"{metric_key}: unavailable reason must be non-empty")
        if metric_key in self.metric_ids_by_key:
            return
        existing = self.statuses.get(metric_key)
        if existing is not None and existing != (status, reason):
            raise MetricsEngineError(f"{metric_key}: conflicting execution statuses")
        self.statuses[metric_key] = (status, reason)

    def finalize(self) -> MetricsBuild:
        missing = sorted(set(self.registry.definitions) - set(self.statuses))
        if missing:
            raise MetricsEngineError(f"metric execution ledger omitted registered metrics {missing}")
        records = tuple(
            MetricExecutionRecord(
                run_id=self.data.run_plan.run_id,
                scenario_id=self.data.run_plan.scenario_id,
                replicate_id=self.data.run_plan.replicate_id,
                metric_key=key,
                status=self.statuses[key][0],
                reason=self.statuses[key][1],
                output_metric_ids=tuple(sorted(self.metric_ids_by_key.get(key, ()))),
            )
            for key in sorted(self.registry.definitions)
        )
        build = MetricsBuild(
            run_metrics=tuple(sorted(self.rows, key=lambda row: str(row["metric_id"]))),
            provenance=tuple(sorted(self.provenance, key=lambda item: item.metric_id)),
            execution_records=records,
            registry=self.registry,
        )
        validate_metrics_build(build, contract=self.contract)
        return build


def build_run_metrics(
    data: MetricsInput,
    *,
    registry: MetricRegistry | None = None,
    contract: ContractSpec | None = None,
) -> MetricsBuild:
    """Compute one complete, registry-bound per-replicate S14 metric ledger."""

    schema_contract = contract if contract is not None else load_contract()
    metric_registry = registry if registry is not None else load_metric_registry(contract=schema_contract)
    emitter = _MetricEmitter(data, metric_registry, schema_contract)
    _physical_metrics(emitter)
    _temporal_metrics(emitter)
    _topology_metrics(emitter)
    _workflow_metrics(emitter)
    _policy_metrics(emitter)
    _anomaly_metrics(emitter)
    _evidence_metrics(emitter)
    _observer_metrics(emitter)
    _sampling_metrics(emitter)
    _privacy_metrics(emitter)
    _artifact_metrics(emitter)
    _performance_metrics(emitter)
    return emitter.finalize()


def validate_metrics_build(
    build: MetricsBuild,
    *,
    contract: ContractSpec | None = None,
) -> None:
    schema_contract = contract if contract is not None else load_contract()
    metric_ids: set[str] = set()
    for index, row in enumerate(build.run_metrics):
        validate_record(schema_contract, "run_metric", row)
        metric_id = str(row["metric_id"])
        if metric_id in metric_ids:
            raise MetricsEngineError(f"run_metric[{index}] duplicates metric_id={metric_id}")
        metric_ids.add(metric_id)
        definition = build.registry.definition(str(row["metric_name"]))
        for field, expected in (
            ("metric_domain", definition.domain),
            ("unit", definition.unit),
            ("estimator", definition.estimator),
            ("weighting", definition.weighting),
        ):
            if row[field] != expected:
                raise MetricsEngineError(
                    f"metric_id={metric_id}: {field}={row[field]!r} disagrees with registry {expected!r}"
                )
    provenance_by_id = {item.metric_id: item for item in build.provenance}
    if set(provenance_by_id) != metric_ids or len(provenance_by_id) != len(build.provenance):
        raise MetricsEngineError("every run_metric row must have exactly one observation provenance row")
    for row in build.run_metrics:
        item = provenance_by_id[str(row["metric_id"])]
        if item.metric_key != row["metric_name"]:
            raise MetricsEngineError(f"metric_id={item.metric_id}: provenance metric key mismatch")
        if item.estimator != row["estimator"] or item.weighting != row["weighting"]:
            raise MetricsEngineError(f"metric_id={item.metric_id}: provenance estimator/weighting mismatch")
        if item.replicate_set != (int(row["replicate_id"]),):
            raise MetricsEngineError(f"metric_id={item.metric_id}: invalid per-replicate scope")
        if not item.uncertainty_reason.strip():
            raise MetricsEngineError(f"metric_id={item.metric_id}: uncertainty reason is missing")
    execution_by_key = {item.metric_key: item for item in build.execution_records}
    if len(execution_by_key) != len(build.execution_records):
        raise MetricsEngineError("metric execution ledger contains duplicate keys")
    if set(execution_by_key) != set(build.registry.definitions):
        raise MetricsEngineError("metric execution ledger does not cover the complete registry")
    for key, execution in execution_by_key.items():
        expected_ids = tuple(sorted(item.metric_id for item in build.provenance if item.metric_key == key))
        if execution.output_metric_ids != expected_ids:
            raise MetricsEngineError(f"{key}: execution output IDs disagree with provenance")
        if execution.status == COMPUTED and not expected_ids:
            raise MetricsEngineError(f"{key}: computed status has no metric observation")
        if execution.status != COMPUTED and expected_ids:
            raise MetricsEngineError(f"{key}: unavailable status has metric observations")


def validate_metric_execution_for_publication(build: MetricsBuild) -> None:
    """Block publication on failed, unexecuted, or unjustified metric states."""

    for execution in build.execution_records:
        definition = build.registry.definition(execution.metric_key)
        if execution.status == COMPUTED:
            continue
        if execution.status == NOT_APPLICABLE:
            if definition.applicability == "always":
                raise MetricsEngineError(
                    f"{execution.metric_key}: always-applicable metric was marked "
                    f"not_applicable: {execution.reason}"
                )
            if not execution.reason.strip():
                raise MetricsEngineError(
                    f"{execution.metric_key}: not_applicable lacks a justification"
                )
            continue
        raise MetricsEngineError(
            f"{execution.metric_key}: publication-blocking metric status "
            f"{execution.status!r}: {execution.reason}"
        )


def _physical_metrics(emitter: _MetricEmitter) -> None:
    reference = emitter.data.physical_reference
    backend = emitter.data.resolved.physical.backend
    if backend not in CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES:
        raise MetricsEngineError(
            f"unsupported physical metric profile for backend {backend!r}"
        )
    if reference is not None:
        raise MetricsEngineError(
            "physical calibration reference is forbidden for the current controlled "
            "procedural synthetic profile; external calibration transformations, source "
            "licenses, and adapters are not implemented"
        )
    if reference is None:
        for key in (
            "meter_energy_wasserstein",
            "meter_energy_ks",
            "acf_error_l1",
            "peak_timing_distance",
            "load_factor_error",
        ):
            emitter.unavailable(
                key,
                NOT_APPLICABLE,
                "the procedural-controlled-synthetic-v1 release profile has no external "
                "physical reference and forbids calibrated-fidelity claims",
            )
    emitter.unavailable(
        "network_solver_convergence_rate",
        NOT_APPLICABLE,
        "external power-flow solver execution is deferred; controlled analytic network "
        "state generation does not support a solver-convergence claim",
    )
    diagnostic = _scenario_diagnostic(
        emitter.data.physical.diagnostics,
        emitter.data.run_plan.scenario_id,
    )
    emitter.emit(
        "der_energy_balance_error",
        diagnostic.max_export_balance_error,
        scope={
            "physical_profile": emitter.data.resolved.output.release_profile_id,
            "balance_convention": "aggregate_meter_export_not_above_generated_DER_energy",
        },
        numerator=diagnostic.max_export_balance_error,
        denominator=None,
        denominator_unit="not_applicable_maximum_residual",
        execution_evidence=asdict(diagnostic),
    )
    rows = tuple(emitter.data.physical.raw_network_states)
    if not rows:
        for key in ("voltage_violation_rate", "loading_violation_rate"):
            emitter.unavailable(key, NOT_APPLICABLE, "no network-state rows exist in this scenario")
        return
    voltage_rows = tuple(row for row in rows if row["voltage_pu"] is not None)
    if voltage_rows:
        violations = sum(
            bool({"voltage_high", "voltage_low"} & set(str(value) for value in row["violation_flags"]))
            for row in voltage_rows
        )
        emitter.emit(
            "voltage_violation_rate",
            violations / len(voltage_rows),
            scope={"network_state_scope": "modeled_voltage"},
            numerator=violations,
            denominator=len(voltage_rows),
            denominator_unit="network_state_rows",
            execution_evidence=voltage_rows,
        )
    else:
        emitter.unavailable("voltage_violation_rate", NOT_APPLICABLE, "voltage is not modeled")
    loading_rows = tuple(row for row in rows if row["loading_percent"] is not None)
    if loading_rows:
        violations = sum(
            bool({"loading_high", "thermal_limit"} & set(str(value) for value in row["violation_flags"]))
            for row in loading_rows
        )
        emitter.emit(
            "loading_violation_rate",
            violations / len(loading_rows),
            scope={"network_state_scope": "modeled_loading"},
            numerator=violations,
            denominator=len(loading_rows),
            denominator_unit="network_state_rows",
            execution_evidence=loading_rows,
        )
    else:
        emitter.unavailable("loading_violation_rate", NOT_APPLICABLE, "loading is not modeled")


def _physical_reference_metrics(
    emitter: _MetricEmitter, reference: PhysicalCalibrationReference
) -> None:
    _validate_reference_identity(reference.reference_id, reference.source_label)
    if not reference.observations:
        raise MetricsEngineError("physical calibration reference observations must not be empty")
    if not reference.acf_lags or any(lag <= 0 for lag in reference.acf_lags):
        raise MetricsEngineError("physical calibration reference requires positive ACF lags")
    generated = tuple(emitter.data.physical.raw_meter_readings)
    generated_groups = _meter_distribution_groups(generated)
    reference_groups = _reference_distribution_groups(reference)
    if set(generated_groups) != set(reference_groups):
        raise MetricsEngineError(
            "physical reference strata do not match generated cohort/hour strata: "
            f"missing={sorted(set(generated_groups)-set(reference_groups))[:8]} "
            f"extra={sorted(set(reference_groups)-set(generated_groups))[:8]}"
        )
    exposure_total = 0.0
    wasserstein_sum = 0.0
    ks_sum = 0.0
    for key in sorted(generated_groups):
        left_values, left_weights = reference_groups[key]
        right_values, right_weights = generated_groups[key]
        exposure = math.fsum(left_weights)
        exposure_total += exposure
        wasserstein_sum += exposure * weighted_wasserstein_1d(
            left_values, left_weights, right_values, right_weights
        )
        ks_sum += exposure * weighted_ks_2sample(
            left_values, left_weights, right_values, right_weights
        )
    scope = {
        "reference_id": reference.reference_id,
        "strata": "cohort_id_x_utc_hour",
        "stratum_count": len(generated_groups),
    }
    emitter.emit(
        "meter_energy_wasserstein",
        wasserstein_sum / exposure_total,
        scope=scope,
        numerator=wasserstein_sum,
        denominator=exposure_total,
        denominator_unit="reference_represented_meter_interval_exposure",
        reference_id=reference.reference_id,
        execution_evidence={"generated": generated, "reference": [asdict(item) for item in reference.observations]},
    )
    emitter.emit(
        "meter_energy_ks",
        ks_sum / exposure_total,
        scope=scope,
        numerator=ks_sum,
        denominator=exposure_total,
        denominator_unit="reference_represented_meter_interval_exposure",
        reference_id=reference.reference_id,
        execution_evidence={"generated": generated, "reference": [asdict(item) for item in reference.observations]},
    )
    generated_series = _meter_series(generated)
    reference_series = _reference_series(reference)
    if set(generated_series) != set(reference_series):
        raise MetricsEngineError("physical reference cohort series do not match generated cohort series")
    errors: list[float] = []
    for cohort_id in sorted(generated_series):
        generated_values = generated_series[cohort_id]
        reference_values = reference_series[cohort_id]
        for lag in reference.acf_lags:
            try:
                errors.append(
                    abs(autocorrelation(reference_values, lag) - autocorrelation(generated_values, lag))
                )
            except MetricStatisticsError as exc:
                raise MetricsEngineError(f"ACF comparison cohort={cohort_id} lag={lag}: {exc}") from exc
    emitter.emit(
        "acf_error_l1",
        math.fsum(errors) / len(errors),
        scope={**scope, "acf_lags": list(reference.acf_lags)},
        numerator=math.fsum(errors),
        denominator=len(errors),
        denominator_unit="cohort_lag_comparisons",
        reference_id=reference.reference_id,
        execution_evidence={"errors": errors, "reference_id": reference.reference_id},
    )


def _temporal_metrics(emitter: _MetricEmitter) -> None:
    diagnostic = _scenario_diagnostic(emitter.data.arrivals.diagnostics, emitter.data.run_plan.scenario_id)
    scope = {"arrival_model": diagnostic.model_class}
    denominator = max(float(diagnostic.expected_count), 1e-15)
    emitter.emit("count_mean_ratio", diagnostic.count_mean_ratio, scope=scope, numerator=diagnostic.observed_count, denominator=denominator, denominator_unit="integrated_expected_arrivals", execution_evidence=asdict(diagnostic))
    positive_bin_count = sum(item.integrated_intensity > 0 for item in emitter.data.arrivals.intensity_bins)
    dispersion_degrees = max(positive_bin_count - 1, 1)
    emitter.emit("dispersion_index", diagnostic.dispersion_index, scope=scope, numerator=diagnostic.dispersion_index * dispersion_degrees, denominator=dispersion_degrees, denominator_unit="positive_intensity_bin_degrees_of_freedom", execution_evidence=asdict(diagnostic))
    emitter.emit("time_rescaling_ks", diagnostic.time_rescaling_ks, scope=scope, numerator=None, denominator=max(len(emitter.data.arrivals.arrivals) - 1, 1), denominator_unit="rescaled_interarrival_residuals", execution_evidence=asdict(diagnostic))
    emitter.emit("bin_deviance", diagnostic.bin_deviance, scope=scope, numerator=diagnostic.bin_deviance, denominator=max(len(emitter.data.arrivals.intensity_bins), 1), denominator_unit="integrated_intensity_bins", execution_evidence=asdict(diagnostic))
    emitter.emit(
        "interarrival_distance",
        diagnostic.interarrival_distance,
        scope=scope,
        numerator=diagnostic.interarrival_distance,
        denominator=max(len(emitter.data.arrivals.arrivals) - 1, 1),
        denominator_unit="transformed_interarrival_spacings",
        execution_evidence=asdict(diagnostic),
    )
    model = str(diagnostic.model_class).lower()
    if model == "hawkes":
        emitter.emit(
            "cross_excitation_error",
            diagnostic.cross_excitation_error,
            scope=scope,
            numerator=diagnostic.cross_excitation_error,
            denominator=max(len(emitter.data.arrivals.arrivals), 1),
            denominator_unit="hawkes_arrivals",
            execution_evidence=asdict(diagnostic),
        )
    else:
        emitter.unavailable(
            "cross_excitation_error",
            NOT_APPLICABLE,
            f"arrival model {diagnostic.model_class!r} is not Hawkes",
        )
    if model == "mmpp":
        emitter.emit(
            "mmpp_regime_occupancy_error",
            diagnostic.regime_occupancy_error,
            scope=scope,
            numerator=diagnostic.regime_occupancy_error,
            denominator=max(len(emitter.data.arrivals.intensity_bins), 1),
            denominator_unit="mmpp_regime_intervals",
            execution_evidence=asdict(diagnostic),
        )
    else:
        emitter.unavailable(
            "mmpp_regime_occupancy_error",
            NOT_APPLICABLE,
            f"arrival model {diagnostic.model_class!r} is not MMPP",
        )


def _topology_metrics(emitter: _MetricEmitter) -> None:
    fk = _validation_row(emitter.data.validation.validation_issues, "FK-001")
    affected = tuple(str(value) for value in fk["affected_record_ids"])
    value = 0.0 if fk["status"] == "pass" else float(len(affected))
    emitter.emit(
        "fk_violation_count", value,
        scope={"tables": "all_authoritative_S00_S12"}, numerator=value, denominator=None,
        denominator_unit="not_applicable_count", uncertainty_status="not_applicable",
        uncertainty_reason="foreign-key violations are a complete finite validation census",
        execution_evidence=fk,
        publication_eligible=fk["status"] == "pass",
    )
    events = {str(row["event_id"]): row for row in emitter.data.causal_dag.governance_events}
    decisions = tuple(emitter.data.policy.policy_decisions)
    weights = [float(events[str(row["event_id"])]["represented_event_count"]) for row in decisions]
    denominator = math.fsum(weights)
    numerator = math.fsum(weight for row, weight in zip(decisions, weights) if bool(row["is_cross_region"]))
    emitter.emit(
        "cross_region_transfer_rate", numerator / denominator,
        scope={"truth_source": "policy_oracle_actual_region_and_jurisdiction_facts"},
        numerator=numerator, denominator=denominator, denominator_unit="represented_event_exposure",
        execution_evidence=decisions,
    )
    for key in (
        "actor_degree_distance",
        "custody_component_distribution",
        "replica_count_distance",
    ):
        emitter.unavailable(
            key,
            NOT_APPLICABLE,
            "the supported controlled-synthetic release profile has no registered "
            "external topology distribution reference",
        )


def _workflow_metrics(emitter: _MetricEmitter) -> None:
    workflow = _scenario_diagnostic(emitter.data.workflows.diagnostics, emitter.data.run_plan.scenario_id)
    dag = _scenario_diagnostic(emitter.data.causal_dag.diagnostics, emitter.data.run_plan.scenario_id)
    emitter.emit(
        "transition_conformance_rate", workflow.transition_conformance_rate,
        scope={"workflow_definition_versions": "resolved_config"},
        numerator=workflow.transition_conformance_rate * workflow.governance_event_count,
        denominator=max(workflow.governance_event_count, 1), denominator_unit="workflow_transitions",
        execution_evidence=asdict(workflow),
    )
    roots = {str(row["root_event_id"]) for row in emitter.data.causal_dag.governance_events}
    non_root_count = max(dag.event_count - len(roots), 0)
    orphan_rate = dag.orphan_non_root_count / non_root_count if non_root_count else 0.0
    emitter.emit(
        "causal_orphan_rate", orphan_rate, scope={"edge_authority": "event_edge.parquet"},
        numerator=dag.orphan_non_root_count, denominator=max(non_root_count, 1),
        denominator_unit="non_root_events",
        uncertainty_status="not_applicable" if non_root_count == 0 else None,
        uncertainty_reason="no non-root events exist" if non_root_count == 0 else None,
        execution_evidence=asdict(dag),
    )
    emitter.emit("causal_cycle_count", dag.disallowed_cycle_count, scope={"edge_authority": "event_edge.parquet"}, numerator=dag.disallowed_cycle_count, denominator=None, denominator_unit="not_applicable_count", uncertainty_status="not_applicable", uncertainty_reason="cycle count is a complete finite graph census", execution_evidence=asdict(dag))
    emitter.emit("depth_reconciliation_error", dag.depth_reconciliation_error_count, scope={"edge_authority": "event_edge.parquet"}, numerator=dag.depth_reconciliation_error_count, denominator=None, denominator_unit="not_applicable_count", uncertainty_status="not_applicable", uncertainty_reason="depth mismatch count is a complete finite graph census", execution_evidence=asdict(dag))
    event_by_id = {
        str(row["event_id"]): row
        for row in emitter.data.causal_dag.governance_events
    }
    instances = tuple(emitter.data.causal_dag.workflow_instances)
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    grouped["all"].extend(instances)
    for row in instances:
        grouped[str(row["workflow_type"])].append(row)
    for family, rows in sorted(grouped.items()):
        weights = [
            float(event_by_id[str(row["root_event_id"])]["represented_event_count"])
            for row in rows
        ]
        denominator = math.fsum(weights)
        completed = math.fsum(
            weight
            for row, weight in zip(rows, weights)
            if row["terminal_event_id"] is not None and row["ended_at"] is not None
        )
        emitter.emit(
            "workflow_completion_rate",
            completed / denominator,
            scope={"workflow_family": family},
            numerator=completed,
            denominator=denominator,
            denominator_unit="represented_root_event_exposure",
            execution_evidence=rows,
        )
    emitter.unavailable(
        "workflow_duration_distance",
        NOT_APPLICABLE,
        "the supported release profile has no registered external workflow-duration reference",
    )


def _policy_metrics(emitter: _MetricEmitter) -> None:
    diagnostic = _scenario_diagnostic(emitter.data.policy.diagnostics, emitter.data.run_plan.scenario_id)
    emitter.emit(
        "golden_decision_accuracy", diagnostic.golden_decision_accuracy,
        scope={"golden_suite_id": emitter.data.policy.golden_result.golden_suite_id},
        numerator=emitter.data.policy.golden_result.exact_match_count,
        denominator=emitter.data.policy.golden_result.case_count,
        denominator_unit="golden_cases", uncertainty_status="not_applicable",
        uncertainty_reason="the pinned independently authored golden suite is evaluated as a finite census",
        execution_evidence=asdict(emitter.data.policy.golden_result),
    )
    emitter.emit(
        "rule_trace_coverage", diagnostic.rule_trace_coverage,
        scope={"policy_profile_id": diagnostic.policy_profile_id},
        numerator=diagnostic.rule_trace_coverage * diagnostic.decision_count,
        denominator=max(diagnostic.decision_count, 1), denominator_unit="policy_decisions",
        execution_evidence=asdict(diagnostic),
    )
    conflict_cases = emitter.data.policy.golden_result.conflict_case_count
    emitter.emit(
        "conflict_resolution_agreement",
        emitter.data.policy.golden_result.conflict_resolution_agreement,
        scope={"golden_suite_id": emitter.data.policy.golden_result.golden_suite_id},
        numerator=(
            emitter.data.policy.golden_result.conflict_resolution_agreement
            * conflict_cases
        ),
        denominator=conflict_cases,
        denominator_unit="golden_conflict_cases",
        uncertainty_status="not_applicable",
        uncertainty_reason=(
            "the independently authored golden conflict cases are evaluated as a finite census"
        ),
        execution_evidence=asdict(emitter.data.policy.golden_result),
    )


def _anomaly_metrics(emitter: _MetricEmitter) -> None:
    diagnostic = _scenario_diagnostic(emitter.data.anomalies.diagnostics, emitter.data.run_plan.scenario_id)
    if diagnostic.anomaly_count <= 0:
        for key in (
            "target_violation_success",
            "collateral_violation_rate",
            "counterfactual_edit_cost",
            "pair_non_target_predictability",
        ):
            emitter.unavailable(key, NOT_APPLICABLE, "the resolved scenario generated no anomaly instances")
        return
    scope = {
        "invariant_registry_sha256": emitter.data.anomalies.invariant_registry_sha256,
        "edit_grammar_sha256": emitter.data.anomalies.edit_grammar_sha256,
    }
    emitter.emit("target_violation_success", diagnostic.target_violation_success_rate, scope=scope, numerator=diagnostic.target_violation_success_rate * diagnostic.anomaly_count, denominator=diagnostic.anomaly_count, denominator_unit="accepted_anomalies", execution_evidence=asdict(diagnostic))
    emitter.emit("collateral_violation_rate", diagnostic.protected_collateral_violation_rate, scope=scope, numerator=diagnostic.protected_collateral_violation_rate * diagnostic.anomaly_count, denominator=diagnostic.anomaly_count, denominator_unit="accepted_anomalies", execution_evidence=asdict(diagnostic))
    emitter.emit("counterfactual_edit_cost", diagnostic.mean_edit_cost, scope=scope, numerator=diagnostic.mean_edit_cost * diagnostic.anomaly_count, denominator=diagnostic.anomaly_count, denominator_unit="accepted_anomalies", execution_evidence=[asdict(item.search_diagnostics) for item in emitter.data.anomalies.counterfactual_pairs])
    signature_weights: dict[tuple[tuple[str, str], ...], list[float]] = defaultdict(
        lambda: [0.0, 0.0]
    )
    for pair in emitter.data.anomalies.counterfactual_pairs:
        valid = {item.invariant_id: item for item in pair.valid_invariant_outcomes}
        invalid = {item.invariant_id: item for item in pair.invalid_invariant_outcomes}
        valid_signature = tuple(
            (invariant_id, valid[invariant_id].status)
            for invariant_id in sorted(pair.preserved_invariant_ids)
        )
        invalid_signature = tuple(
            (invariant_id, invalid[invariant_id].status)
            for invariant_id in sorted(pair.preserved_invariant_ids)
        )
        signature_weights[valid_signature][0] += pair.analysis_weight
        signature_weights[invalid_signature][1] += pair.analysis_weight
    correct_weight = math.fsum(max(weights) for weights in signature_weights.values())
    total_weight = math.fsum(math.fsum(weights) for weights in signature_weights.values())
    emitter.emit(
        "pair_non_target_predictability",
        correct_weight / total_weight,
        scope={
            **scope,
            "feature_contract": "protected_non_target_invariant_status_signatures",
            "balanced_pair_members": True,
        },
        numerator=correct_weight,
        denominator=total_weight,
        denominator_unit="weighted_pair_members",
        execution_evidence={
            str(index): {"valid_weight": value[0], "invalid_weight": value[1]}
            for index, value in enumerate(
                signature_weights[key] for key in sorted(signature_weights)
            )
        },
    )


def _evidence_metrics(emitter: _MetricEmitter) -> None:
    independent = emitter.data.receipts.verification.sufficiency
    provenance_by_id = {item.obligation_id: item for item in emitter.data.obligations.provenance}
    required_count = sum(len(item.coverage_member_ids) for item in provenance_by_id.values())
    missing_count = sum(len(item.missing_coverage_ids) for item in independent.truth)
    if required_count <= 0:
        emitter.unavailable("obligation_coverage", NOT_APPLICABLE, "no evidence coverage members are required")
    else:
        covered = required_count - missing_count
        emitter.emit("obligation_coverage", covered / required_count, scope={"coverage_truth": "independent_valid_timely_receipts"}, numerator=covered, denominator=required_count, denominator_unit="required_coverage_members", execution_evidence=[asdict(item) for item in independent.truth])
    declared = evaluate_evidence_sufficiency(
        emitter.data.obligations,
        emitter.data.receipts.evidence_receipts,
        world=emitter.data.world,
        catalog=emitter.data.catalog,
        causal_dag=emitter.data.causal_dag,
        contract=emitter.contract,
    )
    independent_by_id = {item.obligation_id: item.sufficient for item in independent.truth}
    declared_by_id = {item.obligation_id: item.sufficient for item in declared.truth}
    if not independent_by_id:
        emitter.unavailable("sufficiency_precision_recall", NOT_APPLICABLE, "no evidence obligations exist")
    else:
        ids = sorted(independent_by_id)
        f1, precision, recall, tp, fp, fn = f1_from_labels(
            (independent_by_id[key] for key in ids),
            (declared_by_id[key] for key in ids),
        )
        emitter.emit("sufficiency_precision_recall", f1, scope={"precision": precision, "recall": recall, "true_positive": tp, "false_positive": fp, "false_negative": fn, "label_unit": "obligation"}, numerator=f1 * len(ids), denominator=len(ids), denominator_unit="evidence_obligations", execution_evidence={"independent": independent_by_id, "declared": declared_by_id})
    verification = emitter.data.receipts.verification.diagnostics
    if verification.receipt_count:
        emitter.emit("receipt_validity_rate", verification.valid_count / verification.receipt_count, scope={"evidence_profile": emitter.data.receipts.receipt_profile_bundle_sha256}, numerator=verification.valid_count, denominator=verification.receipt_count, denominator_unit="evidence_receipts", execution_evidence=asdict(verification))
    else:
        emitter.unavailable("receipt_validity_rate", NOT_APPLICABLE, "no evidence receipts were emitted")
    truth = tuple(emitter.data.receipts.verification.truth)
    if truth:
        timely_count = sum(item.timely for item in truth)
        emitter.emit(
            "receipt_timeliness_rate",
            timely_count / len(truth),
            scope={"deadline_truth": "independent_obligation_due_at_comparison"},
            numerator=timely_count,
            denominator=len(truth),
            denominator_unit="evidence_receipts",
            execution_evidence=[asdict(item) for item in truth],
        )
    else:
        emitter.unavailable(
            "receipt_timeliness_rate",
            NOT_APPLICABLE,
            "no evidence receipts were emitted",
        )
    contradiction_cases = tuple(
        item
        for item in emitter.data.receipts.adversarial_cases
        if item.case_type == "contradictory"
    )
    if contradiction_cases:
        truth_by_id = {item.receipt_id: item for item in truth}
        detected = sum(
            all(
                receipt_id in truth_by_id
                and not truth_by_id[receipt_id].contradiction_free
                for receipt_id in case.receipt_ids
            )
            for case in contradiction_cases
        )
        emitter.emit(
            "contradiction_detection_rate",
            detected / len(contradiction_cases),
            scope={"fixture_type": "contradictory"},
            numerator=detected,
            denominator=len(contradiction_cases),
            denominator_unit="contradictory_fixture_cases",
            execution_evidence=[asdict(item) for item in contradiction_cases],
        )
    else:
        emitter.unavailable(
            "contradiction_detection_rate",
            NOT_APPLICABLE,
            "the configured evidence profile emitted no contradictory adversarial fixtures",
        )
    obligation_count = len(emitter.data.obligations.evidence_obligations)
    if obligation_count:
        verification_bytes = sum(
            len(_canonical_json(_normalize_digest_value(row)).encode("utf-8"))
            for row in emitter.data.receipts.evidence_receipts
        )
        verification_bytes += sum(
            len(_canonical_json(_normalize_digest_value(asdict(item))).encode("utf-8"))
            for item in (
                *emitter.data.receipts.receipt_fixtures,
                *emitter.data.receipts.synthetic_keys,
                *emitter.data.receipts.synthetic_anchors,
            )
        )
        emitter.emit(
            "verification_cost",
            verification_bytes / obligation_count,
            scope={
                "cost_dimension": "canonical_bytes",
                "cpu_time_measured": False,
                "memory_measured": False,
            },
            numerator=verification_bytes,
            denominator=obligation_count,
            denominator_unit="evidence_obligations",
            execution_evidence={
                "canonical_verification_bytes": verification_bytes,
                "obligation_count": obligation_count,
            },
        )
    else:
        emitter.unavailable(
            "verification_cost",
            NOT_APPLICABLE,
            "no evidence obligations exist",
        )


def _observer_metrics(emitter: _MetricEmitter) -> None:
    diagnostics = tuple(
        item for key, item in sorted(emitter.data.observers.diagnostics.items())
        if key != FULL_OBSERVER_PROFILE_ID
    )
    if not diagnostics:
        for key in (
            "visible_event_coverage",
            "visible_edge_coverage",
            "evidence_recoverability",
        ):
            emitter.unavailable(key, NOT_APPLICABLE, "no non-full observer profiles are configured")
    else:
        denominator = sum(item.source_event_count for item in diagnostics)
        visible = math.fsum(item.weighted_visible_event_coverage * item.source_event_count for item in diagnostics)
        recoverable = math.fsum(item.evidence_recoverability for item in diagnostics)
        emitter.emit("visible_event_coverage", visible / denominator, scope={"observer_profiles": [item.profile_id for item in diagnostics]}, numerator=visible, denominator=denominator, denominator_unit="observer_profile_world_event_exposure", execution_evidence=[asdict(item) for item in diagnostics])
        emitter.emit("evidence_recoverability", recoverable / len(diagnostics), scope={"observer_profiles": [item.profile_id for item in diagnostics]}, numerator=recoverable, denominator=len(diagnostics), denominator_unit="observer_profiles", execution_evidence=[asdict(item) for item in diagnostics])
        event_by_id = {
            str(row["event_id"]): row
            for row in emitter.data.causal_dag.governance_events
        }
        required_edges = tuple(
            row
            for row in emitter.data.causal_dag.event_edges
            if bool(row["required_for_closure"])
        )
        visible_by_profile: dict[str, set[str]] = defaultdict(set)
        for mapping in emitter.data.observers.source_mappings:
            if mapping.projection_profile_id != FULL_OBSERVER_PROFILE_ID and mapping.visible:
                visible_by_profile[mapping.projection_profile_id].add(
                    mapping.source_event_id
                )
        edge_denominator = 0.0
        edge_numerator = 0.0
        for diagnostic in diagnostics:
            visible_ids = visible_by_profile.get(diagnostic.profile_id, set())
            for edge in required_edges:
                destination_id = str(edge["target_event_id"])
                weight = float(event_by_id[destination_id]["represented_event_count"])
                edge_denominator += weight
                if (
                    str(edge["source_event_id"]) in visible_ids
                    and destination_id in visible_ids
                ):
                    edge_numerator += weight
        emitter.emit(
            "visible_edge_coverage",
            edge_numerator / edge_denominator if edge_denominator else 1.0,
            scope={
                "observer_profiles": [item.profile_id for item in diagnostics],
                "edge_policy": "required_for_closure",
            },
            numerator=edge_numerator,
            denominator=max(edge_denominator, 1.0),
            denominator_unit="represented_required_edge_exposure",
            uncertainty_status="not_applicable" if not required_edges else None,
            uncertainty_reason="no required causal edges exist" if not required_edges else None,
            execution_evidence=required_edges,
        )
    leakage = emitter.data.observers.leakage_diagnostics
    emitter.emit("sealed_truth_leakage", leakage.sealed_truth_leakage_count, scope={"release_profiles": "all_releasable_observer_views"}, numerator=leakage.sealed_truth_leakage_count, denominator=None, denominator_unit="not_applicable_count", uncertainty_status="not_applicable", uncertainty_reason="leakage is a deterministic exhaustive scan of the generated release views", execution_evidence=asdict(leakage), publication_eligible=leakage.passed)
    collusion = tuple(item for item in diagnostics if item.mode == "collusion")
    if collusion:
        emitter.emit("collusion_gain", math.fsum(item.collusion_gain for item in collusion) / len(collusion), scope={"collusion_profiles": [item.profile_id for item in collusion]}, numerator=math.fsum(item.collusion_gain for item in collusion), denominator=len(collusion), denominator_unit="collusion_profiles", execution_evidence=[asdict(item) for item in collusion])
    else:
        emitter.unavailable("collusion_gain", NOT_APPLICABLE, "no collusion observer profile is configured")


def _sampling_metrics(emitter: _MetricEmitter) -> None:
    if not emitter.data.sampling.diagnostics:
        for key in (
            "effective_sample_size",
            "closure_expansion_factor",
            "weight_reconciliation_error",
            "design_effect",
        ):
            emitter.unavailable(key, NOT_APPLICABLE, "no probability sampling designs exist")
    eligible_weight_reconciliation = False
    for design_id, diagnostic in sorted(emitter.data.sampling.diagnostics.items()):
        membership = tuple(
            row for row in emitter.data.sampling.sample_memberships
            if str(row["sample_design_id"]) == design_id
        )
        weight_sum = math.fsum(float(row["analysis_weight"]) for row in membership)
        weight_square_sum = math.fsum(float(row["analysis_weight"]) ** 2 for row in membership)
        emitter.emit("effective_sample_size", diagnostic.effective_sample_size, scope={"sample_design_id": design_id, "primary_unit_type": diagnostic.primary_unit_type}, numerator=weight_sum ** 2, denominator=weight_square_sum, denominator_unit="sum_squared_analysis_weights", execution_evidence={"diagnostic": asdict(diagnostic), "membership_count": len(membership)})
        primary_rows = tuple(
            row
            for row in membership
            if str(row["selection_reason"]) in {"primary_draw", "census"}
        )
        emitter.emit(
            "closure_expansion_factor",
            diagnostic.closure_expansion_factor,
            scope={"sample_design_id": design_id},
            numerator=diagnostic.closure_added_count,
            denominator=diagnostic.selected_primary_unit_count,
            denominator_unit="selected_primary_units",
            execution_evidence=asdict(diagnostic),
        )
        emitter.emit(
            "design_effect",
            diagnostic.design_effect,
            scope={"sample_design_id": design_id},
            numerator=diagnostic.selected_primary_unit_count,
            denominator=diagnostic.effective_sample_size,
            denominator_unit="kish_effective_sample_size",
            execution_evidence=asdict(diagnostic),
        )
        if primary_rows and all(bool(row["estimator_eligible"]) for row in primary_rows):
            estimated_population_count = math.fsum(
                float(row["design_weight"]) for row in primary_rows
            )
            declared_count = diagnostic.population_primary_unit_count
            error = abs(estimated_population_count - declared_count) / declared_count
            emitter.emit(
                "weight_reconciliation_error",
                error,
                scope={"sample_design_id": design_id},
                numerator=abs(estimated_population_count - declared_count),
                denominator=declared_count,
                denominator_unit="declared_primary_units",
                execution_evidence={
                    "estimated_primary_unit_count": estimated_population_count,
                    "declared_primary_unit_count": declared_count,
                },
            )
            eligible_weight_reconciliation = True
    if emitter.data.sampling.diagnostics and not eligible_weight_reconciliation:
        emitter.unavailable(
            "weight_reconciliation_error",
            NOT_APPLICABLE,
            "no estimator-eligible probability design exists",
        )
    known = tuple(emitter.data.sampling.known_total_diagnostics)
    if not known:
        for key in ("relative_bias_known_total", "ci_coverage", "rmse_known_total"):
            emitter.unavailable(key, NOT_APPLICABLE, "no eligible known-total probability-design simulation exists")
        return
    for item in known:
        scope = {"sample_design_id": item.sample_design_id, "analysis_domain": item.analysis_domain, "estimator_family": item.estimator_family, "simulation_repetitions": item.repetitions, "confidence_level": item.confidence_level}
        bias_se = item.empirical_standard_deviation / math.sqrt(item.repetitions) / abs(item.truth_total)
        coverage_se = math.sqrt(item.ci_coverage * (1.0 - item.ci_coverage) / item.repetitions)
        emitter.emit("relative_bias_known_total", item.relative_bias, scope=scope, numerator=item.mean_estimate - item.truth_total, denominator=abs(item.truth_total), denominator_unit="known_truth_total", standard_error=bias_se, uncertainty_status="estimated_within_design", uncertainty_reason="standard error derives from repeated probability-design estimates", execution_evidence=asdict(item))
        emitter.emit("ci_coverage", item.ci_coverage, scope=scope, numerator=item.ci_coverage * item.repetitions, denominator=item.repetitions, denominator_unit="design_simulations", standard_error=coverage_se, uncertainty_status="estimated_within_design", uncertainty_reason="binomial standard error across repeated probability-design simulations", execution_evidence=asdict(item))
        emitter.emit("rmse_known_total", item.relative_rmse, scope=scope, numerator=None, denominator=abs(item.truth_total), denominator_unit="known_truth_total", uncertainty_status="not_available_from_retained_summary", uncertainty_reason="repeat-level squared errors are not retained; the reported value is the executed repeated-design RMSE", execution_evidence=asdict(item))


def _privacy_metrics(emitter: _MetricEmitter) -> None:
    numerator, denominator, profile_ids = _rare_trace_counts(emitter.data)
    if denominator:
        emitter.emit("rare_trace_exposure", numerator / denominator, scope={"observer_profiles": profile_ids, "rare_signature_max_frequency": 1}, numerator=numerator, denominator=denominator, denominator_unit="visible_observer_events", execution_evidence={"rare_event_count": numerator, "visible_event_count": denominator, "profiles": profile_ids})
    else:
        emitter.unavailable("rare_trace_exposure", NOT_APPLICABLE, "non-full observer profiles expose no workflow events")
    reference = emitter.data.privacy_reference
    if reference is None:
        for key in (
            "exact_duplicate_rate",
            "nearest_neighbor_ratio",
            "membership_inference_auc",
            "attribute_inference_gain",
        ):
            emitter.unavailable(
                key,
                NOT_APPLICABLE,
                "the controlled-synthetic release profile has no observed source-population "
                "comparison set and does not permit source-privacy attack claims",
            )
    else:
        _privacy_duplicate_metric(emitter, reference)
        for key in (
            "nearest_neighbor_ratio",
            "membership_inference_auc",
            "attribute_inference_gain",
        ):
            emitter.unavailable(
                key,
                NOT_EXECUTED,
                "the supplied digest-only privacy reference lacks the feature and challenge "
                "contracts required by this metric",
            )


def _artifact_metrics(emitter: _MetricEmitter) -> None:
    reference = emitter.data.reproducibility_reference_digests
    if reference is None:
        emitter.unavailable("deterministic_digest_match", NOT_EXECUTED, "no separately executed clean-rerun digest inventory was supplied")
    else:
        status = _validation_row(emitter.data.validation.validation_issues, "REPRODUCIBILITY-001")["status"]
        if status == "not_executed":
            emitter.unavailable("deterministic_digest_match", NOT_EXECUTED, "the supplied digest inventory was not executed by the S13 clean-rerun validator")
        else:
            match = 1.0 if status == "pass" else 0.0
            emitter.emit("deterministic_digest_match", match, scope={"compared_table_names": sorted(reference)}, numerator=match * len(reference), denominator=max(len(reference), 1), denominator_unit="authoritative_table_digests", uncertainty_status="not_applicable", uncertainty_reason="digest equality is a deterministic comparison, not a stochastic estimate", execution_evidence=reference, publication_eligible=status == "pass")
    verification = emitter.data.artifact_verification
    if verification is None:
        emitter.unavailable("manifest_coverage", NOT_EXECUTED, "no stored artifact bytes and schema-valid manifest inventory were supplied")
    else:
        status = _validation_row(emitter.data.validation.validation_issues, "MANIFEST-001")["status"]
        if status == "not_executed":
            emitter.unavailable("manifest_coverage", NOT_EXECUTED, "the supplied inventory was not executed by the S13 stored-artifact manifest validator")
        elif status != "pass":
            emitter.unavailable("manifest_coverage", FAILED, "S13 manifest verification failed; S14 does not replace the failed census with a coarse or partial coverage value")
        else:
            denominator = len(verification.artifact_payloads)
            emitter.emit("manifest_coverage", 1.0, scope={"inventory_stage": "supplied_S13_artifact_verification", "artifact_paths": sorted(verification.artifact_payloads)}, numerator=denominator, denominator=max(denominator, 1), denominator_unit="stored_artifact_payloads", uncertainty_status="not_applicable", uncertainty_reason="manifest coverage is a deterministic stored-byte inventory census", execution_evidence={"manifest_rows": list(verification.manifest_rows), "payload_digests": {key: hashlib.sha256(value).hexdigest() for key, value in sorted(verification.artifact_payloads.items())}}, publication_eligible=True)


def _performance_metrics(emitter: _MetricEmitter) -> None:
    observation = emitter.data.performance_observation
    if observation is None:
        for key in (
            "generation_rows_per_second",
            "peak_resident_memory_bytes",
            "stored_bytes_per_event",
            "parallel_efficiency",
            "row_group_efficiency",
            "stage_stored_bytes_per_row",
        ):
            emitter.unavailable(key, NOT_EXECUTED, "no externally measured process and artifact telemetry was supplied")
        return
    values = (observation.elapsed_seconds, observation.rows_per_second, observation.peak_memory_bytes, observation.stored_bytes)
    if any(not math.isfinite(float(value)) or float(value) <= 0 for value in values):
        raise MetricsEngineError("performance observation values must be positive and finite")
    if observation.measurement_profile_id != emitter.data.resolved.validation.metric_threshold_profile_id:
        raise MetricsEngineError("performance measurement profile does not match the resolved validation profile")
    if observation.generated_row_count <= 0:
        raise MetricsEngineError("performance generated_row_count must be positive")
    recomputed = observation.generated_row_count / observation.elapsed_seconds
    if not math.isclose(recomputed, observation.rows_per_second, rel_tol=1e-9):
        raise MetricsEngineError("performance rows_per_second does not reconcile to rows/elapsed_seconds")
    recomputed_bytes = observation.stored_bytes / observation.generated_row_count
    if not math.isclose(recomputed_bytes, observation.bytes_per_row, rel_tol=1e-9):
        raise MetricsEngineError("performance bytes_per_row does not reconcile to stored_bytes/generated_rows")
    if not math.isfinite(observation.parallel_efficiency) or observation.parallel_efficiency <= 0:
        raise MetricsEngineError("performance parallel_efficiency must be positive and finite")
    if observation.requested_worker_count < 1 or observation.effective_worker_count < 1:
        raise MetricsEngineError("performance worker counts must be positive")
    if observation.effective_worker_count > observation.requested_worker_count:
        raise MetricsEngineError("effective worker count cannot exceed requested worker count")
    if observation.effective_worker_count > 1:
        if observation.serial_elapsed_seconds is None:
            raise MetricsEngineError("parallel efficiency requires a serial elapsed measurement")
        expected_efficiency = observation.serial_elapsed_seconds / (
            observation.elapsed_seconds * observation.effective_worker_count
        )
        if not math.isclose(expected_efficiency, observation.parallel_efficiency, rel_tol=1e-9):
            raise MetricsEngineError("parallel efficiency does not reconcile to serial/(parallel*workers)")
    scope = {"measurement_profile_id": observation.measurement_profile_id}
    performance_status = _validation_row(emitter.data.validation.validation_issues, "PERFORMANCE-001")["status"]
    publication_eligible = performance_status == "pass"
    emitter.emit("generation_rows_per_second", observation.rows_per_second, scope=scope, numerator=observation.generated_row_count, denominator=observation.elapsed_seconds, denominator_unit="elapsed_wall_clock_seconds", execution_evidence=asdict(observation), publication_eligible=publication_eligible)
    emitter.emit("peak_resident_memory_bytes", observation.peak_memory_bytes, scope=scope, numerator=observation.peak_memory_bytes, denominator=None, denominator_unit="not_applicable_peak_measurement", execution_evidence=asdict(observation), publication_eligible=publication_eligible)
    emitter.emit(
        "parallel_efficiency",
        observation.parallel_efficiency,
        scope={
            **scope,
            "requested_worker_count": observation.requested_worker_count,
            "effective_worker_count": observation.effective_worker_count,
        },
        numerator=(
            observation.serial_elapsed_seconds
            if observation.serial_elapsed_seconds is not None
            else observation.elapsed_seconds
        ),
        denominator=observation.elapsed_seconds * observation.effective_worker_count,
        denominator_unit="parallel_elapsed_seconds_times_effective_workers",
        execution_evidence=asdict(observation),
        publication_eligible=publication_eligible,
    )
    event_count = len(emitter.data.causal_dag.governance_events)
    if event_count:
        emitter.emit("stored_bytes_per_event", observation.stored_bytes / event_count, scope=scope, numerator=observation.stored_bytes, denominator=event_count, denominator_unit="canonical_governance_events", execution_evidence=asdict(observation), publication_eligible=publication_eligible)
    else:
        emitter.unavailable("stored_bytes_per_event", NOT_APPLICABLE, "no canonical governance events exist")

    if not observation.stage_observations:
        emitter.unavailable(
            "row_group_efficiency",
            NOT_APPLICABLE,
            "the external performance observation did not declare a stage-bound Parquet "
            "row-group measurement profile",
        )
        emitter.unavailable(
            "stage_stored_bytes_per_row",
            NOT_APPLICABLE,
            "the external performance observation did not declare stage-bound stored-byte telemetry",
        )
        return

    for stage in observation.stage_observations:
        if stage.elapsed_seconds <= 0 or not math.isfinite(stage.elapsed_seconds):
            raise MetricsEngineError(f"{stage.stage_id}: stage elapsed time must be positive")
        if stage.generated_row_count < 0:
            raise MetricsEngineError(f"{stage.stage_id}: generated row count cannot be negative")
        expected_rate = stage.generated_row_count / stage.elapsed_seconds
        if not math.isclose(expected_rate, stage.rows_per_second, rel_tol=1e-9):
            raise MetricsEngineError(f"{stage.stage_id}: rows_per_second does not reconcile")
        if min(stage.rss_before_bytes, stage.rss_after_bytes, stage.peak_resident_memory_bytes) <= 0:
            raise MetricsEngineError(f"{stage.stage_id}: RSS observations must be positive")
        if stage.peak_resident_memory_bytes < max(stage.rss_before_bytes, stage.rss_after_bytes):
            raise MetricsEngineError(f"{stage.stage_id}: peak RSS is below an endpoint RSS")
        if stage.serial_elapsed_seconds is None or stage.serial_elapsed_seconds <= 0:
            raise MetricsEngineError(f"{stage.stage_id}: serial stage timing is missing")
        expected_stage_efficiency = stage.serial_elapsed_seconds / (
            stage.elapsed_seconds * observation.effective_worker_count
        )
        if not math.isclose(
            expected_stage_efficiency,
            stage.parallel_efficiency,
            rel_tol=1e-9,
        ):
            raise MetricsEngineError(
                f"{stage.stage_id}: parallel efficiency does not reconcile"
            )
        stage_scope = {
            **scope,
            "stage_id": stage.stage_id,
            "operation": stage.operation,
            "measurement_pass": "pre_publication_external_evidence",
        }
        emitter.emit(
            "generation_rows_per_second",
            stage.rows_per_second,
            scope=stage_scope,
            numerator=stage.generated_row_count,
            denominator=stage.elapsed_seconds,
            denominator_unit="stage_elapsed_wall_clock_seconds",
            execution_evidence=asdict(stage),
            publication_eligible=publication_eligible,
        )
        emitter.emit(
            "peak_resident_memory_bytes",
            stage.peak_resident_memory_bytes,
            scope=stage_scope,
            numerator=stage.peak_resident_memory_bytes,
            denominator=None,
            denominator_unit="not_applicable_stage_peak_measurement",
            execution_evidence=asdict(stage),
            publication_eligible=publication_eligible,
        )
        emitter.emit(
            "parallel_efficiency",
            stage.parallel_efficiency,
            scope=stage_scope,
            numerator=stage.serial_elapsed_seconds,
            denominator=stage.elapsed_seconds * observation.effective_worker_count,
            denominator_unit="stage_parallel_elapsed_seconds_times_effective_workers",
            execution_evidence=asdict(stage),
            publication_eligible=publication_eligible,
        )
        if stage.generated_row_count > 0 and stage.stored_bytes > 0:
            emitter.emit(
                "stage_stored_bytes_per_row",
                stage.stored_bytes / stage.generated_row_count,
                scope=stage_scope,
                numerator=stage.stored_bytes,
                denominator=stage.generated_row_count,
                denominator_unit="stage_generated_rows",
                execution_evidence=asdict(stage),
                publication_eligible=publication_eligible,
            )
        if stage.row_group_efficiency is not None:
            if not 0 < stage.row_group_efficiency <= 1 or stage.row_group_count <= 0:
                raise MetricsEngineError(f"{stage.stage_id}: invalid row-group efficiency evidence")
            emitter.emit(
                "row_group_efficiency",
                stage.row_group_efficiency,
                scope=stage_scope,
                numerator=stage.row_group_efficiency * stage.row_group_count,
                denominator=stage.row_group_count,
                denominator_unit="stage_parquet_row_groups",
                execution_evidence=asdict(stage),
                publication_eligible=publication_eligible,
            )

    if "stage_stored_bytes_per_row" not in emitter.metric_ids_by_key:
        emitter.unavailable(
            "stage_stored_bytes_per_row",
            NOT_APPLICABLE,
            "executed stages emitted no positive-row stored artifacts",
        )
    if "row_group_efficiency" not in emitter.metric_ids_by_key:
        emitter.unavailable(
            "row_group_efficiency",
            NOT_APPLICABLE,
            "stage artifacts had no pinned row-group target observations",
        )


def _privacy_duplicate_metric(emitter: _MetricEmitter, reference: PrivacySourceReference) -> None:
    _validate_reference_identity(reference.reference_id, reference.source_label)
    source = set(reference.canonical_record_digests)
    released = tuple(reference.comparable_released_record_digests)
    if not source or not released:
        raise MetricsEngineError("privacy source comparison digest sets must be non-empty")
    for value in (*source, *released):
        if value != value.lower() or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise MetricsEngineError("privacy comparison records must be lowercase SHA-256 digests")
    duplicates = sum(value in source for value in released)
    emitter.emit("exact_duplicate_rate", duplicates / len(released), scope={"reference_id": reference.reference_id, "comparison_projection": "canonical_registered_projection"}, numerator=duplicates, denominator=len(released), denominator_unit="comparable_released_records", reference_id=reference.reference_id, execution_evidence=asdict(reference))


def _rare_trace_counts(data: MetricsInput) -> tuple[int, int, list[str]]:
    event_by_id = {str(row["event_id"]): row for row in data.causal_dag.governance_events}
    mappings_by_profile: dict[str, list[Any]] = defaultdict(list)
    for item in data.observers.source_mappings:
        profile_id = item.projection_profile_id
        if profile_id != FULL_OBSERVER_PROFILE_ID and item.visible:
            mappings_by_profile[profile_id].append(item)
    rare_event_count = 0
    visible_event_count = 0
    for profile_id, mappings in sorted(mappings_by_profile.items()):
        by_workflow: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for item in mappings:
            event = event_by_id[item.source_event_id]
            by_workflow[str(event["workflow_instance_id"])].append(
                (int(event["workflow_step_index"]), str(event["event_type"]))
            )
        signatures = {
            workflow_id: tuple(value for _, value in sorted(items))
            for workflow_id, items in by_workflow.items()
        }
        counts = Counter(signatures.values())
        rare_workflows = {key for key, value in signatures.items() if counts[value] == 1}
        visible_event_count += len(mappings)
        rare_event_count += sum(len(by_workflow[key]) for key in rare_workflows)
    return rare_event_count, visible_event_count, sorted(mappings_by_profile)


def _meter_distribution_groups(rows: Sequence[Mapping[str, Any]]) -> Mapping[tuple[str, int], tuple[list[float], list[float]]]:
    result: dict[tuple[str, int], tuple[list[float], list[float]]] = {}
    for row in rows:
        key = (str(row["cohort_id"]), _timestamp(row["interval_start"]).hour)
        values, weights = result.setdefault(key, ([], []))
        values.append(float(row["import_energy_kwh"]))
        weights.append(float(row["represented_meter_count"]))
    return result


def _reference_distribution_groups(reference: PhysicalCalibrationReference) -> Mapping[tuple[str, int], tuple[list[float], list[float]]]:
    result: dict[tuple[str, int], tuple[list[float], list[float]]] = {}
    for row in reference.observations:
        if not math.isfinite(row.import_energy_kwh) or row.import_energy_kwh < 0:
            raise MetricsEngineError("reference import energy must be non-negative and finite")
        if not math.isfinite(row.represented_meter_count) or row.represented_meter_count <= 0:
            raise MetricsEngineError("reference represented-meter count must be positive and finite")
        key = (row.cohort_id, _timestamp(row.interval_start).hour)
        values, weights = result.setdefault(key, ([], []))
        values.append(row.import_energy_kwh)
        weights.append(row.represented_meter_count)
    return result


def _meter_series(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, list[float]]:
    grouped: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["cohort_id"])].append((_timestamp(row["interval_start"]), float(row["import_energy_kwh"])))
    return {key: [value for _, value in sorted(items)] for key, items in grouped.items()}


def _reference_series(reference: PhysicalCalibrationReference) -> Mapping[str, list[float]]:
    grouped: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    for row in reference.observations:
        grouped[row.cohort_id].append((_timestamp(row.interval_start), row.import_energy_kwh))
    return {key: [value for _, value in sorted(items)] for key, items in grouped.items()}


def _validation_row(rows: Sequence[Mapping[str, Any]], check_id: str) -> Mapping[str, Any]:
    matches = tuple(row for row in rows if str(row["check_id"]) == check_id)
    if len(matches) != 1:
        raise MetricsEngineError(f"validation ledger must contain exactly one {check_id} row")
    return matches[0]


def _scenario_diagnostic(diagnostics: Mapping[str, Any], scenario_id: str) -> Any:
    try:
        return diagnostics[scenario_id]
    except KeyError as exc:
        raise MetricsEngineError(f"missing diagnostics for scenario={scenario_id}") from exc


def _validate_reference_identity(reference_id: str, source_label: str) -> None:
    if not reference_id.strip():
        raise MetricsEngineError("reference_id must be non-empty")
    if source_label not in ALLOWED_SOURCE_LABELS:
        raise MetricsEngineError(f"reference source_label={source_label!r} is not controlled")


def _per_replicate_uncertainty(
    policy: str, replicate_count: int, standard_error: float | None
) -> tuple[str, str]:
    if standard_error is not None:
        return "estimated_within_design", "standard error was computed from the declared within-run design"
    if policy == "not_applicable":
        return "not_applicable", "metric is a deterministic finite-census or identity result"
    if policy == "design_simulation":
        return "not_available_from_retained_summary", "the executed design summary does not retain sufficient repeat-level values for this standard error"
    if replicate_count >= 2:
        return "pending_replicate_aggregation", "uncertainty is computed across independent full-pipeline replicates in replicate_summary.parquet"
    return "not_estimable_single_replicate", "the resolved run contains one full-pipeline replicate"


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest_payload(value: Any) -> str:
    normalized = _normalize_digest_value(value)
    return hashlib.sha256(_canonical_json(normalized).encode("utf-8")).hexdigest()


def _normalize_digest_value(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return _normalize_digest_value(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _normalize_digest_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_normalize_digest_value(item) for item in value]
        return sorted(items, key=_canonical_json) if isinstance(value, (set, frozenset)) else items
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    return value
