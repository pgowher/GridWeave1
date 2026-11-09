"""Typed S14 metric definitions, observations, aggregates, and comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class MetricDefinition:
    metric_key: str
    domain: str
    definition: str
    direction: str
    unit: str
    estimator: str
    weighting: str
    scope_contract: str
    denominator_contract: str
    uncertainty_policy: str
    requires: str
    applicability: str


@dataclass(frozen=True)
class MetricRegistry:
    registry_id: str
    version: str
    source: str
    sha256: str
    definitions: Mapping[str, MetricDefinition]

    def definition(self, metric_key: str) -> MetricDefinition:
        try:
            return self.definitions[metric_key]
        except KeyError as exc:
            raise KeyError(f"metric key {metric_key!r} is not registered in {self.registry_id}") from exc


@dataclass(frozen=True)
class PhysicalReferenceObservation:
    cohort_id: str
    interval_start: str
    import_energy_kwh: float
    represented_meter_count: float


@dataclass(frozen=True)
class PhysicalCalibrationReference:
    reference_id: str
    source_label: str
    observations: tuple[PhysicalReferenceObservation, ...]
    acf_lags: tuple[int, ...]


@dataclass(frozen=True)
class PrivacySourceReference:
    reference_id: str
    source_label: str
    canonical_record_digests: tuple[str, ...]
    comparable_released_record_digests: tuple[str, ...]


@dataclass(frozen=True)
class MetricsInput:
    resolved: Any
    run_plan: Any
    tables: Mapping[str, tuple[Mapping[str, Any], ...]]
    world: Any
    catalog: Any
    physical: Any
    arrivals: Any
    workflows: Any
    causal_dag: Any
    policy: Any
    obligations: Any
    receipts: Any
    anomalies: Any
    observers: Any
    sampling: Any
    validation: Any
    physical_reference: PhysicalCalibrationReference | None = None
    privacy_reference: PrivacySourceReference | None = None
    artifact_verification: Any | None = None
    reproducibility_reference_digests: Mapping[str, str] | None = None
    performance_observation: Any | None = None


@dataclass(frozen=True)
class MetricObservationProvenance:
    metric_id: str
    metric_key: str
    definition_id: str
    registry_id: str
    registry_version: str
    registry_sha256: str
    run_id: str
    scenario_id: str
    replicate_id: int
    scope_id: str
    scope_json: str
    numerator: float | None
    denominator: float | None
    denominator_unit: str
    estimator: str
    weighting: str
    baseline_id: str | None
    replicate_set: tuple[int, ...]
    uncertainty_status: str
    uncertainty_reason: str
    reference_id: str | None
    publication_eligible: bool
    execution_evidence_digest: str


@dataclass(frozen=True)
class MetricExecutionRecord:
    run_id: str
    scenario_id: str
    replicate_id: int
    metric_key: str
    status: str
    reason: str
    output_metric_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReplicateMetricAggregate:
    aggregate_id: str
    run_id: str
    scenario_id: str
    metric_key: str
    metric_domain: str
    scope_id: str
    baseline_id: str | None
    unit: str
    estimator: str
    weighting: str
    replicate_ids: tuple[int, ...]
    replicate_count: int
    mean_value: float
    empirical_standard_error: float | None
    ci_lower: float | None
    ci_upper: float | None
    confidence_level: float
    uncertainty_method: str
    uncertainty_status: str
    uncertainty_reason: str


@dataclass(frozen=True)
class MetricConditionSeries:
    condition_id: str
    condition_role: str
    common_random_group: str
    metrics: tuple[dict[str, Any], ...]
    provenance: tuple[MetricObservationProvenance, ...]


@dataclass(frozen=True)
class PairedMetricComparison:
    comparison_id: str
    metric_key: str
    metric_domain: str
    scope_id: str
    unit: str
    estimator: str
    weighting: str
    common_random_group: str
    baseline_condition_id: str
    treatment_condition_id: str
    treatment_role: str
    paired_replicate_ids: tuple[int, ...]
    pair_count: int
    mean_difference: float
    empirical_standard_error: float | None
    ci_lower: float | None
    ci_upper: float | None
    standardized_effect_size: float | None
    effect_size_method: str
    confidence_level: float
    uncertainty_method: str
    status: str
    reason: str


@dataclass(frozen=True)
class MetricsBuild:
    run_metrics: tuple[dict[str, Any], ...]
    provenance: tuple[MetricObservationProvenance, ...]
    execution_records: tuple[MetricExecutionRecord, ...]
    registry: MetricRegistry

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {"run_metric": self.run_metrics}


@dataclass(frozen=True)
class MetricsRunGroupBuild:
    per_replicate: tuple[MetricsBuild, ...]
    aggregates: tuple[ReplicateMetricAggregate, ...]
    paired_comparisons: tuple[PairedMetricComparison, ...]
