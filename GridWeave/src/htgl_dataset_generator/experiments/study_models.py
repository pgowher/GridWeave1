"""Typed P8 factorial-study plans, execution ledgers, and scale claims."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class FactorLevel:
    level_id: str
    value: Any
    claim_eligible: bool
    required_capability: str | None


@dataclass(frozen=True)
class FactorAxis:
    axis_id: str
    execution_mode: str
    levels: tuple[FactorLevel, ...]


@dataclass(frozen=True)
class FactorialStudyRegistry:
    registry_id: str
    version: str
    source: str
    sha256: str
    axes: tuple[FactorAxis, ...]

    def axis(self, axis_id: str) -> FactorAxis:
        matches = tuple(axis for axis in self.axes if axis.axis_id == axis_id)
        if len(matches) != 1:
            raise KeyError(f"factor axis {axis_id!r} does not resolve uniquely")
        return matches[0]


@dataclass(frozen=True)
class PrecisionJustification:
    method: str
    confidence_level: float
    target_half_width: float
    pilot_standard_deviation: float
    pilot_repetitions: int
    source_label: str
    source_id: str


@dataclass(frozen=True)
class StudyResourceBudget:
    maximum_conditions: int
    maximum_replicates: int
    maximum_materialized_rows_per_replicate: int
    maximum_total_materialized_rows: int
    maximum_total_stored_bytes: int
    stored_bytes_per_materialized_row_upper_bound: int
    capabilities: frozenset[str]


@dataclass(frozen=True)
class StudyCondition:
    condition_id: str
    ordinal: int
    factor_level_ids: Mapping[str, str]
    factor_values: Mapping[str, Any]
    represented_population_N: int
    materialized_row_target_n: int
    executed_operation_target_q: int | None
    repetitions: int
    common_random_group: str
    estimator_eligible: bool
    feasibility_status: str
    feasibility_reasons: tuple[str, ...]
    projected_materialized_rows: int
    projected_stored_bytes_upper_bound: int


@dataclass(frozen=True)
class FactorialStudyPlan:
    study_id: str
    registry: FactorialStudyRegistry
    design_mode: str
    design_scope_statement: str
    requested_repetitions: int
    required_repetitions: int
    precision_justification: PrecisionJustification | None
    full_factorial_condition_count: int
    selected_condition_count: int
    pairwise_requirement_count: int
    pairwise_covered_count: int
    conditions: tuple[StudyCondition, ...]
    plan_sha256: str


@dataclass(frozen=True)
class DownstreamReplayEvidence:
    condition_id: str
    scenario_id: str
    replicate_id: int
    executed_operation_count_q: int
    workload_digest: str
    result_digest: str
    implementation_id: str
    hardware_profile_id: str


@dataclass(frozen=True)
class ReplicateStudyEvidence:
    condition_id: str
    run_id: str
    scenario_id: str
    replicate_id: int
    execution_status: str
    represented_population_N: int
    materialized_row_target_n: int
    materialized_governance_event_rows_n: int | None
    materialized_total_table_rows: int | None
    executed_operations_q: int | None
    seed_stream_digest: str | None
    canonical_table_digest: str | None
    retained_metric_count: int
    validation_status: str
    known_total_status: str
    maximum_absolute_relative_bias: float | None
    relative_rmse: float | None
    minimum_ci_coverage: float | None
    resource_status: str
    generated_rows: int | None
    elapsed_seconds: float | None
    rows_per_second: float | None
    peak_resident_memory_bytes: int | None
    stored_bytes: int | None
    artifact_manifest_sha256: str | None
    clean_rerun_digest_match: bool | None
    failure_code: str | None
    failure_message: str | None


@dataclass(frozen=True)
class ScaleClaim:
    claim_id: str
    condition_id: str
    claim_class: str
    represented_population_N: int
    materialized_row_target_n: int
    materialized_rows_min_n: int | None
    materialized_rows_max_n: int | None
    executed_operations_sum_q: int | None
    retained_repetitions: int
    required_repetitions: int
    validation_gate: str
    statistical_gate: str
    artifact_gate: str
    reproducibility_gate: str
    claim_status: str
    claim_statement: str
    prohibited_interpretation: str


@dataclass(frozen=True)
class StudyExecutionBuild:
    plan: FactorialStudyPlan
    replicate_evidence: tuple[ReplicateStudyEvidence, ...]
    run_metrics: tuple[Mapping[str, Any], ...]
    factor_metrics: tuple[Mapping[str, Any], ...]
    metric_aggregates: tuple[Mapping[str, Any], ...]
    validation_issues: tuple[Mapping[str, Any], ...]
    scale_claims: tuple[ScaleClaim, ...]
    execution_sha256: str
    publication_eligible: bool
    publication_blockers: tuple[str, ...]


@dataclass(frozen=True)
class StudyPackageOptions:
    package_kind: str = "diagnostic"
    collision_policy: str = "fail"
    compression_level: int = 9
    condition_release_root: Path | None = None
    failure_injector: Callable[[str, Path], None] | None = None


@dataclass(frozen=True)
class StudyPackageResult:
    package_root: Path
    manifest_path: Path
    manifest_sha256: str
    semantic_digest: str
    byte_digest: str
    artifact_count: int
    publication_eligible: bool
    reused_existing_package: bool
