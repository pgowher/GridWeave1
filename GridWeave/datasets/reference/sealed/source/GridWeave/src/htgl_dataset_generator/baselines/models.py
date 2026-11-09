"""Typed P8 baseline, ablation, metric, and paired-comparison artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class BaselineProfile:
    profile_id: str
    family: str
    role: str
    mechanism: str
    claim_eligible: bool
    shared_budget_contract: str
    required_metrics: tuple[str, ...]
    parameters: Mapping[str, Any]
    exclusion_reason: str | None


@dataclass(frozen=True)
class BaselineRegistry:
    registry_id: str
    version: str
    source: str
    sha256: str
    profiles: Mapping[str, BaselineProfile]

    def profile(self, profile_id: str) -> BaselineProfile:
        try:
            return self.profiles[profile_id]
        except KeyError as exc:
            raise KeyError(
                f"baseline profile {profile_id!r} is not registered in {self.registry_id}"
            ) from exc


@dataclass(frozen=True)
class BaselineConditionOutput:
    condition_output_id: str
    run_id: str
    scenario_id: str
    replicate_id: int
    profile_id: str
    family: str
    role: str
    mechanism: str
    common_random_group: str
    seed_stream_name: str
    registry_id: str
    registry_version: str
    registry_sha256: str
    represented_population: int
    materialized_row_budget: int
    executed_operation_count: int | None
    source_record_count: int
    output_record_count: int
    output_digest: str
    claim_eligible: bool
    exclusion_reason: str | None
    parameters_json: str
    diagnostics_json: str


@dataclass(frozen=True)
class BaselineMetricObservation:
    metric_observation_id: str
    run_id: str
    scenario_id: str
    replicate_id: int
    profile_id: str
    family: str
    role: str
    metric_name: str
    value: float
    unit: str
    numerator: float | None
    denominator: float | None
    estimator: str
    weighting: str
    common_random_group: str
    claim_eligible: bool
    uncertainty_status: str
    uncertainty_reason: str


@dataclass(frozen=True)
class BaselinePairedComparison:
    comparison_id: str
    run_id: str
    scenario_id: str
    family: str
    metric_name: str
    unit: str
    common_random_group: str
    comparator_profile_id: str
    proposed_profile_id: str
    comparator_role: str
    paired_replicate_ids: tuple[int, ...]
    pair_count: int
    mean_difference: float
    empirical_standard_error: float | None
    ci_lower: float | None
    ci_upper: float | None
    standardized_effect_size: float | None
    confidence_level: float
    uncertainty_method: str
    status: str
    reason: str


@dataclass(frozen=True)
class BaselineOutputSample:
    sample_id: str
    run_id: str
    scenario_id: str
    replicate_id: int
    profile_id: str
    family: str
    output_type: str
    ordinal: int
    record_json: str
    evaluator_only: bool


@dataclass(frozen=True)
class BaselineStudyBuild:
    registry: BaselineRegistry
    conditions: tuple[BaselineConditionOutput, ...]
    metrics: tuple[BaselineMetricObservation, ...]
    comparisons: tuple[BaselinePairedComparison, ...]
    output_samples: tuple[BaselineOutputSample, ...]

    def condition(self, profile_id: str, scenario_id: str, replicate_id: int) -> BaselineConditionOutput:
        matches = tuple(
            item
            for item in self.conditions
            if item.profile_id == profile_id
            and item.scenario_id == scenario_id
            and item.replicate_id == replicate_id
        )
        if len(matches) != 1:
            raise KeyError(
                f"baseline condition does not resolve uniquely profile={profile_id} "
                f"scenario={scenario_id} replicate={replicate_id}"
            )
        return matches[0]
