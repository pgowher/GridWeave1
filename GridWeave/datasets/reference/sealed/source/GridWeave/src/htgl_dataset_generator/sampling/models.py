"""Typed S12 probability-design, closure, simulation, and artifact models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True, order=True)
class UnitKey:
    unit_type: str
    unit_id: str


@dataclass(frozen=True)
class PrimaryUnit:
    key: UnitKey
    scenario_id: str
    stratum_id: str
    size_measure: float
    represented_value: float
    crn_key: str
    seed_event_ids: tuple[str, ...]


@dataclass(frozen=True)
class PopulationUnit:
    key: UnitKey
    stratum_id: str
    represented_value: float


@dataclass(frozen=True)
class DependencyClosure:
    scenario_id: str
    primary_unit_type: str
    closure_policy: str
    primary_units: tuple[PrimaryUnit, ...]
    population_units: Mapping[UnitKey, PopulationUnit]
    members_by_primary: Mapping[str, tuple[UnitKey, ...]]
    causes_by_member: Mapping[UnitKey, tuple[str, ...]]


@dataclass(frozen=True)
class ClosureProvenance:
    sample_design_id: str
    unit_id: str
    unit_type: str
    selected_causing_primary_unit_ids: tuple[str, ...]
    eligible_causing_primary_unit_ids: tuple[str, ...]
    closure_policy: str


@dataclass(frozen=True)
class ProbabilityDesignResult:
    design_type: str
    target_size: int
    selected_primary_unit_ids: tuple[str, ...]
    primary_inclusion_probabilities: Mapping[str, float]
    stratum_population_counts: Mapping[str, int]
    stratum_sample_counts: Mapping[str, int]
    pps_single_draw_probabilities: Mapping[str, float]
    pps_draw_count: int
    exact_inclusion_probabilities: bool


@dataclass(frozen=True)
class KnownTotalDiagnostic:
    sample_design_id: str
    analysis_domain: str
    estimator_family: str
    repetitions: int
    truth_total: float
    actual_estimate: float
    mean_estimate: float
    empirical_standard_deviation: float
    relative_bias: float
    relative_rmse: float
    ci_coverage: float
    confidence_level: float
    passed: bool


@dataclass(frozen=True)
class SamplingDesignDiagnostics:
    sample_design_id: str
    scenario_id: str
    replicate_id: int
    design_type: str
    primary_unit_type: str
    estimator_family: str
    population_primary_unit_count: int
    selected_primary_unit_count: int
    membership_count: int
    closure_added_count: int
    closure_expansion_factor: float
    effective_sample_size: float
    design_effect: float
    minimum_inclusion_probability: float
    maximum_inclusion_probability: float
    exact_induced_probability_count: int
    ineligible_membership_count: int


@dataclass(frozen=True)
class SamplingBaselineResult:
    baseline_id: str
    scenario_id: str
    primary_unit_type: str
    selected_unit_count: int
    raw_relative_error: float
    estimator_eligible: bool
    exclusion_reason: str


@dataclass(frozen=True)
class SamplingBuild:
    sampling_designs: tuple[dict[str, Any], ...]
    sample_memberships: tuple[dict[str, Any], ...]
    closure_provenance: tuple[ClosureProvenance, ...]
    known_total_diagnostics: tuple[KnownTotalDiagnostic, ...]
    diagnostics: Mapping[str, SamplingDesignDiagnostics]
    baselines: tuple[SamplingBaselineResult, ...]
    run_metrics: tuple[dict[str, Any], ...]
    scale_semantics: Mapping[str, int | None]
    frozen_input_digest: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "sampling_design": self.sampling_designs,
            "sample_membership": self.sample_memberships,
        }
