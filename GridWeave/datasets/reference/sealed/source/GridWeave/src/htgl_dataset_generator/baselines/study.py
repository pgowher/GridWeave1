"""Executable P8 baseline and one-factor ablation study compiler.

All controls consume finalized generated artifacts. They are evaluator-only
comparators and never replace canonical S00-S15 truth. The negative temporal
control is deliberately approximate and is never described as Poisson/NHPP.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from math import cos, exp, fsum, isfinite, log, pi, sqrt
from statistics import mean, pstdev, stdev
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.metrics.statistics import (
    deterministic_percentile_interval,
    empirical_standard_error,
)
from htgl_dataset_generator.schemas import load_contract, validate_record
from htgl_dataset_generator.seeds import (
    CounterRng,
    canonical_records_digest,
    content_id,
    deterministic_uuid,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.workflows import workflow_definitions

from .anomalies import RANDOM_FIELD_PROFILE, RANDOM_TRANSITION_PROFILE
from .models import (
    BaselineConditionOutput,
    BaselineMetricObservation,
    BaselineOutputSample,
    BaselinePairedComparison,
    BaselineProfile,
    BaselineRegistry,
    BaselineStudyBuild,
)
from .registry import load_baseline_registry


BASELINE_COMPONENT = "P8.baselines"
BOOTSTRAP_REPETITIONS = 2000
EPSILON = 1e-12
MAX_EXACT_POISSON_EXPECTATION = 100_000.0
SAMPLE_ROWS_PER_CONDITION = 3

PROPOSED_BY_FAMILY = {
    "temporal": "PROPOSED-HIERARCHICAL-ARRIVAL-MODEL-v1",
    "structure": "PROPOSED-GOVERNANCE-COMPLETE-STRUCTURE-v1",
    "anomaly": "PROPOSED-MINIMAL-COUNTERFACTUAL-v1",
    "observer": "PROPOSED-OBSERVER-PROJECTION-DSL-v1",
    "sampling": "PROPOSED-DEPENDENCY-CLOSED-PROBABILITY-DESIGN-v1",
}

METRIC_CONTRACTS: Mapping[str, Mapping[str, tuple[str, str, str]]] = {
    "temporal": {
        "count_mean_ratio": ("ratio", "integrated_intensity_count_ratio_v1", "analytic"),
        "dispersion_index": ("ratio", "arrival_bin_dispersion_v1", "analytic"),
        "bin_deviance": ("deviance", "integrated_intensity_bin_deviance_v1", "analytic"),
        "time_rescaling_ks": ("dimensionless", "integrated_intensity_rescaling_ks_v1", "analytic"),
    },
    "structure": {
        "custody_reference_coverage": ("fraction", "custody_reference_census_v1", "unweighted"),
        "causal_edge_coverage": ("fraction", "normalized_edge_retention_census_v1", "unweighted"),
        "topology_reference_coverage": ("fraction", "topology_reference_census_v1", "unweighted"),
        "policy_trace_coverage": ("fraction", "policy_trace_retention_census_v1", "unweighted"),
        "evidence_obligation_coverage": ("fraction", "obligation_retention_census_v1", "unweighted"),
        "transition_conformance_rate": ("fraction", "workflow_transition_census_v1", "unweighted"),
    },
    "anomaly": {
        "target_violation_success": ("fraction", "independent_invariant_outcome_census_v1", "unweighted"),
        "collateral_violation_rate": ("fraction", "protected_invariant_outcome_census_v1", "unweighted"),
        "mean_failed_invariant_count": ("invariants", "failed_invariant_count_mean_v1", "unweighted"),
    },
    "observer": {
        "visible_event_coverage": ("fraction", "frozen_event_visibility_census_v1", "analytic"),
        "evidence_recoverability": ("fraction", "obligation_event_recoverability_census_v1", "unweighted"),
        "anomaly_event_recoverability": ("fraction", "anomaly_event_recoverability_census_v1", "unweighted"),
        "mean_delay_seconds": ("seconds", "visible_event_delay_mean_v1", "unweighted"),
        "omission_rate": ("fraction", "frozen_event_omission_census_v1", "analytic"),
        "sealed_truth_leakage": ("count", "released_projection_leakage_scan_v1", "unweighted"),
    },
    "sampling": {
        "raw_relative_error": ("ratio", "known_total_raw_relative_error_v1", "design"),
        "estimator_eligibility_rate": ("fraction", "membership_eligibility_census_v1", "unweighted"),
        "closure_expansion_factor": ("ratio", "dependency_closure_expansion_mean_v1", "unweighted"),
        "effective_sample_size": ("units", "design_weight_effective_sample_size_mean_v1", "design"),
    },
}


class BaselineStudyError(ValueError):
    """Raised when executable comparators cannot satisfy the P8 contract."""


def build_baseline_study(
    resolved: ResolvedConfig,
    replicate_results: Iterable[Any],
    *,
    registry: BaselineRegistry | None = None,
) -> BaselineStudyBuild:
    """Execute all registered controls and pair them by CRN and replicate ID."""

    profile_registry = registry if registry is not None else load_baseline_registry()
    results = tuple(
        sorted(
            replicate_results,
            key=lambda item: (item.run_plan.scenario_id, item.run_plan.replicate_id),
        )
    )
    if not results:
        raise BaselineStudyError("baseline study requires at least one finalized replicate")
    expected = {
        (plan.scenario_id, plan.replicate_id)
        for plan in _run_plans(resolved)
    }
    observed = {(item.run_plan.scenario_id, item.run_plan.replicate_id) for item in results}
    if observed != expected:
        raise BaselineStudyError(
            f"replicate coverage mismatch missing={sorted(expected-observed)} "
            f"extra={sorted(observed-expected)}"
        )
    conditions: list[BaselineConditionOutput] = []
    metrics: list[BaselineMetricObservation] = []
    samples: list[BaselineOutputSample] = []
    for result in results:
        condition_builds = _build_replicate_conditions(resolved, result, profile_registry)
        for profile, records, metric_values, diagnostics, stream_name, group, eligible, exclusion in condition_builds:
            condition = _condition_output(
                resolved,
                result.run_plan,
                profile_registry,
                profile,
                records,
                diagnostics,
                stream_name,
                group,
                claim_eligible=eligible,
                exclusion_reason=exclusion,
                source_record_count=int(diagnostics["source_record_count"]),
            )
            conditions.append(condition)
            metrics.extend(
                _metric_observations(
                    resolved,
                    result.run_plan,
                    profile,
                    metric_values,
                    group,
                    claim_eligible=eligible,
                )
            )
            samples.extend(
                _output_samples(
                    resolved,
                    result.run_plan,
                    profile,
                    records,
                    diagnostics,
                )
            )
    comparisons = build_baseline_paired_comparisons(resolved, metrics, results)
    build = BaselineStudyBuild(
        registry=profile_registry,
        conditions=tuple(sorted(conditions, key=lambda item: item.condition_output_id)),
        metrics=tuple(sorted(metrics, key=lambda item: item.metric_observation_id)),
        comparisons=comparisons,
        output_samples=tuple(sorted(samples, key=lambda item: item.sample_id)),
    )
    validate_baseline_study(build, resolved)
    return build


def validate_baseline_study(build: BaselineStudyBuild, resolved: ResolvedConfig) -> None:
    expected_runs = {
        (plan.scenario_id, plan.replicate_id) for plan in _run_plans(resolved)
    }
    expected_profiles = set(build.registry.profiles)
    condition_keys = {
        (item.scenario_id, item.replicate_id, item.profile_id) for item in build.conditions
    }
    expected_condition_keys = {
        (scenario_id, replicate_id, profile_id)
        for scenario_id, replicate_id in expected_runs
        for profile_id in expected_profiles
    }
    if condition_keys != expected_condition_keys or len(condition_keys) != len(build.conditions):
        raise BaselineStudyError("condition outputs do not cover every profile/run exactly once")
    metric_keys = {
        (item.scenario_id, item.replicate_id, item.profile_id, item.metric_name)
        for item in build.metrics
    }
    for scenario_id, replicate_id in sorted(expected_runs):
        for profile in build.registry.profiles.values():
            observed = {
                metric_name
                for s_id, r_id, p_id, metric_name in metric_keys
                if (s_id, r_id, p_id) == (scenario_id, replicate_id, profile.profile_id)
            }
            if observed != set(profile.required_metrics):
                raise BaselineStudyError(
                    f"profile={profile.profile_id} missing metric contract "
                    f"missing={sorted(set(profile.required_metrics)-observed)} "
                    f"extra={sorted(observed-set(profile.required_metrics))}"
                )
    if len(metric_keys) != len(build.metrics):
        raise BaselineStudyError("duplicate baseline metric observation")
    if any(not isfinite(item.value) for item in build.metrics):
        raise BaselineStudyError("baseline metrics must be finite")
    if any(item.executed_operation_count is not None for item in build.conditions):
        raise BaselineStudyError("P8 controls must not claim downstream executed operations q")
    negative = tuple(
        item
        for item in build.conditions
        if item.profile_id == "NEGATIVE-CONTROL-ROUNDED-GAUSSIAN-UNIFORM-BIN-v1"
    )
    if not negative or any(item.claim_eligible or not item.exclusion_reason for item in negative):
        raise BaselineStudyError("defective temporal negative control must be claim-ineligible")
    if any(not item.evaluator_only for item in build.output_samples):
        raise BaselineStudyError("baseline output samples must remain evaluator-only")
    sample_profiles = {
        (item.scenario_id, item.replicate_id, item.profile_id) for item in build.output_samples
    }
    if sample_profiles != expected_condition_keys:
        raise BaselineStudyError("every condition must have a non-empty evaluator audit sample")
    ineligible_sampling = {
        item.profile_id
        for item in build.conditions
        if item.family == "sampling" and not item.claim_eligible
    }
    for item in build.metrics:
        if item.profile_id in ineligible_sampling and item.metric_name == "raw_relative_error":
            if item.estimator != "known_total_diagnostic_not_population_estimate_v1":
                raise BaselineStudyError(
                    f"{item.profile_id}: ineligible raw error cannot be a population estimator"
                )


def _build_replicate_conditions(
    resolved: ResolvedConfig,
    result: Any,
    registry: BaselineRegistry,
) -> tuple[tuple[BaselineProfile, tuple[dict[str, Any], ...], Mapping[str, tuple[float, float | None, float | None]], Mapping[str, Any], str, str, bool, str | None], ...]:
    components = _components(result)
    stream_by_family = {
        "temporal": _component_crn_identity(resolved, result.run_plan, "S05.arrivals"),
        "structure": _component_crn_identity(resolved, result.run_plan, BASELINE_COMPONENT),
        "anomaly": _component_crn_identity(resolved, result.run_plan, "S08.counterfactuals"),
        "observer": _component_crn_identity(resolved, result.run_plan, "S11.projections"),
        "sampling": _component_crn_identity(resolved, result.run_plan, "S12.sampling"),
    }
    _, _, temporal_rng, temporal_namespace = stream_by_family["temporal"]
    _, _, structure_rng, structure_namespace = stream_by_family["structure"]
    _, _, observer_rng, _ = stream_by_family["observer"]
    all_builds = [
        *_temporal_conditions(
            resolved, components, registry, temporal_rng, temporal_namespace
        ),
        *_structure_conditions(
            components, registry, structure_rng, structure_namespace
        ),
        *_anomaly_conditions(resolved, components, registry),
        *_observer_conditions(components, registry, observer_rng),
        *_sampling_conditions(components, registry),
    ]
    results = []
    for profile, records, metric_values, diagnostics, eligible, exclusion in all_builds:
        stream_name, group, _, _ = stream_by_family[profile.family]
        results.append(
            (
                profile,
                records,
                metric_values,
                diagnostics,
                stream_name,
                group,
                eligible,
                exclusion,
            )
        )
    return tuple(results)


def _components(result: Any) -> Mapping[str, Any]:
    try:
        through_validation = result.artifacts.through_validation
        through_sampling = through_validation.through_sampling
        through_observers = through_sampling.through_observers
        through_anomalies = through_observers.through_anomalies
        through_evidence = through_anomalies.through_evidence
        through_obligations = through_evidence.through_obligations
        through_policy = through_obligations.through_policy
        through_dag = through_policy.through_dag
    except AttributeError as exc:
        raise BaselineStudyError(
            "baseline study requires PipelineThroughMetricsResult-compatible finalized artifacts"
        ) from exc
    return {
        "world": through_dag.world,
        "catalog": through_dag.catalog,
        "physical": through_dag.physical,
        "workflows": through_dag.workflows,
        "arrivals": through_dag.arrivals,
        "dag": through_dag.causal_dag,
        "policy": through_policy.policy,
        "obligations": through_obligations.evidence_obligations,
        "receipts": through_evidence.evidence_receipts,
        "anomalies": through_anomalies.anomalies,
        "anomaly_baselines": through_anomalies.anomaly_baselines,
        "observers": through_observers.observers,
        "sampling": through_sampling.sampling,
        "run_plan": result.run_plan,
    }


def _baseline_rng(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
) -> tuple[str, str, CounterRng, str]:
    return _component_crn_identity(resolved, plan, BASELINE_COMPONENT)


def _component_crn_identity(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    component: str,
) -> tuple[str, str, CounterRng, str]:
    groups = tuple(sorted(resolved.sampling.common_random_groups))
    if not groups:
        raise BaselineStudyError("P8 comparisons require a pinned common-random-number group")
    group = groups[0]
    rows = seed_stream_records_for_plan(resolved, plan)
    suffix = f"component={component}|partition=global"
    matches = tuple(
        row
        for row in rows
        if str(row["stream_name"]).startswith(f"crn={group}|")
        and str(row["stream_name"]).endswith(suffix)
    )
    if len(matches) != 1:
        raise BaselineStudyError(
            f"CRN seed stream does not resolve uniquely component={component} group={group} "
            f"scenario={plan.scenario_id} replicate={plan.replicate_id}"
        )
    row = matches[0]
    return (
        str(row["stream_name"]),
        group,
        CounterRng(str(row["seed_material_hex"])),
        str(row["deterministic_id_namespace"]),
    )


def _temporal_conditions(
    resolved: ResolvedConfig,
    components: Mapping[str, Any],
    registry: BaselineRegistry,
    rng: CounterRng,
    namespace: str,
) -> list[tuple[Any, ...]]:
    arrival_build = components["arrivals"]
    bins = tuple(
        sorted(
            arrival_build.intensity_bins,
            key=lambda item: (item.region_id, item.event_family, item.bin_start, item.bin_index),
        )
    )
    if not bins:
        raise BaselineStudyError("temporal baselines require non-empty integrated intensity bins")
    expected = _expected_bin_counts(resolved, bins)
    profiles = [
        registry.profile("BASELINE-HOMOGENEOUS-POISSON-v1"),
        registry.profile("BASELINE-EXACT-INDEPENDENT-NHPP-v1"),
        registry.profile("NEGATIVE-CONTROL-ROUNDED-GAUSSIAN-UNIFORM-BIN-v1"),
        registry.profile("BASELINE-MMPP-2STATE-v1"),
        registry.profile("BASELINE-HAWKES-EXPONENTIAL-v1"),
        registry.profile("PROPOSED-HIERARCHICAL-ARRIVAL-MODEL-v1"),
    ]
    generated = {
        profiles[0].profile_id: _homogeneous_poisson(bins, expected, rng, namespace),
        profiles[1].profile_id: _exact_nhpp(bins, expected, rng, namespace),
        profiles[2].profile_id: _defective_gaussian_uniform(bins, expected, rng, namespace),
        profiles[3].profile_id: _mmpp(bins, expected, rng, namespace),
        profiles[4].profile_id: _hawkes(bins, expected, rng, namespace),
        profiles[5].profile_id: tuple(
            {
                "event_id": str(row["arrival_id"]),
                "timestamp": str(row["timestamp"]),
                "region_id": str(row["region_id"]),
                "event_family": str(row["event_family"]),
                "arrival_bin": int(row["arrival_bin"]),
                "regime_id": row.get("regime_id"),
                "parent_event_id": row.get("parent_arrival_id"),
                "generation_class": str(row["model_class"]),
            }
            for row in arrival_build.arrivals
        ),
    }
    result = []
    for profile in profiles:
        records = generated[profile.profile_id]
        values, diagnostics = _temporal_metrics(records, bins, expected)
        diagnostics = {
            **diagnostics,
            "source_record_count": len(arrival_build.arrivals),
            "model_semantics": profile.mechanism,
        }
        result.append(
            (
                profile,
                records,
                values,
                diagnostics,
                profile.claim_eligible,
                profile.exclusion_reason,
            )
        )
    return result


def _expected_bin_counts(resolved: ResolvedConfig, bins: Sequence[Any]) -> tuple[float, ...]:
    integrated = tuple(max(0.0, float(item.integrated_intensity)) for item in bins)
    total = fsum(integrated)
    if total <= 0:
        raise BaselineStudyError("integrated arrival exposure must be positive")
    conditioned = resolved.arrivals.conditioned_total
    if conditioned is not None:
        return tuple(float(conditioned) * value / total for value in integrated)
    return integrated


def _homogeneous_poisson(
    bins: Sequence[Any], expected: Sequence[float], rng: CounterRng, namespace: str
) -> tuple[dict[str, Any], ...]:
    durations = tuple(
        max(EPSILON, (_timestamp(item.bin_end) - _timestamp(item.bin_start)).total_seconds())
        for item in bins
    )
    total_duration = fsum(durations)
    events: list[dict[str, Any]] = []
    for index, (bin_row, duration) in enumerate(zip(bins, durations)):
        homogeneous_mean = fsum(expected) * duration / total_duration
        count = _poisson_exact(rng, "homogeneous-poisson", homogeneous_mean, index)
        for ordinal in range(count):
            fraction = rng.uniform(f"homogeneous-time:{index}", ordinal)
            events.append(
                _temporal_event(
                    namespace,
                    "homogeneous_poisson",
                    bin_row,
                    ordinal,
                    fraction,
                )
            )
    return tuple(events)


def _exact_nhpp(
    bins: Sequence[Any], expected: Sequence[float], rng: CounterRng, namespace: str
) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    for index, (bin_row, lambda_value) in enumerate(zip(bins, expected)):
        count = _poisson_exact(rng, "exact-nhpp", lambda_value, index)
        for ordinal in range(count):
            fraction = _linear_intensity_inverse(
                rng.uniform(f"exact-nhpp-time:{index}", ordinal),
                float(bin_row.intensity_start_factor),
                float(bin_row.intensity_end_factor),
            )
            events.append(
                _temporal_event(namespace, "exact_independent_nhpp", bin_row, ordinal, fraction)
            )
    return tuple(events)


def _defective_gaussian_uniform(
    bins: Sequence[Any], expected: Sequence[float], rng: CounterRng, namespace: str
) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    for index, (bin_row, lambda_value) in enumerate(zip(bins, expected)):
        z_value = _standard_normal(rng, "negative-control-gaussian", index)
        count = max(0, int(round(lambda_value + sqrt(max(0.0, lambda_value)) * z_value)))
        for ordinal in range(count):
            fraction = rng.uniform(f"negative-control-uniform-time:{index}", ordinal)
            events.append(
                _temporal_event(
                    namespace,
                    "rounded_gaussian_uniform_negative_control",
                    bin_row,
                    ordinal,
                    fraction,
                )
            )
    return tuple(events)


def _mmpp(
    bins: Sequence[Any], expected: Sequence[float], rng: CounterRng, namespace: str
) -> tuple[dict[str, Any], ...]:
    q = (0.0003, 0.0005)
    multipliers = (0.55, 1.75)
    stationary_low = q[1] / (q[0] + q[1])
    groups: dict[tuple[str, str], list[tuple[int, Any, float]]] = {}
    for index, (bin_row, lambda_value) in enumerate(zip(bins, expected)):
        groups.setdefault((bin_row.region_id, bin_row.event_family), []).append(
            (index, bin_row, lambda_value)
        )
    events: list[dict[str, Any]] = []
    for group_index, (key, group_bins) in enumerate(sorted(groups.items())):
        group_bins.sort(key=lambda item: item[1].bin_start)
        state = 0 if rng.uniform(f"mmpp-initial:{key}", group_index) < stationary_low else 1
        start = _timestamp(group_bins[0][1].bin_start)
        end = _timestamp(group_bins[-1][1].bin_end)
        regimes: list[tuple[datetime, datetime, int]] = []
        cursor = start
        transition = 0
        while cursor < end:
            u = max(EPSILON, rng.uniform(f"mmpp-holding:{key}", transition))
            holding = -log(u) / q[state]
            next_cursor = min(end, cursor + timedelta(seconds=holding))
            regimes.append((cursor, next_cursor, state))
            cursor = next_cursor
            if cursor < end:
                state = 1 - state
                transition += 1
        for bin_index, bin_row, lambda_value in group_bins:
            bin_start = _timestamp(bin_row.bin_start)
            bin_end = _timestamp(bin_row.bin_end)
            duration = max(EPSILON, (bin_end - bin_start).total_seconds())
            base_rate = lambda_value / duration
            ordinal = 0
            for regime_index, (left, right, regime_state) in enumerate(regimes):
                segment_start = max(bin_start, left)
                segment_end = min(bin_end, right)
                seconds = (segment_end - segment_start).total_seconds()
                if seconds <= 0:
                    continue
                segment_mean = base_rate * multipliers[regime_state] * seconds
                count = _poisson_exact(
                    rng,
                    f"mmpp-count:{key}:{bin_index}:{regime_index}",
                    segment_mean,
                    0,
                )
                for within in range(count):
                    u = rng.uniform(
                        f"mmpp-time:{key}:{bin_index}:{regime_index}", within
                    )
                    event_time = segment_start + timedelta(seconds=seconds * u)
                    fraction = (event_time - bin_start).total_seconds() / duration
                    row = _temporal_event(namespace, "mmpp", bin_row, ordinal, fraction)
                    row["regime_id"] = f"state-{regime_state}"
                    events.append(row)
                    ordinal += 1
    return tuple(events)


def _hawkes(
    bins: Sequence[Any], expected: Sequence[float], rng: CounterRng, namespace: str
) -> tuple[dict[str, Any], ...]:
    branching_ratio = 0.2
    beta = 0.001
    alpha = branching_ratio * beta
    groups: dict[tuple[str, str], list[tuple[int, Any, float]]] = {}
    for index, (bin_row, lambda_value) in enumerate(zip(bins, expected)):
        groups.setdefault((bin_row.region_id, bin_row.event_family), []).append(
            (index, bin_row, lambda_value)
        )
    events: list[dict[str, Any]] = []
    for group_key, group_bins in sorted(groups.items()):
        group_bins.sort(key=lambda item: item[1].bin_start)
        accepted_times: list[datetime] = []
        accepted_ids: list[str] = []
        parent_weights: list[float] = []
        cumulative_parent_weights: list[float] = []
        weight_base_time = _timestamp(group_bins[0][1].bin_start)
        excitation = 0.0
        excitation_time = weight_base_time
        proposal_index = 0
        for bin_index, bin_row, lambda_value in group_bins:
            bin_start = _timestamp(bin_row.bin_start)
            bin_end = _timestamp(bin_row.bin_end)
            duration = max(EPSILON, (bin_end - bin_start).total_seconds())
            immigrant_rate = lambda_value * (1.0 - branching_ratio) / duration
            excitation *= exp(-beta * max(0.0, (bin_start - excitation_time).total_seconds()))
            excitation_time = bin_start
            cursor = bin_start
            ordinal = 0
            while cursor < bin_end:
                upper = immigrant_rate + excitation
                if upper <= 0:
                    break
                waiting_u = max(
                    EPSILON,
                    rng.uniform(f"hawkes-wait:{group_key}", proposal_index),
                )
                candidate = cursor + timedelta(seconds=-log(waiting_u) / upper)
                if candidate >= bin_end:
                    excitation *= exp(
                        -beta * max(0.0, (bin_end - excitation_time).total_seconds())
                    )
                    excitation_time = bin_end
                    proposal_index += 1
                    break
                excitation *= exp(
                    -beta * max(0.0, (candidate - excitation_time).total_seconds())
                )
                excitation_time = candidate
                actual = immigrant_rate + excitation
                accepted = (
                    rng.uniform(f"hawkes-accept:{group_key}", proposal_index) * upper
                    <= actual
                )
                cursor = candidate
                if accepted:
                    fraction = (candidate - bin_start).total_seconds() / duration
                    row = _temporal_event(namespace, "hawkes", bin_row, ordinal, fraction)
                    if excitation > 0 and accepted_ids:
                        parent_probability = excitation / actual
                        if rng.uniform(f"hawkes-parent-class:{group_key}", proposal_index) < parent_probability:
                            parent_id = _weighted_parent_id(
                                accepted_times,
                                accepted_ids,
                                parent_weights,
                                cumulative_parent_weights,
                                candidate,
                                beta,
                                weight_base_time,
                                rng,
                                f"hawkes-parent:{group_key}",
                                proposal_index,
                            )
                            row["parent_event_id"] = parent_id
                    events.append(row)
                    if beta * (candidate - weight_base_time).total_seconds() > 600.0:
                        factor = exp(-beta * (candidate - weight_base_time).total_seconds())
                        parent_weights[:] = [value * factor for value in parent_weights]
                        cumulative_parent_weights[:] = _cumulative(parent_weights)
                        weight_base_time = candidate
                    new_weight = exp(beta * (candidate - weight_base_time).total_seconds())
                    parent_weights.append(new_weight)
                    cumulative_parent_weights.append(
                        new_weight
                        + (cumulative_parent_weights[-1] if cumulative_parent_weights else 0.0)
                    )
                    accepted_times.append(candidate)
                    accepted_ids.append(str(row["event_id"]))
                    excitation += alpha
                    ordinal += 1
                proposal_index += 1
    return tuple(events)


def _weighted_parent_id(
    times: Sequence[datetime],
    ids: Sequence[str],
    weights: Sequence[float],
    cumulative: Sequence[float],
    candidate: datetime,
    beta: float,
    base_time: datetime,
    rng: CounterRng,
    label: str,
    index: int,
) -> str:
    del times, candidate, beta, base_time
    if not ids or not weights or not cumulative or cumulative[-1] <= 0:
        raise BaselineStudyError("Hawkes parent selection requires positive history weights")
    cut = rng.uniform(label, index) * cumulative[-1]
    return ids[min(bisect_left(cumulative, cut), len(ids) - 1)]


def _cumulative(values: Sequence[float]) -> list[float]:
    result: list[float] = []
    running = 0.0
    for value in values:
        running += value
        result.append(running)
    return result


def _temporal_event(
    namespace: str,
    generation_class: str,
    bin_row: Any,
    ordinal: int,
    fraction: float,
) -> dict[str, Any]:
    start = _timestamp(bin_row.bin_start)
    end = _timestamp(bin_row.bin_end)
    bounded = max(0.0, min(1.0 - 1e-15, fraction))
    timestamp = start + timedelta(seconds=(end - start).total_seconds() * bounded)
    event_id = deterministic_uuid(
        namespace,
        "baseline_temporal_event",
        {
            "bin": int(bin_row.bin_index),
            "class": generation_class,
            "family": str(bin_row.event_family),
            "ordinal": ordinal,
            "region": str(bin_row.region_id),
        },
    )
    return {
        "event_id": event_id,
        "timestamp": _format_timestamp(timestamp),
        "region_id": str(bin_row.region_id),
        "event_family": str(bin_row.event_family),
        "arrival_bin": int(bin_row.bin_index),
        "regime_id": None,
        "parent_event_id": None,
        "generation_class": generation_class,
    }


def _temporal_metrics(
    records: Sequence[Mapping[str, Any]],
    bins: Sequence[Any],
    expected: Sequence[float],
) -> tuple[Mapping[str, tuple[float, float | None, float | None]], Mapping[str, Any]]:
    key_to_index = {
        (str(item.region_id), str(item.event_family), int(item.bin_index)): index
        for index, item in enumerate(bins)
    }
    counts = [0 for _ in bins]
    for row in records:
        key = (str(row["region_id"]), str(row["event_family"]), int(row["arrival_bin"]))
        if key not in key_to_index:
            raise BaselineStudyError(f"temporal comparator emitted unknown intensity bin {key}")
        counts[key_to_index[key]] += 1
    observed_total = len(records)
    expected_total = fsum(expected)
    count_ratio = observed_total / expected_total if expected_total else 0.0
    count_mean = mean(counts) if counts else 0.0
    dispersion = (pstdev(counts) ** 2 / count_mean) if count_mean > 0 else 0.0
    deviance = 0.0
    for observed, expected_value in zip(counts, expected):
        if expected_value <= 0:
            deviance += float("inf") if observed else 0.0
        elif observed:
            deviance += 2.0 * (observed * log(observed / expected_value) - (observed - expected_value))
        else:
            deviance += 2.0 * expected_value
    transformed = _transformed_positions(records, bins, expected)
    ks = _ks_uniform(transformed)
    values = {
        "count_mean_ratio": (float(count_ratio), float(observed_total), float(expected_total)),
        "dispersion_index": (float(dispersion), None, float(len(counts))),
        "bin_deviance": (float(deviance), None, float(len(counts))),
        "time_rescaling_ks": (float(ks), None, float(len(transformed))),
    }
    diagnostics = {
        "bin_count": len(bins),
        "expected_count": expected_total,
        "observed_count": observed_total,
        "parented_event_count": sum(row.get("parent_event_id") is not None for row in records),
        "regime_event_count": sum(row.get("regime_id") is not None for row in records),
    }
    return values, diagnostics


def _transformed_positions(
    records: Sequence[Mapping[str, Any]], bins: Sequence[Any], expected: Sequence[float]
) -> list[float]:
    ordered_bins = sorted(
        enumerate(bins),
        key=lambda pair: (pair[1].bin_start, pair[1].region_id, pair[1].event_family),
    )
    cumulative: dict[tuple[str, str, int], float] = {}
    running = 0.0
    for index, item in ordered_bins:
        cumulative[(item.region_id, item.event_family, item.bin_index)] = running
        running += expected[index]
    if running <= 0:
        return []
    bins_by_key = {
        (item.region_id, item.event_family, item.bin_index): (index, item)
        for index, item in enumerate(bins)
    }
    result: list[float] = []
    for row in sorted(records, key=lambda item: (str(item["timestamp"]), str(item["event_id"]))):
        key = (str(row["region_id"]), str(row["event_family"]), int(row["arrival_bin"]))
        index, bin_row = bins_by_key[key]
        start = _timestamp(bin_row.bin_start)
        end = _timestamp(bin_row.bin_end)
        fraction = (_timestamp(str(row["timestamp"])) - start).total_seconds() / max(
            EPSILON, (end - start).total_seconds()
        )
        x = max(0.0, min(1.0, fraction))
        y0 = max(EPSILON, float(bin_row.intensity_start_factor))
        y1 = max(EPSILON, float(bin_row.intensity_end_factor))
        normalized_mass = (y0 * x + 0.5 * (y1 - y0) * x * x) / ((y0 + y1) / 2.0)
        result.append((cumulative[key] + expected[index] * normalized_mass) / running)
    return result


def _ks_uniform(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    size = len(ordered)
    return max(
        max(abs(index / size - value), abs((index - 1) / size - value))
        for index, value in enumerate(ordered, start=1)
    )


def _poisson_exact(rng: CounterRng, label: str, lambda_value: float, index: int) -> int:
    if not isfinite(lambda_value) or lambda_value < 0:
        raise BaselineStudyError(f"{label}: Poisson expectation must be finite and non-negative")
    if lambda_value == 0:
        return 0
    if lambda_value > MAX_EXACT_POISSON_EXPECTATION:
        raise BaselineStudyError(
            f"{label}: exact Poisson expectation {lambda_value:.3f} exceeds "
            f"{MAX_EXACT_POISSON_EXPECTATION:.0f}; use conditioned materialization"
        )
    count = 0
    elapsed = 0.0
    draw_index = 0
    while True:
        u = max(EPSILON, rng.uniform(f"{label}:poisson-wait", index * 1_000_003 + draw_index))
        elapsed += -log(u)
        if elapsed > lambda_value:
            return count
        count += 1
        draw_index += 1


def _standard_normal(rng: CounterRng, label: str, index: int) -> float:
    u1 = max(EPSILON, rng.uniform(f"{label}:box-muller-u1", index))
    u2 = rng.uniform(f"{label}:box-muller-u2", index)
    return sqrt(-2.0 * log(u1)) * cos(2.0 * pi * u2)


def _linear_intensity_inverse(u: float, start_factor: float, end_factor: float) -> float:
    y0 = max(EPSILON, start_factor)
    y1 = max(EPSILON, end_factor)
    if abs(y1 - y0) <= 1e-12:
        return u
    slope = y1 - y0
    target = u * (y0 + y1) / 2.0
    discriminant = max(0.0, y0 * y0 + 2.0 * slope * target)
    return max(0.0, min(1.0, (-y0 + sqrt(discriminant)) / slope))


def _structure_conditions(
    components: Mapping[str, Any],
    registry: BaselineRegistry,
    rng: CounterRng,
    namespace: str,
) -> list[tuple[Any, ...]]:
    dag = components["dag"]
    world = components["world"]
    catalog = components["catalog"]
    policy_rows = tuple(components["policy"].policy_decisions)
    obligation_rows = tuple(components["obligations"].evidence_obligations)
    source_events = tuple(dict(row) for row in dag.governance_events)
    if not source_events:
        raise BaselineStudyError("structure baselines require governance events")
    profiles = [
        registry.profile("BASELINE-UNIFORM-IID-RECORD-v1"),
        registry.profile("BASELINE-GENERIC-PROCESS-LOG-v1"),
        registry.profile("BASELINE-RELATIONAL-SEQUENTIAL-SYNTHESIZER-v1"),
        registry.profile("ABLATION-NO-CUSTODY-v1"),
        registry.profile("ABLATION-NO-CAUSAL-CLOSURE-v1"),
        registry.profile("ABLATION-NO-TOPOLOGY-v1"),
        registry.profile("ABLATION-NO-POLICY-v1"),
        registry.profile("ABLATION-NO-EVIDENCE-v1"),
        registry.profile("PROPOSED-GOVERNANCE-COMPLETE-STRUCTURE-v1"),
    ]
    iid_events = _iid_governance_events(source_events, rng, namespace)
    relational_events = _relational_sequential_events(source_events, rng)
    process_rows = tuple(
        {
            "case_id": str(row["workflow_instance_id"]),
            "activity": str(row["event_type"]),
            "timestamp": str(row["timestamp"]),
            "sequence_index": int(row["workflow_step_index"]),
        }
        for row in sorted(
            source_events,
            key=lambda item: (
                str(item["workflow_instance_id"]),
                int(item["workflow_step_index"]),
                str(item["event_id"]),
            ),
        )
    )
    full = {
        "events": source_events,
        "edges": tuple(dag.event_edges),
        "actors": tuple(world.actors),
        "relationships": tuple(world.actor_relationships),
        "network_areas": tuple(world.network_areas),
        "databases": tuple(catalog.local_databases),
        "objects": tuple(catalog.data_objects),
        "replicas": tuple(catalog.data_object_replicas),
        "policy": policy_rows,
        "obligations": obligation_rows,
        "workflow_instances": tuple(dag.workflow_instances),
    }
    configurations: dict[str, tuple[tuple[dict[str, Any], ...], dict[str, Any]]] = {
        profiles[0].profile_id: (iid_events, {**full, "events": iid_events, "edges": (), "actors": (), "relationships": (), "network_areas": (), "databases": (), "objects": (), "replicas": (), "policy": (), "obligations": ()}),
        profiles[1].profile_id: (process_rows, {**full, "events": source_events, "edges": (), "actors": (), "relationships": (), "network_areas": (), "databases": (), "objects": (), "replicas": (), "policy": (), "obligations": ()}),
        profiles[2].profile_id: (relational_events, {**full, "events": relational_events}),
        profiles[3].profile_id: (_event_layer_rows(source_events, "custody", False), {**full, "databases": (), "objects": (), "replicas": ()}),
        profiles[4].profile_id: (_event_layer_rows(source_events, "dependencies", False), {**full, "edges": ()}),
        profiles[5].profile_id: (_event_layer_rows(source_events, "topology", False), {**full, "relationships": (), "network_areas": ()}),
        profiles[6].profile_id: (_event_layer_rows(source_events, "policy_trace", False), {**full, "policy": ()}),
        profiles[7].profile_id: (_event_layer_rows(source_events, "evidence", False), {**full, "obligations": ()}),
        profiles[8].profile_id: (_event_layer_rows(source_events, "governance_complete", True), full),
    }
    results = []
    for profile in profiles:
        records, state = configurations[profile.profile_id]
        values, diagnostics = _structure_metrics(state, full)
        diagnostics = {
            **diagnostics,
            "source_record_count": len(source_events),
            "condition_record_type": "generic_process_event" if profile == profiles[1] else "governance_comparison_record",
        }
        results.append((profile, records, values, diagnostics, profile.claim_eligible, profile.exclusion_reason))
    return results


def _iid_governance_events(
    events: Sequence[Mapping[str, Any]], rng: CounterRng, namespace: str
) -> tuple[dict[str, Any], ...]:
    contract = load_contract()
    fields = contract.table("governance_event").field_names
    supports = {field: tuple(row[field] for row in events) for field in fields}
    rows: list[dict[str, Any]] = []
    for row_index in range(len(events)):
        row = {
            field: supports[field][
                rng.randint(f"iid-field:{field}", row_index, 0, len(events) - 1)
            ]
            for field in fields
        }
        row["event_id"] = deterministic_uuid(
            namespace,
            "iid_governance_event",
            {"ordinal": row_index, "source_count": len(events)},
        )
        validate_record(contract, "governance_event", row)
        rows.append(row)
    return tuple(rows)


def _relational_sequential_events(
    events: Sequence[Mapping[str, Any]], rng: CounterRng
) -> tuple[dict[str, Any], ...]:
    fields = (
        "source_actor_id", "requesting_actor_id", "controller_actor_id",
        "processor_actor_id", "oversight_actor_id", "local_database_id", "data_object_id",
    )
    supports = {field: tuple(row[field] for row in events) for field in fields}
    contract = load_contract()
    rows: list[dict[str, Any]] = []
    for row_index, source in enumerate(events):
        row = dict(source)
        for field in fields:
            row[field] = supports[field][
                rng.randint(f"relational-sequential:{field}", row_index, 0, len(events) - 1)
            ]
        validate_record(contract, "governance_event", row)
        rows.append(row)
    return tuple(rows)


def _event_layer_rows(
    events: Sequence[Mapping[str, Any]], layer: str, present: bool
) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "event_id": str(row["event_id"]),
            "workflow_instance_id": str(row["workflow_instance_id"]),
            "layer": layer,
            "layer_present": present,
        }
        for row in events
    )


def _structure_metrics(
    state: Mapping[str, Any], source: Mapping[str, Any]
) -> tuple[Mapping[str, tuple[float, float | None, float | None]], Mapping[str, Any]]:
    events = tuple(state["events"])
    database_by_id = {str(row["database_id"]): row for row in state["databases"]}
    object_by_id = {str(row["data_object_id"]): row for row in state["objects"]}
    actor_ids = {str(row["actor_id"]) for row in state["actors"]}
    custody_pass = 0
    topology_pass = 0
    for row in events:
        database_id = str(row["local_database_id"])
        object_row = object_by_id.get(str(row["data_object_id"]))
        if database_id in database_by_id and object_row is not None and str(object_row["origin_database_id"]) == database_id:
            custody_pass += 1
        actor_fields = (
            "source_actor_id", "requesting_actor_id", "controller_actor_id",
            "processor_actor_id", "oversight_actor_id",
        )
        if (
            state["relationships"]
            and state["network_areas"]
            and all(row[field] is None or str(row[field]) in actor_ids for field in actor_fields)
        ):
            topology_pass += 1
    event_denominator = max(1, len(events))
    source_edge_count = len(source["edges"])
    policy_count = len(state["policy"])
    source_policy_count = len(source["policy"])
    obligation_count = len(state["obligations"])
    source_obligation_count = len(source["obligations"])
    transition_count, conformant = _transition_conformance(events, state["workflow_instances"])
    values = {
        "custody_reference_coverage": (custody_pass / event_denominator, float(custody_pass), float(len(events))),
        "causal_edge_coverage": (
            len(state["edges"]) / source_edge_count if source_edge_count else 1.0,
            float(len(state["edges"])),
            float(source_edge_count),
        ),
        "topology_reference_coverage": (topology_pass / event_denominator, float(topology_pass), float(len(events))),
        "policy_trace_coverage": (
            policy_count / source_policy_count if source_policy_count else 1.0,
            float(policy_count),
            float(source_policy_count),
        ),
        "evidence_obligation_coverage": (
            obligation_count / source_obligation_count if source_obligation_count else 1.0,
            float(obligation_count),
            float(source_obligation_count),
        ),
        "transition_conformance_rate": (
            conformant / transition_count if transition_count else 0.0,
            float(conformant),
            float(transition_count),
        ),
    }
    return values, {
        "event_count": len(events),
        "edge_count": len(state["edges"]),
        "database_count": len(state["databases"]),
        "object_count": len(state["objects"]),
        "replica_count": len(state["replicas"]),
        "policy_decision_count": policy_count,
        "obligation_count": obligation_count,
        "transition_count": transition_count,
    }


def _transition_conformance(
    events: Sequence[Mapping[str, Any]], workflow_instances: Sequence[Mapping[str, Any]]
) -> tuple[int, int]:
    workflow_type = {
        str(row["workflow_instance_id"]): str(row["workflow_type"])
        for row in workflow_instances
    }
    definitions = workflow_definitions()
    total = 0
    passed = 0
    for row in events:
        definition = definitions.get(workflow_type.get(str(row["workflow_instance_id"]), ""))
        total += 1
        if definition is None:
            continue
        legal = {
            (item.event_type, item.state_before, item.state_after)
            for item in definition.transitions
        }
        passed += (
            str(row["event_type"]),
            str(row["workflow_state_before"]),
            str(row["workflow_state_after"]),
        ) in legal
    return total, passed


def _anomaly_conditions(
    resolved: ResolvedConfig,
    components: Mapping[str, Any],
    registry: BaselineRegistry,
) -> list[tuple[Any, ...]]:
    anomaly_build = components["anomalies"]
    baseline_build = components["anomaly_baselines"]
    profiles = [
        registry.profile(RANDOM_FIELD_PROFILE),
        registry.profile(RANDOM_TRANSITION_PROFILE),
        registry.profile("PROPOSED-MINIMAL-COUNTERFACTUAL-v1"),
    ]
    result = []
    configured_protected = set(resolved.anomaly.protected_invariant_ids) | {
        "INV-SCHEMA-CONFORMANT",
        "INV-PHYSICAL-CONTEXT-UNCHANGED",
    }
    for profile in profiles[:2]:
        cases = tuple(case for case in baseline_build.cases if case.profile_id == profile.profile_id)
        if not cases:
            raise BaselineStudyError(f"anomaly baseline {profile.profile_id} is empty")
        target_id = str(profile.parameters["target_invariant"])
        successes = sum(target_id in case.failed_invariant_ids for case in cases)
        collateral = sum(
            any(item in configured_protected for item in case.failed_invariant_ids)
            for case in cases
        )
        failed_count = sum(len(case.failed_invariant_ids) for case in cases)
        records = tuple(
            {
                "profile_id": case.profile_id,
                "source_workflow_id": case.source_workflow_id,
                "changed_field_paths": list(case.changed_field_paths),
                "failed_invariant_ids": list(case.failed_invariant_ids),
                "source_trace_digest": case.source_trace_digest,
            }
            for case in cases
        )
        values = {
            "target_violation_success": (successes / len(cases), float(successes), float(len(cases))),
            "collateral_violation_rate": (collateral / len(cases), float(collateral), float(len(cases))),
            "mean_failed_invariant_count": (failed_count / len(cases), float(failed_count), float(len(cases))),
        }
        result.append(
            (
                profile,
                records,
                values,
                {"source_record_count": len(cases), "case_count": len(cases), "target_invariant_id": target_id},
                profile.claim_eligible,
                profile.exclusion_reason,
            )
        )
    proposed = profiles[2]
    pairs = tuple(anomaly_build.counterfactual_pairs)
    comparison_source = "authoritative_S08_counterfactual_pairs"
    if not pairs:
        from htgl_dataset_generator.anomalies import build_minimal_counterfactual_comparison

        plan = components["run_plan"]
        comparison_build = build_minimal_counterfactual_comparison(
            resolved,
            world=components["world"],
            catalog=components["catalog"],
            physical=components["physical"],
            workflows=components["workflows"],
            causal_dag=components["dag"],
            policy=components["policy"],
            obligations=components["obligations"],
            receipts=components["receipts"],
            anomaly_types=("unauthorized_purpose",),
            episodes_per_type=1,
            replicate_id=plan.replicate_id,
            scenario_ids=(plan.scenario_id,),
        )
        pairs = tuple(comparison_build.counterfactual_pairs)
        comparison_source = "evaluator_only_P8_bounded_production_S08_search"
    if not pairs:
        raise BaselineStudyError("minimal counterfactual comparator is empty")
    target_success = sum(
        any(
            item.invariant_id == pair.target_invariant_id and item.status == "fail"
            for item in pair.invalid_invariant_outcomes
        )
        for pair in pairs
    )
    collateral = sum(
        any(
            item.status == "fail" and item.invariant_id in set(pair.preserved_invariant_ids)
            for item in pair.invalid_invariant_outcomes
        )
        for pair in pairs
    )
    failed_count = sum(
        sum(item.status == "fail" for item in pair.invalid_invariant_outcomes)
        for pair in pairs
    )
    records = tuple(
        {
            "anomaly_type": pair.anomaly_type,
            "target_invariant_id": pair.target_invariant_id,
            "changed_field_paths": list(
                pair.edit.primitive_changed_field_paths
                + pair.edit.derived_changed_field_paths
            ),
            "edit_cost": pair.edit.cost,
            "minimality_proven_within_bound": pair.search_diagnostics.minimality_proven_within_bound,
        }
        for pair in pairs
    )
    values = {
        "target_violation_success": (target_success / len(pairs), float(target_success), float(len(pairs))),
        "collateral_violation_rate": (collateral / len(pairs), float(collateral), float(len(pairs))),
        "mean_failed_invariant_count": (failed_count / len(pairs), float(failed_count), float(len(pairs))),
    }
    result.append(
        (
            proposed,
            records,
            values,
            {"source_record_count": len(pairs), "accepted_pair_count": len(pairs), "protected_pair_ids_exported": False, "comparison_source": comparison_source},
            proposed.claim_eligible,
            proposed.exclusion_reason,
        )
    )
    return result


def _observer_conditions(
    components: Mapping[str, Any], registry: BaselineRegistry, rng: CounterRng
) -> list[tuple[Any, ...]]:
    events = tuple(components["dag"].governance_events)
    if not events:
        raise BaselineStudyError("observer controls require source events")
    event_ids = {str(row["event_id"]) for row in events}
    obligation_event_ids = {
        str(row["event_id"])
        for row in components["obligations"].evidence_obligations
    }
    anomaly_event_ids = {
        str(event["event_id"])
        for pair in components["anomalies"].counterfactual_pairs
        for event in pair.invalid_trace.events
        if str(event["event_id"]) in event_ids
    }
    profiles = [
        registry.profile("BASELINE-FULL-CENTRAL-LOG-v1"),
        registry.profile("BASELINE-INDEPENDENT-RANDOM-DROPOUT-v1"),
        registry.profile("ABLATION-NO-OBSERVER-PROJECTION-v1"),
        registry.profile("PROPOSED-OBSERVER-PROJECTION-DSL-v1"),
    ]
    result = []
    full_records = tuple(
        {"event_id": str(row["event_id"]), "visible": True, "omission_reason": None, "delay_seconds": 0}
        for row in events
    )
    full_values = _observer_metric_values(
        event_ids, event_ids, obligation_event_ids, anomaly_event_ids, (), 0
    )
    for profile in (profiles[0], profiles[2]):
        result.append(
            (
                profile,
                full_records,
                full_values,
                {"source_record_count": len(events), "visible_event_count": len(events), "release_class": "evaluator_only"},
                profile.claim_eligible,
                profile.exclusion_reason,
            )
        )
    dropout_probability = float(profiles[1].parameters["dropout_probability"])
    visible = {
        event_id
        for event_id in sorted(event_ids)
        if rng.uniform(f"observer-independent-dropout:{event_id}", 0) >= dropout_probability
    }
    dropout_records = tuple(
        {
            "event_id": event_id,
            "visible": event_id in visible,
            "omission_reason": None if event_id in visible else "independent_random_dropout",
            "delay_seconds": 0,
        }
        for event_id in sorted(event_ids)
    )
    result.append(
        (
            profiles[1],
            dropout_records,
            _observer_metric_values(event_ids, visible, obligation_event_ids, anomaly_event_ids, (), 0),
            {"source_record_count": len(events), "visible_event_count": len(visible), "dropout_probability": dropout_probability, "release_class": "evaluator_only"},
            profiles[1].claim_eligible,
            profiles[1].exclusion_reason,
        )
    )
    observer_build = components["observers"]
    diagnostics = tuple(observer_build.diagnostics.values())
    source_total = sum(item.source_event_count for item in diagnostics)
    visible_total = sum(item.visible_event_count for item in diagnostics)
    proposed_records = tuple(
        {
            "observer_record_id": str(row["observer_record_id"]),
            "projection_profile_id": str(row["projection_profile_id"]),
            "source_event_id": str(row["source_event_id"]),
            "visibility_class": str(row["visibility_class"]),
            "omission_reason": row["omission_reason"],
        }
        for row in observer_build.observer_events
    )
    if not proposed_records or source_total <= 0:
        raise BaselineStudyError("proposed observer projection output is empty")
    proposed_values = {
        "visible_event_coverage": (
            sum(item.weighted_visible_event_coverage * item.source_event_count for item in diagnostics) / source_total,
            float(visible_total),
            float(source_total),
        ),
        "evidence_recoverability": (
            sum(item.evidence_recoverability * item.source_event_count for item in diagnostics) / source_total,
            None,
            float(source_total),
        ),
        "anomaly_event_recoverability": (
            sum(item.anomaly_event_recoverability * item.source_event_count for item in diagnostics) / source_total,
            None,
            float(source_total),
        ),
        "mean_delay_seconds": (
            sum(item.mean_delay_seconds * item.visible_event_count for item in diagnostics) / max(1, visible_total),
            None,
            float(visible_total),
        ),
        "omission_rate": (
            sum(item.overall_omission_rate * item.source_event_count for item in diagnostics) / source_total,
            float(source_total - visible_total),
            float(source_total),
        ),
        "sealed_truth_leakage": (
            float(observer_build.leakage_diagnostics.sealed_truth_leakage_count),
            float(observer_build.leakage_diagnostics.sealed_truth_leakage_count),
            float(observer_build.leakage_diagnostics.scanned_record_count),
        ),
    }
    result.append(
        (
            profiles[3],
            proposed_records,
            proposed_values,
            {"source_record_count": len(events), "projection_record_count": len(proposed_records), "profile_count": len(diagnostics), "release_class": "sanitized_profile_outputs_plus_evaluator_mapping_separation"},
            profiles[3].claim_eligible,
            profiles[3].exclusion_reason,
        )
    )
    return result


def _observer_metric_values(
    source_ids: set[str],
    visible_ids: set[str],
    obligation_ids: set[str],
    anomaly_ids: set[str],
    delays: Sequence[float],
    leakage_count: int,
) -> Mapping[str, tuple[float, float | None, float | None]]:
    source_count = len(source_ids)
    omitted = source_count - len(visible_ids)
    obligation_visible = len(obligation_ids & visible_ids)
    anomaly_visible = len(anomaly_ids & visible_ids)
    return {
        "visible_event_coverage": (len(visible_ids) / source_count, float(len(visible_ids)), float(source_count)),
        "evidence_recoverability": (
            obligation_visible / len(obligation_ids) if obligation_ids else 1.0,
            float(obligation_visible),
            float(len(obligation_ids)),
        ),
        "anomaly_event_recoverability": (
            anomaly_visible / len(anomaly_ids) if anomaly_ids else 1.0,
            float(anomaly_visible),
            float(len(anomaly_ids)),
        ),
        "mean_delay_seconds": (mean(delays) if delays else 0.0, None, float(len(delays))),
        "omission_rate": (omitted / source_count, float(omitted), float(source_count)),
        "sealed_truth_leakage": (float(leakage_count), float(leakage_count), float(source_count)),
    }


def _sampling_conditions(
    components: Mapping[str, Any], registry: BaselineRegistry
) -> list[tuple[Any, ...]]:
    sampling = components["sampling"]
    profiles = [
        registry.profile("BASELINE-FIRST-N-TRUNCATION"),
        registry.profile("BASELINE-SIMPLE-RANDOM-EVENT-ROWS"),
        registry.profile("BASELINE-UNWEIGHTED-WORKFLOW"),
        registry.profile("ABLATION-NO-SAMPLING-WEIGHTS-v1"),
        registry.profile("PROPOSED-DEPENDENCY-CLOSED-PROBABILITY-DESIGN-v1"),
    ]
    baseline_by_id: dict[str, list[Any]] = {}
    for item in sampling.baselines:
        baseline_by_id.setdefault(item.baseline_id, []).append(item)
    result = []
    for profile in profiles[:3]:
        cases = tuple(baseline_by_id.get(profile.profile_id, ()))
        if not cases:
            raise BaselineStudyError(f"sampling baseline {profile.profile_id} is empty")
        raw_error = mean([float(item.raw_relative_error) for item in cases])
        selected = sum(int(item.selected_unit_count) for item in cases)
        records = tuple(asdict(item) for item in cases)
        values = {
            "raw_relative_error": (raw_error, None, float(len(cases))),
            "estimator_eligibility_rate": (0.0, 0.0, float(len(cases))),
            "closure_expansion_factor": (0.0, None, float(len(cases))),
            "effective_sample_size": (0.0, 0.0, float(selected)),
        }
        result.append(
            (
                profile,
                records,
                values,
                {"source_record_count": len(sampling.sample_memberships), "case_count": len(cases), "population_estimate_emitted": False},
                False,
                profile.exclusion_reason,
            )
        )
    unweighted_cases = tuple(baseline_by_id.get("BASELINE-UNWEIGHTED-WORKFLOW", ()))
    ablation = profiles[3]
    ablation_records = tuple(
        {
            "sample_design_id": str(row["sample_design_id"]),
            "unit_id": str(row["unit_id"]),
            "unit_type": str(row["unit_type"]),
            "selected": True,
            "first_order_inclusion_probability": None,
            "design_weight": None,
            "analysis_weight": None,
            "estimator_eligible": False,
        }
        for row in sampling.sample_memberships
    )
    ablation_error = mean([float(item.raw_relative_error) for item in unweighted_cases])
    result.append(
        (
            ablation,
            ablation_records,
            {
                "raw_relative_error": (ablation_error, None, float(len(unweighted_cases))),
                "estimator_eligibility_rate": (0.0, 0.0, float(len(ablation_records))),
                "closure_expansion_factor": (
                    mean([item.closure_expansion_factor for item in sampling.diagnostics.values()]),
                    None,
                    float(len(sampling.diagnostics)),
                ),
                "effective_sample_size": (0.0, 0.0, float(len(ablation_records))),
            },
            {"source_record_count": len(sampling.sample_memberships), "selected_unit_count": len(ablation_records), "population_estimate_emitted": False},
            False,
            ablation.exclusion_reason,
        )
    )
    proposed = profiles[4]
    memberships = tuple(sampling.sample_memberships)
    diagnostics = tuple(sampling.diagnostics.values())
    known = tuple(sampling.known_total_diagnostics)
    if not memberships or not diagnostics or not known:
        raise BaselineStudyError("proposed probability sampling outputs are incomplete")
    eligible_count = sum(bool(row["estimator_eligible"]) for row in memberships)
    actual_errors = [
        (item.actual_estimate - item.truth_total) / item.truth_total
        for item in known
        if item.truth_total != 0
    ]
    if not actual_errors:
        raise BaselineStudyError("proposed sampling has no non-zero known-total diagnostic")
    proposed_eligible = eligible_count == len(memberships)
    result.append(
        (
            proposed,
            tuple(
                {
                    "sample_design_id": str(row["sample_design_id"]),
                    "unit_id": str(row["unit_id"]),
                    "unit_type": str(row["unit_type"]),
                    "first_order_inclusion_probability": float(row["first_order_inclusion_probability"]),
                    "design_weight": float(row["design_weight"]),
                    "selection_reason": str(row["selection_reason"]),
                    "estimator_eligible": bool(row["estimator_eligible"]),
                }
                for row in memberships
            ),
            {
                "raw_relative_error": (mean(actual_errors), None, float(len(actual_errors))),
                "estimator_eligibility_rate": (eligible_count / len(memberships), float(eligible_count), float(len(memberships))),
                "closure_expansion_factor": (mean([item.closure_expansion_factor for item in diagnostics]), None, float(len(diagnostics))),
                "effective_sample_size": (mean([item.effective_sample_size for item in diagnostics]), None, float(len(diagnostics))),
            },
            {"source_record_count": len(memberships), "membership_count": len(memberships), "known_total_diagnostic_count": len(known), "population_estimate_emitted": proposed_eligible},
            proposed.claim_eligible and proposed_eligible,
            None if proposed_eligible else "One or more sample memberships are estimator-ineligible; population estimates are blocked.",
        )
    )
    return result


def _condition_output(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    registry: BaselineRegistry,
    profile: BaselineProfile,
    records: Sequence[Mapping[str, Any]],
    diagnostics: Mapping[str, Any],
    stream_name: str,
    group: str,
    *,
    claim_eligible: bool,
    exclusion_reason: str | None,
    source_record_count: int,
) -> BaselineConditionOutput:
    digest_records = tuple(records) or ({"empty_realization": True, "profile_id": profile.profile_id},)
    output_digest = canonical_records_digest(digest_records)
    return BaselineConditionOutput(
        condition_output_id=content_id(
            "baseline_condition_output",
            {
                "config_sha256": resolved.config_sha256,
                "output_digest": output_digest,
                "profile_id": profile.profile_id,
                "replicate_id": plan.replicate_id,
                "scenario_id": plan.scenario_id,
            },
        ),
        run_id=plan.run_id,
        scenario_id=plan.scenario_id,
        replicate_id=plan.replicate_id,
        profile_id=profile.profile_id,
        family=profile.family,
        role=profile.role,
        mechanism=profile.mechanism,
        common_random_group=group,
        seed_stream_name=stream_name,
        registry_id=registry.registry_id,
        registry_version=registry.version,
        registry_sha256=registry.sha256,
        represented_population=resolved.claim_scale.represented_population,
        materialized_row_budget=resolved.claim_scale.materialized_row_target,
        executed_operation_count=None,
        source_record_count=source_record_count,
        output_record_count=len(records),
        output_digest=output_digest,
        claim_eligible=claim_eligible,
        exclusion_reason=exclusion_reason,
        parameters_json=_canonical_json(profile.parameters),
        diagnostics_json=_canonical_json(diagnostics),
    )


def _metric_observations(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    profile: BaselineProfile,
    values: Mapping[str, tuple[float, float | None, float | None]],
    group: str,
    *,
    claim_eligible: bool,
) -> tuple[BaselineMetricObservation, ...]:
    expected = set(profile.required_metrics)
    if set(values) != expected:
        raise BaselineStudyError(
            f"profile={profile.profile_id}: metric implementation mismatch "
            f"missing={sorted(expected-set(values))} extra={sorted(set(values)-expected)}"
        )
    rows = []
    for metric_name in profile.required_metrics:
        value, numerator, denominator = values[metric_name]
        unit, estimator, weighting = METRIC_CONTRACTS[profile.family][metric_name]
        if profile.family == "sampling" and not claim_eligible and metric_name == "raw_relative_error":
            estimator = "known_total_diagnostic_not_population_estimate_v1"
        rows.append(
            BaselineMetricObservation(
                metric_observation_id=content_id(
                    "baseline_metric_observation",
                    {
                        "metric_name": metric_name,
                        "profile_id": profile.profile_id,
                        "replicate_id": plan.replicate_id,
                        "scenario_id": plan.scenario_id,
                    },
                ),
                run_id=plan.run_id,
                scenario_id=plan.scenario_id,
                replicate_id=plan.replicate_id,
                profile_id=profile.profile_id,
                family=profile.family,
                role=profile.role,
                metric_name=metric_name,
                value=float(value),
                unit=unit,
                numerator=None if numerator is None else float(numerator),
                denominator=None if denominator is None else float(denominator),
                estimator=estimator,
                weighting=weighting,
                common_random_group=group,
                claim_eligible=claim_eligible,
                uncertainty_status="replicate_observation",
                uncertainty_reason="paired uncertainty is computed only across independent full-pipeline replicates",
            )
        )
    return tuple(rows)


def _output_samples(
    resolved: ResolvedConfig,
    plan: ResolvedRunPlan,
    profile: BaselineProfile,
    records: Sequence[Mapping[str, Any]],
    diagnostics: Mapping[str, Any],
) -> tuple[BaselineOutputSample, ...]:
    selected = tuple(records[:SAMPLE_ROWS_PER_CONDITION])
    output_type = "condition_record"
    if not selected:
        selected = ({"empty_stochastic_realization": True, "diagnostics": diagnostics},)
        output_type = "empty_realization_diagnostic"
    return tuple(
        BaselineOutputSample(
            sample_id=content_id(
                "baseline_output_sample",
                {
                    "ordinal": index,
                    "profile_id": profile.profile_id,
                    "replicate_id": plan.replicate_id,
                    "scenario_id": plan.scenario_id,
                },
            ),
            run_id=plan.run_id,
            scenario_id=plan.scenario_id,
            replicate_id=plan.replicate_id,
            profile_id=profile.profile_id,
            family=profile.family,
            output_type=output_type,
            ordinal=index,
            record_json=_canonical_json(record),
            evaluator_only=True,
        )
        for index, record in enumerate(selected)
    )


def build_baseline_paired_comparisons(
    resolved: ResolvedConfig,
    metrics: Sequence[BaselineMetricObservation],
    results: Sequence[Any],
) -> tuple[BaselinePairedComparison, ...]:
    by_scenario: dict[str, list[BaselineMetricObservation]] = {}
    for item in metrics:
        by_scenario.setdefault(item.scenario_id, []).append(item)
    comparisons: list[BaselinePairedComparison] = []
    for scenario_id, scenario_metrics in sorted(by_scenario.items()):
        index = {
            (item.profile_id, item.metric_name, item.replicate_id): item
            for item in scenario_metrics
        }
        profiles = {item.profile_id: item for item in scenario_metrics}
        families = {item.family for item in scenario_metrics}
        for family in sorted(families):
            proposed_id = PROPOSED_BY_FAMILY[family]
            comparator_ids = sorted(
                profile_id
                for profile_id, item in profiles.items()
                if item.family == family and profile_id != proposed_id
            )
            metric_names = tuple(METRIC_CONTRACTS[family])
            for comparator_id in comparator_ids:
                comparator_role = profiles[comparator_id].role
                for metric_name in metric_names:
                    paired_ids = tuple(
                        replicate_id
                        for replicate_id in range(resolved.run.replicate_count)
                        if (comparator_id, metric_name, replicate_id) in index
                        and (proposed_id, metric_name, replicate_id) in index
                    )
                    if not paired_ids:
                        raise BaselineStudyError(
                            f"no CRN pairs for {scenario_id}/{comparator_id}/{metric_name}"
                        )
                    differences = [
                        index[(proposed_id, metric_name, replicate_id)].value
                        - index[(comparator_id, metric_name, replicate_id)].value
                        for replicate_id in paired_ids
                    ]
                    group_values = {
                        index[(profile_id, metric_name, replicate_id)].common_random_group
                        for profile_id in (proposed_id, comparator_id)
                        for replicate_id in paired_ids
                    }
                    if len(group_values) != 1:
                        raise BaselineStudyError("paired baseline conditions use different CRN groups")
                    group = next(iter(group_values))
                    confidence = 1.0 - resolved.validation.alpha
                    if len(differences) >= 2:
                        rng = _comparison_rng(resolved, scenario_id, group, results)
                        lower, upper = deterministic_percentile_interval(
                            differences,
                            confidence_level=confidence,
                            rng=rng,
                            label=f"P8:{scenario_id}:{family}:{comparator_id}:{metric_name}",
                            repetitions=BOOTSTRAP_REPETITIONS,
                        )
                        standard_error = empirical_standard_error(differences)
                        difference_sd = stdev(differences)
                        effect = mean(differences) / difference_sd if difference_sd > 0 else (0.0 if abs(mean(differences)) <= 1e-15 else None)
                        method = f"paired_deterministic_percentile_bootstrap_{BOOTSTRAP_REPETITIONS}_v1"
                        status = "estimated"
                        reason = "paired by pinned common-random-number group and independent full-pipeline replicate ID"
                    else:
                        standard_error = lower = upper = effect = None
                        method = "not_estimated"
                        status = "insufficient_pairs"
                        reason = "at least two independent full-pipeline replicate pairs are required for uncertainty and effect size"
                    unit = index[(proposed_id, metric_name, paired_ids[0])].unit
                    comparisons.append(
                        BaselinePairedComparison(
                            comparison_id=content_id(
                                "baseline_paired_comparison",
                                {
                                    "comparator": comparator_id,
                                    "metric": metric_name,
                                    "paired_replicates": paired_ids,
                                    "proposed": proposed_id,
                                    "scenario_id": scenario_id,
                                },
                            ),
                            run_id=resolved.run.run_id,
                            scenario_id=scenario_id,
                            family=family,
                            metric_name=metric_name,
                            unit=unit,
                            common_random_group=group,
                            comparator_profile_id=comparator_id,
                            proposed_profile_id=proposed_id,
                            comparator_role=comparator_role,
                            paired_replicate_ids=paired_ids,
                            pair_count=len(paired_ids),
                            mean_difference=mean(differences),
                            empirical_standard_error=standard_error,
                            ci_lower=lower,
                            ci_upper=upper,
                            standardized_effect_size=effect,
                            confidence_level=confidence,
                            uncertainty_method=method,
                            status=status,
                            reason=reason,
                        )
                    )
    return tuple(sorted(comparisons, key=lambda item: item.comparison_id))


def _comparison_rng(
    resolved: ResolvedConfig,
    scenario_id: str,
    group: str,
    results: Sequence[Any],
) -> CounterRng:
    result = next(
        item
        for item in results
        if item.run_plan.scenario_id == scenario_id and item.run_plan.replicate_id == 0
    )
    _, observed_group, rng, _ = _baseline_rng(resolved, result.run_plan)
    if observed_group != group:
        raise BaselineStudyError("comparison CRN group does not match P8 stream")
    return rng


def _run_plans(resolved: ResolvedConfig) -> tuple[ResolvedRunPlan, ...]:
    return tuple(
        ResolvedRunPlan(
            run_id=resolved.run.run_id,
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            config_sha256=resolved.config_sha256,
        )
        for scenario_id in resolved.run.selected_scenario_ids
        for replicate_id in range(resolved.run.replicate_count)
    )


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
