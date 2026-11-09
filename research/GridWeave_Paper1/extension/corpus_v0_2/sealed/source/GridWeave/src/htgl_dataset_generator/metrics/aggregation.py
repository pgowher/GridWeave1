"""Cross-replicate uncertainty and common-random-number paired comparisons."""

from __future__ import annotations

from collections import defaultdict
import math
from statistics import mean, stdev
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.seeds import CounterRng, content_id, seed_stream_records_for_plan

from .models import (
    MetricConditionSeries,
    MetricObservationProvenance,
    MetricsBuild,
    PairedMetricComparison,
    ReplicateMetricAggregate,
)
from .statistics import deterministic_percentile_interval, empirical_standard_error


BOOTSTRAP_REPETITIONS = 2000


class MetricAggregationError(ValueError):
    """Raised when replicate or CRN comparison contracts do not reconcile."""


def aggregate_replicate_metrics(
    builds: Iterable[MetricsBuild],
    resolved: ResolvedConfig,
) -> tuple[ReplicateMetricAggregate, ...]:
    """Aggregate matching per-replicate observations with deterministic uncertainty."""

    items = tuple(builds)
    if not items:
        raise MetricAggregationError("replicate aggregation requires at least one MetricsBuild")
    registry_digests = {item.registry.sha256 for item in items}
    if len(registry_digests) != 1:
        raise MetricAggregationError("replicate metrics use different registry versions")
    expected_replicates = set(range(resolved.run.replicate_count))
    groups: dict[tuple[str, str, str, str | None], list[tuple[dict[str, Any], MetricObservationProvenance]]] = defaultdict(list)
    for build in items:
        provenance = {item.metric_id: item for item in build.provenance}
        for row in build.run_metrics:
            item = provenance[str(row["metric_id"])]
            groups[(str(row["scenario_id"]), item.metric_key, item.scope_id, item.baseline_id)].append((row, item))
    results: list[ReplicateMetricAggregate] = []
    for key, observations in sorted(groups.items(), key=lambda pair: tuple("" if value is None else value for value in pair[0])):
        scenario_id, metric_key, scope_id, baseline_id = key
        observations.sort(key=lambda pair: int(pair[0]["replicate_id"]))
        rows = [pair[0] for pair in observations]
        replicate_ids = tuple(int(row["replicate_id"]) for row in rows)
        if len(replicate_ids) != len(set(replicate_ids)):
            raise MetricAggregationError(f"{metric_key}/{scope_id}: duplicate replicate observations")
        for field in ("metric_domain", "unit", "estimator", "weighting"):
            if len({str(row[field]) for row in rows}) != 1:
                raise MetricAggregationError(f"{metric_key}/{scope_id}: {field} differs across replicates")
        values = [float(row["value"]) for row in rows]
        confidence = 1.0 - resolved.validation.alpha
        complete = set(replicate_ids) == expected_replicates
        if len(values) >= 2:
            rng = _aggregation_rng(resolved, scenario_id)
            lower, upper = deterministic_percentile_interval(
                values,
                confidence_level=confidence,
                rng=rng,
                label=f"aggregate:{metric_key}:{scope_id}:{baseline_id or 'none'}",
                repetitions=BOOTSTRAP_REPETITIONS,
            )
            standard_error = empirical_standard_error(values)
            method = f"deterministic_percentile_bootstrap_{BOOTSTRAP_REPETITIONS}_v1"
            status = "estimated" if complete else "incomplete_replicate_set"
            reason = (
                "uncertainty uses every configured independent full-pipeline replicate"
                if complete
                else f"available replicates={replicate_ids}; expected={tuple(sorted(expected_replicates))}"
            )
        else:
            standard_error = lower = upper = None
            method = "not_estimated"
            status = "insufficient_replicates"
            reason = "at least two independent full-pipeline replicates are required"
        results.append(
            ReplicateMetricAggregate(
                aggregate_id=content_id(
                    "replicate_metric_aggregate",
                    {
                        "baseline_id": baseline_id,
                        "metric_key": metric_key,
                        "registry_sha256": next(iter(registry_digests)),
                        "replicate_ids": replicate_ids,
                        "run_id": str(rows[0]["run_id"]),
                        "scenario_id": scenario_id,
                        "scope_id": scope_id,
                    },
                ),
                run_id=str(rows[0]["run_id"]),
                scenario_id=scenario_id,
                metric_key=metric_key,
                metric_domain=str(rows[0]["metric_domain"]),
                scope_id=scope_id,
                baseline_id=baseline_id,
                unit=str(rows[0]["unit"]),
                estimator=str(rows[0]["estimator"]),
                weighting=str(rows[0]["weighting"]),
                replicate_ids=replicate_ids,
                replicate_count=len(replicate_ids),
                mean_value=mean(values),
                empirical_standard_error=standard_error,
                ci_lower=lower,
                ci_upper=upper,
                confidence_level=confidence,
                uncertainty_method=method,
                uncertainty_status=status,
                uncertainty_reason=reason,
            )
        )
    _validate_aggregates(results)
    return tuple(results)


def build_paired_crn_comparisons(
    baseline: MetricConditionSeries,
    treatments: Iterable[MetricConditionSeries],
    resolved: ResolvedConfig,
) -> tuple[PairedMetricComparison, ...]:
    """Build paired baseline/treatment or baseline/ablation comparisons by replicate."""

    if baseline.condition_role != "baseline":
        raise MetricAggregationError("paired comparison baseline must have condition_role='baseline'")
    if not baseline.common_random_group:
        raise MetricAggregationError("paired comparison requires a non-empty common-random-number group")
    baseline_index = _condition_index(baseline)
    comparisons: list[PairedMetricComparison] = []
    expected_replicates = set(range(resolved.run.replicate_count))
    for treatment in treatments:
        if treatment.condition_role not in {"treatment", "ablation"}:
            raise MetricAggregationError("comparison conditions must be treatment or ablation")
        if treatment.common_random_group != baseline.common_random_group:
            raise MetricAggregationError(
                f"condition={treatment.condition_id}: CRN group differs from baseline"
            )
        treatment_index = _condition_index(treatment)
        common_keys = sorted(set(baseline_index) & set(treatment_index))
        for metric_key, scope_id in common_keys:
            baseline_rows = baseline_index[(metric_key, scope_id)]
            treatment_rows = treatment_index[(metric_key, scope_id)]
            paired_ids = tuple(sorted(set(baseline_rows) & set(treatment_rows)))
            if not paired_ids:
                continue
            left = [baseline_rows[replicate_id][0] for replicate_id in paired_ids]
            right = [treatment_rows[replicate_id][0] for replicate_id in paired_ids]
            for field in ("metric_domain", "unit", "estimator", "weighting"):
                if len({str(row[field]) for row in (*left, *right)}) != 1:
                    raise MetricAggregationError(
                        f"{metric_key}/{scope_id}: paired {field} contract differs"
                    )
            differences = [float(treat["value"]) - float(base["value"]) for base, treat in zip(left, right)]
            confidence = 1.0 - resolved.validation.alpha
            complete = set(paired_ids) == expected_replicates
            if len(differences) >= 2:
                rng = _aggregation_rng(
                    resolved,
                    str(right[0]["scenario_id"]),
                    common_random_group=baseline.common_random_group,
                )
                lower, upper = deterministic_percentile_interval(
                    differences,
                    confidence_level=confidence,
                    rng=rng,
                    label=(
                        f"paired:{baseline.common_random_group}:{baseline.condition_id}:"
                        f"{treatment.condition_id}:{metric_key}:{scope_id}"
                    ),
                    repetitions=BOOTSTRAP_REPETITIONS,
                )
                standard_error = empirical_standard_error(differences)
                difference_sd = stdev(differences)
                if difference_sd > 0:
                    effect = mean(differences) / difference_sd
                    effect_reason = "paired_cohen_dz"
                elif math.isclose(mean(differences), 0.0, abs_tol=1e-15):
                    effect = 0.0
                    effect_reason = "paired_cohen_dz_zero_difference"
                else:
                    effect = None
                    effect_reason = "paired_cohen_dz_undefined_zero_difference_variance"
                status = "estimated" if complete else "incomplete_pair_set"
                reason = (
                    "paired by common-random-number group and replicate ID"
                    if complete
                    else f"paired replicates={paired_ids}; expected={tuple(sorted(expected_replicates))}"
                )
                method = f"paired_deterministic_percentile_bootstrap_{BOOTSTRAP_REPETITIONS}_v1"
            else:
                standard_error = lower = upper = effect = None
                effect_reason = "not_estimable_from_one_pair"
                status = "insufficient_pairs"
                reason = "paired uncertainty and effect size require at least two paired replicates"
                method = "not_estimated"
            comparisons.append(
                PairedMetricComparison(
                    comparison_id=content_id(
                        "paired_metric_comparison",
                        {
                            "baseline": baseline.condition_id,
                            "crn_group": baseline.common_random_group,
                            "metric_key": metric_key,
                            "paired_replicates": paired_ids,
                            "scope_id": scope_id,
                            "treatment": treatment.condition_id,
                        },
                    ),
                    metric_key=metric_key,
                    metric_domain=str(right[0]["metric_domain"]),
                    scope_id=scope_id,
                    unit=str(right[0]["unit"]),
                    estimator=str(right[0]["estimator"]),
                    weighting=str(right[0]["weighting"]),
                    common_random_group=baseline.common_random_group,
                    baseline_condition_id=baseline.condition_id,
                    treatment_condition_id=treatment.condition_id,
                    treatment_role=treatment.condition_role,
                    paired_replicate_ids=paired_ids,
                    pair_count=len(paired_ids),
                    mean_difference=mean(differences),
                    empirical_standard_error=standard_error,
                    ci_lower=lower,
                    ci_upper=upper,
                    standardized_effect_size=effect,
                    effect_size_method=effect_reason,
                    confidence_level=confidence,
                    uncertainty_method=method,
                    status=status,
                    reason=reason,
                )
            )
    return tuple(sorted(comparisons, key=lambda item: item.comparison_id))


def _condition_index(
    condition: MetricConditionSeries,
) -> Mapping[tuple[str, str], Mapping[int, tuple[dict[str, Any], MetricObservationProvenance]]]:
    provenance = {item.metric_id: item for item in condition.provenance}
    if set(provenance) != {str(row["metric_id"]) for row in condition.metrics}:
        raise MetricAggregationError(
            f"condition={condition.condition_id}: metrics/provenance do not reconcile"
        )
    result: dict[tuple[str, str], dict[int, tuple[dict[str, Any], MetricObservationProvenance]]] = defaultdict(dict)
    for row in condition.metrics:
        item = provenance[str(row["metric_id"])]
        replicate_id = int(row["replicate_id"])
        key = (item.metric_key, item.scope_id)
        if replicate_id in result[key]:
            raise MetricAggregationError(
                f"condition={condition.condition_id}: duplicate metric/scope/replicate {key}/{replicate_id}"
            )
        result[key][replicate_id] = (row, item)
    return result


def _aggregation_rng(
    resolved: ResolvedConfig,
    scenario_id: str,
    *,
    common_random_group: str | None = None,
) -> CounterRng:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=0,
        config_sha256=resolved.config_sha256,
    )
    rows = seed_stream_records_for_plan(resolved, plan)
    prefix = (
        f"crn={common_random_group}|"
        if common_random_group is not None
        else f"scenario={scenario_id}|"
    )
    matches = tuple(
        row for row in rows
        if str(row["stream_name"]).startswith(prefix)
        and str(row["stream_name"]).endswith("component=S14.metrics|partition=global")
    )
    if len(matches) != 1:
        raise MetricAggregationError("S14 named seed stream does not resolve uniquely")
    return CounterRng(str(matches[0]["seed_material_hex"]))


def _validate_aggregates(rows: Sequence[ReplicateMetricAggregate]) -> None:
    ids: set[str] = set()
    for row in rows:
        if row.aggregate_id in ids:
            raise MetricAggregationError(f"duplicate aggregate_id={row.aggregate_id}")
        ids.add(row.aggregate_id)
        if row.replicate_count != len(row.replicate_ids):
            raise MetricAggregationError(f"aggregate_id={row.aggregate_id}: replicate count mismatch")
        if row.replicate_ids != tuple(sorted(set(row.replicate_ids))):
            raise MetricAggregationError(f"aggregate_id={row.aggregate_id}: invalid replicate set")
        if (row.ci_lower is None) != (row.ci_upper is None):
            raise MetricAggregationError(f"aggregate_id={row.aggregate_id}: partial CI")
