"""Defective sampling controls kept separate from S12 probability truth."""

from __future__ import annotations

from htgl_dataset_generator.sampling.models import (
    DependencyClosure,
    ProbabilityDesignResult,
    SamplingBaselineResult,
)
from htgl_dataset_generator.seeds import CounterRng


def build_sampling_baselines(
    closure: DependencyClosure,
    actual_design: ProbabilityDesignResult,
    *,
    rng: CounterRng,
    target_size: int,
) -> tuple[SamplingBaselineResult, ...]:
    """Evaluate controls without granting estimator eligibility or population claims."""

    primary = tuple(sorted(closure.primary_units, key=lambda item: item.key.unit_id))
    truth = sum(item.represented_value for item in primary)
    draw_count = min(max(1, target_size), len(primary))
    first = primary[:draw_count]
    first_estimate = len(primary) * sum(item.represented_value for item in first) / len(first)

    selected = tuple(
        item
        for item in primary
        if item.key.unit_id in set(actual_design.selected_primary_unit_ids)
    )
    unweighted_estimate = sum(item.represented_value for item in selected)
    analytic_estimate = (
        len(primary) / len(selected) * unweighted_estimate if selected else 0.0
    )

    event_population = tuple(
        item
        for key, item in sorted(closure.population_units.items())
        if key.unit_type == "event"
    )
    event_draw_count = min(draw_count, len(event_population))
    ranked_events = sorted(
        event_population,
        key=lambda item: (
            rng.uint64(f"sampling-baseline:event-row:{item.key.unit_id}", 0),
            item.key.unit_id,
        ),
    )
    event_truth = sum(item.represented_value for item in event_population)
    event_estimate = (
        len(event_population)
        * sum(item.represented_value for item in ranked_events[:event_draw_count])
        / event_draw_count
        if event_draw_count
        else 0.0
    )
    return (
        _result(
            "BASELINE-FIRST-N-TRUNCATION",
            closure,
            len(first),
            first_estimate,
            truth,
            "deterministic first-n selection has no positive probability design",
        ),
        _result(
            "BASELINE-SIMPLE-RANDOM-EVENT-ROWS",
            closure,
            event_draw_count,
            event_estimate,
            event_truth,
            "event-row SRS breaks workflow, causal, replica, and evidence closure",
        ),
        _result(
            "BASELINE-UNWEIGHTED-WORKFLOW",
            closure,
            len(selected),
            unweighted_estimate,
            truth,
            "unweighted selected workflows cannot estimate represented totals",
        ),
        _result(
            "BASELINE-POSTHOC-ANALYTIC-WEIGHT",
            closure,
            len(selected),
            analytic_estimate,
            truth,
            "post-hoc N/n weighting is not a recorded probability design",
        ),
    )


def _result(
    baseline_id: str,
    closure: DependencyClosure,
    count: int,
    estimate: float,
    truth: float,
    reason: str,
) -> SamplingBaselineResult:
    relative_error = (estimate - truth) / truth if truth else 0.0
    return SamplingBaselineResult(
        baseline_id=baseline_id,
        scenario_id=closure.scenario_id,
        primary_unit_type=closure.primary_unit_type,
        selected_unit_count=count,
        raw_relative_error=relative_error,
        estimator_eligible=False,
        exclusion_reason=reason,
    )
