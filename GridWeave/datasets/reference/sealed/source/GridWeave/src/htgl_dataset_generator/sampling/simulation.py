"""Repeated-design known-total proof for probability and closure semantics."""

from __future__ import annotations

import hashlib
import math
from statistics import NormalDist
from typing import Iterable, Mapping

from htgl_dataset_generator.seeds import CounterRng

from .designs import draw_probability_design, induced_inclusion_probability
from .estimators import estimate_total
from .models import (
    DependencyClosure,
    KnownTotalDiagnostic,
    ProbabilityDesignResult,
    UnitKey,
)


class SamplingSimulationError(ValueError):
    """Raised when repeated-design validation cannot establish estimator quality."""


def run_known_total_simulation(
    closure: DependencyClosure,
    *,
    sample_design_id: str,
    simulation_draw_label: str,
    design_type: str,
    target_size: int,
    estimator_family: str,
    actual_result: ProbabilityDesignResult,
    rng: CounterRng,
    repetitions: int,
    confidence_level: float,
    maximum_absolute_relative_bias: float,
    minimum_ci_coverage: float,
    use_crn_keys: bool,
) -> tuple[KnownTotalDiagnostic, ...]:
    """Re-draw the declared design and recover known primary/event totals."""

    if repetitions < 100:
        raise SamplingSimulationError("known-total proof requires at least 100 repetitions")
    primary_by_id = {item.key.unit_id: item for item in closure.primary_units}
    event_population = {
        key: item
        for key, item in closure.population_units.items()
        if key.unit_type == "event"
    }
    domains = {
        "primary_represented_total": (
            sum(item.represented_value for item in closure.primary_units),
            len(closure.primary_units),
        ),
        "primary_contrast_total": (
            sum(_primary_contrast_value(item) for item in closure.primary_units),
            len(closure.primary_units),
        ),
        "event_represented_total": (
            sum(item.represented_value for item in event_population.values()),
            len(event_population),
        ),
    }
    if any(count <= 0 or total <= 0 for total, count in domains.values()):
        raise SamplingSimulationError("known-total domains must be positive and non-empty")
    estimates: dict[str, list[float]] = {name: [] for name in domains}
    for repetition in range(repetitions):
        result = draw_probability_design(
            closure.primary_units,
            design_type=design_type,
            target_size=target_size,
            rng=rng,
            draw_label=f"simulation:{simulation_draw_label}:repetition={repetition:06d}",
            use_crn_keys=use_crn_keys,
        )
        selected = set(result.selected_primary_unit_ids)
        primary_values = tuple(
            (
                primary_by_id[unit_id].represented_value,
                result.primary_inclusion_probabilities[unit_id],
            )
            for unit_id in sorted(selected)
        )
        estimates["primary_represented_total"].append(
            estimate_total(
                estimator_family,
                primary_values,
                population_unit_count=len(closure.primary_units),
                estimator_eligible=result.exact_inclusion_probabilities,
            )
        )
        contrast_values = tuple(
            (
                _primary_contrast_value(primary_by_id[unit_id]),
                result.primary_inclusion_probabilities[unit_id],
            )
            for unit_id in sorted(selected)
        )
        estimates["primary_contrast_total"].append(
            estimate_total(
                estimator_family,
                contrast_values,
                population_unit_count=len(closure.primary_units),
                estimator_eligible=result.exact_inclusion_probabilities,
            )
        )
        selected_members = _selected_members(closure, selected)
        event_values = tuple(
            (
                event_population[key].represented_value,
                induced_inclusion_probability(
                    result, closure.causes_by_member[key], primary_by_id
                ),
            )
            for key in sorted(selected_members)
            if key in event_population
        )
        estimates["event_represented_total"].append(
            estimate_total(
                estimator_family,
                event_values,
                population_unit_count=len(event_population),
                estimator_eligible=result.exact_inclusion_probabilities,
            )
        )

    actual_estimates = _actual_estimates(
        closure, actual_result, estimator_family, primary_by_id, event_population
    )
    z_value = NormalDist().inv_cdf(0.5 + confidence_level / 2.0)
    diagnostics: list[KnownTotalDiagnostic] = []
    for domain, values in sorted(estimates.items()):
        truth, _ = domains[domain]
        mean = sum(values) / len(values)
        variance = (
            sum((value - mean) ** 2 for value in values) / (len(values) - 1)
            if len(values) > 1
            else 0.0
        )
        standard_deviation = math.sqrt(max(0.0, variance))
        relative_bias = (mean - truth) / truth
        relative_rmse = math.sqrt(
            sum((value - truth) ** 2 for value in values) / len(values)
        ) / truth
        if standard_deviation == 0.0:
            coverage = 1.0 if all(abs(value - truth) <= 1e-12 for value in values) else 0.0
        else:
            half_width = z_value * standard_deviation
            coverage = sum(
                value - half_width <= truth <= value + half_width for value in values
            ) / len(values)
        passed = (
            abs(relative_bias) <= maximum_absolute_relative_bias
            and coverage >= minimum_ci_coverage
        )
        diagnostics.append(
            KnownTotalDiagnostic(
                sample_design_id=sample_design_id,
                analysis_domain=domain,
                estimator_family=estimator_family,
                repetitions=repetitions,
                truth_total=truth,
                actual_estimate=actual_estimates[domain],
                mean_estimate=mean,
                empirical_standard_deviation=standard_deviation,
                relative_bias=relative_bias,
                relative_rmse=relative_rmse,
                ci_coverage=coverage,
                confidence_level=confidence_level,
                passed=passed,
            )
        )
    return tuple(diagnostics)


def _actual_estimates(
    closure: DependencyClosure,
    result: ProbabilityDesignResult,
    estimator_family: str,
    primary_by_id: Mapping[str, object],
    event_population: Mapping[UnitKey, object],
) -> Mapping[str, float]:
    selected = set(result.selected_primary_unit_ids)
    primary_values = tuple(
        (
            float(getattr(primary_by_id[unit_id], "represented_value")),
            result.primary_inclusion_probabilities[unit_id],
        )
        for unit_id in sorted(selected)
    )
    selected_members = _selected_members(closure, selected)
    event_values = tuple(
        (
            float(getattr(event_population[key], "represented_value")),
            induced_inclusion_probability(result, closure.causes_by_member[key], primary_by_id),
        )
        for key in sorted(selected_members)
        if key in event_population
    )
    return {
        "primary_represented_total": estimate_total(
            estimator_family,
            primary_values,
            population_unit_count=len(closure.primary_units),
            estimator_eligible=result.exact_inclusion_probabilities,
        ),
        "primary_contrast_total": estimate_total(
            estimator_family,
            tuple(
                (
                    _primary_contrast_value(primary_by_id[unit_id]),
                    result.primary_inclusion_probabilities[unit_id],
                )
                for unit_id in sorted(selected)
            ),
            population_unit_count=len(closure.primary_units),
            estimator_eligible=result.exact_inclusion_probabilities,
        ),
        "event_represented_total": estimate_total(
            estimator_family,
            event_values,
            population_unit_count=len(event_population),
            estimator_eligible=result.exact_inclusion_probabilities,
        ),
    }


def _primary_contrast_value(primary: object) -> float:
    crn_key = str(getattr(primary, "crn_key"))
    represented_value = float(getattr(primary, "represented_value"))
    bucket = int.from_bytes(
        hashlib.sha256(crn_key.encode("utf-8")).digest()[:2], "big"
    ) % 7
    return represented_value * (1.0 + bucket / 10.0)


def _selected_members(
    closure: DependencyClosure, selected_primary_ids: Iterable[str]
) -> set[UnitKey]:
    members: set[UnitKey] = set()
    for primary_id in sorted(selected_primary_ids):
        members.update(closure.members_by_primary[primary_id])
    return members
