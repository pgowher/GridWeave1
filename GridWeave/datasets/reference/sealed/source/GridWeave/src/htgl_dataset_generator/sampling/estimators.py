"""Design-gated Horvitz-Thompson and Hajek estimators."""

from __future__ import annotations

import math
from typing import Iterable, Mapping


class EstimatorEligibilityError(ValueError):
    """Raised when an estimate is requested without valid probability semantics."""


def horvitz_thompson_total(
    sampled_values: Iterable[tuple[float, float]],
    *,
    estimator_eligible: bool,
) -> float:
    """Estimate a finite-population total from values and first-order probabilities."""

    values = tuple(sampled_values)
    _validate(values, estimator_eligible)
    return sum(value / probability for value, probability in values)


def hajek_total(
    sampled_values: Iterable[tuple[float, float]],
    *,
    population_unit_count: int,
    estimator_eligible: bool,
) -> float:
    """Estimate a total as population size times the Hajek ratio mean."""

    values = tuple(sampled_values)
    _validate(values, estimator_eligible)
    if population_unit_count <= 0:
        raise EstimatorEligibilityError("Hajek estimator requires positive population_unit_count")
    denominator = sum(1.0 / probability for _, probability in values)
    if denominator <= 0 or not math.isfinite(denominator):
        raise EstimatorEligibilityError("Hajek denominator is not positive and finite")
    numerator = sum(value / probability for value, probability in values)
    return population_unit_count * numerator / denominator


def estimate_total(
    estimator_family: str,
    sampled_values: Iterable[tuple[float, float]],
    *,
    population_unit_count: int,
    estimator_eligible: bool,
) -> float:
    if estimator_family == "Horvitz_Thompson":
        return horvitz_thompson_total(
            sampled_values, estimator_eligible=estimator_eligible
        )
    if estimator_family == "Hajek":
        return hajek_total(
            sampled_values,
            population_unit_count=population_unit_count,
            estimator_eligible=estimator_eligible,
        )
    raise EstimatorEligibilityError(
        f"unsupported estimator_family={estimator_family!r}"
    )


def effective_sample_size(probabilities: Iterable[float]) -> float:
    weights = tuple(1.0 / probability for probability in probabilities)
    if not weights:
        return 0.0
    denominator = sum(weight * weight for weight in weights)
    return (sum(weights) ** 2) / denominator if denominator else 0.0


def _validate(
    values: tuple[tuple[float, float], ...], estimator_eligible: bool
) -> None:
    if not estimator_eligible:
        raise EstimatorEligibilityError(
            "population estimate prohibited because estimator_eligible=false"
        )
    if not values:
        raise EstimatorEligibilityError("population estimate requires sampled units")
    for index, (value, probability) in enumerate(values):
        if not math.isfinite(value):
            raise EstimatorEligibilityError(f"sample value[{index}] is not finite")
        if not math.isfinite(probability) or not (0.0 < probability <= 1.0):
            raise EstimatorEligibilityError(
                f"sample probability[{index}]={probability} is outside (0, 1]"
            )


def values_from_membership(
    memberships: Iterable[Mapping[str, object]],
    population_values: Mapping[tuple[str, str], float],
) -> tuple[tuple[float, float], ...]:
    result: list[tuple[float, float]] = []
    for row in memberships:
        key = (str(row["unit_type"]), str(row["unit_id"]))
        if key not in population_values:
            raise EstimatorEligibilityError(f"membership unit does not resolve: {key}")
        result.append(
            (
                float(population_values[key]),
                float(row["first_order_inclusion_probability"]),
            )
        )
    return tuple(result)
