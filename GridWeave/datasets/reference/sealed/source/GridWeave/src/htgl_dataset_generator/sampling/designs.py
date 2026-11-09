"""Exact first-order probability designs and closure-induced probabilities."""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
import math
from typing import Mapping, Sequence

from htgl_dataset_generator.seeds import CounterRng

from .models import PrimaryUnit, ProbabilityDesignResult


class ProbabilityDesignError(ValueError):
    """Raised when a declared probability design cannot preserve positive support."""


def draw_probability_design(
    primary_units: Sequence[PrimaryUnit],
    *,
    design_type: str,
    target_size: int,
    rng: CounterRng,
    draw_label: str,
    use_crn_keys: bool = False,
) -> ProbabilityDesignResult:
    """Draw one probability sample without depending on input order."""

    units = tuple(sorted(primary_units, key=lambda item: item.key.unit_id))
    if not units:
        raise ProbabilityDesignError("probability design requires at least one primary unit")
    if target_size <= 0:
        raise ProbabilityDesignError("target_size must be positive")
    if len({item.key.unit_id for item in units}) != len(units):
        raise ProbabilityDesignError("primary unit IDs must be unique")
    if design_type == "census" or target_size >= len(units):
        return _census(units, design_type)
    if design_type == "stratified":
        return _stratified(units, target_size, rng, draw_label, use_crn_keys)
    if design_type in {"cluster", "nested_common_random_numbers"}:
        return _global_srs(
            units,
            target_size,
            rng,
            draw_label,
            use_crn_keys=design_type == "nested_common_random_numbers" or use_crn_keys,
            design_type=design_type,
        )
    if design_type == "PPS":
        return _pps_with_replacement(units, target_size, rng, draw_label)
    raise ProbabilityDesignError(f"unsupported design_type={design_type!r}")


def induced_inclusion_probability(
    result: ProbabilityDesignResult,
    causing_primary_unit_ids: Sequence[str],
    primary_by_id: Mapping[str, PrimaryUnit],
) -> float:
    """Return exact probability that at least one causing primary unit is drawn."""

    causes = tuple(sorted(set(causing_primary_unit_ids)))
    if not causes:
        raise ProbabilityDesignError("closure member has no eligible causing primary units")
    unknown = sorted(set(causes) - set(primary_by_id))
    if unknown:
        raise ProbabilityDesignError(f"closure causes contain unknown primary IDs {unknown[:3]}")
    if result.design_type == "census" or all(
        result.primary_inclusion_probabilities[item] == 1.0 for item in causes
    ):
        return 1.0
    if result.design_type == "PPS" and result.pps_draw_count > 0:
        single_draw_mass = sum(result.pps_single_draw_probabilities[item] for item in causes)
        return _bounded_probability(1.0 - (1.0 - single_draw_mass) ** result.pps_draw_count)
    if result.design_type == "stratified":
        causes_by_stratum: dict[str, int] = defaultdict(int)
        for unit_id in causes:
            causes_by_stratum[primary_by_id[unit_id].stratum_id] += 1
        none_probability = 1.0
        for stratum_id, population_count in result.stratum_population_counts.items():
            cause_count = causes_by_stratum.get(stratum_id, 0)
            sample_count = result.stratum_sample_counts[stratum_id]
            none_probability *= _srs_none_probability(
                population_count, cause_count, sample_count
            )
        return _bounded_probability(1.0 - none_probability)
    population_count = sum(result.stratum_population_counts.values())
    sample_count = sum(result.stratum_sample_counts.values())
    return _bounded_probability(
        1.0 - _srs_none_probability(population_count, len(causes), sample_count)
    )


def _census(
    units: Sequence[PrimaryUnit], declared_design_type: str
) -> ProbabilityDesignResult:
    strata = _stratum_population_counts(units)
    return ProbabilityDesignResult(
        design_type="census" if declared_design_type == "census" else declared_design_type,
        target_size=len(units),
        selected_primary_unit_ids=tuple(item.key.unit_id for item in units),
        primary_inclusion_probabilities={item.key.unit_id: 1.0 for item in units},
        stratum_population_counts=strata,
        stratum_sample_counts=strata,
        pps_single_draw_probabilities={},
        pps_draw_count=0,
        exact_inclusion_probabilities=True,
    )


def _stratified(
    units: Sequence[PrimaryUnit],
    target_size: int,
    rng: CounterRng,
    label: str,
    use_crn_keys: bool,
) -> ProbabilityDesignResult:
    grouped: dict[str, list[PrimaryUnit]] = defaultdict(list)
    for unit in units:
        grouped[unit.stratum_id].append(unit)
    if target_size < len(grouped):
        raise ProbabilityDesignError(
            f"stratified target={target_size} is smaller than stratum count={len(grouped)}; "
            "positive inclusion support cannot be preserved"
        )
    allocation = _proportional_allocation(
        {key: len(value) for key, value in grouped.items()}, target_size
    )
    selected: list[str] = []
    probabilities: dict[str, float] = {}
    for stratum_id, values in sorted(grouped.items()):
        draw_count = allocation[stratum_id]
        ranked = sorted(
            values,
            key=lambda item: (
                rng.uint64(
                    f"{label}:stratum={stratum_id}:rank={item.crn_key if use_crn_keys else item.key.unit_id}",
                    0,
                ),
                item.key.unit_id,
            ),
        )
        selected.extend(item.key.unit_id for item in ranked[:draw_count])
        probability = draw_count / len(values)
        for item in values:
            probabilities[item.key.unit_id] = probability
    return ProbabilityDesignResult(
        design_type="stratified",
        target_size=target_size,
        selected_primary_unit_ids=tuple(sorted(selected)),
        primary_inclusion_probabilities=dict(sorted(probabilities.items())),
        stratum_population_counts=dict(sorted((key, len(value)) for key, value in grouped.items())),
        stratum_sample_counts=dict(sorted(allocation.items())),
        pps_single_draw_probabilities={},
        pps_draw_count=0,
        exact_inclusion_probabilities=True,
    )


def _global_srs(
    units: Sequence[PrimaryUnit],
    target_size: int,
    rng: CounterRng,
    label: str,
    *,
    use_crn_keys: bool,
    design_type: str,
) -> ProbabilityDesignResult:
    ranked = sorted(
        units,
        key=lambda item: (
            rng.uint64(
                f"{label}:global-rank={item.crn_key if use_crn_keys else item.key.unit_id}",
                0,
            ),
            item.key.unit_id,
        ),
    )
    probability = target_size / len(units)
    return ProbabilityDesignResult(
        design_type=design_type,
        target_size=target_size,
        selected_primary_unit_ids=tuple(sorted(item.key.unit_id for item in ranked[:target_size])),
        primary_inclusion_probabilities={item.key.unit_id: probability for item in units},
        stratum_population_counts={"ALL": len(units)},
        stratum_sample_counts={"ALL": target_size},
        pps_single_draw_probabilities={},
        pps_draw_count=0,
        exact_inclusion_probabilities=True,
    )


def _pps_with_replacement(
    units: Sequence[PrimaryUnit],
    draw_count: int,
    rng: CounterRng,
    label: str,
) -> ProbabilityDesignResult:
    total_measure = sum(item.size_measure for item in units)
    if not math.isfinite(total_measure) or total_measure <= 0:
        raise ProbabilityDesignError("PPS size measures must have a positive finite sum")
    probabilities = {
        item.key.unit_id: item.size_measure / total_measure for item in units
    }
    ordered = tuple(sorted(units, key=lambda item: item.key.unit_id))
    cumulative: list[float] = []
    running = 0.0
    for item in ordered:
        running += probabilities[item.key.unit_id]
        cumulative.append(running)
    cumulative[-1] = 1.0
    selected: set[str] = set()
    for index in range(draw_count):
        value = rng.uniform(f"{label}:pps-with-replacement", index)
        selected.add(ordered[min(bisect_left(cumulative, value), len(ordered) - 1)].key.unit_id)
    inclusion = {
        unit_id: _bounded_probability(1.0 - (1.0 - probability) ** draw_count)
        for unit_id, probability in probabilities.items()
    }
    return ProbabilityDesignResult(
        design_type="PPS",
        target_size=draw_count,
        selected_primary_unit_ids=tuple(sorted(selected)),
        primary_inclusion_probabilities=dict(sorted(inclusion.items())),
        stratum_population_counts={"ALL": len(units)},
        stratum_sample_counts={"ALL": draw_count},
        pps_single_draw_probabilities=dict(sorted(probabilities.items())),
        pps_draw_count=draw_count,
        exact_inclusion_probabilities=True,
    )


def _proportional_allocation(
    population_counts: Mapping[str, int], target_size: int
) -> Mapping[str, int]:
    total = sum(population_counts.values())
    quotas = {
        key: target_size * count / total for key, count in population_counts.items()
    }
    allocation = {
        key: min(count, max(1, math.floor(quotas[key])))
        for key, count in population_counts.items()
    }
    while sum(allocation.values()) < target_size:
        candidates = [
            key for key, count in population_counts.items() if allocation[key] < count
        ]
        if not candidates:
            raise ProbabilityDesignError("cannot allocate requested stratified target")
        chosen = max(
            candidates,
            key=lambda key: (quotas[key] - allocation[key], population_counts[key], key),
        )
        allocation[chosen] += 1
    while sum(allocation.values()) > target_size:
        candidates = [key for key in allocation if allocation[key] > 1]
        if not candidates:
            raise ProbabilityDesignError("cannot reduce stratified allocation without zero support")
        chosen = max(
            candidates,
            key=lambda key: (allocation[key] - quotas[key], allocation[key], key),
        )
        allocation[chosen] -= 1
    return dict(sorted(allocation.items()))


def _stratum_population_counts(
    units: Sequence[PrimaryUnit],
) -> Mapping[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in units:
        counts[item.stratum_id] += 1
    return dict(sorted(counts.items()))


def _srs_none_probability(
    population_count: int, cause_count: int, sample_count: int
) -> float:
    if cause_count <= 0 or sample_count <= 0:
        return 1.0
    if cause_count >= population_count or sample_count > population_count - cause_count:
        return 0.0
    probability = 1.0
    for draw in range(sample_count):
        probability *= (population_count - cause_count - draw) / (population_count - draw)
    return _bounded_probability(probability)


def _bounded_probability(value: float) -> float:
    if not math.isfinite(value):
        raise ProbabilityDesignError(f"non-finite inclusion probability {value}")
    bounded = min(1.0, max(0.0, value))
    if bounded <= 0.0:
        raise ProbabilityDesignError(
            "declared design produced zero inclusion probability for an observable unit"
        )
    return bounded
