"""Small deterministic statistical primitives used by the S14 metric engine."""

from __future__ import annotations

from math import fsum, isfinite, sqrt
from statistics import mean, stdev
from typing import Iterable, Sequence

from htgl_dataset_generator.seeds import CounterRng


class MetricStatisticsError(ValueError):
    """Raised when a statistical metric has invalid or insufficient inputs."""


def weighted_wasserstein_1d(
    left_values: Sequence[float],
    left_weights: Sequence[float],
    right_values: Sequence[float],
    right_weights: Sequence[float],
) -> float:
    """Exact integral of the absolute weighted empirical-CDF difference."""

    left = _weighted_points(left_values, left_weights, "left")
    right = _weighted_points(right_values, right_weights, "right")
    support = sorted({value for value, _ in left} | {value for value, _ in right})
    if len(support) < 2:
        return 0.0
    left_total = fsum(weight for _, weight in left)
    right_total = fsum(weight for _, weight in right)
    left_by_value = _weight_by_value(left)
    right_by_value = _weight_by_value(right)
    left_cdf = 0.0
    right_cdf = 0.0
    distance = 0.0
    for index, value in enumerate(support[:-1]):
        left_cdf += left_by_value.get(value, 0.0) / left_total
        right_cdf += right_by_value.get(value, 0.0) / right_total
        distance += abs(left_cdf - right_cdf) * (support[index + 1] - value)
    return distance


def weighted_ks_2sample(
    left_values: Sequence[float],
    left_weights: Sequence[float],
    right_values: Sequence[float],
    right_weights: Sequence[float],
) -> float:
    """Maximum absolute difference of two weighted empirical CDFs."""

    left = _weighted_points(left_values, left_weights, "left")
    right = _weighted_points(right_values, right_weights, "right")
    support = sorted({value for value, _ in left} | {value for value, _ in right})
    left_total = fsum(weight for _, weight in left)
    right_total = fsum(weight for _, weight in right)
    left_by_value = _weight_by_value(left)
    right_by_value = _weight_by_value(right)
    left_cdf = 0.0
    right_cdf = 0.0
    result = 0.0
    for value in support:
        left_cdf += left_by_value.get(value, 0.0) / left_total
        right_cdf += right_by_value.get(value, 0.0) / right_total
        result = max(result, abs(left_cdf - right_cdf))
    return result


def autocorrelation(values: Sequence[float], lag: int) -> float:
    """Population autocorrelation at a positive lag with explicit degeneracy checks."""

    series = _finite_values(values, "autocorrelation")
    if lag <= 0:
        raise MetricStatisticsError("autocorrelation lag must be positive")
    if len(series) <= lag + 1:
        raise MetricStatisticsError(
            f"autocorrelation needs more than lag+1 observations; n={len(series)} lag={lag}"
        )
    center = mean(series)
    denominator = fsum((value - center) ** 2 for value in series)
    if denominator <= 0:
        raise MetricStatisticsError("autocorrelation is undefined for a constant series")
    numerator = fsum(
        (series[index] - center) * (series[index - lag] - center)
        for index in range(lag, len(series))
    )
    return numerator / denominator


def empirical_standard_error(values: Sequence[float]) -> float | None:
    series = _finite_values(values, "standard error")
    return stdev(series) / sqrt(len(series)) if len(series) >= 2 else None


def deterministic_percentile_interval(
    values: Sequence[float],
    *,
    confidence_level: float,
    rng: CounterRng,
    label: str,
    repetitions: int = 2000,
) -> tuple[float, float]:
    """Percentile bootstrap interval using addressed draws from a named seed stream."""

    series = _finite_values(values, "bootstrap interval")
    if len(series) < 2:
        raise MetricStatisticsError("bootstrap interval requires at least two independent replicates")
    if not 0.0 < confidence_level < 1.0:
        raise MetricStatisticsError("confidence_level must be in (0, 1)")
    if repetitions < 200:
        raise MetricStatisticsError("bootstrap repetitions must be at least 200")
    estimates: list[float] = []
    size = len(series)
    for repetition in range(repetitions):
        sample = [
            series[
                rng.randint(
                    f"{label}:bootstrap-index:{draw}",
                    repetition,
                    0,
                    size - 1,
                )
            ]
            for draw in range(size)
        ]
        estimates.append(mean(sample))
    estimates.sort()
    alpha = 1.0 - confidence_level
    return (_quantile(estimates, alpha / 2.0), _quantile(estimates, 1.0 - alpha / 2.0))


def f1_from_labels(
    truth: Iterable[bool],
    predicted: Iterable[bool],
) -> tuple[float, float, float, int, int, int]:
    truth_values = tuple(bool(value) for value in truth)
    predicted_values = tuple(bool(value) for value in predicted)
    if len(truth_values) != len(predicted_values) or not truth_values:
        raise MetricStatisticsError("F1 labels must be non-empty and have equal length")
    tp = sum(left and right for left, right in zip(truth_values, predicted_values))
    fp = sum(not left and right for left, right in zip(truth_values, predicted_values))
    fn = sum(left and not right for left, right in zip(truth_values, predicted_values))
    precision = tp / (tp + fp) if tp + fp else (1.0 if not any(truth_values) else 0.0)
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    return f1, precision, recall, tp, fp, fn


def _weighted_points(
    values: Sequence[float], weights: Sequence[float], location: str
) -> tuple[tuple[float, float], ...]:
    if len(values) != len(weights) or not values:
        raise MetricStatisticsError(f"{location}: values and weights must be non-empty and equal length")
    points = []
    for index, (value, weight) in enumerate(zip(values, weights)):
        if not isfinite(value):
            raise MetricStatisticsError(f"{location}[{index}]: value must be finite")
        if not isfinite(weight) or weight <= 0:
            raise MetricStatisticsError(f"{location}[{index}]: weight must be positive and finite")
        points.append((float(value), float(weight)))
    return tuple(points)


def _weight_by_value(points: Sequence[tuple[float, float]]) -> dict[float, float]:
    result: dict[float, float] = {}
    for value, weight in points:
        result[value] = result.get(value, 0.0) + weight
    return result


def _finite_values(values: Sequence[float], location: str) -> tuple[float, ...]:
    result = tuple(float(value) for value in values)
    if not result or any(not isfinite(value) for value in result):
        raise MetricStatisticsError(f"{location} values must be non-empty and finite")
    return result


def _quantile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise MetricStatisticsError("quantile input is empty")
    position = probability * (len(sorted_values) - 1)
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction

