"""S14 metric registry, diagnostics, uncertainty, and paired comparisons."""

from .aggregation import (
    BOOTSTRAP_REPETITIONS,
    MetricAggregationError,
    aggregate_replicate_metrics,
    build_paired_crn_comparisons,
)
from .engine import (
    MetricsEngineError,
    build_run_metrics,
    validate_metric_execution_for_publication,
    validate_metrics_build,
)
from .models import (
    MetricConditionSeries,
    MetricDefinition,
    MetricExecutionRecord,
    MetricObservationProvenance,
    MetricRegistry,
    MetricsBuild,
    MetricsInput,
    MetricsRunGroupBuild,
    PairedMetricComparison,
    PhysicalCalibrationReference,
    PhysicalReferenceObservation,
    PrivacySourceReference,
    ReplicateMetricAggregate,
)
from .registry import MetricRegistryError, load_metric_registry
from .statistics import (
    MetricStatisticsError,
    autocorrelation,
    deterministic_percentile_interval,
    empirical_standard_error,
    f1_from_labels,
    weighted_ks_2sample,
    weighted_wasserstein_1d,
)

__all__ = [
    "BOOTSTRAP_REPETITIONS",
    "MetricAggregationError",
    "MetricConditionSeries",
    "MetricDefinition",
    "MetricExecutionRecord",
    "MetricObservationProvenance",
    "MetricRegistry",
    "MetricRegistryError",
    "MetricStatisticsError",
    "MetricsBuild",
    "MetricsEngineError",
    "MetricsInput",
    "MetricsRunGroupBuild",
    "PairedMetricComparison",
    "PhysicalCalibrationReference",
    "PhysicalReferenceObservation",
    "PrivacySourceReference",
    "ReplicateMetricAggregate",
    "aggregate_replicate_metrics",
    "autocorrelation",
    "build_paired_crn_comparisons",
    "build_run_metrics",
    "deterministic_percentile_interval",
    "empirical_standard_error",
    "f1_from_labels",
    "load_metric_registry",
    "validate_metrics_build",
    "validate_metric_execution_for_publication",
    "weighted_ks_2sample",
    "weighted_wasserstein_1d",
]
