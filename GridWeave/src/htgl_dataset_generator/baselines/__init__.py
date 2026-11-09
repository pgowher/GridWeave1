"""Independent comparison baselines for benchmark ablations."""

from .anomalies import (
    RANDOM_FIELD_PROFILE,
    RANDOM_TRANSITION_PROFILE,
    AnomalyBaselineBuild,
    AnomalyBaselineCase,
    build_seeded_anomaly_baselines,
)
from .sampling import build_sampling_baselines
from .models import (
    BaselineConditionOutput,
    BaselineMetricObservation,
    BaselineOutputSample,
    BaselinePairedComparison,
    BaselineProfile,
    BaselineRegistry,
    BaselineStudyBuild,
)
from .registry import BaselineRegistryError, load_baseline_registry

__all__ = [
    "RANDOM_FIELD_PROFILE",
    "RANDOM_TRANSITION_PROFILE",
    "AnomalyBaselineBuild",
    "AnomalyBaselineCase",
    "build_seeded_anomaly_baselines",
    "build_sampling_baselines",
    "BaselineConditionOutput",
    "BaselineMetricObservation",
    "BaselineOutputSample",
    "BaselinePairedComparison",
    "BaselineProfile",
    "BaselineRegistry",
    "BaselineRegistryError",
    "BaselineStudyBuild",
    "load_baseline_registry",
]
