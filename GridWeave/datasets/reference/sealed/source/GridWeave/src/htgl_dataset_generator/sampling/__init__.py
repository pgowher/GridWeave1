"""S12 dependency-closed probability sampling and estimator API."""

from .designs import (
    ProbabilityDesignError,
    draw_probability_design,
    induced_inclusion_probability,
)
from .estimators import (
    EstimatorEligibilityError,
    hajek_total,
    horvitz_thompson_total,
)
from .models import (
    ClosureProvenance,
    DependencyClosure,
    KnownTotalDiagnostic,
    PrimaryUnit,
    ProbabilityDesignResult,
    SamplingBaselineResult,
    SamplingBuild,
    SamplingDesignDiagnostics,
    UnitKey,
)
from .units import SamplingUnitError, build_dependency_closure, parse_stratum_definitions


def __getattr__(name: str):
    if name in {
        "SamplingBuildError",
        "build_dependency_closed_sample",
        "validate_sampling_build",
    }:
        from .builder import (
            SamplingBuildError,
            build_dependency_closed_sample,
            validate_sampling_build,
        )

        return {
            "SamplingBuildError": SamplingBuildError,
            "build_dependency_closed_sample": build_dependency_closed_sample,
            "validate_sampling_build": validate_sampling_build,
        }[name]
    raise AttributeError(name)

__all__ = [
    "ClosureProvenance",
    "DependencyClosure",
    "EstimatorEligibilityError",
    "KnownTotalDiagnostic",
    "PrimaryUnit",
    "ProbabilityDesignError",
    "ProbabilityDesignResult",
    "SamplingBaselineResult",
    "SamplingBuild",
    "SamplingBuildError",
    "SamplingDesignDiagnostics",
    "SamplingUnitError",
    "UnitKey",
    "build_dependency_closed_sample",
    "build_dependency_closure",
    "draw_probability_design",
    "hajek_total",
    "horvitz_thompson_total",
    "induced_inclusion_probability",
    "parse_stratum_definitions",
    "validate_sampling_build",
]
