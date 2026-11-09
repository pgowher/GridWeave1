"""S11 partial-observer projection, omission truth, and non-leakage API."""

from .compiler import ObserverProjectionError, build_observer_projections, validate_observer_build
from .language import VisibilityLanguageError, evaluate_visibility_expression
from .leakage import scan_observer_releases
from .models import (
    LeakageDiagnostics,
    LeakageFinding,
    ObserverBuild,
    ObserverProfileDiagnostics,
    ObserverReleaseView,
    ObserverTaskResult,
    OmissionOracleDiagnostics,
    OmissionOracleTruth,
    ProjectionSourceMapping,
)
from .profiles import ObserverProfileBundle, ObserverProfileError, load_observer_profile_bundle

__all__ = [
    "LeakageDiagnostics",
    "LeakageFinding",
    "ObserverBuild",
    "ObserverProfileBundle",
    "ObserverProfileDiagnostics",
    "ObserverProfileError",
    "ObserverProjectionError",
    "ObserverReleaseView",
    "ObserverTaskResult",
    "OmissionOracleDiagnostics",
    "OmissionOracleTruth",
    "ProjectionSourceMapping",
    "VisibilityLanguageError",
    "build_observer_projections",
    "evaluate_visibility_expression",
    "load_observer_profile_bundle",
    "scan_observer_releases",
    "validate_observer_build",
]
