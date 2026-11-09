"""Resolved configuration contract for HTGL dataset-generator runs."""

from .resolver import (
    ALLOWED_SOURCE_LABELS,
    CONTROLLED_SYNTHETIC_CALIBRATION_PREFIX,
    CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES,
    CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE,
    CONTROLLED_SYNTHETIC_SOURCE_PREFIX,
    ConfigResolutionError,
    DEFERRED_EXTERNAL_PHYSICAL_BACKENDS,
    ResolvedConfig,
    ResolvedRunPlan,
    build_run_plan,
    compute_config_sha256,
    load_config,
    resolve_config,
    resolve_config_file,
)
from .release_profiles import (
    PROCEDURAL_CONTROLLED_SYNTHETIC_V1,
    SUPPORTED_RELEASE_PROFILE,
    ReleaseProfile,
    ReleaseProfileError,
    load_release_profile,
    validate_resolved_release_profile,
)
from .validation_contract import (
    CHECK_ID_PATTERN,
    CORE_VALIDATION_CHECK_IDS,
    ValidationProfileContractError,
    resolve_required_check_ids,
)

__all__ = [
    "ALLOWED_SOURCE_LABELS",
    "CONTROLLED_SYNTHETIC_CALIBRATION_PREFIX",
    "CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES",
    "CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE",
    "CONTROLLED_SYNTHETIC_SOURCE_PREFIX",
    "ConfigResolutionError",
    "CHECK_ID_PATTERN",
    "CORE_VALIDATION_CHECK_IDS",
    "DEFERRED_EXTERNAL_PHYSICAL_BACKENDS",
    "PROCEDURAL_CONTROLLED_SYNTHETIC_V1",
    "SUPPORTED_RELEASE_PROFILE",
    "ReleaseProfile",
    "ReleaseProfileError",
    "load_release_profile",
    "validate_resolved_release_profile",
    "ResolvedConfig",
    "ResolvedRunPlan",
    "ValidationProfileContractError",
    "build_run_plan",
    "compute_config_sha256",
    "load_config",
    "resolve_config",
    "resolve_config_file",
    "resolve_required_check_ids",
]
