"""Pinned S13 metric-threshold profile loading and fingerprinting."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.policy.language import canonical_json


PROFILE_PATH = Path(__file__).with_name("threshold_profiles_v1.json")


class ValidationThresholdProfileError(ValueError):
    """Raised when a threshold profile is missing, unpinned, or malformed."""


@dataclass(frozen=True)
class ValidationThresholdProfile:
    profile_id: str
    profile_version: str
    source_label: str
    engineering_basis: str
    max_affected_record_ids: int
    minimum_rows_per_second: float
    maximum_peak_memory_bytes: int
    maximum_bytes_per_row: float
    minimum_parallel_efficiency: float
    profile_sha256: str


def load_validation_threshold_profile(profile_id: str) -> ValidationThresholdProfile:
    """Load and validate one controlled, versioned threshold bundle."""

    raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profiles = raw.get("profiles")
    if not isinstance(profiles, Mapping) or profile_id not in profiles:
        raise ValidationThresholdProfileError(f"unknown metric threshold profile {profile_id!r}")
    profile = profiles[profile_id]
    if not isinstance(profile, Mapping):
        raise ValidationThresholdProfileError(f"profile {profile_id!r} must be an object")
    required = {
        "source_label",
        "engineering_basis",
        "max_affected_record_ids",
        "minimum_rows_per_second",
        "maximum_peak_memory_bytes",
        "maximum_bytes_per_row",
        "minimum_parallel_efficiency",
    }
    missing = sorted(required - set(profile))
    extra = sorted(set(profile) - required)
    if missing or extra:
        raise ValidationThresholdProfileError(
            f"profile {profile_id!r} fields mismatch missing={missing} extra={extra}"
        )
    values: dict[str, Any] = dict(profile)
    if values["source_label"] != "controlled_synthetic":
        raise ValidationThresholdProfileError(f"profile {profile_id!r} has unsupported source label")
    if not isinstance(values["engineering_basis"], str) or not values["engineering_basis"].strip():
        raise ValidationThresholdProfileError(f"profile {profile_id!r} lacks engineering basis")
    max_ids = values["max_affected_record_ids"]
    peak = values["maximum_peak_memory_bytes"]
    if not isinstance(max_ids, int) or isinstance(max_ids, bool) or max_ids < 1:
        raise ValidationThresholdProfileError(f"profile {profile_id!r} max_affected_record_ids invalid")
    if not isinstance(peak, int) or isinstance(peak, bool) or peak < 1:
        raise ValidationThresholdProfileError(f"profile {profile_id!r} maximum_peak_memory_bytes invalid")
    numeric_names = (
        "minimum_rows_per_second",
        "maximum_bytes_per_row",
        "minimum_parallel_efficiency",
    )
    for name in numeric_names:
        value = values[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationThresholdProfileError(f"profile {profile_id!r} {name} must be numeric")
        if not math.isfinite(float(value)) or float(value) <= 0:
            raise ValidationThresholdProfileError(f"profile {profile_id!r} {name} must be positive and finite")
    core = {"profile_id": profile_id, "profile_version": raw["profile_version"], **values}
    digest = hashlib.sha256(canonical_json(core).encode("utf-8")).hexdigest()
    return ValidationThresholdProfile(
        profile_id=profile_id,
        profile_version=str(raw["profile_version"]),
        source_label=str(values["source_label"]),
        engineering_basis=str(values["engineering_basis"]),
        max_affected_record_ids=max_ids,
        minimum_rows_per_second=float(values["minimum_rows_per_second"]),
        maximum_peak_memory_bytes=peak,
        maximum_bytes_per_row=float(values["maximum_bytes_per_row"]),
        minimum_parallel_efficiency=float(values["minimum_parallel_efficiency"]),
        profile_sha256=digest,
    )
