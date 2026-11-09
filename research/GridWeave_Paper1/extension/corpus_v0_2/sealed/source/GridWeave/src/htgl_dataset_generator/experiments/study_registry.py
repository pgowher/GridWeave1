"""Fail-closed loader for the Section 30.2 factorial-study registry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .study_models import FactorAxis, FactorLevel, FactorialStudyRegistry


REGISTRY_FORMAT = "htgl.factorial-study-registry.v1"
DEFAULT_REGISTRY_PATH = Path(__file__).with_name("factorial_study_v1.json")
ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]+$")
REQUIRED_AXES = (
    "represented_population_N",
    "materialized_row_target_n",
    "region_count",
    "organization_graph_density",
    "arrival_model",
    "workflow_mix",
    "anomaly_prevalence",
    "visibility_profile",
    "evidence_profile",
    "physical_backend",
    "sampling_profile",
)
EXPECTED_LEVEL_COUNTS = (6, 4, 4, 3, 4, 4, 5, 6, 5, 3, 3)


class StudyRegistryError(ValueError):
    """Raised when the controlling factor registry is incomplete or ambiguous."""


def load_factorial_study_registry(
    path: str | Path | None = None,
) -> FactorialStudyRegistry:
    registry_path = Path(path).resolve() if path is not None else DEFAULT_REGISTRY_PATH
    payload = registry_path.read_bytes()
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise StudyRegistryError(f"invalid study registry JSON {registry_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise StudyRegistryError("study registry root must be an object")
    _exact_keys(
        raw,
        {"registry_format", "registry_id", "version", "source", "axes"},
        "study registry",
    )
    if raw["registry_format"] != REGISTRY_FORMAT:
        raise StudyRegistryError(f"registry_format must be {REGISTRY_FORMAT}")
    axes_raw = raw["axes"]
    if not isinstance(axes_raw, list) or not axes_raw:
        raise StudyRegistryError("axes must be a non-empty list")
    axes: list[FactorAxis] = []
    seen_levels: set[str] = set()
    for axis_index, item in enumerate(axes_raw):
        location = f"axes[{axis_index}]"
        if not isinstance(item, Mapping):
            raise StudyRegistryError(f"{location} must be an object")
        _exact_keys(item, {"axis_id", "execution_mode", "levels"}, location)
        axis_id = _identifier(item["axis_id"], f"{location}.axis_id")
        levels_raw = item["levels"]
        if not isinstance(levels_raw, list) or not levels_raw:
            raise StudyRegistryError(f"{axis_id}.levels must be non-empty")
        levels: list[FactorLevel] = []
        for level_index, level in enumerate(levels_raw):
            level_location = f"{axis_id}.levels[{level_index}]"
            if not isinstance(level, Mapping):
                raise StudyRegistryError(f"{level_location} must be an object")
            _exact_keys(
                level,
                {"level_id", "value", "claim_eligible", "required_capability"},
                level_location,
            )
            level_id = _identifier(level["level_id"], f"{level_location}.level_id")
            if level_id in seen_levels:
                raise StudyRegistryError(f"duplicate level_id={level_id}")
            seen_levels.add(level_id)
            if not isinstance(level["claim_eligible"], bool):
                raise StudyRegistryError(f"{level_id}.claim_eligible must be boolean")
            capability = level["required_capability"]
            if capability is not None:
                capability = _identifier(capability, f"{level_id}.required_capability")
            value = level["value"]
            if value is None or isinstance(value, (list, dict)):
                raise StudyRegistryError(f"{level_id}.value must be a non-null scalar")
            levels.append(
                FactorLevel(
                    level_id=level_id,
                    value=value,
                    claim_eligible=bool(level["claim_eligible"]),
                    required_capability=capability,
                )
            )
        axes.append(
            FactorAxis(
                axis_id=axis_id,
                execution_mode=_identifier(item["execution_mode"], f"{axis_id}.execution_mode"),
                levels=tuple(levels),
            )
        )
    observed_axes = tuple(axis.axis_id for axis in axes)
    if observed_axes != REQUIRED_AXES:
        raise StudyRegistryError(
            f"axis inventory/order mismatch expected={REQUIRED_AXES} observed={observed_axes}"
        )
    observed_counts = tuple(len(axis.levels) for axis in axes)
    if observed_counts != EXPECTED_LEVEL_COUNTS:
        raise StudyRegistryError(
            f"level inventory mismatch expected={EXPECTED_LEVEL_COUNTS} observed={observed_counts}"
        )
    _validate_controlling_values(axes)
    return FactorialStudyRegistry(
        registry_id=_identifier(raw["registry_id"], "registry_id"),
        version=_string(raw["version"], "version"),
        source=_string(raw["source"], "source"),
        sha256=hashlib.sha256(payload).hexdigest(),
        axes=tuple(axes),
    )


def _validate_controlling_values(axes: list[FactorAxis]) -> None:
    values = {axis.axis_id: tuple(level.value for level in axis.levels) for axis in axes}
    expected = {
        "represented_population_N": (10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 450_000_000),
        "materialized_row_target_n": (10_000, 100_000, 1_000_000, 10_000_000),
        "region_count": (1, 3, 10, 30),
        "organization_graph_density": ("sparse", "medium", "dense"),
        "arrival_model": ("conditioned_NHPP", "unconditioned_NHPP", "MMPP", "Hawkes"),
        "workflow_mix": ("consent_only", "balanced_rights", "erasure_heavy", "incident_heavy"),
        "anomaly_prevalence": (0.0, 0.001, 0.01, 0.05, 0.05),
        "visibility_profile": ("full", "role_based", "delayed", "lossy", "adversarial_omission", "collusion"),
        "evidence_profile": ("digest", "hmac_signature", "merkle", "replica_attestation", "mixed"),
        "physical_backend": (
            "procedural",
            "opensynth_style_synthetic",
            "smart_ds_style_synthetic",
        ),
        "sampling_profile": ("cluster_pps", "stratified", "naive_srs_truncation"),
    }
    for axis_id, expected_values in expected.items():
        if values[axis_id] != expected_values:
            raise StudyRegistryError(
                f"{axis_id} levels differ from controlling contract expected={expected_values} observed={values[axis_id]}"
            )


def _exact_keys(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        raise StudyRegistryError(
            f"{location} key mismatch missing={sorted(missing)} unknown={sorted(unknown)}"
        )


def _identifier(value: Any, location: str) -> str:
    text = _string(value, location)
    if ID_RE.fullmatch(text) is None:
        raise StudyRegistryError(f"{location} is not a controlled identifier: {text!r}")
    return text


def _string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StudyRegistryError(f"{location} must be a non-empty string")
    return value
