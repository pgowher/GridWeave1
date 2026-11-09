"""Strict, digest-pinned registry for executable P8 controls and ablations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .models import BaselineProfile, BaselineRegistry


REGISTRY_FORMAT = "htgl.baseline-profile-registry.v1"
DEFAULT_REGISTRY_PATH = Path(__file__).with_name("baseline_profiles_v1.json")
PROFILE_ID_RE = re.compile(r"^[A-Z][A-Za-z0-9._-]+$")
FAMILIES = frozenset({"temporal", "structure", "anomaly", "observer", "sampling"})
ROLES = frozenset({"baseline", "ablation", "proposed"})
REQUIRED_PROFILE_IDS = frozenset(
    {
        "BASELINE-HOMOGENEOUS-POISSON-v1",
        "BASELINE-EXACT-INDEPENDENT-NHPP-v1",
        "NEGATIVE-CONTROL-ROUNDED-GAUSSIAN-UNIFORM-BIN-v1",
        "BASELINE-MMPP-2STATE-v1",
        "BASELINE-HAWKES-EXPONENTIAL-v1",
        "PROPOSED-HIERARCHICAL-ARRIVAL-MODEL-v1",
        "BASELINE-UNIFORM-IID-RECORD-v1",
        "BASELINE-GENERIC-PROCESS-LOG-v1",
        "BASELINE-RELATIONAL-SEQUENTIAL-SYNTHESIZER-v1",
        "ABLATION-NO-CUSTODY-v1",
        "ABLATION-NO-CAUSAL-CLOSURE-v1",
        "ABLATION-NO-TOPOLOGY-v1",
        "ABLATION-NO-POLICY-v1",
        "ABLATION-NO-EVIDENCE-v1",
        "PROPOSED-GOVERNANCE-COMPLETE-STRUCTURE-v1",
        "BASELINE-SEEDED-RANDOM-FIELD-CORRUPTION-v1",
        "BASELINE-SEEDED-RANDOM-INVALID-TRANSITION-v1",
        "PROPOSED-MINIMAL-COUNTERFACTUAL-v1",
        "BASELINE-FULL-CENTRAL-LOG-v1",
        "BASELINE-INDEPENDENT-RANDOM-DROPOUT-v1",
        "ABLATION-NO-OBSERVER-PROJECTION-v1",
        "PROPOSED-OBSERVER-PROJECTION-DSL-v1",
        "BASELINE-FIRST-N-TRUNCATION",
        "BASELINE-SIMPLE-RANDOM-EVENT-ROWS",
        "BASELINE-UNWEIGHTED-WORKFLOW",
        "ABLATION-NO-SAMPLING-WEIGHTS-v1",
        "PROPOSED-DEPENDENCY-CLOSED-PROBABILITY-DESIGN-v1",
    }
)


class BaselineRegistryError(ValueError):
    """Raised when the P8 profile contract is incomplete or ambiguous."""


def load_baseline_registry(path: str | Path | None = None) -> BaselineRegistry:
    registry_path = Path(path).resolve() if path is not None else DEFAULT_REGISTRY_PATH
    payload = registry_path.read_bytes()
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise BaselineRegistryError(f"invalid baseline registry JSON {registry_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise BaselineRegistryError("baseline registry root must be an object")
    _exact_keys(
        raw,
        {"registry_format", "registry_id", "version", "source", "profiles"},
        "baseline registry",
    )
    if raw["registry_format"] != REGISTRY_FORMAT:
        raise BaselineRegistryError(f"registry_format must be {REGISTRY_FORMAT}")
    profiles_raw = raw["profiles"]
    if not isinstance(profiles_raw, list) or not profiles_raw:
        raise BaselineRegistryError("baseline registry profiles must be a non-empty list")
    profiles: dict[str, BaselineProfile] = {}
    expected_keys = {
        "profile_id", "family", "role", "mechanism", "claim_eligible",
        "shared_budget_contract", "required_metrics", "parameters", "exclusion_reason",
    }
    for index, item in enumerate(profiles_raw):
        if not isinstance(item, Mapping):
            raise BaselineRegistryError(f"profiles[{index}] must be an object")
        _exact_keys(item, expected_keys, f"profiles[{index}]")
        profile_id = _string(item["profile_id"], f"profiles[{index}].profile_id")
        if PROFILE_ID_RE.fullmatch(profile_id) is None:
            raise BaselineRegistryError(f"invalid profile_id={profile_id!r}")
        if profile_id in profiles:
            raise BaselineRegistryError(f"duplicate profile_id={profile_id}")
        family = _string(item["family"], f"{profile_id}.family")
        role = _string(item["role"], f"{profile_id}.role")
        if family not in FAMILIES:
            raise BaselineRegistryError(f"{profile_id}: unknown family {family!r}")
        if role not in ROLES:
            raise BaselineRegistryError(f"{profile_id}: unknown role {role!r}")
        if not isinstance(item["claim_eligible"], bool):
            raise BaselineRegistryError(f"{profile_id}.claim_eligible must be boolean")
        exclusion = item["exclusion_reason"]
        if exclusion is not None:
            exclusion = _string(exclusion, f"{profile_id}.exclusion_reason")
        if not item["claim_eligible"] and exclusion is None:
            raise BaselineRegistryError(
                f"{profile_id}: claim-ineligible profiles require an exclusion reason"
            )
        metrics = item["required_metrics"]
        if (
            not isinstance(metrics, list)
            or not metrics
            or any(not isinstance(value, str) or not value for value in metrics)
            or len(metrics) != len(set(metrics))
        ):
            raise BaselineRegistryError(f"{profile_id}.required_metrics must be unique strings")
        parameters = item["parameters"]
        if not isinstance(parameters, Mapping) or not parameters:
            raise BaselineRegistryError(f"{profile_id}.parameters must be a non-empty object")
        profiles[profile_id] = BaselineProfile(
            profile_id=profile_id,
            family=family,
            role=role,
            mechanism=_string(item["mechanism"], f"{profile_id}.mechanism"),
            claim_eligible=bool(item["claim_eligible"]),
            shared_budget_contract=_string(
                item["shared_budget_contract"], f"{profile_id}.shared_budget_contract"
            ),
            required_metrics=tuple(metrics),
            parameters=dict(sorted(parameters.items())),
            exclusion_reason=exclusion,
        )
    observed = frozenset(profiles)
    if observed != REQUIRED_PROFILE_IDS:
        raise BaselineRegistryError(
            f"profile inventory mismatch missing={sorted(REQUIRED_PROFILE_IDS-observed)} "
            f"unknown={sorted(observed-REQUIRED_PROFILE_IDS)}"
        )
    for family in sorted(FAMILIES):
        proposed = [item for item in profiles.values() if item.family == family and item.role == "proposed"]
        if len(proposed) != 1:
            raise BaselineRegistryError(f"family={family} requires exactly one proposed profile")
        metric_contracts = {item.required_metrics for item in profiles.values() if item.family == family}
        if len(metric_contracts) != 1:
            raise BaselineRegistryError(f"family={family} profiles must share one metric contract")
    return BaselineRegistry(
        registry_id=_string(raw["registry_id"], "registry_id"),
        version=_string(raw["version"], "version"),
        source=_string(raw["source"], "source"),
        sha256=hashlib.sha256(payload).hexdigest(),
        profiles=dict(sorted(profiles.items())),
    )


def _exact_keys(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        raise BaselineRegistryError(
            f"{location} key mismatch missing={sorted(missing)} unknown={sorted(unknown)}"
        )


def _string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BaselineRegistryError(f"{location} must be a non-empty string")
    return value
