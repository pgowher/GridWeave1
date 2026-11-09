"""S00 resolved configuration contract.

The raw configuration format is JSON. Every field inside a required Appendix C
group is a source-labelled value:

```
"contract_version": {"value": "1.1.0", "source": "controlled_synthetic"}
```

The resolver unwraps those labelled values, validates all required groups and
references, and emits a frozen run plan with a deterministic ``config_sha256``.
No implicit current time, implicit versions, best-effort enum parsing, or
first-scenario-only behavior is allowed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
import copy
import hashlib
import json
import math
import os
import re

from htgl_dataset_generator.schemas import ContractSpec, load_contract

from .validation_contract import (
    ValidationProfileContractError,
    resolve_required_check_ids,
)


ALLOWED_SOURCE_LABELS = frozenset(
    {
        "controlled_synthetic",
        "calibrated_from_source",
        "imported_template",
        "publication_derived",
        "deployment_measured",
    }
)
JSONL_COMPATIBILITY_ADAPTER = "jsonl_debug_view"
INTEROPERABILITY_ADAPTERS = frozenset(
    {"jsonl_debug_view", "csv", "xes", "jsonld", "cim", "green_button", "sqlite"}
)
CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES: Mapping[str, tuple[str, str]] = {
    "procedural": ("procedural.v1", "procedural_analytic:v1"),
    "opensynth_style_synthetic": (
        "opensynth_style_synthetic.v1",
        "controlled_synthetic_profile_analytic:v1",
    ),
    "smart_ds_style_synthetic": (
        "smart_ds_style_synthetic.v1",
        "controlled_synthetic_template_analytic:v1",
    ),
}
DEFERRED_EXTERNAL_PHYSICAL_BACKENDS: Mapping[str, str] = {
    "opensynth_faraday": "opensynth_style_synthetic",
    "smart_ds": "smart_ds_style_synthetic",
    "simbench": "smart_ds_style_synthetic",
    "opendss": "procedural",
    "gridlabd": "procedural",
    "pandapower": "procedural",
    "imported_benchmark": "procedural",
    "co_simulation": "procedural",
}
CONTROLLED_SYNTHETIC_CALIBRATION_PREFIX = "CAL-CONTROLLED-SYNTHETIC-"
CONTROLLED_SYNTHETIC_SOURCE_PREFIX = "SRC-CONTROLLED-SYNTHETIC-"
CONTROLLED_SYNTHETIC_PHYSICAL_VALIDITY_SCOPE = (
    "procedural model constraints, units, continuity, temporal behavior, DER bounds, "
    "energy balance, and analytic voltage/loading checks only; no imported benchmark, "
    "learned external model, or external power-flow solver was executed"
)

GROUP_ORDER = (
    "run",
    "claim_scale",
    "world",
    "physical",
    "catalog",
    "arrivals",
    "workflows",
    "policy",
    "anomaly",
    "evidence",
    "observer",
    "sampling",
    "validation",
    "output",
)

GROUP_FIELDS: Mapping[str, tuple[str, ...]] = {
    "run": (
        "contract_version",
        "code_version",
        "container_version",
        "run_id",
        "scenario_id",
        "selected_scenario_ids",
        "replicate_count",
        "root_seed",
        "horizon_start",
        "horizon_end",
        "time_zone",
        "calibration_profile_id",
        "policy_profile_id",
    ),
    "claim_scale": (
        "represented_population",
        "materialized_row_target",
        "executed_operation_target",
        "aggregation_semantics",
        "replay_semantics",
        "estimator_eligible",
        "scale_claim_allowed",
        "operational_claim_allowed",
    ),
    "world": (
        "regions",
        "jurisdictions",
        "actor_relationship_counts",
        "cohorts",
        "organizations",
        "fault_domains",
        "trust_domains",
    ),
    "physical": (
        "backend",
        "backend_version",
        "calibration_bundle_id",
        "calibration_source_ids",
        "conditioning_variables",
        "interval_seconds",
        "units",
        "meter_error_profile_id",
        "solver_backend",
        "solver_tolerances",
    ),
    "catalog": (
        "database_profiles",
        "object_profiles",
        "replica_profiles",
        "retention_profiles",
        "security_profiles",
        "derivation_rules",
    ),
    "arrivals": (
        "model_classes",
        "base_rates_per_day",
        "diurnal_profile_id",
        "weekday_profile_id",
        "scenario_factors",
        "conditioned_total",
        "hawkes_parameters",
        "mmpp_parameters",
    ),
    "workflows": (
        "definition_versions",
        "families",
        "transition_probability_profile_id",
        "delay_model_id",
        "resource_profile_id",
        "mix_profile_id",
        "open_horizon_policy",
    ),
    "policy": (
        "profile_id",
        "profile_version",
        "rule_source_ids",
        "conflict_strategy",
        "golden_suite_id",
        "evaluator_profile",
        "golden_decision_accuracy_target",
        "rule_trace_coverage_target",
        "conflict_resolution_agreement_target",
    ),
    "anomaly": (
        "types",
        "prevalence",
        "oversampling_strategy",
        "invariant_registry_id",
        "invariant_registry_version",
        "invariant_registry_sha256",
        "target_invariant_ids",
        "protected_invariant_ids",
        "edit_grammar_id",
        "edit_grammar_version",
        "edit_grammar_sha256",
        "cost_model_id",
        "cost_model_version",
        "acceptance_profile_id",
        "baseline_profile_ids",
        "search_bound",
    ),
    "evidence": (
        "obligation_template_bundle_id",
        "obligation_template_bundle_version",
        "obligation_template_bundle_sha256",
        "obligation_template_ids",
        "sufficiency_profile_id",
        "receipt_profile_bundle_id",
        "receipt_profile_bundle_version",
        "receipt_profile_bundle_sha256",
        "canonicalization_profile_id",
        "receipt_profiles",
        "anchor_profiles",
        "honest_rate",
        "adversarial_rate",
        "adversarial_case_weights",
        "synthetic_key_profile_id",
        "ml_removal_profile_ids",
        "proof_limit_statement",
    ),
    "observer": (
        "profile_bundle_id",
        "profile_bundle_version",
        "profile_bundle_sha256",
        "visibility_dsl_profile_id",
        "leakage_scan_profile_id",
        "task_registry_id",
        "observer_profile_ids",
        "visibility_profiles",
        "redaction_profiles",
        "delay_profiles",
        "loss_profiles",
        "collusion_profiles",
        "forbidden_field_sets",
    ),
    "sampling": (
        "design_types",
        "primary_unit_types",
        "strata_definitions",
        "pps_measure",
        "target_sample_size",
        "closure_policy",
        "estimator_families",
        "common_random_groups",
        "simulation_repetitions",
        "confidence_level",
        "maximum_absolute_relative_bias",
        "minimum_ci_coverage",
    ),
    "validation": (
        "required_check_ids",
        "metric_threshold_profile_id",
        "repetition_count",
        "alpha",
        "confidence_interval_method",
        "multiplicity_correction",
    ),
    "output": (
        "release_profile_id",
        "output_profile_id",
        "schema_contract_id",
        "schema_contract_fingerprint",
        "dictionary_version",
        "parquet_compression",
        "partition_keys",
        "row_group_target_bytes",
        "adapters",
        "access_classes",
        "manifest_policy",
        "archive_policy",
        "table_schema_ids",
    ),
}

TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
UNPINNED_VERSION_VALUES = frozenset({"latest", "current", "head", "main", "master", "dev"})
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class ConfigResolutionError(ValueError):
    """Raised when raw configuration cannot become an immutable run plan."""


@dataclass(frozen=True)
class RunConfig:
    contract_version: str
    code_version: str
    container_version: str
    run_id: str
    scenario_id: str
    selected_scenario_ids: tuple[str, ...]
    replicate_count: int
    root_seed: str
    horizon_start: str
    horizon_end: str
    time_zone: str
    calibration_profile_id: str
    policy_profile_id: str


@dataclass(frozen=True)
class ClaimScaleConfig:
    represented_population: int
    materialized_row_target: int
    executed_operation_target: int | None
    aggregation_semantics: str
    replay_semantics: str
    estimator_eligible: bool
    scale_claim_allowed: bool
    operational_claim_allowed: bool


@dataclass(frozen=True)
class WorldConfig:
    regions: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    actor_relationship_counts: Mapping[str, int]
    cohorts: tuple[Mapping[str, Any], ...]
    organizations: tuple[Mapping[str, Any], ...]
    fault_domains: tuple[str, ...]
    trust_domains: tuple[str, ...]


@dataclass(frozen=True)
class PhysicalConfig:
    backend: str
    backend_version: str
    calibration_bundle_id: str
    calibration_source_ids: tuple[str, ...]
    conditioning_variables: tuple[str, ...]
    interval_seconds: int
    units: Mapping[str, str]
    meter_error_profile_id: str
    solver_backend: str
    solver_tolerances: Mapping[str, float]

    @property
    def is_controlled_synthetic(self) -> bool:
        return self.backend in CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES


@dataclass(frozen=True)
class CatalogConfig:
    database_profiles: tuple[str, ...]
    object_profiles: tuple[str, ...]
    replica_profiles: tuple[str, ...]
    retention_profiles: tuple[str, ...]
    security_profiles: tuple[str, ...]
    derivation_rules: tuple[str, ...]


@dataclass(frozen=True)
class ArrivalsConfig:
    model_classes: tuple[str, ...]
    base_rates_per_day: Mapping[str, float]
    diurnal_profile_id: str
    weekday_profile_id: str
    scenario_factors: Mapping[str, float]
    conditioned_total: int | None
    hawkes_parameters: Mapping[str, Any]
    mmpp_parameters: Mapping[str, Any]


@dataclass(frozen=True)
class WorkflowsConfig:
    definition_versions: Mapping[str, str]
    families: tuple[str, ...]
    transition_probability_profile_id: str
    delay_model_id: str
    resource_profile_id: str
    mix_profile_id: str
    open_horizon_policy: str


@dataclass(frozen=True)
class PolicyConfig:
    profile_id: str
    profile_version: str
    rule_source_ids: tuple[str, ...]
    conflict_strategy: str
    golden_suite_id: str
    evaluator_profile: str
    golden_decision_accuracy_target: float
    rule_trace_coverage_target: float
    conflict_resolution_agreement_target: float


@dataclass(frozen=True)
class AnomalyConfig:
    types: tuple[str, ...]
    prevalence: Mapping[str, float]
    oversampling_strategy: str
    invariant_registry_id: str
    invariant_registry_version: str
    invariant_registry_sha256: str
    target_invariant_ids: tuple[str, ...]
    protected_invariant_ids: tuple[str, ...]
    edit_grammar_id: str
    edit_grammar_version: str
    edit_grammar_sha256: str
    cost_model_id: str
    cost_model_version: str
    acceptance_profile_id: str
    baseline_profile_ids: tuple[str, ...]
    search_bound: int


@dataclass(frozen=True)
class EvidenceConfig:
    obligation_template_bundle_id: str
    obligation_template_bundle_version: str
    obligation_template_bundle_sha256: str
    obligation_template_ids: tuple[str, ...]
    sufficiency_profile_id: str
    receipt_profile_bundle_id: str
    receipt_profile_bundle_version: str
    receipt_profile_bundle_sha256: str
    canonicalization_profile_id: str
    receipt_profiles: tuple[str, ...]
    anchor_profiles: tuple[str, ...]
    honest_rate: float
    adversarial_rate: float
    adversarial_case_weights: Mapping[str, float]
    synthetic_key_profile_id: str
    ml_removal_profile_ids: tuple[str, ...]
    proof_limit_statement: str


@dataclass(frozen=True)
class ObserverConfig:
    profile_bundle_id: str
    profile_bundle_version: str
    profile_bundle_sha256: str
    visibility_dsl_profile_id: str
    leakage_scan_profile_id: str
    task_registry_id: str
    observer_profile_ids: tuple[str, ...]
    visibility_profiles: tuple[str, ...]
    redaction_profiles: tuple[str, ...]
    delay_profiles: tuple[str, ...]
    loss_profiles: tuple[str, ...]
    collusion_profiles: tuple[str, ...]
    forbidden_field_sets: tuple[str, ...]


@dataclass(frozen=True)
class SamplingConfig:
    design_types: tuple[str, ...]
    primary_unit_types: tuple[str, ...]
    strata_definitions: tuple[str, ...]
    pps_measure: str
    target_sample_size: int
    closure_policy: str
    estimator_families: tuple[str, ...]
    common_random_groups: tuple[str, ...]
    simulation_repetitions: int
    confidence_level: float
    maximum_absolute_relative_bias: float
    minimum_ci_coverage: float


@dataclass(frozen=True)
class ValidationConfig:
    required_check_ids: tuple[str, ...]
    metric_threshold_profile_id: str
    repetition_count: int
    alpha: float
    confidence_interval_method: str
    multiplicity_correction: str


@dataclass(frozen=True)
class OutputConfig:
    release_profile_id: str
    output_profile_id: str
    schema_contract_id: str
    schema_contract_fingerprint: str
    dictionary_version: str
    parquet_compression: str
    partition_keys: tuple[str, ...]
    row_group_target_bytes: int
    adapters: tuple[str, ...]
    access_classes: tuple[str, ...]
    manifest_policy: str
    archive_policy: str
    table_schema_ids: tuple[str, ...]


@dataclass(frozen=True)
class ResolvedRunPlan:
    run_id: str
    scenario_id: str
    replicate_id: int
    config_sha256: str


@dataclass(frozen=True)
class ResolvedConfig:
    run: RunConfig
    claim_scale: ClaimScaleConfig
    world: WorldConfig
    physical: PhysicalConfig
    catalog: CatalogConfig
    arrivals: ArrivalsConfig
    workflows: WorkflowsConfig
    policy: PolicyConfig
    anomaly: AnomalyConfig
    evidence: EvidenceConfig
    observer: ObserverConfig
    sampling: SamplingConfig
    validation: ValidationConfig
    output: OutputConfig
    source_labels: Mapping[str, str]
    resolved_references: Mapping[str, str]
    config_sha256: str
    source_path: str | None = None

    def as_dict(self, include_digest: bool = True) -> dict[str, Any]:
        data = {
            "run": _to_plain(asdict(self.run)),
            "claim_scale": _to_plain(asdict(self.claim_scale)),
            "world": _to_plain(asdict(self.world)),
            "physical": _to_plain(asdict(self.physical)),
            "catalog": _to_plain(asdict(self.catalog)),
            "arrivals": _to_plain(asdict(self.arrivals)),
            "workflows": _to_plain(asdict(self.workflows)),
            "policy": _to_plain(asdict(self.policy)),
            "anomaly": _to_plain(asdict(self.anomaly)),
            "evidence": _to_plain(asdict(self.evidence)),
            "observer": _to_plain(asdict(self.observer)),
            "sampling": _to_plain(asdict(self.sampling)),
            "validation": _to_plain(asdict(self.validation)),
            "output": _to_plain(asdict(self.output)),
            "source_labels": dict(sorted(self.source_labels.items())),
            "resolved_references": dict(sorted(self.resolved_references.items())),
        }
        if include_digest:
            data["config_sha256"] = self.config_sha256
        return data


def _to_plain(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_to_plain(item) for item in value]
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _to_plain(value[key]) for key in sorted(value)}
    return value


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_json(data: Any) -> str:
    return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigResolutionError(message)


def load_config(path: str | os.PathLike[str]) -> Mapping[str, Any]:
    config_path = Path(path)
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigResolutionError(f"{config_path}: invalid JSON: {exc}") from exc


def _unwrap_source_value(path: str, node: Any, source_labels: dict[str, str]) -> Any:
    if not isinstance(node, Mapping):
        raise ConfigResolutionError(f"{path}: each config value must be source-labelled")
    if set(node.keys()) != {"value", "source"}:
        raise ConfigResolutionError(
            f"{path}: expected exactly 'value' and 'source' keys"
        )
    source = node["source"]
    if source not in ALLOWED_SOURCE_LABELS:
        raise ConfigResolutionError(f"{path}: unsupported source label {source!r}")
    source_labels[path] = source
    return copy.deepcopy(node["value"])


def _unwrap_group(group_name: str, raw_group: Any, source_labels: dict[str, str]) -> dict[str, Any]:
    if not isinstance(raw_group, Mapping):
        raise ConfigResolutionError(f"/{group_name}: group must be an object")
    expected = set(GROUP_FIELDS[group_name])
    observed = set(raw_group.keys())
    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    if missing:
        raise ConfigResolutionError(f"/{group_name}: missing fields {missing}")
    if extra:
        raise ConfigResolutionError(f"/{group_name}: unknown fields {extra}")
    return {
        field_name: _unwrap_source_value(
            f"/{group_name}/{field_name}", raw_group[field_name], source_labels
        )
        for field_name in GROUP_FIELDS[group_name]
    }


def _as_tuple(path: str, value: Any, *, non_empty: bool = True) -> tuple[Any, ...]:
    _require(isinstance(value, list), f"{path}: expected list")
    if non_empty:
        _require(bool(value), f"{path}: list must not be empty")
    return tuple(value)


def _as_str_tuple(path: str, value: Any, *, non_empty: bool = True) -> tuple[str, ...]:
    items = _as_tuple(path, value, non_empty=non_empty)
    for item in items:
        _require(isinstance(item, str) and item, f"{path}: expected non-empty strings")
    return tuple(str(item) for item in items)


def _as_mapping(path: str, value: Any, *, non_empty: bool = True) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), f"{path}: expected object")
    if non_empty:
        _require(bool(value), f"{path}: object must not be empty")
    return dict(value)


def _as_float_mapping(path: str, value: Any, *, non_empty: bool = True) -> Mapping[str, float]:
    raw = _as_mapping(path, value, non_empty=non_empty)
    result: dict[str, float] = {}
    for key, item in raw.items():
        _require(isinstance(key, str) and key, f"{path}: expected non-empty string keys")
        result[key] = _as_float(f"{path}/{key}", item)
    return dict(sorted(result.items()))


def _as_int(path: str, value: Any, *, allow_null: bool = False) -> int | None:
    if value is None and allow_null:
        return None
    _require(isinstance(value, int) and not isinstance(value, bool), f"{path}: expected integer")
    return value


def _as_float(path: str, value: Any) -> float:
    _require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{path}: expected number",
    )
    result = float(value)
    _require(math.isfinite(result), f"{path}: number must be finite")
    return result


def _as_bool(path: str, value: Any) -> bool:
    _require(isinstance(value, bool), f"{path}: expected bool")
    return value


def _as_str(path: str, value: Any) -> str:
    _require(isinstance(value, str) and value != "", f"{path}: expected non-empty string")
    return value


def _validate_timestamp(path: str, value: str) -> None:
    _require(TIMESTAMP_RE.match(value) is not None, f"{path}: timestamp must include Z or offset")
    normalized = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ConfigResolutionError(f"{path}: invalid timestamp {value!r}") from exc


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_version(path: str, value: str) -> None:
    lowered = value.lower()
    _require(lowered not in UNPINNED_VERSION_VALUES, f"{path}: version {value!r} is unpinned")
    _require(VERSION_RE.match(value) is not None, f"{path}: version {value!r} is invalid")


def _walk_values(path: str, value: Any) -> list[tuple[str, Any]]:
    rows = [(path, value)]
    if isinstance(value, Mapping):
        for key, item in value.items():
            rows.extend(_walk_values(f"{path}/{key}", item))
    elif isinstance(value, list) or isinstance(value, tuple):
        for index, item in enumerate(value):
            rows.extend(_walk_values(f"{path}/{index}", item))
    return rows


def _validate_no_current_time_tokens(resolved_groups: Mapping[str, Any]) -> None:
    forbidden = {"now", "current_time", "today", "yesterday", "tomorrow"}
    for path, value in _walk_values("", resolved_groups):
        if isinstance(value, str) and value.lower() in forbidden:
            raise ConfigResolutionError(f"{path}: current-time token {value!r} is forbidden")


def _validate_non_negative_numbers(resolved_groups: Mapping[str, Any]) -> None:
    guarded_tokens = (
        "rate",
        "count",
        "target",
        "population",
        "size",
        "prevalence",
        "fraction",
        "tolerance",
        "alpha",
        "interval_seconds",
        "search_bound",
        "row_group_target_bytes",
    )
    bounded_tokens = ("fraction", "prevalence", "alpha", "honest_rate", "adversarial_rate")
    for path, value in _walk_values("", resolved_groups):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        lowered_path = path.lower()
        if any(token in lowered_path for token in guarded_tokens):
            if value < 0:
                raise ConfigResolutionError(f"{path}: negative numeric value is forbidden")
        if any(token in lowered_path for token in bounded_tokens):
            if not 0 <= float(value) <= 1:
                raise ConfigResolutionError(f"{path}: value must be in [0, 1]")


def _validate_versions(resolved_groups: Mapping[str, Any]) -> None:
    for path, value in _walk_values("", resolved_groups):
        if isinstance(value, str) and (
            path.endswith("_version")
            or "/version" in path
            or path.endswith("version")
            or "container_version" in path
        ):
            _validate_version(path, value)


def _validate_enum_list(path: str, values: tuple[str, ...], allowed: tuple[str, ...]) -> None:
    allowed_set = set(allowed)
    for value in values:
        if value not in allowed_set:
            raise ConfigResolutionError(f"{path}: unknown enum value {value!r}")


def _validate_enum_mapping_keys(path: str, values: Mapping[str, Any], allowed: tuple[str, ...]) -> None:
    allowed_set = set(allowed)
    for key in values:
        if key not in allowed_set:
            raise ConfigResolutionError(f"{path}: unknown enum key {key!r}")


def _build_groups(resolved: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    run = RunConfig(
        contract_version=_as_str("/run/contract_version", resolved["run"]["contract_version"]),
        code_version=_as_str("/run/code_version", resolved["run"]["code_version"]),
        container_version=_as_str("/run/container_version", resolved["run"]["container_version"]),
        run_id=_as_str("/run/run_id", resolved["run"]["run_id"]),
        scenario_id=_as_str("/run/scenario_id", resolved["run"]["scenario_id"]),
        selected_scenario_ids=_as_str_tuple("/run/selected_scenario_ids", resolved["run"]["selected_scenario_ids"]),
        replicate_count=_as_int("/run/replicate_count", resolved["run"]["replicate_count"]) or 0,
        root_seed=_as_str("/run/root_seed", resolved["run"]["root_seed"]),
        horizon_start=_as_str("/run/horizon_start", resolved["run"]["horizon_start"]),
        horizon_end=_as_str("/run/horizon_end", resolved["run"]["horizon_end"]),
        time_zone=_as_str("/run/time_zone", resolved["run"]["time_zone"]),
        calibration_profile_id=_as_str("/run/calibration_profile_id", resolved["run"]["calibration_profile_id"]),
        policy_profile_id=_as_str("/run/policy_profile_id", resolved["run"]["policy_profile_id"]),
    )
    claim_scale = ClaimScaleConfig(
        represented_population=_as_int("/claim_scale/represented_population", resolved["claim_scale"]["represented_population"]) or 0,
        materialized_row_target=_as_int("/claim_scale/materialized_row_target", resolved["claim_scale"]["materialized_row_target"]) or 0,
        executed_operation_target=_as_int("/claim_scale/executed_operation_target", resolved["claim_scale"]["executed_operation_target"], allow_null=True),
        aggregation_semantics=_as_str("/claim_scale/aggregation_semantics", resolved["claim_scale"]["aggregation_semantics"]),
        replay_semantics=_as_str("/claim_scale/replay_semantics", resolved["claim_scale"]["replay_semantics"]),
        estimator_eligible=_as_bool("/claim_scale/estimator_eligible", resolved["claim_scale"]["estimator_eligible"]),
        scale_claim_allowed=_as_bool("/claim_scale/scale_claim_allowed", resolved["claim_scale"]["scale_claim_allowed"]),
        operational_claim_allowed=_as_bool("/claim_scale/operational_claim_allowed", resolved["claim_scale"]["operational_claim_allowed"]),
    )
    world = WorldConfig(
        regions=_as_str_tuple("/world/regions", resolved["world"]["regions"]),
        jurisdictions=_as_str_tuple("/world/jurisdictions", resolved["world"]["jurisdictions"]),
        actor_relationship_counts=_as_mapping("/world/actor_relationship_counts", resolved["world"]["actor_relationship_counts"]),
        cohorts=tuple(_as_tuple("/world/cohorts", resolved["world"]["cohorts"])),
        organizations=tuple(_as_tuple("/world/organizations", resolved["world"]["organizations"])),
        fault_domains=_as_str_tuple("/world/fault_domains", resolved["world"]["fault_domains"]),
        trust_domains=_as_str_tuple("/world/trust_domains", resolved["world"]["trust_domains"]),
    )
    physical = PhysicalConfig(
        backend=_as_str("/physical/backend", resolved["physical"]["backend"]),
        backend_version=_as_str("/physical/backend_version", resolved["physical"]["backend_version"]),
        calibration_bundle_id=_as_str("/physical/calibration_bundle_id", resolved["physical"]["calibration_bundle_id"]),
        calibration_source_ids=_as_str_tuple("/physical/calibration_source_ids", resolved["physical"]["calibration_source_ids"]),
        conditioning_variables=_as_str_tuple("/physical/conditioning_variables", resolved["physical"]["conditioning_variables"]),
        interval_seconds=_as_int("/physical/interval_seconds", resolved["physical"]["interval_seconds"]) or 0,
        units=_as_mapping("/physical/units", resolved["physical"]["units"]),
        meter_error_profile_id=_as_str("/physical/meter_error_profile_id", resolved["physical"]["meter_error_profile_id"]),
        solver_backend=_as_str("/physical/solver_backend", resolved["physical"]["solver_backend"]),
        solver_tolerances=_as_mapping("/physical/solver_tolerances", resolved["physical"]["solver_tolerances"]),
    )
    catalog = CatalogConfig(
        database_profiles=_as_str_tuple("/catalog/database_profiles", resolved["catalog"]["database_profiles"]),
        object_profiles=_as_str_tuple("/catalog/object_profiles", resolved["catalog"]["object_profiles"]),
        replica_profiles=_as_str_tuple("/catalog/replica_profiles", resolved["catalog"]["replica_profiles"]),
        retention_profiles=_as_str_tuple("/catalog/retention_profiles", resolved["catalog"]["retention_profiles"]),
        security_profiles=_as_str_tuple("/catalog/security_profiles", resolved["catalog"]["security_profiles"]),
        derivation_rules=_as_str_tuple("/catalog/derivation_rules", resolved["catalog"]["derivation_rules"]),
    )
    arrivals = ArrivalsConfig(
        model_classes=_as_str_tuple("/arrivals/model_classes", resolved["arrivals"]["model_classes"]),
        base_rates_per_day=_as_mapping("/arrivals/base_rates_per_day", resolved["arrivals"]["base_rates_per_day"]),
        diurnal_profile_id=_as_str("/arrivals/diurnal_profile_id", resolved["arrivals"]["diurnal_profile_id"]),
        weekday_profile_id=_as_str("/arrivals/weekday_profile_id", resolved["arrivals"]["weekday_profile_id"]),
        scenario_factors=_as_mapping("/arrivals/scenario_factors", resolved["arrivals"]["scenario_factors"]),
        conditioned_total=_as_int("/arrivals/conditioned_total", resolved["arrivals"]["conditioned_total"], allow_null=True),
        hawkes_parameters=_as_mapping("/arrivals/hawkes_parameters", resolved["arrivals"]["hawkes_parameters"], non_empty=False),
        mmpp_parameters=_as_mapping("/arrivals/mmpp_parameters", resolved["arrivals"]["mmpp_parameters"], non_empty=False),
    )
    workflows = WorkflowsConfig(
        definition_versions=_as_mapping("/workflows/definition_versions", resolved["workflows"]["definition_versions"]),
        families=_as_str_tuple("/workflows/families", resolved["workflows"]["families"]),
        transition_probability_profile_id=_as_str("/workflows/transition_probability_profile_id", resolved["workflows"]["transition_probability_profile_id"]),
        delay_model_id=_as_str("/workflows/delay_model_id", resolved["workflows"]["delay_model_id"]),
        resource_profile_id=_as_str("/workflows/resource_profile_id", resolved["workflows"]["resource_profile_id"]),
        mix_profile_id=_as_str("/workflows/mix_profile_id", resolved["workflows"]["mix_profile_id"]),
        open_horizon_policy=_as_str("/workflows/open_horizon_policy", resolved["workflows"]["open_horizon_policy"]),
    )
    policy = PolicyConfig(
        profile_id=_as_str("/policy/profile_id", resolved["policy"]["profile_id"]),
        profile_version=_as_str("/policy/profile_version", resolved["policy"]["profile_version"]),
        rule_source_ids=_as_str_tuple("/policy/rule_source_ids", resolved["policy"]["rule_source_ids"]),
        conflict_strategy=_as_str("/policy/conflict_strategy", resolved["policy"]["conflict_strategy"]),
        golden_suite_id=_as_str("/policy/golden_suite_id", resolved["policy"]["golden_suite_id"]),
        evaluator_profile=_as_str("/policy/evaluator_profile", resolved["policy"]["evaluator_profile"]),
        golden_decision_accuracy_target=_as_float(
            "/policy/golden_decision_accuracy_target",
            resolved["policy"]["golden_decision_accuracy_target"],
        ),
        rule_trace_coverage_target=_as_float(
            "/policy/rule_trace_coverage_target",
            resolved["policy"]["rule_trace_coverage_target"],
        ),
        conflict_resolution_agreement_target=_as_float(
            "/policy/conflict_resolution_agreement_target",
            resolved["policy"]["conflict_resolution_agreement_target"],
        ),
    )
    anomaly = AnomalyConfig(
        types=_as_str_tuple("/anomaly/types", resolved["anomaly"]["types"], non_empty=False),
        prevalence=_as_float_mapping("/anomaly/prevalence", resolved["anomaly"]["prevalence"], non_empty=False),
        oversampling_strategy=_as_str("/anomaly/oversampling_strategy", resolved["anomaly"]["oversampling_strategy"]),
        invariant_registry_id=_as_str("/anomaly/invariant_registry_id", resolved["anomaly"]["invariant_registry_id"]),
        invariant_registry_version=_as_str("/anomaly/invariant_registry_version", resolved["anomaly"]["invariant_registry_version"]),
        invariant_registry_sha256=_as_str("/anomaly/invariant_registry_sha256", resolved["anomaly"]["invariant_registry_sha256"]),
        target_invariant_ids=_as_str_tuple("/anomaly/target_invariant_ids", resolved["anomaly"]["target_invariant_ids"], non_empty=False),
        protected_invariant_ids=_as_str_tuple("/anomaly/protected_invariant_ids", resolved["anomaly"]["protected_invariant_ids"], non_empty=False),
        edit_grammar_id=_as_str("/anomaly/edit_grammar_id", resolved["anomaly"]["edit_grammar_id"]),
        edit_grammar_version=_as_str("/anomaly/edit_grammar_version", resolved["anomaly"]["edit_grammar_version"]),
        edit_grammar_sha256=_as_str("/anomaly/edit_grammar_sha256", resolved["anomaly"]["edit_grammar_sha256"]),
        cost_model_id=_as_str("/anomaly/cost_model_id", resolved["anomaly"]["cost_model_id"]),
        cost_model_version=_as_str("/anomaly/cost_model_version", resolved["anomaly"]["cost_model_version"]),
        acceptance_profile_id=_as_str("/anomaly/acceptance_profile_id", resolved["anomaly"]["acceptance_profile_id"]),
        baseline_profile_ids=_as_str_tuple("/anomaly/baseline_profile_ids", resolved["anomaly"]["baseline_profile_ids"]),
        search_bound=_as_int("/anomaly/search_bound", resolved["anomaly"]["search_bound"]) or 0,
    )
    evidence = EvidenceConfig(
        obligation_template_bundle_id=_as_str(
            "/evidence/obligation_template_bundle_id",
            resolved["evidence"]["obligation_template_bundle_id"],
        ),
        obligation_template_bundle_version=_as_str(
            "/evidence/obligation_template_bundle_version",
            resolved["evidence"]["obligation_template_bundle_version"],
        ),
        obligation_template_bundle_sha256=_as_str(
            "/evidence/obligation_template_bundle_sha256",
            resolved["evidence"]["obligation_template_bundle_sha256"],
        ),
        obligation_template_ids=_as_str_tuple("/evidence/obligation_template_ids", resolved["evidence"]["obligation_template_ids"]),
        sufficiency_profile_id=_as_str(
            "/evidence/sufficiency_profile_id",
            resolved["evidence"]["sufficiency_profile_id"],
        ),
        receipt_profile_bundle_id=_as_str(
            "/evidence/receipt_profile_bundle_id",
            resolved["evidence"]["receipt_profile_bundle_id"],
        ),
        receipt_profile_bundle_version=_as_str(
            "/evidence/receipt_profile_bundle_version",
            resolved["evidence"]["receipt_profile_bundle_version"],
        ),
        receipt_profile_bundle_sha256=_as_str(
            "/evidence/receipt_profile_bundle_sha256",
            resolved["evidence"]["receipt_profile_bundle_sha256"],
        ),
        canonicalization_profile_id=_as_str(
            "/evidence/canonicalization_profile_id",
            resolved["evidence"]["canonicalization_profile_id"],
        ),
        receipt_profiles=_as_str_tuple("/evidence/receipt_profiles", resolved["evidence"]["receipt_profiles"]),
        anchor_profiles=_as_str_tuple("/evidence/anchor_profiles", resolved["evidence"]["anchor_profiles"], non_empty=False),
        honest_rate=_as_float("/evidence/honest_rate", resolved["evidence"]["honest_rate"]),
        adversarial_rate=_as_float("/evidence/adversarial_rate", resolved["evidence"]["adversarial_rate"]),
        adversarial_case_weights=_as_float_mapping(
            "/evidence/adversarial_case_weights",
            resolved["evidence"]["adversarial_case_weights"],
        ),
        synthetic_key_profile_id=_as_str("/evidence/synthetic_key_profile_id", resolved["evidence"]["synthetic_key_profile_id"]),
        ml_removal_profile_ids=_as_str_tuple(
            "/evidence/ml_removal_profile_ids",
            resolved["evidence"]["ml_removal_profile_ids"],
            non_empty=False,
        ),
        proof_limit_statement=_as_str("/evidence/proof_limit_statement", resolved["evidence"]["proof_limit_statement"]),
    )
    observer = ObserverConfig(
        profile_bundle_id=_as_str("/observer/profile_bundle_id", resolved["observer"]["profile_bundle_id"]),
        profile_bundle_version=_as_str("/observer/profile_bundle_version", resolved["observer"]["profile_bundle_version"]),
        profile_bundle_sha256=_as_str("/observer/profile_bundle_sha256", resolved["observer"]["profile_bundle_sha256"]),
        visibility_dsl_profile_id=_as_str("/observer/visibility_dsl_profile_id", resolved["observer"]["visibility_dsl_profile_id"]),
        leakage_scan_profile_id=_as_str("/observer/leakage_scan_profile_id", resolved["observer"]["leakage_scan_profile_id"]),
        task_registry_id=_as_str("/observer/task_registry_id", resolved["observer"]["task_registry_id"]),
        observer_profile_ids=_as_str_tuple("/observer/observer_profile_ids", resolved["observer"]["observer_profile_ids"]),
        visibility_profiles=_as_str_tuple("/observer/visibility_profiles", resolved["observer"]["visibility_profiles"]),
        redaction_profiles=_as_str_tuple("/observer/redaction_profiles", resolved["observer"]["redaction_profiles"], non_empty=False),
        delay_profiles=_as_str_tuple("/observer/delay_profiles", resolved["observer"]["delay_profiles"], non_empty=False),
        loss_profiles=_as_str_tuple("/observer/loss_profiles", resolved["observer"]["loss_profiles"], non_empty=False),
        collusion_profiles=_as_str_tuple("/observer/collusion_profiles", resolved["observer"]["collusion_profiles"], non_empty=False),
        forbidden_field_sets=_as_str_tuple("/observer/forbidden_field_sets", resolved["observer"]["forbidden_field_sets"]),
    )
    sampling = SamplingConfig(
        design_types=_as_str_tuple("/sampling/design_types", resolved["sampling"]["design_types"]),
        primary_unit_types=_as_str_tuple("/sampling/primary_unit_types", resolved["sampling"]["primary_unit_types"]),
        strata_definitions=_as_str_tuple("/sampling/strata_definitions", resolved["sampling"]["strata_definitions"]),
        pps_measure=_as_str("/sampling/pps_measure", resolved["sampling"]["pps_measure"]),
        target_sample_size=_as_int("/sampling/target_sample_size", resolved["sampling"]["target_sample_size"]) or 0,
        closure_policy=_as_str("/sampling/closure_policy", resolved["sampling"]["closure_policy"]),
        estimator_families=_as_str_tuple("/sampling/estimator_families", resolved["sampling"]["estimator_families"]),
        common_random_groups=_as_str_tuple("/sampling/common_random_groups", resolved["sampling"]["common_random_groups"], non_empty=False),
        simulation_repetitions=_as_int(
            "/sampling/simulation_repetitions",
            resolved["sampling"]["simulation_repetitions"],
        ) or 0,
        confidence_level=_as_float(
            "/sampling/confidence_level", resolved["sampling"]["confidence_level"]
        ),
        maximum_absolute_relative_bias=_as_float(
            "/sampling/maximum_absolute_relative_bias",
            resolved["sampling"]["maximum_absolute_relative_bias"],
        ),
        minimum_ci_coverage=_as_float(
            "/sampling/minimum_ci_coverage",
            resolved["sampling"]["minimum_ci_coverage"],
        ),
    )
    configured_check_ids = _as_str_tuple(
        "/validation/required_check_ids",
        resolved["validation"]["required_check_ids"],
    )
    try:
        required_check_ids = resolve_required_check_ids(configured_check_ids)
    except ValidationProfileContractError as exc:
        raise ConfigResolutionError(f"/validation/required_check_ids: {exc}") from exc
    validation = ValidationConfig(
        required_check_ids=required_check_ids,
        metric_threshold_profile_id=_as_str("/validation/metric_threshold_profile_id", resolved["validation"]["metric_threshold_profile_id"]),
        repetition_count=_as_int("/validation/repetition_count", resolved["validation"]["repetition_count"]) or 0,
        alpha=_as_float("/validation/alpha", resolved["validation"]["alpha"]),
        confidence_interval_method=_as_str("/validation/confidence_interval_method", resolved["validation"]["confidence_interval_method"]),
        multiplicity_correction=_as_str("/validation/multiplicity_correction", resolved["validation"]["multiplicity_correction"]),
    )
    output = OutputConfig(
        release_profile_id=_as_str("/output/release_profile_id", resolved["output"]["release_profile_id"]),
        output_profile_id=_as_str("/output/output_profile_id", resolved["output"]["output_profile_id"]),
        schema_contract_id=_as_str("/output/schema_contract_id", resolved["output"]["schema_contract_id"]),
        schema_contract_fingerprint=_as_str("/output/schema_contract_fingerprint", resolved["output"]["schema_contract_fingerprint"]),
        dictionary_version=_as_str("/output/dictionary_version", resolved["output"]["dictionary_version"]),
        parquet_compression=_as_str("/output/parquet_compression", resolved["output"]["parquet_compression"]),
        partition_keys=_as_str_tuple("/output/partition_keys", resolved["output"]["partition_keys"]),
        row_group_target_bytes=_as_int("/output/row_group_target_bytes", resolved["output"]["row_group_target_bytes"]) or 0,
        adapters=_as_str_tuple("/output/adapters", resolved["output"]["adapters"], non_empty=False),
        access_classes=_as_str_tuple("/output/access_classes", resolved["output"]["access_classes"]),
        manifest_policy=_as_str("/output/manifest_policy", resolved["output"]["manifest_policy"]),
        archive_policy=_as_str("/output/archive_policy", resolved["output"]["archive_policy"]),
        table_schema_ids=_as_str_tuple("/output/table_schema_ids", resolved["output"]["table_schema_ids"]),
    )
    return {
        "run": run,
        "claim_scale": claim_scale,
        "world": world,
        "physical": physical,
        "catalog": catalog,
        "arrivals": arrivals,
        "workflows": workflows,
        "policy": policy,
        "anomaly": anomaly,
        "evidence": evidence,
        "observer": observer,
        "sampling": sampling,
        "validation": validation,
        "output": output,
    }


def _validate_controlled_synthetic_physical_profile(
    physical: PhysicalConfig,
    source_labels: Mapping[str, str],
) -> None:
    if physical.backend in DEFERRED_EXTERNAL_PHYSICAL_BACKENDS:
        replacement = DEFERRED_EXTERNAL_PHYSICAL_BACKENDS[physical.backend]
        raise ConfigResolutionError(
            f"/physical/backend: external integration {physical.backend!r} is deferred and "
            f"unsupported; use controlled synthetic profile {replacement!r} without "
            "external-backend claims"
        )
    _require(
        physical.backend in CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES,
        f"/physical/backend: unsupported physical profile {physical.backend!r}; current "
        "project supports controlled procedural synthetic profiles only",
    )
    expected_version, expected_analytic_backend = CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES[
        physical.backend
    ]
    _require(
        physical.backend_version == expected_version,
        f"/physical/backend_version: profile {physical.backend!r} requires "
        f"{expected_version!r}",
    )
    _require(
        physical.solver_backend == expected_analytic_backend,
        f"/physical/solver_backend: profile {physical.backend!r} requires controlled "
        f"analytic backend {expected_analytic_backend!r}; external solver execution is deferred",
    )
    controlled_paths = (
        "/run/calibration_profile_id",
        *(f"/physical/{field_name}" for field_name in GROUP_FIELDS["physical"]),
    )
    incorrectly_labelled = tuple(
        path for path in controlled_paths if source_labels.get(path) != "controlled_synthetic"
    )
    _require(
        not incorrectly_labelled,
        "/physical: controlled synthetic profile requires source=controlled_synthetic for "
        f"all physical values; invalid paths={incorrectly_labelled}",
    )
    _require(
        physical.calibration_bundle_id.startswith(
            CONTROLLED_SYNTHETIC_CALIBRATION_PREFIX
        ),
        "/physical/calibration_bundle_id: controlled procedural output requires a "
        f"{CONTROLLED_SYNTHETIC_CALIBRATION_PREFIX!r} identifier",
    )
    invalid_sources = tuple(
        source_id
        for source_id in physical.calibration_source_ids
        if not source_id.startswith(CONTROLLED_SYNTHETIC_SOURCE_PREFIX)
    )
    _require(
        not invalid_sources,
        "/physical/calibration_source_ids: real or external source IDs are forbidden until "
        f"a transformation and license-bound adapter is implemented; invalid={invalid_sources}",
    )


def _validate_cross_references(
    groups: Mapping[str, Any],
    contract: ContractSpec,
    source_labels: Mapping[str, str],
) -> Mapping[str, str]:
    run: RunConfig = groups["run"]
    claim_scale: ClaimScaleConfig = groups["claim_scale"]
    physical: PhysicalConfig = groups["physical"]
    arrivals: ArrivalsConfig = groups["arrivals"]
    workflows: WorkflowsConfig = groups["workflows"]
    policy: PolicyConfig = groups["policy"]
    anomaly: AnomalyConfig = groups["anomaly"]
    evidence: EvidenceConfig = groups["evidence"]
    observer: ObserverConfig = groups["observer"]
    sampling: SamplingConfig = groups["sampling"]
    validation: ValidationConfig = groups["validation"]
    output: OutputConfig = groups["output"]

    _require(run.contract_version == contract.contract_version, "/run/contract_version: does not match schema contract")
    _require(run.scenario_id in run.selected_scenario_ids, "/run/scenario_id: must be selected")
    _require(run.replicate_count > 0, "/run/replicate_count: must be positive")
    _validate_timestamp("/run/horizon_start", run.horizon_start)
    _validate_timestamp("/run/horizon_end", run.horizon_end)
    _require(_timestamp_value(run.horizon_start) < _timestamp_value(run.horizon_end), "/run: horizon_start must be before horizon_end")
    _require(run.time_zone == "UTC" or "/" in run.time_zone, "/run/time_zone: must be UTC or an IANA-like zone")

    _require(claim_scale.represented_population > 0, "/claim_scale/represented_population: must be positive")
    _require(claim_scale.materialized_row_target > 0, "/claim_scale/materialized_row_target: must be positive")
    if claim_scale.executed_operation_target is not None:
        _require(claim_scale.executed_operation_target >= 0, "/claim_scale/executed_operation_target: must be non-negative")
    _require(
        claim_scale.materialized_row_target <= claim_scale.represented_population,
        "/claim_scale: materialized_row_target cannot exceed represented_population",
    )
    if claim_scale.executed_operation_target is None:
        _require(
            not claim_scale.operational_claim_allowed,
            "/claim_scale: operational claims require executed_operation_target",
        )

    _require(physical.calibration_bundle_id == run.calibration_profile_id, "/physical/calibration_bundle_id: must match run calibration_profile_id")
    _validate_controlled_synthetic_physical_profile(physical, source_labels)
    _require(policy.profile_id == run.policy_profile_id, "/policy/profile_id: must match run policy_profile_id")
    _require(
        policy.conflict_strategy == "priority_then_specificity",
        "/policy/conflict_strategy: only priority_then_specificity is supported",
    )
    _require(
        policy.evaluator_profile == "safe_declarative_v1",
        "/policy/evaluator_profile: only safe_declarative_v1 is supported",
    )
    for field_name, target in (
        ("golden_decision_accuracy_target", policy.golden_decision_accuracy_target),
        ("rule_trace_coverage_target", policy.rule_trace_coverage_target),
        ("conflict_resolution_agreement_target", policy.conflict_resolution_agreement_target),
    ):
        _require(0.0 <= target <= 1.0, f"/policy/{field_name}: must be in [0, 1]")

    _validate_enum_list("/physical/backend", (physical.backend,), contract.dictionary_values("physical_backend"))
    _validate_enum_list("/arrivals/model_classes", arrivals.model_classes, contract.dictionary_values("arrival_model_class"))
    _validate_enum_mapping_keys("/arrivals/base_rates_per_day", arrivals.base_rates_per_day, contract.dictionary_values("event_family"))
    _validate_enum_mapping_keys("/workflows/definition_versions", workflows.definition_versions, contract.dictionary_values("workflow_type"))
    _validate_enum_list("/workflows/families", workflows.families, contract.dictionary_values("workflow_type"))
    _validate_enum_list("/anomaly/types", anomaly.types, contract.dictionary_values("anomaly_type"))
    _validate_enum_mapping_keys("/anomaly/prevalence", anomaly.prevalence, contract.dictionary_values("anomaly_type"))
    _require(
        set(anomaly.types) == set(anomaly.prevalence),
        "/anomaly: types and prevalence keys must match exactly",
    )
    _require(
        sum(anomaly.prevalence.values()) <= 1.0 + 1e-12,
        "/anomaly/prevalence: total materialized anomaly prevalence cannot exceed 1",
    )
    target_invariant_by_type = {
        "unauthorized_purpose": "INV-PURPOSE-PERMITTED",
        "missing_erasure_propagation": "INV-ERASURE-REPLICA-CLOSURE",
        "premature_deletion": "INV-RETENTION-DUTY-SATISFIED",
        "false_confirmation": "INV-RECEIPT-MATCHES-ACTION",
        "causal_orphan": "INV-CAUSAL-PARENT-REQUIRED",
        "observer_omission": "INV-OBSERVER-REQUIRED-EVIDENCE-VISIBLE",
        "cross_region_rule_breach": "INV-CROSS-REGION-PERMISSION",
        "clock_replay_conflict": "INV-RECORDED-TIME-CAUSAL-ORDER",
    }
    _require(
        set(anomaly.target_invariant_ids) == set(target_invariant_by_type.values()),
        "/anomaly/target_invariant_ids: must contain exactly one target for every controlled anomaly type",
    )
    _require(
        not (set(anomaly.target_invariant_ids) & set(anomaly.protected_invariant_ids)),
        "/anomaly: target and globally protected invariant IDs must be disjoint",
    )
    _require(anomaly.oversampling_strategy == "paired_counterfactual_weighted", "/anomaly/oversampling_strategy: unsupported strategy")
    _require(anomaly.invariant_registry_id == "INVARIANT-REGISTRY-GOVERNANCE-v1", "/anomaly/invariant_registry_id: unsupported registry")
    _require(anomaly.edit_grammar_id == "EDIT-GRAMMAR-GOVERNANCE-v1", "/anomaly/edit_grammar_id: unsupported grammar")
    _require(anomaly.cost_model_id == "EDIT-COST-v1", "/anomaly/cost_model_id: unsupported cost model")
    _require(anomaly.acceptance_profile_id == "COUNTERFACTUAL-STRICT-TARGET-ONLY-v1", "/anomaly/acceptance_profile_id: unsupported acceptance profile")
    _require(
        anomaly.baseline_profile_ids == (
            "BASELINE-SEEDED-RANDOM-FIELD-CORRUPTION-v1",
            "BASELINE-SEEDED-RANDOM-INVALID-TRANSITION-v1",
        ),
        "/anomaly/baseline_profile_ids: must pin both separate deterministic baselines in order",
    )
    _require(anomaly.search_bound > 0, "/anomaly/search_bound: must be positive")
    for field_name, digest in (
        ("invariant_registry_sha256", anomaly.invariant_registry_sha256),
        ("edit_grammar_sha256", anomaly.edit_grammar_sha256),
    ):
        _require(
            re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"/anomaly/{field_name}: must be a lowercase SHA-256 digest",
        )
    _validate_enum_list("/evidence/receipt_profiles", evidence.receipt_profiles, contract.dictionary_values("evidence_type"))
    _require(
        re.fullmatch(r"[0-9a-f]{64}", evidence.obligation_template_bundle_sha256) is not None,
        "/evidence/obligation_template_bundle_sha256: must be a lowercase SHA-256 digest",
    )
    _require(
        re.fullmatch(r"[0-9a-f]{64}", evidence.receipt_profile_bundle_sha256) is not None,
        "/evidence/receipt_profile_bundle_sha256: must be a lowercase SHA-256 digest",
    )
    _require(
        abs((evidence.honest_rate + evidence.adversarial_rate) - 1.0) <= 1e-12,
        "/evidence: honest_rate and adversarial_rate must sum to 1",
    )
    expected_adversarial_cases = {
        "invalid",
        "late",
        "malformed",
        "contradictory",
        "forged_under_synthetic_key",
        "incomplete",
        "missing_dependency",
    }
    _require(
        set(evidence.adversarial_case_weights) == expected_adversarial_cases,
        "/evidence/adversarial_case_weights: must define exactly the seven controlled fixture cases",
    )
    _require(
        all(weight > 0.0 for weight in evidence.adversarial_case_weights.values()),
        "/evidence/adversarial_case_weights: every controlled case must have positive weight",
    )
    _require(
        abs(sum(evidence.adversarial_case_weights.values()) - 1.0) <= 1e-12,
        "/evidence/adversarial_case_weights: weights must sum to 1",
    )
    _require(
        not evidence.ml_removal_profile_ids,
        "/evidence/ml_removal_profile_ids: model-removal evidence requires a separately pinned model/input contract",
    )
    _validate_enum_list("/observer/visibility_profiles", observer.visibility_profiles, contract.dictionary_values("visibility_class"))
    _require(observer.profile_bundle_id == "OBSERVER-PROFILES-REFERENCE-v1", "/observer/profile_bundle_id: unsupported bundle")
    _require(observer.visibility_dsl_profile_id == "OBSERVER-VISIBILITY-DSL-v1", "/observer/visibility_dsl_profile_id: unsupported DSL")
    _require(observer.leakage_scan_profile_id == "OBSERVER-NONLEAKAGE-STRICT-v1", "/observer/leakage_scan_profile_id: unsupported scanner")
    _require(observer.task_registry_id == "OBSERVER-RESEARCH-TASKS-v1", "/observer/task_registry_id: unsupported task registry")
    _require(
        re.fullmatch(r"[0-9a-f]{64}", observer.profile_bundle_sha256) is not None,
        "/observer/profile_bundle_sha256: must be a lowercase SHA-256 digest",
    )
    _require(
        observer.observer_profile_ids == (
            "OBS-FULL-EVALUATOR",
            "OBS-DSO-DIRECT",
            "OBS-AUDITOR-DELAYED",
            "OBS-PUBLIC-LOSSY",
            "OBS-ADVERSARIAL-OMISSION",
            "OBS-COLLUSION-UTILITY-AUDITOR",
        ),
        "/observer/observer_profile_ids: must pin all six observer modes in dependency order",
    )
    _require(
        set(observer.visibility_profiles) == set(contract.dictionary_values("visibility_class")),
        "/observer/visibility_profiles: must cover every locked visibility class",
    )
    _require(observer.redaction_profiles == ("REDACT-TRUTH-LABELS-v1",), "/observer/redaction_profiles: unsupported profiles")
    _require(observer.delay_profiles == ("DELAY-NONE-v1", "DELAY-OBSERVER-v1"), "/observer/delay_profiles: unsupported profiles")
    _require(observer.loss_profiles == ("LOSS-NONE-v1", "LOSS-LOW-v1", "LOSS-PUBLIC-v1"), "/observer/loss_profiles: unsupported profiles")
    _require(observer.collusion_profiles == ("COLLUSION-UTILITY-AUDITOR-v1",), "/observer/collusion_profiles: unsupported profiles")
    _require(
        observer.forbidden_field_sets == (
            "FORBID-TRUTH-LABELS",
            "FORBID-PAIR-IDS",
            "FORBID-SEALED-IDS",
            "FORBID-SAMPLING-PROBABILITIES",
        ),
        "/observer/forbidden_field_sets: must pin the strict non-leakage sets in order",
    )
    _validate_enum_list("/sampling/design_types", sampling.design_types, contract.dictionary_values("design_type"))
    _validate_enum_list("/sampling/primary_unit_types", sampling.primary_unit_types, contract.dictionary_values("primary_unit_type"))
    _validate_enum_list("/sampling/closure_policy", (sampling.closure_policy,), contract.dictionary_values("closure_policy"))
    _validate_enum_list("/sampling/estimator_families", sampling.estimator_families, contract.dictionary_values("estimator_family"))
    _require(
        set(sampling.estimator_families) <= {"Horvitz_Thompson", "Hajek"},
        "/sampling/estimator_families: population sampling supports only Horvitz_Thompson and Hajek",
    )
    _require(sampling.target_sample_size > 0, "/sampling/target_sample_size: must be positive")
    _require(
        sampling.simulation_repetitions >= 100,
        "/sampling/simulation_repetitions: at least 100 repeated designs are required",
    )
    _require(
        0 < sampling.confidence_level < 1,
        "/sampling/confidence_level: must be in (0, 1)",
    )
    _require(
        0 <= sampling.maximum_absolute_relative_bias < 1,
        "/sampling/maximum_absolute_relative_bias: must be in [0, 1)",
    )
    _require(
        0 < sampling.minimum_ci_coverage <= sampling.confidence_level,
        "/sampling/minimum_ci_coverage: must be positive and no greater than confidence_level",
    )
    _require(
        sampling.pps_measure in {"represented_event_count", "represented_measure", "unit_count"},
        "/sampling/pps_measure: unsupported controlled measure",
    )
    stratum_units: list[str] = []
    for definition in sampling.strata_definitions:
        _require(
            "=" in definition and definition.count("=") == 1,
            "/sampling/strata_definitions: each definition must use unit_type=field[:field]",
        )
        unit_type, expression = definition.split("=", 1)
        _require(
            unit_type in contract.dictionary_values("primary_unit_type"),
            f"/sampling/strata_definitions: unknown unit type {unit_type!r}",
        )
        fields = expression.split(":")
        _require(
            bool(expression) and all(field and field.replace("_", "").isalnum() for field in fields),
            f"/sampling/strata_definitions: invalid controlled expression {expression!r}",
        )
        stratum_units.append(unit_type)
    _require(
        len(stratum_units) == len(set(stratum_units)),
        "/sampling/strata_definitions: duplicate primary-unit definition",
    )
    _require(
        set(stratum_units) == set(sampling.primary_unit_types),
        "/sampling/strata_definitions: must define every and only configured primary unit type",
    )
    if "nested_common_random_numbers" in sampling.design_types:
        _require(
            bool(sampling.common_random_groups),
            "/sampling/common_random_groups: nested design requires a pinned CRN group",
        )
    _validate_enum_list("/output/access_classes", output.access_classes, contract.dictionary_values("privacy_class"))

    _require(validation.repetition_count == run.replicate_count, "/validation/repetition_count: must equal run replicate_count")
    _require(0 < validation.alpha < 1, "/validation/alpha: must be in (0, 1)")
    missing_workflow_versions = tuple(
        family for family in workflows.families if family not in workflows.definition_versions
    )
    _require(
        not missing_workflow_versions,
        f"/workflows/definition_versions: missing selected workflow families {missing_workflow_versions}",
    )

    expected_schema_ids = tuple(table.schema_id for table in contract.tables)
    _require(output.schema_contract_id == contract.contract_id, "/output/schema_contract_id: unknown schema contract")
    _require(output.schema_contract_fingerprint == contract.contract_fingerprint, "/output/schema_contract_fingerprint: mismatch")
    _require(output.dictionary_version == contract.contract_version, "/output/dictionary_version: must match contract version")
    _require(output.table_schema_ids == expected_schema_ids, "/output/table_schema_ids: must list every locked schema in contract order")
    _require(output.parquet_compression.upper() == "ZSTD", "/output/parquet_compression: authoritative output must use ZSTD")
    _require(output.row_group_target_bytes > 0, "/output/row_group_target_bytes: must be positive")
    _require(
        not output.output_profile_id.lower().endswith("jsonl"),
        "/output/output_profile_id: JSONL cannot be an authoritative output profile",
    )
    normalized_adapters = tuple(adapter.lower() for adapter in output.adapters)
    _require(
        normalized_adapters == output.adapters,
        "/output/adapters: adapter IDs must be lowercase controlled values",
    )
    _require(
        len(normalized_adapters) == len(set(normalized_adapters)),
        "/output/adapters: duplicate adapter IDs are forbidden",
    )
    _require(
        "jsonl" not in normalized_adapters,
        "/output/adapters: bare jsonl is ambiguous; use jsonl_debug_view for non-authoritative compatibility output",
    )
    for adapter in normalized_adapters:
        if adapter == "jsonl" or adapter.startswith("jsonl_"):
            _require(
                adapter == JSONL_COMPATIBILITY_ADAPTER,
                "/output/adapters: JSONL adapters must be named jsonl_debug_view and remain non-authoritative",
            )
    unknown_adapters = sorted(set(normalized_adapters) - INTEROPERABILITY_ADAPTERS)
    _require(
        not unknown_adapters,
        f"/output/adapters: unknown interoperability adapters {unknown_adapters}",
    )

    return {
        "schema_contract_id": contract.contract_id,
        "schema_contract_fingerprint": contract.contract_fingerprint,
        "calibration_profile_id": run.calibration_profile_id,
        "policy_profile_id": run.policy_profile_id,
        "output_profile_id": output.output_profile_id,
    }


def _validate_resolved_groups(
    resolved_groups: Mapping[str, Mapping[str, Any]],
    groups: Mapping[str, Any],
    contract: ContractSpec,
    source_labels: Mapping[str, str],
) -> Mapping[str, str]:
    _validate_no_current_time_tokens(resolved_groups)
    _validate_non_negative_numbers(resolved_groups)
    _validate_versions(resolved_groups)
    return _validate_cross_references(groups, contract, source_labels)


def compute_config_sha256(resolved_without_digest: Mapping[str, Any]) -> str:
    """Compute the deterministic digest for an already normalized config dict."""

    data = copy.deepcopy(dict(resolved_without_digest))
    data.pop("config_sha256", None)
    data.pop("source_path", None)
    return _sha256_json(data)


def build_run_plan(resolved: ResolvedConfig) -> tuple[ResolvedRunPlan, ...]:
    """Build one immutable run-plan row for every selected scenario and replicate."""

    plans: list[ResolvedRunPlan] = []
    for scenario_id in resolved.run.selected_scenario_ids:
        for replicate_id in range(resolved.run.replicate_count):
            plans.append(
                ResolvedRunPlan(
                    run_id=resolved.run.run_id,
                    scenario_id=scenario_id,
                    replicate_id=replicate_id,
                    config_sha256=resolved.config_sha256,
                )
            )
    return tuple(plans)


def resolve_config(
    raw_config: Mapping[str, Any],
    *,
    contract: ContractSpec | None = None,
    source_path: str | os.PathLike[str] | None = None,
) -> ResolvedConfig:
    """Resolve and validate a raw JSON configuration into an immutable run plan."""

    schema_contract = contract if contract is not None else load_contract()
    observed_groups = set(raw_config.keys())
    expected_groups = set(GROUP_ORDER)
    missing_groups = sorted(expected_groups - observed_groups)
    extra_groups = sorted(observed_groups - expected_groups)
    if missing_groups:
        raise ConfigResolutionError(f"config missing groups {missing_groups}")
    if extra_groups:
        raise ConfigResolutionError(f"config has unknown groups {extra_groups}")

    source_labels: dict[str, str] = {}
    resolved_groups = {
        group: _unwrap_group(group, raw_config[group], source_labels)
        for group in GROUP_ORDER
    }
    groups = _build_groups(resolved_groups)
    references = _validate_resolved_groups(
        resolved_groups, groups, schema_contract, source_labels
    )

    provisional = ResolvedConfig(
        run=groups["run"],
        claim_scale=groups["claim_scale"],
        world=groups["world"],
        physical=groups["physical"],
        catalog=groups["catalog"],
        arrivals=groups["arrivals"],
        workflows=groups["workflows"],
        policy=groups["policy"],
        anomaly=groups["anomaly"],
        evidence=groups["evidence"],
        observer=groups["observer"],
        sampling=groups["sampling"],
        validation=groups["validation"],
        output=groups["output"],
        source_labels=dict(sorted(source_labels.items())),
        resolved_references=dict(sorted(references.items())),
        config_sha256="",
        source_path=str(source_path) if source_path is not None else None,
    )
    digest = compute_config_sha256(provisional.as_dict(include_digest=False))
    return ResolvedConfig(
        run=provisional.run,
        claim_scale=provisional.claim_scale,
        world=provisional.world,
        physical=provisional.physical,
        catalog=provisional.catalog,
        arrivals=provisional.arrivals,
        workflows=provisional.workflows,
        policy=provisional.policy,
        anomaly=provisional.anomaly,
        evidence=provisional.evidence,
        observer=provisional.observer,
        sampling=provisional.sampling,
        validation=provisional.validation,
        output=provisional.output,
        source_labels=provisional.source_labels,
        resolved_references=provisional.resolved_references,
        config_sha256=digest,
        source_path=provisional.source_path,
    )


def resolve_config_file(path: str | os.PathLike[str], *, contract: ContractSpec | None = None) -> ResolvedConfig:
    """Load and resolve a JSON config file."""

    return resolve_config(load_config(path), contract=contract, source_path=path)
