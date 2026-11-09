"""Versioned Appendix-A metric registry with fail-closed threshold discipline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from htgl_dataset_generator.schemas import ContractSpec, load_contract

from .models import MetricDefinition, MetricRegistry


REGISTRY_FORMAT = "htgl.metric-registry.v1"
DEFAULT_REGISTRY_PATH = Path(__file__).with_name("metric_registry_v1.json")
KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
UNCERTAINTY_POLICIES = frozenset(
    {"replicate_aggregate", "design_simulation", "not_applicable"}
)
REQUIREMENT_TYPES = frozenset(
    {
        "generated_artifacts",
        "validation_ledger",
        "physical_calibration_reference",
        "privacy_source_reference",
        "artifact_verification",
        "reproducibility_reference",
        "performance_observation",
    }
)
THRESHOLD_BASES = frozenset(
    {"controlled_engineering_requirement", "calibrated_from_source", "theory"}
)

METRIC_APPLICABILITY_RULES: Mapping[str, str] = {
    "meter_energy_wasserstein": "external_physical_reference",
    "meter_energy_ks": "external_physical_reference",
    "acf_error_l1": "external_physical_reference",
    "peak_timing_distance": "external_physical_reference",
    "load_factor_error": "external_physical_reference",
    "network_solver_convergence_rate": "external_solver_execution",
    "actor_degree_distance": "external_topology_reference",
    "custody_component_distribution": "external_topology_reference",
    "replica_count_distance": "external_topology_reference",
    "workflow_duration_distance": "external_workflow_reference",
    "cross_excitation_error": "hawkes_arrival_mode",
    "mmpp_regime_occupancy_error": "mmpp_arrival_mode",
    "target_violation_success": "anomaly_instances_present",
    "collateral_violation_rate": "anomaly_instances_present",
    "counterfactual_edit_cost": "anomaly_instances_present",
    "pair_non_target_predictability": "anomaly_instances_present",
    "obligation_coverage": "evidence_obligations_present",
    "sufficiency_precision_recall": "evidence_obligations_present",
    "receipt_validity_rate": "evidence_receipts_present",
    "receipt_timeliness_rate": "evidence_receipts_present",
    "contradiction_detection_rate": "contradictory_receipt_fixtures_present",
    "verification_cost": "evidence_obligations_present",
    "visible_event_coverage": "non_full_observers_present",
    "visible_edge_coverage": "non_full_observers_present",
    "evidence_recoverability": "non_full_observers_present",
    "collusion_gain": "collusion_profile_present",
    "effective_sample_size": "probability_design_present",
    "closure_expansion_factor": "probability_design_present",
    "weight_reconciliation_error": "probability_design_present",
    "design_effect": "probability_design_present",
    "relative_bias_known_total": "known_total_simulation_present",
    "ci_coverage": "known_total_simulation_present",
    "rmse_known_total": "known_total_simulation_present",
    "rare_trace_exposure": "non_full_observers_present",
    "exact_duplicate_rate": "external_privacy_reference",
    "nearest_neighbor_ratio": "external_privacy_reference",
    "membership_inference_auc": "external_privacy_reference",
    "attribute_inference_gain": "external_privacy_reference",
    "generation_rows_per_second": "performance_observation_present",
    "peak_resident_memory_bytes": "performance_observation_present",
    "stored_bytes_per_event": "performance_observation_present",
    "parallel_efficiency": "performance_observation_present",
    "row_group_efficiency": "performance_observation_present",
    "stage_stored_bytes_per_row": "performance_observation_present",
}


class MetricRegistryError(ValueError):
    """Raised when metric metadata could create an ambiguous publication claim."""


def load_metric_registry(
    path: str | Path | None = None,
    *,
    contract: ContractSpec | None = None,
) -> MetricRegistry:
    registry_path = Path(path).resolve() if path is not None else DEFAULT_REGISTRY_PATH
    payload = registry_path.read_bytes()
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise MetricRegistryError(f"invalid metric registry JSON {registry_path}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise MetricRegistryError("metric registry root must be an object")
    _exact_keys(
        raw,
        {"registry_format", "registry_id", "version", "source", "definitions"},
        "metric registry",
    )
    if raw["registry_format"] != REGISTRY_FORMAT:
        raise MetricRegistryError(f"registry_format must be {REGISTRY_FORMAT}")
    definitions_raw = raw["definitions"]
    if not isinstance(definitions_raw, list) or not definitions_raw:
        raise MetricRegistryError("metric registry definitions must be a non-empty list")
    schema_contract = contract if contract is not None else load_contract()
    allowed_domains = set(schema_contract.dictionary_values("metric_domain"))
    allowed_weighting = set(schema_contract.dictionary_values("metric_weighting"))
    definitions: dict[str, MetricDefinition] = {}
    required = {
        "metric_key", "domain", "definition", "direction", "unit", "estimator",
        "weighting", "scope_contract", "denominator_contract", "uncertainty_policy",
        "requires",
    }
    for index, item in enumerate(definitions_raw):
        if not isinstance(item, Mapping):
            raise MetricRegistryError(f"definitions[{index}] must be an object")
        unknown = set(item) - (required | {"threshold"})
        missing = required - set(item)
        if missing or unknown:
            raise MetricRegistryError(
                f"definitions[{index}] key mismatch missing={sorted(missing)} unknown={sorted(unknown)}"
            )
        key = _string(item["metric_key"], f"definitions[{index}].metric_key")
        if KEY_RE.fullmatch(key) is None:
            raise MetricRegistryError(f"invalid metric_key={key!r}")
        if key in definitions:
            raise MetricRegistryError(f"duplicate metric_key={key!r}")
        domain = _string(item["domain"], f"{key}.domain")
        weighting = _string(item["weighting"], f"{key}.weighting")
        uncertainty = _string(item["uncertainty_policy"], f"{key}.uncertainty_policy")
        requirement = _string(item["requires"], f"{key}.requires")
        if domain not in allowed_domains:
            raise MetricRegistryError(f"{key}: unknown metric domain {domain!r}")
        if weighting not in allowed_weighting:
            raise MetricRegistryError(f"{key}: unknown metric weighting {weighting!r}")
        if uncertainty not in UNCERTAINTY_POLICIES:
            raise MetricRegistryError(f"{key}: unknown uncertainty policy {uncertainty!r}")
        if requirement not in REQUIREMENT_TYPES:
            raise MetricRegistryError(f"{key}: unknown evidence requirement {requirement!r}")
        if "threshold" in item:
            _validate_threshold(key, item["threshold"])
        definitions[key] = MetricDefinition(
            metric_key=key,
            domain=domain,
            definition=_string(item["definition"], f"{key}.definition"),
            direction=_string(item["direction"], f"{key}.direction"),
            unit=_string(item["unit"], f"{key}.unit"),
            estimator=_string(item["estimator"], f"{key}.estimator"),
            weighting=weighting,
            scope_contract=_string(item["scope_contract"], f"{key}.scope_contract"),
            denominator_contract=_string(
                item["denominator_contract"], f"{key}.denominator_contract"
            ),
            uncertainty_policy=uncertainty,
            requires=requirement,
            applicability=METRIC_APPLICABILITY_RULES.get(key, "always"),
        )
    observed_domains = {item.domain for item in definitions.values()}
    mandatory_domains = {
        "physical", "temporal", "topology", "workflow", "policy", "anomaly",
        "evidence", "observer", "sampling", "privacy", "artifact", "performance",
    }
    missing_domains = sorted(mandatory_domains - observed_domains)
    if missing_domains:
        raise MetricRegistryError(f"registry omits mandatory domains {missing_domains}")
    return MetricRegistry(
        registry_id=_string(raw["registry_id"], "registry_id"),
        version=_string(raw["version"], "version"),
        source=_string(raw["source"], "source"),
        sha256=hashlib.sha256(payload).hexdigest(),
        definitions=dict(sorted(definitions.items())),
    )


def _validate_threshold(metric_key: str, value: Any) -> None:
    if not isinstance(value, Mapping):
        raise MetricRegistryError(f"{metric_key}.threshold must be an object")
    _exact_keys(value, {"operator", "value", "basis", "source_id"}, f"{metric_key}.threshold")
    basis = _string(value["basis"], f"{metric_key}.threshold.basis")
    if basis not in THRESHOLD_BASES:
        raise MetricRegistryError(
            f"{metric_key}: arbitrary threshold basis {basis!r} is prohibited"
        )
    _string(value["operator"], f"{metric_key}.threshold.operator")
    _string(value["source_id"], f"{metric_key}.threshold.source_id")
    if not isinstance(value["value"], (int, float)) or isinstance(value["value"], bool):
        raise MetricRegistryError(f"{metric_key}.threshold.value must be numeric")


def _exact_keys(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        raise MetricRegistryError(
            f"{location} key mismatch missing={sorted(missing)} unknown={sorted(unknown)}"
        )


def _string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MetricRegistryError(f"{location} must be a non-empty string")
    return value
