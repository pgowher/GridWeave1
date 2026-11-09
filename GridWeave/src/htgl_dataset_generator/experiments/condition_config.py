"""Compile one factor-study cell into a fully resolved immutable run config."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from htgl_dataset_generator.config import ResolvedConfig, resolve_config

from .study_models import StudyCondition


class ConditionConfigError(ValueError):
    """Raised when a study condition cannot become a valid generator config."""


WORKFLOW_RATE_WEIGHTS: Mapping[str, Mapping[str, float]] = {
    "consent_only": {"consent": 1.0, "access": 0.0, "disclosure": 0.0, "erasure": 0.0, "audit": 0.0, "incident": 0.0},
    "balanced_rights": {"consent": 0.38, "access": 0.16, "disclosure": 0.16, "erasure": 0.12, "audit": 0.10, "incident": 0.08},
    "erasure_heavy": {"consent": 0.15, "access": 0.10, "disclosure": 0.10, "erasure": 0.45, "audit": 0.10, "incident": 0.10},
    "incident_heavy": {"consent": 0.12, "access": 0.08, "disclosure": 0.10, "erasure": 0.10, "audit": 0.15, "incident": 0.45},
}


def compile_condition_config(
    base: ResolvedConfig,
    condition: StudyCondition,
    *,
    study_id: str,
) -> ResolvedConfig:
    """Return a resolver-validated condition config while preserving CRN semantics."""

    if condition.feasibility_status != "eligible":
        raise ConditionConfigError(
            f"condition {condition.condition_id} is not executable: {condition.feasibility_reasons}"
        )
    raw = _raw_from_resolved(base)
    values = condition.factor_values
    required = {
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
    }
    missing = sorted(required - set(values))
    if missing:
        raise ConditionConfigError(f"condition lacks controlling factors {missing}")
    _set(raw, "run", "run_id", f"{study_id}-{condition.condition_id}")
    _set(raw, "run", "replicate_count", condition.repetitions)
    _set(raw, "claim_scale", "represented_population", condition.represented_population_N)
    _set(raw, "claim_scale", "materialized_row_target", condition.materialized_row_target_n)
    _set(raw, "claim_scale", "executed_operation_target", condition.executed_operation_target_q)
    _set(raw, "claim_scale", "operational_claim_allowed", False)
    _set(raw, "claim_scale", "replay_semantics", "weighted_analytic_only_no_downstream_execution")

    region_count = _positive_int(values["region_count"], "region_count")
    regions = [f"R-STUDY-{index + 1:02d}" for index in range(region_count)]
    jurisdictions = [f"J-STUDY-{index + 1:02d}" for index in range(region_count)]
    _set(raw, "world", "regions", regions)
    _set(raw, "world", "jurisdictions", jurisdictions)
    _set(raw, "world", "fault_domains", [f"FD-STUDY-{index + 1:02d}" for index in range(region_count)])
    _set(raw, "world", "trust_domains", ["TD-UTILITY", "TD-MARKET", "TD-OVERSIGHT"])
    _set(raw, "world", "cohorts", _cohorts(condition.represented_population_N, regions))
    _set(raw, "world", "organizations", _organizations(region_count))
    _set(
        raw,
        "world",
        "actor_relationship_counts",
        _relationship_counts(region_count, str(values["organization_graph_density"])),
    )

    backend_value = str(values["physical_backend"])
    backend = backend_value
    backend_versions = {
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
    if backend not in backend_versions:
        raise ConditionConfigError(f"unsupported executable physical backend {backend_value!r}")
    backend_version, solver_backend = backend_versions[backend]
    _set(raw, "physical", "backend", backend)
    _set(raw, "physical", "backend_version", backend_version)
    _set(raw, "physical", "solver_backend", solver_backend)

    arrival_model = str(values["arrival_model"])
    _set(raw, "arrivals", "model_classes", [arrival_model])
    conditioned_total = (
        condition.materialized_row_target_n
        if arrival_model in {"conditioned_NHPP", "MMPP"}
        else None
    )
    _set(raw, "arrivals", "conditioned_total", conditioned_total)
    mix = str(values["workflow_mix"])
    if mix not in WORKFLOW_RATE_WEIGHTS:
        raise ConditionConfigError(f"unsupported workflow mix {mix!r}")
    _set(raw, "workflows", "mix_profile_id", f"MIX-{mix.upper().replace('_', '-')}-v1")
    _set(
        raw,
        "arrivals",
        "base_rates_per_day",
        _scaled_arrival_rates(base, condition, WORKFLOW_RATE_WEIGHTS[mix], arrival_model),
    )
    _set(raw, "arrivals", "mmpp_parameters", _mmpp_parameters())
    _set(raw, "arrivals", "hawkes_parameters", _hawkes_parameters(WORKFLOW_RATE_WEIGHTS[mix]))

    prevalence = float(values["anomaly_prevalence"])
    if not 0.0 <= prevalence <= 1.0:
        raise ConditionConfigError("anomaly_prevalence must be in [0, 1]")
    anomaly_types = tuple(base.anomaly.types)
    per_type = prevalence / len(anomaly_types) if anomaly_types else 0.0
    _set(raw, "anomaly", "prevalence", {item: per_type for item in anomaly_types})

    sampling_profile = str(values["sampling_profile"])
    if sampling_profile == "cluster_pps":
        designs = ["cluster", "PPS", "nested_common_random_numbers"]
        estimator_eligible = True
    elif sampling_profile == "stratified":
        designs = ["stratified", "nested_common_random_numbers"]
        estimator_eligible = True
    elif sampling_profile == "naive_srs_truncation":
        designs = ["stratified"]
        estimator_eligible = False
    else:
        raise ConditionConfigError(f"unsupported sampling profile {sampling_profile!r}")
    _set(raw, "sampling", "design_types", designs)
    _set(raw, "sampling", "common_random_groups", [condition.common_random_group])
    _set(raw, "claim_scale", "estimator_eligible", estimator_eligible)
    _set(raw, "claim_scale", "scale_claim_allowed", estimator_eligible)
    _set(raw, "validation", "repetition_count", condition.repetitions)
    return resolve_config(raw, source_path=f"factorial-study:{study_id}:{condition.condition_id}")


def _raw_from_resolved(resolved: ResolvedConfig) -> dict[str, dict[str, dict[str, Any]]]:
    plain = resolved.as_dict(include_digest=False)
    groups: dict[str, dict[str, dict[str, Any]]] = {}
    for group_name in (
        "run", "claim_scale", "world", "physical", "catalog", "arrivals", "workflows",
        "policy", "anomaly", "evidence", "observer", "sampling", "validation", "output",
    ):
        fields: dict[str, dict[str, Any]] = {}
        for field_name, value in plain[group_name].items():
            path = f"/{group_name}/{field_name}"
            try:
                source = resolved.source_labels[path]
            except KeyError as exc:
                raise ConditionConfigError(f"base resolved config lacks source label {path}") from exc
            fields[field_name] = {"value": value, "source": source}
        groups[group_name] = fields
    return groups


def _set(raw: dict[str, dict[str, dict[str, Any]]], group: str, field: str, value: Any) -> None:
    if group not in raw or field not in raw[group]:
        raise ConditionConfigError(f"cannot override unknown resolved field /{group}/{field}")
    raw[group][field] = {"value": value, "source": "controlled_synthetic"}


def _cohorts(total: int, regions: list[str]) -> list[dict[str, Any]]:
    quotient, remainder = divmod(total, len(regions))
    return [
        {
            "cohort_id": f"COHORT-STUDY-{index + 1:02d}",
            "region_id": region,
            "represented_count": quotient + (1 if index < remainder else 0),
            "dwelling_type": ("urban", "suburban", "rural")[index % 3],
            "subject_scope": "household",
        }
        for index, region in enumerate(regions)
    ]


def _organizations(region_count: int) -> list[dict[str, str]]:
    classes = ("dso", "tso", "supplier", "aggregator", "regulator", "vendor", "auditor", "processor")
    return [
        {"organization_id": f"ORG-STUDY-{actor_class.upper()}-0001", "actor_class": actor_class}
        for actor_class in classes
    ]


def _relationship_counts(region_count: int, density: str) -> dict[str, int]:
    multiplier = {"sparse": 1, "medium": 4, "dense": 16}.get(density)
    if multiplier is None:
        raise ConditionConfigError(f"unknown organization graph density {density!r}")
    base = max(1, region_count * multiplier)
    return {
        "controls": base,
        "processes_for": base * 2,
        "supplies": base,
        "aggregates": base,
        "oversees": max(1, base // 2),
        "audits": max(1, base // 4),
        "discloses_to": base * 2,
    }


def _scaled_arrival_rates(
    base: ResolvedConfig,
    condition: StudyCondition,
    weights: Mapping[str, float],
    arrival_model: str,
) -> dict[str, float]:
    start = datetime.fromisoformat(base.run.horizon_start.replace("Z", "+00:00"))
    end = datetime.fromisoformat(base.run.horizon_end.replace("Z", "+00:00"))
    horizon_days = (end - start).total_seconds() / 86_400.0
    if horizon_days <= 0.0:
        raise ConditionConfigError("base horizon must be positive")
    target_fraction = 1.0 if arrival_model in {"conditioned_NHPP", "MMPP"} else 0.35
    total_rate = (
        condition.materialized_row_target_n
        * target_fraction
        / condition.represented_population_N
        / horizon_days
    )
    normalized = sum(weights.values())
    return {
        family: total_rate * float(weights.get(family, 0.0)) / normalized
        for family in base.arrivals.base_rates_per_day
    }


def _mmpp_parameters() -> dict[str, Any]:
    return {
        "states": ["normal", "stress", "incident"],
        "initial_distribution": {"normal": 0.8, "stress": 0.15, "incident": 0.05},
        "state_rate_multipliers": {"normal": 0.75, "stress": 1.5, "incident": 3.0},
        "generator_matrix": [[-0.3, 0.24, 0.06], [0.4, -0.6, 0.2], [0.5, 0.5, -1.0]],
    }


def _hawkes_parameters(weights: Mapping[str, float]) -> dict[str, Any]:
    active = tuple(family for family, weight in weights.items() if weight > 0.0)
    branching: dict[str, dict[str, float]] = {}
    for family in weights:
        branching[family] = {}
        if family in active:
            branching[family][family] = 0.12
            if len(active) > 1:
                next_family = active[(active.index(family) + 1) % len(active)]
                branching[family][next_family] = 0.03
    return {
        "kernel": "exponential.v1",
        "mean_delay_seconds": 600.0,
        "branching": branching,
        "background_fraction": 0.8,
        "spectral_radius_bound": 0.8,
    }


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConditionConfigError(f"{name} must be a positive integer")
    return value
