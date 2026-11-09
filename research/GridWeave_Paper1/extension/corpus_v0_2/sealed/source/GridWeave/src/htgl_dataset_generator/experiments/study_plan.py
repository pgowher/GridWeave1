"""Deterministic full-factorial and budgeted pairwise study planning."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from itertools import combinations, product
from math import ceil, prod
from statistics import NormalDist
from typing import Iterable, Mapping, Sequence

from htgl_dataset_generator.artifacts.canonical import domain_sha256
from htgl_dataset_generator.seeds import content_id

from .study_models import (
    FactorAxis,
    FactorLevel,
    FactorialStudyPlan,
    FactorialStudyRegistry,
    PrecisionJustification,
    StudyCondition,
    StudyResourceBudget,
)
from .study_registry import load_factorial_study_registry


class StudyPlanningError(ValueError):
    """Raised when a requested study is ambiguous, underpowered, or over budget."""


DEFAULT_CAPABILITIES = frozenset(
    {
        "paired_counterfactual_oversampling",
        "physical_procedural",
        "physical_opensynth_style_synthetic",
        "physical_smart_ds_style_synthetic",
    }
)


def default_study_resource_budget() -> StudyResourceBudget:
    """Return conservative explicit engineering limits for study planning."""

    return StudyResourceBudget(
        maximum_conditions=512,
        maximum_replicates=15_360,
        maximum_materialized_rows_per_replicate=1_000_000,
        maximum_total_materialized_rows=2_000_000_000,
        maximum_total_stored_bytes=4_000_000_000_000,
        stored_bytes_per_materialized_row_upper_bound=2_000,
        capabilities=DEFAULT_CAPABILITIES,
    )


def full_factorial_condition_count(
    registry: FactorialStudyRegistry,
    selected_level_ids: Mapping[str, Sequence[str]] | None = None,
) -> int:
    axes = _selected_axes(registry, selected_level_ids)
    return prod(len(axis.levels) for axis in axes)


def required_repetition_count(
    requested_repetitions: int,
    precision_justification: PrecisionJustification | None,
) -> int:
    if requested_repetitions < 1:
        raise StudyPlanningError("requested_repetitions must be positive")
    if requested_repetitions >= 30:
        return 30
    if precision_justification is None:
        raise StudyPlanningError(
            "fewer than 30 repetitions requires a pinned power/precision justification"
        )
    item = precision_justification
    if item.method != "normal_half_width_v1":
        raise StudyPlanningError("precision method must be normal_half_width_v1")
    if not 0.0 < item.confidence_level < 1.0:
        raise StudyPlanningError("precision confidence_level must be in (0, 1)")
    if item.target_half_width <= 0.0 or item.pilot_standard_deviation < 0.0:
        raise StudyPlanningError("precision half-width must be positive and pilot deviation non-negative")
    if item.pilot_repetitions < 2:
        raise StudyPlanningError("precision justification requires at least two pilot repetitions")
    if item.source_label not in {
        "controlled_synthetic",
        "calibrated_from_source",
        "imported_template",
        "publication_derived",
        "deployment_measured",
    }:
        raise StudyPlanningError("precision justification has an unknown source label")
    if not item.source_id.strip():
        raise StudyPlanningError("precision justification requires a non-empty source_id")
    z_score = NormalDist().inv_cdf(0.5 + item.confidence_level / 2.0)
    computed = max(
        1,
        ceil((z_score * item.pilot_standard_deviation / item.target_half_width) ** 2),
    )
    if requested_repetitions < computed:
        raise StudyPlanningError(
            f"requested_repetitions={requested_repetitions} is below precision-derived requirement={computed}"
        )
    return computed


def build_factorial_study_plan(
    study_id: str,
    *,
    design_mode: str = "pairwise_covering",
    requested_repetitions: int = 30,
    precision_justification: PrecisionJustification | None = None,
    selected_level_ids: Mapping[str, Sequence[str]] | None = None,
    resource_budget: StudyResourceBudget | None = None,
    executed_operation_target_q: int | None = None,
    registry: FactorialStudyRegistry | None = None,
) -> FactorialStudyPlan:
    """Resolve a deterministic study matrix without concealing infeasible cells."""

    if not study_id or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for character in study_id):
        raise StudyPlanningError("study_id must be a non-empty path-safe ASCII identifier")
    if executed_operation_target_q is not None and executed_operation_target_q < 0:
        raise StudyPlanningError("executed_operation_target_q cannot be negative")
    factor_registry = registry or load_factorial_study_registry()
    budget = resource_budget or default_study_resource_budget()
    _validate_budget(budget)
    required_repetitions = required_repetition_count(
        requested_repetitions, precision_justification
    )
    axes = _selected_axes(factor_registry, selected_level_ids)
    factorial_count = prod(len(axis.levels) for axis in axes)
    if design_mode == "full_factorial":
        if factorial_count > budget.maximum_conditions:
            raise StudyPlanningError(
                f"full factorial has {factorial_count} conditions, exceeding explicit "
                f"maximum_conditions={budget.maximum_conditions}; increase the declared budget "
                "or use pairwise_covering without calling it full factorial"
            )
        level_tuples = tuple(product(*(axis.levels for axis in axes)))
        pair_requirements = _pair_requirements(axes)
        design_statement = "complete Cartesian factorial over every selected factor level"
    elif design_mode == "pairwise_covering":
        level_tuples, pair_requirements = _pairwise_covering_rows(axes)
        if len(level_tuples) > budget.maximum_conditions:
            raise StudyPlanningError(
                f"pairwise covering requires {len(level_tuples)} conditions, exceeding "
                f"maximum_conditions={budget.maximum_conditions}"
            )
        design_statement = (
            "deterministic reduced pairwise-covering design; not a full factorial and not "
            "eligible for unqualified higher-order interaction claims"
        )
    else:
        raise StudyPlanningError("design_mode must be full_factorial or pairwise_covering")

    conditions: list[StudyCondition] = []
    consumed_replicates = 0
    consumed_rows = 0
    for ordinal, levels in enumerate(level_tuples):
        by_axis = {axis.axis_id: level for axis, level in zip(axes, levels, strict=True)}
        n_represented = _integer_level(by_axis, "represented_population_N")
        n_materialized = _integer_level(by_axis, "materialized_row_target_n")
        projected_rows = n_materialized * requested_repetitions
        projected_bytes = projected_rows * budget.stored_bytes_per_materialized_row_upper_bound
        reasons = _cell_feasibility_reasons(
            levels,
            n_represented=n_represented,
            n_materialized=n_materialized,
            projected_rows=projected_rows,
            projected_bytes=projected_bytes,
            budget=budget,
        )
        if consumed_replicates + requested_repetitions > budget.maximum_replicates:
            reasons.append("global_replicate_budget_exceeded")
        if consumed_rows + projected_rows > budget.maximum_total_materialized_rows:
            reasons.append("global_materialized_row_budget_exceeded")
        feasible = not reasons
        structurally_ineligible = bool(reasons) and set(reasons) == {
            "materialized_target_n_exceeds_represented_population_N"
        }
        if feasible:
            consumed_replicates += requested_repetitions
            consumed_rows += projected_rows
        factor_ids = {axis.axis_id: level.level_id for axis, level in zip(axes, levels, strict=True)}
        factor_values = {axis.axis_id: level.value for axis, level in zip(axes, levels, strict=True)}
        condition_id = content_id(
            "factorial-study-condition",
            {
                "study_id": study_id,
                "registry_sha256": factor_registry.sha256,
                "factor_level_ids": factor_ids,
                "repetitions": requested_repetitions,
                "q_target": executed_operation_target_q,
            },
        )
        conditions.append(
            StudyCondition(
                condition_id=condition_id,
                ordinal=ordinal,
                factor_level_ids=dict(sorted(factor_ids.items())),
                factor_values=dict(sorted(factor_values.items())),
                represented_population_N=n_represented,
                materialized_row_target_n=n_materialized,
                executed_operation_target_q=executed_operation_target_q,
                repetitions=requested_repetitions,
                common_random_group=f"{study_id}-CRN-v1",
                estimator_eligible=all(level.claim_eligible for level in levels),
                feasibility_status=(
                    "eligible"
                    if feasible
                    else ("structurally_ineligible" if structurally_ineligible else "blocked")
                ),
                feasibility_reasons=tuple(sorted(set(reasons))),
                projected_materialized_rows=projected_rows,
                projected_stored_bytes_upper_bound=projected_bytes,
            )
        )
    covered = _covered_pair_requirements(axes, level_tuples)
    condition_payload = [asdict(condition) for condition in conditions]
    plan_payload = {
        "study_id": study_id,
        "registry_sha256": factor_registry.sha256,
        "design_mode": design_mode,
        "requested_repetitions": requested_repetitions,
        "required_repetitions": required_repetitions,
        "precision_justification": asdict(precision_justification) if precision_justification else None,
        "full_factorial_condition_count": factorial_count,
        "pairwise_requirement_count": len(pair_requirements),
        "pairwise_covered_count": len(covered),
        "conditions": condition_payload,
    }
    return FactorialStudyPlan(
        study_id=study_id,
        registry=factor_registry,
        design_mode=design_mode,
        design_scope_statement=design_statement,
        requested_repetitions=requested_repetitions,
        required_repetitions=required_repetitions,
        precision_justification=precision_justification,
        full_factorial_condition_count=factorial_count,
        selected_condition_count=len(conditions),
        pairwise_requirement_count=len(pair_requirements),
        pairwise_covered_count=len(covered),
        conditions=tuple(conditions),
        plan_sha256=domain_sha256("P8-factorial-study-plan", plan_payload),
    )


def _selected_axes(
    registry: FactorialStudyRegistry,
    selected: Mapping[str, Sequence[str]] | None,
) -> tuple[FactorAxis, ...]:
    requested = selected or {}
    unknown_axes = sorted(set(requested) - {axis.axis_id for axis in registry.axes})
    if unknown_axes:
        raise StudyPlanningError(f"unknown selected factor axes {unknown_axes}")
    result: list[FactorAxis] = []
    for axis in registry.axes:
        selected_ids = requested.get(axis.axis_id)
        if selected_ids is None:
            result.append(axis)
            continue
        if not selected_ids or len(selected_ids) != len(set(selected_ids)):
            raise StudyPlanningError(f"{axis.axis_id} selected levels must be non-empty and unique")
        by_id = {level.level_id: level for level in axis.levels}
        unknown = sorted(set(selected_ids) - set(by_id))
        if unknown:
            raise StudyPlanningError(f"{axis.axis_id} has unknown levels {unknown}")
        result.append(
            FactorAxis(
                axis_id=axis.axis_id,
                execution_mode=axis.execution_mode,
                levels=tuple(by_id[level_id] for level_id in selected_ids),
            )
        )
    return tuple(result)


def _pair_requirements(axes: Sequence[FactorAxis]) -> frozenset[tuple[str, str, str, str]]:
    return frozenset(
        (left.axis_id, left_level.level_id, right.axis_id, right_level.level_id)
        for left_index, left in enumerate(axes)
        for right in axes[left_index + 1 :]
        for left_level in left.levels
        for right_level in right.levels
    )


def _covered_pair_requirements(
    axes: Sequence[FactorAxis],
    rows: Iterable[Sequence[FactorLevel]],
) -> frozenset[tuple[str, str, str, str]]:
    covered: set[tuple[str, str, str, str]] = set()
    for row in rows:
        for left_index, right_index in combinations(range(len(axes)), 2):
            covered.add(
                (
                    axes[left_index].axis_id,
                    row[left_index].level_id,
                    axes[right_index].axis_id,
                    row[right_index].level_id,
                )
            )
    return frozenset(covered)


def _pairwise_covering_rows(
    axes: Sequence[FactorAxis],
) -> tuple[tuple[tuple[FactorLevel, ...], ...], frozenset[tuple[str, str, str, str]]]:
    requirements = _pair_requirements(axes)
    if len(axes) < 2:
        rows = tuple((level,) for level in axes[0].levels)
        return rows, requirements
    candidate_map: dict[tuple[str, ...], tuple[FactorLevel, ...]] = {}
    for left_index, right_index in combinations(range(len(axes)), 2):
        for left_level in axes[left_index].levels:
            for right_level in axes[right_index].levels:
                fixed = {left_index: left_level, right_index: right_level}
                seed = hashlib.sha256(
                    f"{axes[left_index].axis_id}:{left_level.level_id}|{axes[right_index].axis_id}:{right_level.level_id}".encode("ascii")
                ).digest()
                row: list[FactorLevel] = []
                for axis_index, axis in enumerate(axes):
                    if axis_index in fixed:
                        row.append(fixed[axis_index])
                    else:
                        offset = int.from_bytes(seed[(axis_index * 2) % 30 : (axis_index * 2) % 30 + 2], "big")
                        row.append(axis.levels[offset % len(axis.levels)])
                candidate = tuple(row)
                candidate_map[tuple(level.level_id for level in candidate)] = candidate
    candidates = tuple(candidate_map[key] for key in sorted(candidate_map))
    coverage = {candidate: _covered_pair_requirements(axes, (candidate,)) for candidate in candidates}
    uncovered = set(requirements)
    selected: list[tuple[FactorLevel, ...]] = []
    while uncovered:
        ranked = sorted(
            candidates,
            key=lambda candidate: (
                -len(coverage[candidate] & uncovered),
                tuple(level.level_id for level in candidate),
            ),
        )
        best = ranked[0]
        gain = coverage[best] & uncovered
        if not gain:
            raise StudyPlanningError("pairwise planner cannot cover the declared factor registry")
        selected.append(best)
        uncovered -= gain
    rows = tuple(sorted(set(selected), key=lambda row: tuple(level.level_id for level in row)))
    if _covered_pair_requirements(axes, rows) != requirements:
        raise StudyPlanningError("pairwise coverage postcondition failed")
    return rows, requirements


def _integer_level(by_axis: Mapping[str, FactorLevel], axis_id: str) -> int:
    value = by_axis[axis_id].value
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise StudyPlanningError(f"{axis_id} must resolve to a positive integer")
    return value


def _cell_feasibility_reasons(
    levels: Sequence[FactorLevel],
    *,
    n_represented: int,
    n_materialized: int,
    projected_rows: int,
    projected_bytes: int,
    budget: StudyResourceBudget,
) -> list[str]:
    reasons: list[str] = []
    if n_materialized > n_represented:
        reasons.append("materialized_target_n_exceeds_represented_population_N")
    if n_materialized > budget.maximum_materialized_rows_per_replicate:
        reasons.append("per_replicate_materialized_row_budget_exceeded")
    if projected_rows > budget.maximum_total_materialized_rows:
        reasons.append("condition_materialized_row_budget_exceeded")
    if projected_bytes > budget.maximum_total_stored_bytes:
        reasons.append("condition_storage_envelope_exceeded")
    for level in levels:
        capability = level.required_capability
        if capability is not None and capability not in budget.capabilities:
            reasons.append(f"missing_capability:{capability}")
    return reasons


def _validate_budget(budget: StudyResourceBudget) -> None:
    numeric = (
        budget.maximum_conditions,
        budget.maximum_replicates,
        budget.maximum_materialized_rows_per_replicate,
        budget.maximum_total_materialized_rows,
        budget.maximum_total_stored_bytes,
        budget.stored_bytes_per_materialized_row_upper_bound,
    )
    if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in numeric):
        raise StudyPlanningError("every resource-budget bound must be a positive integer")
