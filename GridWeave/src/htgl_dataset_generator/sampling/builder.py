"""S12 dependency-closed probability sampler and scale-semantics gate."""

from __future__ import annotations

import hashlib
import math
from statistics import NormalDist
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.baselines.sampling import build_sampling_baselines
from htgl_dataset_generator.catalog import CatalogBuild
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.dag import CausalDagBuild
from htgl_dataset_generator.evidence import EvidenceObligationBuild, EvidenceReceiptBuild
from htgl_dataset_generator.observers import ObserverBuild
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import (
    CounterRng,
    canonical_records_digest,
    deterministic_uuid,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.world import FederatedWorld

from .designs import draw_probability_design, induced_inclusion_probability
from .estimators import effective_sample_size
from .models import (
    ClosureProvenance,
    DependencyClosure,
    KnownTotalDiagnostic,
    SamplingBuild,
    SamplingDesignDiagnostics,
    UnitKey,
)
from .simulation import run_known_total_simulation
from .units import build_dependency_closure, parse_stratum_definitions


SAMPLING_COMPONENT = "S12.sampling"


class SamplingBuildError(ValueError):
    """Raised when probability, closure, estimator, or scale gates fail closed."""


def build_dependency_closed_sample(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    observers: ObserverBuild,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> SamplingBuild:
    """Compile every configured S12 design and reject unsupported estimates."""

    schema_contract = contract if contract is not None else load_contract()
    selected_scenarios = tuple(sorted(scenario_ids or resolved.run.selected_scenario_ids))
    if not selected_scenarios:
        raise SamplingBuildError("at least one scenario_id is required")
    unknown = sorted(set(selected_scenarios) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise SamplingBuildError(f"scenario_ids not selected in config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise SamplingBuildError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    parse_stratum_definitions(resolved.sampling)
    frozen_before = _frozen_digest(
        world, catalog, causal_dag, obligations, receipts, observers, selected_scenarios
    )
    designs: list[dict[str, Any]] = []
    memberships: list[dict[str, Any]] = []
    provenance: list[ClosureProvenance] = []
    known_total: list[KnownTotalDiagnostic] = []
    diagnostics: dict[str, SamplingDesignDiagnostics] = {}
    baselines = []
    metrics: list[dict[str, Any]] = []

    for scenario_id in selected_scenarios:
        streams = _sampling_streams(
            resolved, scenario_id, replicate_id, schema_contract
        )
        standard_stream = streams[None]
        namespace = str(standard_stream["deterministic_id_namespace"])
        standard_rng = CounterRng(str(standard_stream["seed_material_hex"]))
        strata_by_type = parse_stratum_definitions(resolved.sampling)
        scenario_baselines_added: set[str] = set()
        for primary_unit_type in resolved.sampling.primary_unit_types:
            closure = build_dependency_closure(
                scenario_id=scenario_id,
                namespace=namespace,
                sampling_config=resolved.sampling,
                primary_unit_type=primary_unit_type,
                world=world,
                catalog=catalog,
                dag=causal_dag,
                obligations=obligations,
                receipts=receipts,
            )
            for design_type in resolved.sampling.design_types:
                groups: tuple[str | None, ...] = (
                    tuple(resolved.sampling.common_random_groups)
                    if design_type == "nested_common_random_numbers"
                    else (None,)
                )
                for common_group in groups:
                    stream = streams[common_group]
                    rng = CounterRng(str(stream["seed_material_hex"]))
                    scope_prefix = (
                        ""
                        if design_type == "nested_common_random_numbers"
                        else f"scenario={scenario_id}:"
                    )
                    base_label = (
                        f"{scope_prefix}replicate={replicate_id}:unit={primary_unit_type}:"
                        f"design={design_type}:crn={common_group or 'none'}"
                    )
                    actual = draw_probability_design(
                        closure.primary_units,
                        design_type=design_type,
                        target_size=resolved.sampling.target_sample_size,
                        rng=rng,
                        draw_label=f"actual:{base_label}",
                        use_crn_keys=design_type == "nested_common_random_numbers",
                    )
                    if primary_unit_type not in scenario_baselines_added:
                        baselines.extend(
                            build_sampling_baselines(
                                closure,
                                actual,
                                rng=standard_rng,
                                target_size=resolved.sampling.target_sample_size,
                            )
                        )
                        scenario_baselines_added.add(primary_unit_type)
                    for estimator_family in resolved.sampling.estimator_families:
                        sample_design_id = deterministic_uuid(
                            namespace,
                            "sampling_design",
                            {
                                "common_random_group": common_group,
                                "design_type": design_type,
                                "estimator_family": estimator_family,
                                "primary_unit_type": primary_unit_type,
                                "replicate_id": replicate_id,
                                "scenario_id": scenario_id,
                            },
                        )
                        design_row = {
                            "sample_design_id": sample_design_id,
                            "scenario_id": scenario_id,
                            "design_type": design_type,
                            "primary_unit_type": primary_unit_type,
                            "stratum_definition": (
                                f"{primary_unit_type}="
                                + ":".join(strata_by_type[primary_unit_type])
                            ),
                            "target_sample_size": actual.target_size,
                            "closure_policy": resolved.sampling.closure_policy,
                            "estimator_family": estimator_family,
                            "common_random_number_group": common_group,
                            "design_seed_stream": str(stream["stream_name"]),
                        }
                        validate_record(schema_contract, "sampling_design", design_row)
                        design_memberships, design_provenance = _materialize_membership(
                            schema_contract,
                            sample_design_id,
                            closure,
                            actual,
                        )
                        design_diagnostics = _design_diagnostics(
                            sample_design_id,
                            scenario_id,
                            replicate_id,
                            design_type,
                            primary_unit_type,
                            estimator_family,
                            closure,
                            actual,
                            design_memberships,
                        )
                        simulation = run_known_total_simulation(
                            closure,
                            sample_design_id=sample_design_id,
                            simulation_draw_label=base_label,
                            design_type=design_type,
                            target_size=resolved.sampling.target_sample_size,
                            estimator_family=estimator_family,
                            actual_result=actual,
                            rng=rng,
                            repetitions=resolved.sampling.simulation_repetitions,
                            confidence_level=resolved.sampling.confidence_level,
                            maximum_absolute_relative_bias=(
                                resolved.sampling.maximum_absolute_relative_bias
                            ),
                            minimum_ci_coverage=resolved.sampling.minimum_ci_coverage,
                            use_crn_keys=design_type == "nested_common_random_numbers",
                        )
                        failed = [item for item in simulation if not item.passed]
                        if failed:
                            item = failed[0]
                            raise SamplingBuildError(
                                f"{scenario_id}: known-total gate failed design={sample_design_id} "
                                f"domain={item.analysis_domain} relative_bias={item.relative_bias:.6f} "
                                f"coverage={item.ci_coverage:.6f}"
                            )
                        designs.append(design_row)
                        memberships.extend(design_memberships)
                        provenance.extend(design_provenance)
                        known_total.extend(simulation)
                        diagnostics[sample_design_id] = design_diagnostics
                        metrics.extend(
                            _sampling_metrics(
                                resolved,
                                namespace,
                                scenario_id,
                                replicate_id,
                                design_diagnostics,
                                simulation,
                                schema_contract,
                            )
                        )
        metrics.extend(
            _scale_contract_metrics(
                resolved,
                namespace,
                scenario_id,
                replicate_id,
                schema_contract,
            )
        )
        metrics.extend(
            _baseline_metrics(
                resolved,
                namespace,
                scenario_id,
                replicate_id,
                tuple(item for item in baselines if item.scenario_id == scenario_id),
                schema_contract,
            )
        )

    if _frozen_digest(
        world, catalog, causal_dag, obligations, receipts, observers, selected_scenarios
    ) != frozen_before:
        raise SamplingBuildError("frozen world/event/evidence/observer truth mutated during sampling")
    build = SamplingBuild(
        sampling_designs=tuple(sorted(designs, key=lambda row: str(row["sample_design_id"]))),
        sample_memberships=tuple(
            sorted(
                memberships,
                key=lambda row: (
                    str(row["sample_design_id"]),
                    str(row["unit_type"]),
                    str(row["unit_id"]),
                ),
            )
        ),
        closure_provenance=tuple(
            sorted(
                provenance,
                key=lambda item: (item.sample_design_id, item.unit_type, item.unit_id),
            )
        ),
        known_total_diagnostics=tuple(
            sorted(known_total, key=lambda item: (item.sample_design_id, item.analysis_domain))
        ),
        diagnostics=dict(sorted(diagnostics.items())),
        baselines=tuple(
            sorted(baselines, key=lambda item: (item.scenario_id, item.primary_unit_type, item.baseline_id))
        ),
        run_metrics=tuple(sorted(metrics, key=lambda row: str(row["metric_id"]))),
        scale_semantics={
            "represented_population_N": resolved.claim_scale.represented_population,
            "materialized_row_target_n": resolved.claim_scale.materialized_row_target,
            "executed_operation_target_q": resolved.claim_scale.executed_operation_target,
        },
        frozen_input_digest=frozen_before,
    )
    validate_sampling_build(build, resolved, contract=schema_contract)
    return build


def _materialize_membership(
    contract: ContractSpec,
    sample_design_id: str,
    closure: DependencyClosure,
    result: Any,
) -> tuple[tuple[dict[str, Any], ...], tuple[ClosureProvenance, ...]]:
    primary_by_id = {item.key.unit_id: item for item in closure.primary_units}
    selected_primary = set(result.selected_primary_unit_ids)
    selected_members: set[UnitKey] = set()
    for primary_id in sorted(selected_primary):
        selected_members.update(closure.members_by_primary[primary_id])
    rows: list[dict[str, Any]] = []
    provenance: list[ClosureProvenance] = []
    census = (
        len(selected_primary) == len(primary_by_id)
        and all(probability == 1.0 for probability in result.primary_inclusion_probabilities.values())
    )
    for key in sorted(selected_members):
        eligible_causes = closure.causes_by_member[key]
        selected_causes = tuple(sorted(set(eligible_causes) & selected_primary))
        if not selected_causes:
            raise SamplingBuildError(
                f"{sample_design_id}: closure member {key} has no selected cause"
            )
        directly_selected = (
            key.unit_type == closure.primary_unit_type and key.unit_id in selected_primary
        )
        if directly_selected:
            probability = float(result.primary_inclusion_probabilities[key.unit_id])
            reason = "census" if census else "primary_draw"
            primary_unit_id = key.unit_id
        else:
            probability = induced_inclusion_probability(
                result, eligible_causes, primary_by_id
            )
            reason = "closure_added"
            primary_unit_id = selected_causes[0]
        if not (0.0 < probability <= 1.0):
            raise SamplingBuildError(
                f"{sample_design_id}: invalid inclusion probability={probability} for {key}"
            )
        weight = 1.0 / probability
        population = closure.population_units[key]
        row = {
            "sample_design_id": sample_design_id,
            "unit_id": key.unit_id,
            "unit_type": key.unit_type,
            "stratum_id": population.stratum_id,
            "first_order_inclusion_probability": probability,
            "design_weight": weight,
            "selection_reason": reason,
            "primary_unit_id": primary_unit_id,
            "analysis_weight": weight,
            "estimator_eligible": bool(result.exact_inclusion_probabilities),
        }
        validate_record(contract, "sample_membership", row)
        rows.append(row)
        provenance.append(
            ClosureProvenance(
                sample_design_id=sample_design_id,
                unit_id=key.unit_id,
                unit_type=key.unit_type,
                selected_causing_primary_unit_ids=selected_causes,
                eligible_causing_primary_unit_ids=eligible_causes,
                closure_policy=closure.closure_policy,
            )
        )
    return tuple(rows), tuple(provenance)


def _design_diagnostics(
    sample_design_id: str,
    scenario_id: str,
    replicate_id: int,
    design_type: str,
    primary_unit_type: str,
    estimator_family: str,
    closure: DependencyClosure,
    result: Any,
    memberships: Sequence[Mapping[str, Any]],
) -> SamplingDesignDiagnostics:
    primary_rows = tuple(
        row for row in memberships if str(row["selection_reason"]) in {"primary_draw", "census"}
    )
    probabilities = tuple(
        float(row["first_order_inclusion_probability"]) for row in memberships
    )
    ess = effective_sample_size(
        float(row["first_order_inclusion_probability"]) for row in primary_rows
    )
    selected_count = len(result.selected_primary_unit_ids)
    return SamplingDesignDiagnostics(
        sample_design_id=sample_design_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        design_type=design_type,
        primary_unit_type=primary_unit_type,
        estimator_family=estimator_family,
        population_primary_unit_count=len(closure.primary_units),
        selected_primary_unit_count=selected_count,
        membership_count=len(memberships),
        closure_added_count=len(memberships) - len(primary_rows),
        closure_expansion_factor=(len(memberships) - len(primary_rows)) / len(primary_rows),
        effective_sample_size=ess,
        design_effect=selected_count / ess if ess else math.inf,
        minimum_inclusion_probability=min(probabilities),
        maximum_inclusion_probability=max(probabilities),
        exact_induced_probability_count=len(memberships),
        ineligible_membership_count=sum(not bool(row["estimator_eligible"]) for row in memberships),
    )


def _sampling_metrics(
    resolved: ResolvedConfig,
    namespace: str,
    scenario_id: str,
    replicate_id: int,
    diagnostics: SamplingDesignDiagnostics,
    known_total: Sequence[KnownTotalDiagnostic],
    contract: ContractSpec,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for item in known_total:
        z_value = NormalDist().inv_cdf(0.5 + item.confidence_level / 2.0)
        rows.append(
            _metric(
                resolved,
                namespace,
                scenario_id,
                replicate_id,
                f"sampling.{item.sample_design_id}.{item.analysis_domain}.estimate",
                item.actual_estimate,
                "represented_units",
                item.empirical_standard_deviation,
                item.actual_estimate - z_value * item.empirical_standard_deviation,
                item.actual_estimate + z_value * item.empirical_standard_deviation,
                f"{item.estimator_family}_exact_pi_empirical_design_se_v1",
                "HT" if item.estimator_family == "Horvitz_Thompson" else "Hajek",
                "BASELINE-FIRST-N-TRUNCATION",
                contract,
            )
        )
        for metric_name, value, unit in (
            ("known_total_relative_bias", item.relative_bias, "fraction"),
            ("known_total_relative_rmse", item.relative_rmse, "fraction"),
            ("known_total_ci_coverage", item.ci_coverage, "fraction"),
        ):
            rows.append(
                _metric(
                    resolved,
                    namespace,
                    scenario_id,
                    replicate_id,
                    f"sampling.{item.sample_design_id}.{item.analysis_domain}.{metric_name}",
                    value,
                    unit,
                    None,
                    None,
                    None,
                    "repeated_probability_design_known_total_v1",
                    "unweighted",
                    None,
                    contract,
                )
            )
    for metric_name, value, unit in (
        ("effective_sample_size", diagnostics.effective_sample_size, "units"),
        ("design_effect", diagnostics.design_effect, "ratio"),
        ("closure_expansion", diagnostics.closure_expansion_factor, "ratio"),
        ("minimum_inclusion_probability", diagnostics.minimum_inclusion_probability, "probability"),
        ("sample_membership_rows", float(diagnostics.membership_count), "rows"),
    ):
        rows.append(
            _metric(
                resolved,
                namespace,
                scenario_id,
                replicate_id,
                f"sampling.{diagnostics.sample_design_id}.{metric_name}",
                float(value),
                unit,
                None,
                None,
                None,
                "exact_probability_design_diagnostic_v1",
                "unweighted",
                None,
                contract,
            )
        )
    return tuple(rows)


def _scale_contract_metrics(
    resolved: ResolvedConfig,
    namespace: str,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
) -> tuple[dict[str, Any], ...]:
    values = [
        ("scale.represented_population_N", resolved.claim_scale.represented_population),
        ("scale.materialized_row_target_n", resolved.claim_scale.materialized_row_target),
    ]
    if resolved.claim_scale.executed_operation_target is not None:
        values.append(
            ("scale.executed_operation_target_q", resolved.claim_scale.executed_operation_target)
        )
    return tuple(
        _metric(
            resolved,
            namespace,
            scenario_id,
            replicate_id,
            name,
            float(value),
            "count",
            None,
            None,
            None,
            "declared_scale_contract_not_estimate_v1",
            "unweighted",
            None,
            contract,
        )
        for name, value in values
    )


def _baseline_metrics(
    resolved: ResolvedConfig,
    namespace: str,
    scenario_id: str,
    replicate_id: int,
    baselines: Sequence[Any],
    contract: ContractSpec,
) -> tuple[dict[str, Any], ...]:
    return tuple(
        _metric(
            resolved,
            namespace,
            scenario_id,
            replicate_id,
            f"sampling.baseline.{item.primary_unit_type}.{item.baseline_id}.raw_relative_error",
            item.raw_relative_error,
            "fraction",
            None,
            None,
            None,
            "ineligible_sampling_control_no_population_claim_v1",
            "unweighted",
            item.baseline_id,
            contract,
        )
        for item in baselines
    )


def _metric(
    resolved: ResolvedConfig,
    namespace: str,
    scenario_id: str,
    replicate_id: int,
    metric_name: str,
    value: float,
    unit: str,
    standard_error: float | None,
    ci_lower: float | None,
    ci_upper: float | None,
    estimator: str,
    weighting: str,
    baseline_id: str | None,
    contract: ContractSpec,
) -> dict[str, Any]:
    row = {
        "metric_id": deterministic_uuid(
            namespace,
            "run_metric",
            {
                "metric_name": metric_name,
                "replicate_id": replicate_id,
                "scenario_id": scenario_id,
            },
        ),
        "run_id": resolved.run.run_id,
        "scenario_id": scenario_id,
        "replicate_id": replicate_id,
        "metric_domain": "sampling",
        "metric_name": metric_name,
        "value": float(value),
        "unit": unit,
        "standard_error": standard_error,
        "ci_lower": ci_lower,
        "ci_upper": ci_upper,
        "estimator": estimator,
        "weighting": weighting,
        "baseline_id": baseline_id,
    }
    validate_record(contract, "run_metric", row)
    return row


def validate_sampling_build(
    build: SamplingBuild,
    resolved: ResolvedConfig,
    *,
    contract: ContractSpec | None = None,
) -> None:
    """Fail closed on schema, probability, provenance, estimator, and N/n/q semantics."""

    schema_contract = contract if contract is not None else load_contract()
    design_ids: set[str] = set()
    for row in build.sampling_designs:
        validate_record(schema_contract, "sampling_design", row)
        design_id = str(row["sample_design_id"])
        if design_id in design_ids:
            raise SamplingBuildError(f"duplicate sample_design_id={design_id}")
        design_ids.add(design_id)
    memberships_by_design: dict[str, list[Mapping[str, Any]]] = {
        design_id: [] for design_id in design_ids
    }
    membership_keys: set[tuple[str, str, str]] = set()
    for row in build.sample_memberships:
        validate_record(schema_contract, "sample_membership", row)
        design_id = str(row["sample_design_id"])
        if design_id not in design_ids:
            raise SamplingBuildError(f"membership references unknown design={design_id}")
        key = (design_id, str(row["unit_type"]), str(row["unit_id"]))
        if key in membership_keys:
            raise SamplingBuildError(f"duplicate sample membership={key}")
        membership_keys.add(key)
        probability = float(row["first_order_inclusion_probability"])
        if not (0.0 < probability <= 1.0):
            raise SamplingBuildError(f"membership {key}: pi={probability} outside (0,1]")
        expected_weight = 1.0 / probability
        if not math.isclose(float(row["design_weight"]), expected_weight, rel_tol=1e-12):
            raise SamplingBuildError(f"membership {key}: design_weight != 1/pi")
        if not math.isclose(float(row["analysis_weight"]), expected_weight, rel_tol=1e-12):
            raise SamplingBuildError(f"membership {key}: undocumented analysis-weight adjustment")
        if row["primary_unit_id"] is None:
            raise SamplingBuildError(f"membership {key}: closure provenance is missing")
        memberships_by_design[design_id].append(row)
    if any(not rows for rows in memberships_by_design.values()):
        raise SamplingBuildError("every sampling design must emit membership rows")
    provenance_keys = {
        (item.sample_design_id, item.unit_type, item.unit_id)
        for item in build.closure_provenance
    }
    if provenance_keys != membership_keys:
        raise SamplingBuildError("closure provenance does not reconcile with sample membership")
    if any(not item.eligible_causing_primary_unit_ids for item in build.closure_provenance):
        raise SamplingBuildError("closure provenance has an empty eligible-cause set")
    if any(not item.passed for item in build.known_total_diagnostics):
        raise SamplingBuildError("known-total simulation gate failed")
    for row in build.run_metrics:
        validate_record(schema_contract, "run_metric", row)
        is_population_estimate = str(row["metric_name"]).endswith(".estimate")
        if is_population_estimate:
            design_id = str(row["metric_name"]).split(".")[1]
            if design_id not in memberships_by_design or not all(
                bool(item["estimator_eligible"]) for item in memberships_by_design[design_id]
            ):
                raise SamplingBuildError(
                    f"population estimate emitted for ineligible design={design_id}"
                )
    expected_scale = {
        "represented_population_N": resolved.claim_scale.represented_population,
        "materialized_row_target_n": resolved.claim_scale.materialized_row_target,
        "executed_operation_target_q": resolved.claim_scale.executed_operation_target,
    }
    if dict(build.scale_semantics) != expected_scale:
        raise SamplingBuildError("N/n/q scale semantics do not match resolved config")
    if expected_scale["represented_population_N"] == expected_scale["materialized_row_target_n"] and expected_scale["represented_population_N"] >= 100_000_000:
        raise SamplingBuildError("large represented N must not be mislabeled as materialized n")
    if expected_scale["executed_operation_target_q"] is None and any(
        "executed_operation_target_q" in str(row["metric_name"]) for row in build.run_metrics
    ):
        raise SamplingBuildError("q metric emitted although executed_operation_target is undeclared")
    if any(item.estimator_eligible for item in build.baselines):
        raise SamplingBuildError("defective sampling baselines cannot become estimator eligible")


def _sampling_streams(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
) -> Mapping[str | None, Mapping[str, Any]]:
    plan = ResolvedRunPlan(
        resolved.run.run_id,
        scenario_id,
        replicate_id,
        resolved.config_sha256,
    )
    rows = seed_stream_records_for_plan(resolved, plan, contract=contract)
    result: dict[str | None, Mapping[str, Any]] = {}
    standard_suffix = f"component={SAMPLING_COMPONENT}|partition=global"
    for row in rows:
        name = str(row["stream_name"])
        if not name.endswith(standard_suffix):
            continue
        if name.startswith("scenario="):
            result[None] = row
        elif name.startswith("crn="):
            group = name.split("|", 1)[0].split("=", 1)[1]
            result[group] = row
    expected = {None, *resolved.sampling.common_random_groups}
    if set(result) != expected:
        raise SamplingBuildError(
            f"{scenario_id}: S12 seed streams missing expected={sorted(str(x) for x in expected)}"
        )
    return result


def _frozen_digest(
    world: FederatedWorld,
    catalog: CatalogBuild,
    dag: CausalDagBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    observers: ObserverBuild,
    scenario_ids: Sequence[str],
) -> str:
    selected = set(scenario_ids)
    tables = {
        "actor": tuple(row for row in world.actors if str(row["scenario_id"]) in selected),
        "prosumer_cohort": tuple(row for row in world.prosumer_cohorts if str(row["scenario_id"]) in selected),
        "local_database": tuple(row for row in catalog.local_databases if str(row["scenario_id"]) in selected),
        "data_object": tuple(row for row in catalog.data_objects if str(row["scenario_id"]) in selected),
        "data_object_replica": tuple(row for row in catalog.data_object_replicas if str(row["data_object_id"]) in {str(item["data_object_id"]) for item in catalog.data_objects if str(item["scenario_id"]) in selected}),
        "governance_event": tuple(row for row in dag.governance_events if str(row["scenario_id"]) in selected),
        "event_edge": tuple(row for row in dag.event_edges if str(row["scenario_id"]) in selected),
        "workflow_instance": tuple(row for row in dag.workflow_instances if str(row["scenario_id"]) in selected),
        "evidence_obligation": tuple(row for row in obligations.evidence_obligations if str(row["event_id"]) in {str(item["event_id"]) for item in dag.governance_events if str(item["scenario_id"]) in selected}),
        "evidence_receipt": tuple(row for row in receipts.evidence_receipts if str(row["event_id"]) in {str(item["event_id"]) for item in dag.governance_events if str(item["scenario_id"]) in selected}),
        "observer_event": tuple(row for row in observers.observer_events if str(row["source_event_id"]) in {str(item["event_id"]) for item in dag.governance_events if str(item["scenario_id"]) in selected}),
    }
    return hashlib.sha256(
        canonical_json(
            {name: canonical_records_digest(rows) for name, rows in sorted(tables.items())}
        ).encode("utf-8")
    ).hexdigest()
