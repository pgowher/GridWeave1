"""Independent S07 policy oracle over finalized normalized world facts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.arrivals import ArrivalBuild
from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.dag import CausalDagBuild, build_causal_dag
from htgl_dataset_generator.physical import PhysicalRawBuild
from htgl_dataset_generator.policy.golden import GoldenSuiteResult, evaluate_golden_suite
from htgl_dataset_generator.policy.package import (
    ACTION_RULE_KINDS,
    PolicyEvaluation,
    PolicyPackage,
    PolicyPackageError,
    SafePolicyEvaluator,
    load_policy_package,
)
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import content_id
from htgl_dataset_generator.workflows import WorkflowBuild
from htgl_dataset_generator.world import FederatedWorld, build_federated_world


ALLOW_STATE_AFTER = frozenset({"granted", "authorized", "fulfilled", "received", "executed"})


class PolicyOracleError(ValueError):
    """Raised when policy normalization, evaluation, or validation fails."""


@dataclass(frozen=True)
class PolicyOracleDiagnostics:
    scenario_id: str
    replicate_id: int
    policy_profile_id: str
    package_sha256: str
    decision_count: int
    violation_count: int
    cross_region_count: int
    conflict_decision_count: int
    rule_trace_coverage: float
    explanation_coverage: float
    golden_case_count: int
    golden_decision_accuracy: float
    conflict_resolution_agreement: float


@dataclass(frozen=True)
class PolicyOracleBuild:
    policy_rules: tuple[dict[str, Any], ...]
    policy_decisions: tuple[dict[str, Any], ...]
    diagnostics: Mapping[str, PolicyOracleDiagnostics]
    golden_result: GoldenSuiteResult
    package_sha256: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "policy_rule": self.policy_rules,
            "policy_decision_truth": self.policy_decisions,
        }


@dataclass(frozen=True)
class _PolicyFactIndex:
    scenario_id: str
    actors: Mapping[str, Mapping[str, Any]]
    databases: Mapping[str, Mapping[str, Any]]
    objects: Mapping[str, Mapping[str, Any]]
    workflow_instances: Mapping[str, Mapping[str, Any]]
    replicas_by_object: Mapping[str, tuple[Mapping[str, Any], ...]]
    relationships_by_pair: Mapping[tuple[str, str], tuple[Mapping[str, Any], ...]]


def build_policy_oracle(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    catalog: CatalogBuild | None = None,
    physical: PhysicalRawBuild | None = None,
    arrivals: ArrivalBuild | None = None,
    workflows: WorkflowBuild | None = None,
    causal_dag: CausalDagBuild | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    package_path: Path | None = None,
    golden_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> PolicyOracleBuild:
    """Build schema-valid policy rules and evaluator-only decision truth."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise PolicyOracleError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise PolicyOracleError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise PolicyOracleError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )

    package = load_policy_package(resolved, package_path, contract=schema_contract)
    evaluator = SafePolicyEvaluator(package)
    golden_result = evaluate_golden_suite(package, evaluator, golden_path)
    _enforce_golden_gates(resolved, golden_result)

    world_build = (
        world
        if world is not None
        else build_federated_world(
            resolved,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    catalog_build = (
        catalog
        if catalog is not None
        else build_catalog(
            resolved,
            world=world_build,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    dag_build = (
        causal_dag
        if causal_dag is not None
        else build_causal_dag(
            resolved,
            world=world_build,
            catalog=catalog_build,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )

    decisions: list[dict[str, Any]] = []
    diagnostics: dict[str, PolicyOracleDiagnostics] = {}
    for scenario_id in sorted(selected):
        fact_index = _build_fact_index(
            scenario_id,
            world=world_build,
            catalog=catalog_build,
            causal_dag=dag_build,
        )
        scenario_events = tuple(
            sorted(
                (
                    row
                    for row in dag_build.governance_events
                    if str(row["scenario_id"]) == scenario_id
                ),
                key=lambda row: str(row["event_id"]),
            )
        )
        if not scenario_events:
            raise PolicyOracleError(f"{scenario_id}: no finalized governance events")
        scenario_decisions: list[dict[str, Any]] = []
        conflict_count = 0
        for event in scenario_events:
            facts = _normalize_event_policy_facts(event, fact_index)
            try:
                evaluation = evaluator.evaluate(facts)
            except PolicyPackageError as exc:
                raise PolicyOracleError(f"event {event['event_id']}: policy evaluation failed: {exc}") from exc
            row = _decision_record(event, evaluation, package)
            validate_record(schema_contract, "policy_decision_truth", row)
            scenario_decisions.append(row)
            if _action_candidate_count(evaluation, package) > 1:
                conflict_count += 1
        trace_coverage = sum(bool(row["applied_rule_ids"]) for row in scenario_decisions) / len(
            scenario_decisions
        )
        explanation_coverage = sum(
            bool(str(row["explanation_code"]).strip())
            and bool(row["conflict_resolution_trace"])
            for row in scenario_decisions
        ) / len(scenario_decisions)
        diagnostics[scenario_id] = PolicyOracleDiagnostics(
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            policy_profile_id=package.policy_profile_id,
            package_sha256=package.package_sha256,
            decision_count=len(scenario_decisions),
            violation_count=sum(bool(row["is_violation"]) for row in scenario_decisions),
            cross_region_count=sum(bool(row["is_cross_region"]) for row in scenario_decisions),
            conflict_decision_count=conflict_count,
            rule_trace_coverage=trace_coverage,
            explanation_coverage=explanation_coverage,
            golden_case_count=golden_result.case_count,
            golden_decision_accuracy=golden_result.decision_accuracy,
            conflict_resolution_agreement=golden_result.conflict_resolution_agreement,
        )
        decisions.extend(scenario_decisions)

    build = PolicyOracleBuild(
        policy_rules=package.rule_records(),
        policy_decisions=tuple(sorted(decisions, key=lambda row: row["decision_id"])),
        diagnostics=dict(sorted(diagnostics.items())),
        golden_result=golden_result,
        package_sha256=package.package_sha256,
    )
    validate_policy_oracle(
        build,
        resolved,
        world=world_build,
        catalog=catalog_build,
        causal_dag=dag_build,
        package=package,
        evaluator=evaluator,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    return build


def normalize_event_policy_facts(
    event: Mapping[str, Any],
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
) -> Mapping[str, Any]:
    """Normalize one finalized event without consulting generated policy labels."""

    scenario_id = str(event["scenario_id"])
    fact_index = _build_fact_index(
        scenario_id,
        world=world,
        catalog=catalog,
        causal_dag=causal_dag,
    )
    return _normalize_event_policy_facts(event, fact_index)


def _normalize_event_policy_facts(
    event: Mapping[str, Any],
    fact_index: _PolicyFactIndex,
) -> Mapping[str, Any]:
    scenario_id = str(event["scenario_id"])
    if scenario_id != fact_index.scenario_id:
        raise PolicyOracleError(
            f"event {event['event_id']}: scenario_id does not match policy fact index"
        )
    timestamp = str(event["timestamp"])
    workflow_id = str(event["workflow_instance_id"])
    workflow = fact_index.workflow_instances.get(workflow_id)
    if workflow is None:
        raise PolicyOracleError(f"event {event['event_id']}: workflow_instance_id does not resolve")
    workflow_type = str(workflow["workflow_type"])

    source = _required_actor(event.get("source_actor_id"), fact_index.actors, event, "source_actor_id", timestamp)
    requesting = _optional_actor(
        event.get("requesting_actor_id"), fact_index.actors, event, "requesting_actor_id", timestamp
    )
    controller = _optional_actor(
        event.get("controller_actor_id"), fact_index.actors, event, "controller_actor_id", timestamp
    )
    processor = _optional_actor(
        event.get("processor_actor_id"), fact_index.actors, event, "processor_actor_id", timestamp
    )
    oversight = _optional_actor(
        event.get("oversight_actor_id"), fact_index.actors, event, "oversight_actor_id", timestamp
    )
    destination = _destination_actor(
        workflow_type,
        requesting=requesting,
        controller=controller,
        processor=processor,
        oversight=oversight,
    )
    if destination is None:
        raise PolicyOracleError(f"event {event['event_id']}: no destination actor resolves for policy facts")

    database_id = event.get("local_database_id")
    database = fact_index.databases.get(str(database_id)) if database_id is not None else None
    if database_id is not None and database is None:
        raise PolicyOracleError(f"event {event['event_id']}: local_database_id does not resolve")
    object_id = event.get("data_object_id")
    data_object = fact_index.objects.get(str(object_id)) if object_id is not None else None
    if object_id is not None and data_object is None:
        raise PolicyOracleError(f"event {event['event_id']}: data_object_id does not resolve")
    replicas = fact_index.replicas_by_object.get(str(object_id), ()) if object_id is not None else ()
    replica_regions = tuple(
        sorted(
            {
                str(fact_index.databases[str(replica["database_id"])]["region_id"])
                for replica in replicas
                if str(replica["database_id"]) in fact_index.databases
            }
        )
    )
    if len(replica_regions) == 0 and replicas:
        raise PolicyOracleError(f"event {event['event_id']}: replica database locations do not resolve")
    non_exempt_replicas = tuple(
        replica for replica in replicas if str(replica["deletion_status"]) != "exempt"
    )
    pending_replicas = tuple(
        replica
        for replica in non_exempt_replicas
        if str(replica["deletion_status"]) != "deleted"
    )
    purpose_tags = tuple(data_object["purpose_tags"]) if data_object is not None else ()
    allowed_purpose_ids = tuple(sorted({_purpose_id(str(value)) for value in purpose_tags}))
    source_to_destination = _active_relationship_types(
        fact_index.relationships_by_pair.get(
            (str(source["actor_id"]), str(destination["actor_id"])), ()
        ),
        timestamp=timestamp,
    )
    destination_to_source = _active_relationship_types(
        fact_index.relationships_by_pair.get(
            (str(destination["actor_id"]), str(source["actor_id"])), ()
        ),
        timestamp=timestamp,
    )
    requesting_to_controller = _relationship_types_or_empty(
        fact_index,
        requesting,
        controller,
        timestamp,
    )
    controller_to_processor = _relationship_types_or_empty(
        fact_index,
        controller,
        processor,
        timestamp,
    )
    return {
        "event.id": str(event["event_id"]),
        "event.type": str(event["event_type"]),
        "event.family": str(event["event_family"]),
        "event.timestamp": timestamp,
        "workflow.type": workflow_type,
        "workflow.state_before": str(event["workflow_state_before"]),
        "workflow.state_after": str(event["workflow_state_after"]),
        "actor.source.id": str(source["actor_id"]),
        "actor.source.class": str(source["actor_class"]),
        "actor.source.region": str(source["region_id"]),
        "actor.source.jurisdiction": str(source["jurisdiction_id"]),
        "actor.destination.id": str(destination["actor_id"]),
        "actor.destination.class": str(destination["actor_class"]),
        "actor.destination.region": str(destination["region_id"]),
        "actor.destination.jurisdiction": str(destination["jurisdiction_id"]),
        "actor.requesting.id": _actor_value(requesting, "actor_id"),
        "actor.requesting.class": _actor_value(requesting, "actor_class"),
        "actor.controller.id": _actor_value(controller, "actor_id"),
        "actor.controller.class": _actor_value(controller, "actor_class"),
        "actor.processor.id": _actor_value(processor, "actor_id"),
        "actor.processor.class": _actor_value(processor, "actor_class"),
        "actor.oversight.id": _actor_value(oversight, "actor_id"),
        "actor.oversight.class": _actor_value(oversight, "actor_class"),
        "relationship.source_to_destination": source_to_destination,
        "relationship.destination_to_source": destination_to_source,
        "relationship.requesting_to_controller": requesting_to_controller,
        "relationship.controller_to_processor": controller_to_processor,
        "object.id": str(object_id) if object_id is not None else None,
        "object.type": str(data_object["object_type"]) if data_object is not None else None,
        "object.sensitivity": str(data_object["sensitivity"]) if data_object is not None else None,
        "object.allowed_purpose_ids": allowed_purpose_ids,
        "purpose.id": str(event["policy_purpose_id"]) if event.get("policy_purpose_id") is not None else None,
        "database.id": str(database_id) if database_id is not None else None,
        "database.region": str(database["region_id"]) if database is not None else None,
        "replica.count": len(replicas),
        "replica.non_exempt_count": len(non_exempt_replicas),
        "replica.pending_deletion_count": len(pending_replicas),
        "replica.regions": replica_regions,
        "replica.deletion_statuses": tuple(sorted({str(row["deletion_status"]) for row in replicas})),
        "replica.retention_basis_rule_ids": tuple(
            sorted(
                {
                    str(row["retention_basis_rule_id"])
                    for row in replicas
                    if row["retention_basis_rule_id"] is not None
                }
            )
        ),
        "state.consent": event.get("consent_state_after"),
        "state.retention": event.get("retention_state_after"),
        "state.erasure": event.get("erasure_state_after"),
        "retention.has_exception": any(
            str(row["deletion_status"]) == "exempt" for row in replicas
        ),
        "observed.action": observed_action_from_event(event, workflow_type),
    }


def observed_action_from_event(event: Mapping[str, Any], workflow_type: str) -> str:
    """Map emitted world-state transitions to policy actions without using labels."""

    event_type = str(event["event_type"])
    if event_type == "erasure_executed" and event.get("erasure_state_after") == "executed":
        return "erase"
    if event_type == "incident_notified":
        return "notify"
    if event_type == "audit_finding":
        return "escalate"
    if event.get("retention_state_after") == "retained_under_rule":
        return "retain"
    if workflow_type not in {"erasure", "retention"} and event.get("workflow_state_after") in ALLOW_STATE_AFTER:
        return "allow"
    return "no_op"


def validate_policy_oracle(
    build: PolicyOracleBuild,
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
    package: PolicyPackage,
    evaluator: SafePolicyEvaluator,
    replicate_id: int,
    scenario_ids: Iterable[str],
    contract: ContractSpec | None = None,
) -> None:
    """Fail closed on schemas, scopes, rule traces, truth, and golden gates."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids))
    rule_by_id = {rule.policy_rule_id: rule for rule in package.rules}
    if len(rule_by_id) != len(package.rules):
        raise PolicyOracleError("duplicate policy rule IDs")
    if tuple(build.policy_rules) != package.rule_records():
        raise PolicyOracleError("policy_rule records do not match the loaded package")
    for row in build.policy_rules:
        validate_record(schema_contract, "policy_rule", row)
    events = {
        str(row["event_id"]): row
        for row in causal_dag.governance_events
        if str(row["scenario_id"]) in selected
    }
    if len(events) != sum(
        1 for row in causal_dag.governance_events if str(row["scenario_id"]) in selected
    ):
        raise PolicyOracleError("duplicate finalized governance event IDs")
    decision_by_event: dict[str, Mapping[str, Any]] = {}
    decision_ids: set[str] = set()
    fact_indexes = {
        scenario_id: _build_fact_index(
            scenario_id,
            world=world,
            catalog=catalog,
            causal_dag=causal_dag,
        )
        for scenario_id in selected
    }
    for row in build.policy_decisions:
        validate_record(schema_contract, "policy_decision_truth", row)
        decision_id = str(row["decision_id"])
        event_id = str(row["event_id"])
        if decision_id in decision_ids:
            raise PolicyOracleError(f"duplicate policy decision_id={decision_id}")
        decision_ids.add(decision_id)
        if event_id not in events:
            raise PolicyOracleError(f"decision {decision_id}: event_id does not resolve")
        if event_id in decision_by_event:
            raise PolicyOracleError(f"event {event_id}: multiple policy decisions")
        if not row["applied_rule_ids"]:
            raise PolicyOracleError(f"decision {decision_id}: applied_rule_ids is empty")
        if not row["conflict_resolution_trace"] or not str(row["explanation_code"]).strip():
            raise PolicyOracleError(f"decision {decision_id}: explanation provenance is incomplete")
        unknown_rules = sorted(set(row["applied_rule_ids"]) - set(rule_by_id))
        if unknown_rules:
            raise PolicyOracleError(f"decision {decision_id}: unknown applied rules {unknown_rules}")
        event_scenario_id = str(events[event_id]["scenario_id"])
        facts = _normalize_event_policy_facts(events[event_id], fact_indexes[event_scenario_id])
        recomputed = _decision_record(events[event_id], evaluator.evaluate(facts), package)
        if dict(row) != recomputed:
            raise PolicyOracleError(f"decision {decision_id}: truth does not match independent recomputation")
        decision_by_event[event_id] = row
    missing_decisions = sorted(set(events) - set(decision_by_event))
    if missing_decisions:
        raise PolicyOracleError(f"finalized events missing policy decisions {missing_decisions[:8]}")
    if build.package_sha256 != package.package_sha256:
        raise PolicyOracleError("policy package digest mismatch")
    _enforce_golden_gates(resolved, build.golden_result)

    if set(build.diagnostics) != set(selected):
        raise PolicyOracleError("policy diagnostics do not cover exactly the selected scenarios")
    for scenario_id in selected:
        rows = tuple(
            row
            for row in build.policy_decisions
            if str(events[str(row["event_id"])]["scenario_id"]) == scenario_id
        )
        diagnostics = build.diagnostics[scenario_id]
        if diagnostics.replicate_id != replicate_id:
            raise PolicyOracleError(f"{scenario_id}: diagnostic replicate_id mismatch")
        if diagnostics.decision_count != len(rows):
            raise PolicyOracleError(f"{scenario_id}: policy decision count does not reconcile")
        if diagnostics.violation_count != sum(bool(row["is_violation"]) for row in rows):
            raise PolicyOracleError(f"{scenario_id}: violation count does not reconcile")
        if diagnostics.cross_region_count != sum(bool(row["is_cross_region"]) for row in rows):
            raise PolicyOracleError(f"{scenario_id}: cross-region count does not reconcile")
        if diagnostics.rule_trace_coverage < resolved.policy.rule_trace_coverage_target:
            raise PolicyOracleError(
                f"{scenario_id}: rule trace coverage {diagnostics.rule_trace_coverage:.6f} is below "
                f"target {resolved.policy.rule_trace_coverage_target:.6f}"
            )
        if diagnostics.explanation_coverage != 1.0:
            raise PolicyOracleError(f"{scenario_id}: explanation coverage is not complete")


def _decision_record(
    event: Mapping[str, Any],
    evaluation: PolicyEvaluation,
    package: PolicyPackage,
) -> dict[str, Any]:
    return {
        "decision_id": content_id(
            "policy_decision_truth",
            {
                "event_id": event["event_id"],
                "oracle_version": package.oracle_version,
                "package_sha256": package.package_sha256,
            },
        ),
        "event_id": str(event["event_id"]),
        "oracle_version": package.oracle_version,
        "expected_action": evaluation.expected_action,
        "observed_action": evaluation.observed_action,
        "is_violation": evaluation.is_violation,
        "violation_type": evaluation.violation_type,
        "requires_retention": evaluation.requires_retention,
        "requires_erasure": evaluation.requires_erasure,
        "is_cross_region": evaluation.is_cross_region,
        "applied_rule_ids": list(evaluation.applied_rule_ids),
        "conflict_resolution_trace": list(evaluation.conflict_resolution_trace),
        "explanation_code": evaluation.explanation_code,
    }


def _enforce_golden_gates(resolved: ResolvedConfig, result: GoldenSuiteResult) -> None:
    if result.failures:
        raise PolicyOracleError(
            f"golden policy suite has {len(result.failures)} exact-case failures: {result.failures[:3]}"
        )
    if result.decision_accuracy < resolved.policy.golden_decision_accuracy_target:
        raise PolicyOracleError(
            f"golden decision accuracy {result.decision_accuracy:.6f} is below configured target "
            f"{resolved.policy.golden_decision_accuracy_target:.6f}"
        )
    if result.conflict_resolution_agreement < resolved.policy.conflict_resolution_agreement_target:
        raise PolicyOracleError(
            f"conflict resolution agreement {result.conflict_resolution_agreement:.6f} is below "
            f"configured target {resolved.policy.conflict_resolution_agreement_target:.6f}"
        )


def _action_candidate_count(evaluation: PolicyEvaluation, package: PolicyPackage) -> int:
    by_id = {rule.policy_rule_id: rule for rule in package.rules}
    return sum(
        1
        for rule_id in evaluation.applied_rule_ids
        if by_id[rule_id].rule_kind in ACTION_RULE_KINDS
    )


def _build_fact_index(
    scenario_id: str,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
) -> _PolicyFactIndex:
    actors = {
        str(row["actor_id"]): row
        for row in world.actors
        if str(row["scenario_id"]) == scenario_id
    }
    databases = {
        str(row["database_id"]): row
        for row in catalog.local_databases
        if str(row["scenario_id"]) == scenario_id
    }
    objects = {
        str(row["data_object_id"]): row
        for row in catalog.data_objects
        if str(row["scenario_id"]) == scenario_id
    }
    workflow_instances = {
        str(row["workflow_instance_id"]): row
        for row in causal_dag.workflow_instances
        if str(row["scenario_id"]) == scenario_id
    }
    if not actors or not databases or not objects or not workflow_instances:
        raise PolicyOracleError(f"{scenario_id}: policy fact index inputs are incomplete")
    replicas_by_object: dict[str, list[Mapping[str, Any]]] = {}
    for row in catalog.data_object_replicas:
        data_object_id = str(row["data_object_id"])
        if data_object_id in objects:
            replicas_by_object.setdefault(data_object_id, []).append(row)
    relationships_by_pair: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in world.actor_relationships:
        if str(row["scenario_id"]) != scenario_id:
            continue
        source_actor_id = str(row["source_actor_id"])
        target_actor_id = str(row["target_actor_id"])
        if source_actor_id not in actors or target_actor_id not in actors:
            raise PolicyOracleError(
                f"relationship {row['relationship_id']}: endpoint does not resolve in policy fact index"
            )
        relationships_by_pair.setdefault((source_actor_id, target_actor_id), []).append(row)
    return _PolicyFactIndex(
        scenario_id=scenario_id,
        actors=dict(sorted(actors.items())),
        databases=dict(sorted(databases.items())),
        objects=dict(sorted(objects.items())),
        workflow_instances=dict(sorted(workflow_instances.items())),
        replicas_by_object={
            object_id: tuple(sorted(rows, key=lambda row: str(row["replica_id"])))
            for object_id, rows in sorted(replicas_by_object.items())
        },
        relationships_by_pair={
            pair: tuple(sorted(rows, key=lambda row: str(row["relationship_id"])))
            for pair, rows in sorted(relationships_by_pair.items())
        },
    )


def _destination_actor(
    workflow_type: str,
    *,
    requesting: Mapping[str, Any] | None,
    controller: Mapping[str, Any] | None,
    processor: Mapping[str, Any] | None,
    oversight: Mapping[str, Any] | None,
) -> Mapping[str, Any] | None:
    if workflow_type in {"disclosure", "audit"}:
        return requesting or oversight or processor or controller
    if workflow_type == "incident":
        return oversight or processor or controller
    if workflow_type in {"collection_processing", "operational"}:
        return processor or controller
    return controller or processor or oversight


def _required_actor(
    actor_id: Any,
    actors: Mapping[str, Mapping[str, Any]],
    event: Mapping[str, Any],
    field_name: str,
    timestamp: str,
) -> Mapping[str, Any]:
    actor = _optional_actor(actor_id, actors, event, field_name, timestamp)
    if actor is None:
        raise PolicyOracleError(f"event {event['event_id']}: {field_name} is required")
    return actor


def _optional_actor(
    actor_id: Any,
    actors: Mapping[str, Mapping[str, Any]],
    event: Mapping[str, Any],
    field_name: str,
    timestamp: str,
) -> Mapping[str, Any] | None:
    if actor_id is None:
        return None
    actor = actors.get(str(actor_id))
    if actor is None:
        raise PolicyOracleError(f"event {event['event_id']}: {field_name} does not resolve")
    if not _effective_at(actor, timestamp):
        raise PolicyOracleError(f"event {event['event_id']}: {field_name} is not effective at event time")
    return actor


def _active_relationship_types(
    relationships: Sequence[Mapping[str, Any]],
    *,
    timestamp: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(row["relationship_type"])
                for row in relationships
                if _effective_at(row, timestamp)
            }
        )
    )


def _relationship_types_or_empty(
    fact_index: _PolicyFactIndex,
    source: Mapping[str, Any] | None,
    target: Mapping[str, Any] | None,
    timestamp: str,
) -> tuple[str, ...]:
    if source is None or target is None:
        return ()
    return _active_relationship_types(
        fact_index.relationships_by_pair.get(
            (str(source["actor_id"]), str(target["actor_id"])), ()
        ),
        timestamp=timestamp,
    )


def _effective_at(row: Mapping[str, Any], timestamp: str) -> bool:
    instant = _timestamp(timestamp)
    start = _timestamp(str(row["valid_from"]))
    end_raw = row.get("valid_to")
    return instant >= start and (end_raw is None or instant <= _timestamp(str(end_raw)))


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyOracleError(f"invalid UTC timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise PolicyOracleError(f"timestamp must be normalized to UTC: {value!r}")
    return parsed


def _actor_value(actor: Mapping[str, Any] | None, field_name: str) -> str | None:
    return str(actor[field_name]) if actor is not None else None


def _purpose_id(value: str) -> str:
    if value.startswith("PURPOSE-"):
        return value
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return f"PURPOSE-{normalized}"
