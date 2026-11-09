"""S09 deterministic policy-to-evidence obligation compiler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.arrivals import ArrivalBuild, build_arrivals
from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.dag import CausalDagBuild, build_causal_dag
from htgl_dataset_generator.physical import PhysicalRawBuild, build_physical_raw
from htgl_dataset_generator.policy import (
    PolicyOracleBuild,
    PolicyPackage,
    build_policy_oracle,
    load_policy_package,
)
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import canonical_records_digest, content_id
from htgl_dataset_generator.workflows import WorkflowBuild, build_workflows
from htgl_dataset_generator.world import FederatedWorld, build_federated_world

from .templates import (
    ObligationClause,
    ObligationTemplateBundle,
    load_obligation_template_bundle,
)


class EvidenceObligationError(ValueError):
    """Raised when S09 obligations are incomplete, contradictory, or invalid."""


@dataclass(frozen=True)
class EvidenceObligationProvenance:
    obligation_id: str
    scenario_id: str
    template_clause_ids: tuple[str, ...]
    source_policy_rule_ids: tuple[str, ...]
    coverage_member_ids: tuple[str, ...]
    exempt_member_ids: tuple[str, ...]
    dependency_event_ids: tuple[str, ...]
    minimization_source_count: int


@dataclass(frozen=True)
class EvidenceObligationDiagnostics:
    scenario_id: str
    replicate_id: int
    obligation_count: int
    expanded_candidate_count: int
    minimized_candidate_count: int
    evidence_trigger_event_count: int
    covered_trigger_event_count: int
    exempt_replica_count: int
    obligation_type_counts: Mapping[str, int]
    coverage_scope_counts: Mapping[str, int]


@dataclass(frozen=True)
class EvidenceObligationBuild:
    evidence_obligations: tuple[dict[str, Any], ...]
    provenance: tuple[EvidenceObligationProvenance, ...]
    diagnostics: Mapping[str, EvidenceObligationDiagnostics]
    template_bundle_sha256: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {"evidence_obligation": self.evidence_obligations}


@dataclass(frozen=True)
class _Candidate:
    scenario_id: str
    event_id: str
    policy_rule_id: str
    obligation_type: str
    subject_object_id: str
    responsible_actor_id: str
    due_at: str
    required_evidence_types: tuple[str, ...]
    minimum_count: int
    coverage_scope: str
    template_clause_id: str
    coverage_member_ids: tuple[str, ...]
    exempt_member_ids: tuple[str, ...]
    dependency_event_ids: tuple[str, ...]


@dataclass(frozen=True)
class _CompilerContext:
    scenario_id: str
    replicate_id: int
    events: Mapping[str, Mapping[str, Any]]
    workflows: Mapping[str, Mapping[str, Any]]
    workflow_events: Mapping[str, tuple[Mapping[str, Any], ...]]
    decisions: Mapping[str, Mapping[str, Any]]
    actors: Mapping[str, Mapping[str, Any]]
    databases: Mapping[str, Mapping[str, Any]]
    objects: Mapping[str, Mapping[str, Any]]
    replicas_by_object: Mapping[str, tuple[Mapping[str, Any], ...]]
    full_closure_by_event: Mapping[str, tuple[str, ...]]
    evidence_trigger_event_ids: frozenset[str]
    policy_package: PolicyPackage
    bundle: ObligationTemplateBundle


def build_evidence_obligations(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    catalog: CatalogBuild | None = None,
    physical: PhysicalRawBuild | None = None,
    arrivals: ArrivalBuild | None = None,
    workflows: WorkflowBuild | None = None,
    causal_dag: CausalDagBuild | None = None,
    policy: PolicyOracleBuild | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    template_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> EvidenceObligationBuild:
    """Compile and independently validate machine-readable evidence duties."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise EvidenceObligationError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise EvidenceObligationError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise EvidenceObligationError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )

    world_build = world or build_federated_world(
        resolved, replicate_id=replicate_id, scenario_ids=selected, contract=schema_contract
    )
    catalog_build = catalog or build_catalog(
        resolved,
        world=world_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    physical_build = physical or build_physical_raw(
        resolved,
        world=world_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    arrival_build = arrivals or build_arrivals(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    workflow_build = workflows or build_workflows(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    dag_build = causal_dag or build_causal_dag(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        workflows=workflow_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    policy_build = policy or build_policy_oracle(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        workflows=workflow_build,
        causal_dag=dag_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    policy_package = load_policy_package(resolved, contract=schema_contract)
    if policy_build.package_sha256 != policy_package.package_sha256:
        raise EvidenceObligationError("policy truth package digest does not match loaded policy package")
    bundle = load_obligation_template_bundle(
        resolved, policy_package, template_path, contract=schema_contract
    )

    all_obligations: list[dict[str, Any]] = []
    all_provenance: list[EvidenceObligationProvenance] = []
    diagnostics: dict[str, EvidenceObligationDiagnostics] = {}
    for scenario_id in sorted(selected):
        context = _build_context(
            scenario_id,
            replicate_id,
            world=world_build,
            catalog=catalog_build,
            workflows=workflow_build,
            causal_dag=dag_build,
            policy=policy_build,
            policy_package=policy_package,
            bundle=bundle,
        )
        candidates = _expand_candidates(context)
        obligations, provenance = _minimize_candidates(candidates, context)
        for row in obligations:
            validate_record(schema_contract, "evidence_obligation", row)
        all_obligations.extend(obligations)
        all_provenance.extend(provenance)
        diagnostics[scenario_id] = _diagnostics(context, candidates, obligations, provenance)

    result = EvidenceObligationBuild(
        evidence_obligations=tuple(sorted(all_obligations, key=lambda row: row["obligation_id"])),
        provenance=tuple(sorted(all_provenance, key=lambda item: item.obligation_id)),
        diagnostics=dict(sorted(diagnostics.items())),
        template_bundle_sha256=bundle.bundle_sha256,
    )
    validate_evidence_obligations(
        result,
        resolved,
        world=world_build,
        catalog=catalog_build,
        workflows=workflow_build,
        causal_dag=dag_build,
        policy=policy_build,
        policy_package=policy_package,
        bundle=bundle,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    return result


def validate_evidence_obligations(
    build: EvidenceObligationBuild,
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    workflows: WorkflowBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    policy_package: PolicyPackage,
    bundle: ObligationTemplateBundle,
    replicate_id: int,
    scenario_ids: Iterable[str],
    contract: ContractSpec | None = None,
) -> None:
    """Fail closed on obligation schemas, FKs, coverage, exemptions, and recomputation."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids))
    if build.template_bundle_sha256 != bundle.bundle_sha256:
        raise EvidenceObligationError("obligation build template digest mismatch")
    obligations_by_id = {str(row["obligation_id"]): row for row in build.evidence_obligations}
    if len(obligations_by_id) != len(build.evidence_obligations):
        raise EvidenceObligationError("duplicate evidence obligation IDs")
    provenance_by_id = {item.obligation_id: item for item in build.provenance}
    if len(provenance_by_id) != len(build.provenance):
        raise EvidenceObligationError("duplicate evidence obligation provenance IDs")
    if set(obligations_by_id) != set(provenance_by_id):
        raise EvidenceObligationError("every obligation must have exactly one evaluator-only provenance sidecar")

    semantic_keys: set[tuple[str, str, str, str, str]] = set()
    for scenario_id in selected:
        context = _build_context(
            scenario_id,
            replicate_id,
            world=world,
            catalog=catalog,
            workflows=workflows,
            causal_dag=causal_dag,
            policy=policy,
            policy_package=policy_package,
            bundle=bundle,
        )
        scenario_rows = tuple(
            row for row in build.evidence_obligations if str(row["event_id"]) in context.events
        )
        scenario_provenance = {
            item.obligation_id: item
            for item in build.provenance
            if item.scenario_id == scenario_id
        }
        for row in scenario_rows:
            validate_record(schema_contract, "evidence_obligation", row)
            _validate_obligation_row(row, provenance_by_id[str(row["obligation_id"])], context, resolved)
            key = (
                str(row["event_id"]),
                str(row["obligation_type"]),
                str(row["subject_object_id"]),
                str(row["responsible_actor_id"]),
                str(row["coverage_scope"]),
            )
            if key in semantic_keys:
                raise EvidenceObligationError(f"duplicate minimized obligation semantic key {key}")
            semantic_keys.add(key)
        _validate_erasure_coverage(scenario_rows, scenario_provenance, context)
        expected_rows, expected_provenance = _minimize_candidates(_expand_candidates(context), context)
        if canonical_records_digest(scenario_rows) != canonical_records_digest(expected_rows):
            raise EvidenceObligationError(f"{scenario_id}: obligations do not match deterministic recomputation")
        if tuple(sorted(scenario_provenance.values(), key=lambda item: item.obligation_id)) != expected_provenance:
            raise EvidenceObligationError(f"{scenario_id}: obligation provenance does not match recomputation")
        diagnostics = build.diagnostics.get(scenario_id)
        if diagnostics is None:
            raise EvidenceObligationError(f"{scenario_id}: missing obligation diagnostics")
        recomputed_diagnostics = _diagnostics(
            context, _expand_candidates(context), expected_rows, expected_provenance
        )
        if diagnostics != recomputed_diagnostics:
            raise EvidenceObligationError(f"{scenario_id}: obligation diagnostics mismatch")
    resolved_event_ids = {
        str(row["event_id"])
        for row in causal_dag.governance_events
        if str(row["scenario_id"]) in selected
    }
    orphan_rows = [row for row in build.evidence_obligations if str(row["event_id"]) not in resolved_event_ids]
    if orphan_rows:
        raise EvidenceObligationError("obligations contain events outside selected scenarios")


def _build_context(
    scenario_id: str,
    replicate_id: int,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    workflows: WorkflowBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    policy_package: PolicyPackage,
    bundle: ObligationTemplateBundle,
) -> _CompilerContext:
    events = {
        str(row["event_id"]): row
        for row in causal_dag.governance_events
        if str(row["scenario_id"]) == scenario_id and int(row["replicate_id"]) == replicate_id
    }
    workflow_rows = {
        str(row["workflow_instance_id"]): row
        for row in causal_dag.workflow_instances
        if str(row["scenario_id"]) == scenario_id
    }
    workflow_events: dict[str, list[Mapping[str, Any]]] = {}
    for event in events.values():
        workflow_events.setdefault(str(event["workflow_instance_id"]), []).append(event)
    ordered_workflow_events = {
        workflow_id: tuple(
            sorted(rows, key=lambda row: (int(row["workflow_step_index"]), str(row["event_id"])))
        )
        for workflow_id, rows in workflow_events.items()
    }
    decisions = {
        str(row["event_id"]): row
        for row in policy.policy_decisions
        if str(row["event_id"]) in events
    }
    if set(decisions) != set(events):
        raise EvidenceObligationError(f"{scenario_id}: policy decisions do not cover finalized events")
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
    replicas_by_object: dict[str, list[Mapping[str, Any]]] = {}
    for replica in catalog.data_object_replicas:
        object_id = str(replica["data_object_id"])
        if object_id in objects:
            replicas_by_object.setdefault(object_id, []).append(replica)
    full_closure_by_event = {
        record.unit_id: tuple(sorted(set(record.member_event_ids) | {record.unit_id}))
        for record in causal_dag.closure_index
        if record.scenario_id == scenario_id and record.closure_type == "full_dependency"
    }
    evidence_trigger_event_ids = frozenset(
        effect.event_id
        for effect in workflows.side_effects
        if effect.scenario_id == scenario_id and effect.evidence_trigger_required
    )
    if not events or not workflow_rows or not actors or not databases or not objects:
        raise EvidenceObligationError(f"{scenario_id}: obligation compiler inputs are incomplete")
    if set(full_closure_by_event) != set(events):
        raise EvidenceObligationError(f"{scenario_id}: full dependency closure is incomplete")
    unknown_triggers = sorted(evidence_trigger_event_ids - set(events))
    if unknown_triggers:
        raise EvidenceObligationError(f"{scenario_id}: evidence triggers do not resolve {unknown_triggers[:8]}")
    return _CompilerContext(
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        events=dict(sorted(events.items())),
        workflows=dict(sorted(workflow_rows.items())),
        workflow_events=dict(sorted(ordered_workflow_events.items())),
        decisions=dict(sorted(decisions.items())),
        actors=dict(sorted(actors.items())),
        databases=dict(sorted(databases.items())),
        objects=dict(sorted(objects.items())),
        replicas_by_object={
            key: tuple(sorted(value, key=lambda row: str(row["replica_id"])))
            for key, value in sorted(replicas_by_object.items())
        },
        full_closure_by_event=dict(sorted(full_closure_by_event.items())),
        evidence_trigger_event_ids=evidence_trigger_event_ids,
        policy_package=policy_package,
        bundle=bundle,
    )


def _expand_candidates(context: _CompilerContext) -> tuple[_Candidate, ...]:
    candidates: list[_Candidate] = []
    for event_id in sorted(context.events):
        event = context.events[event_id]
        workflow = context.workflows[str(event["workflow_instance_id"])]
        workflow_type = str(workflow["workflow_type"])
        decision = context.decisions[event_id]
        applied_rule_ids = set(str(value) for value in decision["applied_rule_ids"])
        for clause in context.bundle.clauses:
            if clause.workflow_types and workflow_type not in clause.workflow_types:
                continue
            if clause.event_types and str(event["event_type"]) not in clause.event_types:
                continue
            matching_rules = tuple(
                rule_id for rule_id in clause.policy_rule_ids if rule_id in applied_rule_ids
            )
            if not matching_rules:
                continue
            if clause.requires_evidence_trigger and event_id not in context.evidence_trigger_event_ids:
                raise EvidenceObligationError(
                    f"event {event_id}: clause {clause.clause_id} requires a typed evidence trigger"
                )
            policy_rule_id = _winning_policy_rule(matching_rules, context.policy_package)
            candidates.extend(_expand_clause(event, workflow, clause, policy_rule_id, context))
    if not candidates:
        raise EvidenceObligationError(f"{context.scenario_id}: obligation expansion produced no candidates")
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                item.event_id,
                item.obligation_type,
                item.subject_object_id,
                item.responsible_actor_id,
                item.coverage_scope,
                item.template_clause_id,
            ),
        )
    )


def _expand_clause(
    event: Mapping[str, Any],
    workflow: Mapping[str, Any],
    clause: ObligationClause,
    policy_rule_id: str,
    context: _CompilerContext,
) -> tuple[_Candidate, ...]:
    event_id = str(event["event_id"])
    object_id = str(event["data_object_id"])
    if object_id not in context.objects:
        raise EvidenceObligationError(f"event {event_id}: data object does not resolve")
    all_replicas = context.replicas_by_object.get(object_id, ())
    exempt_replicas = tuple(
        row for row in all_replicas if str(row["deletion_status"]) == "exempt"
    )
    non_exempt_replicas = tuple(
        row for row in all_replicas if str(row["deletion_status"]) != "exempt"
    )
    expansions: list[tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = []
    if clause.expansion_mode == "object":
        actor_id = _event_actor(event, clause.responsible_actor_role)
        expansions.append((object_id, actor_id, (object_id,), (event_id,), ()))
    elif clause.expansion_mode in {"non_exempt_replicas", "exempt_replicas"}:
        selected = non_exempt_replicas if clause.expansion_mode == "non_exempt_replicas" else exempt_replicas
        exempt_ids = tuple(sorted(str(row["replica_id"]) for row in exempt_replicas))
        for replica in selected:
            database_id = str(replica["database_id"])
            database = context.databases.get(database_id)
            if database is None:
                raise EvidenceObligationError(f"replica {replica['replica_id']}: database does not resolve")
            actor_id = str(database["operator_actor_id"])
            expansions.append(
                (
                    str(replica["replica_id"]),
                    actor_id,
                    (str(replica["replica_id"]),),
                    (event_id,),
                    exempt_ids,
                )
            )
    elif clause.expansion_mode == "workflow_events":
        member_ids = tuple(
            str(row["event_id"])
            for row in context.workflow_events[str(workflow["workflow_instance_id"])]
        )
        expansions.append(
            (object_id, _event_actor(event, clause.responsible_actor_role), member_ids, member_ids, ())
        )
    elif clause.expansion_mode == "actor_set":
        actor_ids = tuple(
            sorted({_event_actor(event, role) for role in clause.actor_roles})
        )
        for actor_id in actor_ids:
            expansions.append((object_id, actor_id, (actor_id,), (event_id,), ()))
    elif clause.expansion_mode == "causal_closure":
        member_ids = context.full_closure_by_event[event_id]
        expansions.append(
            (object_id, _event_actor(event, clause.responsible_actor_role), member_ids, member_ids, ())
        )
    else:
        raise EvidenceObligationError(f"unsupported expansion mode {clause.expansion_mode!r}")

    due_at = _format_timestamp(_timestamp(str(event["timestamp"])) + timedelta(seconds=clause.deadline_seconds))
    candidates: list[_Candidate] = []
    for subject_id, actor_id, coverage_ids, dependency_ids, exempt_ids in expansions:
        if actor_id not in context.actors:
            raise EvidenceObligationError(
                f"event {event_id}: responsible actor {actor_id!r} does not resolve"
            )
        minimum_count = (
            clause.fixed_minimum_count
            if clause.minimum_count_mode == "fixed"
            else max(clause.fixed_minimum_count, len(coverage_ids))
        )
        candidates.append(
            _Candidate(
                scenario_id=context.scenario_id,
                event_id=event_id,
                policy_rule_id=policy_rule_id,
                obligation_type=clause.obligation_type,
                subject_object_id=subject_id,
                responsible_actor_id=actor_id,
                due_at=due_at,
                required_evidence_types=clause.required_evidence_types,
                minimum_count=minimum_count,
                coverage_scope=clause.coverage_scope,
                template_clause_id=f"{clause.template_id}/{clause.clause_id}",
                coverage_member_ids=tuple(sorted(set(coverage_ids))),
                exempt_member_ids=tuple(sorted(set(exempt_ids))),
                dependency_event_ids=tuple(sorted(set(dependency_ids))),
            )
        )
    return tuple(candidates)


def _minimize_candidates(
    candidates: Sequence[_Candidate],
    context: _CompilerContext,
) -> tuple[tuple[dict[str, Any], ...], tuple[EvidenceObligationProvenance, ...]]:
    grouped: dict[tuple[str, str, str, str, str], list[_Candidate]] = {}
    for candidate in candidates:
        key = (
            candidate.event_id,
            candidate.obligation_type,
            candidate.subject_object_id,
            candidate.responsible_actor_id,
            candidate.coverage_scope,
        )
        grouped.setdefault(key, []).append(candidate)
    rows: list[dict[str, Any]] = []
    provenance_rows: list[EvidenceObligationProvenance] = []
    for key in sorted(grouped):
        members = tuple(grouped[key])
        evidence_types = set(members[0].required_evidence_types)
        for member in members[1:]:
            evidence_types.intersection_update(member.required_evidence_types)
        if not evidence_types:
            raise EvidenceObligationError(
                f"contradictory obligation clauses for {key}: no common acceptable evidence type"
            )
        policy_rule_id = _winning_policy_rule(
            tuple(sorted({member.policy_rule_id for member in members})), context.policy_package
        )
        due_at = min((member.due_at for member in members), key=_timestamp)
        minimum_count = max(member.minimum_count for member in members)
        row_without_id = {
            "event_id": key[0],
            "policy_rule_id": policy_rule_id,
            "obligation_type": key[1],
            "subject_object_id": key[2],
            "responsible_actor_id": key[3],
            "due_at": due_at,
            "required_evidence_types": sorted(evidence_types),
            "minimum_count": minimum_count,
            "coverage_scope": key[4],
        }
        obligation_id = content_id(
            "evidence_obligation",
            {**row_without_id, "template_bundle_sha256": context.bundle.bundle_sha256},
        )
        rows.append({"obligation_id": obligation_id, **row_without_id})
        provenance_rows.append(
            EvidenceObligationProvenance(
                obligation_id=obligation_id,
                scenario_id=context.scenario_id,
                template_clause_ids=tuple(sorted({member.template_clause_id for member in members})),
                source_policy_rule_ids=tuple(sorted({member.policy_rule_id for member in members})),
                coverage_member_ids=tuple(
                    sorted({value for member in members for value in member.coverage_member_ids})
                ),
                exempt_member_ids=tuple(
                    sorted({value for member in members for value in member.exempt_member_ids})
                ),
                dependency_event_ids=tuple(
                    sorted({value for member in members for value in member.dependency_event_ids})
                ),
                minimization_source_count=len(members),
            )
        )
    return (
        tuple(sorted(rows, key=lambda row: row["obligation_id"])),
        tuple(sorted(provenance_rows, key=lambda item: item.obligation_id)),
    )


def _validate_obligation_row(
    row: Mapping[str, Any],
    provenance: EvidenceObligationProvenance,
    context: _CompilerContext,
    resolved: ResolvedConfig,
) -> None:
    obligation_id = str(row["obligation_id"])
    event_id = str(row["event_id"])
    event = context.events.get(event_id)
    if event is None:
        raise EvidenceObligationError(f"obligation {obligation_id}: event does not resolve")
    decision = context.decisions[event_id]
    if str(row["policy_rule_id"]) not in set(decision["applied_rule_ids"]):
        raise EvidenceObligationError(
            f"obligation {obligation_id}: policy rule was not applied to triggering event"
        )
    subject_id = str(row["subject_object_id"])
    object_id = str(event["data_object_id"])
    replica_ids = {
        str(replica["replica_id"]): replica
        for replica in context.replicas_by_object.get(object_id, ())
    }
    if subject_id != object_id and subject_id not in replica_ids:
        raise EvidenceObligationError(
            f"obligation {obligation_id}: subject is not the event object or one of its replicas"
        )
    actor_id = str(row["responsible_actor_id"])
    if actor_id not in context.actors:
        raise EvidenceObligationError(f"obligation {obligation_id}: responsible actor does not resolve")
    if _timestamp(str(row["due_at"])) < _timestamp(str(event["timestamp"])):
        raise EvidenceObligationError(f"obligation {obligation_id}: due_at precedes triggering event")
    evidence_types = tuple(str(value) for value in row["required_evidence_types"])
    if not evidence_types or len(set(evidence_types)) != len(evidence_types):
        raise EvidenceObligationError(f"obligation {obligation_id}: evidence types are empty or duplicated")
    if set(evidence_types) - set(resolved.evidence.receipt_profiles):
        raise EvidenceObligationError(f"obligation {obligation_id}: evidence type is not enabled")
    if int(row["minimum_count"]) <= 0:
        raise EvidenceObligationError(f"obligation {obligation_id}: minimum_count must be positive")
    if provenance.scenario_id != context.scenario_id or provenance.obligation_id != obligation_id:
        raise EvidenceObligationError(f"obligation {obligation_id}: provenance identity mismatch")
    if not provenance.template_clause_ids or not provenance.source_policy_rule_ids:
        raise EvidenceObligationError(f"obligation {obligation_id}: provenance is incomplete")
    if not provenance.coverage_member_ids or not provenance.dependency_event_ids:
        raise EvidenceObligationError(f"obligation {obligation_id}: coverage/dependency expansion is empty")
    unknown_dependencies = sorted(set(provenance.dependency_event_ids) - set(context.events))
    if unknown_dependencies:
        raise EvidenceObligationError(
            f"obligation {obligation_id}: dependency events do not resolve {unknown_dependencies[:8]}"
        )


def _validate_erasure_coverage(
    rows: Sequence[Mapping[str, Any]],
    provenance_by_id: Mapping[str, EvidenceObligationProvenance],
    context: _CompilerContext,
) -> None:
    rows_by_event: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        rows_by_event.setdefault(str(row["event_id"]), []).append(row)
    for event_id, event in context.events.items():
        workflow = context.workflows[str(event["workflow_instance_id"])]
        if str(workflow["workflow_type"]) != "erasure":
            continue
        object_id = str(event["data_object_id"])
        replicas = context.replicas_by_object.get(object_id, ())
        exempt_ids = {str(row["replica_id"]) for row in replicas if row["deletion_status"] == "exempt"}
        non_exempt_ids = {str(row["replica_id"]) for row in replicas if row["deletion_status"] != "exempt"}
        event_rows = rows_by_event.get(event_id, [])
        event_type = str(event["event_type"])
        if event_type == "erasure_requested":
            _require_obligation(event_rows, "authorization", "object", {object_id}, event_id)
            scoping = [
                row
                for row in event_rows
                if row["obligation_type"] == "provenance"
                and any("ERASURE-REQUEST-SCOPING" in value for value in provenance_by_id[row["obligation_id"]].template_clause_ids)
            ]
            if not scoping:
                raise EvidenceObligationError(f"event {event_id}: missing erasure scoping obligation")
            _require_obligation(event_rows, "retention_exception", "replica_set", exempt_ids, event_id)
        elif event_type == "erasure_propagated":
            _require_obligation(event_rows, "provenance", "replica_set", non_exempt_ids, event_id)
            _forbid_replica_subjects(event_rows, exempt_ids, {"provenance", "replica_deletion"}, event_id)
        elif event_type == "erasure_executed":
            _require_obligation(event_rows, "replica_deletion", "replica_set", non_exempt_ids, event_id)
            _forbid_replica_subjects(event_rows, exempt_ids, {"provenance", "replica_deletion"}, event_id)
        elif event_type == "erasure_verified":
            verification = [
                row
                for row in event_rows
                if row["obligation_type"] == "verification"
                and row["coverage_scope"] == "causal_closure"
            ]
            if len(verification) != 1:
                raise EvidenceObligationError(f"event {event_id}: requires exactly one final verification obligation")
            provenance = provenance_by_id[str(verification[0]["obligation_id"])]
            expected_dependencies = set(context.full_closure_by_event[event_id])
            if set(provenance.dependency_event_ids) != expected_dependencies:
                raise EvidenceObligationError(f"event {event_id}: final verification closure is incomplete")
            if int(verification[0]["minimum_count"]) < len(expected_dependencies):
                raise EvidenceObligationError(f"event {event_id}: final verification minimum count is incomplete")


def _require_obligation(
    rows: Sequence[Mapping[str, Any]],
    obligation_type: str,
    coverage_scope: str,
    expected_subject_ids: set[str],
    event_id: str,
) -> None:
    observed = {
        str(row["subject_object_id"])
        for row in rows
        if row["obligation_type"] == obligation_type and row["coverage_scope"] == coverage_scope
    }
    if observed != expected_subject_ids:
        raise EvidenceObligationError(
            f"event {event_id}: {obligation_type}/{coverage_scope} subjects mismatch; "
            f"expected={sorted(expected_subject_ids)} observed={sorted(observed)}"
        )


def _forbid_replica_subjects(
    rows: Sequence[Mapping[str, Any]],
    forbidden_subject_ids: set[str],
    obligation_types: set[str],
    event_id: str,
) -> None:
    improper = sorted(
        str(row["subject_object_id"])
        for row in rows
        if row["obligation_type"] in obligation_types
        and str(row["subject_object_id"]) in forbidden_subject_ids
    )
    if improper:
        raise EvidenceObligationError(
            f"event {event_id}: exempt replicas received deletion/propagation obligations {improper}"
        )


def _diagnostics(
    context: _CompilerContext,
    candidates: Sequence[_Candidate],
    obligations: Sequence[Mapping[str, Any]],
    provenance: Sequence[EvidenceObligationProvenance],
) -> EvidenceObligationDiagnostics:
    covered_events = {str(row["event_id"]) for row in obligations}
    obligation_types: dict[str, int] = {}
    scopes: dict[str, int] = {}
    for row in obligations:
        obligation_types[str(row["obligation_type"])] = obligation_types.get(str(row["obligation_type"]), 0) + 1
        scopes[str(row["coverage_scope"])] = scopes.get(str(row["coverage_scope"]), 0) + 1
    exempt_ids = {value for item in provenance for value in item.exempt_member_ids}
    return EvidenceObligationDiagnostics(
        scenario_id=context.scenario_id,
        replicate_id=context.replicate_id,
        obligation_count=len(obligations),
        expanded_candidate_count=len(candidates),
        minimized_candidate_count=len(candidates) - len(obligations),
        evidence_trigger_event_count=len(context.evidence_trigger_event_ids),
        covered_trigger_event_count=len(context.evidence_trigger_event_ids & covered_events),
        exempt_replica_count=len(exempt_ids),
        obligation_type_counts=dict(sorted(obligation_types.items())),
        coverage_scope_counts=dict(sorted(scopes.items())),
    )


def _winning_policy_rule(rule_ids: Sequence[str], package: PolicyPackage) -> str:
    rules = {rule.policy_rule_id: rule for rule in package.rules}
    unknown = sorted(set(rule_ids) - set(rules))
    if unknown:
        raise EvidenceObligationError(f"unknown policy rules in obligation grammar {unknown}")
    return min(
        rule_ids,
        key=lambda rule_id: (
            -rules[rule_id].priority,
            -rules[rule_id].specificity,
            rule_id,
        ),
    )


def _event_actor(event: Mapping[str, Any], role: str) -> str:
    field = f"{role}_actor_id"
    actor_id = event.get(field)
    if actor_id is None:
        raise EvidenceObligationError(
            f"event {event['event_id']}: responsible role {role!r} does not resolve"
        )
    return str(actor_id)


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceObligationError(f"invalid UTC timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise EvidenceObligationError(f"timestamp must be normalized to UTC: {value!r}")
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
