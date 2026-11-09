"""S07 normalized event-edge DAG and dependency closure indexes.

The authoritative dependency representation is ``event_edge.parquet``. Root
event IDs and causal depths are recomputed from that normalized table after
workflow traces are emitted. Inline fields on governance events are rewritten
from the DAG result and then validated against the recomputed graph.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.arrivals import ArrivalBuild, build_arrivals
from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.physical import PhysicalRawBuild, build_physical_raw
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import content_id
from htgl_dataset_generator.workflows import WorkflowBuild, WorkflowSideEffect, build_workflows
from htgl_dataset_generator.world import FederatedWorld, build_federated_world


EDGE_TYPES: tuple[str, ...] = (
    "causes",
    "responds_to",
    "derives",
    "copies",
    "discloses",
    "invalidates",
    "erases",
    "evidences",
    "precedes",
)
ACYCLIC_EDGE_TYPES = frozenset(EDGE_TYPES)
SIDEEFFECT_EDGE_TYPE: Mapping[str, str] = {
    "replica_creation": "copies",
    "disclosure": "discloses",
    "derivation": "derives",
    "correction": "invalidates",
    "invalidation": "invalidates",
    "deletion_status_update": "erases",
    "evidence_trigger": "evidences",
}
REPLICA_CLOSURE_EDGE_TYPES = frozenset({"copies", "derives"})
EVIDENCE_CLOSURE_EDGE_TYPES = frozenset({"evidences"})


class DagValidationError(ValueError):
    """Raised when the normalized causal graph violates S07 invariants."""


@dataclass(frozen=True)
class ClosureIndexRecord:
    scenario_id: str
    unit_id: str
    closure_type: str
    member_event_ids: tuple[str, ...]
    closure_size: int
    max_member_depth: int

    def as_record(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "unit_id": self.unit_id,
            "closure_type": self.closure_type,
            "member_event_ids": list(self.member_event_ids),
            "closure_size": self.closure_size,
            "max_member_depth": self.max_member_depth,
        }


@dataclass(frozen=True)
class CausalDagDiagnostics:
    scenario_id: str
    event_count: int
    edge_count: int
    orphan_non_root_count: int
    disallowed_cycle_count: int
    depth_reconciliation_error_count: int
    closure_record_count: int
    max_closure_size: int
    edge_type_counts: Mapping[str, int]


@dataclass(frozen=True)
class CausalDagBuild:
    governance_events: tuple[dict[str, Any], ...]
    event_edges: tuple[dict[str, Any], ...]
    workflow_instances: tuple[dict[str, Any], ...]
    closure_index: tuple[ClosureIndexRecord, ...]
    diagnostics: Mapping[str, CausalDagDiagnostics]

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "governance_event": self.governance_events,
            "event_edge": self.event_edges,
            "workflow_instance": self.workflow_instances,
        }


def build_causal_dag(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    catalog: CatalogBuild | None = None,
    physical: PhysicalRawBuild | None = None,
    arrivals: ArrivalBuild | None = None,
    workflows: WorkflowBuild | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> CausalDagBuild:
    """Normalize S06 traces into an authoritative event-edge DAG."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise DagValidationError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise DagValidationError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise DagValidationError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )

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
    physical_build = (
        physical
        if physical is not None
        else build_physical_raw(
            resolved,
            world=world_build,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    arrival_build = (
        arrivals
        if arrivals is not None
        else build_arrivals(
            resolved,
            world=world_build,
            catalog=catalog_build,
            physical=physical_build,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    workflow_build = (
        workflows
        if workflows is not None
        else build_workflows(
            resolved,
            world=world_build,
            catalog=catalog_build,
            physical=physical_build,
            arrivals=arrival_build,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )

    all_events: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []
    all_instances: list[dict[str, Any]] = []
    all_closure: list[ClosureIndexRecord] = []
    diagnostics: dict[str, CausalDagDiagnostics] = {}
    for scenario_id in sorted(selected):
        scenario_events = tuple(
            dict(row) for row in workflow_build.governance_events if row["scenario_id"] == scenario_id
        )
        scenario_edges = tuple(
            dict(row) for row in workflow_build.event_edges if row["scenario_id"] == scenario_id
        )
        scenario_instances = tuple(
            dict(row) for row in workflow_build.workflow_instances if row["scenario_id"] == scenario_id
        )
        scenario_effects = tuple(
            effect for effect in workflow_build.side_effects if effect.scenario_id == scenario_id
        )
        scenario_arrivals = tuple(
            dict(row)
            for row in arrival_build.arrivals
            if row["scenario_id"] == scenario_id and int(row["replicate_id"]) == replicate_id
        )
        normalized_edges = _normalize_edges(
            scenario_id,
            scenario_events,
            scenario_edges,
            scenario_effects,
            scenario_arrivals,
        )
        roots_depths = _compute_roots_and_depths(scenario_events, normalized_edges)
        updated_events = _rewrite_events_from_dag(scenario_events, roots_depths)
        updated_instances = _rewrite_instances_from_dag(scenario_instances, updated_events)
        closure = _build_closure_index(scenario_id, updated_events, normalized_edges)
        partial = CausalDagBuild(
            governance_events=updated_events,
            event_edges=normalized_edges,
            workflow_instances=updated_instances,
            closure_index=closure,
            diagnostics={
                scenario_id: _diagnostics(scenario_id, updated_events, normalized_edges, closure)
            },
        )
        validate_causal_dag(partial, resolved, contract=schema_contract)
        all_events.extend(partial.governance_events)
        all_edges.extend(partial.event_edges)
        all_instances.extend(partial.workflow_instances)
        all_closure.extend(partial.closure_index)
        diagnostics[scenario_id] = partial.diagnostics[scenario_id]

    return CausalDagBuild(
        governance_events=tuple(sorted(all_events, key=lambda row: (row["scenario_id"], row["event_id"]))),
        event_edges=tuple(sorted(all_edges, key=lambda row: (row["scenario_id"], row["edge_id"]))),
        workflow_instances=tuple(sorted(all_instances, key=lambda row: (row["scenario_id"], row["workflow_instance_id"]))),
        closure_index=tuple(sorted(all_closure, key=lambda row: (row.scenario_id, row.unit_id, row.closure_type))),
        diagnostics=dict(sorted(diagnostics.items())),
    )


def _normalize_edges(
    scenario_id: str,
    events: tuple[dict[str, Any], ...],
    edges: tuple[dict[str, Any], ...],
    side_effects: tuple[WorkflowSideEffect, ...],
    arrivals: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    event_by_id = {str(row["event_id"]): row for row in events}
    if len(event_by_id) != len(events):
        raise DagValidationError(f"{scenario_id}: duplicate governance_event.event_id values")
    event_ids = set(event_by_id)
    workflow_by_event = {
        event_id: str(row["workflow_instance_id"]) for event_id, row in event_by_id.items()
    }
    normalized: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_edge(
        source_event_id: str,
        target_event_id: str,
        edge_type: str,
        *,
        dependency_strength: float,
        required_for_closure: bool,
        rule_id: str,
        declared_cross_workflow: bool | None = None,
    ) -> None:
        if edge_type not in EDGE_TYPES:
            raise DagValidationError(f"unknown edge_type={edge_type!r}")
        if source_event_id == target_event_id:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: self edge is not allowed"
            )
        if source_event_id not in event_ids:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: source_event_id does not resolve"
            )
        if target_event_id not in event_ids:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: target_event_id does not resolve"
            )
        source_scenario_id = str(event_by_id[source_event_id]["scenario_id"])
        target_scenario_id = str(event_by_id[target_event_id]["scenario_id"])
        if source_scenario_id != scenario_id or target_scenario_id != scenario_id:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: endpoint scenario does not match {scenario_id}"
            )
        cross_workflow = workflow_by_event[source_event_id] != workflow_by_event[target_event_id]
        if declared_cross_workflow is not None and declared_cross_workflow != cross_workflow:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: cross_workflow flag does not match endpoints"
            )
        if not math.isfinite(dependency_strength) or not 0.0 <= dependency_strength <= 1.0:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: dependency_strength must be finite in [0, 1]"
            )
        normalized_rule_id = rule_id.strip()
        if not normalized_rule_id:
            raise DagValidationError(
                f"edge {source_event_id}->{target_event_id}/{edge_type}: rule_id is required"
            )
        key = (source_event_id, target_event_id, edge_type)
        if key in normalized:
            existing = normalized[key]
            existing["dependency_strength"] = max(
                float(existing["dependency_strength"] or 0.0), dependency_strength
            )
            existing["required_for_closure"] = bool(existing["required_for_closure"] or required_for_closure)
            existing["rule_ids"].add(normalized_rule_id)
            return
        normalized[key] = {
            "scenario_id": scenario_id,
            "source_event_id": source_event_id,
            "target_event_id": target_event_id,
            "edge_type": edge_type,
            "cross_workflow": cross_workflow,
            "dependency_strength": float(dependency_strength),
            "required_for_closure": required_for_closure,
            "rule_ids": {normalized_rule_id},
        }

    for edge in edges:
        if str(edge["scenario_id"]) != scenario_id:
            raise DagValidationError(f"edge {edge['edge_id']}: scenario_id does not match partition")
        add_edge(
            str(edge["source_event_id"]),
            str(edge["target_event_id"]),
            str(edge["edge_type"]),
            dependency_strength=float(edge["dependency_strength"] if edge["dependency_strength"] is not None else 1.0),
            required_for_closure=bool(edge["required_for_closure"]),
            rule_id=str(edge["rule_id"] or ""),
            declared_cross_workflow=bool(edge["cross_workflow"]),
        )

    events_by_workflow = _events_by_workflow(events)
    previous_by_event: dict[str, str] = {}
    for workflow_id, workflow_events in events_by_workflow.items():
        for index, event in enumerate(workflow_events):
            if index == 0:
                continue
            previous_id = str(workflow_events[index - 1]["event_id"])
            target_id = str(event["event_id"])
            previous_by_event[target_id] = previous_id
            add_edge(
                previous_id,
                target_id,
                "precedes",
                dependency_strength=0.75,
                required_for_closure=True,
                rule_id="S07-WORKFLOW-PRECEDES",
            )
            if index == 1:
                add_edge(
                    str(workflow_events[0]["event_id"]),
                    target_id,
                    "causes",
                    dependency_strength=1.0,
                    required_for_closure=True,
                    rule_id="S07-WORKFLOW-ROOT-CAUSE",
                )

    for effect in side_effects:
        edge_type = SIDEEFFECT_EDGE_TYPE.get(effect.side_effect_type)
        if edge_type is None:
            raise DagValidationError(
                f"side effect {effect.side_effect_id}: no edge mapping for {effect.side_effect_type!r}"
            )
        if effect.event_id not in event_ids:
            raise DagValidationError(f"side effect {effect.side_effect_id}: event_id does not resolve")
        if effect.workflow_instance_id != workflow_by_event[effect.event_id]:
            raise DagValidationError(
                f"side effect {effect.side_effect_id}: workflow_instance_id does not match event"
            )
        source_event_id = previous_by_event.get(effect.event_id)
        if source_event_id is None:
            continue
        add_edge(
            source_event_id,
            effect.event_id,
            edge_type,
            dependency_strength=0.90,
            required_for_closure=True,
            rule_id=effect.rule_id,
        )

    effects_by_target: dict[tuple[str, str], list[WorkflowSideEffect]] = {}
    for effect in side_effects:
        if effect.side_effect_type not in SIDEEFFECT_EDGE_TYPE:
            continue
        effects_by_target.setdefault((effect.target_table, effect.target_id), []).append(effect)
    for target_key in sorted(effects_by_target):
        ordered_effects = sorted(
            effects_by_target[target_key],
            key=lambda effect: (
                str(event_by_id[effect.event_id]["timestamp"]),
                int(event_by_id[effect.event_id]["workflow_step_index"]),
                effect.event_id,
                effect.side_effect_id,
            ),
        )
        previous_effect: WorkflowSideEffect | None = None
        for effect in ordered_effects:
            if previous_effect is not None:
                previous_event = event_by_id[previous_effect.event_id]
                current_event = event_by_id[effect.event_id]
                if (
                    previous_effect.event_id != effect.event_id
                    and workflow_by_event[previous_effect.event_id] != workflow_by_event[effect.event_id]
                    and str(previous_event["timestamp"]) < str(current_event["timestamp"])
                ):
                    add_edge(
                        previous_effect.event_id,
                        effect.event_id,
                        "precedes",
                        dependency_strength=0.50,
                        required_for_closure=False,
                        rule_id="S07-TARGET-TEMPORAL-ORDER",
                    )
            previous_effect = effect

    arrival_by_id = {str(row["arrival_id"]): row for row in arrivals}
    if len(arrival_by_id) != len(arrivals):
        raise DagValidationError(f"{scenario_id}: duplicate arrival.arrival_id values")
    root_event_by_arrival: dict[str, Mapping[str, Any]] = {}
    for event in events:
        source_event_id = str(event["source_event_id"] or "")
        if int(event["workflow_step_index"]) == 0 and source_event_id in arrival_by_id:
            if source_event_id in root_event_by_arrival:
                raise DagValidationError(f"arrival {source_event_id}: resolves to multiple workflow roots")
            root_event_by_arrival[source_event_id] = event
    missing_roots = sorted(set(arrival_by_id) - set(root_event_by_arrival))
    if missing_roots:
        raise DagValidationError(f"arrivals do not resolve to workflow roots {missing_roots[:8]}")
    for arrival_id in sorted(arrival_by_id):
        parent_arrival_id = arrival_by_id[arrival_id].get("parent_arrival_id")
        if parent_arrival_id is None:
            continue
        parent_arrival_id = str(parent_arrival_id)
        if parent_arrival_id not in arrival_by_id:
            raise DagValidationError(
                f"arrival {arrival_id}: parent_arrival_id={parent_arrival_id!r} does not resolve"
            )
        add_edge(
            str(root_event_by_arrival[parent_arrival_id]["event_id"]),
            str(root_event_by_arrival[arrival_id]["event_id"]),
            "causes",
            dependency_strength=1.0,
            required_for_closure=True,
            rule_id="S07-ARRIVAL-PARENT-CAUSE",
        )

    finalized: list[dict[str, Any]] = []
    for key in sorted(normalized):
        accumulator = normalized[key]
        rule_ids = tuple(sorted(accumulator.pop("rule_ids")))
        rule_id = rule_ids[0] if len(rule_ids) == 1 else f"S07-MERGED({','.join(rule_ids)})"
        row = dict(accumulator)
        row["rule_id"] = rule_id
        row["edge_id"] = content_id(
            "event_edge",
            {
                "edge_type": row["edge_type"],
                "rule_id": rule_id,
                "scenario_id": scenario_id,
                "source_event_id": row["source_event_id"],
                "target_event_id": row["target_event_id"],
            },
        )
        finalized.append(row)
    return tuple(finalized)


def _compute_roots_and_depths(
    events: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> Mapping[str, tuple[str, int]]:
    event_ids = {str(row["event_id"]) for row in events}
    incoming: dict[str, set[str]] = {event_id: set() for event_id in event_ids}
    outgoing: dict[str, set[str]] = {event_id: set() for event_id in event_ids}
    for edge in edges:
        if edge["edge_type"] not in ACYCLIC_EDGE_TYPES or not bool(edge["required_for_closure"]):
            continue
        source = str(edge["source_event_id"])
        target = str(edge["target_event_id"])
        if source not in event_ids or target not in event_ids:
            raise DagValidationError(f"edge {edge['edge_id']}: endpoint does not resolve")
        incoming[target].add(source)
        outgoing[source].add(target)

    remaining_incoming = {event_id: set(parents) for event_id, parents in incoming.items()}
    queue = sorted(event_id for event_id, parents in remaining_incoming.items() if not parents)
    root_by_event = {event_id: event_id for event_id in queue}
    depth_by_event = {event_id: 0 for event_id in queue}
    visited: list[str] = []
    while queue:
        current = queue.pop(0)
        visited.append(current)
        for child in sorted(outgoing[current]):
            candidate_depth = depth_by_event[current] + 1
            candidate_root = root_by_event[current]
            if (
                child not in depth_by_event
                or candidate_depth > depth_by_event[child]
                or (candidate_depth == depth_by_event[child] and candidate_root < root_by_event[child])
            ):
                depth_by_event[child] = candidate_depth
                root_by_event[child] = candidate_root
            remaining_incoming[child].discard(current)
            if not remaining_incoming[child] and child not in visited and child not in queue:
                queue.append(child)
                queue.sort()
    if len(visited) != len(event_ids):
        cycle_nodes = sorted(event_ids - set(visited))
        raise DagValidationError(f"disallowed cycle detected among events {cycle_nodes[:8]}")
    return {event_id: (root_by_event[event_id], depth_by_event[event_id]) for event_id in sorted(event_ids)}


def _rewrite_events_from_dag(
    events: Sequence[Mapping[str, Any]],
    roots_depths: Mapping[str, tuple[str, int]],
) -> tuple[dict[str, Any], ...]:
    rewritten: list[dict[str, Any]] = []
    for event in events:
        row = dict(event)
        root_event_id, causal_depth = roots_depths[str(row["event_id"])]
        row["root_event_id"] = root_event_id
        row["causal_depth"] = causal_depth
        rewritten.append(row)
    return tuple(sorted(rewritten, key=lambda row: (row["workflow_instance_id"], row["causal_depth"], row["event_id"])))


def _rewrite_instances_from_dag(
    instances: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    events_by_workflow = _events_by_workflow(events)
    rewritten: list[dict[str, Any]] = []
    for instance in instances:
        row = dict(instance)
        workflow_events = events_by_workflow[str(row["workflow_instance_id"])]
        row["root_event_id"] = workflow_events[0]["event_id"]
        row["final_state"] = workflow_events[-1]["workflow_state_after"]
        row["event_count"] = len(workflow_events)
        if row["terminal_event_id"] is not None:
            row["terminal_event_id"] = workflow_events[-1]["event_id"]
            row["ended_at"] = workflow_events[-1]["timestamp"]
        rewritten.append(row)
    return tuple(sorted(rewritten, key=lambda row: row["workflow_instance_id"]))


def _build_closure_index(
    scenario_id: str,
    events: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> tuple[ClosureIndexRecord, ...]:
    event_ids = tuple(sorted(str(row["event_id"]) for row in events))
    depth_by_event = {str(row["event_id"]): int(row["causal_depth"]) for row in events}
    forward_all, reverse_all = _adjacency(edges, edge_types=None)
    forward_replica, reverse_replica = _adjacency(edges, edge_types=REPLICA_CLOSURE_EDGE_TYPES)
    forward_evidence, reverse_evidence = _adjacency(edges, edge_types=EVIDENCE_CLOSURE_EDGE_TYPES)
    records: list[ClosureIndexRecord] = []
    for event_id in event_ids:
        ancestors = _reachable(event_id, reverse_all)
        descendants = _reachable(event_id, forward_all)
        replica = tuple(sorted(set(_reachable(event_id, forward_replica)) | set(_reachable(event_id, reverse_replica))))
        evidence = tuple(sorted(set(_reachable(event_id, forward_evidence)) | set(_reachable(event_id, reverse_evidence))))
        full = tuple(sorted(set(ancestors) | set(descendants)))
        records.append(_closure_record(scenario_id, event_id, "ancestor", ancestors, depth_by_event))
        records.append(_closure_record(scenario_id, event_id, "descendant", descendants, depth_by_event))
        records.append(_closure_record(scenario_id, event_id, "replica", replica, depth_by_event))
        records.append(_closure_record(scenario_id, event_id, "evidence", evidence, depth_by_event))
        records.append(_closure_record(scenario_id, event_id, "full_dependency", full, depth_by_event))
    return tuple(sorted(records, key=lambda row: (row.unit_id, row.closure_type)))


def _closure_record(
    scenario_id: str,
    unit_id: str,
    closure_type: str,
    members: Sequence[str],
    depth_by_event: Mapping[str, int],
) -> ClosureIndexRecord:
    member_ids = tuple(sorted(members))
    return ClosureIndexRecord(
        scenario_id=scenario_id,
        unit_id=unit_id,
        closure_type=closure_type,
        member_event_ids=member_ids,
        closure_size=len(member_ids),
        max_member_depth=max((depth_by_event[member] for member in member_ids), default=depth_by_event[unit_id]),
    )


def _adjacency(
    edges: Sequence[Mapping[str, Any]],
    *,
    edge_types: frozenset[str] | None,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for edge in edges:
        if not bool(edge["required_for_closure"]):
            continue
        if edge_types is not None and edge["edge_type"] not in edge_types:
            continue
        source = str(edge["source_event_id"])
        target = str(edge["target_event_id"])
        forward.setdefault(source, set()).add(target)
        reverse.setdefault(target, set()).add(source)
        forward.setdefault(target, set())
        reverse.setdefault(source, set())
    return forward, reverse


def _reachable(start: str, adjacency: Mapping[str, set[str]]) -> tuple[str, ...]:
    visited: set[str] = set()
    stack = list(sorted(adjacency.get(start, ()), reverse=True))
    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        for child in sorted(adjacency.get(current, ()), reverse=True):
            if child not in visited:
                stack.append(child)
    visited.discard(start)
    return tuple(sorted(visited))


def _diagnostics(
    scenario_id: str,
    events: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    closure: Sequence[ClosureIndexRecord],
) -> CausalDagDiagnostics:
    roots_depths = _compute_roots_and_depths(events, edges)
    incoming_required: dict[str, int] = {str(row["event_id"]): 0 for row in events}
    for edge in edges:
        if bool(edge["required_for_closure"]):
            incoming_required[str(edge["target_event_id"])] += 1
    orphan_count = sum(
        1
        for event in events
        if int(event["causal_depth"]) > 0 and incoming_required[str(event["event_id"])] == 0
    )
    depth_errors = sum(
        1
        for event in events
        if roots_depths[str(event["event_id"])] != (str(event["root_event_id"]), int(event["causal_depth"]))
    )
    edge_type_counts = {edge_type: 0 for edge_type in EDGE_TYPES}
    for edge in edges:
        edge_type_counts[str(edge["edge_type"])] = edge_type_counts.get(str(edge["edge_type"]), 0) + 1
    return CausalDagDiagnostics(
        scenario_id=scenario_id,
        event_count=len(events),
        edge_count=len(edges),
        orphan_non_root_count=orphan_count,
        disallowed_cycle_count=0,
        depth_reconciliation_error_count=depth_errors,
        closure_record_count=len(closure),
        max_closure_size=max((record.closure_size for record in closure), default=0),
        edge_type_counts=dict(sorted(edge_type_counts.items())),
    )


def validate_causal_dag(
    dag_build: CausalDagBuild,
    resolved: ResolvedConfig,
    *,
    contract: ContractSpec | None = None,
) -> None:
    """Fail-closed validation for normalized S07 causal graph artifacts."""

    schema_contract = contract if contract is not None else load_contract()
    event_by_id = {str(row["event_id"]): row for row in dag_build.governance_events}
    if len(event_by_id) != len(dag_build.governance_events):
        raise DagValidationError("duplicate governance_event.event_id values")
    event_ids = set(event_by_id)
    workflow_by_event = {
        event_id: str(row["workflow_instance_id"]) for event_id, row in event_by_id.items()
    }
    selected_scenario_ids = set(resolved.run.selected_scenario_ids)
    edge_ids = {str(row["edge_id"]) for row in dag_build.event_edges}
    if len(edge_ids) != len(dag_build.event_edges):
        raise DagValidationError("duplicate event_edge.edge_id values")
    edge_keys: set[tuple[str, str, str]] = set()
    for event in dag_build.governance_events:
        validate_record(schema_contract, "governance_event", event)
        if str(event["scenario_id"]) not in selected_scenario_ids:
            raise DagValidationError(
                f"event {event['event_id']}: scenario_id is not selected by the resolved run"
            )
    for edge in dag_build.event_edges:
        validate_record(schema_contract, "event_edge", edge)
        source = str(edge["source_event_id"])
        target = str(edge["target_event_id"])
        if source not in event_ids:
            raise DagValidationError(f"edge {edge['edge_id']}: source_event_id does not resolve")
        if target not in event_ids:
            raise DagValidationError(f"edge {edge['edge_id']}: target_event_id does not resolve")
        if source == target:
            raise DagValidationError(f"edge {edge['edge_id']}: self edge is not allowed")
        source_scenario_id = str(event_by_id[source]["scenario_id"])
        target_scenario_id = str(event_by_id[target]["scenario_id"])
        if str(edge["scenario_id"]) != source_scenario_id or source_scenario_id != target_scenario_id:
            raise DagValidationError(f"edge {edge['edge_id']}: scenario_id does not match endpoints")
        expected_cross_workflow = workflow_by_event[source] != workflow_by_event[target]
        if bool(edge["cross_workflow"]) != expected_cross_workflow:
            raise DagValidationError(f"edge {edge['edge_id']}: cross_workflow flag does not match endpoints")
        dependency_strength = edge["dependency_strength"]
        if dependency_strength is not None:
            strength = float(dependency_strength)
            if not math.isfinite(strength) or not 0.0 <= strength <= 1.0:
                raise DagValidationError(
                    f"edge {edge['edge_id']}: dependency_strength must be finite in [0, 1]"
                )
        if edge["rule_id"] is None or not str(edge["rule_id"]).strip():
            raise DagValidationError(f"edge {edge['edge_id']}: rule_id is required")
        key = (source, target, str(edge["edge_type"]))
        if key in edge_keys:
            raise DagValidationError(f"duplicate edge key {key}")
        edge_keys.add(key)
    roots_depths = _compute_roots_and_depths(dag_build.governance_events, dag_build.event_edges)
    incoming_required: dict[str, int] = {event_id: 0 for event_id in event_ids}
    for edge in dag_build.event_edges:
        if bool(edge["required_for_closure"]):
            incoming_required[str(edge["target_event_id"])] += 1
    for event in dag_build.governance_events:
        event_id = str(event["event_id"])
        root_event_id, causal_depth = roots_depths[event_id]
        if str(event["root_event_id"]) != root_event_id:
            raise DagValidationError(f"event {event_id}: root_event_id does not match normalized DAG")
        if int(event["causal_depth"]) != causal_depth:
            raise DagValidationError(f"event {event_id}: causal_depth does not match normalized DAG")
        if causal_depth > 0 and incoming_required[event_id] == 0:
            raise DagValidationError(f"event {event_id}: non-root event has no required incoming edge")
    events_by_workflow = _events_by_workflow(dag_build.governance_events)
    for instance in dag_build.workflow_instances:
        validate_record(schema_contract, "workflow_instance", instance)
        workflow_events = events_by_workflow.get(str(instance["workflow_instance_id"]))
        if workflow_events is None:
            raise DagValidationError(f"workflow {instance['workflow_instance_id']}: no events")
        if int(instance["event_count"]) != len(workflow_events):
            raise DagValidationError(f"workflow {instance['workflow_instance_id']}: event_count mismatch")
        if str(instance["root_event_id"]) != str(workflow_events[0]["event_id"]):
            raise DagValidationError(f"workflow {instance['workflow_instance_id']}: root_event_id mismatch")
    closure_event_ids = set(event_ids)
    expected_closure_types = {"ancestor", "descendant", "replica", "evidence", "full_dependency"}
    seen_closure: set[tuple[str, str, str]] = set()
    for record in dag_build.closure_index:
        if record.unit_id not in event_ids:
            raise DagValidationError(f"closure {record.unit_id}/{record.closure_type}: unit_id does not resolve")
        if record.scenario_id != str(event_by_id[record.unit_id]["scenario_id"]):
            raise DagValidationError(
                f"closure {record.unit_id}/{record.closure_type}: scenario_id does not match unit"
            )
        if record.closure_type not in expected_closure_types:
            raise DagValidationError(f"closure {record.unit_id}: unknown closure_type={record.closure_type}")
        if set(record.member_event_ids) - closure_event_ids:
            raise DagValidationError(f"closure {record.unit_id}/{record.closure_type}: member does not resolve")
        if len(record.member_event_ids) != record.closure_size:
            raise DagValidationError(f"closure {record.unit_id}/{record.closure_type}: closure_size mismatch")
        key = (record.scenario_id, record.unit_id, record.closure_type)
        if key in seen_closure:
            raise DagValidationError(f"duplicate closure record {key}")
        seen_closure.add(key)
    expected_closure_count = len(event_ids) * len(expected_closure_types)
    if len(dag_build.closure_index) != expected_closure_count:
        raise DagValidationError("closure index does not cover every event and closure type")
    recomputed_closure: list[ClosureIndexRecord] = []
    observed_scenario_ids = sorted({str(row["scenario_id"]) for row in dag_build.governance_events})
    for scenario_id in observed_scenario_ids:
        scenario_events = tuple(
            row for row in dag_build.governance_events if str(row["scenario_id"]) == scenario_id
        )
        scenario_edges = tuple(
            row for row in dag_build.event_edges if str(row["scenario_id"]) == scenario_id
        )
        recomputed_closure.extend(_build_closure_index(scenario_id, scenario_events, scenario_edges))
    expected_closure_records = {
        (record.scenario_id, record.unit_id, record.closure_type): record.as_record()
        for record in recomputed_closure
    }
    observed_closure_records = {
        (record.scenario_id, record.unit_id, record.closure_type): record.as_record()
        for record in dag_build.closure_index
    }
    if observed_closure_records != expected_closure_records:
        raise DagValidationError("closure index does not match normalized event-edge reachability")
    if set(dag_build.diagnostics) != set(observed_scenario_ids):
        raise DagValidationError("diagnostics do not cover exactly the observed scenarios")
    for scenario_id, diagnostics in dag_build.diagnostics.items():
        scenario_events = tuple(
            row for row in dag_build.governance_events if str(row["scenario_id"]) == scenario_id
        )
        scenario_edges = tuple(
            row for row in dag_build.event_edges if str(row["scenario_id"]) == scenario_id
        )
        scenario_closure = tuple(
            row for row in dag_build.closure_index if row.scenario_id == scenario_id
        )
        expected_diagnostics = _diagnostics(
            scenario_id,
            scenario_events,
            scenario_edges,
            scenario_closure,
        )
        if diagnostics != expected_diagnostics:
            raise DagValidationError(f"{scenario_id}: diagnostics do not reconcile to DAG artifacts")
        if diagnostics.orphan_non_root_count != 0:
            raise DagValidationError(f"{scenario_id}: causal orphan rate is not zero")
        if diagnostics.disallowed_cycle_count != 0:
            raise DagValidationError(f"{scenario_id}: disallowed cycle count is not zero")
        if diagnostics.depth_reconciliation_error_count != 0:
            raise DagValidationError(f"{scenario_id}: depth reconciliation errors detected")


def _events_by_workflow(events: Iterable[Mapping[str, Any]]) -> dict[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        grouped.setdefault(str(event["workflow_instance_id"]), []).append(event)
    return {
        workflow_id: tuple(sorted(rows, key=lambda row: int(row["workflow_step_index"])))
        for workflow_id, rows in grouped.items()
    }
