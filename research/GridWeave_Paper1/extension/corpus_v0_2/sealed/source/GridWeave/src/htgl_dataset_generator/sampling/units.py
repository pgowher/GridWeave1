"""Primary-unit registries and deterministic multi-domain dependency closure."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.catalog import CatalogBuild
from htgl_dataset_generator.config.resolver import SamplingConfig
from htgl_dataset_generator.dag import CausalDagBuild
from htgl_dataset_generator.evidence import EvidenceObligationBuild, EvidenceReceiptBuild
from htgl_dataset_generator.seeds import deterministic_uuid
from htgl_dataset_generator.world import FederatedWorld

from .models import DependencyClosure, PopulationUnit, PrimaryUnit, UnitKey


STRATUM_FIELDS: Mapping[str, frozenset[str]] = {
    "workflow": frozenset({"region_id", "event_family", "cohort_id", "workflow_type"}),
    "cohort": frozenset({"region_id", "sampling_stratum", "cohort_id", "subject_scope"}),
    "actor": frozenset({"region_id", "actor_class", "jurisdiction_id"}),
    "object": frozenset({"region_id", "object_type", "data_object_id"}),
    "time_bin": frozenset({"region_id", "time_bin"}),
    "dependency_component": frozenset({"region_id", "component_size_band"}),
}
EVENT_ACTOR_FIELDS = (
    "source_actor_id",
    "requesting_actor_id",
    "controller_actor_id",
    "processor_actor_id",
    "oversight_actor_id",
)
CLOSURE_INDEX_NAMES = {
    "ancestor": "ancestor",
    "descendant": "descendant",
    "replica": "replica",
    "evidence": "evidence",
    "full_dependency_closure": "full_dependency",
}


class SamplingUnitError(ValueError):
    """Raised when a primary-unit universe or closure cannot be resolved."""


def parse_stratum_definitions(config: SamplingConfig) -> Mapping[str, tuple[str, ...]]:
    definitions: dict[str, tuple[str, ...]] = {}
    for raw in config.strata_definitions:
        if raw.count("=") != 1:
            raise SamplingUnitError(
                f"invalid stratum definition {raw!r}; expected unit_type=field[:field]"
            )
        unit_type, expression = raw.split("=", 1)
        fields = tuple(expression.split(":"))
        unknown = sorted(set(fields) - set(STRATUM_FIELDS.get(unit_type, ())))
        if unit_type not in STRATUM_FIELDS or not fields or unknown:
            raise SamplingUnitError(
                f"stratum definition {raw!r} has unsupported fields {unknown}"
            )
        if unit_type in definitions:
            raise SamplingUnitError(f"duplicate stratum definition for {unit_type}")
        definitions[unit_type] = fields
    if set(definitions) != set(config.primary_unit_types):
        raise SamplingUnitError(
            "stratum definitions must exactly match configured primary unit types"
        )
    return dict(sorted(definitions.items()))


def build_dependency_closure(
    *,
    scenario_id: str,
    namespace: str,
    sampling_config: SamplingConfig,
    primary_unit_type: str,
    world: FederatedWorld,
    catalog: CatalogBuild,
    dag: CausalDagBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
) -> DependencyClosure:
    """Build all possible primary closures and invert them for induced probabilities."""

    definitions = parse_stratum_definitions(sampling_config)
    if primary_unit_type not in definitions:
        raise SamplingUnitError(
            f"primary unit type {primary_unit_type!r} has no controlled stratum definition"
        )
    context = _UnitContext(
        scenario_id=scenario_id,
        namespace=namespace,
        closure_policy=sampling_config.closure_policy,
        stratum_fields=definitions[primary_unit_type],
        world=world,
        catalog=catalog,
        dag=dag,
        obligations=obligations,
        receipts=receipts,
    )
    primary_units = _primary_units(context, primary_unit_type)
    if not primary_units:
        raise SamplingUnitError(
            f"{scenario_id}: primary unit type={primary_unit_type} resolved no units"
        )
    population: dict[UnitKey, PopulationUnit] = {}
    members_by_primary: dict[str, tuple[UnitKey, ...]] = {}
    causes: dict[UnitKey, set[str]] = defaultdict(set)
    for primary in primary_units:
        members, member_records = _close_primary(context, primary)
        if primary.key not in members:
            raise SamplingUnitError(
                f"primary unit {primary.key.unit_id} is absent from its own closure"
            )
        members_by_primary[primary.key.unit_id] = tuple(sorted(members))
        for key, record in member_records.items():
            prior = population.get(key)
            if prior is not None and prior != record:
                raise SamplingUnitError(
                    f"inconsistent population metadata for {key.unit_type}/{key.unit_id}"
                )
            population[key] = record
            causes[key].add(primary.key.unit_id)
    return DependencyClosure(
        scenario_id=scenario_id,
        primary_unit_type=primary_unit_type,
        closure_policy=sampling_config.closure_policy,
        primary_units=tuple(sorted(primary_units, key=lambda item: item.key.unit_id)),
        population_units=dict(sorted(population.items())),
        members_by_primary=dict(sorted(members_by_primary.items())),
        causes_by_member={
            key: tuple(sorted(value)) for key, value in sorted(causes.items())
        },
    )


class _UnitContext:
    def __init__(
        self,
        *,
        scenario_id: str,
        namespace: str,
        closure_policy: str,
        stratum_fields: tuple[str, ...],
        world: FederatedWorld,
        catalog: CatalogBuild,
        dag: CausalDagBuild,
        obligations: EvidenceObligationBuild,
        receipts: EvidenceReceiptBuild,
    ) -> None:
        self.scenario_id = scenario_id
        self.namespace = namespace
        self.closure_policy = closure_policy
        self.stratum_fields = stratum_fields
        self.events = {
            str(row["event_id"]): row
            for row in dag.governance_events
            if str(row["scenario_id"]) == scenario_id
        }
        self.workflows = {
            str(row["workflow_instance_id"]): row
            for row in dag.workflow_instances
            if str(row["scenario_id"]) == scenario_id
        }
        self.events_by_workflow = _group(self.events.values(), "workflow_instance_id", "event_id")
        self.actors = {
            str(row["actor_id"]): row
            for row in world.actors
            if str(row["scenario_id"]) == scenario_id
        }
        self.cohorts = {
            str(row["cohort_id"]): row
            for row in world.prosumer_cohorts
            if str(row["scenario_id"]) == scenario_id
        }
        self.databases = {
            str(row["database_id"]): row
            for row in catalog.local_databases
            if str(row["scenario_id"]) == scenario_id
        }
        self.objects = {
            str(row["data_object_id"]): row
            for row in catalog.data_objects
            if str(row["scenario_id"]) == scenario_id
        }
        self.replicas = {
            str(row["replica_id"]): row
            for row in catalog.data_object_replicas
            if str(row["data_object_id"]) in self.objects
        }
        self.replicas_by_object = _group(self.replicas.values(), "data_object_id", "replica_id")
        self.object_custody_adjacency = _custody_adjacency(catalog, scenario_id)
        self.obligations = {
            str(row["obligation_id"]): row
            for row in obligations.evidence_obligations
            if str(row["event_id"]) in self.events
        }
        self.obligations_by_event = _group(self.obligations.values(), "event_id", "obligation_id")
        self.receipts = {
            str(row["receipt_id"]): row
            for row in receipts.evidence_receipts
            if str(row["event_id"]) in self.events
        }
        self.receipts_by_event = _group(self.receipts.values(), "event_id", "receipt_id")
        closure_name = CLOSURE_INDEX_NAMES.get(closure_policy)
        if closure_name is None:
            raise SamplingUnitError(f"unsupported closure policy {closure_policy!r}")
        self.event_closure = {
            record.unit_id: record.member_event_ids
            for record in dag.closure_index
            if record.scenario_id == scenario_id and record.closure_type == closure_name
        }
        if set(self.event_closure) != set(self.events):
            raise SamplingUnitError(
                f"{scenario_id}: DAG closure index is incomplete for policy={closure_policy}"
            )
        self.required_edges = tuple(
            row
            for row in dag.event_edges
            if str(row["scenario_id"]) == scenario_id and bool(row["required_for_closure"])
        )
        if not self.events or not self.workflows:
            raise SamplingUnitError(f"{scenario_id}: sampling requires events and workflows")


def _primary_units(context: _UnitContext, unit_type: str) -> tuple[PrimaryUnit, ...]:
    builders = {
        "workflow": _workflow_units,
        "cohort": _cohort_units,
        "actor": _actor_units,
        "object": _object_units,
        "time_bin": _time_bin_units,
        "dependency_component": _component_units,
    }
    try:
        units = builders[unit_type](context)
    except KeyError as exc:
        raise SamplingUnitError(f"unsupported primary unit type {unit_type!r}") from exc
    grouped: dict[str, list[PrimaryUnit]] = defaultdict(list)
    for unit in units:
        grouped[unit.stratum_id].append(unit)
    result: list[PrimaryUnit] = []
    for stratum_id, values in sorted(grouped.items()):
        for ordinal, unit in enumerate(sorted(values, key=_semantic_primary_sort_key)):
            result.append(
                replace(
                    unit,
                    crn_key=(
                        f"{unit.key.unit_type}|{stratum_id}|ordinal={ordinal:012d}"
                    ),
                )
            )
    return tuple(sorted(result, key=lambda item: item.key.unit_id))


def _workflow_units(context: _UnitContext) -> tuple[PrimaryUnit, ...]:
    result: list[PrimaryUnit] = []
    for workflow_id, workflow in sorted(context.workflows.items()):
        events = context.events_by_workflow.get(workflow_id, ())
        if not events:
            raise SamplingUnitError(f"workflow {workflow_id}: no events")
        root = events[0]
        facts = {
            "region_id": _event_region(context, root),
            "event_family": str(root["event_family"]),
            "cohort_id": str(root["subject_cohort_id"] or "NO_COHORT"),
            "workflow_type": str(workflow["workflow_type"]),
        }
        represented = sum(float(row["represented_event_count"]) for row in events)
        result.append(
            _primary(
                context,
                "workflow",
                workflow_id,
                facts,
                represented,
                tuple(str(row["event_id"]) for row in events),
            )
        )
    return tuple(result)


def _cohort_units(context: _UnitContext) -> tuple[PrimaryUnit, ...]:
    events_by_cohort = _group(
        (row for row in context.events.values() if row["subject_cohort_id"] is not None),
        "subject_cohort_id",
        "event_id",
    )
    result = []
    for cohort_id, cohort in sorted(context.cohorts.items()):
        facts = {
            "region_id": str(cohort["region_id"]),
            "sampling_stratum": str(cohort["sampling_stratum"]),
            "cohort_id": cohort_id,
            "subject_scope": str(cohort["subject_scope"]),
        }
        represented = float(cohort["represented_consumer_count"])
        result.append(
            _primary(
                context,
                "cohort",
                cohort_id,
                facts,
                represented,
                tuple(str(row["event_id"]) for row in events_by_cohort.get(cohort_id, ())),
            )
        )
    return tuple(result)


def _actor_units(context: _UnitContext) -> tuple[PrimaryUnit, ...]:
    actor_events: dict[str, list[str]] = defaultdict(list)
    for event_id, event in context.events.items():
        for actor_id in _event_actor_ids(event):
            actor_events[actor_id].append(event_id)
    result = []
    for actor_id, actor in sorted(context.actors.items()):
        facts = {
            "region_id": str(actor["region_id"]),
            "actor_class": str(actor["actor_class"]),
            "jurisdiction_id": str(actor["jurisdiction_id"]),
        }
        exposure = sum(
            float(context.events[event_id]["represented_event_count"])
            for event_id in actor_events.get(actor_id, ())
        )
        result.append(
            _primary(
                context,
                "actor",
                actor_id,
                facts,
                max(1.0, exposure),
                tuple(sorted(actor_events.get(actor_id, ()))),
                represented_value=1.0,
            )
        )
    return tuple(result)


def _object_units(context: _UnitContext) -> tuple[PrimaryUnit, ...]:
    object_events = _group(context.events.values(), "data_object_id", "event_id")
    result = []
    for object_id, data_object in sorted(context.objects.items()):
        database = context.databases[str(data_object["origin_database_id"])]
        events = object_events.get(object_id, ())
        exposure = sum(float(row["represented_event_count"]) for row in events)
        facts = {
            "region_id": str(database["region_id"]),
            "object_type": str(data_object["object_type"]),
            "data_object_id": object_id,
        }
        result.append(
            _primary(
                context,
                "object",
                object_id,
                facts,
                max(1.0, exposure),
                tuple(str(row["event_id"]) for row in events),
                represented_value=1.0,
            )
        )
    return tuple(result)


def _time_bin_units(context: _UnitContext) -> tuple[PrimaryUnit, ...]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for event in context.events.values():
        region_id = _event_region(context, event)
        time_bin = _timestamp(str(event["timestamp"])).strftime("%Y-%m-%dT%H:00:00Z")
        grouped[(region_id, time_bin)].append(event)
    result = []
    for (region_id, time_bin), events in sorted(grouped.items()):
        unit_id = deterministic_uuid(
            context.namespace,
            "sampling_time_bin",
            {"region_id": region_id, "scenario_id": context.scenario_id, "time_bin": time_bin},
        )
        represented = sum(float(row["represented_event_count"]) for row in events)
        result.append(
            _primary(
                context,
                "time_bin",
                unit_id,
                {"region_id": region_id, "time_bin": time_bin},
                represented,
                tuple(sorted(str(row["event_id"]) for row in events)),
            )
        )
    return tuple(result)


def _component_units(context: _UnitContext) -> tuple[PrimaryUnit, ...]:
    adjacency: dict[str, set[str]] = {event_id: set() for event_id in context.events}
    for edge in context.required_edges:
        source = str(edge["source_event_id"])
        target = str(edge["target_event_id"])
        adjacency[source].add(target)
        adjacency[target].add(source)
    remaining = set(adjacency)
    components: list[tuple[str, ...]] = []
    while remaining:
        start = min(remaining)
        stack = [start]
        members: set[str] = set()
        while stack:
            current = stack.pop()
            if current in members:
                continue
            members.add(current)
            stack.extend(sorted(adjacency[current] - members, reverse=True))
        remaining -= members
        components.append(tuple(sorted(members)))
    result = []
    for members in sorted(components):
        regions = [_event_region(context, context.events[event_id]) for event_id in members]
        region_id = min(regions)
        size_band = "small" if len(members) <= 5 else "medium" if len(members) <= 20 else "large"
        unit_id = deterministic_uuid(
            context.namespace,
            "dependency_component",
            {"event_ids": members, "scenario_id": context.scenario_id},
        )
        represented = sum(
            float(context.events[event_id]["represented_event_count"]) for event_id in members
        )
        result.append(
            _primary(
                context,
                "dependency_component",
                unit_id,
                {"region_id": region_id, "component_size_band": size_band},
                represented,
                members,
            )
        )
    return tuple(result)


def _primary(
    context: _UnitContext,
    unit_type: str,
    unit_id: str,
    facts: Mapping[str, str],
    size_measure: float,
    seed_event_ids: tuple[str, ...],
    *,
    represented_value: float | None = None,
) -> PrimaryUnit:
    if not (size_measure > 0):
        raise SamplingUnitError(f"{unit_type}/{unit_id}: size measure must be positive")
    missing = sorted(set(context.stratum_fields) - set(facts))
    if missing:
        raise SamplingUnitError(f"{unit_type}/{unit_id}: missing stratum facts {missing}")
    stratum_id = ":".join(str(facts[field]) for field in context.stratum_fields)
    return PrimaryUnit(
        key=UnitKey(unit_type, unit_id),
        scenario_id=context.scenario_id,
        stratum_id=stratum_id,
        size_measure=float(size_measure),
        represented_value=float(represented_value if represented_value is not None else size_measure),
        crn_key="",
        seed_event_ids=tuple(sorted(seed_event_ids)),
    )


def _close_primary(
    context: _UnitContext, primary: PrimaryUnit
) -> tuple[set[UnitKey], Mapping[UnitKey, PopulationUnit]]:
    event_ids = _expanded_event_ids(context, primary.seed_event_ids)
    members: set[UnitKey] = {primary.key}
    records: dict[UnitKey, PopulationUnit] = {
        primary.key: PopulationUnit(primary.key, primary.stratum_id, primary.represented_value)
    }
    for event_id in event_ids:
        event = context.events[event_id]
        event_key = UnitKey("event", event_id)
        event_stratum = f"{_event_region(context, event)}:{event['event_family']}"
        records[event_key] = PopulationUnit(
            event_key, event_stratum, float(event["represented_event_count"])
        )
        members.add(event_key)
        workflow_id = str(event["workflow_instance_id"])
        workflow_key = UnitKey("workflow", workflow_id)
        workflow_events = context.events_by_workflow[workflow_id]
        workflow_value = sum(
            float(item["represented_event_count"]) for item in workflow_events
        )
        records.setdefault(
            workflow_key,
            PopulationUnit(workflow_key, event_stratum, workflow_value),
        )
        members.add(workflow_key)

    if context.closure_policy in {"replica", "full_dependency_closure"}:
        object_ids = {str(context.events[event_id]["data_object_id"]) for event_id in event_ids}
        if context.closure_policy == "full_dependency_closure":
            object_ids = _reachable_objects(object_ids, context.object_custody_adjacency)
        for object_id in sorted(object_ids):
            data_object = context.objects[object_id]
            database = context.databases[str(data_object["origin_database_id"])]
            object_key = UnitKey("object", object_id)
            object_stratum = f"{database['region_id']}:{data_object['object_type']}"
            records.setdefault(object_key, PopulationUnit(object_key, object_stratum, 1.0))
            members.add(object_key)
            for replica in context.replicas_by_object.get(object_id, ()):
                replica_key = UnitKey("replica", str(replica["replica_id"]))
                replica_database = context.databases[str(replica["database_id"])]
                replica_stratum = f"{replica_database['region_id']}:{replica['replica_role']}"
                records[replica_key] = PopulationUnit(replica_key, replica_stratum, 1.0)
                members.add(replica_key)

    if context.closure_policy in {"evidence", "full_dependency_closure"}:
        for event_id in event_ids:
            event = context.events[event_id]
            evidence_stratum = f"{event['event_family']}:evidence"
            for obligation in context.obligations_by_event.get(event_id, ()):
                key = UnitKey("evidence", str(obligation["obligation_id"]))
                records[key] = PopulationUnit(key, evidence_stratum, 1.0)
                members.add(key)
            for receipt in context.receipts_by_event.get(event_id, ()):
                key = UnitKey("evidence", str(receipt["receipt_id"]))
                records[key] = PopulationUnit(key, evidence_stratum, 1.0)
                members.add(key)
    return members, dict(sorted(records.items()))


def _expanded_event_ids(
    context: _UnitContext, seed_event_ids: Sequence[str]
) -> tuple[str, ...]:
    selected = set(seed_event_ids)
    pending = list(sorted(selected))
    while pending:
        event_id = pending.pop()
        event = context.events[event_id]
        workflow_id = str(event["workflow_instance_id"])
        candidates = {
            str(row["event_id"]) for row in context.events_by_workflow[workflow_id]
        }
        candidates.update(context.event_closure[event_id])
        for candidate in sorted(candidates):
            if candidate not in selected:
                selected.add(candidate)
                pending.append(candidate)
    return tuple(sorted(selected))


def _custody_adjacency(
    catalog: CatalogBuild, scenario_id: str
) -> Mapping[str, set[str]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in catalog.custody_edges:
        if edge.scenario_id != scenario_id:
            continue
        if edge.source_table == "data_object" and edge.target_table == "data_object":
            adjacency[edge.source_id].add(edge.target_id)
            adjacency[edge.target_id].add(edge.source_id)
    return adjacency


def _reachable_objects(
    seeds: Iterable[str], adjacency: Mapping[str, set[str]]
) -> set[str]:
    selected = set(seeds)
    stack = list(sorted(selected, reverse=True))
    while stack:
        current = stack.pop()
        for related in sorted(adjacency.get(current, ()), reverse=True):
            if related not in selected:
                selected.add(related)
                stack.append(related)
    return selected


def _semantic_primary_sort_key(unit: PrimaryUnit) -> tuple[Any, ...]:
    return (
        unit.stratum_id,
        tuple(unit.seed_event_ids),
        unit.represented_value,
        unit.size_measure,
        unit.key.unit_id,
    )


def _event_region(context: _UnitContext, event: Mapping[str, Any]) -> str:
    database = context.databases[str(event["local_database_id"])]
    return str(database["region_id"])


def _event_actor_ids(event: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(event[field])
                for field in EVENT_ACTOR_FIELDS
                if event[field] is not None
            }
        )
    )


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SamplingUnitError(f"timestamp is not timezone-aware: {value!r}")
    return parsed


def _group(
    rows: Iterable[Mapping[str, Any]], key_field: str, sort_field: str
) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[key_field])].append(row)
    return {
        key: tuple(sorted(values, key=lambda row: str(row[sort_field])))
        for key, values in sorted(grouped.items())
    }
