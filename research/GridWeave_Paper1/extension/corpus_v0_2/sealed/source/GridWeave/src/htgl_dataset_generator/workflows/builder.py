"""S06 workflow automata and governance event compiler.

The compiler consumes S05 arrivals and conditional marks. It emits real
workflow state transitions, causal event edges, workflow instances, and typed
side-effect sidecars for later policy, evidence, observer, and sampling stages.
It does not execute HTGL consensus, ledger anchoring, real erasure, or legal
enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence
import re

from htgl_dataset_generator.arrivals import ArrivalBuild, ArrivalMark, build_arrivals
from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.physical import PhysicalRawBuild, build_physical_raw
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import CounterRng, deterministic_uuid, seed_stream_records_for_plan
from htgl_dataset_generator.world import FederatedWorld, build_federated_world


WORKFLOW_COMPONENT = "S06.workflows"
REQUIRED_WORKFLOW_TYPES: tuple[str, ...] = (
    "consent",
    "collection_processing",
    "disclosure",
    "access",
    "correction",
    "retention",
    "erasure",
    "audit",
    "operational",
    "incident",
)
SIDE_EFFECT_TYPES: tuple[str, ...] = (
    "replica_creation",
    "disclosure",
    "derivation",
    "correction",
    "invalidation",
    "deletion_status_update",
    "evidence_trigger",
)
LEGAL_BASIS_BY_WORKFLOW: Mapping[str, str] = {
    "consent": "LBL-CONSENT",
    "collection_processing": "LBL-CONTRACTUAL-NECESSITY",
    "disclosure": "LBL-AUTHORIZED-DISCLOSURE",
    "access": "LBL-DATA-SUBJECT-RIGHTS",
    "correction": "LBL-DATA-SUBJECT-RIGHTS",
    "retention": "LBL-RETENTION-RULE",
    "erasure": "LBL-DATA-SUBJECT-RIGHTS",
    "audit": "LBL-LEGAL-OBLIGATION",
    "operational": "LBL-GRID-OPERATIONS",
    "incident": "LBL-SECURITY-INCIDENT",
}
CONTROLLED_LEGAL_BASIS_LABEL_IDS = frozenset(LEGAL_BASIS_BY_WORKFLOW.values())
WORKFLOW_TYPE_BY_EVENT_FAMILY: Mapping[str, str] = {
    "notification": "incident",
}
DEFAULT_OPEN_HORIZON_STATES = frozenset(
    {
        "requested",
        "proposed",
        "authorized",
        "received",
        "review_due",
        "propagated",
        "executed",
        "opened",
        "evidence_collected",
        "remediation",
    }
)


class WorkflowCompilerError(ValueError):
    """Raised when S06 workflow compilation violates the contract."""


@dataclass(frozen=True)
class TransitionSpec:
    event_type: str
    state_before: str
    state_after: str
    edge_type_from_previous: str
    delay_seconds: int
    max_delay_seconds: int
    side_effects: tuple[str, ...]
    consent_state_after: str | None = None
    retention_state_after: str | None = None
    erasure_state_after: str | None = None
    legal_basis_label_id: str | None = None
    payload_schema_id: str | None = None


@dataclass(frozen=True)
class WorkflowDefinition:
    workflow_type: str
    definition_version: str
    initial_state: str
    terminal_states: tuple[str, ...]
    open_horizon_states: tuple[str, ...]
    transitions: tuple[TransitionSpec, ...]


@dataclass(frozen=True)
class WorkflowSideEffect:
    side_effect_id: str
    scenario_id: str
    replicate_id: int
    workflow_instance_id: str
    event_id: str
    side_effect_type: str
    source_table: str
    source_id: str
    target_table: str
    target_id: str
    status: str
    rule_id: str
    evidence_trigger_required: bool


@dataclass(frozen=True)
class WorkflowDiagnostics:
    scenario_id: str
    replicate_id: int
    workflow_count: int
    governance_event_count: int
    event_edge_count: int
    side_effect_count: int
    transition_conformance_rate: float
    terminal_workflow_count: int
    open_horizon_workflow_count: int
    deadline_violation_count: int


@dataclass(frozen=True)
class WorkflowBuild:
    governance_events: tuple[dict[str, Any], ...]
    event_edges: tuple[dict[str, Any], ...]
    workflow_instances: tuple[dict[str, Any], ...]
    side_effects: tuple[WorkflowSideEffect, ...]
    diagnostics: Mapping[str, WorkflowDiagnostics]

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "governance_event": self.governance_events,
            "event_edge": self.event_edges,
            "workflow_instance": self.workflow_instances,
        }


@dataclass(frozen=True)
class _WorkflowContext:
    resolved: ResolvedConfig
    scenario_id: str
    replicate_id: int
    namespace: str
    rng: CounterRng
    contract: ContractSpec
    world: FederatedWorld
    catalog: CatalogBuild
    arrivals: ArrivalBuild


def workflow_definitions(resolved: ResolvedConfig | None = None) -> Mapping[str, WorkflowDefinition]:
    """Return the versioned workflow automata required by Dataset-2."""

    versions = resolved.workflows.definition_versions if resolved is not None else {}

    def version(name: str) -> str:
        return str(versions.get(name, f"{name}.v1"))

    definitions = {
        "consent": WorkflowDefinition(
            workflow_type="consent",
            definition_version=version("consent"),
            initial_state="not_requested",
            terminal_states=("granted", "refused", "withdrawn", "expired"),
            open_horizon_states=("requested",),
            transitions=(
                TransitionSpec(
                    "consent_requested",
                    "not_requested",
                    "requested",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    consent_state_after="requested",
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-CONSENT",
                ),
                TransitionSpec(
                    "consent_granted",
                    "requested",
                    "granted",
                    "responds_to",
                    300,
                    3_600,
                    ("replica_creation", "evidence_trigger"),
                    consent_state_after="granted",
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-CONSENT",
                ),
            ),
        ),
        "collection_processing": WorkflowDefinition(
            workflow_type="collection_processing",
            definition_version=version("collection_processing"),
            initial_state="not_requested",
            terminal_states=("fulfilled",),
            open_horizon_states=("active",),
            transitions=(
                TransitionSpec(
                    "collection_started",
                    "not_requested",
                    "active",
                    "causes",
                    0,
                    0,
                    ("replica_creation",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-CONTRACTUAL-NECESSITY",
                ),
                TransitionSpec(
                    "processing_started",
                    "active",
                    "fulfilled",
                    "derives",
                    600,
                    7_200,
                    ("derivation", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-CONTRACTUAL-NECESSITY",
                ),
            ),
        ),
        "disclosure": WorkflowDefinition(
            workflow_type="disclosure",
            definition_version=version("disclosure"),
            initial_state="not_requested",
            terminal_states=("received", "denied"),
            open_horizon_states=("proposed", "authorized", "transferred"),
            transitions=(
                TransitionSpec(
                    "disclosure_proposed",
                    "not_requested",
                    "proposed",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-AUTHORIZED-DISCLOSURE",
                ),
                TransitionSpec(
                    "transfer_authorized",
                    "proposed",
                    "authorized",
                    "responds_to",
                    900,
                    14_400,
                    ("disclosure", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-AUTHORIZED-DISCLOSURE",
                ),
                TransitionSpec(
                    "transfer_received",
                    "authorized",
                    "received",
                    "discloses",
                    600,
                    14_400,
                    ("replica_creation", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-AUTHORIZED-DISCLOSURE",
                ),
            ),
        ),
        "access": WorkflowDefinition(
            workflow_type="access",
            definition_version=version("access"),
            initial_state="not_requested",
            terminal_states=("fulfilled", "refused", "appealed", "closed"),
            open_horizon_states=("requested", "authenticated", "scoped"),
            transitions=(
                TransitionSpec(
                    "access_requested",
                    "not_requested",
                    "requested",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
                TransitionSpec(
                    "access_fulfilled",
                    "requested",
                    "fulfilled",
                    "responds_to",
                    1_800,
                    86_400,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
            ),
        ),
        "correction": WorkflowDefinition(
            workflow_type="correction",
            definition_version=version("correction"),
            initial_state="not_requested",
            terminal_states=("fulfilled", "refused", "closed"),
            open_horizon_states=("requested", "authenticated", "scoped"),
            transitions=(
                TransitionSpec(
                    "correction_requested",
                    "not_requested",
                    "requested",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
                TransitionSpec(
                    "correction_applied",
                    "requested",
                    "fulfilled",
                    "responds_to",
                    1_200,
                    86_400,
                    ("correction", "invalidation", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
            ),
        ),
        "retention": WorkflowDefinition(
            workflow_type="retention",
            definition_version=version("retention"),
            initial_state="active",
            terminal_states=("retained_under_rule", "disposal_scheduled"),
            open_horizon_states=("review_due",),
            transitions=(
                TransitionSpec(
                    "retention_review_due",
                    "active",
                    "review_due",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="review_due",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-RETENTION-RULE",
                ),
                TransitionSpec(
                    "retention_review_due",
                    "review_due",
                    "retained_under_rule",
                    "responds_to",
                    3_600,
                    86_400,
                    ("evidence_trigger",),
                    retention_state_after="retained_under_rule",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-RETENTION-RULE",
                ),
            ),
        ),
        "erasure": WorkflowDefinition(
            workflow_type="erasure",
            definition_version=version("erasure"),
            initial_state="not_requested",
            terminal_states=("verified", "closed", "denied", "partial"),
            open_horizon_states=("received", "authenticated", "scoped", "propagated", "executed"),
            transitions=(
                TransitionSpec(
                    "erasure_requested",
                    "not_requested",
                    "received",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="received",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
                TransitionSpec(
                    "erasure_propagated",
                    "received",
                    "propagated",
                    "erases",
                    900,
                    86_400,
                    ("evidence_trigger",),
                    retention_state_after="disposal_scheduled",
                    erasure_state_after="propagated",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
                TransitionSpec(
                    "erasure_executed",
                    "propagated",
                    "executed",
                    "erases",
                    900,
                    86_400,
                    ("deletion_status_update", "evidence_trigger"),
                    retention_state_after="disposal_scheduled",
                    erasure_state_after="executed",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
                TransitionSpec(
                    "erasure_verified",
                    "executed",
                    "verified",
                    "evidences",
                    600,
                    86_400,
                    ("evidence_trigger",),
                    retention_state_after="disposal_scheduled",
                    erasure_state_after="verified",
                    legal_basis_label_id="LBL-DATA-SUBJECT-RIGHTS",
                ),
            ),
        ),
        "audit": WorkflowDefinition(
            workflow_type="audit",
            definition_version=version("audit"),
            initial_state="active",
            terminal_states=("finding", "closed"),
            open_horizon_states=("opened", "evidence_collected"),
            transitions=(
                TransitionSpec(
                    "audit_opened",
                    "active",
                    "opened",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-LEGAL-OBLIGATION",
                ),
                TransitionSpec(
                    "audit_finding",
                    "opened",
                    "finding",
                    "evidences",
                    3_600,
                    172_800,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-LEGAL-OBLIGATION",
                ),
            ),
        ),
        "operational": WorkflowDefinition(
            workflow_type="operational",
            definition_version=version("operational"),
            initial_state="proposed",
            terminal_states=("executed", "denied"),
            open_horizon_states=("authorized",),
            transitions=(
                TransitionSpec(
                    "operational_command_issued",
                    "proposed",
                    "authorized",
                    "causes",
                    0,
                    0,
                    ("evidence_trigger",),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-GRID-OPERATIONS",
                ),
                TransitionSpec(
                    "operational_command_issued",
                    "authorized",
                    "executed",
                    "responds_to",
                    120,
                    3_600,
                    ("derivation", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-GRID-OPERATIONS",
                ),
            ),
        ),
        "incident": WorkflowDefinition(
            workflow_type="incident",
            definition_version=version("incident"),
            initial_state="active",
            terminal_states=("remediation", "closed"),
            open_horizon_states=("opened", "finding"),
            transitions=(
                TransitionSpec(
                    "incident_notified",
                    "active",
                    "opened",
                    "causes",
                    0,
                    0,
                    ("disclosure", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-SECURITY-INCIDENT",
                ),
                TransitionSpec(
                    "incident_notified",
                    "opened",
                    "remediation",
                    "responds_to",
                    900,
                    7_200,
                    ("invalidation", "evidence_trigger"),
                    retention_state_after="active",
                    erasure_state_after="not_requested",
                    legal_basis_label_id="LBL-SECURITY-INCIDENT",
                ),
            ),
        ),
    }
    return dict(sorted(definitions.items()))


def build_workflows(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    catalog: CatalogBuild | None = None,
    physical: PhysicalRawBuild | None = None,
    arrivals: ArrivalBuild | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> WorkflowBuild:
    """Compile S06 governance events, event edges, and workflow instances."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise WorkflowCompilerError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise WorkflowCompilerError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise WorkflowCompilerError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    _validate_definition_coverage(resolved, schema_contract)

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

    all_events: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []
    all_instances: list[dict[str, Any]] = []
    all_side_effects: list[WorkflowSideEffect] = []
    diagnostics: dict[str, WorkflowDiagnostics] = {}
    for scenario_id in sorted(selected):
        ctx = _workflow_context(
            resolved,
            scenario_id,
            replicate_id,
            world_build,
            catalog_build,
            arrival_build,
            schema_contract,
        )
        events, edges, instances, side_effects = _compile_scenario(ctx)
        partial = WorkflowBuild(
            governance_events=events,
            event_edges=edges,
            workflow_instances=instances,
            side_effects=side_effects,
            diagnostics={scenario_id: _diagnostics(ctx, events, edges, instances, side_effects)},
        )
        validate_workflows(partial, resolved, arrivals=arrival_build, catalog=catalog_build, contract=schema_contract)
        all_events.extend(events)
        all_edges.extend(edges)
        all_instances.extend(instances)
        all_side_effects.extend(side_effects)
        diagnostics[scenario_id] = partial.diagnostics[scenario_id]

    return WorkflowBuild(
        governance_events=tuple(sorted(all_events, key=lambda row: (row["scenario_id"], row["event_id"]))),
        event_edges=tuple(sorted(all_edges, key=lambda row: (row["scenario_id"], row["edge_id"]))),
        workflow_instances=tuple(
            sorted(all_instances, key=lambda row: (row["scenario_id"], row["workflow_instance_id"]))
        ),
        side_effects=tuple(sorted(all_side_effects, key=lambda item: (item.scenario_id, item.side_effect_id))),
        diagnostics=dict(sorted(diagnostics.items())),
    )


def _validate_definition_coverage(resolved: ResolvedConfig, contract: ContractSpec) -> None:
    definitions = workflow_definitions(resolved)
    required = set(REQUIRED_WORKFLOW_TYPES)
    missing_definitions = sorted(required - set(definitions))
    if missing_definitions:
        raise WorkflowCompilerError(f"missing required workflow automata {missing_definitions}")
    workflow_type_values = set(contract.dictionary_values("workflow_type"))
    event_type_values = set(contract.dictionary_values("event_type"))
    workflow_state_values = set(contract.dictionary_values("workflow_state"))
    edge_type_values = set(contract.dictionary_values("edge_type"))
    for workflow_type, definition in definitions.items():
        if workflow_type not in workflow_type_values:
            raise WorkflowCompilerError(f"workflow definition {workflow_type} is not in locked dictionary")
        if workflow_type not in resolved.workflows.definition_versions:
            raise WorkflowCompilerError(f"workflow {workflow_type} has no pinned definition version")
        if not definition.definition_version.strip():
            raise WorkflowCompilerError(f"workflow {workflow_type} has an empty definition version")
        if not definition.transitions:
            raise WorkflowCompilerError(f"workflow {workflow_type} has no transitions")
        if definition.initial_state not in workflow_state_values:
            raise WorkflowCompilerError(
                f"workflow {workflow_type}: initial_state={definition.initial_state!r} is not in the locked dictionary"
            )
        unknown_terminal_states = sorted(set(definition.terminal_states) - workflow_state_values)
        if unknown_terminal_states:
            raise WorkflowCompilerError(
                f"workflow {workflow_type}: terminal states are not in the locked dictionary {unknown_terminal_states}"
            )
        unknown_open_states = sorted(set(definition.open_horizon_states) - workflow_state_values)
        if unknown_open_states:
            raise WorkflowCompilerError(
                f"workflow {workflow_type}: open-horizon states are not in the locked dictionary {unknown_open_states}"
            )
        for transition in definition.transitions:
            if transition.event_type not in event_type_values:
                raise WorkflowCompilerError(
                    f"workflow {workflow_type}: event_type={transition.event_type!r} is not in the locked dictionary"
                )
            if transition.state_before not in workflow_state_values or transition.state_after not in workflow_state_values:
                raise WorkflowCompilerError(
                    f"workflow {workflow_type}/{transition.event_type}: transition state is not in the locked dictionary"
                )
            if transition.edge_type_from_previous not in edge_type_values:
                raise WorkflowCompilerError(
                    f"workflow {workflow_type}/{transition.event_type}: edge type is not in the locked dictionary"
                )
            unknown_side_effects = sorted(set(transition.side_effects) - set(SIDE_EFFECT_TYPES))
            if unknown_side_effects:
                raise WorkflowCompilerError(
                    f"workflow {workflow_type}/{transition.event_type}: unknown side effects {unknown_side_effects}"
                )
            legal_basis_label_id = (
                transition.legal_basis_label_id or LEGAL_BASIS_BY_WORKFLOW[workflow_type]
            )
            if legal_basis_label_id not in CONTROLLED_LEGAL_BASIS_LABEL_IDS:
                raise WorkflowCompilerError(
                    f"workflow {workflow_type}/{transition.event_type}: uncontrolled experimental "
                    f"legal_basis_label_id={legal_basis_label_id!r}"
                )
    side_effects = {effect for definition in definitions.values() for transition in definition.transitions for effect in transition.side_effects}
    missing_effects = sorted(set(SIDE_EFFECT_TYPES) - side_effects)
    if missing_effects:
        raise WorkflowCompilerError(f"workflow definitions do not cover required side effects {missing_effects}")


def _workflow_context(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    world: FederatedWorld,
    catalog: CatalogBuild,
    arrivals: ArrivalBuild,
    contract: ContractSpec,
) -> _WorkflowContext:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        config_sha256=resolved.config_sha256,
    )
    suffix = f"component={WORKFLOW_COMPONENT}|partition=global"
    for row in seed_stream_records_for_plan(resolved, plan, contract=contract):
        if row["stream_name"].endswith(suffix):
            return _WorkflowContext(
                resolved=resolved,
                scenario_id=scenario_id,
                replicate_id=replicate_id,
                namespace=str(row["deterministic_id_namespace"]),
                rng=CounterRng(str(row["seed_material_hex"])),
                contract=contract,
                world=world,
                catalog=catalog,
                arrivals=arrivals,
            )
    raise WorkflowCompilerError(f"{scenario_id}: missing {WORKFLOW_COMPONENT} seed stream")


def _compile_scenario(
    ctx: _WorkflowContext,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...], tuple[dict[str, Any], ...], tuple[WorkflowSideEffect, ...]]:
    definitions = workflow_definitions(ctx.resolved)
    mark_by_arrival = {mark.arrival_id: mark for mark in ctx.arrivals.marks}
    selected_arrivals = tuple(
        sorted(
            (
                row
                for row in ctx.arrivals.arrivals
                if row["scenario_id"] == ctx.scenario_id and int(row["replicate_id"]) == ctx.replicate_id
            ),
            key=lambda row: (row["timestamp"], row["arrival_id"]),
        )
    )
    events: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    side_effects: list[WorkflowSideEffect] = []
    allowed_workflow_types = set(ctx.resolved.workflows.families)
    bootstrap_events, bootstrap_edges, bootstrap_instances, bootstrap_effects = (
        _compile_catalog_initialization_workflows(
            ctx,
            definitions["collection_processing"],
        )
    )
    events.extend(bootstrap_events)
    edges.extend(bootstrap_edges)
    instances.extend(bootstrap_instances)
    side_effects.extend(bootstrap_effects)
    for arrival_index, arrival in enumerate(selected_arrivals):
        mark = mark_by_arrival.get(str(arrival["arrival_id"]))
        if mark is None:
            raise WorkflowCompilerError(f"arrival {arrival['arrival_id']}: missing conditional mark")
        workflow_type = _workflow_type_for_arrival(arrival)
        if workflow_type not in allowed_workflow_types:
            raise WorkflowCompilerError(
                f"arrival {arrival['arrival_id']}: workflow_type={workflow_type} is not enabled by config"
            )
        definition = definitions[workflow_type]
        workflow_id = deterministic_uuid(
            ctx.namespace,
            "workflow_instance",
            {
                "arrival_id": arrival["arrival_id"],
                "replicate_id": ctx.replicate_id,
                "scenario_id": ctx.scenario_id,
                "workflow_type": workflow_type,
            },
        )
        workflow_events, workflow_edges, workflow_side_effects = _compile_arrival_workflow(
            ctx,
            arrival,
            mark,
            definition,
            workflow_id,
            arrival_index,
        )
        root_event_id = workflow_events[0]["event_id"]
        final_event = workflow_events[-1]
        instance = {
            "workflow_instance_id": workflow_id,
            "scenario_id": ctx.scenario_id,
            "workflow_type": workflow_type,
            "workflow_definition_version": definition.definition_version,
            "root_event_id": root_event_id,
            "initial_state": definition.initial_state,
            "final_state": final_event["workflow_state_after"],
            "started_at": workflow_events[0]["timestamp"],
            "ended_at": final_event["timestamp"] if final_event["workflow_state_after"] in definition.terminal_states else None,
            "terminal_event_id": final_event["event_id"] if final_event["workflow_state_after"] in definition.terminal_states else None,
            "is_conformant_world_truth": True,
            "event_count": len(workflow_events),
        }
        events.extend(workflow_events)
        edges.extend(workflow_edges)
        side_effects.extend(workflow_side_effects)
        instances.append(instance)
    return (
        tuple(sorted(events, key=lambda row: (row["workflow_instance_id"], row["workflow_step_index"]))),
        tuple(sorted(edges, key=lambda row: row["edge_id"])),
        tuple(sorted(instances, key=lambda row: row["workflow_instance_id"])),
        tuple(sorted(side_effects, key=lambda item: item.side_effect_id)),
    )


def _compile_catalog_initialization_workflows(
    ctx: _WorkflowContext,
    definition: WorkflowDefinition,
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
    tuple[WorkflowSideEffect, ...],
]:
    """Materialize the causal events required by replica creation FKs."""

    actor_by_id = {str(row["actor_id"]): row for row in ctx.world.actors}
    database_by_id = {
        str(row["database_id"]): row
        for row in ctx.catalog.local_databases
        if str(row["scenario_id"]) == ctx.scenario_id
    }
    oversight_candidates = sorted(
        (
            row
            for row in ctx.world.actors
            if str(row["scenario_id"]) == ctx.scenario_id
            and str(row["actor_class"]) in {"auditor", "regulator", "oversight"}
        ),
        key=lambda row: str(row["actor_id"]),
    )
    objects = tuple(
        sorted(
            (
                row
                for row in ctx.catalog.data_objects
                if str(row["scenario_id"]) == ctx.scenario_id
            ),
            key=lambda row: str(row["data_object_id"]),
        )
    )
    replicas_by_object: dict[str, list[Mapping[str, Any]]] = {}
    for replica in ctx.catalog.data_object_replicas:
        replicas_by_object.setdefault(str(replica["data_object_id"]), []).append(replica)

    events: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    effects: list[WorkflowSideEffect] = []
    for object_index, data_object in enumerate(objects):
        object_id = str(data_object["data_object_id"])
        replicas = replicas_by_object.get(object_id, [])
        if not replicas:
            raise WorkflowCompilerError(f"catalog object {object_id}: no replica creation target")
        creation_event_ids = {str(row["created_by_event_id"]) for row in replicas}
        if len(creation_event_ids) != 1:
            raise WorkflowCompilerError(
                f"catalog object {object_id}: replicas do not share one causal creation event"
            )
        creation_event_id = next(iter(creation_event_ids))
        origin_database_id = str(data_object["origin_database_id"])
        database = database_by_id.get(origin_database_id)
        if database is None:
            raise WorkflowCompilerError(
                f"catalog object {object_id}: origin database does not resolve in scenario"
            )
        controller_id = str(database["controller_actor_id"])
        processor_id = str(database["operator_actor_id"] or controller_id)
        controller = actor_by_id.get(controller_id)
        if controller is None or processor_id not in actor_by_id:
            raise WorkflowCompilerError(
                f"catalog object {object_id}: controller/operator actor does not resolve"
            )
        oversight_id = (
            str(oversight_candidates[0]["actor_id"])
            if oversight_candidates
            else controller_id
        )
        workflow_id = deterministic_uuid(
            ctx.namespace,
            "catalog_initialization_workflow",
            {
                "creation_event_id": creation_event_id,
                "data_object_id": object_id,
                "scenario_id": ctx.scenario_id,
            },
        )
        synthetic_arrival = {
            "arrival_id": creation_event_id,
            "timestamp": ctx.resolved.run.horizon_start,
            "event_family": "collection_processing",
            "subject_cohort_id": data_object["subject_cohort_id"],
            "represented_arrival_count": 1.0,
        }
        mark = ArrivalMark(
            arrival_id=creation_event_id,
            source_actor_id=controller_id,
            requesting_actor_id=controller_id,
            controller_actor_id=controller_id,
            processor_actor_id=processor_id,
            oversight_actor_id=oversight_id,
            local_database_id=origin_database_id,
            data_object_id=object_id,
            purpose_tag=str(data_object["purpose_tags"][0]),
            jurisdiction_id=str(controller["jurisdiction_id"]),
            workflow_profile_id=definition.definition_version,
            structural_path=(
                ctx.scenario_id,
                str(controller["region_id"]),
                origin_database_id,
                object_id,
            ),
        )
        workflow_events, workflow_edges, workflow_effects = _compile_arrival_workflow(
            ctx,
            synthetic_arrival,
            mark,
            definition,
            workflow_id,
            object_index,
            root_event_id_override=creation_event_id,
            source_arrival=False,
            materialization_reason_override="closure_added",
        )
        final_event = workflow_events[-1]
        instances.append(
            {
                "workflow_instance_id": workflow_id,
                "scenario_id": ctx.scenario_id,
                "workflow_type": definition.workflow_type,
                "workflow_definition_version": definition.definition_version,
                "root_event_id": creation_event_id,
                "initial_state": definition.initial_state,
                "final_state": final_event["workflow_state_after"],
                "started_at": workflow_events[0]["timestamp"],
                "ended_at": final_event["timestamp"],
                "terminal_event_id": final_event["event_id"],
                "is_conformant_world_truth": True,
                "event_count": len(workflow_events),
            }
        )
        events.extend(workflow_events)
        edges.extend(workflow_edges)
        effects.extend(workflow_effects)
    return tuple(events), tuple(edges), tuple(instances), tuple(effects)


def _compile_arrival_workflow(
    ctx: _WorkflowContext,
    arrival: Mapping[str, Any],
    mark: ArrivalMark,
    definition: WorkflowDefinition,
    workflow_id: str,
    arrival_index: int,
    *,
    root_event_id_override: str | None = None,
    source_arrival: bool = True,
    materialization_reason_override: str | None = None,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...], tuple[WorkflowSideEffect, ...]]:
    events: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    side_effects: list[WorkflowSideEffect] = []
    cursor = _timestamp(str(arrival["timestamp"]))
    horizon_end = _timestamp(ctx.resolved.run.horizon_end)
    root_event_id: str | None = None
    previous_event_id: str | None = None
    for step_index, transition in enumerate(definition.transitions):
        if step_index > 0:
            candidate_timestamp = cursor + timedelta(
                seconds=_transition_delay(ctx, workflow_id, transition, step_index, arrival_index)
            )
            if candidate_timestamp > horizon_end:
                if not events or events[-1]["workflow_state_after"] not in definition.open_horizon_states:
                    raise WorkflowCompilerError(
                        f"workflow {workflow_id}: horizon truncation would leave disallowed state "
                        f"{events[-1]['workflow_state_after'] if events else definition.initial_state!r}"
                    )
                break
            cursor = candidate_timestamp
        event_id = (
            root_event_id_override
            if step_index == 0 and root_event_id_override is not None
            else deterministic_uuid(
                ctx.namespace,
                "governance_event",
                {
                    "arrival_id": arrival["arrival_id"],
                    "event_type": transition.event_type,
                    "step_index": step_index,
                    "workflow_id": workflow_id,
                },
            )
        )
        if root_event_id is None:
            root_event_id = event_id
        event = {
            "event_id": event_id,
            "source_event_id": (
                str(arrival["arrival_id"])
                if step_index == 0 and source_arrival
                else previous_event_id
            ),
            "scenario_id": ctx.scenario_id,
            "replicate_id": ctx.replicate_id,
            "timestamp": _format_timestamp(cursor),
            "recorded_timestamp": _format_timestamp(cursor + timedelta(seconds=_recording_delay(ctx, workflow_id, step_index))),
            "event_type": transition.event_type,
            "event_family": str(arrival["event_family"]),
            "source_actor_id": mark.source_actor_id,
            "requesting_actor_id": mark.requesting_actor_id,
            "controller_actor_id": mark.controller_actor_id,
            "processor_actor_id": mark.processor_actor_id,
            "oversight_actor_id": mark.oversight_actor_id,
            "subject_cohort_id": arrival.get("subject_cohort_id"),
            "local_database_id": mark.local_database_id,
            "data_object_id": mark.data_object_id,
            "workflow_instance_id": workflow_id,
            "workflow_state_before": transition.state_before,
            "workflow_state_after": transition.state_after,
            "workflow_step_index": step_index,
            "root_event_id": root_event_id,
            "causal_depth": step_index,
            "policy_purpose_id": _purpose_id(mark.purpose_tag),
            "legal_basis_label_id": transition.legal_basis_label_id or LEGAL_BASIS_BY_WORKFLOW[definition.workflow_type],
            "consent_state_after": transition.consent_state_after,
            "retention_state_after": transition.retention_state_after,
            "erasure_state_after": transition.erasure_state_after,
            "payload_schema_id": transition.payload_schema_id or f"payload.{transition.event_type}.v1",
            "payload_ref": _payload_ref(ctx, workflow_id, step_index, transition),
            "represented_event_count": float(arrival["represented_arrival_count"]),
            "materialization_reason": (
                materialization_reason_override
                if materialization_reason_override is not None
                else _materialization_reason(ctx, arrival)
            ),
        }
        events.append(event)
        side_effects.extend(_side_effects_for_transition(ctx, event, mark, transition))
        if previous_event_id is not None:
            edges.append(
                {
                    "edge_id": deterministic_uuid(
                        ctx.namespace,
                        "event_edge",
                        {
                            "source_event_id": previous_event_id,
                            "target_event_id": event_id,
                            "workflow_id": workflow_id,
                        },
                    ),
                    "scenario_id": ctx.scenario_id,
                    "source_event_id": previous_event_id,
                    "target_event_id": event_id,
                    "edge_type": transition.edge_type_from_previous,
                    "cross_workflow": False,
                    "dependency_strength": 1.0,
                    "required_for_closure": True,
                    "rule_id": _transition_rule_id(definition.workflow_type, transition, step_index),
                }
            )
        previous_event_id = event_id
    return tuple(events), tuple(edges), tuple(side_effects)


def _workflow_type_for_arrival(arrival: Mapping[str, Any]) -> str:
    family = str(arrival["event_family"])
    return WORKFLOW_TYPE_BY_EVENT_FAMILY.get(family, family)


def _transition_delay(
    ctx: _WorkflowContext,
    workflow_id: str,
    transition: TransitionSpec,
    step_index: int,
    arrival_index: int,
) -> int:
    if transition.delay_seconds <= 0:
        return 0
    jitter_bound = max(0, transition.delay_seconds // 4)
    jitter = ctx.rng.randint(
        f"workflow-delay:{workflow_id}:{transition.event_type}",
        arrival_index * 100 + step_index,
        0,
        jitter_bound,
    )
    return min(transition.max_delay_seconds, transition.delay_seconds + jitter)


def _recording_delay(ctx: _WorkflowContext, workflow_id: str, step_index: int) -> int:
    return ctx.rng.randint(f"workflow-recording-delay:{workflow_id}", step_index, 1, 30)


def _side_effects_for_transition(
    ctx: _WorkflowContext,
    event: Mapping[str, Any],
    mark: ArrivalMark,
    transition: TransitionSpec,
) -> tuple[WorkflowSideEffect, ...]:
    effects: list[WorkflowSideEffect] = []
    for side_effect_type in transition.side_effects:
        target_table, target_id, status = _side_effect_target(side_effect_type, mark)
        if side_effect_type == "evidence_trigger":
            target_table = "governance_event"
            target_id = str(event["event_id"])
        side_effect_id = deterministic_uuid(
            ctx.namespace,
            "workflow_side_effect",
            {
                "event_id": event["event_id"],
                "side_effect_type": side_effect_type,
                "target_id": target_id,
            },
        )
        effects.append(
            WorkflowSideEffect(
                side_effect_id=side_effect_id,
                scenario_id=ctx.scenario_id,
                replicate_id=ctx.replicate_id,
                workflow_instance_id=str(event["workflow_instance_id"]),
                event_id=str(event["event_id"]),
                side_effect_type=side_effect_type,
                source_table="governance_event",
                source_id=str(event["event_id"]),
                target_table=target_table,
                target_id=target_id,
                status=status,
                rule_id=f"S06-SIDEEFFECT-{_normalize(side_effect_type)}",
                evidence_trigger_required=side_effect_type == "evidence_trigger",
            )
        )
    return tuple(effects)


def _side_effect_target(side_effect_type: str, mark: ArrivalMark) -> tuple[str, str, str]:
    if side_effect_type == "replica_creation":
        return "data_object", mark.data_object_id, "replica_required"
    if side_effect_type == "disclosure":
        return "actor", mark.oversight_actor_id, "disclosure_recorded"
    if side_effect_type == "derivation":
        return "data_object", mark.data_object_id, "derived_object_required"
    if side_effect_type == "correction":
        return "data_object", mark.data_object_id, "correction_applied"
    if side_effect_type == "invalidation":
        return "data_object", mark.data_object_id, "prior_value_invalidated"
    if side_effect_type == "deletion_status_update":
        return "data_object", mark.data_object_id, "model_erasure_status_updated"
    if side_effect_type == "evidence_trigger":
        return "governance_event", mark.arrival_id, "evidence_obligation_required"
    raise WorkflowCompilerError(f"unknown side_effect_type={side_effect_type!r}")


def _diagnostics(
    ctx: _WorkflowContext,
    events: tuple[dict[str, Any], ...],
    edges: tuple[dict[str, Any], ...],
    instances: tuple[dict[str, Any], ...],
    side_effects: tuple[WorkflowSideEffect, ...],
) -> WorkflowDiagnostics:
    definitions = workflow_definitions(ctx.resolved)
    conformant = 0
    deadline_violations = 0
    events_by_workflow = _events_by_workflow(events)
    for instance in instances:
        definition = definitions[str(instance["workflow_type"])]
        workflow_events = events_by_workflow[str(instance["workflow_instance_id"])]
        if _workflow_events_conform(definition, workflow_events):
            conformant += len(workflow_events)
        deadline_violations += _deadline_violations(definition, workflow_events)
    terminal_count = sum(
        1
        for instance in instances
        if instance["final_state"] in definitions[str(instance["workflow_type"])].terminal_states
    )
    open_count = sum(
        1
        for instance in instances
        if instance["final_state"] in definitions[str(instance["workflow_type"])].open_horizon_states
    )
    return WorkflowDiagnostics(
        scenario_id=ctx.scenario_id,
        replicate_id=ctx.replicate_id,
        workflow_count=len(instances),
        governance_event_count=len(events),
        event_edge_count=len(edges),
        side_effect_count=len(side_effects),
        transition_conformance_rate=conformant / len(events) if events else 1.0,
        terminal_workflow_count=terminal_count,
        open_horizon_workflow_count=open_count,
        deadline_violation_count=deadline_violations,
    )


def validate_workflows(
    workflow_build: WorkflowBuild,
    resolved: ResolvedConfig,
    *,
    arrivals: ArrivalBuild,
    catalog: CatalogBuild,
    contract: ContractSpec | None = None,
) -> None:
    """Validate S06 workflow tables, transitions, edges, and side effects."""

    schema_contract = contract if contract is not None else load_contract()
    definitions = workflow_definitions(resolved)
    event_ids = {row["event_id"] for row in workflow_build.governance_events}
    arrival_ids = {row["arrival_id"] for row in arrivals.arrivals}
    object_ids = {row["data_object_id"] for row in catalog.data_objects}
    database_ids = {row["database_id"] for row in catalog.local_databases}
    if len(event_ids) != len(workflow_build.governance_events):
        raise WorkflowCompilerError("duplicate governance_event.event_id values")
    for event in workflow_build.governance_events:
        validate_record(schema_contract, "governance_event", event)
        if event["source_event_id"] is not None and event["source_event_id"] not in event_ids | arrival_ids:
            raise WorkflowCompilerError(f"event {event['event_id']}: source_event_id does not resolve")
        if event["data_object_id"] not in object_ids:
            raise WorkflowCompilerError(f"event {event['event_id']}: data_object_id does not resolve")
        if event["local_database_id"] not in database_ids:
            raise WorkflowCompilerError(f"event {event['event_id']}: local_database_id does not resolve")
        if float(event["represented_event_count"]) < 0:
            raise WorkflowCompilerError(f"event {event['event_id']}: represented_event_count must be non-negative")
        if event["legal_basis_label_id"] not in CONTROLLED_LEGAL_BASIS_LABEL_IDS:
            raise WorkflowCompilerError(
                f"event {event['event_id']}: uncontrolled experimental legal_basis_label_id="
                f"{event['legal_basis_label_id']!r}"
            )
    for edge in workflow_build.event_edges:
        validate_record(schema_contract, "event_edge", edge)
        if edge["source_event_id"] not in event_ids:
            raise WorkflowCompilerError(f"edge {edge['edge_id']}: source_event_id does not resolve")
        if edge["target_event_id"] not in event_ids:
            raise WorkflowCompilerError(f"edge {edge['edge_id']}: target_event_id does not resolve")
    events_by_workflow = _events_by_workflow(workflow_build.governance_events)
    edge_targets = {edge["target_event_id"] for edge in workflow_build.event_edges}
    for instance in workflow_build.workflow_instances:
        validate_record(schema_contract, "workflow_instance", instance)
        workflow_id = str(instance["workflow_instance_id"])
        workflow_type = str(instance["workflow_type"])
        if workflow_type not in definitions:
            raise WorkflowCompilerError(f"workflow {workflow_id}: unknown workflow_type={workflow_type}")
        definition = definitions[workflow_type]
        workflow_events = events_by_workflow.get(workflow_id)
        if workflow_events is None:
            raise WorkflowCompilerError(f"workflow {workflow_id}: has no governance events")
        if int(instance["event_count"]) != len(workflow_events):
            raise WorkflowCompilerError(f"workflow {workflow_id}: event_count does not reconcile")
        if instance["root_event_id"] != workflow_events[0]["event_id"]:
            raise WorkflowCompilerError(f"workflow {workflow_id}: root_event_id does not match first event")
        if instance["final_state"] != workflow_events[-1]["workflow_state_after"]:
            raise WorkflowCompilerError(f"workflow {workflow_id}: final_state does not match terminal event")
        if instance["final_state"] in definition.terminal_states:
            if instance["terminal_event_id"] != workflow_events[-1]["event_id"]:
                raise WorkflowCompilerError(f"workflow {workflow_id}: terminal_event_id does not match final event")
            if instance["ended_at"] is None:
                raise WorkflowCompilerError(f"workflow {workflow_id}: terminal workflow is missing ended_at")
        elif instance["final_state"] not in definition.open_horizon_states:
            raise WorkflowCompilerError(
                f"workflow {workflow_id}: final state {instance['final_state']} is neither terminal nor open-horizon"
            )
        if not _workflow_events_conform(definition, workflow_events):
            raise WorkflowCompilerError(f"workflow {workflow_id}: illegal state transition sequence")
        if _deadline_violations(definition, workflow_events):
            raise WorkflowCompilerError(f"workflow {workflow_id}: transition deadline violation")
        for event in workflow_events[1:]:
            if event["event_id"] not in edge_targets:
                raise WorkflowCompilerError(f"workflow {workflow_id}: non-root event has no incoming edge")
    valid_side_effect_targets = object_ids | event_ids | arrival_ids
    actor_ids = set()
    for event in workflow_build.governance_events:
        actor_ids.update(
            str(event[field])
            for field in (
                "source_actor_id",
                "requesting_actor_id",
                "controller_actor_id",
                "processor_actor_id",
                "oversight_actor_id",
            )
            if event.get(field) is not None
        )
    valid_side_effect_targets |= actor_ids
    for effect in workflow_build.side_effects:
        if effect.side_effect_type not in SIDE_EFFECT_TYPES:
            raise WorkflowCompilerError(f"side effect {effect.side_effect_id}: unknown side_effect_type")
        if effect.event_id not in event_ids:
            raise WorkflowCompilerError(f"side effect {effect.side_effect_id}: event_id does not resolve")
        if effect.target_id not in valid_side_effect_targets:
            raise WorkflowCompilerError(f"side effect {effect.side_effect_id}: target_id does not resolve")
    for scenario_id, diagnostics in workflow_build.diagnostics.items():
        if diagnostics.transition_conformance_rate != 1.0:
            raise WorkflowCompilerError(f"{scenario_id}: transition conformance is not 100 percent")
        if diagnostics.deadline_violation_count != 0:
            raise WorkflowCompilerError(f"{scenario_id}: deadline violations recorded")


def _events_by_workflow(events: Iterable[Mapping[str, Any]]) -> dict[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        grouped.setdefault(str(event["workflow_instance_id"]), []).append(event)
    return {
        workflow_id: tuple(sorted(rows, key=lambda row: int(row["workflow_step_index"])))
        for workflow_id, rows in grouped.items()
    }


def _workflow_events_conform(
    definition: WorkflowDefinition,
    events: Sequence[Mapping[str, Any]],
) -> bool:
    if not events or len(events) > len(definition.transitions):
        return False
    for index, (event, transition) in enumerate(zip(events, definition.transitions)):
        if int(event["workflow_step_index"]) != index:
            return False
        if event["event_type"] != transition.event_type:
            return False
        if event["workflow_state_before"] != transition.state_before:
            return False
        if event["workflow_state_after"] != transition.state_after:
            return False
        expected_legal_basis_label_id = (
            transition.legal_basis_label_id or LEGAL_BASIS_BY_WORKFLOW[definition.workflow_type]
        )
        if event["legal_basis_label_id"] != expected_legal_basis_label_id:
            return False
        if int(event["causal_depth"]) != index:
            return False
    return True


def _deadline_violations(
    definition: WorkflowDefinition,
    events: Sequence[Mapping[str, Any]],
) -> int:
    violations = 0
    for index in range(1, len(events)):
        elapsed = (_timestamp(str(events[index]["timestamp"])) - _timestamp(str(events[index - 1]["timestamp"]))).total_seconds()
        if elapsed > definition.transitions[index].max_delay_seconds:
            violations += 1
    return violations


def _materialization_reason(ctx: _WorkflowContext, arrival: Mapping[str, Any]) -> str:
    if arrival["model_class"] == "replay":
        return "replay"
    if (
        ctx.resolved.claim_scale.materialized_row_target == ctx.resolved.claim_scale.represented_population
        and "census" in ctx.resolved.claim_scale.aggregation_semantics.lower()
    ):
        return "census"
    return "sampled"


def _purpose_id(purpose_tag: str) -> str:
    return f"PURPOSE-{_normalize(purpose_tag)}"


def _transition_rule_id(workflow_type: str, transition: TransitionSpec, step_index: int) -> str:
    return f"WF-{_normalize(workflow_type)}-{_normalize(transition.event_type)}-{step_index:02d}"


def _payload_ref(
    ctx: _WorkflowContext,
    workflow_id: str,
    step_index: int,
    transition: TransitionSpec,
) -> str:
    return (
        f"payload://{ctx.scenario_id}/replicate={ctx.replicate_id}/"
        f"workflow={workflow_id}/step={step_index}/event_type={transition.event_type}"
    )


def _normalize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
