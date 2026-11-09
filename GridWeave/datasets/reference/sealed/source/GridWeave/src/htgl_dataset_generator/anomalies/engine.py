"""S08 deterministic minimal-counterfactual anomaly generation.

The engine starts from finalized valid traces. It enumerates only edits declared
by the locked grammar, recomputes policy and graph-derived truth, and accepts a
pair only when the independently evaluated target invariant fails while every
declared protected invariant remains non-failing. Pair keys and complete traces
are evaluator-only sidecars; ``anomaly_instance.parquet`` never exposes them.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
import hashlib
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.catalog import CatalogBuild
from htgl_dataset_generator.baselines import AnomalyBaselineBuild, build_seeded_anomaly_baselines
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.dag import CausalDagBuild
from htgl_dataset_generator.evidence import EvidenceObligationBuild, EvidenceReceiptBuild
from htgl_dataset_generator.physical import PhysicalRawBuild
from htgl_dataset_generator.policy import (
    PolicyOracleBuild,
    SafePolicyEvaluator,
    load_policy_package,
    normalize_event_policy_facts,
)
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import (
    CounterRng,
    canonical_records_digest,
    deterministic_uuid,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.workflows import WorkflowBuild
from htgl_dataset_generator.world import FederatedWorld

from .invariants import IndependentInvariantChecker, outcome_by_id
from .models import (
    AnomalyBuild,
    AnomalyDiagnostics,
    AnomalySearchDiagnostics,
    CounterfactualEdit,
    CounterfactualPair,
    CounterfactualTrace,
    InvariantOutcome,
)
from .registry import EditGrammar, EditGrammarRule, InvariantRegistry, load_anomaly_contract


ANOMALY_COMPONENT = "S08.counterfactuals"
UNAUTHORIZED_PURPOSE_ID = "PURPOSE-COUNTERFACTUAL-UNAUTHORIZED-v1"
COMPLETED_ACTION = "completed"
INCOMPLETE_ACTION = "incomplete"


class AnomalyGenerationError(ValueError):
    """Raised when the configured anomaly contract cannot be satisfied exactly."""


@dataclass(frozen=True)
class _EngineContext:
    resolved: ResolvedConfig
    scenario_id: str
    replicate_id: int
    namespace: str
    rng: CounterRng
    contract: ContractSpec
    world: FederatedWorld
    catalog: CatalogBuild
    physical: PhysicalRawBuild
    workflows: WorkflowBuild
    causal_dag: CausalDagBuild
    policy: PolicyOracleBuild
    obligations: EvidenceObligationBuild
    receipts: EvidenceReceiptBuild
    registry: InvariantRegistry
    grammar: EditGrammar
    checker: IndependentInvariantChecker
    evaluator: SafePolicyEvaluator
    physical_digest: str


@dataclass(frozen=True)
class _AcceptedCandidate:
    edit: CounterfactualEdit
    invalid_trace: CounterfactualTrace
    invalid_outcomes: tuple[InvariantOutcome, ...]
    counters: Counter[str]
    lower_cost_candidate_count: int


def build_anomalies(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    physical: PhysicalRawBuild,
    workflows: WorkflowBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    invariant_registry_path: Path | None = None,
    edit_grammar_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> AnomalyBuild:
    """Generate strictly accepted minimal counterfactual anomaly episodes."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids or resolved.run.selected_scenario_ids))
    if not selected:
        raise AnomalyGenerationError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise AnomalyGenerationError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise AnomalyGenerationError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    registry, grammar = load_anomaly_contract(
        resolved,
        invariant_path=invariant_registry_path,
        grammar_path=edit_grammar_path,
        contract=schema_contract,
    )
    checker = IndependentInvariantChecker(registry, contract=schema_contract)
    evaluator = SafePolicyEvaluator(load_policy_package(resolved, contract=schema_contract))

    all_rows: list[dict[str, Any]] = []
    all_pairs: list[CounterfactualPair] = []
    all_diagnostics: dict[str, AnomalyDiagnostics] = {}
    for scenario_id in selected:
        ctx = _engine_context(
            resolved=resolved,
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            contract=schema_contract,
            world=world,
            catalog=catalog,
            physical=physical,
            workflows=workflows,
            causal_dag=causal_dag,
            policy=policy,
            obligations=obligations,
            receipts=receipts,
            registry=registry,
            grammar=grammar,
            checker=checker,
            evaluator=evaluator,
        )
        rows, pairs, diagnostics = _build_scenario(ctx)
        all_rows.extend(rows)
        all_pairs.extend(pairs)
        all_diagnostics[scenario_id] = diagnostics

    build = AnomalyBuild(
        anomaly_instances=tuple(sorted(all_rows, key=lambda row: str(row["anomaly_instance_id"]))),
        counterfactual_pairs=tuple(
            sorted(all_pairs, key=lambda pair: pair.anomaly_instance_id)
        ),
        diagnostics=dict(sorted(all_diagnostics.items())),
        invariant_registry_sha256=registry.bundle_sha256,
        edit_grammar_sha256=grammar.bundle_sha256,
    )
    validate_anomaly_build(build, resolved, contract=schema_contract)
    return build


def build_minimal_counterfactual_comparison(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    physical: PhysicalRawBuild,
    workflows: WorkflowBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    anomaly_types: Sequence[str] = ("unauthorized_purpose",),
    episodes_per_type: int = 1,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    invariant_registry_path: Path | None = None,
    edit_grammar_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> AnomalyBuild:
    """Execute a bounded evaluator-only P8 comparison without changing S08 truth.

    This uses the production grammar, independent invariant checker, policy
    recomputation, and strict target-only acceptance path. It does not add rows
    to the configured authoritative anomaly output.
    """

    if not anomaly_types or len(set(anomaly_types)) != len(tuple(anomaly_types)):
        raise AnomalyGenerationError("comparison anomaly_types must be unique and non-empty")
    if episodes_per_type <= 0:
        raise AnomalyGenerationError("comparison episodes_per_type must be positive")
    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids or resolved.run.selected_scenario_ids))
    if not selected:
        raise AnomalyGenerationError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise AnomalyGenerationError(f"scenario_ids not selected in config: {unknown}")
    registry, grammar = load_anomaly_contract(
        resolved,
        invariant_path=invariant_registry_path,
        grammar_path=edit_grammar_path,
        contract=schema_contract,
    )
    for anomaly_type in anomaly_types:
        grammar.rule(anomaly_type)
    checker = IndependentInvariantChecker(registry, contract=schema_contract)
    evaluator = SafePolicyEvaluator(load_policy_package(resolved, contract=schema_contract))
    all_rows: list[dict[str, Any]] = []
    all_pairs: list[CounterfactualPair] = []
    diagnostics: dict[str, AnomalyDiagnostics] = {}
    for scenario_id in selected:
        ctx = _engine_context(
            resolved=resolved,
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            contract=schema_contract,
            world=world,
            catalog=catalog,
            physical=physical,
            workflows=workflows,
            causal_dag=causal_dag,
            policy=policy,
            obligations=obligations,
            receipts=receipts,
            registry=registry,
            grammar=grammar,
            checker=checker,
            evaluator=evaluator,
        )
        rows, pairs, item = _build_scenario(
            ctx,
            configured_types_override=tuple(anomaly_types),
            target_count_override=episodes_per_type,
        )
        all_rows.extend(rows)
        all_pairs.extend(pairs)
        diagnostics[scenario_id] = item
    build = AnomalyBuild(
        anomaly_instances=tuple(sorted(all_rows, key=lambda row: str(row["anomaly_instance_id"]))),
        counterfactual_pairs=tuple(sorted(all_pairs, key=lambda pair: pair.anomaly_instance_id)),
        diagnostics=dict(sorted(diagnostics.items())),
        invariant_registry_sha256=registry.bundle_sha256,
        edit_grammar_sha256=grammar.bundle_sha256,
    )
    validate_anomaly_build(build, resolved, contract=schema_contract)
    return build


def build_anomaly_baselines(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    physical: PhysicalRawBuild,
    workflows: WorkflowBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    invariant_registry_path: Path | None = None,
    edit_grammar_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> AnomalyBaselineBuild:
    """Build seeded comparison controls without emitting anomaly truth rows."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids or resolved.run.selected_scenario_ids))
    registry, grammar = load_anomaly_contract(
        resolved,
        invariant_path=invariant_registry_path,
        grammar_path=edit_grammar_path,
        contract=schema_contract,
    )
    checker = IndependentInvariantChecker(registry, contract=schema_contract)
    evaluator = SafePolicyEvaluator(load_policy_package(resolved, contract=schema_contract))
    all_cases = []
    for scenario_id in selected:
        ctx = _engine_context(
            resolved=resolved,
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            contract=schema_contract,
            world=world,
            catalog=catalog,
            physical=physical,
            workflows=workflows,
            causal_dag=causal_dag,
            policy=policy,
            obligations=obligations,
            receipts=receipts,
            registry=registry,
            grammar=grammar,
            checker=checker,
            evaluator=evaluator,
        )
        traces = tuple(_extract_valid_traces(ctx).values())
        scenario_build = build_seeded_anomaly_baselines(
            traces,
            rng=ctx.rng,
            checker=ctx.checker,
            recompute=lambda trace, context=ctx: _recompute_trace(context, trace),
            contract=schema_contract,
            profile_ids=resolved.anomaly.baseline_profile_ids,
        )
        all_cases.extend(scenario_build.cases)
    counts = Counter(case.profile_id for case in all_cases)
    return AnomalyBaselineBuild(
        cases=tuple(sorted(all_cases, key=lambda case: (case.profile_id, case.source_workflow_id))),
        profile_counts=dict(sorted(counts.items())),
        mean_failed_invariant_count=(
            sum(len(case.failed_invariant_ids) for case in all_cases) / len(all_cases)
            if all_cases
            else 0.0
        ),
    )


def _build_scenario(
    ctx: _EngineContext,
    *,
    configured_types_override: Sequence[str] | None = None,
    target_count_override: int | None = None,
) -> tuple[tuple[dict[str, Any], ...], tuple[CounterfactualPair, ...], AnomalyDiagnostics]:
    traces = _extract_valid_traces(ctx)
    configured_types = (
        tuple(configured_types_override)
        if configured_types_override is not None
        else tuple(ctx.resolved.anomaly.types)
    )
    if not configured_types:
        return (), (), AnomalyDiagnostics(
            scenario_id=ctx.scenario_id,
            replicate_id=ctx.replicate_id,
            anomaly_count=0,
            target_violation_success_rate=1.0,
            protected_collateral_violation_rate=0.0,
            mean_edit_cost=0.0,
            anomaly_type_counts={},
            mean_candidates_evaluated=0.0,
        )
    if not traces:
        raise AnomalyGenerationError(f"{ctx.scenario_id}: no finalized workflows available")

    valid_outcomes = {
        workflow_id: ctx.checker.evaluate(trace)
        for workflow_id, trace in traces.items()
    }
    pairs: list[CounterfactualPair] = []
    rows: list[dict[str, Any]] = []
    for anomaly_type in configured_types:
        rule = ctx.grammar.rule(anomaly_type)
        target_count = (
            target_count_override
            if target_count_override is not None
            else _configured_target_count(
                len(traces), float(ctx.resolved.anomaly.prevalence[anomaly_type])
            )
        )
        if target_count == 0:
            continue
        candidates = _candidate_edits(ctx, traces, anomaly_type, rule)
        if not candidates:
            raise AnomalyGenerationError(
                f"{ctx.scenario_id}: anomaly_type={anomaly_type} has positive prevalence "
                "but no grammar-eligible candidate edits"
            )
        eligible_workflows = {
            workflow_id
            for workflow_id, _ in candidates
            if _source_is_eligible(
                valid_outcomes[workflow_id], rule.target_invariant_id, _protected_ids(ctx, rule)
            )
        }
        if len(eligible_workflows) < target_count:
            raise AnomalyGenerationError(
                f"{ctx.scenario_id}: anomaly_type={anomaly_type} requires {target_count} accepted "
                f"episodes but only {len(eligible_workflows)} valid source workflows are eligible"
            )
        candidates_by_workflow: dict[str, list[CounterfactualEdit]] = defaultdict(list)
        for workflow_id, edit in candidates:
            candidates_by_workflow[workflow_id].append(edit)
        accepted_candidates: dict[str, _AcceptedCandidate] = {}
        aggregate_rejections = Counter()
        for workflow_id in sorted(candidates_by_workflow):
            valid_trace = traces[workflow_id]
            source_outcomes = valid_outcomes[workflow_id]
            local = Counter(generated=len(candidates_by_workflow[workflow_id]))
            if not _source_is_eligible(
                source_outcomes, rule.target_invariant_id, _protected_ids(ctx, rule)
            ):
                local["invalid_source"] += 1
                aggregate_rejections.update(local)
                continue
            ordered_edits = sorted(
                candidates_by_workflow[workflow_id],
                key=lambda edit: (
                    edit.cost,
                    ctx.rng.uint64(
                        f"within-workflow-edit:{anomaly_type}:{workflow_id}:{_edit_identity(edit)}",
                        0,
                    ),
                    _edit_identity(edit),
                ),
            )
            for edit in ordered_edits:
                if edit.cost > ctx.resolved.anomaly.search_bound:
                    continue
                local["evaluated"] += 1
                invalid_trace = _apply_and_recompute(ctx, valid_trace, edit)
                invalid_outcomes = ctx.checker.evaluate(
                    invalid_trace,
                    reference=valid_trace,
                    anomaly_type=anomaly_type,
                )
                accepted, rejection = _acceptance(
                    invalid_outcomes,
                    target_invariant_id=rule.target_invariant_id,
                    protected_ids=_protected_ids(ctx, rule),
                )
                if not accepted:
                    local[rejection] += 1
                    continue
                accepted_candidates[workflow_id] = _AcceptedCandidate(
                    edit=edit,
                    invalid_trace=invalid_trace,
                    invalid_outcomes=invalid_outcomes,
                    counters=local.copy(),
                    lower_cost_candidate_count=sum(
                        candidate.cost < edit.cost for candidate in ordered_edits
                    ),
                )
                break
            aggregate_rejections.update(local)
        if len(accepted_candidates) < target_count:
            raise AnomalyGenerationError(
                f"{ctx.scenario_id}: anomaly_type={anomaly_type} accepted-source pool "
                f"{len(accepted_candidates)}/{target_count}; diagnostics={dict(aggregate_rejections)}"
            )
        selected_workflows = tuple(
            sorted(
                accepted_candidates,
                key=lambda workflow_id: (
                    ctx.rng.uint64(
                        f"workflow-selection:{anomaly_type}:{workflow_id}", 0
                    ),
                    workflow_id,
                ),
            )[:target_count]
        )
        for workflow_id in selected_workflows:
            accepted_candidate = accepted_candidates[workflow_id]
            valid_trace = traces[workflow_id]
            pair, row = _accepted_pair(
                ctx,
                anomaly_type=anomaly_type,
                rule=rule,
                valid_trace=valid_trace,
                invalid_trace=accepted_candidate.invalid_trace,
                edit=accepted_candidate.edit,
                valid_outcomes=valid_outcomes[workflow_id],
                invalid_outcomes=accepted_candidate.invalid_outcomes,
                candidate_count=len(candidates),
                eligible_workflow_count=len(accepted_candidates),
                target_count=target_count,
                counters=accepted_candidate.counters,
                lower_cost_candidate_count=accepted_candidate.lower_cost_candidate_count,
            )
            pairs.append(pair)
            rows.append(row)

    type_counts = Counter(pair.anomaly_type for pair in pairs)
    diagnostics = AnomalyDiagnostics(
        scenario_id=ctx.scenario_id,
        replicate_id=ctx.replicate_id,
        anomaly_count=len(pairs),
        target_violation_success_rate=(
            sum(
                not outcome_by_id(pair.invalid_invariant_outcomes)[pair.target_invariant_id].passed
                for pair in pairs
            )
            / len(pairs)
            if pairs
            else 1.0
        ),
        protected_collateral_violation_rate=(
            sum(
                1
                for pair in pairs
                for invariant_id in pair.preserved_invariant_ids
                if outcome_by_id(pair.invalid_invariant_outcomes)[invariant_id].status == "fail"
            )
            / sum(len(pair.preserved_invariant_ids) for pair in pairs)
            if pairs
            else 0.0
        ),
        mean_edit_cost=sum(pair.edit.cost for pair in pairs) / len(pairs) if pairs else 0.0,
        anomaly_type_counts=dict(sorted(type_counts.items())),
        mean_candidates_evaluated=(
            sum(pair.search_diagnostics.evaluated_candidate_count for pair in pairs) / len(pairs)
            if pairs
            else 0.0
        ),
    )
    return tuple(rows), tuple(pairs), diagnostics


def _extract_valid_traces(ctx: _EngineContext) -> Mapping[str, CounterfactualTrace]:
    scenario_workflows = tuple(
        sorted(
            (
                row
                for row in ctx.causal_dag.workflow_instances
                if str(row["scenario_id"]) == ctx.scenario_id
            ),
            key=lambda row: str(row["workflow_instance_id"]),
        )
    )
    scenario_events = tuple(
        row
        for row in ctx.causal_dag.governance_events
        if str(row["scenario_id"]) == ctx.scenario_id
    )
    events_by_workflow: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in scenario_events:
        events_by_workflow[str(row["workflow_instance_id"])].append(dict(row))
    workflow_by_event = {
        str(row["event_id"]): str(row["workflow_instance_id"])
        for row in scenario_events
    }
    edges_by_workflow: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ctx.causal_dag.event_edges:
        source_workflow = workflow_by_event.get(str(row["source_event_id"]))
        target_workflow = workflow_by_event.get(str(row["target_event_id"]))
        if source_workflow is not None and source_workflow == target_workflow:
            edges_by_workflow[source_workflow].append(dict(row))
    replicas_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ctx.catalog.data_object_replicas:
        replicas_by_object[str(row["data_object_id"])].append(dict(row))
    obligations_by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ctx.obligations.evidence_obligations:
        obligations_by_event[str(row["event_id"])].append(dict(row))
    all_valid_receipt_ids = frozenset(
        item.receipt_id
        for item in ctx.receipts.verification.truth
        if item.expected_status == "valid"
    )
    receipts_by_obligation: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ctx.receipts.evidence_receipts:
        if str(row["receipt_id"]) in all_valid_receipt_ids:
            receipts_by_obligation[str(row["obligation_id"])].append(dict(row))
    side_effect_events = {
        str(item.event_id)
        for item in ctx.workflows.side_effects
        if item.side_effect_type == "deletion_status_update"
        and item.status == "model_erasure_status_updated"
    }
    traces: dict[str, CounterfactualTrace] = {}
    for workflow in scenario_workflows:
        workflow_id = str(workflow["workflow_instance_id"])
        events = tuple(
            sorted(
                events_by_workflow.get(workflow_id, ()),
                key=lambda row: (int(row["workflow_step_index"]), str(row["event_id"])),
            )
        )
        if not events:
            raise AnomalyGenerationError(f"workflow {workflow_id}: no events")
        event_ids = {str(row["event_id"]) for row in events}
        edges = tuple(
            sorted(
                edges_by_workflow.get(workflow_id, ()),
                key=lambda row: str(row["edge_id"]),
            )
        )
        object_ids = {str(row["data_object_id"]) for row in events}
        replicas = tuple(
            sorted(
                (
                    row
                    for object_id in sorted(object_ids)
                    for row in replicas_by_object.get(object_id, ())
                ),
                key=lambda row: str(row["replica_id"]),
            )
        )
        episode_obligations = tuple(
            sorted(
                (
                    row
                    for event_id in sorted(event_ids)
                    for row in obligations_by_event.get(event_id, ())
                ),
                key=lambda row: str(row["obligation_id"]),
            )
        )
        obligation_ids = {str(row["obligation_id"]) for row in episode_obligations}
        episode_receipts = tuple(
            sorted(
                (
                    row
                    for obligation_id in obligation_ids
                    for row in receipts_by_obligation.get(obligation_id, ())
                ),
                key=lambda row: str(row["receipt_id"]),
            )
        )
        valid_ids = frozenset(str(row["receipt_id"]) for row in episode_receipts)
        action_status: dict[str, str] = {}
        event_by_id = {str(row["event_id"]): row for row in events}
        for obligation in episode_obligations:
            if (
                str(obligation["obligation_type"]) == "replica_deletion"
                and str(obligation["coverage_scope"]) == "replica_set"
                and str(obligation["event_id"]) in side_effect_events
                and str(event_by_id[str(obligation["event_id"])]["erasure_state_after"]) == "executed"
            ):
                action_status[str(obligation["subject_object_id"])] = COMPLETED_ACTION
        trace = CounterfactualTrace(
            scenario_id=ctx.scenario_id,
            replicate_id=ctx.replicate_id,
            workflow_instance=dict(workflow),
            events=events,
            edges=edges,
            replicas=replicas,
            obligations=episode_obligations,
            receipts=episode_receipts,
            independently_valid_receipt_ids=valid_ids,
            policy_evaluations={},
            evidence_duty_signatures={},
            ancestor_closure={},
            derived_root_event_ids={},
            derived_causal_depths={},
            observer_required_receipt_ids=valid_ids,
            observer_visible_receipt_ids=valid_ids,
            replica_action_status=dict(sorted(action_status.items())),
            sampling_membership=(),
            physical_context_digest=ctx.physical_digest,
        )
        finalized_trace = _recompute_trace(ctx, trace)
        source_failures = tuple(
            item.invariant_id
            for item in ctx.checker.evaluate(finalized_trace)
            if item.status == "fail"
        )
        if source_failures:
            # Receipt generation deliberately includes adversarial verification
            # fixtures. Such episodes remain evaluator truth, but they cannot be
            # the valid member of a minimal counterfactual pair.
            continue
        traces[workflow_id] = finalized_trace
    return dict(sorted(traces.items()))


def _candidate_edits(
    ctx: _EngineContext,
    traces: Mapping[str, CounterfactualTrace],
    anomaly_type: str,
    rule: EditGrammarRule,
) -> tuple[tuple[str, CounterfactualEdit], ...]:
    operation = rule.operations[0]
    candidates: list[tuple[str, CounterfactualEdit]] = []
    actors = {str(row["actor_id"]): row for row in ctx.world.actors}
    for workflow_id, trace in traces.items():
        if anomaly_type == "unauthorized_purpose":
            for event in trace.events:
                if str(event["policy_purpose_id"]) == UNAUTHORIZED_PURPOSE_ID:
                    continue
                candidates.append(
                    (workflow_id, _edit(operation, rule, (
                        ("event_id", str(event["event_id"])),
                        ("replacement_purpose_id", UNAUTHORIZED_PURPOSE_ID),
                    ), (f"governance_event[event_id={event['event_id']}].policy_purpose_id",),
                    (f"policy_evaluation[event_id={event['event_id']}]",)))
                )
        elif anomaly_type == "missing_erasure_propagation":
            obligation_by_id = {
                str(row["obligation_id"]): row
                for row in trace.obligations
                if row["obligation_type"] == "provenance"
                and row["coverage_scope"] == "replica_set"
            }
            for receipt in trace.receipts:
                obligation = obligation_by_id.get(str(receipt["obligation_id"]))
                if obligation is None:
                    continue
                replica_id = str(obligation["subject_object_id"])
                if replica_id not in {str(value) for value in receipt["covers_replica_ids"]}:
                    continue
                candidates.append((workflow_id, _edit(
                    operation, rule,
                    (("receipt_id", str(receipt["receipt_id"])), ("replica_id", replica_id)),
                    (f"evidence_receipt[receipt_id={receipt['receipt_id']}]",),
                    (f"evidence_coverage[replica_id={replica_id}]",),
                )))
        elif anomaly_type == "premature_deletion":
            for replica in trace.replicas:
                if replica["deletion_due_at"] is None or str(replica["deletion_status"]) == "exempt":
                    continue
                candidates.append((workflow_id, _edit(
                    operation, rule,
                    (("replica_id", str(replica["replica_id"])),),
                    (
                        f"data_object_replica[replica_id={replica['replica_id']}].deletion_status",
                        f"data_object_replica[replica_id={replica['replica_id']}].deleted_at",
                    ),
                    ("policy_evaluations",),
                )))
        elif anomaly_type == "false_confirmation":
            deletion_obligations = {
                str(row["obligation_id"]): str(row["subject_object_id"])
                for row in trace.obligations
                if row["obligation_type"] == "replica_deletion"
                and row["coverage_scope"] == "replica_set"
            }
            for receipt in trace.receipts:
                replica_id = deletion_obligations.get(str(receipt["obligation_id"]))
                if replica_id is None or trace.replica_action_status.get(replica_id) != COMPLETED_ACTION:
                    continue
                candidates.append((workflow_id, _edit(
                    operation, rule,
                    (("receipt_id", str(receipt["receipt_id"])), ("replica_id", replica_id)),
                    (f"replica_action_truth[replica_id={replica_id}].status",),
                    (f"receipt_action_match[receipt_id={receipt['receipt_id']}]",),
                )))
        elif anomaly_type == "causal_orphan":
            for edge in trace.edges:
                if (
                    str(edge["edge_type"]) == "precedes"
                    and "S07-WORKFLOW-PRECEDES" in str(edge.get("rule_id") or "")
                ):
                    candidates.append((workflow_id, _edit(
                        operation, rule,
                        (("edge_id", str(edge["edge_id"])), ("target_event_id", str(edge["target_event_id"]))),
                        (f"event_edge[edge_id={edge['edge_id']}]",),
                        ("ancestor_closure", "derived_root_event_ids", "derived_causal_depths"),
                    )))
        elif anomaly_type == "observer_omission":
            for receipt_id in sorted(trace.observer_required_receipt_ids):
                candidates.append((workflow_id, _edit(
                    operation, rule,
                    (("receipt_id", receipt_id),),
                    (f"observer_delivery.required_receipt_ids[receipt_id={receipt_id}]",),
                    ("observer_task_sufficiency",),
                )))
        elif anomaly_type == "cross_region_rule_breach":
            for event in trace.events:
                if str(event["event_type"]) not in {"transfer_authorized", "transfer_received"}:
                    continue
                current_id = str(event["requesting_actor_id"] or "")
                current = actors.get(current_id)
                if current is None:
                    continue
                for candidate in sorted(ctx.world.actors, key=lambda row: str(row["actor_id"])):
                    if (
                        str(candidate["actor_id"]) != current_id
                        and str(candidate["scenario_id"]) == ctx.scenario_id
                        and str(candidate["actor_class"]) == str(current["actor_class"])
                        and str(candidate["jurisdiction_id"]) != str(current["jurisdiction_id"])
                        and _active_at(candidate, str(event["timestamp"]))
                    ):
                        candidates.append((workflow_id, _edit(
                            operation, rule,
                            (("event_id", str(event["event_id"])), ("replacement_actor_id", str(candidate["actor_id"]))),
                            (f"governance_event[event_id={event['event_id']}].requesting_actor_id",),
                            (f"policy_evaluation[event_id={event['event_id']}]",),
                        )))
        elif anomaly_type == "clock_replay_conflict":
            for edge in trace.edges:
                if (
                    str(edge["edge_type"]) == "precedes"
                    and "S07-WORKFLOW-PRECEDES" in str(edge.get("rule_id") or "")
                ):
                    candidates.append((workflow_id, _edit(
                        operation, rule,
                        (("edge_id", str(edge["edge_id"])), ("parent_event_id", str(edge["source_event_id"])), ("child_event_id", str(edge["target_event_id"]))),
                        (f"governance_event[event_id={edge['target_event_id']}].recorded_timestamp",),
                        ("recorded_time_causal_order",),
                    )))
        else:
            raise AnomalyGenerationError(f"unsupported anomaly_type={anomaly_type!r}")
    return tuple(candidates)


def _apply_and_recompute(
    ctx: _EngineContext,
    trace: CounterfactualTrace,
    edit: CounterfactualEdit,
) -> CounterfactualTrace:
    operation = edit.operation
    events = [dict(row) for row in trace.events]
    edges = [dict(row) for row in trace.edges]
    replicas = [dict(row) for row in trace.replicas]
    receipts = [dict(row) for row in trace.receipts]
    observer_visible = set(trace.observer_visible_receipt_ids)
    action_status = dict(trace.replica_action_status)
    if operation == "replace_policy_purpose_with_unpermitted_controlled_id":
        _row_by(events, "event_id", edit.parameter("event_id"))["policy_purpose_id"] = edit.parameter("replacement_purpose_id")
    elif operation == "omit_one_timely_valid_replica_propagation_receipt":
        receipts = [row for row in receipts if str(row["receipt_id"]) != edit.parameter("receipt_id")]
    elif operation == "set_one_replica_deleted_one_microsecond_before_due":
        replica = _row_by(replicas, "replica_id", edit.parameter("replica_id"))
        due = _timestamp(str(replica["deletion_due_at"]))
        replica["deletion_status"] = "deleted"
        replica["deleted_at"] = _format_timestamp(due - timedelta(microseconds=1))
    elif operation == "mark_one_receipted_replica_action_incomplete_without_mutating_receipt":
        action_status[edit.parameter("replica_id")] = INCOMPLETE_ACTION
    elif operation == "remove_one_required_incoming_event_edge":
        edges = [row for row in edges if str(row["edge_id"]) != edit.parameter("edge_id")]
    elif operation == "omit_one_required_receipt_from_counterfactual_observer_delivery":
        observer_visible.remove(edit.parameter("receipt_id"))
    elif operation == "replace_destination_actor_with_effective_same_class_actor_in_other_jurisdiction":
        _row_by(events, "event_id", edit.parameter("event_id"))["requesting_actor_id"] = edit.parameter("replacement_actor_id")
    elif operation == "shift_one_child_recorded_time_one_microsecond_before_parent_without_changing_world_time":
        parent = _row_by(events, "event_id", edit.parameter("parent_event_id"))
        child = _row_by(events, "event_id", edit.parameter("child_event_id"))
        parent_recorded = _timestamp(str(parent["recorded_timestamp"] or parent["timestamp"]))
        child["recorded_timestamp"] = _format_timestamp(parent_recorded - timedelta(microseconds=1))
    else:
        raise AnomalyGenerationError(f"unknown grammar operation={operation!r}")
    changed = replace(
        trace,
        events=tuple(sorted(events, key=lambda row: (int(row["workflow_step_index"]), str(row["event_id"])))),
        edges=tuple(sorted(edges, key=lambda row: str(row["edge_id"]))),
        replicas=tuple(sorted(replicas, key=lambda row: str(row["replica_id"]))),
        receipts=tuple(sorted(receipts, key=lambda row: str(row["receipt_id"]))),
        observer_visible_receipt_ids=frozenset(observer_visible),
        replica_action_status=dict(sorted(action_status.items())),
    )
    return _recompute_trace(ctx, changed)


def _recompute_trace(ctx: _EngineContext, trace: CounterfactualTrace) -> CounterfactualTrace:
    modified_replica_by_id = {str(row["replica_id"]): dict(row) for row in trace.replicas}
    full_replicas = tuple(
        modified_replica_by_id.get(str(row["replica_id"]), dict(row))
        for row in ctx.catalog.data_object_replicas
    )
    modified_catalog = replace(ctx.catalog, data_object_replicas=full_replicas)
    modified_event_by_id = {str(row["event_id"]): dict(row) for row in trace.events}
    full_events = tuple(
        modified_event_by_id.get(str(row["event_id"]), dict(row))
        for row in ctx.causal_dag.governance_events
    )
    modified_dag = replace(ctx.causal_dag, governance_events=full_events)
    policy_evaluations: dict[str, Mapping[str, Any]] = {}
    for event in trace.events:
        facts = normalize_event_policy_facts(
            event,
            world=ctx.world,
            catalog=modified_catalog,
            causal_dag=modified_dag,
        )
        evaluation = ctx.evaluator.evaluate(facts)
        policy_evaluations[str(event["event_id"])] = asdict(evaluation)
    ancestor_closure, roots, depths = _graph_truth(trace.events, trace.edges)
    duty_signatures: dict[str, tuple[str, ...]] = {}
    for obligation in trace.obligations:
        event_id = str(obligation["event_id"])
        signature = canonical_json({
            "applied_rule_ids": list(policy_evaluations[event_id]["applied_rule_ids"]),
            "coverage_scope": obligation["coverage_scope"],
            "obligation_type": obligation["obligation_type"],
            "required_evidence_types": obligation["required_evidence_types"],
            "subject_object_id": obligation["subject_object_id"],
        })
        duty_signatures.setdefault(event_id, tuple())
        duty_signatures[event_id] = tuple(sorted((*duty_signatures[event_id], signature)))
    return replace(
        trace,
        policy_evaluations=dict(sorted(policy_evaluations.items())),
        evidence_duty_signatures=dict(sorted(duty_signatures.items())),
        ancestor_closure=ancestor_closure,
        derived_root_event_ids=roots,
        derived_causal_depths=depths,
    )


def _accepted_pair(
    ctx: _EngineContext,
    *,
    anomaly_type: str,
    rule: EditGrammarRule,
    valid_trace: CounterfactualTrace,
    invalid_trace: CounterfactualTrace,
    edit: CounterfactualEdit,
    valid_outcomes: tuple[InvariantOutcome, ...],
    invalid_outcomes: tuple[InvariantOutcome, ...],
    candidate_count: int,
    eligible_workflow_count: int,
    target_count: int,
    counters: Counter[str],
    lower_cost_candidate_count: int,
) -> tuple[CounterfactualPair, dict[str, Any]]:
    id_parts = {
        "anomaly_type": anomaly_type,
        "edit": _edit_identity(edit),
        "replicate_id": ctx.replicate_id,
        "scenario_id": ctx.scenario_id,
        "valid_workflow_id": valid_trace.workflow_id,
    }
    anomaly_id = deterministic_uuid(ctx.namespace, "anomaly_instance", id_parts)
    invalid_workflow_id = deterministic_uuid(ctx.namespace, "invalid_counterfactual_workflow", id_parts)
    pair_id = deterministic_uuid(ctx.namespace, "protected_counterfactual_pair", id_parts)
    protected_ids = _protected_ids(ctx, rule)
    search = AnomalySearchDiagnostics(
        anomaly_type=anomaly_type,
        target_invariant_id=rule.target_invariant_id,
        search_bound=ctx.resolved.anomaly.search_bound,
        generated_candidate_count=candidate_count,
        evaluated_candidate_count=int(counters["evaluated"]),
        rejected_valid_source_count=int(counters["invalid_source"]),
        rejected_target_not_failed_count=int(counters["target_not_failed"]),
        rejected_protected_failure_count=int(counters["protected_failure"]),
        rejected_schema_or_physical_count=int(counters["schema_or_physical"]),
        accepted_cost=edit.cost,
        lower_cost_candidate_count=lower_cost_candidate_count,
        minimality_proven_within_bound=edit.cost <= ctx.resolved.anomaly.search_bound,
        minimality_scope=ctx.grammar.minimality_scope,
    )
    probability = min(1.0, target_count / float(eligible_workflow_count))
    pair = CounterfactualPair(
        protected_pair_id=pair_id,
        anomaly_instance_id=anomaly_id,
        anomaly_type=anomaly_type,
        target_invariant_id=rule.target_invariant_id,
        valid_trace=valid_trace,
        invalid_trace=invalid_trace,
        invalid_counterfactual_workflow_id=invalid_workflow_id,
        edit=edit,
        valid_invariant_outcomes=valid_outcomes,
        invalid_invariant_outcomes=invalid_outcomes,
        preserved_invariant_ids=protected_ids,
        search_diagnostics=search,
        selection_probability=probability,
        analysis_weight=1.0 / probability,
    )
    times = sorted(_timestamp(str(row["timestamp"])) for row in valid_trace.events)
    row = {
        "anomaly_instance_id": anomaly_id,
        "scenario_id": ctx.scenario_id,
        "anomaly_type": anomaly_type,
        "target_invariant_id": rule.target_invariant_id,
        "severity": float(rule.severity),
        "start_time": _format_timestamp(times[0]),
        "end_time": _format_timestamp(times[-1]),
        "valid_counterfactual_workflow_id": valid_trace.workflow_id,
        "invalid_counterfactual_workflow_id": invalid_workflow_id,
        "changed_field_paths": list(edit.primitive_changed_field_paths),
        "preserved_invariant_ids": list(protected_ids),
        "adversarial": True,
        "episode_event_count": len(valid_trace.events),
    }
    validate_record(ctx.contract, "anomaly_instance", row)
    return pair, row


def validate_anomaly_build(
    build: AnomalyBuild,
    resolved: ResolvedConfig,
    *,
    contract: ContractSpec | None = None,
) -> None:
    """Fail closed on schemas, privacy, exact acceptance, and diagnostics."""

    schema_contract = contract if contract is not None else load_contract()
    if build.invariant_registry_sha256 != resolved.anomaly.invariant_registry_sha256:
        raise AnomalyGenerationError("invariant registry digest mismatch")
    if build.edit_grammar_sha256 != resolved.anomaly.edit_grammar_sha256:
        raise AnomalyGenerationError("edit grammar digest mismatch")
    rows = {str(row["anomaly_instance_id"]): row for row in build.anomaly_instances}
    if len(rows) != len(build.anomaly_instances):
        raise AnomalyGenerationError("duplicate anomaly_instance_id")
    pairs = {pair.anomaly_instance_id: pair for pair in build.counterfactual_pairs}
    if set(rows) != set(pairs):
        raise AnomalyGenerationError("anomaly rows and evaluator-only pairs do not reconcile")
    protected_pair_ids: set[str] = set()
    invalid_workflow_ids: set[str] = set()
    for anomaly_id, row in rows.items():
        validate_record(schema_contract, "anomaly_instance", row)
        pair = pairs[anomaly_id]
        if pair.protected_pair_id in protected_pair_ids:
            raise AnomalyGenerationError("duplicate protected pair ID")
        protected_pair_ids.add(pair.protected_pair_id)
        if pair.invalid_counterfactual_workflow_id in invalid_workflow_ids:
            raise AnomalyGenerationError("duplicate invalid counterfactual workflow ID")
        invalid_workflow_ids.add(pair.invalid_counterfactual_workflow_id)
        serialized_row = canonical_json(row)
        if pair.protected_pair_id in serialized_row or "protected_pair" in serialized_row:
            raise AnomalyGenerationError("protected pair key leaked into anomaly_instance")
        outcomes = outcome_by_id(pair.invalid_invariant_outcomes)
        if outcomes[pair.target_invariant_id].status != "fail":
            raise AnomalyGenerationError(f"{anomaly_id}: target invariant did not fail")
        failed_protected = [
            invariant_id
            for invariant_id in pair.preserved_invariant_ids
            if outcomes[invariant_id].status == "fail"
        ]
        if failed_protected:
            raise AnomalyGenerationError(
                f"{anomaly_id}: protected invariant failures {failed_protected}"
            )
        if pair.edit.cost > resolved.anomaly.search_bound:
            raise AnomalyGenerationError(f"{anomaly_id}: accepted edit exceeds search bound")
        if not pair.search_diagnostics.minimality_proven_within_bound:
            raise AnomalyGenerationError(f"{anomaly_id}: bounded grammar minimality not established")
        if not 0.0 < pair.selection_probability <= 1.0:
            raise AnomalyGenerationError(f"{anomaly_id}: invalid selection probability")
        if not math.isclose(pair.analysis_weight, 1.0 / pair.selection_probability):
            raise AnomalyGenerationError(f"{anomaly_id}: analysis weight is not inverse probability")
    for scenario_id, diagnostics in build.diagnostics.items():
        scenario_pairs = [
            pair for pair in build.counterfactual_pairs if pair.valid_trace.scenario_id == scenario_id
        ]
        if diagnostics.anomaly_count != len(scenario_pairs):
            raise AnomalyGenerationError(f"{scenario_id}: anomaly diagnostics do not reconcile")
        if diagnostics.target_violation_success_rate != 1.0:
            raise AnomalyGenerationError(f"{scenario_id}: target violation success is not 1.0")
        if diagnostics.protected_collateral_violation_rate != 0.0:
            raise AnomalyGenerationError(f"{scenario_id}: protected collateral violation rate is nonzero")


def _acceptance(
    outcomes: Sequence[InvariantOutcome],
    *,
    target_invariant_id: str,
    protected_ids: Sequence[str],
) -> tuple[bool, str]:
    indexed = outcome_by_id(outcomes)
    if indexed[target_invariant_id].status != "fail":
        return False, "target_not_failed"
    schema_or_physical = {
        "INV-SCHEMA-CONFORMANT",
        "INV-PHYSICAL-CONTEXT-UNCHANGED",
    }
    if any(indexed[item].status == "fail" for item in schema_or_physical):
        return False, "schema_or_physical"
    if any(indexed[item].status == "fail" for item in protected_ids):
        return False, "protected_failure"
    return True, "accepted"


def _source_is_eligible(
    outcomes: Sequence[InvariantOutcome],
    target_invariant_id: str,
    protected_ids: Sequence[str],
) -> bool:
    indexed = outcome_by_id(outcomes)
    return indexed[target_invariant_id].status == "pass" and all(
        indexed[item].status != "fail" for item in protected_ids
    )


def _protected_ids(ctx: _EngineContext, rule: EditGrammarRule) -> tuple[str, ...]:
    return tuple(sorted(set(rule.protected_invariant_ids) | set(ctx.resolved.anomaly.protected_invariant_ids)))


def _configured_target_count(workflow_count: int, prevalence: float) -> int:
    if prevalence <= 0.0:
        return 0
    return max(1, int(math.floor(workflow_count * prevalence + 0.5)))


def _edit(
    operation: str,
    rule: EditGrammarRule,
    parameters: tuple[tuple[str, str], ...],
    primitive_paths: tuple[str, ...],
    derived_paths: tuple[str, ...],
) -> CounterfactualEdit:
    return CounterfactualEdit(
        operation=operation,
        cost=rule.primitive_edit_cost,
        primitive_changed_field_paths=tuple(sorted(primitive_paths)),
        derived_changed_field_paths=tuple(sorted(derived_paths)),
        parameters=tuple(sorted(parameters)),
    )


def _edit_identity(edit: CounterfactualEdit) -> str:
    return canonical_json({
        "cost": edit.cost,
        "operation": edit.operation,
        "parameters": list(edit.parameters),
    })


def _graph_truth(
    events: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> tuple[Mapping[str, tuple[str, ...]], Mapping[str, str], Mapping[str, int]]:
    event_ids = {str(row["event_id"]) for row in events}
    parents: dict[str, set[str]] = {event_id: set() for event_id in event_ids}
    children: dict[str, set[str]] = {event_id: set() for event_id in event_ids}
    for row in edges:
        source = str(row["source_event_id"])
        target = str(row["target_event_id"])
        if source not in event_ids or target not in event_ids:
            raise AnomalyGenerationError(f"edge {row['edge_id']}: endpoint outside episode")
        parents[target].add(source)
        children[source].add(target)
    indegree = {event_id: len(values) for event_id, values in parents.items()}
    queue = sorted(event_id for event_id, count in indegree.items() if count == 0)
    order: list[str] = []
    while queue:
        current = queue.pop(0)
        order.append(current)
        for child in sorted(children[current]):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
                queue.sort()
    if len(order) != len(event_ids):
        raise AnomalyGenerationError("cannot recompute graph truth for cyclic episode")
    ancestors: dict[str, set[str]] = {event_id: set() for event_id in event_ids}
    depths: dict[str, int] = {event_id: 0 for event_id in event_ids}
    roots: dict[str, str] = {}
    for event_id in order:
        if not parents[event_id]:
            roots[event_id] = event_id
            continue
        for parent in parents[event_id]:
            ancestors[event_id].add(parent)
            ancestors[event_id].update(ancestors[parent])
        depths[event_id] = 1 + max(depths[parent] for parent in parents[event_id])
        root_candidates = {roots[parent] for parent in parents[event_id]}
        roots[event_id] = sorted(root_candidates)[0]
    return (
        {key: tuple(sorted(value)) for key, value in sorted(ancestors.items())},
        dict(sorted(roots.items())),
        dict(sorted(depths.items())),
    )


def _stream_identity(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
) -> tuple[str, CounterRng]:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        config_sha256=resolved.config_sha256,
    )
    suffix = f"component={ANOMALY_COMPONENT}|partition=global"
    for row in seed_stream_records_for_plan(resolved, plan, contract=contract):
        if str(row["stream_name"]).endswith(suffix):
            return (
                str(row["deterministic_id_namespace"]),
                CounterRng(str(row["seed_material_hex"])),
            )
    raise AnomalyGenerationError(f"{scenario_id}: missing {ANOMALY_COMPONENT} seed stream")


def _engine_context(
    *,
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
    world: FederatedWorld,
    catalog: CatalogBuild,
    physical: PhysicalRawBuild,
    workflows: WorkflowBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    registry: InvariantRegistry,
    grammar: EditGrammar,
    checker: IndependentInvariantChecker,
    evaluator: SafePolicyEvaluator,
) -> _EngineContext:
    namespace, rng = _stream_identity(resolved, scenario_id, replicate_id, contract)
    return _EngineContext(
        resolved=resolved,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        namespace=namespace,
        rng=rng,
        contract=contract,
        world=world,
        catalog=catalog,
        physical=physical,
        workflows=workflows,
        causal_dag=causal_dag,
        policy=policy,
        obligations=obligations,
        receipts=receipts,
        registry=registry,
        grammar=grammar,
        checker=checker,
        evaluator=evaluator,
        physical_digest=_physical_digest(physical, scenario_id),
    )


def _physical_digest(physical: PhysicalRawBuild, scenario_id: str) -> str:
    table_digests = {
        name: canonical_records_digest(
            row for row in rows if str(row["scenario_id"]) == scenario_id
        )
        for name, rows in physical.table_records().items()
    }
    return hashlib.sha256(canonical_json(table_digests).encode("utf-8")).hexdigest()


def _active_at(actor: Mapping[str, Any], timestamp: str) -> bool:
    value = _timestamp(timestamp)
    if value < _timestamp(str(actor["valid_from"])):
        return False
    return actor["valid_to"] is None or value <= _timestamp(str(actor["valid_to"]))


def _row_by(rows: Sequence[dict[str, Any]], field: str, value: str) -> dict[str, Any]:
    matches = [row for row in rows if str(row[field]) == value]
    if len(matches) != 1:
        raise AnomalyGenerationError(
            f"expected exactly one row with {field}={value!r}; found {len(matches)}"
        )
    return matches[0]


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AnomalyGenerationError(f"timestamp is not timezone-aware: {value!r}")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
