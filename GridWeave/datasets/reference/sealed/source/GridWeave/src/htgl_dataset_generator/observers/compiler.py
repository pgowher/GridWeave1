"""S11 observer projection compiler over frozen world, policy, and evidence truth."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.anomalies import AnomalyBuild
from htgl_dataset_generator.catalog import CatalogBuild
from htgl_dataset_generator.config import ResolvedConfig, ResolvedRunPlan
from htgl_dataset_generator.dag import CausalDagBuild
from htgl_dataset_generator.evidence import EvidenceObligationBuild, EvidenceReceiptBuild
from htgl_dataset_generator.policy import PolicyOracleBuild
from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import (
    CounterRng,
    canonical_records_digest,
    deterministic_uuid,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.world import FederatedWorld

from .language import normalize_visibility_facts
from .leakage import scan_observer_releases
from .models import (
    ObserverBuild,
    ObserverProfileDiagnostics,
    ObserverReleaseView,
    ObserverTaskResult,
    OmissionOracleDiagnostics,
    OmissionOracleTruth,
    ProjectionSourceMapping,
)
from .oracle import expected_projection, projection_digest_payload
from .projection import compile_projection
from .profiles import ObserverProfile, ObserverProfileBundle, load_observer_profile_bundle


OBSERVER_COMPONENT = "S11.projections"
FULL_PROFILE_ID = "OBS-FULL-EVALUATOR"


class ObserverProjectionError(ValueError):
    """Raised when projection, leakage, omission, or task gates fail closed."""


@dataclass(frozen=True)
class _ProjectionContext:
    resolved: ResolvedConfig
    scenario_id: str
    replicate_id: int
    namespace: str
    rng: CounterRng
    contract: ContractSpec
    bundle: ObserverProfileBundle
    world: FederatedWorld
    catalog: CatalogBuild
    dag: CausalDagBuild
    policy: PolicyOracleBuild
    obligations: EvidenceObligationBuild
    receipts: EvidenceReceiptBuild
    anomalies: AnomalyBuild
    actors: Mapping[str, Mapping[str, Any]]
    events: Mapping[str, Mapping[str, Any]]
    workflows: Mapping[str, Mapping[str, Any]]
    databases: Mapping[str, Mapping[str, Any]]
    objects: Mapping[str, Mapping[str, Any]]
    decisions: Mapping[str, Mapping[str, Any]]
    obligations_by_event: Mapping[str, tuple[Mapping[str, Any], ...]]
    receipts_by_event: Mapping[str, tuple[Mapping[str, Any], ...]]
    receipts_by_obligation: Mapping[str, tuple[Mapping[str, Any], ...]]
    independently_valid_receipt_ids: frozenset[str]
    incoming_edges: Mapping[str, tuple[Mapping[str, Any], ...]]
    anomaly_ids_by_workflow: Mapping[str, tuple[str, ...]]
    pair_ids_by_workflow: Mapping[str, tuple[str, ...]]
    frozen_truth_digest: str


def build_observer_projections(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    anomalies: AnomalyBuild,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    profile_bundle_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> ObserverBuild:
    """Compile canonical projection truth and sanitized release views."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids or resolved.run.selected_scenario_ids))
    if not selected:
        raise ObserverProjectionError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise ObserverProjectionError(f"scenario_ids not selected in config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise ObserverProjectionError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    bundle = load_observer_profile_bundle(
        resolved, profile_bundle_path, contract=schema_contract
    )
    all_rows: list[dict[str, Any]] = []
    all_mappings: list[ProjectionSourceMapping] = []
    all_views: dict[str, ObserverReleaseView] = {}
    all_truth: list[OmissionOracleTruth] = []
    all_tasks: list[ObserverTaskResult] = []
    all_diagnostics: dict[str, ObserverProfileDiagnostics] = {}
    all_metrics: list[dict[str, Any]] = []
    oracle_counts = defaultdict(int)
    frozen_digests: dict[str, str] = {}

    for scenario_id in selected:
        ctx = _context(
            resolved=resolved,
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            contract=schema_contract,
            bundle=bundle,
            world=world,
            catalog=catalog,
            causal_dag=causal_dag,
            policy=policy,
            obligations=obligations,
            receipts=receipts,
            anomalies=anomalies,
        )
        rows, mappings, views, actor_by_profile = _compile_scenario(ctx)
        leakage = _scan_leakage(ctx, views)
        if not leakage.passed:
            first = leakage.findings[0]
            raise ObserverProjectionError(
                f"{scenario_id}: observer non-leakage gate failed profile={first.profile_id} "
                f"record={first.observer_record_id} type={first.finding_type} path={first.path}"
            )
        truth, omission_diagnostics = _verify_omission_oracle(
            ctx, rows, mappings, actor_by_profile
        )
        if not omission_diagnostics.passed:
            raise ObserverProjectionError(
                f"{scenario_id}: omission oracle mismatch {omission_diagnostics}"
            )
        diagnostics = _profile_diagnostics(
            ctx, mappings, rows, leakage, actor_by_profile
        )
        tasks = _task_results(ctx, diagnostics)
        failed_tasks = [item for item in tasks if item.status == "fail"]
        if failed_tasks:
            item = failed_tasks[0]
            raise ObserverProjectionError(
                f"{scenario_id}: required observer task failed task={item.task_id} "
                f"profile={item.profile_id} value={item.value:.6f} "
                f"threshold={item.required_threshold:.6f}"
            )
        diagnostics = _attach_task_rates(diagnostics, tasks)
        metrics = _run_metrics(ctx, diagnostics)
        if _frozen_truth_digest(ctx) != ctx.frozen_truth_digest:
            raise ObserverProjectionError(
                f"{scenario_id}: frozen world/policy/evidence/anomaly truth mutated during projection"
            )
        all_rows.extend(rows)
        all_mappings.extend(mappings)
        all_truth.extend(truth)
        all_tasks.extend(tasks)
        all_metrics.extend(metrics)
        for profile_id, view in views.items():
            key = f"{scenario_id}:{profile_id}" if len(selected) > 1 else profile_id
            all_views[key] = view
        for profile_id, item in diagnostics.items():
            key = f"{scenario_id}:{profile_id}" if len(selected) > 1 else profile_id
            all_diagnostics[key] = item
        oracle_counts["evaluated"] += omission_diagnostics.evaluated_record_count
        oracle_counts["visibility"] += omission_diagnostics.visibility_mismatch_count
        oracle_counts["reason"] += omission_diagnostics.omission_reason_mismatch_count
        oracle_counts["timestamp"] += omission_diagnostics.timestamp_mismatch_count
        oracle_counts["digest"] += omission_diagnostics.projection_digest_mismatch_count
        frozen_digests[scenario_id] = ctx.frozen_truth_digest

    combined_leakage = _combined_leakage(all_views, bundle, world, catalog, causal_dag, policy, obligations, receipts, anomalies)
    build = ObserverBuild(
        observer_events=tuple(sorted(all_rows, key=lambda row: str(row["observer_record_id"]))),
        source_mappings=tuple(sorted(all_mappings, key=lambda item: item.observer_record_id)),
        release_views=dict(sorted(all_views.items())),
        omission_truth=tuple(sorted(all_truth, key=lambda item: item.observer_record_id)),
        omission_diagnostics=OmissionOracleDiagnostics(
            evaluated_record_count=oracle_counts["evaluated"],
            visibility_mismatch_count=oracle_counts["visibility"],
            omission_reason_mismatch_count=oracle_counts["reason"],
            timestamp_mismatch_count=oracle_counts["timestamp"],
            projection_digest_mismatch_count=oracle_counts["digest"],
        ),
        leakage_diagnostics=combined_leakage,
        task_results=tuple(
            sorted(
                all_tasks,
                key=lambda item: (
                    item.scenario_id,
                    item.replicate_id,
                    item.profile_id,
                    item.task_id,
                ),
            )
        ),
        diagnostics=dict(sorted(all_diagnostics.items())),
        run_metrics=tuple(sorted(all_metrics, key=lambda row: str(row["metric_id"]))),
        profile_bundle_sha256=bundle.bundle_sha256,
        frozen_truth_digest=hashlib.sha256(canonical_json(frozen_digests).encode("utf-8")).hexdigest(),
    )
    validate_observer_build(
        build,
        resolved,
        world=world,
        causal_dag=causal_dag,
        bundle=bundle,
        scenario_ids=selected,
        contract=schema_contract,
    )
    return build


def _context(
    *,
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
    bundle: ObserverProfileBundle,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    anomalies: AnomalyBuild,
) -> _ProjectionContext:
    namespace, rng = _stream_identity(resolved, scenario_id, replicate_id, contract)
    actors = _unique_index(
        (row for row in world.actors if str(row["scenario_id"]) == scenario_id),
        "actor_id",
        f"{scenario_id} actors",
    )
    events = _unique_index(
        (row for row in causal_dag.governance_events if str(row["scenario_id"]) == scenario_id),
        "event_id",
        f"{scenario_id} events",
    )
    workflows = _unique_index(
        (row for row in causal_dag.workflow_instances if str(row["scenario_id"]) == scenario_id),
        "workflow_instance_id",
        f"{scenario_id} workflows",
    )
    databases = _unique_index(
        (row for row in catalog.local_databases if str(row["scenario_id"]) == scenario_id),
        "database_id",
        f"{scenario_id} databases",
    )
    objects = _unique_index(
        (row for row in catalog.data_objects if str(row["scenario_id"]) == scenario_id),
        "data_object_id",
        f"{scenario_id} objects",
    )
    decisions = _unique_index(
        (row for row in policy.policy_decisions if str(row["event_id"]) in events),
        "event_id",
        f"{scenario_id} policy decisions",
    )
    obligations_by_event = _group(
        (row for row in obligations.evidence_obligations if str(row["event_id"]) in events),
        "event_id",
        "obligation_id",
    )
    receipt_rows = tuple(
        row for row in receipts.evidence_receipts if str(row["event_id"]) in events
    )
    receipts_by_event = _group(receipt_rows, "event_id", "receipt_id")
    receipts_by_obligation = _group(receipt_rows, "obligation_id", "receipt_id")
    independently_valid = frozenset(
        item.receipt_id
        for item in receipts.verification.truth
        if item.expected_status == "valid"
    )
    incoming = _group(
        (
            row
            for row in causal_dag.event_edges
            if str(row["source_event_id"]) in events
            and str(row["target_event_id"]) in events
        ),
        "target_event_id",
        "edge_id",
    )
    anomaly_ids: dict[str, list[str]] = defaultdict(list)
    for row in anomalies.anomaly_instances:
        if str(row["scenario_id"]) == scenario_id and row["valid_counterfactual_workflow_id"]:
            anomaly_ids[str(row["valid_counterfactual_workflow_id"])].append(
                str(row["anomaly_instance_id"])
            )
    pair_ids: dict[str, list[str]] = defaultdict(list)
    for pair in anomalies.counterfactual_pairs:
        if pair.valid_trace.scenario_id == scenario_id:
            pair_ids[pair.valid_trace.workflow_id].append(pair.protected_pair_id)
    context = _ProjectionContext(
        resolved=resolved,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        namespace=namespace,
        rng=rng,
        contract=contract,
        bundle=bundle,
        world=world,
        catalog=catalog,
        dag=causal_dag,
        policy=policy,
        obligations=obligations,
        receipts=receipts,
        anomalies=anomalies,
        actors=actors,
        events=events,
        workflows=workflows,
        databases=databases,
        objects=objects,
        decisions=decisions,
        obligations_by_event=obligations_by_event,
        receipts_by_event=receipts_by_event,
        receipts_by_obligation=receipts_by_obligation,
        independently_valid_receipt_ids=independently_valid,
        incoming_edges=incoming,
        anomaly_ids_by_workflow={key: tuple(sorted(value)) for key, value in anomaly_ids.items()},
        pair_ids_by_workflow={key: tuple(sorted(value)) for key, value in pair_ids.items()},
        frozen_truth_digest="",
    )
    return replace(context, frozen_truth_digest=_frozen_truth_digest(context))


def _compile_scenario(
    ctx: _ProjectionContext,
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[ProjectionSourceMapping, ...],
    Mapping[str, ObserverReleaseView],
    Mapping[str, Mapping[str, Any]],
]:
    rows_by_profile_event: dict[tuple[str, str], dict[str, Any]] = {}
    mappings_by_profile_event: dict[tuple[str, str], ProjectionSourceMapping] = {}
    actor_by_profile = {
        profile.profile_id: _select_observer_actor(ctx, profile)
        for profile in ctx.bundle.profiles
    }
    for profile in ctx.bundle.profiles:
        if profile.mode == "collusion":
            continue
        observer = actor_by_profile[profile.profile_id]
        for event_id, event in sorted(ctx.events.items()):
            facts = _visibility_facts(ctx, observer, event)
            expectation = compile_projection(
                profile,
                event_id=event_id,
                event_timestamp=str(event["timestamp"]),
                facts=facts,
                rng=ctx.rng,
                bundle=ctx.bundle,
            )
            row, mapping = _projection_row(
                ctx,
                profile=profile,
                observer=observer,
                event=event,
                expectation=expectation,
                allowed_fields=profile.allowed_payload_fields,
                collusion_member_record_ids=(),
            )
            rows_by_profile_event[(profile.profile_id, event_id)] = row
            mappings_by_profile_event[(profile.profile_id, event_id)] = mapping

    for profile in ctx.bundle.profiles:
        if profile.mode != "collusion":
            continue
        observer = actor_by_profile[profile.profile_id]
        member_profiles = tuple(ctx.bundle.profile(item) for item in profile.collusion_member_profile_ids)
        allowed_fields = tuple(sorted({field for item in member_profiles for field in item.allowed_payload_fields}))
        for event_id, event in sorted(ctx.events.items()):
            member_rows = tuple(rows_by_profile_event[(item.profile_id, event_id)] for item in member_profiles)
            member_mappings = tuple(mappings_by_profile_event[(item.profile_id, event_id)] for item in member_profiles)
            visible_members = tuple(
                (row, mapping)
                for row, mapping in zip(member_rows, member_mappings)
                if mapping.visible
            )
            if visible_members:
                selected_row, selected_mapping = min(
                    visible_members,
                    key=lambda item: (str(item[0]["visible_timestamp"]), item[1].observer_record_id),
                )
                expectation = _collusion_expectation(
                    event,
                    selected_row=selected_row,
                    selected_mapping=selected_mapping,
                    visible=True,
                )
            else:
                reason = _collusion_omission_reason(member_mappings)
                expectation = _collusion_expectation(
                    event,
                    selected_row=None,
                    selected_mapping=None,
                    visible=False,
                    omission_reason=reason,
                )
            row, mapping = _projection_row(
                ctx,
                profile=profile,
                observer=observer,
                event=event,
                expectation=expectation,
                allowed_fields=allowed_fields,
                collusion_member_record_ids=tuple(item.observer_record_id for item in member_mappings),
            )
            rows_by_profile_event[(profile.profile_id, event_id)] = row
            mappings_by_profile_event[(profile.profile_id, event_id)] = mapping

    views: dict[str, ObserverReleaseView] = {}
    for profile in ctx.bundle.profiles:
        profile_rows = tuple(
            rows_by_profile_event[(profile.profile_id, event_id)]
            for event_id in sorted(ctx.events)
        )
        profile_mappings = tuple(
            mappings_by_profile_event[(profile.profile_id, event_id)]
            for event_id in sorted(ctx.events)
        )
        released = tuple(
            _release_record(ctx, profile, row)
            for row, mapping in zip(profile_rows, profile_mappings)
            if mapping.visible
        )
        views[profile.profile_id] = ObserverReleaseView(
            profile_id=profile.profile_id,
            access_class=profile.release_access_class,
            schema_profile_id=profile.schema_profile_id,
            records=tuple(sorted(released, key=lambda row: str(row["observer_record_id"]))),
        )
    return (
        tuple(rows_by_profile_event.values()),
        tuple(mappings_by_profile_event.values()),
        dict(sorted(views.items())),
        actor_by_profile,
    )


def _projection_row(
    ctx: _ProjectionContext,
    *,
    profile: ObserverProfile,
    observer: Mapping[str, Any],
    event: Mapping[str, Any],
    expectation: Any,
    allowed_fields: Sequence[str],
    collusion_member_record_ids: tuple[str, ...],
) -> tuple[dict[str, Any], ProjectionSourceMapping]:
    event_id = str(event["event_id"])
    workflow_id = str(event["workflow_instance_id"])
    record_id = deterministic_uuid(
        ctx.namespace,
        "observer_record",
        {
            "event_id": event_id,
            "profile_id": profile.profile_id,
            "replicate_id": ctx.replicate_id,
            "scenario_id": ctx.scenario_id,
        },
    )
    payload = (
        _payload(ctx, profile.profile_id, event, allowed_fields)
        if expectation.final_visibility_class != "omitted"
        else {}
    )
    payload_json = canonical_json(payload)
    redacted_paths = tuple(ctx.bundle.redaction_profiles[profile.redaction_profile_id])
    row: dict[str, Any] = {
        "observer_record_id": record_id,
        "observer_actor_id": str(observer["actor_id"]),
        "source_event_id": event_id,
        "projection_profile_id": profile.profile_id,
        "visible_timestamp": expectation.visible_timestamp,
        "visibility_class": expectation.final_visibility_class,
        "omission_reason": expectation.omission_reason,
        "redacted_field_paths": list(redacted_paths),
        "schema_profile_id": profile.schema_profile_id,
        "payload_json": payload_json,
        "projection_digest": "",
        "ground_truth_access_class": "evaluator_only",
    }
    row["projection_digest"] = hashlib.sha256(
        canonical_json(projection_digest_payload(row)).encode("utf-8")
    ).hexdigest()
    validate_record(ctx.contract, "observer_event", row)
    event_receipts = tuple(ctx.receipts_by_event.get(event_id, ()))
    valid_receipts = tuple(
        sorted(
            str(item["receipt_id"])
            for item in event_receipts
            if str(item["receipt_id"]) in ctx.independently_valid_receipt_ids
        )
    )
    mapping = ProjectionSourceMapping(
        observer_record_id=record_id,
        observer_actor_id=str(observer["actor_id"]),
        projection_profile_id=profile.profile_id,
        source_event_id=event_id,
        source_workflow_id=workflow_id,
        base_visibility_class=expectation.base_visibility_class,
        final_visibility_class=expectation.final_visibility_class,
        omission_reason=expectation.omission_reason,
        delay_seconds=int(expectation.delay_seconds),
        clock_offset_seconds=int(expectation.clock_offset_seconds),
        source_obligation_ids=tuple(
            sorted(str(item["obligation_id"]) for item in ctx.obligations_by_event.get(event_id, ()))
        ),
        source_receipt_ids=tuple(sorted(str(item["receipt_id"]) for item in event_receipts)),
        independently_valid_receipt_ids=valid_receipts,
        source_anomaly_instance_ids=ctx.anomaly_ids_by_workflow.get(workflow_id, ()),
        protected_pair_ids=ctx.pair_ids_by_workflow.get(workflow_id, ()),
        collusion_member_record_ids=tuple(sorted(collusion_member_record_ids)),
        source_event_digest=hashlib.sha256(canonical_json(dict(event)).encode("utf-8")).hexdigest(),
    )
    return row, mapping


def _payload(
    ctx: _ProjectionContext,
    profile_id: str,
    event: Mapping[str, Any],
    allowed_fields: Sequence[str],
) -> Mapping[str, Any]:
    event_id = str(event["event_id"])
    workflow_id = str(event["workflow_instance_id"])
    actor_rows = tuple(
        ctx.actors[str(actor_id)]
        for actor_id in _event_actor_ids(event)
        if str(actor_id) in ctx.actors
    )
    evidence_rows = ctx.receipts_by_event.get(event_id, ())
    parent_ids = tuple(
        sorted({str(edge["source_event_id"]) for edge in ctx.incoming_edges.get(event_id, ())})
    )
    database = ctx.databases[str(event["local_database_id"])]
    data_object = ctx.objects[str(event["data_object_id"])]
    available: Mapping[str, Any] = {
        "actor_classes": sorted({str(item["actor_class"]) for item in actor_rows}),
        "causal_parent_refs": [_pseudonym(profile_id, "event", item) for item in parent_ids],
        "database_kind": database["database_kind"],
        "event_family": event["event_family"],
        "event_ref": _pseudonym(profile_id, "event", event_id),
        "event_type": event["event_type"],
        "evidence_present": bool(evidence_rows),
        "evidence_receipt_count": len(evidence_rows),
        "evidence_types": sorted({str(item["evidence_type"]) for item in evidence_rows}),
        "inferred_summary": f"{event['event_family']}:evidence={'present' if evidence_rows else 'absent'}",
        "object_type": data_object["object_type"],
        "policy_purpose_id": event["policy_purpose_id"],
        "workflow_ref": _pseudonym(profile_id, "workflow", workflow_id),
        "workflow_state_after": event["workflow_state_after"],
        "workflow_state_before": event["workflow_state_before"],
    }
    return {field: available[field] for field in sorted(allowed_fields)}


def _release_record(
    ctx: _ProjectionContext,
    profile: ObserverProfile,
    row: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "observer_record_id": row["observer_record_id"],
        "observer_ref": _pseudonym(profile.profile_id, "observer", str(row["observer_actor_id"])),
        "projection_profile_id": profile.profile_id,
        "visible_timestamp": row["visible_timestamp"],
        "visibility_class": row["visibility_class"],
        "redacted_field_paths": list(row["redacted_field_paths"]),
        "schema_profile_id": row["schema_profile_id"],
        "payload": json.loads(str(row["payload_json"])),
        "projection_digest": row["projection_digest"],
    }


def _visibility_facts(
    ctx: _ProjectionContext,
    observer: Mapping[str, Any],
    event: Mapping[str, Any],
) -> Mapping[str, Any]:
    event_id = str(event["event_id"])
    actor_ids = _event_actor_ids(event)
    relationships = _active_relationship_types(
        ctx,
        str(observer["actor_id"]),
        actor_ids,
        str(event["timestamp"]),
    )
    source_actor = ctx.actors[str(event["source_actor_id"])]
    database = ctx.databases[str(event["local_database_id"])]
    workflow = ctx.workflows[str(event["workflow_instance_id"])]
    decision = ctx.decisions[event_id]
    receipts = ctx.receipts_by_event.get(event_id, ())
    return normalize_visibility_facts(
        {
            "anomaly.workflow_member": bool(ctx.anomaly_ids_by_workflow.get(str(event["workflow_instance_id"]))),
            "event.actor_ids": actor_ids,
            "event.database_region": str(database["region_id"]),
            "event.family": str(event["event_family"]),
            "event.id": event_id,
            "event.source_region": str(source_actor["region_id"]),
            "event.type": str(event["event_type"]),
            "event.workflow_type": str(workflow["workflow_type"]),
            "evidence.has_obligation": bool(ctx.obligations_by_event.get(event_id)),
            "evidence.receipt_count": len(receipts),
            "evidence.types": tuple(sorted({str(item["evidence_type"]) for item in receipts})),
            "observer.class": str(observer["actor_class"]),
            "observer.id": str(observer["actor_id"]),
            "observer.jurisdiction": str(observer["jurisdiction_id"]),
            "observer.region": str(observer["region_id"]),
            "observer.relationship_types_to_event_actors": relationships,
            "policy.is_violation": bool(decision["is_violation"]),
        }
    )


def _profile_diagnostics(
    ctx: _ProjectionContext,
    mappings: Sequence[ProjectionSourceMapping],
    rows: Sequence[Mapping[str, Any]],
    leakage: Any,
    actor_by_profile: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, ObserverProfileDiagnostics]:
    row_by_id = {str(row["observer_record_id"]): row for row in rows}
    event_weights = {
        event_id: float(event["represented_event_count"])
        for event_id, event in ctx.events.items()
    }
    required_edges = tuple(
        row
        for row in ctx.dag.event_edges
        if str(row["source_event_id"]) in ctx.events
        and str(row["target_event_id"]) in ctx.events
        and bool(row["required_for_closure"])
    )
    diagnostics: dict[str, ObserverProfileDiagnostics] = {}
    for profile in ctx.bundle.profiles:
        scoped = tuple(item for item in mappings if item.projection_profile_id == profile.profile_id)
        visible = tuple(item for item in scoped if item.visible)
        visible_ids = {item.source_event_id for item in visible}
        total_weight = sum(event_weights.values())
        visible_weight = sum(event_weights[item] for item in visible_ids)
        edge_total = sum(
            min(event_weights[str(edge["source_event_id"])], event_weights[str(edge["target_event_id"])])
            for edge in required_edges
        )
        edge_visible = sum(
            min(event_weights[str(edge["source_event_id"])], event_weights[str(edge["target_event_id"])])
            for edge in required_edges
            if str(edge["source_event_id"]) in visible_ids
            and str(edge["target_event_id"]) in visible_ids
        )
        allowed = _effective_allowed_fields(ctx.bundle, profile)
        recoverable = 0
        obligation_rows = tuple(
            row
            for rows_for_event in ctx.obligations_by_event.values()
            for row in rows_for_event
        )
        if {"evidence_receipt_count", "evidence_types"} <= set(allowed):
            for obligation in obligation_rows:
                event_id = str(obligation["event_id"])
                if event_id not in visible_ids:
                    continue
                valid = tuple(
                    receipt
                    for receipt in ctx.receipts_by_obligation.get(str(obligation["obligation_id"]), ())
                    if str(receipt["receipt_id"]) in ctx.independently_valid_receipt_ids
                    and str(receipt["evidence_type"]) in set(obligation["required_evidence_types"])
                )
                if len(valid) >= int(obligation["minimum_count"]):
                    recoverable += 1
        anomaly_workflows = set(ctx.anomaly_ids_by_workflow)
        anomaly_events = tuple(
            event_id
            for event_id, event in ctx.events.items()
            if str(event["workflow_instance_id"]) in anomaly_workflows
        )
        anomaly_total_weight = sum(event_weights[item] for item in anomaly_events)
        anomaly_visible_weight = sum(event_weights[item] for item in anomaly_events if item in visible_ids)
        delays = sorted(
            max(0.0, (_timestamp(str(row_by_id[item.observer_record_id]["visible_timestamp"])) - _timestamp(str(ctx.events[item.source_event_id]["timestamp"]))).total_seconds())
            for item in visible
        )
        detection_times: list[float] = []
        for workflow_id in sorted(anomaly_workflows):
            workflow_events = tuple(
                event for event in ctx.events.values() if str(event["workflow_instance_id"]) == workflow_id
            )
            visible_times = [
                _timestamp(str(row_by_id[item.observer_record_id]["visible_timestamp"]))
                for item in visible
                if item.source_workflow_id == workflow_id
            ]
            if workflow_events and visible_times:
                detection_times.append(
                    max(0.0, (min(visible_times) - min(_timestamp(str(event["timestamp"])) for event in workflow_events)).total_seconds())
                )
        profile_findings = tuple(item for item in leakage.findings if item.profile_id == profile.profile_id)
        diagnostics[profile.profile_id] = ObserverProfileDiagnostics(
            scenario_id=ctx.scenario_id,
            replicate_id=ctx.replicate_id,
            profile_id=profile.profile_id,
            mode=profile.mode,
            observer_actor_id=str(actor_by_profile[profile.profile_id]["actor_id"]),
            source_event_count=len(scoped),
            visible_event_count=len(visible),
            omitted_event_count=len(scoped) - len(visible),
            weighted_visible_event_coverage=visible_weight / total_weight if total_weight else 0.0,
            visible_edge_coverage=edge_visible / edge_total if edge_total else 1.0,
            evidence_recoverability=recoverable / len(obligation_rows) if obligation_rows else 1.0,
            anomaly_event_recoverability=anomaly_visible_weight / anomaly_total_weight if anomaly_total_weight else 1.0,
            mean_delay_seconds=sum(delays) / len(delays) if delays else 0.0,
            p95_delay_seconds=_quantile(delays, 0.95),
            maximum_delay_seconds=max(delays, default=0.0),
            transport_loss_rate=sum(item.omission_reason == "transport_loss" for item in scoped) / len(scoped),
            adversarial_omission_rate=sum(item.omission_reason == "compromise" for item in scoped) / len(scoped),
            overall_omission_rate=(len(scoped) - len(visible)) / len(scoped),
            mean_time_to_detection_seconds=sum(detection_times) / len(detection_times) if detection_times else 0.0,
            projection_payload_bytes=sum(len(str(row_by_id[item.observer_record_id]["payload_json"]).encode("utf-8")) for item in visible),
            collusion_gain=0.0,
            sealed_truth_leakage_count=len(profile_findings),
            task_sufficiency_rate=1.0,
        )
    for collusion in ctx.bundle.collusion_profiles.values():
        output = diagnostics[collusion.output_profile_id]
        best_member = max(diagnostics[item].evidence_recoverability for item in collusion.member_profile_ids)
        diagnostics[collusion.output_profile_id] = replace(
            output,
            collusion_gain=output.evidence_recoverability - best_member,
        )
    return dict(sorted(diagnostics.items()))


def _task_results(
    ctx: _ProjectionContext,
    diagnostics: Mapping[str, ObserverProfileDiagnostics],
) -> tuple[ObserverTaskResult, ...]:
    results: list[ObserverTaskResult] = []
    has_anomalies = bool(ctx.anomaly_ids_by_workflow)
    for task in ctx.bundle.tasks:
        for profile_id, threshold in sorted(task.required_profile_thresholds.items()):
            value = float(getattr(diagnostics[profile_id], task.metric_name))
            if task.metric_name == "anomaly_event_recoverability" and not has_anomalies:
                status = "not_applicable"
                reason = "no materialized counterfactual anomaly workflow in this scenario"
            else:
                status = "pass" if value + 1e-12 >= threshold else "fail"
                reason = "configured task threshold satisfied" if status == "pass" else "configured task threshold not satisfied"
            results.append(
                ObserverTaskResult(
                    scenario_id=ctx.scenario_id,
                    replicate_id=ctx.replicate_id,
                    task_id=task.task_id,
                    profile_id=profile_id,
                    metric_name=task.metric_name,
                    value=value,
                    required_threshold=threshold,
                    status=status,
                    reason=reason,
                )
            )
    return tuple(results)


def _attach_task_rates(
    diagnostics: Mapping[str, ObserverProfileDiagnostics],
    tasks: Sequence[ObserverTaskResult],
) -> Mapping[str, ObserverProfileDiagnostics]:
    result = dict(diagnostics)
    for profile_id, item in diagnostics.items():
        scoped = tuple(task for task in tasks if task.profile_id == profile_id and task.status != "not_applicable")
        rate = sum(task.status == "pass" for task in scoped) / len(scoped) if scoped else 1.0
        result[profile_id] = replace(item, task_sufficiency_rate=rate)
    return dict(sorted(result.items()))


def _run_metrics(
    ctx: _ProjectionContext,
    diagnostics: Mapping[str, ObserverProfileDiagnostics],
) -> tuple[dict[str, Any], ...]:
    fields = (
        ("visible_event_coverage", "weighted_visible_event_coverage", "fraction"),
        ("visible_edge_coverage", "visible_edge_coverage", "fraction"),
        ("evidence_recoverability", "evidence_recoverability", "fraction"),
        ("anomaly_event_recoverability", "anomaly_event_recoverability", "fraction"),
        ("mean_delay_seconds", "mean_delay_seconds", "seconds"),
        ("p95_delay_seconds", "p95_delay_seconds", "seconds"),
        ("omission_rate", "overall_omission_rate", "fraction"),
        ("transport_loss_rate", "transport_loss_rate", "fraction"),
        ("adversarial_omission_rate", "adversarial_omission_rate", "fraction"),
        ("collusion_gain", "collusion_gain", "fraction"),
        ("projection_size_rows", "visible_event_count", "rows"),
        ("projection_payload_bytes", "projection_payload_bytes", "bytes"),
        ("mean_time_to_detection_seconds", "mean_time_to_detection_seconds", "seconds"),
        ("sealed_truth_leakage", "sealed_truth_leakage_count", "count"),
        ("task_sufficiency_rate", "task_sufficiency_rate", "fraction"),
    )
    rows: list[dict[str, Any]] = []
    for profile_id, diagnostic in sorted(diagnostics.items()):
        for metric_name, attribute, unit in fields:
            row = {
                "metric_id": deterministic_uuid(
                    ctx.namespace,
                    "run_metric",
                    {
                        "metric_name": metric_name,
                        "profile_id": profile_id,
                        "replicate_id": ctx.replicate_id,
                        "scenario_id": ctx.scenario_id,
                    },
                ),
                "run_id": ctx.resolved.run.run_id,
                "scenario_id": ctx.scenario_id,
                "replicate_id": ctx.replicate_id,
                "metric_domain": "observer",
                "metric_name": f"observer.{profile_id}.{metric_name}",
                "value": float(getattr(diagnostic, attribute)),
                "unit": unit,
                "standard_error": None,
                "ci_lower": None,
                "ci_upper": None,
                "estimator": "deterministic_frozen_truth_profile_measure_v1",
                "weighting": "analytic",
                "baseline_id": None if profile_id == FULL_PROFILE_ID else FULL_PROFILE_ID,
            }
            validate_record(ctx.contract, "run_metric", row)
            rows.append(row)
    return tuple(rows)


def _verify_omission_oracle(
    ctx: _ProjectionContext,
    rows: Sequence[Mapping[str, Any]],
    mappings: Sequence[ProjectionSourceMapping],
    actor_by_profile: Mapping[str, Mapping[str, Any]],
) -> tuple[tuple[OmissionOracleTruth, ...], OmissionOracleDiagnostics]:
    row_by_id = {str(row["observer_record_id"]): row for row in rows}
    mapping_by_key = {(item.projection_profile_id, item.source_event_id): item for item in mappings}
    truth: list[OmissionOracleTruth] = []
    counts = defaultdict(int)
    for mapping in sorted(mappings, key=lambda item: item.observer_record_id):
        profile = ctx.bundle.profile(mapping.projection_profile_id)
        event = ctx.events[mapping.source_event_id]
        row = row_by_id[mapping.observer_record_id]
        if profile.mode == "collusion":
            members = tuple(mapping_by_key[(item, mapping.source_event_id)] for item in profile.collusion_member_profile_ids)
            visible_members = tuple(item for item in members if item.visible)
            if visible_members:
                selected = min(
                    visible_members,
                    key=lambda item: (
                        str(row_by_id[item.observer_record_id]["visible_timestamp"]),
                        item.observer_record_id,
                    ),
                )
                expected_class = "shared"
                expected_reason = None
                expected_timestamp = str(row_by_id[selected.observer_record_id]["visible_timestamp"])
            else:
                expected_class = "omitted"
                expected_reason = _collusion_omission_reason(members)
                expected_timestamp = str(event["timestamp"])
        else:
            facts = _visibility_facts(ctx, actor_by_profile[profile.profile_id], event)
            expected = expected_projection(
                profile,
                event_id=mapping.source_event_id,
                event_timestamp=str(event["timestamp"]),
                facts=facts,
                rng=ctx.rng,
                bundle=ctx.bundle,
            )
            expected_class = expected.final_visibility_class
            expected_reason = expected.omission_reason
            expected_timestamp = expected.visible_timestamp
        visibility_match = str(row["visibility_class"]) == expected_class
        reason_match = row["omission_reason"] == expected_reason
        timestamp_match = str(row["visible_timestamp"]) == expected_timestamp
        expected_digest = hashlib.sha256(
            canonical_json(projection_digest_payload(row)).encode("utf-8")
        ).hexdigest()
        digest_match = str(row["projection_digest"]) == expected_digest
        counts["visibility"] += not visibility_match
        counts["reason"] += not reason_match
        counts["timestamp"] += not timestamp_match
        counts["digest"] += not digest_match
        truth.append(
            OmissionOracleTruth(
                observer_record_id=mapping.observer_record_id,
                projection_profile_id=profile.profile_id,
                source_event_id=mapping.source_event_id,
                expected_visibility_class=expected_class,
                observed_visibility_class=str(row["visibility_class"]),
                expected_omission_reason=expected_reason,
                observed_omission_reason=row["omission_reason"],
                expected_visible_timestamp=expected_timestamp,
                observed_visible_timestamp=str(row["visible_timestamp"]),
                matches=visibility_match and reason_match and timestamp_match and digest_match,
            )
        )
    return tuple(truth), OmissionOracleDiagnostics(
        evaluated_record_count=len(truth),
        visibility_mismatch_count=counts["visibility"],
        omission_reason_mismatch_count=counts["reason"],
        timestamp_mismatch_count=counts["timestamp"],
        projection_digest_mismatch_count=counts["digest"],
    )


def validate_observer_build(
    build: ObserverBuild,
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    causal_dag: CausalDagBuild,
    bundle: ObserverProfileBundle,
    scenario_ids: Iterable[str],
    contract: ContractSpec | None = None,
) -> None:
    """Fail closed on schema, mapping, leakage, oracle, task, and collusion gates."""

    schema_contract = contract if contract is not None else load_contract()
    if build.profile_bundle_sha256 != resolved.observer.profile_bundle_sha256:
        raise ObserverProjectionError("observer profile bundle digest mismatch")
    row_by_id: dict[str, Mapping[str, Any]] = {}
    for row in build.observer_events:
        validate_record(schema_contract, "observer_event", row)
        record_id = str(row["observer_record_id"])
        if record_id in row_by_id:
            raise ObserverProjectionError(f"duplicate observer_record_id={record_id}")
        if canonical_json(json.loads(str(row["payload_json"]))) != str(row["payload_json"]):
            raise ObserverProjectionError(f"{record_id}: payload_json is not canonical")
        expected_digest = hashlib.sha256(
            canonical_json(projection_digest_payload(row)).encode("utf-8")
        ).hexdigest()
        if str(row["projection_digest"]) != expected_digest:
            raise ObserverProjectionError(
                f"{record_id}: projection digest does not bind the emitted projection"
            )
        row_by_id[record_id] = row
    mapping_by_id = {item.observer_record_id: item for item in build.source_mappings}
    if len(mapping_by_id) != len(build.source_mappings) or set(mapping_by_id) != set(row_by_id):
        raise ObserverProjectionError("observer rows and evaluator-only source mappings do not reconcile")
    released_ids: set[str] = set()
    for view_key, view in build.release_views.items():
        for record in view.records:
            record_id = str(record.get("observer_record_id", ""))
            if record_id in released_ids:
                raise ObserverProjectionError(
                    f"observer release record {record_id} occurs in multiple views"
                )
            released_ids.add(record_id)
            mapping = mapping_by_id.get(record_id)
            source_row = row_by_id.get(record_id)
            if mapping is None or source_row is None or not mapping.visible:
                raise ObserverProjectionError(
                    f"release view={view_key} contains an omitted or unresolved projection {record_id}"
                )
            if mapping.projection_profile_id != view.profile_id:
                raise ObserverProjectionError(
                    f"release view={view_key} profile does not match projection {record_id}"
                )
            if str(record.get("projection_digest")) != str(source_row["projection_digest"]):
                raise ObserverProjectionError(
                    f"release view={view_key} projection digest mismatch for {record_id}"
                )
    expected_released_ids = {
        item.observer_record_id for item in build.source_mappings if item.visible
    }
    if released_ids != expected_released_ids:
        missing = sorted(expected_released_ids - released_ids)
        extra = sorted(released_ids - expected_released_ids)
        raise ObserverProjectionError(
            "release views do not reconcile with visible projections "
            f"missing={missing[:3]} extra={extra[:3]}"
        )
    selected = set(scenario_ids)
    event_ids = {
        str(row["event_id"])
        for row in causal_dag.governance_events
        if str(row["scenario_id"]) in selected
    }
    expected_count = len(event_ids) * len(bundle.profiles)
    if len(build.observer_events) != expected_count:
        raise ObserverProjectionError(
            f"observer row count={len(build.observer_events)} expected={expected_count}"
        )
    actor_ids = {str(row["actor_id"]) for row in world.actors}
    for mapping in build.source_mappings:
        if mapping.source_event_id not in event_ids:
            raise ObserverProjectionError(f"mapping {mapping.observer_record_id}: source event does not resolve")
        if mapping.observer_actor_id not in actor_ids:
            raise ObserverProjectionError(f"mapping {mapping.observer_record_id}: observer actor does not resolve")
        row = row_by_id[mapping.observer_record_id]
        if str(row["source_event_id"]) != mapping.source_event_id:
            raise ObserverProjectionError(
                f"mapping {mapping.observer_record_id}: source event disagrees with canonical projection"
            )
        if str(row["observer_actor_id"]) != mapping.observer_actor_id:
            raise ObserverProjectionError(
                f"mapping {mapping.observer_record_id}: observer actor disagrees with canonical projection"
            )
    if not build.leakage_diagnostics.passed:
        raise ObserverProjectionError("sealed truth leakage count is nonzero")
    if not build.omission_diagnostics.passed or not all(item.matches for item in build.omission_truth):
        raise ObserverProjectionError("omission oracle recomputation failed")
    if any(item.status == "fail" for item in build.task_results):
        raise ObserverProjectionError("required observer task sufficiency gate failed")
    for row in build.run_metrics:
        validate_record(schema_contract, "run_metric", row)
        if str(row["metric_domain"]) != "observer":
            raise ObserverProjectionError("observer build emitted non-observer metric")
    full = tuple(item for item in build.source_mappings if item.projection_profile_id == FULL_PROFILE_ID)
    if not full or not all(item.visible for item in full):
        raise ObserverProjectionError("full evaluator profile must cover every source event")
    for collusion in bundle.collusion_profiles.values():
        output = {item.source_event_id for item in build.source_mappings if item.projection_profile_id == collusion.output_profile_id and item.visible}
        member_union = {
            item.source_event_id
            for item in build.source_mappings
            if item.projection_profile_id in collusion.member_profile_ids and item.visible
        }
        if output != member_union:
            raise ObserverProjectionError(f"{collusion.output_profile_id}: collusion view is not exact member union")
        collusion_diagnostics = tuple(
            item
            for key, item in build.diagnostics.items()
            if key.endswith(collusion.output_profile_id)
        )
        if not collusion_diagnostics or any(
            item.collusion_gain < -1e-12 for item in collusion_diagnostics
        ):
            raise ObserverProjectionError(
                f"{collusion.output_profile_id}: collusion gain is missing or negative"
            )


def _scan_leakage(
    ctx: _ProjectionContext,
    views: Mapping[str, ObserverReleaseView],
):
    return scan_observer_releases(
        views,
        bundle=ctx.bundle,
        exact_protected_identifiers=_protected_identifiers(
            ctx.world, ctx.catalog, ctx.dag, ctx.policy, ctx.obligations, ctx.receipts
        ),
        pair_identifiers=(
            pair.protected_pair_id for pair in ctx.anomalies.counterfactual_pairs
        ),
        sealed_truth_values=_sealed_truth_values(ctx.policy, ctx.anomalies),
    )


def _combined_leakage(
    views: Mapping[str, ObserverReleaseView],
    bundle: ObserverProfileBundle,
    world: FederatedWorld,
    catalog: CatalogBuild,
    dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
    anomalies: AnomalyBuild,
):
    return scan_observer_releases(
        views,
        bundle=bundle,
        exact_protected_identifiers=_protected_identifiers(world, catalog, dag, policy, obligations, receipts),
        pair_identifiers=(pair.protected_pair_id for pair in anomalies.counterfactual_pairs),
        sealed_truth_values=_sealed_truth_values(policy, anomalies),
    )


def _protected_identifiers(
    world: FederatedWorld,
    catalog: CatalogBuild,
    dag: CausalDagBuild,
    policy: PolicyOracleBuild,
    obligations: EvidenceObligationBuild,
    receipts: EvidenceReceiptBuild,
) -> tuple[str, ...]:
    values: set[str] = set()
    fields_and_rows = (
        ("actor_id", world.actors),
        ("workflow_instance_id", dag.workflow_instances),
        ("event_id", dag.governance_events),
        ("database_id", catalog.local_databases),
        ("data_object_id", catalog.data_objects),
        ("replica_id", catalog.data_object_replicas),
        ("decision_id", policy.policy_decisions),
        ("obligation_id", obligations.evidence_obligations),
        ("receipt_id", receipts.evidence_receipts),
    )
    for field, rows in fields_and_rows:
        values.update(str(row[field]) for row in rows)
    return tuple(sorted(values))


def _sealed_truth_values(policy: PolicyOracleBuild, anomalies: AnomalyBuild) -> tuple[str, ...]:
    values = {
        str(row["violation_type"])
        for row in policy.policy_decisions
        if str(row["violation_type"]) != "none"
    }
    values.update(str(row["target_invariant_id"]) for row in anomalies.anomaly_instances)
    values.update(str(row["anomaly_instance_id"]) for row in anomalies.anomaly_instances)
    return tuple(sorted(values))


def _frozen_truth_digest(ctx: _ProjectionContext) -> str:
    tables = {
        "actor": tuple(row for row in ctx.world.actors if str(row["scenario_id"]) == ctx.scenario_id),
        "actor_relationship": tuple(row for row in ctx.world.actor_relationships if str(row["scenario_id"]) == ctx.scenario_id),
        "local_database": tuple(ctx.databases.values()),
        "data_object": tuple(ctx.objects.values()),
        "governance_event": tuple(ctx.events.values()),
        "event_edge": tuple(row for row in ctx.dag.event_edges if str(row["scenario_id"]) == ctx.scenario_id),
        "workflow_instance": tuple(ctx.workflows.values()),
        "policy_decision_truth": tuple(ctx.decisions.values()),
        "evidence_obligation": tuple(row for rows in ctx.obligations_by_event.values() for row in rows),
        "evidence_receipt": tuple(row for rows in ctx.receipts_by_event.values() for row in rows),
        "anomaly_instance": tuple(row for row in ctx.anomalies.anomaly_instances if str(row["scenario_id"]) == ctx.scenario_id),
    }
    digests = {name: canonical_records_digest(rows) for name, rows in tables.items()}
    digests["protected_pairs"] = hashlib.sha256(
        canonical_json(
            sorted(
                pair.protected_pair_id
                for pair in ctx.anomalies.counterfactual_pairs
                if pair.valid_trace.scenario_id == ctx.scenario_id
            )
        ).encode("utf-8")
    ).hexdigest()
    return hashlib.sha256(canonical_json(digests).encode("utf-8")).hexdigest()


def _stream_identity(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    contract: ContractSpec,
) -> tuple[str, CounterRng]:
    plan = ResolvedRunPlan(resolved.run.run_id, scenario_id, replicate_id, resolved.config_sha256)
    suffix = f"component={OBSERVER_COMPONENT}|partition=global"
    for row in seed_stream_records_for_plan(resolved, plan, contract=contract):
        if str(row["stream_name"]).endswith(suffix):
            return str(row["deterministic_id_namespace"]), CounterRng(str(row["seed_material_hex"]))
    raise ObserverProjectionError(f"{scenario_id}: missing {OBSERVER_COMPONENT} seed stream")


def _select_observer_actor(
    ctx: _ProjectionContext,
    profile: ObserverProfile,
) -> Mapping[str, Any]:
    candidates = tuple(
        row for row in ctx.actors.values() if str(row["actor_class"]) == profile.observer_actor_class
    )
    if not candidates:
        raise ObserverProjectionError(
            f"{ctx.scenario_id}: profile={profile.profile_id} requires actor_class={profile.observer_actor_class}"
        )
    return min(
        candidates,
        key=lambda row: (
            ctx.rng.uint64(f"observer-actor:{profile.profile_id}:{row['actor_id']}", 0),
            str(row["actor_id"]),
        ),
    )


def _active_relationship_types(
    ctx: _ProjectionContext,
    observer_id: str,
    event_actor_ids: Sequence[str],
    timestamp: str,
) -> tuple[str, ...]:
    time = _timestamp(timestamp)
    event_actors = set(event_actor_ids)
    values: set[str] = set()
    for row in ctx.world.actor_relationships:
        if str(row["scenario_id"]) != ctx.scenario_id:
            continue
        source = str(row["source_actor_id"])
        target = str(row["target_actor_id"])
        if not ((source == observer_id and target in event_actors) or (target == observer_id and source in event_actors)):
            continue
        if time < _timestamp(str(row["valid_from"])):
            continue
        if row["valid_to"] is not None and time > _timestamp(str(row["valid_to"])):
            continue
        values.add(str(row["relationship_type"]))
    return tuple(sorted(values))


def _event_actor_ids(event: Mapping[str, Any]) -> tuple[str, ...]:
    fields = (
        "source_actor_id", "requesting_actor_id", "controller_actor_id",
        "processor_actor_id", "oversight_actor_id",
    )
    return tuple(sorted({str(event[field]) for field in fields if event[field] is not None}))


def _collusion_expectation(
    event: Mapping[str, Any],
    *,
    selected_row: Mapping[str, Any] | None,
    selected_mapping: ProjectionSourceMapping | None,
    visible: bool,
    omission_reason: str | None = None,
):
    from .oracle import ProjectionExpectation

    if visible and selected_row is not None and selected_mapping is not None:
        delay = max(0, int((_timestamp(str(selected_row["visible_timestamp"])) - _timestamp(str(event["timestamp"]))).total_seconds()))
        return ProjectionExpectation("shared", "shared", None, delay, 0, str(selected_row["visible_timestamp"]))
    return ProjectionExpectation("omitted", "omitted", omission_reason or "out_of_scope", 0, 0, str(event["timestamp"]))


def _collusion_omission_reason(mappings: Sequence[ProjectionSourceMapping]) -> str:
    reasons = {item.omission_reason for item in mappings}
    for candidate in ("compromise", "transport_loss", "policy", "out_of_scope", "redaction", "sampling"):
        if candidate in reasons:
            return candidate
    return "out_of_scope"


def _effective_allowed_fields(
    bundle: ObserverProfileBundle, profile: ObserverProfile
) -> tuple[str, ...]:
    if profile.mode != "collusion":
        return profile.allowed_payload_fields
    return tuple(sorted({field for member in profile.collusion_member_profile_ids for field in bundle.profile(member).allowed_payload_fields}))


def _pseudonym(profile_id: str, kind: str, value: str) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "domain": "htgl.observer.release-pseudonym.v1",
                "kind": kind,
                "profile_id": profile_id,
                "value": value,
            }
        ).encode("utf-8")
    ).hexdigest()


def _group(
    rows: Iterable[Mapping[str, Any]],
    key_field: str,
    sort_field: str,
) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
    result: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        result[str(row[key_field])].append(row)
    return {
        key: tuple(sorted(value, key=lambda row: str(row[sort_field])))
        for key, value in sorted(result.items())
    }


def _unique_index(
    rows: Iterable[Mapping[str, Any]], field: str, label: str
) -> Mapping[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        key = str(row[field])
        if key in result:
            raise ObserverProjectionError(f"{label}: duplicate {field}={key}")
        result[key] = row
    if not result:
        raise ObserverProjectionError(f"{label}: no records")
    return dict(sorted(result.items()))


def _quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        return 0.0
    index = max(0, min(len(values) - 1, math.ceil(probability * len(values)) - 1))
    return float(values[index])


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ObserverProjectionError(f"timestamp is not timezone-aware: {value!r}")
    return parsed
