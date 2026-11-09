"""Privileged Model-v1.0 ground-truth projection over the existing pipeline."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable, Mapping, TYPE_CHECKING

from htgl_dataset_generator.seeds import content_id

from .._canonical import artifact
from ..models import (
    FECM_MODEL_VERSION,
    PAEGEN_INTERFACE_VERSION,
    PAEGEN_SCHEMA_VERSION,
    PaEGenArtifact,
)

if TYPE_CHECKING:
    from htgl_dataset_generator.experiments.orchestration import PipelineThroughObserversResult


GROUND_TRUTH_SCHEMA_ID = "https://pae.local/schema/paegen-ground-truth/v1"


def _closure(start_ids: Iterable[str], edges: Iterable[Any]) -> tuple[str, ...]:
    reached = set(start_ids)
    changed = True
    edge_rows = tuple(edges)
    while changed:
        changed = False
        for edge in edge_rows:
            if edge.edge_type != "derived_from" or edge.source_id not in reached:
                continue
            if edge.target_id not in reached:
                reached.add(edge.target_id)
                changed = True
    return tuple(sorted(reached))


def _resolution(truth: Any, obligation_type: str) -> tuple[str, tuple[str, ...]]:
    reasons: list[str] = []
    if truth.contradictory_receipt_ids or not truth.contradiction_free:
        reasons.append("CONTRADICTORY_EVIDENCE")
    if truth.missing_coverage_ids:
        reasons.append("MISSING_COVERAGE")
    if truth.invalid_receipt_ids:
        reasons.append("INVALID_EVIDENCE")
    if truth.late_receipt_ids:
        reasons.append("LATE_EVIDENCE")
    if truth.missing_dependency_receipt_ids:
        reasons.append("INCOMPLETE_EVIDENCE_CONTINUITY")
    if truth.sufficient:
        status = "EXCEPTION" if obligation_type == "retention_exception" else "SUCCESS"
        reasons.append("ADMISSIBLE_TERMINAL_RESOLUTION")
    else:
        status = "UNRESOLVED"
        if not reasons:
            reasons.append("INSUFFICIENT_EVIDENCE")
    return status, tuple(sorted(set(reasons)))


def _world_disposition(
    obligation_type: str,
    coverage_member_ids: Iterable[str],
    *,
    replica_by_id: Mapping[str, Mapping[str, Any]],
    replicas_by_asset: Mapping[str, list[Mapping[str, Any]]],
) -> str:
    if obligation_type == "retention_exception":
        return "RETAINED"
    if obligation_type != "replica_deletion":
        return "UNKNOWN"
    replicas: dict[str, Mapping[str, Any]] = {}
    for member_id in coverage_member_ids:
        if member_id in replica_by_id:
            replicas[member_id] = replica_by_id[member_id]
        for replica in replicas_by_asset.get(member_id, ()):
            replicas[str(replica["replica_id"])] = replica
    statuses = {str(replica["deletion_status"]) for replica in replicas.values()}
    if replicas and statuses <= {"deleted"}:
        return "ERASED"
    if replicas and statuses <= {"exempt"}:
        return "RETAINED"
    if "failed" in statuses:
        return "FAILED"
    return "UNKNOWN"


def _case_outcome(dispositions: Iterable[Mapping[str, Any]]) -> tuple[str, tuple[str, ...]]:
    rows = tuple(dispositions)
    if any("CONTRADICTORY_EVIDENCE" in row["reason_codes"] for row in rows):
        return "DISPUTED", ("UNRESOLVED_CONTRADICTION",)
    resolved = [row for row in rows if row["status"] in {"SUCCESS", "EXCEPTION"}]
    if rows and len(resolved) == len(rows):
        if any(row["status"] == "EXCEPTION" for row in rows):
            return "CLOSED_WITH_EXCEPTIONS", ("ALL_OBLIGATIONS_RESOLVED", "VALID_EXCEPTION_PRESENT")
        return "CLOSED", ("ALL_OBLIGATIONS_RESOLVED",)
    if resolved:
        return "PARTIALLY_CLOSED", ("RESOLVED_AND_UNRESOLVED_OBLIGATIONS",)
    if rows:
        return "OPEN", ("NO_ADMISSIBLE_TERMINAL_RESOLUTION",)
    return "UNVERIFIABLE", ("NO_AUTHENTICATED_OBLIGATION_SET",)


def build_ground_truth_artifact(result: "PipelineThroughObserversResult") -> PaEGenArtifact:
    """Build sealed closure truth without changing the existing generator stages."""

    top = result.artifacts
    evidence = top.through_anomalies.through_evidence
    obligations_build = evidence.through_obligations.evidence_obligations
    through_dag = evidence.through_obligations.through_policy.through_dag
    workflows = through_dag.workflows
    catalog = through_dag.catalog
    receipts_build = evidence.evidence_receipts

    events_by_workflow: dict[str, list[Mapping[str, Any]]] = {}
    for event in workflows.governance_events:
        events_by_workflow.setdefault(str(event["workflow_instance_id"]), []).append(event)
    obligation_by_event: dict[str, list[Mapping[str, Any]]] = {}
    for obligation in obligations_build.evidence_obligations:
        obligation_by_event.setdefault(str(obligation["event_id"]), []).append(obligation)
    provenance_by_id = {item.obligation_id: item for item in obligations_build.provenance}
    sufficiency_by_id = {
        item.obligation_id: item for item in receipts_build.verification.sufficiency.truth
    }
    receipts_by_obligation: dict[str, list[Mapping[str, Any]]] = {}
    for receipt in receipts_build.evidence_receipts:
        receipts_by_obligation.setdefault(str(receipt["obligation_id"]), []).append(receipt)
    replicas_by_asset: dict[str, list[Mapping[str, Any]]] = {}
    replica_by_id: dict[str, Mapping[str, Any]] = {}
    for replica in catalog.data_object_replicas:
        replicas_by_asset.setdefault(str(replica["data_object_id"]), []).append(replica)
        replica_by_id[str(replica["replica_id"])] = replica
    verification_by_id = {
        item.receipt_id: item for item in receipts_build.verification.truth
    }

    cases: list[dict[str, Any]] = []
    for workflow in sorted(workflows.workflow_instances, key=lambda row: str(row["workflow_instance_id"])):
        if workflow["workflow_type"] != "erasure":
            continue
        workflow_id = str(workflow["workflow_instance_id"])
        events = sorted(events_by_workflow.get(workflow_id, ()), key=lambda row: int(row["workflow_step_index"]))
        root_asset_ids = tuple(sorted({str(row["data_object_id"]) for row in events}))
        asset_ids = _closure(root_asset_ids, catalog.custody_edges)
        replica_ids = tuple(sorted(
            str(replica["replica_id"])
            for asset_id in asset_ids
            for replica in replicas_by_asset.get(asset_id, ())
        ))
        obligations = sorted(
            (obligation for event in events for obligation in obligation_by_event.get(str(event["event_id"]), ())),
            key=lambda row: str(row["obligation_id"]),
        )
        dispositions: list[dict[str, Any]] = []
        exceptions: list[dict[str, Any]] = []
        normalized_obligations: list[dict[str, Any]] = []
        for obligation in obligations:
            obligation_id = str(obligation["obligation_id"])
            provenance = provenance_by_id[obligation_id]
            truth = sufficiency_by_id[obligation_id]
            status, reason_codes = _resolution(
                truth, str(obligation["obligation_type"])
            )
            world_disposition = _world_disposition(
                str(obligation["obligation_type"]),
                provenance.coverage_member_ids,
                replica_by_id=replica_by_id,
                replicas_by_asset=replicas_by_asset,
            )
            receipt_ids = tuple(sorted(
                str(receipt["receipt_id"])
                for receipt in receipts_by_obligation.get(obligation_id, ())
            ))
            normalized_obligations.append({
                "obligation_id": obligation_id,
                "event_id": str(obligation["event_id"]),
                "obligation_type": str(obligation["obligation_type"]),
                "subject_asset_id": str(obligation["subject_object_id"]),
                "responsible_principal_id": str(obligation["responsible_actor_id"]),
                "deadline": str(obligation["due_at"]),
                "coverage_member_ids": list(provenance.coverage_member_ids),
                "exempt_member_ids": list(provenance.exempt_member_ids),
                "dependency_event_ids": list(provenance.dependency_event_ids),
            })
            dispositions.append({
                "obligation_id": obligation_id,
                "status": status,
                "world_disposition": world_disposition,
                "evidence_ids": list(receipt_ids),
                "reason_codes": list(reason_codes),
            })
            if obligation["obligation_type"] == "retention_exception":
                exceptions.append({
                    "exception_id": content_id("paegen_exception_v1", obligation_id),
                    "obligation_id": obligation_id,
                    "replica_ids": list(provenance.exempt_member_ids),
                    "justification_code": "POLICY_RETENTION_BASIS",
                    "valid": bool(truth.sufficient),
                    "evidence_ids": list(receipt_ids),
                })
        outcome, outcome_reasons = _case_outcome(dispositions)
        case_receipts = sorted(
            (
                receipt
                for obligation in obligations
                for receipt in receipts_by_obligation.get(str(obligation["obligation_id"]), ())
            ),
            key=lambda row: str(row["receipt_id"]),
        )
        case_id = content_id("paegen_erasure_case_v1", {
            "scenario_id": result.run_plan.scenario_id,
            "replicate_id": result.run_plan.replicate_id,
            "workflow_instance_id": workflow_id,
        })
        relevant_edges = [
            edge for edge in catalog.custody_edges
            if edge.source_id in asset_ids or edge.target_id in asset_ids or edge.target_id in replica_ids
        ]
        cases.append({
            "case_id": case_id,
            "workflow_instance_id": workflow_id,
            "accepted_at": str(workflow["started_at"]),
            "evaluation_time": str(workflow.get("ended_at") or events[-1]["timestamp"]),
            "root_asset_ids": list(root_asset_ids),
            "obligation_graph": {
                "asset_ids": list(asset_ids),
                "replica_ids": list(replica_ids),
                "relationship_edges": [asdict(edge) for edge in sorted(relevant_edges, key=lambda item: item.edge_id)],
                "obligations": normalized_obligations,
            },
            "dispositions": dispositions,
            "exceptions": exceptions,
            "evidence": [
                {
                    "receipt": dict(receipt),
                    "verification": asdict(verification_by_id[str(receipt["receipt_id"])]),
                }
                for receipt in case_receipts
            ],
            "closure_ground_truth": {
                "outcome": outcome,
                "resolved_obligation_ids": [row["obligation_id"] for row in dispositions if row["status"] in {"SUCCESS", "EXCEPTION"}],
                "unresolved_obligation_ids": [row["obligation_id"] for row in dispositions if row["status"] == "UNRESOLVED"],
                "reason_codes": list(outcome_reasons),
            },
        })

    payload = {
        "schema_version": PAEGEN_SCHEMA_VERSION,
        "interface_version": PAEGEN_INTERFACE_VERSION,
        "model_version": FECM_MODEL_VERSION,
        "access_class": "evaluator_only",
        "run_id": result.run_plan.run_id,
        "scenario_id": result.run_plan.scenario_id,
        "replicate_id": result.run_plan.replicate_id,
        "config_sha256": result.run_plan.config_sha256,
        "seed_stream_digest": result.seed_stream_digest,
        "proof_limit_statement": receipts_build.proof_limit_statement,
        "cases": cases,
    }
    return artifact(GROUND_TRUTH_SCHEMA_ID, payload)
