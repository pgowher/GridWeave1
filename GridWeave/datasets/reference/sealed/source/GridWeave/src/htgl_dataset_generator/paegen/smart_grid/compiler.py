"""Deterministic compilation of canonical profiles into PaEGen v1 cases."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any, Iterable, Mapping

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex
from htgl_dataset_generator.observers import ObserverReleaseView
from htgl_dataset_generator.seeds import content_id

from .._canonical import artifact
from ..compiler import MANIFEST_SCHEMA_ID
from ..models import (
    FECM_MODEL_VERSION,
    PAEGEN_INTERFACE_VERSION,
    PAEGEN_SCHEMA_VERSION,
    PaEGenBuild,
    PaEGenReplica,
)
from ..oracle.builder import GROUND_TRUTH_SCHEMA_ID
from ..public import build_observer_artifacts
from .loader import SmartGridScenarioDefinition, load_smart_grid_scenarios


VARIANT_ORDER = {
    "successful_closure": 0,
    "partial_or_unverifiable": 1,
    "adversarial_or_disputed": 2,
}
PROOF_LIMIT = (
    "Synthetic world-state dispositions and evidence fixtures support benchmark truth only; "
    "no evidence grade or receipt silently establishes physical destruction."
)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("scenario time_origin must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _format(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _reasoned_outcome(
    dispositions: Iterable[Mapping[str, Any]], *, baseline_available: bool
) -> tuple[str, tuple[str, ...]]:
    rows = tuple(dispositions)
    if not baseline_available:
        return "UNVERIFIABLE", ("NO_AUTHENTICATED_OBLIGATION_SET",)
    if any("CONTRADICTORY_EVIDENCE" in row["reason_codes"] for row in rows):
        return "DISPUTED", ("UNRESOLVED_CONTRADICTION",)
    resolved = [row for row in rows if row["status"] in {"SUCCESS", "EXCEPTION"}]
    if rows and len(resolved) == len(rows):
        if any(row["status"] == "EXCEPTION" for row in rows):
            return "CLOSED_WITH_EXCEPTIONS", ("ALL_OBLIGATIONS_RESOLVED", "VALID_EXCEPTION_PRESENT")
        return "CLOSED", ("ALL_OBLIGATIONS_RESOLVED",)
    if resolved:
        return "PARTIALLY_CLOSED", ("RESOLVED_AND_UNRESOLVED_OBLIGATIONS",)
    return "OPEN", ("NO_ADMISSIBLE_TERMINAL_RESOLUTION",)


def _responsible_organization(payload: Mapping[str, Any], role: str) -> str:
    matches = sorted(
        str(row["organization_id"])
        for row in payload["organizations"]
        if role in row["roles"]
    )
    if not matches:
        raise ValueError(f"no organization is assigned role {role}")
    return matches[0]


def _compile_variant(
    definition: SmartGridScenarioDefinition,
    variant: Mapping[str, Any],
    *,
    run_id: str,
    replicate_id: int,
    root_seed: str,
) -> PaEGenReplica:
    profile = definition.payload
    accepted = _timestamp(str(profile["time_origin"]))
    case_id = content_id("paebench_smart_grid_case_v1", {
        "profile_sha256": definition.sha256,
        "root_seed": root_seed,
        "variant_id": variant["variant_id"],
    })
    instance_seed = sha256_hex(canonical_json_bytes({
        "root_seed": root_seed,
        "scenario_id": definition.scenario_id,
        "variant_id": variant["variant_id"],
    }))
    asset_rows = {str(row["asset_id"]): row for row in profile["assets"]}
    replica_ids = {
        asset_id: content_id("paebench_replica_v1", {"case_id": case_id, "asset_id": asset_id})
        for asset_id in asset_rows
    }
    obligation_ids = {
        str(row["template_id"]): content_id(
            "paebench_obligation_v1", {"case_id": case_id, "template_id": row["template_id"]}
        )
        for row in profile["obligations"]
    }
    exception_by_obligation = {
        str(row["applies_to_obligation_id"]): row for row in profile["exceptions"]
    }
    mutations = {
        str(item["target_obligation_id"]): str(item["operation"])
        for item in variant["mutations"]
    }
    baseline_available = "REMOVE_BASELINE" not in mutations.values()
    obligations: list[dict[str, Any]] = []
    dispositions: list[dict[str, Any]] = []
    exceptions: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    visible_evidence: list[dict[str, Any]] = []
    for index, template in enumerate(profile["obligations"]):
        template_id = str(template["template_id"])
        obligation_id = obligation_ids[template_id]
        due_at = accepted + timedelta(hours=int(template["deadline_offset_hours"]))
        event_id = content_id("paebench_event_v1", {"case_id": case_id, "template_id": template_id})
        obligations.append({
            "obligation_id": obligation_id,
            "event_id": event_id,
            "obligation_type": "retention_exception" if template_id in exception_by_obligation else "replica_deletion",
            "subject_asset_id": str(template["asset_ids"][0]),
            "responsible_principal_id": _responsible_organization(profile, str(template["responsible_role"])),
            "deadline": _format(due_at),
            "coverage_member_ids": [replica_ids[str(asset_id)] for asset_id in template["asset_ids"]],
            "exempt_member_ids": [replica_ids[str(asset_id)] for asset_id in template["asset_ids"]] if template_id in exception_by_obligation else [],
            "dependency_event_ids": [],
        })
        exception = exception_by_obligation.get(template_id)
        operation = mutations.get(template_id)
        status = "EXCEPTION" if exception is not None else "SUCCESS"
        reasons = ["ADMISSIBLE_TERMINAL_RESOLUTION"]
        if operation == "OMIT_RESOLUTION" or operation == "REMOVE_BASELINE":
            status, reasons = "UNRESOLVED", ["MISSING_COVERAGE"]
        elif operation == "INVALIDATE_EXCEPTION":
            status, reasons = "UNRESOLVED", ["INVALID_EXCEPTION"]
        elif operation == "CONTRADICT_EVIDENCE":
            status, reasons = "UNRESOLVED", ["CONTRADICTORY_EVIDENCE"]
        receipt_ids: list[str] = []
        receipt_count = 0 if operation in {"OMIT_RESOLUTION", "REMOVE_BASELINE"} else (2 if operation == "CONTRADICT_EVIDENCE" else 1)
        for receipt_index in range(receipt_count):
            receipt_id = content_id("paebench_receipt_v1", {
                "case_id": case_id, "template_id": template_id, "receipt_index": receipt_index
            })
            receipt_ids.append(receipt_id)
            contradictory = operation == "CONTRADICT_EVIDENCE" and receipt_index == 1
            claimed_disposition = "FAILED" if contradictory else str(template["required_disposition"])
            receipt = {
                "receipt_id": receipt_id,
                "obligation_id": obligation_id,
                "event_id": event_id,
                "issuer_actor_id": _responsible_organization(profile, str(template["responsible_role"])),
                "evidence_type": str(template["evidence_types"][receipt_index % len(template["evidence_types"])]),
                "issued_at": _format(accepted + timedelta(hours=index + receipt_index + 1)),
                "canonical_digest": hashlib.sha256(f"{instance_seed}|{receipt_id}".encode("utf-8")).hexdigest(),
                "algorithm": "Ed25519-SYNTHETIC",
                "key_id": content_id("paebench_key_v1", receipt_id),
                "anchor_id": None,
                "verification_status_truth": "contradictory" if contradictory else "valid",
                "claimed_disposition": claimed_disposition,
                "covers_replica_ids": [replica_ids[str(asset_id)] for asset_id in template["asset_ids"]],
                "payload_ref": f"fixture://paebench/{case_id}/{receipt_id}",
            }
            verification = {
                "receipt_id": receipt_id,
                "canonical_payload_valid": True,
                "canonical_digest_valid": True,
                "algorithm_valid": True,
                "key_valid": True,
                "authenticator_valid": True,
                "anchor_valid": True,
                "coverage_valid": True,
                "timely": True,
                "dependency_complete": True,
                "contradiction_free": not contradictory,
                "expected_status": receipt["verification_status_truth"],
                "declared_status": receipt["verification_status_truth"],
                "truth_matches_declared": True,
            }
            evidence.append({"receipt": receipt, "verification": verification})
            visible_receipt = {
                "receipt_id": receipt_id,
                "obligation_id": obligation_id,
                "evidence_type": receipt["evidence_type"],
                "issued_at": receipt["issued_at"],
                "covers_replica_count": len(receipt["covers_replica_ids"]),
            }
            if profile["observable_metadata"].get("claim_disposition_visibility", "hidden") == "visible":
                visible_receipt["claimed_disposition"] = receipt["claimed_disposition"]
            visible_evidence.append(visible_receipt)
        dispositions.append({
            "obligation_id": obligation_id,
            "status": status,
            "world_disposition": str(template["required_disposition"]),
            "evidence_ids": receipt_ids,
            "reason_codes": reasons,
        })
        if exception is not None:
            exceptions.append({
                "exception_id": content_id("paebench_exception_v1", {"case_id": case_id, "source": exception["exception_id"]}),
                "obligation_id": obligation_id,
                "replica_ids": [replica_ids[str(asset_id)] for asset_id in template["asset_ids"]],
                "justification_code": str(exception["justification_code"]),
                "valid": operation != "INVALIDATE_EXCEPTION",
                "evidence_ids": receipt_ids,
            })
    outcome, reason_codes = _reasoned_outcome(dispositions, baseline_available=baseline_available)
    if outcome != variant["expected_closure"] or set(reason_codes) != set(variant["expected_reason_codes"]):
        raise ValueError(
            f"{definition.scenario_id}/{variant['variant_id']}: derived {outcome} {reason_codes}, "
            f"declared {variant['expected_closure']} {variant['expected_reason_codes']}"
        )
    relationships: list[dict[str, Any]] = []
    for asset_id, row in sorted(asset_rows.items()):
        relationships.append({
            "edge_id": content_id("paebench_custody_edge_v1", {"case_id": case_id, "asset_id": asset_id}),
            "scenario_id": definition.scenario_id,
            "edge_type": "replicated_to",
            "source_id": asset_id,
            "target_id": replica_ids[asset_id],
            "source_table": "data_object",
            "target_table": "data_object_replica",
            "reason_code": str(row["replica_role"]),
        })
        for parent in row["parent_asset_ids"]:
            relationships.append({
                "edge_id": content_id("paebench_lineage_edge_v1", {"case_id": case_id, "parent": parent, "child": asset_id}),
                "scenario_id": definition.scenario_id,
                "edge_type": "derived_from",
                "source_id": str(parent),
                "target_id": asset_id,
                "source_table": "data_object",
                "target_table": "data_object",
                "reason_code": "declared_scenario_lineage",
            })
    evaluation_time = accepted + timedelta(hours=int(profile["policy_profile"]["deadline_hours"]))
    ground_payload = {
        "schema_version": PAEGEN_SCHEMA_VERSION,
        "interface_version": PAEGEN_INTERFACE_VERSION,
        "model_version": FECM_MODEL_VERSION,
        "access_class": "evaluator_only",
        "run_id": run_id,
        "scenario_id": definition.scenario_id,
        "replicate_id": replicate_id,
        "config_sha256": definition.sha256,
        "seed_stream_digest": instance_seed,
        "proof_limit_statement": PROOF_LIMIT,
        "scenario_profile_id": definition.scenario_id,
        "variant_id": str(variant["variant_id"]),
        "variant_class": str(variant["variant_class"]),
        "cases": [{
            "case_id": case_id,
            "workflow_instance_id": content_id("paebench_workflow_v1", case_id),
            "accepted_at": _format(accepted),
            "evaluation_time": _format(evaluation_time),
            "root_asset_ids": sorted(asset_id for asset_id, row in asset_rows.items() if not row["parent_asset_ids"]),
            "obligation_graph": {
                "asset_ids": sorted(asset_rows),
                "replica_ids": sorted(replica_ids.values()),
                "relationship_edges": sorted(relationships, key=lambda row: row["edge_id"]),
                "obligations": obligations,
            },
            "dispositions": dispositions,
            "exceptions": exceptions,
            "evidence": evidence,
            "closure_ground_truth": {
                "outcome": outcome,
                "resolved_obligation_ids": [row["obligation_id"] for row in dispositions if row["status"] in {"SUCCESS", "EXCEPTION"}],
                "unresolved_obligation_ids": [row["obligation_id"] for row in dispositions if row["status"] == "UNRESOLVED"],
                "reason_codes": list(reason_codes),
            },
        }],
    }
    ground_truth = artifact(GROUND_TRUTH_SCHEMA_ID, ground_payload)
    observer_records = ({
        "record_type": "scenario_context",
        "scenario_id": definition.scenario_id,
        "lifecycle_trigger": profile["lifecycle_trigger"],
        "standards_basis": [row["standard_id"] for row in profile["standards_basis"]],
        "organizations": [
            {"organization_type": row["organization_type"], "roles": row["roles"]}
            for row in profile["organizations"]
        ],
        "repositories": [
            {"repository_id": row["repository_id"], "repository_kind": row["repository_kind"], "region": row["region"]}
            for row in profile["repositories"] if row["observable"]
        ],
        "policy_profile_id": profile["policy_profile"]["profile_id"],
        "observable_field_contract": profile["observable_metadata"]["visible_fields"],
        "synthetic_personal_data": True,
    }, {
        "record_type": "case_declaration",
        "case_id": case_id,
        "accepted_at": _format(accepted),
        "evaluation_time": _format(evaluation_time),
        "assets": [
            {"asset_id": row["asset_id"], "asset_type": row["asset_type"], "parent_asset_ids": row["parent_asset_ids"]}
            for row in profile["assets"]
        ],
        "declared_obligations": [
            {"obligation_id": row["obligation_id"], "obligation_type": row["obligation_type"], "deadline": row["deadline"], "coverage_member_count": len(row["coverage_member_ids"])}
            for row in obligations
        ],
        "submitted_evidence": visible_evidence,
        "declared_exceptions": [
            {
                "exception_id": row["exception_id"],
                "applies_to_obligation_id": obligation_ids[str(row["applies_to_obligation_id"])],
                "justification_code": row["justification_code"],
                "maximum_retention_days": row["maximum_retention_days"],
            }
            for row in profile["exceptions"]
        ],
        "redacted_fields": profile["observable_metadata"]["redacted_fields"],
    })
    release_views = {
        str(observer["observer_profile_id"]): ObserverReleaseView(
            profile_id=str(observer["observer_profile_id"]),
            access_class=str(observer["access_class"]),
            schema_profile_id="paebench.smart-grid.observable.v1",
            records=observer_records,
        )
        for observer in profile["observable_metadata"]["observer_profiles"]
    }
    observer_views = build_observer_artifacts(
        run_id=run_id,
        scenario_id=definition.scenario_id,
        replicate_id=replicate_id,
        config_sha256=definition.sha256,
        release_views=release_views,
    )
    manifest = artifact(MANIFEST_SCHEMA_ID, {
        "schema_version": PAEGEN_SCHEMA_VERSION,
        "interface_version": PAEGEN_INTERFACE_VERSION,
        "model_version": FECM_MODEL_VERSION,
        "run_id": run_id,
        "scenario_id": definition.scenario_id,
        "replicate_id": replicate_id,
        "config_sha256": definition.sha256,
        "seed_stream_digest": instance_seed,
        "case_count": 1,
        "sealed_ground_truth": {"schema_id": ground_truth.schema_id, "sha256": ground_truth.sha256},
        "observer_views": [
            {"observer_profile_id": profile_id, "access_class": item.payload["access_class"], "schema_id": item.schema_id, "sha256": item.sha256, "record_count": item.payload["record_count"]}
            for profile_id, item in observer_views.items()
        ],
    })
    return PaEGenReplica(
        scenario_id=definition.scenario_id,
        replicate_id=replicate_id,
        ground_truth=ground_truth,
        observer_views=observer_views,
        scenario_manifest=manifest,
    )


def compile_smart_grid_benchmark(
    definitions: Iterable[SmartGridScenarioDefinition] | None = None,
    *,
    root_seed: str = "PAEBENCH-SMART-GRID-v1",
) -> PaEGenBuild:
    """Compile schema-valid profiles into three controlled variants per profile."""

    selected = tuple(definitions or load_smart_grid_scenarios())
    if not root_seed:
        raise ValueError("root_seed must be non-empty")
    run_digest = hashlib.sha256(root_seed.encode("utf-8")).hexdigest()[:12].upper()
    run_id = f"RUN-PAEBENCH-SMART-GRID-{run_digest}"
    replicas: list[PaEGenReplica] = []
    for definition in sorted(selected, key=lambda item: item.scenario_id):
        variants = sorted(
            definition.payload["variants"],
            key=lambda item: VARIANT_ORDER[str(item["variant_class"])],
        )
        for replicate_id, variant in enumerate(variants):
            replicas.append(_compile_variant(
                definition,
                variant,
                run_id=run_id,
                replicate_id=replicate_id,
                root_seed=root_seed,
            ))
    return PaEGenBuild(
        run_id=run_id,
        interface_version=PAEGEN_INTERFACE_VERSION,
        model_version=FECM_MODEL_VERSION,
        replicas=tuple(replicas),
    )
