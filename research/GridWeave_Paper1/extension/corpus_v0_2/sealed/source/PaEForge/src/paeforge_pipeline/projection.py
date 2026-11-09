"""Allowlisted PaEGen smart-grid projection into the PaEForge v1 contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any, Mapping

from paeforge_contract import (
    build_case_manifest,
    build_observer_projection,
    build_receipt_stream,
    verclo_obligation_id,
)
from paeforge_contract.canonical import domain_digest, verclo_content_id


EVIDENCE_TYPE_MAP = {
    "backup_expiry_attestation": "replica_attestation",
    "deletion_acknowledgement": "deletion_acknowledgement",
    "key_destruction_attestation": "deletion_acknowledgement",
    "recipient_notification_receipt": "notification_receipt",
    "replica_attestation": "replica_attestation",
    "retention_exception_attestation": "audit_finding",
    "signed_audit_receipt": "audit_finding",
}


@dataclass(frozen=True)
class ProjectionResult:
    manifest: Mapping[str, Any]
    observer_projection: Mapping[str, Any]
    receipt_stream: Mapping[str, Any]
    obligation_id_map: Mapping[str, tuple[str, ...]]
    obligation_visibility: Mapping[str, bool]
    source_observer_payload: Mapping[str, Any]
    source_manifest_payload: Mapping[str, Any]
    security_diagnostics: tuple[str, ...]


def _slug(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", value.upper()).strip("-")


def _record(payload: Mapping[str, Any], record_type: str) -> Mapping[str, Any]:
    matches = [row for row in payload["records"] if row.get("record_type") == record_type]
    if len(matches) != 1:
        raise ValueError(f"PaEGen observer bundle must contain one {record_type} record")
    return matches[0]


def _source_ids(case_id: str, scenario: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    from htgl_dataset_generator.seeds import content_id  # type: ignore[import-not-found]

    replica_ids = {
        str(row["asset_id"]): content_id(
            "paebench_replica_v1", {"case_id": case_id, "asset_id": row["asset_id"]}
        )
        for row in scenario["assets"]
    }
    obligation_ids = {
        str(row["template_id"]): content_id(
            "paebench_obligation_v1",
            {"case_id": case_id, "template_id": row["template_id"]},
        )
        for row in scenario["obligations"]
    }
    return replica_ids, obligation_ids


def translated_policy(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Translate the declared scenario policy, never its expected decisions."""

    source = scenario["policy_profile"]
    dispositions = [
        row for row in source["valid_dispositions"]
        if row in {"ERASED", "CRYPTO_ERASED", "APPROVED_TRANSFORM"}
    ]
    if not dispositions:
        dispositions = ["ERASED"]
    replica_classes = sorted(
        {
            str(row["replica_role"])
            for row in scenario["assets"]
            if row["replica_role"] in {"primary", "secondary", "cache", "backup", "export", "derived"}
        }
    )
    return {
        "schema_version": "1.0.0",
        "model_version": "PAE-FECM-v1.0.0",
        "profile_id": f"VERCLO-POLICY-{_slug(str(source['profile_id']).removeprefix('POL-'))}",
        "version": str(source["version"]),
        "authorization_basis": str(source["authorization_basis"]),
        "applicable_asset_kinds": ["*"],
        "applicable_replica_classes": replica_classes,
        "default_rule": {
            "deadline_hours": int(source["deadline_hours"]),
            "minimum_evidence_grade": str(source["evidence_floor"]),
            "permitted_dispositions": sorted(set(dispositions)),
        },
        "overrides": [],
        "exception_authority_ids": ["AUTHORITY-RETENTION-REVIEW"],
        "early_closure_allowed": False,
    }


def build_projection(
    *,
    scenario: Mapping[str, Any],
    paegen_replica: Any,
    observer_profile_id: str,
    projection_config: Mapping[str, Any],
    policy_ref: Mapping[str, Any],
    root_seed: str,
    paegen_source_revision: str,
    generated_at: str,
) -> ProjectionResult:
    """Build a VERCLO exchange without accepting the PaEGen truth document."""

    if not projection_config["expose_visible_repository_bindings"]:
        raise ValueError("the vertical profile requires explicit visible custody bindings")
    observer_artifact = paegen_replica.observer_views[observer_profile_id]
    observer_payload = observer_artifact.payload
    if observer_payload["access_class"] != projection_config["access_class"]:
        raise ValueError("configured projection access class does not match PaEGen observer")
    scenario_context = _record(observer_payload, "scenario_context")
    case_declaration = _record(observer_payload, "case_declaration")
    case_id = str(case_declaration["case_id"])
    privacy = projection_config.get("privacy", {})
    identifier_mode = str(privacy.get("identifier_mode", "stable"))
    temporal_mode = str(privacy.get("temporal_mode", "exact"))
    topology_mode = str(privacy.get("topology_mode", "full"))
    proof_mode = str(privacy.get("proof_mode", "full"))

    def private_id(prefix: str, value: str) -> str:
        if identifier_mode == "stable":
            return value
        digest = hashlib.sha256(
            b"paeforge-case-scoped-identifier-v1\0"
            + case_id.encode("utf-8") + b"\0" + value.encode("utf-8")
        ).hexdigest()
        return f"{prefix}-{digest[:12].upper()}"

    accepted_source = datetime.fromisoformat(str(case_declaration["accepted_at"]).replace("Z", "+00:00"))

    def private_time(value: str) -> str:
        if temporal_mode == "exact":
            return value
        instant = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        relative_days = (instant - accepted_source).days
        anchor = datetime(2000, 1, 1, tzinfo=accepted_source.tzinfo)
        return (anchor + timedelta(days=relative_days)).isoformat().replace("+00:00", "Z")
    visible_repository_ids = {
        str(row["repository_id"]) for row in scenario_context["repositories"]
    }
    scenario_repositories = {
        str(row["repository_id"]): row
        for row in scenario["repositories"]
        if row["repository_id"] in visible_repository_ids and row["observable"]
    }
    all_scenario_repositories = {
        str(row["repository_id"]): row for row in scenario["repositories"]
    }
    source_assets = {str(row["asset_id"]): row for row in scenario["assets"]}
    declared_assets = {str(row["asset_id"]): row for row in case_declaration["assets"]}
    visible_asset_ids = {
        asset_id for asset_id, row in source_assets.items()
        if row["repository_id"] in scenario_repositories and asset_id in declared_assets
    }
    if not visible_asset_ids or not scenario_repositories:
        raise ValueError("projection has no visible asset/repository topology")
    replica_ids, source_obligation_ids = _source_ids(case_id, scenario)
    output_asset_ids = {asset_id: private_id("AST", asset_id) for asset_id in source_assets}
    output_replica_ids = {asset_id: private_id("RPL", replica_id) for asset_id, replica_id in replica_ids.items()}
    if topology_mode == "aggregated":
        aggregate_repository_id = private_id("REP", "REPOSITORY-AGGREGATE")
        aggregate_organization_id = private_id("ORG", "ORGANIZATION-AGGREGATE")
        output_repository_ids = {repository_id: aggregate_repository_id for repository_id in all_scenario_repositories}
        output_organization_ids = {str(row["organization_id"]): aggregate_organization_id for row in all_scenario_repositories.values()}
    else:
        output_repository_ids = {repository_id: private_id("REP", repository_id) for repository_id in all_scenario_repositories}
        output_organization_ids = {str(row["organization_id"]): private_id("ORG", str(row["organization_id"])) for row in all_scenario_repositories.values()}
    dataset_id = private_id("DST", f"DATASET-{scenario['scenario_id']}")
    correlation_id = f"CORRELATION-{case_id}"

    assets = [
        {
            "asset_id": output_asset_ids[asset_id],
            "dataset_id": dataset_id,
            "asset_kind": str(source_assets[asset_id]["asset_type"]).lower(),
            "visibility": "DECLARED",
        }
        for asset_id in sorted(visible_asset_ids)
    ]
    repositories_by_id: dict[str, dict[str, Any]] = {}
    for repository_id, row in sorted(scenario_repositories.items()):
        output_repository_id = output_repository_ids[repository_id]
        output_organization_id = output_organization_ids[str(row["organization_id"])]
        repositories_by_id.setdefault(output_repository_id, {
            "repository_id": output_repository_id,
            "organization_id": output_organization_id,
            "custodian_principal_id": output_organization_id,
            "repository_class": "AGGREGATED" if topology_mode == "aggregated" else str(row["repository_kind"]),
            "visibility": "DECLARED",
        })
    repositories = list(repositories_by_id.values())
    replicas = [
        {
            "replica_id": output_replica_ids[asset_id],
            "asset_id": output_asset_ids[asset_id],
            "repository_id": output_repository_ids[str(source_assets[asset_id]["repository_id"])],
            "replica_class": str(source_assets[asset_id]["replica_role"]),
            "visibility": "DECLARED",
        }
        for asset_id in sorted(visible_asset_ids)
    ]
    security_diagnostics: list[str] = []
    if identifier_mode == "case_scoped":
        security_diagnostics.append("CASE_SCOPED_IDENTIFIERS_APPLIED")
    if temporal_mode == "relative_day":
        security_diagnostics.append("RELATIVE_DAY_TIMESTAMPS_APPLIED")
    if topology_mode == "aggregated":
        security_diagnostics.append("TOPOLOGY_IDENTITIES_AND_EDGES_AGGREGATED")
    if proof_mode == "no_mechanism":
        security_diagnostics.append("MECHANISM_REFERENCES_OMITTED")
    observer_lineage_available = all(
        "parent_asset_ids" in row for row in declared_assets.values()
    )
    if not observer_lineage_available:
        security_diagnostics.append("OBSERVER_LINEAGE_ABSENT")
    lineage_edges = []
    for child_id in sorted(visible_asset_ids) if topology_mode == "full" else ():
        observer_parents = declared_assets[child_id].get("parent_asset_ids", ())
        for parent_id in sorted(observer_parents):
            if parent_id not in visible_asset_ids:
                continue
            lineage_edges.append(
                {
                    "relationship_id": verclo_content_id(
                        "REL",
                        "paeforge-visible-lineage-v1",
                        {"case_id": case_id, "parent": parent_id, "child": child_id},
                    ),
                    "parent_asset_id": output_asset_ids[parent_id],
                    "child_asset_id": output_asset_ids[child_id],
                    "relationship_type": "DERIVED_FROM",
                    "visibility": "DECLARED",
                }
            )
    if topology_mode == "aggregated":
        root_asset_ids = sorted(output_asset_ids[asset_id] for asset_id in visible_asset_ids)
    else:
        root_asset_ids = sorted(
            output_asset_ids[asset_id] for asset_id in visible_asset_ids
            if not (set(declared_assets[asset_id].get("parent_asset_ids", ())) & visible_asset_ids)
        )
    completeness_mode = str(projection_config.get("scope_completeness_mode", "visible_assertion"))
    if completeness_mode == "visible_assertion":
        declared_scope_complete = True
    elif completeness_mode == "source_audited":
        declared_scope_complete = (
            observer_lineage_available
            and
            visible_repository_ids == {str(row["repository_id"]) for row in scenario["repositories"]}
            and visible_asset_ids == set(source_assets)
        )
    else:
        raise ValueError(f"unsupported scope completeness mode: {completeness_mode}")
    topology = {
        "scope_version": 1,
        "graph_available": observer_lineage_available,
        "declared_scope_complete": declared_scope_complete,
        "unresolved_reference_ids": [],
        "assets": assets,
        "repositories": repositories,
        "replicas": replicas,
        "lineage_edges": lineage_edges,
    }
    scope_material = {
        "case_id": case_id,
        "dataset_id": dataset_id,
        "correlation_id": correlation_id,
        "scope_version": 1,
        "assets": sorted(assets, key=lambda row: row["asset_id"]),
        "repositories": sorted(repositories, key=lambda row: row["repository_id"]),
        "replicas": sorted(replicas, key=lambda row: row["replica_id"]),
        "lineage_edges": sorted(lineage_edges, key=lambda row: row["relationship_id"]),
    }
    from verclo.canonical import commitment  # type: ignore[import-not-found]

    topology["scope_commitment"] = commitment("verclo-visible-scope-v1", scope_material)
    accepted_at = private_time(str(case_declaration["accepted_at"]))
    evaluation_time = private_time(str(case_declaration["evaluation_time"]))
    exchange_id = verclo_content_id(
        "XCH",
        "paeforge-exchange-v1",
        {
            "run_id": observer_payload["run_id"],
            "scenario_id": observer_payload["scenario_id"],
            "replicate_id": observer_payload["replicate_id"],
            "case_id": case_id,
            "observer_profile_id": observer_profile_id,
        },
    )
    seed = {
        "derivation": "NAMED_STREAM_SHA256_V1",
        "replicate_id": int(observer_payload["replicate_id"]),
        "master_seed_commitment": hashlib.sha256(root_seed.encode("utf-8")).hexdigest(),
        "seed_stream_digest": str(paegen_replica.scenario_manifest.payload["seed_stream_digest"]),
    }
    provenance = {
        "producer": "PaEGen",
        "producer_version": str(observer_payload["interface_version"]),
        "source_revision": paegen_source_revision,
        "source_bundle_sha256": observer_artifact.sha256,
    }
    obligation_map: dict[str, tuple[str, ...]] = {}
    obligation_visibility: dict[str, bool] = {}
    binding_by_obligation: dict[str, list[dict[str, str]]] = {}
    for template in scenario["obligations"]:
        source_obligation_id = source_obligation_ids[str(template["template_id"])]
        bindings = []
        evaluator_ids = []
        for asset_id in sorted(set(template["asset_ids"])):
            source_asset = source_assets[asset_id]
            source_repository = next(
                row for row in scenario["repositories"]
                if row["repository_id"] == source_asset["repository_id"]
            )
            target_id = verclo_obligation_id(
                case_id=case_id,
                dataset_id=dataset_id,
                correlation_id=correlation_id,
                asset_id=output_asset_ids[asset_id],
                replica_id=output_replica_ids[asset_id],
                repository_id=output_repository_ids[str(source_asset["repository_id"])],
                custodian_principal_id=output_organization_ids[str(source_repository["organization_id"])],
                policy_profile_id=str(policy_ref["profile_id"]),
                policy_version=str(policy_ref["version"]),
            )
            evaluator_ids.append(target_id)
            is_visible = asset_id in visible_asset_ids
            obligation_visibility[target_id] = is_visible
            if not is_visible:
                continue
            bindings.append(
                {
                    "obligation_id": target_id,
                    "asset_id": output_asset_ids[asset_id],
                    "replica_id": output_replica_ids[asset_id],
                    "repository_id": output_repository_ids[str(source_asset["repository_id"])],
                    "issuer_principal_id": output_organization_ids[str(source_repository["organization_id"])],
                    "disposition": str(template["required_disposition"]),
                }
            )
        obligation_map[source_obligation_id] = tuple(evaluator_ids)
        binding_by_obligation[source_obligation_id] = bindings

    visible_evidence = []
    seen_receipts: dict[str, Mapping[str, Any]] = {}
    for source_receipt in case_declaration["submitted_evidence"]:
        source_receipt_id = str(source_receipt["receipt_id"])
        previous = seen_receipts.get(source_receipt_id)
        if previous is None:
            seen_receipts[source_receipt_id] = source_receipt
            visible_evidence.append(source_receipt)
        elif previous == source_receipt:
            security_diagnostics.append("IDEMPOTENT_REPLAY_DEDUPLICATED")
        else:
            security_diagnostics.append("NON_IDENTICAL_REPLAY_QUARANTINED")
    receipt_rows = []
    for source_receipt in sorted(visible_evidence, key=lambda row: str(row["receipt_id"])):
        source_obligation_id = str(source_receipt["obligation_id"])
        for binding in binding_by_obligation.get(source_obligation_id, ()):
            receipt_id = verclo_content_id(
                "RCP",
                "paeforge-projected-receipt-v1",
                {"source_receipt_id": source_receipt["receipt_id"], "obligation_id": binding["obligation_id"]},
            )
            proof = {
                "format": "PAEGEN-SYNTHETIC-ORDERED-V1",
                "verification_material_refs": [f"fixture-key:{receipt_id}", f"fixture-anchor:{receipt_id}"],
                "credential_ref": f"fixture-key:{receipt_id}",
                "anchor_ref": f"fixture-anchor:{receipt_id}",
            }
            if source_receipt.get("authenticator") == "00-invalid-synthetic-signature":
                proof.pop("credential_ref", None)
                security_diagnostics.append("INVALID_AUTHENTICATOR_PROPAGATED")
            if "canonical_digest" in source_receipt and source_receipt["canonical_digest"] is None:
                proof = {
                    "format": "PAEGEN-SYNTHETIC-ORDERED-V1",
                    "verification_material_refs": [],
                }
                security_diagnostics.append("MALFORMED_CANONICAL_PAYLOAD_PROPAGATED")
            if datetime.fromisoformat(str(source_receipt["issued_at"]).replace("Z", "+00:00")) < accepted_source:
                proof.pop("anchor_ref", None)
                security_diagnostics.append("BACKDATED_ORDERING_SIGNAL_PROPAGATED")
            if proof_mode == "full" and str(policy_ref["minimum_evidence_grade"]) in {"E4", "E5"}:
                proof["mechanism_ref"] = f"fixture-mechanism:{receipt_id}"
            receipt_rows.append(
                {
                    "receipt_id": receipt_id,
                    "case_id": case_id,
                    "obligation_id": binding["obligation_id"],
                    "asset_id": binding["asset_id"],
                    "replica_id": binding["replica_id"],
                    "repository_id": binding["repository_id"],
                    "issuer_principal_id": binding["issuer_principal_id"],
                    "issuer_role": "CUSTODIAN",
                    "trust_domain": f"TRUST-{binding['issuer_principal_id']}",
                    "fault_domain": f"FAULT-{binding['repository_id']}",
                    "evidence_type": EVIDENCE_TYPE_MAP.get(str(source_receipt["evidence_type"]), "signature"),
                    "disposition": str(source_receipt.get("claimed_disposition", binding["disposition"])),
                    "event_time": private_time(str(source_receipt["issued_at"])),
                    "submitted_at": private_time(str(source_receipt["issued_at"])),
                    "not_before": accepted_at,
                    "provenance_refs": [f"paegen-receipt:{receipt_id}"],
                    "claim_commitment": domain_digest("paeforge-synthetic-claim-v1", source_receipt),
                    "proof": proof,
                }
            )

    exception_rows = []
    accepted = datetime.fromisoformat(accepted_at.replace("Z", "+00:00"))
    for source_exception in case_declaration["declared_exceptions"]:
        source_obligation_id = str(source_exception["applies_to_obligation_id"])
        for target_id in obligation_map.get(source_obligation_id, ()):
            exception_id = verclo_content_id(
                "EXC", "paeforge-projected-exception-v1",
                {"source_exception_id": source_exception["exception_id"], "obligation_id": target_id},
            )
            expires = accepted + timedelta(days=int(source_exception["maximum_retention_days"]))
            exception_rows.append(
                {
                    "exception_id": exception_id,
                    "obligation_id": target_id,
                    "authority_principal_id": "AUTHORITY-RETENTION-REVIEW",
                    "basis_commitment": domain_digest("paeforge-exception-basis-v1", source_exception),
                    "effective_at": accepted_at,
                    "expires_at": expires.isoformat().replace("+00:00", "Z"),
                }
            )

    observer_document = build_observer_projection(
        exchange_id=exchange_id,
        run_id=str(observer_payload["run_id"]),
        scenario_id=str(observer_payload["scenario_id"]),
        case_id=case_id,
        seed=seed,
        produced_at=accepted_at if temporal_mode == "relative_day" else generated_at,
        evaluation_time=evaluation_time,
        observer={
            "principal_id": f"OBSERVER-{observer_profile_id}",
            "roles": ["AUDITOR"],
            "profile_id": str(projection_config["profile_id"]),
            "profile_version": str(projection_config["profile_version"]),
            "access_class": str(projection_config["access_class"]),
        },
        policy={key: policy_ref[key] for key in ("profile_id", "version", "sha256")},
        case={
            "dataset_id": dataset_id,
            "correlation_id": correlation_id,
            "request_id": f"REQUEST-{case_id}",
            "requester_principal_id": "REQUESTER-PSEUDONYMOUS",
            "root_asset_ids": root_asset_ids,
            "accepted_at": accepted_at,
            "metadata": {
                "paegen_observer_profile_id": observer_profile_id,
                "projection_profile_id": str(projection_config["profile_id"]),
            },
        },
        topology=topology,
        exceptions=exception_rows,
        challenges=(),
        provenance=provenance,
    )
    receipt_document = build_receipt_stream(
        exchange_id=exchange_id,
        run_id=str(observer_payload["run_id"]),
        scenario_id=str(observer_payload["scenario_id"]),
        case_id=case_id,
        seed=seed,
        stream_id=f"STREAM-{exchange_id}",
        receipts=receipt_rows,
        provenance=provenance,
    )
    manifest = build_case_manifest(
        exchange_id=exchange_id,
        run_id=str(observer_payload["run_id"]),
        scenario_id=str(observer_payload["scenario_id"]),
        case_id=case_id,
        seed=seed,
        policy={key: policy_ref[key] for key in ("profile_id", "version", "sha256")},
        observer_projection=observer_document,
        receipt_stream=receipt_document,
        provenance={
            "producer": "PaEGen",
            "producer_version": str(observer_payload["interface_version"]),
            "source_revision": paegen_source_revision,
            "generated_at": generated_at,
        },
    )
    return ProjectionResult(
        manifest=manifest,
        observer_projection=observer_document,
        receipt_stream=receipt_document,
        obligation_id_map=dict(sorted(obligation_map.items())),
        obligation_visibility=dict(sorted(obligation_visibility.items())),
        source_observer_payload=observer_payload,
        source_manifest_payload=paegen_replica.scenario_manifest.payload,
        security_diagnostics=tuple(sorted(set(security_diagnostics))),
    )
