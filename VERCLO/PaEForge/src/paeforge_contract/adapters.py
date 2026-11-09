"""Narrow adapters between PaEForge exchange documents and existing components."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence

from .canonical import domain_digest, sha256_digest
from .validation import validate_document, validate_verifier_bundle, validate_verifier_input


SCHEMA_VERSION = "1.0.0"
CONTRACT_VERSION = "1.0.0"
MODEL_VERSION = "PAE-FECM-v1.0.0"


def _timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return parsed.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _seed_ref(seed: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "replicate_id": int(seed["replicate_id"]),
        "seed_stream_digest": str(seed["seed_stream_digest"]),
    }


def _input_header(
    *, exchange_id: str, run_id: str, scenario_id: str, case_id: str, seed: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "model_version": MODEL_VERSION,
        "data_class": "VERIFIER_VISIBLE_INPUT",
        "exchange_id": exchange_id,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "case_id": case_id,
        "seed": _seed_ref(seed),
    }


def build_observer_projection(
    *,
    exchange_id: str,
    run_id: str,
    scenario_id: str,
    case_id: str,
    seed: Mapping[str, Any],
    produced_at: datetime | str,
    evaluation_time: datetime | str,
    observer: Mapping[str, Any],
    policy: Mapping[str, Any],
    case: Mapping[str, Any],
    topology: Mapping[str, Any],
    provenance: Mapping[str, Any],
    exceptions: Sequence[Mapping[str, Any]] = (),
    challenges: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Construct a fresh allowlisted projection from sanitized PaEGen records."""

    semantic_material = {
        "observer": dict(observer),
        "policy": dict(policy),
        "case": dict(case),
        "topology": dict(topology),
        "exceptions": [dict(row) for row in exceptions],
        "challenges": [dict(row) for row in challenges],
    }
    payload = {
        "schema_id": "https://paeforge.local/schema/observer-projection/v1",
        **_input_header(
            exchange_id=exchange_id,
            run_id=run_id,
            scenario_id=scenario_id,
            case_id=case_id,
            seed=seed,
        ),
        "produced_at": _timestamp(produced_at),
        "evaluation_time": _timestamp(evaluation_time),
        **semantic_material,
        "projection_commitment": domain_digest(
            "paeforge-observer-projection-v1", semantic_material
        ),
        "provenance": dict(provenance),
    }
    validate_verifier_input(payload)
    return payload


def build_receipt_stream(
    *,
    exchange_id: str,
    run_id: str,
    scenario_id: str,
    case_id: str,
    seed: Mapping[str, Any],
    stream_id: str,
    receipts: Sequence[Mapping[str, Any]],
    provenance: Mapping[str, Any],
    stream_version: int = 1,
) -> dict[str, Any]:
    """Construct a sequenced stream without accepting precomputed validity fields."""

    rows = []
    for sequence, source in enumerate(receipts):
        row = dict(source)
        if "sequence" in row and row["sequence"] != sequence:
            raise ValueError("provided receipt sequence does not match canonical order")
        row["sequence"] = sequence
        rows.append(row)
    payload = {
        "schema_id": "https://paeforge.local/schema/receipt-stream/v1",
        **_input_header(
            exchange_id=exchange_id,
            run_id=run_id,
            scenario_id=scenario_id,
            case_id=case_id,
            seed=seed,
        ),
        "stream_id": stream_id,
        "stream_version": stream_version,
        "receipts": rows,
        "stream_commitment": domain_digest("paeforge-receipt-stream-v1", rows),
        "provenance": dict(provenance),
    }
    validate_verifier_input(payload)
    return payload


def build_case_manifest(
    *,
    exchange_id: str,
    run_id: str,
    scenario_id: str,
    case_id: str,
    seed: Mapping[str, Any],
    policy: Mapping[str, Any],
    observer_projection: Mapping[str, Any],
    receipt_stream: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind safe input artifacts without naming or locating the evaluator bundle."""

    payload = {
        "schema_id": "https://paeforge.local/schema/case-manifest/v1",
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "model_version": MODEL_VERSION,
        "data_class": "VERIFIER_VISIBLE_INPUT",
        "exchange_id": exchange_id,
        "run_id": run_id,
        "scenario_id": scenario_id,
        "case_id": case_id,
        "seed": dict(seed),
        "policy": dict(policy),
        "artifacts": {
            "observer_projection": {
                "schema_id": observer_projection["schema_id"],
                "media_type": "application/json",
                "path": "observer-projection.json",
                "sha256": sha256_digest(observer_projection),
            },
            "receipt_stream": {
                "schema_id": receipt_stream["schema_id"],
                "media_type": "application/json",
                "path": "receipt-stream.json",
                "sha256": sha256_digest(receipt_stream),
            },
        },
        "provenance": dict(provenance),
    }
    validate_verifier_bundle(payload, observer_projection, receipt_stream)
    return payload


class VercloInputAdapter:
    """Translate only validated verifier-visible documents into VERCLO models."""

    def __init__(
        self,
        manifest: Mapping[str, Any],
        observer_projection: Mapping[str, Any],
        receipt_stream: Mapping[str, Any],
        *,
        canary_values: Sequence[str] = (),
    ) -> None:
        validate_verifier_bundle(
            manifest,
            observer_projection,
            receipt_stream,
            canary_values=canary_values,
        )
        self.manifest = manifest
        self.observer_projection = observer_projection
        self.receipt_stream = receipt_stream

    def case_payload(self) -> dict[str, Any]:
        """Return the exact mapping admitted by ErasureCaseManager."""

        case = self.observer_projection["case"]
        return {
            "run_id": self.manifest["run_id"],
            "dataset_id": case["dataset_id"],
            "correlation_id": case["correlation_id"],
            "request_id": case["request_id"],
            "requester_principal_id": case["requester_principal_id"],
            "root_asset_ids": list(case["root_asset_ids"]),
            "policy_profile_id": self.observer_projection["policy"]["profile_id"],
            "accepted_at": case["accepted_at"],
            "case_id": self.manifest["case_id"],
            "metadata": dict(case.get("metadata", {})),
        }

    def topology_view(self) -> Any:
        """Create the existing VERCLO TopologyView without importing PaEGen."""

        from verclo.models import (  # type: ignore[import-not-found]
            AssetDescriptor,
            LineageEdge,
            ReplicaDescriptor,
            RepositoryDescriptor,
            TopologyView,
            Visibility,
        )

        case = self.observer_projection["case"]
        topology = self.observer_projection["topology"]
        return TopologyView(
            case_id=self.manifest["case_id"],
            dataset_id=case["dataset_id"],
            correlation_id=case["correlation_id"],
            scope_version=topology["scope_version"],
            assets=tuple(
                AssetDescriptor(
                    row["asset_id"], row["dataset_id"], row["asset_kind"], Visibility(row["visibility"])
                )
                for row in topology["assets"]
            ),
            repositories=tuple(
                RepositoryDescriptor(
                    row["repository_id"], row["organization_id"], row["custodian_principal_id"],
                    row["repository_class"], Visibility(row["visibility"])
                )
                for row in topology["repositories"]
            ),
            replicas=tuple(
                ReplicaDescriptor(
                    row["replica_id"], row["asset_id"], row["repository_id"],
                    row["replica_class"], Visibility(row["visibility"])
                )
                for row in topology["replicas"]
            ),
            lineage_edges=tuple(
                LineageEdge(
                    row["relationship_id"], row["parent_asset_id"], row["child_asset_id"],
                    row["relationship_type"], Visibility(row["visibility"])
                )
                for row in topology["lineage_edges"]
            ),
            scope_commitment=topology.get("scope_commitment"),
            graph_available=topology["graph_available"],
            declared_scope_complete=topology["declared_scope_complete"],
            unresolved_reference_ids=tuple(topology["unresolved_reference_ids"]),
        )

    def receipts(self) -> tuple[Any, ...]:
        """Create VERCLO receipt assertions; proof validity remains backend-owned."""

        from evidence.models import CustodianReceipt  # type: ignore[import-not-found]

        output = []
        for row in self.receipt_stream["receipts"]:
            output.append(
                CustodianReceipt(
                    receipt_id=row["receipt_id"],
                    case_id=row["case_id"],
                    obligation_id=row["obligation_id"],
                    asset_id=row["asset_id"],
                    replica_id=row["replica_id"],
                    repository_id=row["repository_id"],
                    issuer_principal_id=row["issuer_principal_id"],
                    issuer_role=row["issuer_role"],
                    trust_domain=row["trust_domain"],
                    fault_domain=row["fault_domain"],
                    evidence_type=row["evidence_type"],
                    disposition=row["disposition"],
                    event_time=_parse_timestamp(row["event_time"]),
                    submitted_at=_parse_timestamp(row["submitted_at"]),
                    not_before=_parse_timestamp(row["not_before"]),
                    expires_at=_parse_timestamp(row["expires_at"]) if row.get("expires_at") else None,
                    provenance_refs=tuple(row["provenance_refs"]),
                    canonical_payload_valid=True,
                    obligation_bound=True,
                    claim_commitment=row["claim_commitment"],
                )
            )
        return tuple(output)

    def verification_material(self) -> dict[str, Mapping[str, Any]]:
        """Expose public proof references for the configured validation backend."""

        return {
            row["receipt_id"]: dict(row["proof"])
            for row in self.receipt_stream["receipts"]
        }

    def open_challenge_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                row["challenge_id"]
                for row in self.observer_projection["challenges"]
                if row["status"] == "OPEN"
            )
        )


def build_verclo_result(
    *,
    report: Any,
    manifest: Mapping[str, Any],
    observer_projection: Mapping[str, Any],
    receipt_stream: Mapping[str, Any],
    evaluated_at: datetime | str,
    execution: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Freeze a VERCLO report in the versioned exchange format."""

    validate_verifier_bundle(manifest, observer_projection, receipt_stream)
    if report.case_id != manifest["case_id"]:
        raise ValueError("VERCLO report case_id does not match the exchange")
    obligation_results = [
        {
            "obligation_id": row.obligation_id,
            "category": row.category.value,
            "evidence_grade": row.evidence_grade,
            "required_grade": row.required_grade,
            "disposition": row.disposition,
            "receipt_ids": list(row.receipt_ids),
            "reason_codes": list(row.reason_codes),
        }
        for row in report.obligation_results
    ]
    payload = {
        "schema_id": "https://paeforge.local/schema/verclo-result/v1",
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "model_version": MODEL_VERSION,
        "data_class": "SYSTEM_OUTPUT",
        "exchange_id": manifest["exchange_id"],
        "run_id": manifest["run_id"],
        "scenario_id": manifest["scenario_id"],
        "case_id": manifest["case_id"],
        "seed": _seed_ref(manifest["seed"]),
        "evaluated_at": _timestamp(evaluated_at),
        "evaluated_revision": report.evaluated_revision,
        "closure_class": report.closure_class.value,
        "obligation_results": obligation_results,
        "obligation_sets": {
            "covered": list(report.covered_obligation_ids),
            "missing": list(report.missing_obligation_ids),
            "excepted": list(report.excepted_obligation_ids),
            "invalid": list(report.invalid_obligation_ids),
            "late": list(report.late_obligation_ids),
            "contradictory": list(report.contradictory_obligation_ids),
        },
        "visibility_limitation": report.visibility_limitation,
        "visibility_reason_codes": list(report.visibility_reason_codes),
        "reason_codes": list(report.reason_codes),
        "explanation": report.explanation,
        "physical_destruction_concluded": False,
        "input_commitments": {
            "case_manifest_sha256": sha256_digest(manifest),
            "observer_projection_sha256": sha256_digest(observer_projection),
            "receipt_stream_sha256": sha256_digest(receipt_stream),
        },
        "execution": dict(execution),
        "provenance": dict(provenance),
    }
    validate_document(payload)
    return payload


