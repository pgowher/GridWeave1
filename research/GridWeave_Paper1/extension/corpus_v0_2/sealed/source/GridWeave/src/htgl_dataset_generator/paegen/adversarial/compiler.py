"""Apply each attack independently to a clean canonical PaEGen trace."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex
from htgl_dataset_generator.observers import ObserverReleaseView
from htgl_dataset_generator.seeds import content_id

from .._canonical import artifact
from ..models import PaEGenArtifact
from ..public import build_observer_artifacts
from ..smart_grid import compile_smart_grid_benchmark
from .loader import AdversarialControlBundle, load_adversarial_controls


@dataclass(frozen=True)
class AdversarialFixtureResult:
    fixture_id: str
    attack_type: str
    scenario_id: str
    clean_ground_truth: PaEGenArtifact
    attacked_ground_truth: PaEGenArtifact
    observer_views: Mapping[str, PaEGenArtifact]
    expected_oracle_outcome: str
    expected_verifier_outcome: str
    expected_detection: str
    indistinguishability_class: str | None


@dataclass(frozen=True)
class AdversarialCampaign:
    control_digest: str
    fixtures: tuple[AdversarialFixtureResult, ...]


def _outcome(case: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    rows = case["dispositions"]
    if any("CONTRADICTORY_EVIDENCE" in row["reason_codes"] for row in rows):
        return "DISPUTED", ("UNRESOLVED_CONTRADICTION",)
    resolved = [row for row in rows if row["status"] in {"SUCCESS", "EXCEPTION"}]
    if len(resolved) == len(rows):
        if any(row["status"] == "EXCEPTION" for row in rows):
            return "CLOSED_WITH_EXCEPTIONS", ("ALL_OBLIGATIONS_RESOLVED", "VALID_EXCEPTION_PRESENT")
        return "CLOSED", ("ALL_OBLIGATIONS_RESOLVED",)
    if resolved:
        return "PARTIALLY_CLOSED", ("RESOLVED_AND_UNRESOLVED_OBLIGATIONS",)
    return "OPEN", ("NO_ADMISSIBLE_TERMINAL_RESOLUTION",)


def _mark_unresolved(case: dict[str, Any], index: int, reason: str) -> str:
    disposition = case["dispositions"][index]
    disposition["status"] = "UNRESOLVED"
    disposition["reason_codes"] = [reason]
    obligation_id = str(disposition["obligation_id"])
    return obligation_id


def _evidence_for(case: Mapping[str, Any], obligation_id: str) -> list[dict[str, Any]]:
    return [item for item in case["evidence"] if item["receipt"]["obligation_id"] == obligation_id]


def _visible_declaration(records: list[dict[str, Any]]) -> dict[str, Any]:
    return next(row for row in records if row["record_type"] == "case_declaration")


def _visible_evidence(records: list[dict[str, Any]], obligation_id: str) -> list[dict[str, Any]]:
    declaration = _visible_declaration(records)
    return [row for row in declaration["submitted_evidence"] if row["obligation_id"] == obligation_id]


def _add_hidden_obligation(case: dict[str, Any], fixture: Mapping[str, Any], *, derivative: bool) -> None:
    source = copy.deepcopy(case["obligation_graph"]["obligations"][fixture["target_obligation_index"]])
    hidden_asset_id = content_id("paebench_hidden_asset_v1", fixture["fixture_id"])
    hidden_replica_id = content_id("paebench_hidden_replica_v1", fixture["fixture_id"])
    obligation_id = content_id("paebench_hidden_obligation_v1", fixture["fixture_id"])
    source["obligation_id"] = obligation_id
    source["responsible_principal_id"] = "ORG-UNDISCLOSED-RECIPIENT"
    source["coverage_member_ids"] = [hidden_replica_id]
    source["exempt_member_ids"] = []
    if derivative:
        source_asset = source["subject_asset_id"]
        source["subject_asset_id"] = hidden_asset_id
        case["obligation_graph"]["asset_ids"].append(hidden_asset_id)
        case["obligation_graph"]["replica_ids"].append(hidden_replica_id)
        case["obligation_graph"]["relationship_edges"].extend([
            {
                "edge_id": content_id("paebench_hidden_lineage_edge_v1", fixture["fixture_id"]),
                "scenario_id": fixture["scenario_id"], "edge_type": "derived_from",
                "source_id": source_asset, "target_id": hidden_asset_id,
                "source_table": "data_object", "target_table": "data_object",
                "reason_code": "evaluator_only_hidden_derivative",
            },
            {
                "edge_id": content_id("paebench_hidden_custody_edge_v1", fixture["fixture_id"]),
                "scenario_id": fixture["scenario_id"], "edge_type": "replicated_to",
                "source_id": hidden_asset_id, "target_id": hidden_replica_id,
                "source_table": "data_object", "target_table": "data_object_replica",
                "reason_code": "evaluator_only_hidden_repository",
            },
        ])
    case["obligation_graph"]["obligations"].append(source)
    case["dispositions"].append({
        "obligation_id": obligation_id,
        "status": "UNRESOLVED",
        "world_disposition": "UNKNOWN",
        "evidence_ids": [],
        "reason_codes": ["MISSING_RECIPIENT" if not derivative else "HIDDEN_DERIVATIVE"],
    })


def _apply_attack(
    ground_payload: dict[str, Any], records: list[dict[str, Any]], fixture: Mapping[str, Any]
) -> None:
    case = ground_payload["cases"][0]
    index = int(fixture["target_obligation_index"])
    if index >= len(case["dispositions"]):
        raise ValueError(f"{fixture['fixture_id']}: target obligation index is out of range")
    attack = str(fixture["attack_type"])
    if attack == "MISSING_RECIPIENT":
        _add_hidden_obligation(case, fixture, derivative=False)
    elif attack == "HIDDEN_DERIVATIVE":
        _add_hidden_obligation(case, fixture, derivative=True)
    elif attack == "INCOMPLETE_LINEAGE":
        for asset in _visible_declaration(records)["assets"]:
            asset.pop("parent_asset_ids", None)
    else:
        reason = {
            "FORGED_RECEIPT": "INVALID_EVIDENCE",
            "MALFORMED_RECEIPT": "INVALID_EVIDENCE",
            "BACKDATING": "BACKDATED_EVIDENCE",
            "DELAY": "LATE_EVIDENCE",
            "CONTRADICTION": "CONTRADICTORY_EVIDENCE",
            "COLLUSION": "CONTRADICTORY_EVIDENCE",
        }.get(attack)
        obligation_id = str(case["dispositions"][index]["obligation_id"])
        items = _evidence_for(case, obligation_id)
        visible = _visible_evidence(records, obligation_id)
        if not items or not visible:
            raise ValueError(f"{fixture['fixture_id']}: target has no evidence")
        if attack == "REPLAY":
            case["evidence"].append(copy.deepcopy(items[0]))
            _visible_declaration(records)["submitted_evidence"].append(copy.deepcopy(visible[0]))
        else:
            _mark_unresolved(case, index, str(reason))
            verification = items[0]["verification"]
            receipt = items[0]["receipt"]
            if attack == "FORGED_RECEIPT":
                verification["authenticator_valid"] = False
                verification["expected_status"] = "forged"
                receipt["verification_status_truth"] = "forged"
                visible[0]["authenticator"] = "00-invalid-synthetic-signature"
            elif attack == "MALFORMED_RECEIPT":
                receipt.pop("canonical_digest", None)
                verification["canonical_payload_valid"] = False
                verification["canonical_digest_valid"] = False
                visible[0]["canonical_digest"] = None
            elif attack == "BACKDATING":
                accepted = datetime.fromisoformat(case["accepted_at"].replace("Z", "+00:00"))
                issued = accepted + timedelta(seconds=int(fixture["parameters"]["offset_seconds"]))
                receipt["issued_at"] = issued.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                verification["timely"] = False
                visible[0]["issued_at"] = receipt["issued_at"]
            elif attack == "DELAY":
                deadline = datetime.fromisoformat(
                    case["obligation_graph"]["obligations"][index]["deadline"].replace("Z", "+00:00")
                )
                issued = deadline + timedelta(seconds=int(fixture["parameters"]["after_deadline_seconds"]))
                receipt["issued_at"] = issued.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                verification["timely"] = False
                visible[0]["issued_at"] = receipt["issued_at"]
            elif attack == "CONTRADICTION":
                receipt["claimed_disposition"] = "ERASED"
                conflicting = copy.deepcopy(items[0])
                new_id = content_id("paebench_conflicting_receipt_v1", fixture["fixture_id"])
                conflicting["receipt"]["receipt_id"] = new_id
                conflicting["receipt"]["claimed_disposition"] = "RETAINED"
                conflicting["receipt"]["verification_status_truth"] = "contradictory"
                conflicting["verification"]["receipt_id"] = new_id
                conflicting["verification"]["contradiction_free"] = False
                case["evidence"].append(conflicting)
                visible[0]["claimed_disposition"] = "ERASED"
                other = copy.deepcopy(visible[0])
                other["receipt_id"] = new_id
                other["claimed_disposition"] = "RETAINED"
                _visible_declaration(records)["submitted_evidence"].append(other)
            elif attack == "COLLUSION":
                receipt["collusion_truth"] = True
                verification["contradiction_free"] = False
                for colluder_index in range(1, int(fixture["parameters"]["colluder_count"])):
                    other = copy.deepcopy(visible[0])
                    other["receipt_id"] = content_id(
                        "paebench_collusive_receipt_v1",
                        {"fixture_id": fixture["fixture_id"], "index": colluder_index},
                    )
                    _visible_declaration(records)["submitted_evidence"].append(other)


def _scan_forbidden(value: Any, forbidden: frozenset[str], hidden: frozenset[str]) -> None:
    if isinstance(value, Mapping):
        collisions = (set(map(str, value.keys())) & forbidden) | (set(map(str, value.keys())) & hidden)
        if collisions:
            raise ValueError(f"restricted projection leaked protected fields: {sorted(collisions)}")
        for child in value.values():
            _scan_forbidden(child, forbidden, hidden)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _scan_forbidden(child, forbidden, hidden)


def compile_adversarial_campaign(
    controls: AdversarialControlBundle | None = None,
    *,
    root_seed: str = "PAEBENCH-ADVERSARIAL-v1",
) -> AdversarialCampaign:
    """Create one paired clean/attacked fixture for every independent attack type."""

    bundle = controls or load_adversarial_controls()
    baseline = compile_smart_grid_benchmark(root_seed=root_seed)
    successful = {
        replica.scenario_id: replica for replica in baseline.replicas
        if replica.ground_truth.payload["variant_class"] == "successful_closure"
    }
    results: list[AdversarialFixtureResult] = []
    for fixture in bundle.fixtures:
        clean = successful[str(fixture["scenario_id"])]
        attacked_payload = copy.deepcopy(clean.ground_truth.payload)
        attacked_payload["variant_id"] = str(fixture["fixture_id"]).lower()
        attacked_payload["variant_class"] = "adversarial_or_disputed"
        attacked_payload["seed_stream_digest"] = sha256_hex(canonical_json_bytes({
            "baseline": clean.ground_truth.sha256,
            "control_digest": bundle.digest,
            "fixture_id": fixture["fixture_id"],
        }))
        source_profile = bundle.projection_profiles[str(fixture["projection_profile_id"])]["source_profile_id"]
        source_artifact = clean.observer_views[str(source_profile)]
        records = copy.deepcopy(list(source_artifact.payload["records"]))
        _apply_attack(attacked_payload, records, fixture)
        outcome, reasons = _outcome(attacked_payload["cases"][0])
        case = attacked_payload["cases"][0]
        case["closure_ground_truth"] = {
            "outcome": outcome,
            "resolved_obligation_ids": [row["obligation_id"] for row in case["dispositions"] if row["status"] in {"SUCCESS", "EXCEPTION"}],
            "unresolved_obligation_ids": [row["obligation_id"] for row in case["dispositions"] if row["status"] == "UNRESOLVED"],
            "reason_codes": list(reasons),
        }
        if outcome != fixture["expected_oracle_outcome"]:
            raise ValueError(
                f"{fixture['fixture_id']}: derived oracle outcome {outcome}, "
                f"expected {fixture['expected_oracle_outcome']}"
            )
        projection_profile = bundle.projection_profiles[str(fixture["projection_profile_id"])]
        _scan_forbidden(records, bundle.forbidden_fields, bundle.hidden_topology_fields)
        observer_views = build_observer_artifacts(
            run_id=str(attacked_payload["run_id"]),
            scenario_id=str(attacked_payload["scenario_id"]),
            replicate_id=int(attacked_payload["replicate_id"]),
            config_sha256=str(attacked_payload["config_sha256"]),
            release_views={
                str(projection_profile["profile_id"]): ObserverReleaseView(
                    profile_id=str(projection_profile["profile_id"]),
                    access_class="restricted",
                    schema_profile_id="paebench.adversarial.restricted.v1",
                    records=tuple(records),
                )
            },
        )
        attacked = artifact(clean.ground_truth.schema_id, attacked_payload)
        results.append(AdversarialFixtureResult(
            fixture_id=str(fixture["fixture_id"]),
            attack_type=str(fixture["attack_type"]),
            scenario_id=str(fixture["scenario_id"]),
            clean_ground_truth=clean.ground_truth,
            attacked_ground_truth=attacked,
            observer_views=observer_views,
            expected_oracle_outcome=str(fixture["expected_oracle_outcome"]),
            expected_verifier_outcome=str(fixture["expected_verifier_outcome"]),
            expected_detection=str(fixture["expected_detection"]),
            indistinguishability_class=(
                str(fixture["indistinguishability_class"])
                if fixture["indistinguishability_class"] is not None else None
            ),
        ))
    return AdversarialCampaign(control_digest=bundle.digest, fixtures=tuple(results))
