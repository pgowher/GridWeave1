"""Independent receipt, anchor, dependency, coverage, and sufficiency verification."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.catalog import CatalogBuild
from htgl_dataset_generator.config import ResolvedConfig, build_run_plan
from htgl_dataset_generator.dag import CausalDagBuild
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import CounterRng, seed_stream_records_for_plan
from htgl_dataset_generator.world import FederatedWorld

from .builder import EvidenceObligationBuild, EvidenceObligationError
from .canonical import ReceiptPayloadFacts, canonical_digest, canonical_receipt_payload
from .crypto import derive_synthetic_key, verify_authenticator
from .fixtures import EvidenceReceiptFixture, SyntheticAnchorFixture, SyntheticKeyFixture
from .merkle import verify_merkle_path
from .profiles import ReceiptProfileBundle, load_receipt_profile_bundle
from .sufficiency import EvidenceSufficiencyBuild, evaluate_evidence_sufficiency


@dataclass(frozen=True)
class ReceiptVerificationTruth:
    receipt_id: str
    canonical_payload_valid: bool
    canonical_digest_valid: bool
    algorithm_valid: bool
    key_valid: bool
    authenticator_valid: bool
    anchor_valid: bool
    coverage_valid: bool
    timely: bool
    dependency_complete: bool
    contradiction_free: bool
    expected_status: str
    declared_status: str
    truth_matches_declared: bool


@dataclass(frozen=True)
class EvidenceVerificationDiagnostics:
    receipt_count: int
    valid_count: int
    invalid_count: int
    expired_count: int
    missing_dependency_count: int
    contradiction_count: int
    truth_mismatch_count: int


@dataclass(frozen=True)
class EvidenceVerificationBuild:
    truth: tuple[ReceiptVerificationTruth, ...]
    diagnostics: EvidenceVerificationDiagnostics
    sufficiency: EvidenceSufficiencyBuild


def verify_evidence_receipts(
    resolved: ResolvedConfig,
    receipts: Sequence[Mapping[str, Any]],
    fixtures: Sequence[EvidenceReceiptFixture],
    key_fixtures: Sequence[SyntheticKeyFixture],
    anchors: Sequence[SyntheticAnchorFixture],
    obligations: EvidenceObligationBuild,
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
    replicate_id: int,
    scenario_ids: Iterable[str] | None = None,
    profile_bundle: ReceiptProfileBundle | None = None,
    contract: ContractSpec | None = None,
    require_truth_match: bool = True,
) -> EvidenceVerificationBuild:
    """Recompute receipt truth without trusting generator-declared status labels."""

    schema_contract = contract if contract is not None else load_contract()
    bundle = profile_bundle or load_receipt_profile_bundle(resolved, contract=schema_contract)
    obligation_by_id = {str(row["obligation_id"]): row for row in obligations.evidence_obligations}
    provenance_by_id = {item.obligation_id: item for item in obligations.provenance}
    event_by_id = {str(row["event_id"]): row for row in causal_dag.governance_events}
    actor_ids = {str(row["actor_id"]) for row in world.actors}
    fixture_by_id = _unique_by(fixtures, lambda item: item.receipt_id, "receipt fixtures")
    key_by_id = _unique_by(key_fixtures, lambda item: item.key_id, "synthetic key fixtures")
    anchor_by_id = _unique_by(anchors, lambda item: item.anchor_id, "synthetic anchors")
    receipt_rows: dict[str, dict[str, Any]] = {}
    for raw in receipts:
        row = dict(raw)
        validate_record(schema_contract, "evidence_receipt", row)
        receipt_id = str(row["receipt_id"])
        if receipt_id in receipt_rows:
            raise EvidenceObligationError(f"duplicate evidence receipt_id={receipt_id}")
        if str(row["obligation_id"]) not in obligation_by_id:
            raise EvidenceObligationError(f"receipt {receipt_id}: obligation does not resolve")
        if str(row["event_id"]) not in event_by_id:
            raise EvidenceObligationError(f"receipt {receipt_id}: event does not resolve")
        if str(row["issuer_actor_id"]) not in actor_ids:
            raise EvidenceObligationError(f"receipt {receipt_id}: issuer actor does not resolve")
        receipt_rows[receipt_id] = row
    if set(receipt_rows) != set(fixture_by_id):
        raise EvidenceObligationError(
            "every emitted receipt must have exactly one evaluator-only fixture: "
            f"missing={sorted(set(receipt_rows)-set(fixture_by_id))[:8]} "
            f"orphan={sorted(set(fixture_by_id)-set(receipt_rows))[:8]}"
        )

    preliminary: dict[str, ReceiptVerificationTruth] = {}
    for receipt_id in sorted(receipt_rows):
        row = receipt_rows[receipt_id]
        fixture = fixture_by_id[receipt_id]
        obligation = obligation_by_id[str(row["obligation_id"])]
        provenance = provenance_by_id[str(row["obligation_id"])]
        profile = bundle.profile(str(row["evidence_type"]))
        rng = _evidence_rng(resolved, _scenario_for_event(event_by_id[str(obligation["event_id"])]), replicate_id)
        facts = ReceiptPayloadFacts(
            receipt_id=receipt_id,
            obligation_id=str(row["obligation_id"]),
            evidenced_event_id=str(row["event_id"]),
            triggering_event_id=str(obligation["event_id"]),
            policy_rule_id=str(obligation["policy_rule_id"]),
            subject_object_id=str(obligation["subject_object_id"]),
            responsible_actor_id=str(obligation["responsible_actor_id"]),
            issuer_actor_id=str(row["issuer_actor_id"]),
            evidence_type=str(row["evidence_type"]),
            issued_at=str(row["issued_at"]),
            due_at=str(obligation["due_at"]),
            coverage_scope=str(obligation["coverage_scope"]),
            covers_replica_ids=tuple(str(value) for value in row["covers_replica_ids"]),
        )
        expected_payload = canonical_receipt_payload(facts, profile=profile, bundle=bundle, contract=schema_contract)
        try:
            detached_payload = bytes.fromhex(fixture.canonical_payload_hex)
            detached_payload_well_formed = bool(detached_payload)
        except ValueError:
            detached_payload = b""
            detached_payload_well_formed = False
        canonical_payload_valid = detached_payload_well_formed and detached_payload == expected_payload
        row_digest = str(row["canonical_digest"]).lower()
        canonical_digest_valid = row_digest == canonical_digest(detached_payload)
        algorithm_valid = str(row["algorithm"]) == profile.algorithm
        expected_key = None
        expected_key_id: str | None = None
        key_valid = row["key_id"] is None and fixture.claimed_key_id is None
        if profile.requires_key:
            expected_key = derive_synthetic_key(
                rng,
                subject_actor_id=str(row["issuer_actor_id"]),
                primitive=profile.primitive,
                algorithm=profile.algorithm,
            )
            expected_key_id = expected_key.fixture.key_id
            key_valid = (
                str(row["key_id"]) == expected_key_id
                and fixture.claimed_key_id == expected_key_id
                and key_by_id.get(expected_key_id) == expected_key.fixture
            )
        try:
            authenticator = bytes.fromhex(fixture.authenticator_hex)
        except ValueError:
            authenticator = b""
        authenticator_valid = verify_authenticator(profile, detached_payload, authenticator, expected_key)
        anchor_valid = _anchor_valid(row, fixture, profile, bundle, anchor_by_id)
        timely = _timestamp(str(row["issued_at"])) <= _timestamp(str(obligation["due_at"]))
        dependency_complete = str(row["event_id"]) in set(provenance.dependency_event_ids)
        coverage_valid = _coverage_valid(row, obligation, provenance)
        cryptographic_fixture_valid = all(
            (
                canonical_payload_valid,
                canonical_digest_valid,
                algorithm_valid,
                key_valid,
                authenticator_valid,
                anchor_valid,
            )
        )
        if not cryptographic_fixture_valid:
            expected_status = "invalid"
        elif not dependency_complete:
            expected_status = "missing_dependency"
        elif not coverage_valid:
            expected_status = "invalid"
        elif not timely:
            expected_status = "expired"
        else:
            expected_status = "valid"
        declared = str(row["verification_status_truth"])
        preliminary[receipt_id] = ReceiptVerificationTruth(
            receipt_id=receipt_id,
            canonical_payload_valid=canonical_payload_valid,
            canonical_digest_valid=canonical_digest_valid,
            algorithm_valid=algorithm_valid,
            key_valid=key_valid,
            authenticator_valid=authenticator_valid,
            anchor_valid=anchor_valid,
            coverage_valid=coverage_valid,
            timely=timely,
            dependency_complete=dependency_complete,
            contradiction_free=True,
            expected_status=expected_status,
            declared_status=declared,
            truth_matches_declared=declared == expected_status,
        )

    contradictory_ids = _contradictory_ids(receipt_rows)
    truth: list[ReceiptVerificationTruth] = []
    for receipt_id in sorted(preliminary):
        item = preliminary[receipt_id]
        if receipt_id in contradictory_ids:
            item = replace(
                item,
                contradiction_free=False,
                expected_status="invalid",
                truth_matches_declared=item.declared_status == "invalid",
            )
        truth.append(item)
    mismatch_ids = tuple(item.receipt_id for item in truth if not item.truth_matches_declared)
    if mismatch_ids and require_truth_match:
        raise EvidenceObligationError(
            f"receipt verification truth differs from declared status for {len(mismatch_ids)} rows; "
            f"sample={mismatch_ids[:8]}"
        )
    independently_labeled = []
    truth_by_id = {item.receipt_id: item for item in truth}
    for receipt_id, row in sorted(receipt_rows.items()):
        normalized = dict(row)
        normalized["verification_status_truth"] = truth_by_id[receipt_id].expected_status
        independently_labeled.append(normalized)
    sufficiency = evaluate_evidence_sufficiency(
        obligations,
        independently_labeled,
        world=world,
        catalog=catalog,
        causal_dag=causal_dag,
        contract=schema_contract,
    )
    statuses = [item.expected_status for item in truth]
    diagnostics = EvidenceVerificationDiagnostics(
        receipt_count=len(truth),
        valid_count=statuses.count("valid"),
        invalid_count=statuses.count("invalid"),
        expired_count=statuses.count("expired"),
        missing_dependency_count=statuses.count("missing_dependency"),
        contradiction_count=len(contradictory_ids),
        truth_mismatch_count=len(mismatch_ids),
    )
    return EvidenceVerificationBuild(tuple(truth), diagnostics, sufficiency)


def _anchor_valid(
    row: Mapping[str, Any],
    fixture: EvidenceReceiptFixture,
    profile: Any,
    bundle: ReceiptProfileBundle,
    anchors: Mapping[str, SyntheticAnchorFixture],
) -> bool:
    if not profile.requires_anchor:
        return row["anchor_id"] is None and not fixture.merkle_path
    anchor_id = row["anchor_id"]
    if not isinstance(anchor_id, str) or anchor_id not in anchors:
        return False
    anchor = anchors[anchor_id]
    try:
        anchor_profile = bundle.anchor_profile(anchor.anchor_profile_id)
    except ValueError:
        return False
    return (
        anchor.algorithm == anchor_profile.algorithm
        and verify_merkle_path(
            str(row["canonical_digest"]),
            fixture.merkle_path,
            root_digest=anchor.root_digest,
            profile=anchor_profile,
        )
    )


def _coverage_valid(row: Mapping[str, Any], obligation: Mapping[str, Any], provenance: Any) -> bool:
    scope = str(obligation["coverage_scope"])
    event_id = str(row["event_id"])
    issuer_id = str(row["issuer_actor_id"])
    covers = tuple(sorted(str(value) for value in row["covers_replica_ids"]))
    members = set(provenance.coverage_member_ids)
    if scope == "object":
        return event_id == str(obligation["event_id"]) and not covers and str(obligation["subject_object_id"]) in members
    if scope == "replica_set":
        return covers == (str(obligation["subject_object_id"]),) and covers[0] in members
    if scope in {"workflow", "causal_closure"}:
        return event_id in members and not covers
    if scope == "actor_set":
        return event_id == str(obligation["event_id"]) and issuer_id in members and not covers
    return False


def _contradictory_ids(receipts: Mapping[str, Mapping[str, Any]]) -> set[str]:
    groups: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
    for row in receipts.values():
        key = (
            str(row["obligation_id"]),
            str(row["event_id"]),
            str(row["evidence_type"]),
            str(row["issuer_actor_id"]),
        )
        groups.setdefault(key, []).append(row)
    result: set[str] = set()
    for rows in groups.values():
        semantic_outputs = {
            (str(row["canonical_digest"]), tuple(sorted(str(value) for value in row["covers_replica_ids"])))
            for row in rows
        }
        if len(rows) > 1 and len(semantic_outputs) > 1:
            result.update(str(row["receipt_id"]) for row in rows)
    return result


def _evidence_rng(resolved: ResolvedConfig, scenario_id: str, replicate_id: int) -> CounterRng:
    plans = [
        plan
        for plan in build_run_plan(resolved)
        if plan.scenario_id == scenario_id and plan.replicate_id == replicate_id
    ]
    if len(plans) != 1:
        raise EvidenceObligationError(
            f"cannot resolve one S10.evidence stream for scenario={scenario_id} replicate={replicate_id}"
        )
    rows = seed_stream_records_for_plan(resolved, plans[0], include_common_random_groups=False)
    matching = [row for row in rows if str(row["stream_name"]).endswith("component=S10.evidence|partition=global")]
    if len(matching) != 1:
        raise EvidenceObligationError("S10.evidence named seed stream is missing or duplicated")
    return CounterRng(str(matching[0]["seed_material_hex"]))


def _scenario_for_event(event: Mapping[str, Any]) -> str:
    scenario_id = event.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise EvidenceObligationError("governance event is missing scenario_id")
    return scenario_id


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceObligationError(f"invalid receipt timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise EvidenceObligationError(f"receipt timestamp must be normalized UTC: {value!r}")
    return parsed


def _unique_by(items: Sequence[Any], key: Any, label: str) -> Mapping[str, Any]:
    result: dict[str, Any] = {}
    for item in items:
        item_key = str(key(item))
        if item_key in result:
            raise EvidenceObligationError(f"duplicate {label} ID={item_key}")
        result[item_key] = item
    return result
