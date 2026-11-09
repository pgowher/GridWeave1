"""S10 deterministic obligation-bound evidence receipt and adversarial fixture generator."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from htgl_dataset_generator.arrivals import ArrivalBuild, build_arrivals
from htgl_dataset_generator.catalog import CatalogBuild, build_catalog
from htgl_dataset_generator.config import ResolvedConfig, build_run_plan
from htgl_dataset_generator.dag import CausalDagBuild, build_causal_dag
from htgl_dataset_generator.physical import PhysicalRawBuild, build_physical_raw
from htgl_dataset_generator.policy import PolicyOracleBuild, build_policy_oracle
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import CounterRng, content_id, deterministic_uuid, seed_stream_records_for_plan
from htgl_dataset_generator.workflows import WorkflowBuild, build_workflows
from htgl_dataset_generator.world import FederatedWorld, build_federated_world

from .builder import EvidenceObligationBuild, EvidenceObligationError, EvidenceObligationProvenance, build_evidence_obligations
from .canonical import ReceiptPayloadFacts, canonical_digest, canonical_receipt_payload, normalize_utc_timestamp
from .crypto import DerivedSyntheticKey, authenticate, derive_synthetic_key
from .fixtures import (
    AdversarialReceiptCase,
    EvidenceReceiptFixture,
    SyntheticAnchorFixture,
    SyntheticKeyFixture,
)
from .merkle import build_merkle_anchor
from .profiles import ADVERSARIAL_CASE_TYPES, ReceiptProfile, ReceiptProfileBundle, load_receipt_profile_bundle
from .verification import EvidenceVerificationBuild, verify_evidence_receipts


@dataclass(frozen=True)
class EvidenceReceiptDiagnostics:
    scenario_id: str
    replicate_id: int
    coverage_unit_count: int
    emitted_receipt_count: int
    honest_unit_count: int
    adversarial_unit_count: int
    omitted_unit_count: int
    configured_honest_rate: float
    realized_honest_rate: float
    evidence_type_counts: Mapping[str, int]
    adversarial_case_counts: Mapping[str, int]


@dataclass(frozen=True)
class EvidenceReceiptBuild:
    evidence_receipts: tuple[dict[str, Any], ...]
    receipt_fixtures: tuple[EvidenceReceiptFixture, ...]
    synthetic_keys: tuple[SyntheticKeyFixture, ...]
    synthetic_anchors: tuple[SyntheticAnchorFixture, ...]
    adversarial_cases: tuple[AdversarialReceiptCase, ...]
    verification: EvidenceVerificationBuild
    diagnostics: Mapping[str, EvidenceReceiptDiagnostics]
    receipt_profile_bundle_sha256: str
    proof_limit_statement: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {"evidence_receipt": self.evidence_receipts}


@dataclass(frozen=True)
class _CoverageUnit:
    scenario_id: str
    obligation: Mapping[str, Any]
    provenance: EvidenceObligationProvenance
    coverage_member_id: str
    unit_index: int

    @property
    def key(self) -> str:
        return f"{self.obligation['obligation_id']}|{self.coverage_member_id}|{self.unit_index}"


def build_evidence_receipts(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    catalog: CatalogBuild | None = None,
    physical: PhysicalRawBuild | None = None,
    arrivals: ArrivalBuild | None = None,
    workflows: WorkflowBuild | None = None,
    causal_dag: CausalDagBuild | None = None,
    policy: PolicyOracleBuild | None = None,
    obligations: EvidenceObligationBuild | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    profile_path: Path | None = None,
    contract: ContractSpec | None = None,
) -> EvidenceReceiptBuild:
    """Generate schema-valid receipts plus evaluator-only verification fixtures."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(sorted(scenario_ids or resolved.run.selected_scenario_ids))
    if not selected:
        raise EvidenceObligationError("at least one scenario_id is required for evidence receipts")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise EvidenceObligationError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    world_build = world or build_federated_world(
        resolved, replicate_id=replicate_id, scenario_ids=selected, contract=schema_contract
    )
    catalog_build = catalog or build_catalog(
        resolved,
        world=world_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    physical_build = physical or build_physical_raw(
        resolved,
        world=world_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    arrival_build = arrivals or build_arrivals(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    workflow_build = workflows or build_workflows(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    dag_build = causal_dag or build_causal_dag(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        workflows=workflow_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    policy_build = policy or build_policy_oracle(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        workflows=workflow_build,
        causal_dag=dag_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    obligation_build = obligations or build_evidence_obligations(
        resolved,
        world=world_build,
        catalog=catalog_build,
        physical=physical_build,
        arrivals=arrival_build,
        workflows=workflow_build,
        causal_dag=dag_build,
        policy=policy_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        contract=schema_contract,
    )
    bundle = load_receipt_profile_bundle(resolved, profile_path, contract=schema_contract)
    obligation_by_id = {str(row["obligation_id"]): row for row in obligation_build.evidence_obligations}
    provenance_by_id = {item.obligation_id: item for item in obligation_build.provenance}
    event_by_id = {str(row["event_id"]): row for row in dag_build.governance_events}
    actor_ids = {str(row["actor_id"]) for row in world_build.actors}
    if set(obligation_by_id) != set(provenance_by_id):
        raise EvidenceObligationError("receipt generation requires complete obligation provenance")

    all_rows: list[dict[str, Any]] = []
    all_fixtures: list[EvidenceReceiptFixture] = []
    key_fixtures: dict[str, SyntheticKeyFixture] = {}
    all_cases: list[AdversarialReceiptCase] = []
    diagnostics: dict[str, EvidenceReceiptDiagnostics] = {}
    scenario_row_ids: dict[str, list[str]] = {}
    row_by_id: dict[str, dict[str, Any]] = {}
    fixture_by_id: dict[str, EvidenceReceiptFixture] = {}

    for scenario_id in selected:
        rng, namespace = _evidence_stream(resolved, scenario_id, replicate_id)
        scenario_obligation_ids = {
            obligation_id
            for obligation_id, row in obligation_by_id.items()
            if str(event_by_id[str(row["event_id"])]["scenario_id"]) == scenario_id
        }
        units = _coverage_units(scenario_obligation_ids, obligation_by_id, provenance_by_id)
        case_by_unit = _allocate_adversarial_cases(units, resolved, bundle, rng)
        scenario_cases: list[AdversarialReceiptCase] = []
        for unit in units:
            case_type = case_by_unit.get(unit.key, "valid")
            profile = _select_profile(unit, case_type, bundle, rng)
            if case_type == "incomplete":
                case = AdversarialReceiptCase(
                    case_id=content_id("adversarial_evidence_case", {"case_type": case_type, "unit": unit.key}),
                    case_type=case_type,
                    obligation_id=str(unit.obligation["obligation_id"]),
                    coverage_member_id=unit.coverage_member_id,
                    receipt_ids=(),
                    omission_reason="conditioned_adversarial_fixture_omission",
                )
                scenario_cases.append(case)
                continue
            variants = ("primary", "conflict") if case_type == "contradictory" else ("primary",)
            emitted_ids: list[str] = []
            contradiction_group_id = (
                content_id("evidence_contradiction_group", {"unit": unit.key})
                if case_type == "contradictory"
                else None
            )
            for variant in variants:
                row, fixture, generated_keys = _emit_receipt(
                    unit,
                    case_type,
                    variant,
                    profile,
                    bundle,
                    rng,
                    namespace,
                    event_by_id,
                    actor_ids,
                    contradiction_group_id,
                    schema_contract,
                )
                for key in generated_keys:
                    existing = key_fixtures.get(key.fixture.key_id)
                    if existing is not None and existing != key.fixture:
                        raise EvidenceObligationError(f"synthetic key ID collision {key.fixture.key_id}")
                    key_fixtures[key.fixture.key_id] = key.fixture
                validate_record(schema_contract, "evidence_receipt", row)
                receipt_id = str(row["receipt_id"])
                if receipt_id in row_by_id:
                    raise EvidenceObligationError(f"duplicate deterministic receipt_id={receipt_id}")
                row_by_id[receipt_id] = row
                fixture_by_id[receipt_id] = fixture
                scenario_row_ids.setdefault(scenario_id, []).append(receipt_id)
                emitted_ids.append(receipt_id)
            if case_type != "valid":
                scenario_cases.append(
                    AdversarialReceiptCase(
                        case_id=content_id("adversarial_evidence_case", {"case_type": case_type, "unit": unit.key}),
                        case_type=case_type,
                        obligation_id=str(unit.obligation["obligation_id"]),
                        coverage_member_id=unit.coverage_member_id,
                        receipt_ids=tuple(emitted_ids),
                        omission_reason=None,
                    )
                )
        all_cases.extend(scenario_cases)
        case_counts = {case: 0 for case in ADVERSARIAL_CASE_TYPES}
        for case in scenario_cases:
            case_counts[case.case_type] += 1
        honest_count = len(units) - len(scenario_cases)
        diagnostics[scenario_id] = EvidenceReceiptDiagnostics(
            scenario_id=scenario_id,
            replicate_id=replicate_id,
            coverage_unit_count=len(units),
            emitted_receipt_count=sum(len(case.receipt_ids) for case in scenario_cases) + honest_count,
            honest_unit_count=honest_count,
            adversarial_unit_count=len(scenario_cases),
            omitted_unit_count=case_counts["incomplete"],
            configured_honest_rate=resolved.evidence.honest_rate,
            realized_honest_rate=(honest_count / len(units)) if units else 0.0,
            evidence_type_counts={},
            adversarial_case_counts=dict(sorted(case_counts.items())),
        )

    anchors: list[SyntheticAnchorFixture] = []
    anchor_profile = bundle.anchor_profile(resolved.evidence.anchor_profiles[0])
    for scenario_id in selected:
        receipt_ids = tuple(sorted(scenario_row_ids.get(scenario_id, ())))
        anchor_required_ids = tuple(
            receipt_id
            for receipt_id in receipt_ids
            if bundle.profile(str(row_by_id[receipt_id]["evidence_type"])).requires_anchor
        )
        if not anchor_required_ids:
            continue
        anchor, paths = build_merkle_anchor(
            {receipt_id: str(row_by_id[receipt_id]["canonical_digest"]) for receipt_id in receipt_ids},
            profile=anchor_profile,
            scenario_id=scenario_id,
            replicate_id=replicate_id,
        )
        anchors.append(anchor)
        for receipt_id in anchor_required_ids:
            row_by_id[receipt_id]["anchor_id"] = anchor.anchor_id
            fixture_by_id[receipt_id] = replace(fixture_by_id[receipt_id], merkle_path=paths[receipt_id])

    for scenario_id, item in tuple(diagnostics.items()):
        type_counts: dict[str, int] = {}
        for receipt_id in scenario_row_ids.get(scenario_id, ()):
            evidence_type = str(row_by_id[receipt_id]["evidence_type"])
            type_counts[evidence_type] = type_counts.get(evidence_type, 0) + 1
        diagnostics[scenario_id] = replace(item, evidence_type_counts=dict(sorted(type_counts.items())))
    all_rows = [row_by_id[key] for key in sorted(row_by_id)]
    all_fixtures = [fixture_by_id[key] for key in sorted(fixture_by_id)]
    verification = verify_evidence_receipts(
        resolved,
        all_rows,
        all_fixtures,
        tuple(sorted(key_fixtures.values(), key=lambda item: item.key_id)),
        tuple(sorted(anchors, key=lambda item: item.anchor_id)),
        obligation_build,
        world=world_build,
        catalog=catalog_build,
        causal_dag=dag_build,
        replicate_id=replicate_id,
        scenario_ids=selected,
        profile_bundle=bundle,
        contract=schema_contract,
    )
    return EvidenceReceiptBuild(
        evidence_receipts=tuple(all_rows),
        receipt_fixtures=tuple(all_fixtures),
        synthetic_keys=tuple(sorted(key_fixtures.values(), key=lambda item: item.key_id)),
        synthetic_anchors=tuple(sorted(anchors, key=lambda item: item.anchor_id)),
        adversarial_cases=tuple(sorted(all_cases, key=lambda item: item.case_id)),
        verification=verification,
        diagnostics=dict(sorted(diagnostics.items())),
        receipt_profile_bundle_sha256=bundle.bundle_sha256,
        proof_limit_statement=bundle.proof_limit_statement,
    )


def _coverage_units(
    obligation_ids: set[str],
    obligations: Mapping[str, Mapping[str, Any]],
    provenance: Mapping[str, EvidenceObligationProvenance],
) -> tuple[_CoverageUnit, ...]:
    units: list[_CoverageUnit] = []
    for obligation_id in sorted(obligation_ids):
        row = obligations[obligation_id]
        source = provenance[obligation_id]
        members = tuple(source.coverage_member_ids)
        if not members:
            raise EvidenceObligationError(f"obligation {obligation_id}: no coverage members")
        target = max(len(members), int(row["minimum_count"]))
        for index in range(target):
            units.append(
                _CoverageUnit(
                    scenario_id=source.scenario_id,
                    obligation=row,
                    provenance=source,
                    coverage_member_id=members[index % len(members)],
                    unit_index=index,
                )
            )
    return tuple(sorted(units, key=lambda item: item.key))


def _allocate_adversarial_cases(
    units: Sequence[_CoverageUnit],
    resolved: ResolvedConfig,
    bundle: ReceiptProfileBundle,
    rng: CounterRng,
) -> Mapping[str, str]:
    target = min(len(units), int(math.floor(len(units) * resolved.evidence.adversarial_rate + 0.5)))
    if target == 0:
        return {}
    selected = sorted(units, key=lambda item: (rng.uint64(f"adversarial-select|{item.key}", 0), item.key))[:target]
    counts = _case_counts(target, resolved.evidence.adversarial_case_weights)
    unassigned = {item.key: item for item in selected}
    result: dict[str, str] = {}
    ordered_cases = ("forged_under_synthetic_key",) + tuple(
        case for case in bundle.adversarial_case_types if case != "forged_under_synthetic_key"
    )
    for case_type in ordered_cases:
        eligible = [
            item
            for item in unassigned.values()
            if case_type != "forged_under_synthetic_key"
            or any(bundle.profile(value).requires_key for value in item.obligation["required_evidence_types"])
        ]
        count = counts[case_type]
        if len(eligible) < count:
            raise EvidenceObligationError(
                f"cannot allocate {count} {case_type} fixtures to compatible receipt candidates"
            )
        chosen = sorted(
            eligible,
            key=lambda item: (rng.uint64(f"adversarial-case|{case_type}|{item.key}", 0), item.key),
        )[:count]
        for item in chosen:
            result[item.key] = case_type
            unassigned.pop(item.key)
    if unassigned:
        raise EvidenceObligationError("conditioned adversarial allocation left unassigned candidates")
    return dict(sorted(result.items()))


def _case_counts(total: int, weights: Mapping[str, float]) -> Mapping[str, int]:
    counts = {case: 0 for case in ADVERSARIAL_CASE_TYPES}
    remaining = total
    if total >= len(ADVERSARIAL_CASE_TYPES):
        counts = {case: 1 for case in ADVERSARIAL_CASE_TYPES}
        remaining -= len(ADVERSARIAL_CASE_TYPES)
    raw = {case: remaining * weights[case] for case in ADVERSARIAL_CASE_TYPES}
    for case in ADVERSARIAL_CASE_TYPES:
        allocated = int(math.floor(raw[case]))
        counts[case] += allocated
        remaining -= allocated
    order = sorted(ADVERSARIAL_CASE_TYPES, key=lambda case: (-(raw[case] - math.floor(raw[case])), case))
    for case in order[:remaining]:
        counts[case] += 1
    if sum(counts.values()) != total:
        raise EvidenceObligationError("adversarial largest-remainder allocation did not reconcile")
    return counts


def _select_profile(
    unit: _CoverageUnit,
    case_type: str,
    bundle: ReceiptProfileBundle,
    rng: CounterRng,
) -> ReceiptProfile:
    accepted = tuple(sorted(str(value) for value in unit.obligation["required_evidence_types"]))
    if case_type == "forged_under_synthetic_key":
        accepted = tuple(value for value in accepted if bundle.profile(value).requires_key)
    if not accepted:
        raise EvidenceObligationError(f"unit {unit.key}: no receipt profile supports case={case_type}")
    index = rng.randint(f"receipt-profile|{case_type}|{unit.key}", 0, 0, len(accepted) - 1)
    return bundle.profile(accepted[index])


def _emit_receipt(
    unit: _CoverageUnit,
    case_type: str,
    variant: str,
    profile: ReceiptProfile,
    bundle: ReceiptProfileBundle,
    rng: CounterRng,
    namespace: str,
    event_by_id: Mapping[str, Mapping[str, Any]],
    actor_ids: set[str],
    contradiction_group_id: str | None,
    contract: ContractSpec,
) -> tuple[dict[str, Any], EvidenceReceiptFixture, tuple[DerivedSyntheticKey, ...]]:
    obligation = unit.obligation
    receipt_id = deterministic_uuid(
        namespace,
        "evidence_receipt",
        {"case_type": case_type, "unit": unit.key, "variant": variant},
    )
    triggering_event_id = str(obligation["event_id"])
    event_id = _evidenced_event_id(unit)
    if case_type == "missing_dependency":
        outside = sorted(
            event_id_candidate
            for event_id_candidate, row in event_by_id.items()
            if str(row["scenario_id"]) == unit.scenario_id
            and event_id_candidate not in set(unit.provenance.dependency_event_ids)
        )
        if not outside:
            raise EvidenceObligationError(f"unit {unit.key}: no real outside-dependency event exists")
        event_id = outside[rng.randint(f"missing-dependency|{unit.key}", 0, 0, len(outside) - 1)]
    issuer_actor_id = str(obligation["responsible_actor_id"])
    if issuer_actor_id not in actor_ids:
        raise EvidenceObligationError(f"unit {unit.key}: responsible issuer actor does not resolve")
    issued_at = _honest_issue_time(
        str(event_by_id[triggering_event_id]["timestamp"]),
        str(obligation["due_at"]),
        rng,
        unit.key,
    )
    if case_type == "late":
        issued_at = normalize_utc_timestamp(_timestamp(str(obligation["due_at"])) + timedelta(microseconds=1))
    covers_replica_ids = (
        [str(obligation["subject_object_id"])]
        if str(obligation["coverage_scope"]) == "replica_set"
        else []
    )
    facts = ReceiptPayloadFacts(
        receipt_id=receipt_id,
        obligation_id=str(obligation["obligation_id"]),
        evidenced_event_id=event_id,
        triggering_event_id=triggering_event_id,
        policy_rule_id=str(obligation["policy_rule_id"]),
        subject_object_id=str(obligation["subject_object_id"]),
        responsible_actor_id=str(obligation["responsible_actor_id"]),
        issuer_actor_id=issuer_actor_id,
        evidence_type=profile.evidence_type,
        issued_at=issued_at,
        due_at=str(obligation["due_at"]),
        coverage_scope=str(obligation["coverage_scope"]),
        covers_replica_ids=tuple(covers_replica_ids),
    )
    expected_payload = canonical_receipt_payload(facts, profile=profile, bundle=bundle, contract=contract)
    detached_payload = expected_payload[:-1] if case_type == "malformed" else expected_payload
    generated_keys: list[DerivedSyntheticKey] = []
    claimed_key: DerivedSyntheticKey | None = None
    actual_key: DerivedSyntheticKey | None = None
    if profile.requires_key:
        claimed_key = derive_synthetic_key(
            rng,
            subject_actor_id=issuer_actor_id,
            primitive=profile.primitive,
            algorithm=profile.algorithm,
        )
        generated_keys.append(claimed_key)
        actual_key = claimed_key
        if case_type == "forged_under_synthetic_key":
            actual_key = derive_synthetic_key(
                rng,
                subject_actor_id=issuer_actor_id,
                primitive=profile.primitive,
                algorithm=profile.algorithm,
                key_role="adversary",
                context_id=receipt_id,
            )
            generated_keys.append(actual_key)
    authenticator = authenticate(profile, detached_payload, actual_key)
    if case_type == "invalid":
        authenticator = bytes([authenticator[0] ^ 1]) + authenticator[1:]
    status = {
        "valid": "valid",
        "invalid": "invalid",
        "late": "expired",
        "malformed": "invalid",
        "contradictory": "invalid",
        "forged_under_synthetic_key": "invalid",
        "missing_dependency": "missing_dependency",
    }[case_type]
    row = {
        "receipt_id": receipt_id,
        "obligation_id": str(obligation["obligation_id"]),
        "event_id": event_id,
        "issuer_actor_id": issuer_actor_id,
        "evidence_type": profile.evidence_type,
        "issued_at": issued_at,
        "canonical_digest": canonical_digest(detached_payload),
        "algorithm": profile.algorithm,
        "key_id": claimed_key.fixture.key_id if claimed_key is not None else None,
        "anchor_id": None,
        "verification_status_truth": status,
        "covers_replica_ids": covers_replica_ids,
        "payload_ref": f"fixture://evidence-receipt/{receipt_id}",
    }
    fixture = EvidenceReceiptFixture(
        receipt_id=receipt_id,
        case_type=case_type,
        coverage_member_id=unit.coverage_member_id,
        canonical_payload_hex=detached_payload.hex(),
        authenticator_hex=authenticator.hex(),
        claimed_key_id=claimed_key.fixture.key_id if claimed_key is not None else None,
        actual_key_id=actual_key.fixture.key_id if actual_key is not None else None,
        merkle_path=(),
        contradiction_group_id=contradiction_group_id,
    )
    return row, fixture, tuple(generated_keys)


def _evidenced_event_id(unit: _CoverageUnit) -> str:
    scope = str(unit.obligation["coverage_scope"])
    if scope in {"workflow", "causal_closure"}:
        return unit.coverage_member_id
    return str(unit.obligation["event_id"])


def _honest_issue_time(
    event_timestamp: str,
    due_at: str,
    rng: CounterRng,
    unit_key: str,
) -> str:
    start = _timestamp(event_timestamp)
    due = _timestamp(due_at)
    if due < start:
        raise EvidenceObligationError(f"receipt unit {unit_key}: deadline precedes triggering event")
    available_microseconds = int((due - start).total_seconds() * 1_000_000)
    if available_microseconds == 0:
        return normalize_utc_timestamp(start)
    offset = rng.randint(f"receipt-issued-at|{unit_key}", 0, 1, available_microseconds)
    return normalize_utc_timestamp(start + timedelta(microseconds=offset))


def _evidence_stream(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
) -> tuple[CounterRng, str]:
    plans = [
        plan
        for plan in build_run_plan(resolved)
        if plan.scenario_id == scenario_id and plan.replicate_id == replicate_id
    ]
    if len(plans) != 1:
        raise EvidenceObligationError(
            f"cannot resolve one run plan for scenario={scenario_id} replicate={replicate_id}"
        )
    rows = seed_stream_records_for_plan(resolved, plans[0], include_common_random_groups=False)
    matching = [row for row in rows if str(row["stream_name"]).endswith("component=S10.evidence|partition=global")]
    if len(matching) != 1:
        raise EvidenceObligationError("S10.evidence named seed stream is missing or duplicated")
    row = matching[0]
    return CounterRng(str(row["seed_material_hex"])), str(row["deterministic_id_namespace"])


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceObligationError(f"invalid UTC timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise EvidenceObligationError(f"timestamp must be normalized UTC: {value!r}")
    return parsed.astimezone(timezone.utc)
