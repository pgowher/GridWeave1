"""Independent evaluator-only evidence sufficiency recomputation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from htgl_dataset_generator.catalog import CatalogBuild
from htgl_dataset_generator.dag import CausalDagBuild
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.world import FederatedWorld

from .builder import EvidenceObligationBuild, EvidenceObligationError, EvidenceObligationProvenance


@dataclass(frozen=True)
class EvidenceSufficiencyTruth:
    obligation_id: str
    matching_receipt_count: int
    valid_receipt_count: int
    timely_valid_receipt_count: int
    coverage_complete: bool
    validity_complete: bool
    timeliness_complete: bool
    contradiction_free: bool
    dependencies_complete: bool
    missing_coverage_ids: tuple[str, ...]
    invalid_receipt_ids: tuple[str, ...]
    late_receipt_ids: tuple[str, ...]
    contradictory_receipt_ids: tuple[str, ...]
    missing_dependency_receipt_ids: tuple[str, ...]
    sufficient: bool


@dataclass(frozen=True)
class EvidenceSufficiencyDiagnostics:
    obligation_count: int
    receipt_count: int
    sufficient_obligation_count: int
    incomplete_obligation_count: int
    contradictory_obligation_count: int
    missing_dependency_obligation_count: int


@dataclass(frozen=True)
class EvidenceSufficiencyBuild:
    truth: tuple[EvidenceSufficiencyTruth, ...]
    diagnostics: EvidenceSufficiencyDiagnostics


def evaluate_evidence_sufficiency(
    obligations: EvidenceObligationBuild,
    receipts: Sequence[Mapping[str, Any]],
    *,
    world: FederatedWorld,
    catalog: CatalogBuild,
    causal_dag: CausalDagBuild,
    contract: ContractSpec | None = None,
) -> EvidenceSufficiencyBuild:
    """Recompute strict coverage, validity, timeliness, and dependency sufficiency."""

    schema_contract = contract if contract is not None else load_contract()
    obligation_by_id = {
        str(row["obligation_id"]): row for row in obligations.evidence_obligations
    }
    provenance_by_id = {item.obligation_id: item for item in obligations.provenance}
    if len(obligation_by_id) != len(obligations.evidence_obligations):
        raise EvidenceObligationError("duplicate obligation IDs in sufficiency input")
    if set(obligation_by_id) != set(provenance_by_id):
        raise EvidenceObligationError("sufficiency input is missing obligation provenance")
    event_by_id = {str(row["event_id"]): row for row in causal_dag.governance_events}
    actor_ids = {str(row["actor_id"]) for row in world.actors}
    replica_by_id = {
        str(row["replica_id"]): row for row in catalog.data_object_replicas
    }
    receipt_rows: list[dict[str, Any]] = []
    receipt_ids: set[str] = set()
    for raw in receipts:
        row = dict(raw)
        validate_record(schema_contract, "evidence_receipt", row)
        receipt_id = str(row["receipt_id"])
        if receipt_id in receipt_ids:
            raise EvidenceObligationError(f"duplicate evidence receipt_id={receipt_id}")
        receipt_ids.add(receipt_id)
        obligation_id = str(row["obligation_id"])
        if obligation_id not in obligation_by_id:
            raise EvidenceObligationError(
                f"receipt {receipt_id}: obligation_id={obligation_id!r} does not resolve"
            )
        event_id = str(row["event_id"])
        if event_id not in event_by_id:
            raise EvidenceObligationError(f"receipt {receipt_id}: event_id does not resolve")
        if str(row["issuer_actor_id"]) not in actor_ids:
            raise EvidenceObligationError(f"receipt {receipt_id}: issuer_actor_id does not resolve")
        receipt_rows.append(row)
    receipts_by_obligation: dict[str, list[Mapping[str, Any]]] = {}
    for row in receipt_rows:
        receipts_by_obligation.setdefault(str(row["obligation_id"]), []).append(row)

    truth: list[EvidenceSufficiencyTruth] = []
    for obligation_id in sorted(obligation_by_id):
        truth.append(
            _evaluate_obligation(
                obligation_by_id[obligation_id],
                provenance_by_id[obligation_id],
                tuple(receipts_by_obligation.get(obligation_id, ())),
                replica_by_id=replica_by_id,
            )
        )
    diagnostics = EvidenceSufficiencyDiagnostics(
        obligation_count=len(truth),
        receipt_count=len(receipt_rows),
        sufficient_obligation_count=sum(item.sufficient for item in truth),
        incomplete_obligation_count=sum(not item.sufficient for item in truth),
        contradictory_obligation_count=sum(not item.contradiction_free for item in truth),
        missing_dependency_obligation_count=sum(not item.dependencies_complete for item in truth),
    )
    return EvidenceSufficiencyBuild(tuple(truth), diagnostics)


def require_evidence_sufficient_for_release(build: EvidenceSufficiencyBuild) -> None:
    """Fail a release gate unless every modeled obligation is strictly sufficient."""

    failures = tuple(item for item in build.truth if not item.sufficient)
    if failures:
        sample = tuple(
            (
                item.obligation_id,
                item.missing_coverage_ids,
                item.invalid_receipt_ids,
                item.late_receipt_ids,
                item.contradictory_receipt_ids,
                item.missing_dependency_receipt_ids,
            )
            for item in failures[:5]
        )
        raise EvidenceObligationError(
            f"evidence sufficiency release gate failed for {len(failures)} obligations; sample={sample}"
        )


def _evaluate_obligation(
    obligation: Mapping[str, Any],
    provenance: EvidenceObligationProvenance,
    receipts: Sequence[Mapping[str, Any]],
    *,
    replica_by_id: Mapping[str, Mapping[str, Any]],
) -> EvidenceSufficiencyTruth:
    obligation_id = str(obligation["obligation_id"])
    accepted_types = set(str(value) for value in obligation["required_evidence_types"])
    responsible_actor_id = str(obligation["responsible_actor_id"])
    due_at = _timestamp(str(obligation["due_at"]))
    dependency_ids = set(provenance.dependency_event_ids)
    matching = tuple(row for row in receipts if str(row["evidence_type"]) in accepted_types)
    unacceptable_ids = {
        str(row["receipt_id"])
        for row in receipts
        if str(row["evidence_type"]) not in accepted_types
    }
    wrong_issuer_ids = {
        str(row["receipt_id"])
        for row in matching
        if str(row["issuer_actor_id"]) != responsible_actor_id
    }
    invalid_ids = {
        str(row["receipt_id"])
        for row in matching
        if str(row["verification_status_truth"]) != "valid"
    } | unacceptable_ids | wrong_issuer_ids
    late_ids = {
        str(row["receipt_id"])
        for row in matching
        if _timestamp(str(row["issued_at"])) > due_at
    }
    missing_dependency_ids = {
        str(row["receipt_id"])
        for row in matching
        if str(row["event_id"]) not in dependency_ids
        or str(row["verification_status_truth"]) == "missing_dependency"
    }
    contradictory_ids = _contradictory_receipt_ids(matching)
    valid = tuple(
        row
        for row in matching
        if str(row["receipt_id"]) not in invalid_ids
        and str(row["receipt_id"]) not in missing_dependency_ids
    )
    timely_valid = tuple(
        row for row in valid if str(row["receipt_id"]) not in late_ids
    )
    required_coverage = set(provenance.coverage_member_ids)
    covered = _covered_members(
        obligation,
        provenance,
        timely_valid,
        replica_by_id=replica_by_id,
    )
    missing_coverage = tuple(sorted(required_coverage - covered))
    minimum_count_met = len(timely_valid) >= int(obligation["minimum_count"])
    coverage_complete = not missing_coverage and minimum_count_met
    validity_complete = coverage_complete and not invalid_ids
    timeliness_complete = coverage_complete
    contradiction_free = not contradictory_ids
    dependencies_complete = not missing_dependency_ids
    sufficient = (
        coverage_complete
        and validity_complete
        and timeliness_complete
        and contradiction_free
        and dependencies_complete
    )
    return EvidenceSufficiencyTruth(
        obligation_id=obligation_id,
        matching_receipt_count=len(matching),
        valid_receipt_count=len(valid),
        timely_valid_receipt_count=len(timely_valid),
        coverage_complete=coverage_complete,
        validity_complete=validity_complete,
        timeliness_complete=timeliness_complete,
        contradiction_free=contradiction_free,
        dependencies_complete=dependencies_complete,
        missing_coverage_ids=missing_coverage,
        invalid_receipt_ids=tuple(sorted(invalid_ids)),
        late_receipt_ids=tuple(sorted(late_ids)),
        contradictory_receipt_ids=tuple(sorted(contradictory_ids)),
        missing_dependency_receipt_ids=tuple(sorted(missing_dependency_ids)),
        sufficient=sufficient,
    )


def _covered_members(
    obligation: Mapping[str, Any],
    provenance: EvidenceObligationProvenance,
    receipts: Sequence[Mapping[str, Any]],
    *,
    replica_by_id: Mapping[str, Mapping[str, Any]],
) -> set[str]:
    scope = str(obligation["coverage_scope"])
    trigger_event_id = str(obligation["event_id"])
    subject_id = str(obligation["subject_object_id"])
    if scope == "object":
        return {subject_id} if any(str(row["event_id"]) == trigger_event_id for row in receipts) else set()
    if scope == "replica_set":
        if subject_id not in replica_by_id:
            raise EvidenceObligationError(
                f"obligation {obligation['obligation_id']}: replica subject does not resolve"
            )
        return {
            subject_id
            for row in receipts
            if subject_id in set(str(value) for value in row["covers_replica_ids"])
        }
    if scope in {"workflow", "causal_closure"}:
        dependency_ids = set(provenance.dependency_event_ids)
        return {
            str(row["event_id"])
            for row in receipts
            if str(row["event_id"]) in dependency_ids
        }
    if scope == "actor_set":
        return {
            str(row["issuer_actor_id"])
            for row in receipts
            if str(row["event_id"]) == trigger_event_id
        }
    raise EvidenceObligationError(f"unknown coverage_scope={scope!r}")


def _contradictory_receipt_ids(receipts: Sequence[Mapping[str, Any]]) -> set[str]:
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for row in receipts:
        key = (
            str(row["event_id"]),
            str(row["evidence_type"]),
            str(row["issuer_actor_id"]),
        )
        groups.setdefault(key, []).append(row)
    contradictory: set[str] = set()
    for rows in groups.values():
        signatures = {
            (
                str(row["canonical_digest"]),
                str(row["verification_status_truth"]),
                tuple(sorted(str(value) for value in row["covers_replica_ids"])),
            )
            for row in rows
        }
        if len(signatures) > 1:
            contradictory.update(str(row["receipt_id"]) for row in rows)
    return contradictory


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceObligationError(f"invalid UTC timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise EvidenceObligationError(f"timestamp must be normalized to UTC: {value!r}")
    return parsed
