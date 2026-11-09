"""Deterministic case lifecycle and multi-custodian obligation tracking."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import re
from typing import Any, Mapping

from .canonical import content_id
from .graph_builder import ObligationGraphBuilder
from .models import CasePhase, ErasureCase, ExceptionAssertion, ObligationStatus, TopologyView
from .policy import PolicyRegistry


FORBIDDEN_INPUT_KEYS = frozenset({
    "payload", "operational_payload", "personal_data", "direct_identifier", "raw_telemetry",
    "closure_ground_truth", "expected_outcome", "truth_status", "verification_status_truth",
    "behavior_profile", "controlled_by_adversary", "attack_type", "attack_label",
    "hidden_relationships", "hidden_topology", "world_disposition",
})
CREATE_FIELDS = frozenset({
    "run_id", "dataset_id", "correlation_id", "request_id", "requester_principal_id",
    "root_asset_ids", "policy_profile_id", "accepted_at", "case_id", "metadata",
})
HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def _scan_safe(value: Any) -> None:
    if isinstance(value, Mapping):
        collisions = set(map(str, value)) & FORBIDDEN_INPUT_KEYS
        if collisions:
            raise ValueError(f"VERCLO input contains prohibited fields: {sorted(collisions)}")
        for child in value.values():
            _scan_safe(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _scan_safe(child)


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")


class ErasureCaseManager:
    def __init__(self, policy_registry: PolicyRegistry, graph_builder: ObligationGraphBuilder | None = None) -> None:
        self._policies = policy_registry
        self._builder = graph_builder or ObligationGraphBuilder()
        self._cases: dict[str, ErasureCase] = {}

    def create_case(
        self,
        *,
        run_id: str,
        dataset_id: str,
        correlation_id: str,
        request_id: str,
        requester_principal_id: str,
        root_asset_ids: tuple[str, ...],
        policy_profile_id: str,
        accepted_at: datetime,
        case_id: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> ErasureCase:
        _aware(accepted_at)
        self._policies.get(policy_profile_id)
        roots = tuple(sorted(set(root_asset_ids)))
        if not all((run_id, dataset_id, correlation_id, request_id, requester_principal_id)) or not roots:
            raise ValueError("case identifiers and at least one root asset are required")
        safe_metadata = dict(metadata or {})
        _scan_safe(safe_metadata)
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in safe_metadata.items()):
            raise TypeError("case metadata must contain string keys and values only")
        identifier = case_id or content_id("CASE", "verclo-case-v1", {
            "run_id": run_id, "dataset_id": dataset_id, "correlation_id": correlation_id,
            "request_id": request_id, "requester_principal_id": requester_principal_id,
            "root_asset_ids": roots, "policy_profile_id": policy_profile_id,
            "accepted_at": accepted_at,
        })
        created = ErasureCase(
            case_id=identifier, run_id=run_id, dataset_id=dataset_id,
            correlation_id=correlation_id, request_id=request_id,
            requester_principal_id=requester_principal_id, root_asset_ids=roots,
            policy_profile_id=policy_profile_id, accepted_at=accepted_at,
            phase=CasePhase.ACCEPTED, revision=0, metadata=dict(sorted(safe_metadata.items())),
        )
        prior = self._cases.get(identifier)
        if prior is not None:
            if replace(prior, phase=CasePhase.ACCEPTED, revision=0, graph=None) == created:
                return prior
            raise ValueError(f"case identifier already binds different metadata: {identifier}")
        self._cases[identifier] = created
        return created

    def create_case_from_mapping(self, payload: Mapping[str, Any]) -> ErasureCase:
        _scan_safe(payload)
        unknown = set(payload) - CREATE_FIELDS
        if unknown:
            raise ValueError(f"unknown case input fields: {sorted(unknown)}")
        required = CREATE_FIELDS - {"case_id", "metadata"}
        missing = required - set(payload)
        if missing:
            raise ValueError(f"missing case input fields: {sorted(missing)}")
        accepted = payload["accepted_at"]
        if isinstance(accepted, str):
            accepted = datetime.fromisoformat(accepted.replace("Z", "+00:00"))
        return self.create_case(
            run_id=str(payload["run_id"]), dataset_id=str(payload["dataset_id"]),
            correlation_id=str(payload["correlation_id"]), request_id=str(payload["request_id"]),
            requester_principal_id=str(payload["requester_principal_id"]),
            root_asset_ids=tuple(map(str, payload["root_asset_ids"])),
            policy_profile_id=str(payload["policy_profile_id"]), accepted_at=accepted,
            case_id=str(payload["case_id"]) if payload.get("case_id") is not None else None,
            metadata=payload.get("metadata"),
        )

    def get_case(self, case_id: str) -> ErasureCase:
        try:
            return self._cases[case_id]
        except KeyError as exc:
            raise KeyError(f"unknown case: {case_id}") from exc

    def attach_topology(self, case_id: str, view: TopologyView) -> ErasureCase:
        current = self.get_case(case_id)
        if (view.case_id, view.dataset_id, view.correlation_id) != (current.case_id, current.dataset_id, current.correlation_id):
            raise ValueError("topology case/dataset/correlation binding mismatch")
        if current.graph is not None and view.scope_version < current.graph.scope_version:
            raise ValueError("scope version regression")
        graph = self._builder.build(
            view=view, root_asset_ids=current.root_asset_ids, accepted_at=current.accepted_at,
            policy=self._policies.get(current.policy_profile_id),
        )
        if current.graph is not None:
            prior_definition = (
                current.graph.scope_version, current.graph.root_asset_ids,
                current.graph.discovered_asset_ids, current.graph.relationship_ids,
                tuple(row.obligation_id for row in current.graph.obligations),
                current.graph.custodians, current.graph.scope_commitment,
                current.graph.obligation_commitment, current.graph.baseline_verifiable,
                current.graph.baseline_reason_codes,
            )
            new_definition = (
                graph.scope_version, graph.root_asset_ids, graph.discovered_asset_ids,
                graph.relationship_ids, tuple(row.obligation_id for row in graph.obligations),
                graph.custodians, graph.scope_commitment, graph.obligation_commitment,
                graph.baseline_verifiable, graph.baseline_reason_codes,
            )
            if prior_definition == new_definition:
                return current
        if current.graph is not None and view.scope_version == current.graph.scope_version:
            raise ValueError("same scope version cannot bind different graph content")
        updated = replace(current, graph=graph, phase=CasePhase.OBLIGATIONS_ACTIVE, revision=current.revision + 1)
        self._cases[case_id] = updated
        return updated

    def update_obligation(
        self, case_id: str, obligation_id: str, status: ObligationStatus,
        *, evidence_refs: tuple[str, ...] = (),
    ) -> ErasureCase:
        current = self.get_case(case_id)
        if current.graph is None:
            raise ValueError("case has no obligation graph")
        allowed = {
            ObligationStatus.PENDING: {ObligationStatus.DISPATCHED, ObligationStatus.FAILED, ObligationStatus.UNREACHABLE, ObligationStatus.EXCEPTION_ASSERTED},
            ObligationStatus.DISPATCHED: {ObligationStatus.EVIDENCE_SUBMITTED, ObligationStatus.FAILED, ObligationStatus.UNREACHABLE, ObligationStatus.EXCEPTION_ASSERTED},
            ObligationStatus.EVIDENCE_SUBMITTED: {ObligationStatus.EVIDENCE_VALIDATED, ObligationStatus.FAILED},
            ObligationStatus.EVIDENCE_VALIDATED: {ObligationStatus.RESOLVED, ObligationStatus.FAILED, ObligationStatus.EXCEPTION_ASSERTED},
            ObligationStatus.EXCEPTION_ASSERTED: {ObligationStatus.RESOLVED, ObligationStatus.FAILED},
            ObligationStatus.RESOLVED: set(), ObligationStatus.FAILED: set(), ObligationStatus.UNREACHABLE: set(),
        }
        found = False
        changed = False
        obligations = []
        refs = tuple(sorted(set(evidence_refs)))
        for obligation in current.graph.obligations:
            if obligation.obligation_id != obligation_id:
                obligations.append(obligation)
                continue
            found = True
            if obligation.status == status and obligation.evidence_refs == refs:
                obligations.append(obligation)
                continue
            if status not in allowed[obligation.status]:
                raise ValueError(f"invalid obligation transition: {obligation.status}->{status}")
            obligations.append(replace(obligation, status=status, evidence_refs=refs))
            changed = True
        if not found:
            raise KeyError(f"unknown obligation: {obligation_id}")
        if not changed:
            return current
        graph = replace(current.graph, obligations=tuple(obligations))
        updated = replace(current, graph=graph, revision=current.revision + 1)
        self._cases[case_id] = updated
        return updated

    def assert_exception(
        self, case_id: str, obligation_id: str, *, authority_principal_id: str,
        basis_commitment: str, effective_at: datetime, expires_at: datetime,
        exception_id: str | None = None,
    ) -> ErasureCase:
        current = self.get_case(case_id)
        if current.graph is None:
            raise ValueError("case has no obligation graph")
        _aware(effective_at)
        _aware(expires_at)
        policy = self._policies.get(current.policy_profile_id)
        if authority_principal_id not in policy.exception_authority_ids:
            raise ValueError("exception authority is not admitted by policy")
        obligation = next((row for row in current.graph.obligations if row.obligation_id == obligation_id), None)
        if obligation is None:
            raise KeyError(f"unknown obligation: {obligation_id}")
        if not HEX_256.fullmatch(basis_commitment):
            raise ValueError("exception basis commitment must be SHA-256 hex")
        if effective_at > obligation.deadline or expires_at <= effective_at:
            raise ValueError("exception temporal bounds are invalid")
        identifier = exception_id or content_id("EXC", "verclo-exception-v1", {
            "case_id": case_id, "obligation_id": obligation_id,
            "authority_principal_id": authority_principal_id,
            "basis_commitment": basis_commitment, "effective_at": effective_at,
            "expires_at": expires_at,
        })
        assertion = ExceptionAssertion(
            exception_id=identifier, obligation_id=obligation_id,
            authority_principal_id=authority_principal_id,
            basis_commitment=basis_commitment, effective_at=effective_at, expires_at=expires_at,
        )
        prior = next((row for row in current.graph.exceptions if row.exception_id == identifier), None)
        if prior is not None:
            if prior == assertion:
                return current
            raise ValueError("exception identifier already binds different metadata")
        if obligation.status in {ObligationStatus.RESOLVED, ObligationStatus.FAILED, ObligationStatus.UNREACHABLE}:
            raise ValueError("cannot assert an exception against a terminal obligation")
        obligations = tuple(
            replace(row, status=ObligationStatus.EXCEPTION_ASSERTED)
            if row.obligation_id == obligation_id else row
            for row in current.graph.obligations
        )
        graph = replace(
            current.graph,
            obligations=obligations,
            exceptions=tuple(sorted((*current.graph.exceptions, assertion), key=lambda row: row.exception_id)),
        )
        updated = replace(current, graph=graph, revision=current.revision + 1)
        self._cases[case_id] = updated
        return updated
