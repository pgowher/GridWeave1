"""Immutable metadata models for VERCLO case-level tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Mapping


class Visibility(StrEnum):
    DECLARED = "DECLARED"
    DISCOVERABLE_AUTHENTICATED = "DISCOVERABLE_AUTHENTICATED"


class CasePhase(StrEnum):
    ACCEPTED = "ACCEPTED"
    OBLIGATIONS_ACTIVE = "OBLIGATIONS_ACTIVE"


class ObligationStatus(StrEnum):
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    EVIDENCE_SUBMITTED = "EVIDENCE_SUBMITTED"
    EVIDENCE_VALIDATED = "EVIDENCE_VALIDATED"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    UNREACHABLE = "UNREACHABLE"
    EXCEPTION_ASSERTED = "EXCEPTION_ASSERTED"


@dataclass(frozen=True)
class RepositoryDescriptor:
    repository_id: str
    organization_id: str
    custodian_principal_id: str
    repository_class: str
    visibility: Visibility = Visibility.DECLARED


@dataclass(frozen=True)
class AssetDescriptor:
    asset_id: str
    dataset_id: str
    asset_kind: str
    visibility: Visibility = Visibility.DECLARED


@dataclass(frozen=True)
class ReplicaDescriptor:
    replica_id: str
    asset_id: str
    repository_id: str
    replica_class: str
    visibility: Visibility = Visibility.DECLARED


@dataclass(frozen=True)
class LineageEdge:
    relationship_id: str
    parent_asset_id: str
    child_asset_id: str
    relationship_type: str
    visibility: Visibility = Visibility.DECLARED


@dataclass(frozen=True)
class TopologyView:
    case_id: str
    dataset_id: str
    correlation_id: str
    scope_version: int
    assets: tuple[AssetDescriptor, ...]
    repositories: tuple[RepositoryDescriptor, ...]
    replicas: tuple[ReplicaDescriptor, ...]
    lineage_edges: tuple[LineageEdge, ...]
    scope_commitment: str | None
    graph_available: bool = True
    declared_scope_complete: bool = True
    unresolved_reference_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    case_id: str
    dataset_id: str
    correlation_id: str
    asset_id: str
    replica_id: str
    repository_id: str
    custodian_principal_id: str
    deadline: datetime
    minimum_evidence_grade: str
    permitted_dispositions: tuple[str, ...]
    policy_profile_id: str
    policy_version: str
    status: ObligationStatus = ObligationStatus.PENDING
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExceptionAssertion:
    exception_id: str
    obligation_id: str
    authority_principal_id: str
    basis_commitment: str
    effective_at: datetime
    expires_at: datetime
    status: str = "ASSERTED"


@dataclass(frozen=True)
class ObligationGraph:
    case_id: str
    dataset_id: str
    correlation_id: str
    scope_version: int
    root_asset_ids: tuple[str, ...]
    discovered_asset_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    obligations: tuple[Obligation, ...]
    exceptions: tuple[ExceptionAssertion, ...]
    custodians: tuple[str, ...]
    scope_commitment: str
    obligation_commitment: str
    baseline_verifiable: bool
    baseline_reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class ErasureCase:
    case_id: str
    run_id: str
    dataset_id: str
    correlation_id: str
    request_id: str
    requester_principal_id: str
    root_asset_ids: tuple[str, ...]
    policy_profile_id: str
    accepted_at: datetime
    phase: CasePhase
    revision: int
    graph: ObligationGraph | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)
