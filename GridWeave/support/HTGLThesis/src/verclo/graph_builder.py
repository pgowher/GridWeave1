"""Deterministic visible-lineage expansion and per-replica obligation induction."""

from __future__ import annotations

from datetime import datetime, timedelta
from collections import deque
from typing import Iterable

from .canonical import commitment, content_id
from .models import Obligation, ObligationGraph, TopologyView
from .policy import PolicyProfile


class ObligationGraphBuilder:
    """Build only from authenticated observer metadata, never operational payloads."""

    def __init__(self, *, traversal: str = "fused"):
        if traversal not in {"fused", "legacy", "kahn_bfs"}:
            raise ValueError('unknown graph traversal')
        self.traversal = traversal

    @staticmethod
    def _linear_scope(asset_ids, edges, roots, *, fused=True):
        """Known Kahn traversal with reachability propagation; not a novelty claim.

        Visit the entire graph so a disconnected cycle still invalidates scope.
        Output ordering is canonicalized by build, independent of queue order.
        The kahn_bfs option is the optimized conventional two-pass baseline.
        """
        adjacency = {node: [] for node in asset_ids}
        indegree = {node: 0 for node in asset_ids}
        for parent, child in edges:
            adjacency[parent].append(child)
            indegree[child] += 1
        queue = deque(node for node in asset_ids if indegree[node] == 0)
        discovered = set(roots) & asset_ids
        visited = 0
        while queue:
            node = queue.popleft()
            visited += 1
            for child in adjacency[node]:
                if fused and node in discovered:
                    discovered.add(child)
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        if visited != len(asset_ids):
            raise ValueError('visible lineage must be acyclic')
        if not fused:
            queue = deque(discovered)
            while queue:
                for child in adjacency[queue.popleft()]:
                    if child not in discovered:
                        discovered.add(child)
                        queue.append(child)
        return discovered

    @classmethod
    def _legacy_scope(cls, asset_ids, edges, roots):
        cls._assert_acyclic(asset_ids, edges)
        discovered = set(roots) & asset_ids
        changed = True
        while changed:
            changed = False
            for parent, child in sorted(edges):
                if parent in discovered and child not in discovered:
                    discovered.add(child)
                    changed = True
        return discovered

    @staticmethod
    def scope_material(view: TopologyView) -> dict[str, object]:
        return {
            "case_id": view.case_id,
            "dataset_id": view.dataset_id,
            "correlation_id": view.correlation_id,
            "scope_version": view.scope_version,
            "assets": sorted(
                ({"asset_id": row.asset_id, "dataset_id": row.dataset_id, "asset_kind": row.asset_kind, "visibility": row.visibility.value} for row in view.assets),
                key=lambda row: row["asset_id"],
            ),
            "repositories": sorted(
                ({"repository_id": row.repository_id, "organization_id": row.organization_id, "custodian_principal_id": row.custodian_principal_id, "repository_class": row.repository_class, "visibility": row.visibility.value} for row in view.repositories),
                key=lambda row: row["repository_id"],
            ),
            "replicas": sorted(
                ({"replica_id": row.replica_id, "asset_id": row.asset_id, "repository_id": row.repository_id, "replica_class": row.replica_class, "visibility": row.visibility.value} for row in view.replicas),
                key=lambda row: row["replica_id"],
            ),
            "lineage_edges": sorted(
                ({"relationship_id": row.relationship_id, "parent_asset_id": row.parent_asset_id, "child_asset_id": row.child_asset_id, "relationship_type": row.relationship_type, "visibility": row.visibility.value} for row in view.lineage_edges),
                key=lambda row: row["relationship_id"],
            ),
        }

    @classmethod
    def expected_scope_commitment(cls, view: TopologyView) -> str:
        return commitment("verclo-visible-scope-v1", cls.scope_material(view))

    @staticmethod
    def _unique(rows: Iterable[object], field: str, label: str) -> dict[str, object]:
        result: dict[str, object] = {}
        for row in rows:
            identifier = str(getattr(row, field))
            if not identifier or identifier in result:
                raise ValueError(f"duplicate or empty {label} identifier: {identifier}")
            result[identifier] = row
        return result

    @staticmethod
    def _assert_acyclic(asset_ids: set[str], edges: list[tuple[str, str]]) -> None:
        adjacency = {asset_id: [] for asset_id in asset_ids}
        indegree = {asset_id: 0 for asset_id in asset_ids}
        for parent, child in edges:
            adjacency[parent].append(child)
            indegree[child] += 1
        queue = sorted(key for key, value in indegree.items() if value == 0)
        visited = 0
        while queue:
            node = queue.pop(0)
            visited += 1
            for child in sorted(adjacency[node]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
                    queue.sort()
        if visited != len(asset_ids):
            raise ValueError("visible lineage must be acyclic")

    def build(
        self,
        *,
        view: TopologyView,
        root_asset_ids: tuple[str, ...],
        accepted_at: datetime,
        policy: PolicyProfile,
    ) -> ObligationGraph:
        if accepted_at.tzinfo is None or accepted_at.utcoffset() is None:
            raise ValueError("accepted_at must be timezone-aware")
        if view.scope_version < 1:
            raise ValueError("scope_version must be positive")
        assets = self._unique(view.assets, "asset_id", "asset")
        repositories = self._unique(view.repositories, "repository_id", "repository")
        replicas = self._unique(view.replicas, "replica_id", "replica")
        relationships = self._unique(view.lineage_edges, "relationship_id", "relationship")
        if any(row.dataset_id != view.dataset_id for row in assets.values()):
            raise ValueError("asset dataset_id does not match topology dataset_id")

        unresolved = set(view.unresolved_reference_ids)
        valid_edges: list[tuple[str, str]] = []
        valid_relationship_ids: list[str] = []
        for row in relationships.values():
            if row.relationship_type not in {"DERIVED_FROM", "EXPORTED_FROM"}:
                raise ValueError(f"unsupported lineage relationship: {row.relationship_type}")
            if row.parent_asset_id not in assets or row.child_asset_id not in assets:
                unresolved.update({identifier for identifier in (row.parent_asset_id, row.child_asset_id) if identifier not in assets})
                continue
            valid_edges.append((row.parent_asset_id, row.child_asset_id))
            valid_relationship_ids.append(row.relationship_id)
        roots = tuple(sorted(set(root_asset_ids)))
        unresolved.update(root for root in roots if root not in assets)
        discovered = (self._legacy_scope(set(assets), valid_edges, roots)
            if self.traversal == 'legacy' else self._linear_scope(
                set(assets), valid_edges, roots, fused=self.traversal == 'fused'))

        obligations: list[Obligation] = []
        for replica in sorted(replicas.values(), key=lambda row: row.replica_id):
            if replica.asset_id not in assets or replica.repository_id not in repositories:
                unresolved.update(identifier for identifier in (replica.asset_id, replica.repository_id) if identifier not in assets and identifier not in repositories)
                continue
            if replica.asset_id not in discovered:
                continue
            asset = assets[replica.asset_id]
            repository = repositories[replica.repository_id]
            if not policy.applies(asset.asset_kind, replica.replica_class):
                continue
            rule = policy.resolve_rule(asset.asset_kind, replica.replica_class)
            identity = {
                "case_id": view.case_id, "dataset_id": view.dataset_id,
                "correlation_id": view.correlation_id, "asset_id": asset.asset_id,
                "replica_id": replica.replica_id, "repository_id": repository.repository_id,
                "custodian_principal_id": repository.custodian_principal_id,
                "policy_profile_id": policy.profile_id, "policy_version": policy.version,
            }
            obligations.append(Obligation(
                obligation_id=content_id("OBL", "verclo-obligation-v1", identity),
                case_id=view.case_id,
                dataset_id=view.dataset_id,
                correlation_id=view.correlation_id,
                asset_id=asset.asset_id,
                replica_id=replica.replica_id,
                repository_id=repository.repository_id,
                custodian_principal_id=repository.custodian_principal_id,
                deadline=accepted_at + timedelta(hours=rule.deadline_hours),
                minimum_evidence_grade=rule.minimum_evidence_grade,
                permitted_dispositions=rule.permitted_dispositions,
                policy_profile_id=policy.profile_id,
                policy_version=policy.version,
            ))
        obligations.sort(key=lambda row: row.obligation_id)
        expected_scope = self.expected_scope_commitment(view)
        reasons: list[str] = []
        if not view.graph_available:
            reasons.append("GRAPH_UNAVAILABLE")
        if not view.declared_scope_complete:
            reasons.append("DECLARED_SCOPE_INCOMPLETE")
        if unresolved:
            reasons.append("UNRESOLVED_REFERENCES")
        if view.scope_commitment is None:
            reasons.append("MISSING_SCOPE_COMMITMENT")
        elif view.scope_commitment != expected_scope:
            reasons.append("SCOPE_COMMITMENT_MISMATCH")
        if not obligations:
            reasons.append("NO_APPLICABLE_OBLIGATIONS_UNAUTHENTICATED")
        obligation_material = [
            {
                "obligation_id": row.obligation_id, "asset_id": row.asset_id,
                "replica_id": row.replica_id, "repository_id": row.repository_id,
                "custodian_principal_id": row.custodian_principal_id,
                "deadline": row.deadline, "minimum_evidence_grade": row.minimum_evidence_grade,
                "permitted_dispositions": row.permitted_dispositions,
                "policy_profile_id": row.policy_profile_id, "policy_version": row.policy_version,
            }
            for row in obligations
        ]
        return ObligationGraph(
            case_id=view.case_id,
            dataset_id=view.dataset_id,
            correlation_id=view.correlation_id,
            scope_version=view.scope_version,
            root_asset_ids=roots,
            discovered_asset_ids=tuple(sorted(discovered)),
            relationship_ids=tuple(sorted(valid_relationship_ids)),
            obligations=tuple(obligations),
            exceptions=(),
            custodians=tuple(sorted({row.custodian_principal_id for row in obligations})),
            scope_commitment=expected_scope,
            obligation_commitment=commitment("verclo-obligation-set-v1", obligation_material),
            baseline_verifiable=not reasons,
            baseline_reason_codes=tuple(reasons),
        )
