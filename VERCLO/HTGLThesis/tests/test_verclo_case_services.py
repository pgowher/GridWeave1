from __future__ import annotations

import ast
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from verclo import (  # noqa: E402
    AssetDescriptor,
    ErasureCaseManager,
    LineageEdge,
    ObligationGraphBuilder,
    ObligationStatus,
    PolicyRegistry,
    ReplicaDescriptor,
    RepositoryDescriptor,
    TopologyView,
)
from verclo.models import ErasureCase, Obligation  # noqa: E402


ACCEPTED = datetime(2026, 9, 4, 10, 0, tzinfo=timezone.utc)


class VercloCaseServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = PolicyRegistry.load()
        self.builder = ObligationGraphBuilder()
        self.manager = ErasureCaseManager(self.registry, self.builder)
        self.case = self.manager.create_case(
            run_id="RUN-001", dataset_id="DATASET-SMART-GRID-001",
            correlation_id="CORR-001", request_id="REQUEST-001",
            requester_principal_id="PRINCIPAL-REQUESTER", root_asset_ids=("ASSET-ROOT",),
            policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE",
            accepted_at=ACCEPTED, case_id="CASE-001",
            metadata={"source_profile": "PAEBENCH-SMART-GRID-v1"},
        )

    def _view(self, *, reverse: bool = False, complete: bool = True, unresolved=()) -> TopologyView:
        assets = (
            AssetDescriptor("ASSET-ROOT", "DATASET-SMART-GRID-001", "interval_reading"),
            AssetDescriptor("ASSET-DERIVED", "DATASET-SMART-GRID-001", "feature"),
        )
        repositories = (
            RepositoryDescriptor("REPO-PRIMARY", "ORG-UTILITY", "CUSTODIAN-UTILITY", "operational"),
            RepositoryDescriptor("REPO-BACKUP", "ORG-UTILITY", "CUSTODIAN-BACKUP", "backup_store"),
            RepositoryDescriptor("REPO-DERIVED", "ORG-AGGREGATOR", "CUSTODIAN-AGGREGATOR", "feature_store"),
        )
        replicas = (
            ReplicaDescriptor("REPLICA-PRIMARY", "ASSET-ROOT", "REPO-PRIMARY", "primary"),
            ReplicaDescriptor("REPLICA-BACKUP", "ASSET-ROOT", "REPO-BACKUP", "backup"),
            ReplicaDescriptor("REPLICA-DERIVED", "ASSET-DERIVED", "REPO-DERIVED", "derived"),
        )
        edges = (LineageEdge("REL-DERIVED", "ASSET-ROOT", "ASSET-DERIVED", "DERIVED_FROM"),)
        if reverse:
            assets, repositories, replicas, edges = tuple(reversed(assets)), tuple(reversed(repositories)), tuple(reversed(replicas)), tuple(reversed(edges))
        draft = TopologyView(
            case_id="CASE-001", dataset_id="DATASET-SMART-GRID-001",
            correlation_id="CORR-001", scope_version=1, assets=assets,
            repositories=repositories, replicas=replicas, lineage_edges=edges,
            scope_commitment=None, declared_scope_complete=complete,
            unresolved_reference_ids=tuple(unresolved),
        )
        return replace(draft, scope_commitment=self.builder.expected_scope_commitment(draft))

    def test_multi_custodian_derivative_and_replica_obligations_are_distinct(self) -> None:
        updated = self.manager.attach_topology(self.case.case_id, self._view())
        graph = updated.graph
        self.assertIsNotNone(graph)
        self.assertTrue(graph.baseline_verifiable)
        self.assertEqual({"ASSET-ROOT", "ASSET-DERIVED"}, set(graph.discovered_asset_ids))
        self.assertEqual(3, len(graph.obligations))
        self.assertEqual(3, len({row.obligation_id for row in graph.obligations}))
        self.assertEqual({"REPLICA-PRIMARY", "REPLICA-BACKUP", "REPLICA-DERIVED"}, {row.replica_id for row in graph.obligations})
        self.assertEqual({"CUSTODIAN-UTILITY", "CUSTODIAN-BACKUP", "CUSTODIAN-AGGREGATOR"}, set(graph.custodians))

    def test_input_order_does_not_change_graph_or_commitments(self) -> None:
        policy = self.registry.get(self.case.policy_profile_id)
        first = self.builder.build(view=self._view(), root_asset_ids=self.case.root_asset_ids, accepted_at=ACCEPTED, policy=policy)
        second = self.builder.build(view=self._view(reverse=True), root_asset_ids=self.case.root_asset_ids, accepted_at=ACCEPTED, policy=policy)
        self.assertEqual(first, second)
        self.assertEqual(first.scope_commitment, second.scope_commitment)
        self.assertEqual(first.obligation_commitment, second.obligation_commitment)

    def test_policy_profile_controls_grade_disposition_and_deadline(self) -> None:
        graph = self.manager.attach_topology(self.case.case_id, self._view()).graph
        backup = next(row for row in graph.obligations if row.replica_id == "REPLICA-BACKUP")
        primary = next(row for row in graph.obligations if row.replica_id == "REPLICA-PRIMARY")
        self.assertEqual("E3", backup.minimum_evidence_grade)
        self.assertEqual("E2", primary.minimum_evidence_grade)
        self.assertEqual(ACCEPTED + timedelta(hours=720), primary.deadline)
        self.assertEqual(("CRYPTO_ERASED", "ERASED"), primary.permitted_dispositions)

    def test_case_and_obligation_updates_are_monotone_and_idempotent(self) -> None:
        attached = self.manager.attach_topology(self.case.case_id, self._view())
        obligation_id = attached.graph.obligations[0].obligation_id
        dispatched = self.manager.update_obligation(self.case.case_id, obligation_id, ObligationStatus.DISPATCHED)
        same = self.manager.update_obligation(self.case.case_id, obligation_id, ObligationStatus.DISPATCHED)
        self.assertEqual(dispatched, same)
        submitted = self.manager.update_obligation(self.case.case_id, obligation_id, ObligationStatus.EVIDENCE_SUBMITTED, evidence_refs=("EVIDENCE-002", "EVIDENCE-001"))
        row = next(item for item in submitted.graph.obligations if item.obligation_id == obligation_id)
        self.assertEqual(("EVIDENCE-001", "EVIDENCE-002"), row.evidence_refs)
        with self.assertRaisesRegex(ValueError, "invalid obligation transition"):
            self.manager.update_obligation(self.case.case_id, obligation_id, ObligationStatus.PENDING)
        replayed_create = self.manager.create_case(
            run_id="RUN-001", dataset_id="DATASET-SMART-GRID-001", correlation_id="CORR-001",
            request_id="REQUEST-001", requester_principal_id="PRINCIPAL-REQUESTER",
            root_asset_ids=("ASSET-ROOT",), policy_profile_id="VERCLO-POLICY-TECHNICAL-ERASURE",
            accepted_at=ACCEPTED, case_id="CASE-001",
            metadata={"source_profile": "PAEBENCH-SMART-GRID-v1"},
        )
        self.assertEqual(submitted, replayed_create)

    def test_exception_is_policy_bound_metadata_and_not_automatic_closure(self) -> None:
        attached = self.manager.attach_topology(self.case.case_id, self._view())
        obligation = attached.graph.obligations[0]
        updated = self.manager.assert_exception(
            self.case.case_id, obligation.obligation_id,
            authority_principal_id="AUTHORITY-RETENTION-REVIEW",
            basis_commitment="a" * 64, effective_at=ACCEPTED,
            expires_at=ACCEPTED + timedelta(days=30),
        )
        self.assertEqual(1, len(updated.graph.exceptions))
        self.assertEqual("ASSERTED", updated.graph.exceptions[0].status)
        tracked = next(row for row in updated.graph.obligations if row.obligation_id == obligation.obligation_id)
        self.assertEqual(ObligationStatus.EXCEPTION_ASSERTED, tracked.status)
        self.assertFalse(hasattr(updated, "closure_ground_truth"))
        with self.assertRaisesRegex(ValueError, "not admitted"):
            self.manager.assert_exception(
                self.case.case_id, obligation.obligation_id,
                authority_principal_id="UNAUTHORISED-AUTHORITY",
                basis_commitment="b" * 64, effective_at=ACCEPTED,
                expires_at=ACCEPTED + timedelta(days=1),
            )

    def test_declared_incomplete_visibility_fails_baseline_without_hidden_ids(self) -> None:
        graph = self.manager.attach_topology(
            self.case.case_id,
            self._view(complete=False, unresolved=("UNDISCLOSED-ENDPOINT",)),
        ).graph
        self.assertFalse(graph.baseline_verifiable)
        self.assertEqual(("DECLARED_SCOPE_INCOMPLETE", "UNRESOLVED_REFERENCES"), graph.baseline_reason_codes)
        self.assertNotIn("UNDISCLOSED-ENDPOINT", repr(graph))
        self.assertEqual(3, len(graph.obligations))

    def test_wholly_hidden_derivative_is_not_inferred_from_a_complete_visible_view(self) -> None:
        root_only = TopologyView(
            case_id="CASE-001", dataset_id="DATASET-SMART-GRID-001", correlation_id="CORR-001",
            scope_version=1,
            assets=(AssetDescriptor("ASSET-ROOT", "DATASET-SMART-GRID-001", "interval_reading"),),
            repositories=(RepositoryDescriptor("REPO-PRIMARY", "ORG-UTILITY", "CUSTODIAN-UTILITY", "operational"),),
            replicas=(ReplicaDescriptor("REPLICA-PRIMARY", "ASSET-ROOT", "REPO-PRIMARY", "primary"),),
            lineage_edges=(), scope_commitment=None,
        )
        root_only = replace(root_only, scope_commitment=self.builder.expected_scope_commitment(root_only))
        graph = self.builder.build(view=root_only, root_asset_ids=("ASSET-ROOT",), accepted_at=ACCEPTED, policy=self.registry.get(self.case.policy_profile_id))
        self.assertTrue(graph.baseline_verifiable)
        self.assertEqual(1, len(graph.obligations))
        self.assertEqual(("ASSET-ROOT",), graph.discovered_asset_ids)

    def test_payload_and_privileged_ground_truth_fields_are_rejected(self) -> None:
        base = {
            "run_id":"RUN-X", "dataset_id":"DATASET-X", "correlation_id":"CORR-X",
            "request_id":"REQUEST-X", "requester_principal_id":"PRINCIPAL-X",
            "root_asset_ids":["ASSET-X"], "policy_profile_id":"VERCLO-POLICY-TECHNICAL-ERASURE",
            "accepted_at":"2026-09-04T10:00:00Z",
        }
        for prohibited in ("payload", "personal_data", "closure_ground_truth", "expected_outcome", "attack_type"):
            with self.subTest(prohibited=prohibited):
                value = dict(base)
                value["metadata"] = {prohibited: "forbidden"}
                with self.assertRaisesRegex(ValueError, "prohibited fields"):
                    self.manager.create_case_from_mapping(value)

    def test_verclo_service_imports_are_independent_of_paegen(self) -> None:
        forbidden_modules = {"htgl_dataset_generator", "paegen"}
        for path in (PROJECT_ROOT / "src" / "verclo").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            self.assertFalse(imported & forbidden_modules, path.name)
        model_fields = {item.name for cls in (ErasureCase, Obligation) for item in fields(cls)}
        self.assertFalse(model_fields & {"payload", "personal_data", "closure_ground_truth", "expected_outcome", "world_disposition"})


if __name__ == "__main__":
    unittest.main()
