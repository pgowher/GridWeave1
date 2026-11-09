from __future__ import annotations

import copy
from datetime import datetime, timedelta
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.catalog import CatalogBuild  # noqa: E402
from htgl_dataset_generator.config import load_config, resolve_config  # noqa: E402
from htgl_dataset_generator.evidence import (  # noqa: E402
    EvidenceObligationBuild,
    EvidenceObligationError,
    ObligationTemplateError,
    build_evidence_obligations,
    evaluate_evidence_sufficiency,
    load_obligation_template_bundle,
    require_evidence_sufficient_for_release,
    validate_evidence_obligations,
)
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_obligations  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.policy import build_policy_oracle, load_policy_package  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest, content_id  # noqa: E402


class EvidenceObligationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        families = tuple(raw["workflows"]["families"]["value"])
        raw["arrivals"]["base_rates_per_day"]["value"] = {
            family: 0.01 for family in families
        }
        raw["arrivals"]["conditioned_total"]["value"] = 200
        cls.resolved = resolve_config(raw)
        cls.contract = load_contract()
        cls.result = orchestrate_pipeline_through_obligations(cls.resolved)[0]
        cls.pipeline = cls.result.artifacts
        cls.through_dag = cls.pipeline.through_policy.through_dag
        cls.policy = cls.pipeline.through_policy.policy
        cls.obligations = cls.pipeline.evidence_obligations
        cls.policy_package = load_policy_package(cls.resolved, contract=cls.contract)
        cls.bundle = load_obligation_template_bundle(
            cls.resolved, cls.policy_package, contract=cls.contract
        )

    def test_bundle_is_pinned_and_covers_all_scopes(self) -> None:
        self.assertEqual(
            self.resolved.evidence.obligation_template_bundle_sha256,
            self.bundle.bundle_sha256,
        )
        self.assertEqual(
            set(self.resolved.evidence.obligation_template_ids),
            {template.template_id for template in self.bundle.templates},
        )
        self.assertEqual(
            {"object", "replica_set", "workflow", "actor_set", "causal_closure"},
            {clause.coverage_scope for clause in self.bundle.clauses},
        )

    def test_obligations_are_schema_valid_deterministic_and_minimized(self) -> None:
        repeated = build_evidence_obligations(
            self.resolved,
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            physical=self.through_dag.physical,
            arrivals=self.through_dag.arrivals,
            workflows=self.through_dag.workflows,
            causal_dag=self.through_dag.causal_dag,
            policy=self.policy,
            contract=self.contract,
        )
        self.assertEqual(
            canonical_records_digest(self.obligations.evidence_obligations),
            canonical_records_digest(repeated.evidence_obligations),
        )
        diagnostics = next(iter(self.obligations.diagnostics.values()))
        self.assertGreater(diagnostics.minimized_candidate_count, 0)
        keys = set()
        for row in self.obligations.evidence_obligations:
            validate_record(self.contract, "evidence_obligation", row)
            key = (
                row["event_id"],
                row["obligation_type"],
                row["subject_object_id"],
                row["responsible_actor_id"],
                row["coverage_scope"],
            )
            self.assertNotIn(key, keys)
            keys.add(key)

    def test_erasure_stages_expand_auth_scope_replica_execution_and_verification(self) -> None:
        events = {
            row["event_id"]: row for row in self.through_dag.causal_dag.governance_events
        }
        replicas_by_object: dict[str, set[str]] = {}
        for replica in self.through_dag.catalog.data_object_replicas:
            if replica["deletion_status"] != "exempt":
                replicas_by_object.setdefault(replica["data_object_id"], set()).add(replica["replica_id"])
        rows_by_event: dict[str, list[dict[str, object]]] = {}
        for row in self.obligations.evidence_obligations:
            rows_by_event.setdefault(row["event_id"], []).append(row)
        observed_stages: set[str] = set()
        for event_id, event in events.items():
            if event["event_family"] != "erasure":
                continue
            observed_stages.add(event["event_type"])
            rows = rows_by_event[event_id]
            object_id = event["data_object_id"]
            if event["event_type"] == "erasure_requested":
                self.assertTrue(any(row["obligation_type"] == "authorization" for row in rows))
                self.assertTrue(
                    any(
                        row["obligation_type"] == "provenance"
                        and any(
                            "ERASURE-REQUEST-SCOPING" in clause_id
                            for clause_id in self._provenance(row["obligation_id"]).template_clause_ids
                        )
                        for row in rows
                    )
                )
            elif event["event_type"] == "erasure_propagated":
                observed = {
                    row["subject_object_id"]
                    for row in rows
                    if row["obligation_type"] == "provenance"
                    and row["coverage_scope"] == "replica_set"
                }
                self.assertEqual(replicas_by_object[object_id], observed)
            elif event["event_type"] == "erasure_executed":
                observed = {
                    row["subject_object_id"]
                    for row in rows
                    if row["obligation_type"] == "replica_deletion"
                }
                self.assertEqual(replicas_by_object[object_id], observed)
            elif event["event_type"] == "erasure_verified":
                verification = [row for row in rows if row["obligation_type"] == "verification"]
                self.assertEqual(1, len(verification))
                provenance = self._provenance(verification[0]["obligation_id"])
                self.assertEqual(
                    len(provenance.dependency_event_ids),
                    verification[0]["minimum_count"],
                )
        self.assertEqual(
            {"erasure_requested", "erasure_propagated", "erasure_executed", "erasure_verified"},
            observed_stages,
        )

    def test_retention_exception_exempts_exact_replica(self) -> None:
        erasure_event = next(
            row
            for row in self.through_dag.causal_dag.governance_events
            if row["event_type"] == "erasure_requested"
        )
        object_id = erasure_event["data_object_id"]
        target_replica = next(
            row
            for row in self.through_dag.catalog.data_object_replicas
            if row["data_object_id"] == object_id and row["deletion_status"] != "exempt"
        )
        replicas = []
        for row in self.through_dag.catalog.data_object_replicas:
            updated = dict(row)
            if row["replica_id"] == target_replica["replica_id"]:
                updated["deletion_status"] = "exempt"
                updated["deletion_due_at"] = None
                updated["deleted_at"] = None
            replicas.append(updated)
        altered_catalog = CatalogBuild(
            local_databases=self.through_dag.catalog.local_databases,
            data_objects=self.through_dag.catalog.data_objects,
            data_object_replicas=tuple(replicas),
            custody_edges=self.through_dag.catalog.custody_edges,
            diagnostics=self.through_dag.catalog.diagnostics,
        )
        altered_policy = build_policy_oracle(
            self.resolved,
            world=self.through_dag.world,
            catalog=altered_catalog,
            causal_dag=self.through_dag.causal_dag,
            contract=self.contract,
        )
        altered = build_evidence_obligations(
            self.resolved,
            world=self.through_dag.world,
            catalog=altered_catalog,
            physical=self.through_dag.physical,
            arrivals=self.through_dag.arrivals,
            workflows=self.through_dag.workflows,
            causal_dag=self.through_dag.causal_dag,
            policy=altered_policy,
            contract=self.contract,
        )
        request_rows = [
            row for row in altered.evidence_obligations if row["event_id"] == erasure_event["event_id"]
        ]
        exceptions = {
            row["subject_object_id"]
            for row in request_rows
            if row["obligation_type"] == "retention_exception"
        }
        self.assertEqual({target_replica["replica_id"]}, exceptions)
        later_erasure_event_ids = {
            row["event_id"]
            for row in self.through_dag.causal_dag.governance_events
            if row["workflow_instance_id"] == erasure_event["workflow_instance_id"]
            and row["event_type"] in {"erasure_propagated", "erasure_executed"}
        }
        self.assertFalse(
            any(
                row["event_id"] in later_erasure_event_ids
                and row["subject_object_id"] == target_replica["replica_id"]
                and row["obligation_type"] in {"provenance", "replica_deletion"}
                for row in altered.evidence_obligations
            )
        )

    def test_missing_obligation_fails_independent_recomputation(self) -> None:
        removed = next(
            row for row in self.obligations.evidence_obligations if row["obligation_type"] == "replica_deletion"
        )
        broken = EvidenceObligationBuild(
            evidence_obligations=tuple(
                row for row in self.obligations.evidence_obligations if row["obligation_id"] != removed["obligation_id"]
            ),
            provenance=tuple(
                row for row in self.obligations.provenance if row.obligation_id != removed["obligation_id"]
            ),
            diagnostics=self.obligations.diagnostics,
            template_bundle_sha256=self.obligations.template_bundle_sha256,
        )
        with self.assertRaisesRegex(EvidenceObligationError, "subjects mismatch|recomputation"):
            self._validate(broken)

    def test_strict_sufficiency_detects_missing_late_invalid_dependency_and_contradiction(self) -> None:
        receipts = self._complete_receipts()
        complete = evaluate_evidence_sufficiency(
            self.obligations,
            receipts,
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            causal_dag=self.through_dag.causal_dag,
            contract=self.contract,
        )
        self.assertEqual(complete.diagnostics.obligation_count, complete.diagnostics.sufficient_obligation_count)
        require_evidence_sufficient_for_release(complete)

        verification = next(
            row for row in self.obligations.evidence_obligations if row["obligation_type"] == "verification"
        )
        matching = [row for row in receipts if row["obligation_id"] == verification["obligation_id"]]
        missing = evaluate_evidence_sufficiency(
            self.obligations,
            [row for row in receipts if row["receipt_id"] != matching[0]["receipt_id"]],
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            causal_dag=self.through_dag.causal_dag,
            contract=self.contract,
        )
        missing_truth = next(item for item in missing.truth if item.obligation_id == verification["obligation_id"])
        self.assertFalse(missing_truth.coverage_complete)
        with self.assertRaisesRegex(EvidenceObligationError, "release gate failed"):
            require_evidence_sufficient_for_release(missing)

        base = matching[0]
        contradictory = dict(base)
        contradictory["receipt_id"] = content_id("test_receipt", {"contradiction": base["receipt_id"]})
        contradictory["canonical_digest"] = "f" * 64
        contradictory["verification_status_truth"] = "invalid"
        conflict = evaluate_evidence_sufficiency(
            self.obligations,
            [*receipts, contradictory],
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            causal_dag=self.through_dag.causal_dag,
            contract=self.contract,
        )
        conflict_truth = next(item for item in conflict.truth if item.obligation_id == verification["obligation_id"])
        self.assertFalse(conflict_truth.validity_complete)
        self.assertFalse(conflict_truth.contradiction_free)

        late = [dict(row) for row in receipts]
        late_row = next(row for row in late if row["obligation_id"] == verification["obligation_id"])
        due = datetime.fromisoformat(verification["due_at"].replace("Z", "+00:00"))
        late_row["issued_at"] = (due + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        late_result = evaluate_evidence_sufficiency(
            self.obligations,
            late,
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            causal_dag=self.through_dag.causal_dag,
            contract=self.contract,
        )
        late_truth = next(item for item in late_result.truth if item.obligation_id == verification["obligation_id"])
        self.assertFalse(late_truth.timeliness_complete)
        self.assertTrue(late_truth.late_receipt_ids)

        outside_event = next(
            event_id
            for event_id in {row["event_id"] for row in self.through_dag.causal_dag.governance_events}
            if event_id not in set(self._provenance(verification["obligation_id"]).dependency_event_ids)
        )
        missing_dependency = [dict(row) for row in receipts]
        dependency_row = next(
            row for row in missing_dependency if row["obligation_id"] == verification["obligation_id"]
        )
        dependency_row["event_id"] = outside_event
        dependency_result = evaluate_evidence_sufficiency(
            self.obligations,
            missing_dependency,
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            causal_dag=self.through_dag.causal_dag,
            contract=self.contract,
        )
        dependency_truth = next(
            item for item in dependency_result.truth if item.obligation_id == verification["obligation_id"]
        )
        self.assertFalse(dependency_truth.dependencies_complete)
        self.assertTrue(dependency_truth.missing_dependency_receipt_ids)

    def test_parquet_and_replicate_orchestration(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(
                self.obligations.table_records(), Path(tmp), contract=self.contract
            )
            table = pq.read_table(written["evidence_obligation"])
            self.assertEqual(len(self.obligations.evidence_obligations), table.num_rows)
            self.assertEqual(
                b"htgl.dataset.v1.evidence_obligation",
                table.schema.metadata[b"schema_id"],
            )
            self.assertEqual("ZSTD", pq.ParquetFile(written["evidence_obligation"]).metadata.row_group(0).column(0).compression)

        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["run"]["replicate_count"]["value"] = 2
        raw["validation"]["repetition_count"]["value"] = 2
        resolved = resolve_config(raw)
        serial = orchestrate_pipeline_through_obligations(resolved, worker_count=1)
        results = orchestrate_pipeline_through_obligations(resolved, worker_count=2)
        self.assertEqual([0, 1], [result.run_plan.replicate_id for result in results])
        self.assertEqual(
            [result.table_digests for result in serial],
            [result.table_digests for result in results],
        )
        self.assertNotEqual(
            results[0].table_digests["evidence_obligation"],
            results[1].table_digests["evidence_obligation"],
        )

    def test_template_digest_tampering_fails_closed(self) -> None:
        source = REPO_ROOT / "evidence" / "obligation_templates_v1.json"
        raw = json.loads(source.read_text(encoding="utf-8"))
        raw["templates"][0]["clauses"][0]["deadline_seconds"] += 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered_templates.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(ObligationTemplateError, "SHA-256"):
                load_obligation_template_bundle(
                    self.resolved, self.policy_package, path, contract=self.contract
                )

    def test_contradictory_minimized_obligation_grammar_fails_closed(self) -> None:
        source = REPO_ROOT / "evidence" / "obligation_templates_v1.json"
        templates = json.loads(source.read_text(encoding="utf-8"))
        conflicting_clause = copy.deepcopy(templates["templates"][0]["clauses"][0])
        conflicting_clause["clause_id"] = "POLICY-TRACE-CONTRADICTORY-EVIDENCE-TYPE"
        conflicting_clause["required_evidence_types"] = ["inclusion_proof"]
        templates["templates"][0]["clauses"].append(conflicting_clause)
        digest = hashlib.sha256(
            json.dumps(
                templates,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        raw_config = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        raw_config["arrivals"]["base_rates_per_day"]["value"] = {
            family: 0.01 for family in raw_config["workflows"]["families"]["value"]
        }
        raw_config["arrivals"]["conditioned_total"]["value"] = 200
        raw_config["evidence"]["obligation_template_bundle_sha256"]["value"] = digest
        resolved = resolve_config(raw_config)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contradictory_templates.json"
            path.write_text(json.dumps(templates), encoding="utf-8")
            with self.assertRaisesRegex(EvidenceObligationError, "no common acceptable evidence type"):
                build_evidence_obligations(
                    resolved,
                    world=self.through_dag.world,
                    catalog=self.through_dag.catalog,
                    physical=self.through_dag.physical,
                    arrivals=self.through_dag.arrivals,
                    workflows=self.through_dag.workflows,
                    causal_dag=self.through_dag.causal_dag,
                    policy=self.policy,
                    template_path=path,
                    contract=self.contract,
                )

    def _complete_receipts(self) -> list[dict[str, object]]:
        event_by_id = {
            row["event_id"]: row for row in self.through_dag.causal_dag.governance_events
        }
        receipts: list[dict[str, object]] = []
        for obligation in self.obligations.evidence_obligations:
            provenance = self._provenance(obligation["obligation_id"])
            scope = obligation["coverage_scope"]
            for member in provenance.coverage_member_ids:
                event_id = (
                    member if scope in {"workflow", "causal_closure"} else obligation["event_id"]
                )
                issued_at = event_by_id[obligation["event_id"]]["timestamp"]
                receipt_id = content_id(
                    "evidence_receipt_test_fixture",
                    {"obligation_id": obligation["obligation_id"], "member": member},
                )
                receipts.append(
                    {
                        "receipt_id": receipt_id,
                        "obligation_id": obligation["obligation_id"],
                        "event_id": event_id,
                        "issuer_actor_id": obligation["responsible_actor_id"],
                        "evidence_type": obligation["required_evidence_types"][0],
                        "issued_at": issued_at,
                        "canonical_digest": hashlib.sha256(
                            f"htgl-test-receipt:{receipt_id}:{member}".encode("ascii")
                        ).hexdigest(),
                        "algorithm": "sha256-domain-separated-test-fixture-v1",
                        "key_id": None,
                        "anchor_id": None,
                        "verification_status_truth": "valid",
                        "covers_replica_ids": [member] if scope == "replica_set" else [],
                        "payload_ref": None,
                    }
                )
        return receipts

    def _provenance(self, obligation_id: str):
        return next(row for row in self.obligations.provenance if row.obligation_id == obligation_id)

    def _validate(self, build: EvidenceObligationBuild) -> None:
        validate_evidence_obligations(
            build,
            self.resolved,
            world=self.through_dag.world,
            catalog=self.through_dag.catalog,
            workflows=self.through_dag.workflows,
            causal_dag=self.through_dag.causal_dag,
            policy=self.policy,
            policy_package=self.policy_package,
            bundle=self.bundle,
            replicate_id=0,
            scenario_ids=self.resolved.run.selected_scenario_ids,
            contract=self.contract,
        )


if __name__ == "__main__":
    unittest.main()
