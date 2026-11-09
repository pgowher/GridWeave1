from __future__ import annotations

from dataclasses import replace
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import (  # noqa: E402
    CORE_VALIDATION_CHECK_IDS,
    resolve_config_file,
)
from htgl_dataset_generator.experiments import (  # noqa: E402
    build_validation_for_sampling_result,
    orchestrate_pipeline_through_sampling,
    orchestrate_pipeline_through_validation,
)
from htgl_dataset_generator.io import (  # noqa: E402
    write_parquet_table,
    write_validation_artifact_bundle,
)
from htgl_dataset_generator.schemas import load_contract  # noqa: E402
from htgl_dataset_generator.seeds import (  # noqa: E402
    canonical_records_digest,
    seed_stream_records_for_plan,
)
from htgl_dataset_generator.validation import (  # noqa: E402
    ArtifactVerificationInput,
    JointValidationError,
    PerformanceObservation,
    ReplicateExecutionEvidence,
    ValidationInput,
    build_joint_validation,
    build_run_scenario_record,
    require_validation_release,
    validate_publication_gate,
)


CLAIM_MATRIX = {
    "represented_population": 100,
    "materialized_rows": 25,
    "executed_operations": None,
    "generator_boundary": "benchmark_artifacts_only_no_htgl_consensus_ledger_real_erasure_legal_enforcement_or_utility_deployment",
    "legal_compliance_claim": False,
    "real_deletion_claim": False,
    "cryptographic_proof_scope": "configured synthetic evidence profile only",
    "operational_execution_claim": False,
}


class JointValidationEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        cls.sampling_result = orchestrate_pipeline_through_sampling(cls.resolved)[0]
        cls.replicate_evidence = (
            ReplicateExecutionEvidence(
                scenario_id=cls.sampling_result.run_plan.scenario_id,
                replicate_id=cls.sampling_result.run_plan.replicate_id,
                seed_stream_digest=cls.sampling_result.seed_stream_digest,
                retained_metric_count=len(
                    cls.sampling_result.artifacts.authoritative_table_records()["run_metric"]
                ),
            ),
        )
        cls.default_build = build_validation_for_sampling_result(
            cls.resolved,
            cls.sampling_result,
            replicate_evidence=cls.replicate_evidence,
        )
        cls.default_input = cls._make_input()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.artifact_input = cls._build_artifact_input(
            cls.default_build.prevalidation_table_records(),
            Path(cls.temporary.name),
        )
        cls.reference_digests = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in cls.default_build.prevalidation_table_records().items()
        }
        row_count = sum(
            len(rows) for rows in cls.default_build.prevalidation_table_records().values()
        )
        stored_bytes = sum(len(value) for value in cls.artifact_input.artifact_payloads.values())
        elapsed_seconds = max(1.0, row_count / 1000.0)
        cls.performance = PerformanceObservation(
            measurement_profile_id=cls.resolved.validation.metric_threshold_profile_id,
            generated_row_count=row_count,
            elapsed_seconds=elapsed_seconds,
            rows_per_second=row_count / elapsed_seconds,
            peak_memory_bytes=1024 * 1024,
            stored_bytes=stored_bytes,
            bytes_per_row=stored_bytes / row_count,
            parallel_efficiency=1.0,
            deterministic_digest_equal=True,
        )
        cls.complete_build = build_validation_for_sampling_result(
            cls.resolved,
            cls.sampling_result,
            replicate_evidence=cls.replicate_evidence,
            artifact_verification=cls.artifact_input,
            reproducibility_reference_digests=cls.reference_digests,
            performance_observation=cls.performance,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _make_input(cls, **overrides):
        through_sampling = cls.sampling_result.artifacts
        through_observers = through_sampling.through_observers
        through_anomalies = through_observers.through_anomalies
        through_evidence = through_anomalies.through_evidence
        through_obligations = through_evidence.through_obligations
        through_policy = through_obligations.through_policy
        through_dag = through_policy.through_dag
        run_scenario_rows = (
            build_run_scenario_record(cls.resolved, cls.sampling_result.run_plan),
        )
        seed_rows = tuple(
            seed_stream_records_for_plan(cls.resolved, cls.sampling_result.run_plan)
        )
        tables = dict(through_sampling.authoritative_table_records())
        tables["run_scenario"] = run_scenario_rows
        tables["seed_stream"] = seed_rows
        values = {
            "resolved": cls.resolved,
            "run_plan": cls.sampling_result.run_plan,
            "run_scenario_rows": run_scenario_rows,
            "seed_stream_rows": seed_rows,
            "tables": dict(sorted(tables.items())),
            "world": through_dag.world,
            "catalog": through_dag.catalog,
            "physical": through_dag.physical,
            "arrivals": through_dag.arrivals,
            "workflows": through_dag.workflows,
            "causal_dag": through_dag.causal_dag,
            "policy": through_policy.policy,
            "obligations": through_obligations.evidence_obligations,
            "receipts": through_evidence.evidence_receipts,
            "anomalies": through_anomalies.anomalies,
            "observers": through_observers.observers,
            "sampling": through_sampling.sampling,
            "replicate_evidence": cls.replicate_evidence,
        }
        values.update(overrides)
        return ValidationInput(**values)

    @classmethod
    def _build_artifact_input(cls, tables, root: Path) -> ArtifactVerificationInput:
        payloads = {}
        manifest_rows = []
        record_counts = {}
        schema_ids = {}
        for index, (table_name, rows) in enumerate(sorted(tables.items())):
            relative_path = f"tables/{table_name}.parquet"
            path = write_parquet_table(
                table_name,
                rows,
                root / relative_path,
                contract=cls.contract,
                compression="ZSTD",
            )
            payload = path.read_bytes()
            table = cls.contract.table(table_name)
            payloads[relative_path] = payload
            record_counts[relative_path] = len(rows)
            schema_ids[relative_path] = table.schema_id
            manifest_rows.append(
                {
                    "artifact_id": f"ART-S13-TEST-{index:03d}",
                    "run_id": cls.sampling_result.run_plan.run_id,
                    "relative_path": relative_path,
                    "media_type": "application/parquet",
                    "schema_id": table.schema_id,
                    "record_count": len(rows),
                    "uncompressed_bytes": len(payload),
                    "stored_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "partition_keys": [],
                    "privacy_class": table.privacy_class,
                    "generation_stage": "S15.test-artifact-compiler.v1",
                    "publication_eligible": False,
                }
            )
        return ArtifactVerificationInput(
            artifact_payloads=dict(sorted(payloads.items())),
            manifest_rows=tuple(manifest_rows),
            expected_record_counts=dict(sorted(record_counts.items())),
            expected_schema_ids=dict(sorted(schema_ids.items())),
        )

    @staticmethod
    def _status(build, check_id: str) -> str:
        return next(
            str(row["status"])
            for row in build.validation_issues
            if row["check_id"] == check_id
        )

    def test_registry_finalizes_all_core_checks_and_blocks_unexecuted_release_evidence(self) -> None:
        build = self.default_build.validation
        self.assertEqual(set(CORE_VALIDATION_CHECK_IDS), set(build.required_check_ids))
        self.assertEqual(set(CORE_VALIDATION_CHECK_IDS), {row["check_id"] for row in build.validation_issues})
        self.assertEqual("not_applicable", self._status(build, "PRIVACY-SOURCE-001"))
        self.assertEqual(
            {"MANIFEST-001", "REPRODUCIBILITY-001", "PERFORMANCE-001"},
            {
                row["check_id"]
                for row in build.validation_issues
                if row["status"] == "not_executed"
            },
        )
        self.assertFalse(build.release_eligible)
        with self.assertRaisesRegex(JointValidationError, "release packaging refused"):
            require_validation_release(build)

    def test_complete_external_evidence_makes_the_validation_ledger_release_eligible(self) -> None:
        build = self.complete_build.validation
        self.assertTrue(build.release_eligible)
        require_validation_release(build)
        self.assertEqual([], [row for row in build.validation_issues if row["status"] == "fail"])
        self.assertEqual([], [row for row in build.validation_issues if row["status"] == "not_executed"])
        tables = {
            "validation_issue": build.validation_issues,
            "run_metric": self.complete_build.prevalidation_table_records()["run_metric"],
            "sample_membership": self.complete_build.prevalidation_table_records()["sample_membership"],
            "artifact_manifest": tuple(dict(row) for row in self.artifact_input.manifest_rows),
        }
        validate_publication_gate(
            tables,
            claim_matrix=CLAIM_MATRIX,
            required_check_ids=build.required_check_ids,
            contract=self.contract,
        )

    def test_workflow_mutation_is_detected_by_workflow_check(self) -> None:
        event_id = str(self.default_input.workflows.governance_events[0]["event_id"])
        workflow_events = [dict(row) for row in self.default_input.workflows.governance_events]
        final_events = [dict(row) for row in self.default_input.causal_dag.governance_events]
        for rows in (workflow_events, final_events):
            row = next(item for item in rows if str(item["event_id"]) == event_id)
            row["workflow_state_after"] = "verified"
        workflows = replace(self.default_input.workflows, governance_events=tuple(workflow_events))
        dag = replace(self.default_input.causal_dag, governance_events=tuple(final_events))
        tables = dict(self.default_input.tables)
        tables["governance_event"] = tuple(final_events)
        build = build_joint_validation(
            self._make_input(workflows=workflows, causal_dag=dag, tables=tables)
        )
        self.assertEqual("fail", self._status(build, "WORKFLOW-001"))

    def test_policy_mutation_is_detected_by_independent_policy_check(self) -> None:
        rows = [dict(row) for row in self.default_input.policy.policy_decisions]
        rows[0]["expected_action"] = "deny" if rows[0]["expected_action"] != "deny" else "allow"
        policy = replace(self.default_input.policy, policy_decisions=tuple(rows))
        tables = dict(self.default_input.tables)
        tables["policy_decision_truth"] = tuple(rows)
        build = build_joint_validation(self._make_input(policy=policy, tables=tables))
        self.assertEqual("fail", self._status(build, "POLICY-001"))

    def test_evidence_digest_mutation_is_detected_by_independent_verification(self) -> None:
        rows = [dict(row) for row in self.default_input.receipts.evidence_receipts]
        index = next(
            i for i, row in enumerate(rows) if row["verification_status_truth"] == "valid"
        )
        rows[index]["canonical_digest"] = "00" * 32
        receipts = replace(self.default_input.receipts, evidence_receipts=tuple(rows))
        tables = dict(self.default_input.tables)
        tables["evidence_receipt"] = tuple(rows)
        build = build_joint_validation(self._make_input(receipts=receipts, tables=tables))
        self.assertEqual("fail", self._status(build, "EVIDENCE-001"))

    def test_observer_digest_mutation_is_detected_by_projection_check(self) -> None:
        rows = [dict(row) for row in self.default_input.observers.observer_events]
        rows[0]["projection_digest"] = "00" * 32
        observers = replace(self.default_input.observers, observer_events=tuple(rows))
        tables = dict(self.default_input.tables)
        tables["observer_event"] = tuple(rows)
        build = build_joint_validation(self._make_input(observers=observers, tables=tables))
        self.assertEqual("fail", self._status(build, "OBSERVER-001"))

    def test_sampling_probability_mutation_is_detected_by_sampling_check(self) -> None:
        rows = [dict(row) for row in self.default_input.sampling.sample_memberships]
        rows[0]["first_order_inclusion_probability"] /= 2.0
        sampling = replace(self.default_input.sampling, sample_memberships=tuple(rows))
        tables = dict(self.default_input.tables)
        tables["sample_membership"] = tuple(rows)
        build = build_joint_validation(self._make_input(sampling=sampling, tables=tables))
        self.assertEqual("fail", self._status(build, "SAMPLING-001"))

    def test_manifest_digest_mutation_is_detected_by_artifact_check(self) -> None:
        manifest_rows = [dict(row) for row in self.artifact_input.manifest_rows]
        manifest_rows[0]["sha256"] = "00" * 32
        corrupted = replace(self.artifact_input, manifest_rows=tuple(manifest_rows))
        build = build_joint_validation(
            self._make_input(artifact_verification=corrupted)
        )
        self.assertEqual("fail", self._status(build, "MANIFEST-001"))

    def test_unregistered_additive_check_is_not_executed_and_cannot_hide_core(self) -> None:
        validation = replace(
            self.resolved.validation,
            required_check_ids=tuple(
                sorted(set(self.resolved.validation.required_check_ids) | {"EXT-CUSTOM-001"})
            ),
        )
        resolved = replace(self.resolved, validation=validation)
        build = build_joint_validation(self._make_input(resolved=resolved))
        self.assertEqual("not_executed", self._status(build, "EXT-CUSTOM-001"))
        self.assertTrue(set(CORE_VALIDATION_CHECK_IDS) <= {row["check_id"] for row in build.validation_issues})
        self.assertFalse(build.release_eligible)

    def test_validation_issue_parquet_is_zstd_and_reproducible(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            first = write_validation_artifact_bundle(
                self.complete_build.validation,
                Path(temporary) / "first",
            )
            second = write_validation_artifact_bundle(
                self.complete_build.validation,
                Path(temporary) / "second",
            )
            self.assertEqual(first.metadata_sha256, second.metadata_sha256)
            self.assertEqual(
                hashlib.sha256(first.validation_issue_path.read_bytes()).hexdigest(),
                hashlib.sha256(second.validation_issue_path.read_bytes()).hexdigest(),
            )
            parquet_file = pq.ParquetFile(first.validation_issue_path)
            self.assertEqual(len(CORE_VALIDATION_CHECK_IDS), parquet_file.metadata.num_rows)
            self.assertEqual(
                "ZSTD", parquet_file.metadata.row_group(0).column(0).compression
            )
            parquet_file.close()

    def test_s13_table_digests_are_stable_across_worker_count(self) -> None:
        parallel = orchestrate_pipeline_through_validation(
            self.resolved,
            worker_count=3,
        )[0]
        expected = {
            table_name: canonical_records_digest(rows)
            for table_name, rows in self.default_build.authoritative_table_records().items()
        }
        self.assertEqual(dict(sorted(expected.items())), parallel.table_digests)


if __name__ == "__main__":
    unittest.main()
