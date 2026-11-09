from __future__ import annotations

import json
import csv
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.artifacts import (  # noqa: E402
    ArtifactCollisionError,
    ArtifactCompilerOptions,
    ReleaseEvidence,
    compile_and_publish_artifacts,
)
from htgl_dataset_generator.artifacts.transaction import ReleaseTransaction  # noqa: E402
from htgl_dataset_generator.config import resolve_config_file  # noqa: E402
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_metrics  # noqa: E402
from htgl_dataset_generator.schemas import load_contract  # noqa: E402
from htgl_dataset_generator.validation import PerformanceObservation  # noqa: E402


class ArtifactCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(
            REPO_ROOT / "configs" / "small_deterministic.json"
        )
        cls.primary = orchestrate_pipeline_through_metrics(cls.resolved)
        cls.clean = orchestrate_pipeline_through_metrics(cls.resolved)
        performance = {}
        for result in cls.primary.replicates:
            key = (result.run_plan.scenario_id, result.run_plan.replicate_id)
            row_count = sum(
                len(rows)
                for rows in result.artifacts.through_validation.prevalidation_table_records().values()
            )
            elapsed_seconds = max(1.0, row_count / 1000.0)
            stored_bytes = max(1, row_count * 1000)
            performance[key] = PerformanceObservation(
                measurement_profile_id=cls.resolved.validation.metric_threshold_profile_id,
                generated_row_count=row_count,
                elapsed_seconds=elapsed_seconds,
                rows_per_second=row_count / elapsed_seconds,
                peak_memory_bytes=2_000_000,
                stored_bytes=stored_bytes,
                bytes_per_row=stored_bytes / row_count,
                parallel_efficiency=1.0,
                deterministic_digest_equal=True,
            )
        cls.evidence = ReleaseEvidence(performance_by_run=performance)

    def test_release_has_exact_two_level_manifest_and_no_public_truth_leakage(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            result = compile_and_publish_artifacts(
                self.resolved,
                self.primary,
                self.clean,
                temporary,
                evidence=self.evidence,
            )
            root_manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                {"public", "evaluator_only", "restricted"},
                set(result.bundles),
            )
            self.assertEqual(result.release_root, result.bundle("public").release_root)
            self.assertEqual(
                3,
                len({item.release_root for item in result.bundles.values()}),
            )
            self.assertEqual(
                {(item.run_plan.scenario_id, item.run_plan.replicate_id) for item in self.primary.replicates},
                set(result.final_validation_by_run),
            )
            self.assertEqual(set(result.final_validation_by_run), set(result.final_metrics_by_run))
            self.assertTrue(all(result.final_validation_by_run.values()))
            self.assertTrue(all(result.final_metrics_by_run.values()))
            manifest_table = pq.read_table(result.artifact_manifest_path)
            rows = manifest_table.to_pylist()
            payload_paths = {
                path.relative_to(result.release_root).as_posix()
                for path in result.release_root.rglob("*")
                if path.is_file()
                and path.name not in {"manifest.json", "artifact_manifest.parquet"}
            }
            self.assertEqual(payload_paths, {row["relative_path"] for row in rows})
            self.assertEqual(
                {
                    path.relative_to(result.release_root).as_posix()
                    for path in result.release_root.rglob("*")
                    if path.is_file() and path.name != "manifest.json"
                },
                {item["relative_path"] for item in root_manifest["artifacts"]},
            )
            self.assertEqual(
                result.bundle("public").byte_digest,
                root_manifest["release_byte_digest"],
            )
            self.assertEqual("public", root_manifest["bundle_access_class"])
            self.assertTrue(root_manifest["jsonl_authority"] is False)
            allowed = {
                "public": {"public"},
                "evaluator_only": {"public", "evaluator_only", "sealed"},
                "restricted": {"public", "restricted"},
            }
            for access, bundle in result.bundles.items():
                manifest = json.loads(bundle.manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(access, manifest["bundle_access_class"])
                self.assertEqual(root_manifest["bundle_set_id"], manifest["bundle_set_id"])
                bundle_rows = pq.read_table(bundle.artifact_manifest_path).to_pylist()
                self.assertTrue(bundle_rows)
                self.assertTrue(
                    {row["privacy_class"] for row in bundle_rows} <= allowed[access]
                )
            self.assertFalse((result.release_root / "truth").exists())
            self.assertFalse((result.release_root / "canonical").exists())
            self.assertFalse((result.release_root / "raw").exists())
            self.assertFalse(
                (result.bundle("restricted").release_root / "truth").exists()
            )
            self.assertFalse(
                (result.bundle("evaluator_only").release_root / "canonical").exists()
            )
            public_jsonl = tuple(
                (result.release_root / "publication" / "adapters").rglob("*.jsonl")
            )
            self.assertTrue(public_jsonl)
            self.assertTrue(
                tuple((result.release_root / "publication" / "adapters").rglob("*.csv"))
            )
            adapter_conformance = json.loads(
                (
                    result.release_root
                    / "publication"
                    / "adapters"
                    / "conformance.json"
                ).read_text(encoding="utf-8")
            )
            self.assertTrue(adapter_conformance["all_passed"])
            self.assertEqual(
                sorted(self.resolved.output.adapters),
                adapter_conformance["configured_adapters"],
            )
            self.assertTrue(
                (
                    result.release_root
                    / "publication"
                    / "adapters"
                    / "mapping"
                    / "field_mapping.parquet"
                ).is_file()
            )
            for relative in (
                "metrics/baseline_metrics.parquet",
                "metrics/baseline_comparisons.parquet",
                "metrics/baseline_registry.json",
                "metrics/baseline_metadata.json",
                "publication/reports/baseline_ablation_report.csv",
                "publication/reports/baseline_ablation_report.md",
                "publication/reports/claim_matrix.csv",
                "publication/reports/data_card.md",
                "publication/reports/model_card.md",
                "publication/reports/quality_report.html",
                "publication/reports/quality_report.json",
                "publication/reports/metric_trace.csv",
                "publication/reports/report_evidence.json",
            ):
                self.assertTrue((result.release_root / relative).is_file(), relative)
            self.assertTrue(
                (
                    result.bundle("restricted").release_root
                    / "metrics"
                    / "baseline_conditions.parquet"
                ).is_file()
            )
            self.assertTrue(
                (
                    result.bundle("evaluator_only").release_root
                    / "truth"
                    / "evaluator_only"
                    / "baselines"
                    / "baseline_output_samples.parquet"
                ).is_file()
            )
            source_registry = json.loads(
                (
                    result.bundle("restricted").release_root
                    / "provenance"
                    / "sources.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual("htgl.source-registry.v1", source_registry["registry_format"])
            self.assertTrue(source_registry["records"])
            self.assertTrue(
                all(
                    row["source_label"] == "controlled_synthetic"
                    and row["licence"]["status"]
                    == "not_applicable_generator_owned_synthetic_definition"
                    for row in source_registry["records"]
                )
            )
            release_profile = json.loads(
                (
                    result.bundle("restricted").release_root
                    / "provenance"
                    / "release_profile.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                "procedural-controlled-synthetic-v1",
                release_profile["profile_id"],
            )
            self.assertFalse(release_profile["external_physical_integration_executed"])
            self.assertFalse(release_profile["external_power_flow_solver_executed"])
            self.assertFalse(release_profile["calibrated_physical_fidelity_claim_eligible"])
            self.assertTrue(
                (
                    result.release_root
                    / "publication"
                    / "provenance"
                    / "source_registry.json"
                ).is_file()
            )
            data_card = (
                result.release_root / "publication" / "reports" / "data_card.md"
            ).read_text(encoding="utf-8")
            self.assertIn("controlled procedural synthetic", data_card)
            self.assertIn("No imported physical benchmark", data_card)
            self.assertIn(
                "external solver convergence from controlled procedural synthetic",
                data_card,
            )
            with (
                result.release_root / "publication" / "reports" / "claim_matrix.csv"
            ).open("r", encoding="utf-8", newline="") as handle:
                claims = list(csv.DictReader(handle))
            self.assertTrue(claims)
            self.assertEqual(
                {
                    "claim_id",
                    "claim_text",
                    "evidence_class",
                    "scenario/replicates",
                    "artifact_ids",
                    "metric/estimator",
                    "baseline/ablation",
                    "assumptions",
                    "limitations",
                    "validation_gate",
                    "claim_status",
                },
                set(claims[0]),
            )
            self.assertEqual(len(claims), len({row["claim_id"] for row in claims}))
            self.assertTrue(all("sha256=" in row["artifact_ids"] for row in claims))
            self.assertTrue(all(row["validation_gate"] for row in claims))
            maturity = {
                row["claim_id"]: row["claim_status"]
                for row in claims
                if row["claim_id"].startswith("C-MATURITY-")
            }
            self.assertEqual(
                {
                    "C-MATURITY-REPLAY-01",
                    "C-MATURITY-SCALE-01",
                    "C-MATURITY-SNAPSHOT-01",
                    "C-MATURITY-STATISTICAL-01",
                },
                set(maturity),
            )
            self.assertEqual({"not_supported"}, set(maturity.values()))
            baseline_rows = pq.read_table(
                result.release_root / "metrics" / "baseline_comparisons.parquet"
            ).to_pylist()
            self.assertTrue(baseline_rows)
            self.assertTrue(all(row["common_random_group"] for row in baseline_rows))
            unmapped = json.loads(
                (
                    result.release_root
                    / "publication"
                    / "adapters"
                    / "unmapped_fields.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(0, unmapped["undocumented_field_count"])
            public_payload = "\n".join(path.read_text(encoding="utf-8") for path in public_jsonl)
            for forbidden in (
                "anomaly_instance_id",
                "protected_pair_id",
                "source_event_id",
                "first_order_inclusion_probability",
                "is_violation",
            ):
                self.assertNotIn(forbidden, public_payload)
            for bundle in result.bundles.values():
                parquet_paths = bundle.release_root.rglob("*.parquet")
                for parquet_path in parquet_paths:
                    parquet = pq.ParquetFile(parquet_path)
                    try:
                        for group_index in range(parquet.metadata.num_row_groups):
                            group = parquet.metadata.row_group(group_index)
                            for column_index in range(group.num_columns):
                                self.assertEqual(
                                    "ZSTD", group.column(column_index).compression
                                )
                    finally:
                        parquet.close()

    def test_clean_compilation_is_byte_identical_and_existing_identical_release_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as first_root, tempfile.TemporaryDirectory() as second_root:
            first = compile_and_publish_artifacts(
                self.resolved,
                self.primary,
                self.clean,
                first_root,
                evidence=self.evidence,
            )
            second = compile_and_publish_artifacts(
                self.resolved,
                self.primary,
                self.clean,
                second_root,
                evidence=self.evidence,
            )
            self.assertEqual(first.semantic_digest, second.semantic_digest)
            self.assertEqual(first.byte_digest, second.byte_digest)
            self.assertEqual(
                first.manifest_path.read_bytes(), second.manifest_path.read_bytes()
            )
            reused = compile_and_publish_artifacts(
                self.resolved,
                self.primary,
                self.clean,
                first_root,
                evidence=self.evidence,
                options=ArtifactCompilerOptions(collision_policy="reuse_identical"),
            )
            self.assertTrue(reused.reused_existing_release)
            self.assertEqual(first.byte_digest, reused.byte_digest)

    def test_injected_failure_does_not_publish_partial_release(self) -> None:
        def fail_before_promotion(phase: str, _staging: Path) -> None:
            if phase == "before_promotion":
                raise RuntimeError("injected writer failure")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "injected writer failure"):
                compile_and_publish_artifacts(
                    self.resolved,
                    self.primary,
                    self.clean,
                    temporary,
                    evidence=self.evidence,
                    options=ArtifactCompilerOptions(
                        failure_injector=fail_before_promotion
                    ),
                )
            target = Path(temporary) / f"run_{self.resolved.run.run_id}"
            self.assertFalse(target.exists())
            recovery_logs = tuple(Path(temporary).glob("*.recovery.*.json"))
            self.assertEqual(1, len(recovery_logs))
            recovery = json.loads(recovery_logs[0].read_text(encoding="utf-8"))
            self.assertEqual("compilation_failed", recovery["phases"][-1]["phase"])

    def test_unowned_target_is_never_replaced(self) -> None:
        contract = load_contract()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / f"run_{self.resolved.run.run_id}"
            target.mkdir()
            (target / "unowned.txt").write_text("preserve", encoding="utf-8")
            transaction = ReleaseTransaction(
                Path(temporary),
                run_id=self.resolved.run.run_id,
                config_sha256=self.resolved.config_sha256,
                contract_fingerprint=contract.contract_fingerprint,
                collision_policy="replace_owned",
            )
            transaction.begin()
            transaction.seal_owner_marker()
            with self.assertRaises(ArtifactCollisionError):
                transaction.promote("0" * 64)
            self.assertEqual("preserve", (target / "unowned.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
