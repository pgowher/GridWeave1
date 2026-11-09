from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.api import resolve_config_contract  # noqa: E402
from htgl_dataset_generator.artifacts import (  # noqa: E402
    ArtifactIntegrityError,
    ReleaseEvidence,
    read_release_evidence,
    write_release_evidence,
)
from htgl_dataset_generator.cli.main import main  # noqa: E402
from htgl_dataset_generator.validation import PerformanceObservation  # noqa: E402


class CliApiTests(unittest.TestCase):
    config = REPO_ROOT / "configs" / "small_deterministic.json"

    def test_every_command_has_write_free_explanation(self) -> None:
        extras = {
            "resolve-config": (),
            "generate": (),
            "validate": (),
            "metrics": (),
            "compile-artifacts": (),
            "run-study": ("--study-id", "STUDY-DRY-RUN"),
            "release-gate": ("--study-id", "STUDY-FINAL-GATE-DRY-RUN"),
            "reproduce": ("--source-release", "absent-release"),
            "export-adapter": (
                "--source-release",
                "absent-release",
                "--adapter-id",
                "csv",
            ),
            "report-claims": ("--source-release", "absent-release"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for command, command_extras in extras.items():
                output = root / command
                stdout = io.StringIO()
                stderr = io.StringIO()
                argv = [
                    command,
                    "--config",
                    str(self.config),
                    "--output-dir",
                    str(output),
                    "--dry-run",
                    *command_extras,
                ]
                with self.subTest(command=command), redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = main(argv)
                self.assertEqual(0, exit_code)
                payload = json.loads(stdout.getvalue())
                self.assertEqual(command, payload["command"])
                self.assertFalse(payload["writes_performed"])
                self.assertEqual(100, payload["represented_population_N"])
                self.assertEqual(25, payload["materialized_row_target_n"])
                self.assertIsNone(payload["executed_operation_target_not_observed_q"])
                if command in {"run-study", "release-gate"}:
                    self.assertEqual(30, payload["study_plan"]["required_repetitions"])
                    self.assertTrue(payload["study_plan"]["conditions"])
                    self.assertTrue(
                        all(
                            condition["condition_id"]
                            for condition in payload["study_plan"]["conditions"]
                        )
                    )
                self.assertFalse(output.exists())
                self.assertEqual("", stderr.getvalue())

    def test_resolved_config_workspace_reuses_identical_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = resolve_config_contract(self.config, temporary)
            second = resolve_config_contract(self.config, temporary)
            self.assertEqual(first.output_path, second.output_path)
            self.assertEqual(
                first.output_path.read_bytes(),
                second.output_path.read_bytes(),
            )
            manifest = first.output_path.parents[1] / "manifest.json"
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual("htgl.cli-command-stage-manifest.v1", payload["format"])
            self.assertEqual(first.resolved.config_sha256, payload["config_sha256"])

    def test_generate_command_writes_zstd_parquet_and_structured_events(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    (
                        "generate",
                        "--config",
                        str(self.config),
                        "--output-dir",
                        temporary,
                    )
                )
            self.assertEqual(0, exit_code)
            result = json.loads(stdout.getvalue())
            self.assertEqual("generate", result["command"])
            self.assertFalse(result["publication_eligible"])
            stage_root = Path(result["stage_root"])
            parquet_paths = tuple((stage_root / "authoritative").rglob("*.parquet"))
            self.assertGreater(len(parquet_paths), 20)
            for path in parquet_paths:
                parquet_file = pq.ParquetFile(path)
                try:
                    for group_index in range(parquet_file.num_row_groups):
                        group = parquet_file.metadata.row_group(group_index)
                        for column_index in range(group.num_columns):
                            self.assertEqual("ZSTD", group.column(column_index).compression)
                finally:
                    parquet_file.close()
            events = [json.loads(line) for line in stderr.getvalue().splitlines()]
            self.assertGreaterEqual(len(events), 3)
            self.assertEqual("generation_started", events[0]["event"])
            self.assertEqual("generation_completed", events[-1]["event"])
            self.assertEqual("measured_nonsemantic", events[-1]["deterministic_status"])
            self.assertGreater(events[-1]["resource_usage"]["elapsed_seconds"], 0)

    def test_release_evidence_round_trip_and_semantic_tamper_rejection(self) -> None:
        observation = PerformanceObservation(
            measurement_profile_id="METRIC-THRESHOLDS-SMALL-v1",
            generated_row_count=100,
            elapsed_seconds=2.0,
            rows_per_second=50.0,
            peak_memory_bytes=1_000_000,
            stored_bytes=10_000,
            bytes_per_row=100.0,
            parallel_efficiency=1.0,
            deterministic_digest_equal=True,
        )
        evidence = ReleaseEvidence(
            performance_by_run={("SCN-SMALL-DETERMINISTIC", 0): observation}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_release_evidence(
                root,
                evidence,
                run_id="RUN-SMALL-DETERMINISTIC-0001",
                config_sha256="a" * 64,
            )
            restored = read_release_evidence(
                path,
                expected_run_id="RUN-SMALL-DETERMINISTIC-0001",
                expected_config_sha256="a" * 64,
            )
            self.assertEqual(evidence, restored)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["evidence_is_generation_input"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ArtifactIntegrityError, "semantics mismatch"):
                read_release_evidence(
                    path,
                    expected_run_id="RUN-SMALL-DETERMINISTIC-0001",
                    expected_config_sha256="a" * 64,
                )

    def test_run_study_without_conditions_writes_honest_plan_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    (
                        "run-study",
                        "--config",
                        str(self.config),
                        "--output-dir",
                        temporary,
                        "--study-id",
                        "STUDY-PLAN-ONLY",
                    )
                )
            self.assertEqual(0, exit_code)
            result = json.loads(stdout.getvalue())
            self.assertFalse(result["publication_eligible"])
            self.assertTrue(result["publication_blockers"])
            self.assertTrue(Path(result["package_root"]).is_dir())
            self.assertRegex(result["manifest_sha256"], r"^[0-9a-f]{64}$")
            events = [json.loads(line) for line in stderr.getvalue().splitlines()]
            self.assertEqual("study_plan_resolved", events[0]["event"])
            self.assertEqual("study_package_completed", events[-1]["event"])


if __name__ == "__main__":
    unittest.main()
