from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import load_config, resolve_config, resolve_config_file  # noqa: E402
from htgl_dataset_generator.experiments import (  # noqa: E402
    orchestrate_pipeline_through_metrics,
    orchestrate_pipeline_through_sampling,
)


class IntegrationHardeningTests(unittest.TestCase):
    def test_balanced_reference_derivative_exercises_complete_semantics(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        scenario_id = "SCN-INTEGRATION-HARDENING-0100"
        raw["run"]["run_id"]["value"] = "RUN-INTEGRATION-HARDENING-0100"
        raw["run"]["scenario_id"]["value"] = scenario_id
        raw["run"]["selected_scenario_ids"]["value"] = [scenario_id]
        raw["claim_scale"]["materialized_row_target"]["value"] = 100
        raw["arrivals"]["conditioned_total"]["value"] = 100
        raw["arrivals"]["base_rates_per_day"]["value"] = {
            family: 1.0 for family in raw["workflows"]["families"]["value"]
        }
        raw["anomaly"]["prevalence"]["value"] = {
            anomaly_type: 0.01 for anomaly_type in raw["anomaly"]["types"]["value"]
        }
        raw["sampling"]["design_types"]["value"] = ["census"]
        raw["sampling"]["target_sample_size"]["value"] = 100
        resolved = resolve_config(raw)

        result = orchestrate_pipeline_through_sampling(
            resolved,
            profile_stages=True,
        )[0]
        sampling = result.artifacts
        observers = sampling.through_observers
        anomalies = observers.through_anomalies
        evidence = anomalies.through_evidence
        obligations = evidence.through_obligations
        dag = obligations.through_policy.through_dag.causal_dag

        self.assertEqual(
            set(resolved.workflows.families),
            {str(row["workflow_type"]) for row in dag.workflow_instances},
        )
        self.assertEqual(
            set(resolved.anomaly.types),
            {str(row["anomaly_type"]) for row in anomalies.anomalies.anomaly_instances},
        )
        self.assertEqual(
            set(resolved.observer.observer_profile_ids),
            set(observers.observers.diagnostics),
        )
        self.assertGreater(len(obligations.evidence_obligations.evidence_obligations), 0)
        self.assertGreater(len(evidence.evidence_receipts.evidence_receipts), 0)
        self.assertGreater(len(sampling.sampling.sample_memberships), 0)
        self.assertTrue(
            any(
                row["selection_reason"] != "primary_draw"
                for row in sampling.sampling.sample_memberships
            )
        )
        self.assertEqual(
            {
                "S02", "S03", "S04", "S05", "S06", "S07-dag", "S07-policy",
                "S08", "S09", "S10", "S11", "S12",
            },
            {item.stage_id for item in result.stage_performance},
        )

    def test_small_pipeline_profiles_every_stage_through_metrics(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        result = orchestrate_pipeline_through_metrics(resolved, profile_stages=True).replicates[0]
        self.assertEqual(
            {
                "S02", "S03", "S04", "S05", "S06", "S07-dag", "S07-policy",
                "S08", "S09", "S10", "S11", "S12", "S13", "S14",
            },
            {item.stage_id for item in result.stage_performance},
        )
        for item in result.stage_performance:
            self.assertGreater(item.elapsed_seconds, 0)
            self.assertGreater(item.peak_resident_memory_bytes, 0)
            self.assertGreaterEqual(
                item.peak_resident_memory_bytes,
                max(item.rss_before_bytes, item.rss_after_bytes),
            )
            self.assertTrue(item.table_record_digests)

    def test_wheel_runs_from_isolated_target_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel_dir = root / "wheel"
            site_dir = root / "site"
            wheel_dir.mkdir()
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--no-build-isolation",
                    "-w",
                    str(wheel_dir),
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            wheel = next(wheel_dir.glob("*.whl"))
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site_dir), str(wheel)],
                check=True,
                capture_output=True,
                text=True,
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(site_dir)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "htgl_dataset_generator.cli.main",
                    "resolve-config",
                    "--config",
                    str(REPO_ROOT / "configs" / "small_deterministic.json"),
                    "--output-dir",
                    str(root / "output"),
                    "--dry-run",
                ],
                cwd=root,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(completed.stdout)
            self.assertFalse(payload["writes_performed"])
            self.assertEqual("dry_run", payload["execution_mode"])


if __name__ == "__main__":
    unittest.main()
