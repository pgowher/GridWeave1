from __future__ import annotations

import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import load_config, resolve_config  # noqa: E402
from htgl_dataset_generator.paegen import (  # noqa: E402
    FECM_MODEL_VERSION,
    PAEGEN_INTERFACE_VERSION,
    build_paegen,
    export_paegen,
    validate_paegen_build,
)
from htgl_dataset_generator.paegen.public import build_observer_artifacts  # noqa: E402


def _erasure_config():
    raw = dict(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
    raw["arrivals"]["base_rates_per_day"]["value"] = {"erasure": 0.03}
    raw["workflows"]["families"]["value"] = ["erasure"]
    return resolve_config(raw)


class PaEGenV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = _erasure_config()
        cls.first = build_paegen(cls.resolved)
        cls.second = build_paegen(cls.resolved)

    def test_versioned_artifacts_validate_and_have_explicit_erasure_records(self) -> None:
        validate_paegen_build(self.first)
        self.assertEqual("1.0.0", PAEGEN_INTERFACE_VERSION)
        self.assertEqual("PAE-FECM-v1.0.0", FECM_MODEL_VERSION)
        cases = self.first.replicas[0].ground_truth.payload["cases"]
        self.assertTrue(cases)
        for case in cases:
            self.assertTrue(case["root_asset_ids"])
            self.assertEqual(
                len(case["obligation_graph"]["obligations"]), len(case["dispositions"])
            )
            self.assertTrue(case["evidence"])
            for disposition in case["dispositions"]:
                if disposition["world_disposition"] == "ERASED":
                    obligation = next(
                        item for item in case["obligation_graph"]["obligations"]
                        if item["obligation_id"] == disposition["obligation_id"]
                    )
                    self.assertEqual("replica_deletion", obligation["obligation_type"])
            self.assertIn(
                case["closure_ground_truth"]["outcome"],
                {"CLOSED", "CLOSED_WITH_EXCEPTIONS", "PARTIALLY_CLOSED", "OPEN", "DISPUTED", "UNVERIFIABLE"},
            )

    def test_same_seed_reproduces_graph_evidence_labels_and_views(self) -> None:
        first = self.first.replicas[0]
        second = self.second.replicas[0]
        self.assertEqual(first.ground_truth.sha256, second.ground_truth.sha256)
        self.assertEqual(first.ground_truth.payload, second.ground_truth.payload)
        self.assertEqual(
            {key: value.sha256 for key, value in first.observer_views.items()},
            {key: value.sha256 for key, value in second.observer_views.items()},
        )
        self.assertEqual(first.scenario_manifest.sha256, second.scenario_manifest.sha256)

    def test_public_builder_cannot_accept_privileged_oracle_objects(self) -> None:
        parameters = inspect.signature(build_observer_artifacts).parameters
        self.assertNotIn("ground_truth", parameters)
        self.assertNotIn("oracle", parameters)
        replica = self.first.replicas[0]
        self.assertNotIn("OBS-FULL-EVALUATOR", replica.observer_views)
        serialized = json.dumps(
            [artifact.payload for artifact in replica.observer_views.values()], sort_keys=True
        )
        for forbidden in (
            "closure_ground_truth",
            "omission_truth",
            "verification_status_truth",
            "adversarial_cases",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_export_physically_separates_oracle_and_observer_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = export_paegen(self.first, Path(temporary) / "paegen-v1")
            observer_files = tuple(report.observer_input_root.rglob("*.json"))
            truth_files = tuple(report.sealed_ground_truth_root.rglob("*.json"))
            self.assertTrue(observer_files)
            self.assertTrue(truth_files)
            observer_text = "\n".join(path.read_text(encoding="utf-8") for path in observer_files)
            self.assertNotIn("closure_ground_truth", observer_text)
            self.assertIn("closure_ground_truth", truth_files[0].read_text(encoding="utf-8"))
            repeated = export_paegen(self.first, report.output_root)
            self.assertEqual(report.export_digest, repeated.export_digest)

    def test_existing_non_erasure_configuration_remains_compatible(self) -> None:
        baseline = resolve_config(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        build = build_paegen(baseline)
        validate_paegen_build(build)
        self.assertEqual([], build.replicas[0].ground_truth.payload["cases"])


if __name__ == "__main__":
    unittest.main()
