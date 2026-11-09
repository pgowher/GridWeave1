from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from htgl_dataset_generator.paegen.benchmark_contract import (  # noqa: E402
    load_benchmark_study_contract,
)


class PaEBenchStudyContractTests(unittest.TestCase):
    def test_contract_has_external_baselines_tasks_and_transfer_cases(self) -> None:
        contract = load_benchmark_study_contract()
        payload = contract.payload
        self.assertEqual("PROTOCOL_ONLY_NOT_EXECUTED", payload["status"])
        self.assertEqual(6, len(payload["tasks"]))
        self.assertEqual(4, len(payload["external_baselines"]))
        self.assertEqual(3, len(payload["independent_use_cases"]))
        self.assertTrue(all(row["execution_status"] == "NOT_EXECUTED" for row in payload["external_baselines"]))
        self.assertTrue(all(row["split_policy"] == "sealed_cross_domain_test_only" for row in payload["independent_use_cases"]))
        self.assertEqual(64, len(contract.sha256))

    def test_unknown_task_reference_is_rejected(self) -> None:
        contract = load_benchmark_study_contract()
        changed = copy.deepcopy(contract.payload)
        changed["external_baselines"][0]["supported_tasks"].append("PBE-T99")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown supported tasks"):
                load_benchmark_study_contract(path)

    def test_uncovered_transfer_asset_is_rejected(self) -> None:
        contract = load_benchmark_study_contract()
        changed = copy.deepcopy(contract.payload)
        changed["independent_use_cases"][0]["obligations"].pop()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "every asset must be covered"):
                load_benchmark_study_contract(path)


if __name__ == "__main__":
    unittest.main()
