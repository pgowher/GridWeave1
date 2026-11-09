from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from htgl_dataset_generator.paegen.release import build_reference, verify_reference  # noqa: E402


class PaEBenchReleaseV1Tests(unittest.TestCase):
    def test_reference_build_is_reproducible_and_passes_release_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            summary = build_reference(first)
            repeated = build_reference(second)
            self.assertEqual(summary, repeated)
            self.assertEqual(7, summary["scale_accounting"]["N_represented_population"])
            self.assertEqual(31, summary["scale_accounting"]["n_materialized_records"])
            self.assertIsNone(summary["scale_accounting"]["q_executed_governance_operations"])
            self.assertEqual("PASS", summary["oracle_leakage_audit"])
            self.assertEqual(
                json.loads((first / "reference-hashes.json").read_text(encoding="utf-8"))["files"],
                json.loads((second / "reference-hashes.json").read_text(encoding="utf-8"))["files"],
            )
            self.assertEqual(summary, verify_reference(first))

    def test_hash_verification_rejects_changed_reference_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "reference"
            build_reference(root)
            (root / "summary.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash inventory mismatch"):
                verify_reference(root)


if __name__ == "__main__":
    unittest.main()
