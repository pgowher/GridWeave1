from __future__ import annotations

import csv
from copy import deepcopy
import json
import random
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = REPO_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.reference_closure_oracle import (  # noqa: E402
    TERMINAL_OUTCOMES,
    evaluate_case,
    materialize_case,
)


FORMAL_DIR = PROJECT_ROOT / "Thesis_Docs-" / "Formal_Model" / "Closure"
FORMAL_CASES = FORMAL_DIR / "Worked_Cases_v1.json"
FORMAL_MANUAL = FORMAL_DIR / "Manual_Evaluation_Record.csv"
MIRROR_CASES = REPO_ROOT / "tests" / "golden" / "pae_closure_worked_cases_v1.json"
MIRROR_MANUAL = REPO_ROOT / "tests" / "golden" / "pae_closure_manual_evaluation_v1.csv"
SCHEMA = REPO_ROOT / "schemas" / "pae-closure-worked-case-v1.schema.json"


def _split(value: str) -> list[str]:
    return [] if not value else value.split("|")


def _bool(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError(f"invalid manual Boolean {value!r}")
    return value == "true"


class Phase2ClosureSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = json.loads(FORMAL_CASES.read_text(encoding="utf-8"))
        with FORMAL_MANUAL.open(newline="", encoding="utf-8") as handle:
            cls.manual = {row["case_id"]: row for row in csv.DictReader(handle)}

    def test_suite_conforms_to_machine_readable_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(validator.iter_errors(self.suite), key=lambda item: list(item.path))
        self.assertEqual([], [error.message for error in errors])

    def test_formal_and_executable_mirrors_are_byte_identical(self) -> None:
        self.assertEqual(FORMAL_CASES.read_bytes(), MIRROR_CASES.read_bytes())
        self.assertEqual(FORMAL_MANUAL.read_bytes(), MIRROR_MANUAL.read_bytes())

    def test_manual_and_executable_evaluations_agree_exactly(self) -> None:
        case_ids = {case["case_id"] for case in self.suite["cases"]}
        self.assertEqual(case_ids, set(self.manual))
        for case in self.suite["cases"]:
            observed = evaluate_case(self.suite, case)
            manual = self.manual[case["case_id"]]
            self.assertEqual(manual["manual_outcome"], observed["outcome"], case["case_id"])
            self.assertEqual(_split(manual["discovered_asset_ids"]), observed["discovered_asset_ids"])
            self.assertEqual(_split(manual["obligation_ids"]), observed["obligation_ids"])
            for name, value in observed["predicates"].items():
                self.assertEqual(_bool(manual[name]), value, f"{case['case_id']}:{name}")

    def test_suite_covers_every_terminal_outcome_and_operational_status(self) -> None:
        outcomes = {evaluate_case(self.suite, case)["outcome"] for case in self.suite["cases"]}
        self.assertEqual(set(TERMINAL_OUTCOMES) | {"IN_PROGRESS"}, outcomes)

    def test_oracle_is_deterministic_and_collection_order_invariant(self) -> None:
        original = self.suite["cases"][0]
        expected = evaluate_case(self.suite, original)
        for seed in range(10):
            altered = deepcopy(original)
            rng = random.Random(seed)
            for field in ("assets", "lineage", "replicas", "evidence", "exceptions", "challenges"):
                if field in altered:
                    rng.shuffle(altered[field])
            self.assertEqual(expected, evaluate_case(self.suite, altered))

    def test_disclosure_monotonically_expands_dependency_and_obligation_sets(self) -> None:
        hidden = next(case for case in self.suite["cases"] if case["case_id"] == "WC-08-HIDDEN-LINEAGE-LIMIT")
        disclosed = next(case for case in self.suite["cases"] if case["case_id"] == "WC-09-DISCOVERED-LINEAGE")
        hidden_result = evaluate_case(self.suite, hidden)
        disclosed_result = evaluate_case(self.suite, disclosed)
        self.assertLess(set(hidden_result["discovered_asset_ids"]), set(disclosed_result["discovered_asset_ids"]))
        self.assertLess(set(hidden_result["obligation_ids"]), set(disclosed_result["obligation_ids"]))

    def test_perfectly_hidden_lineage_is_observationally_indistinguishable(self) -> None:
        hidden = deepcopy(next(case for case in self.suite["cases"] if case["case_id"] == "WC-08-HIDDEN-LINEAGE-LIMIT"))
        without_hidden = materialize_case(self.suite, hidden)
        without_hidden["assets"] = [
            row for row in without_hidden["assets"] if row["asset_id"] != "A1"
        ]
        without_hidden["lineage"] = []
        without_hidden["replicas"] = [
            row for row in without_hidden["replicas"] if row["asset_id"] != "A1"
        ]
        self.assertEqual(
            evaluate_case(self.suite, hidden),
            evaluate_case(self.suite, without_hidden),
        )

    def test_more_evidence_can_create_a_dispute_counterexample(self) -> None:
        closed = deepcopy(next(case for case in self.suite["cases"] if case["case_id"] == "WC-01-CLOSED"))
        self.assertEqual("CLOSED", evaluate_case(self.suite, closed)["outcome"])
        conflicting = deepcopy(closed["evidence"][0])
        conflicting["evidence_id"] = "E0-CONFLICT"
        conflicting["disposition"] = "FAILED"
        conflicting["event_time"] = "2026-09-10T00:00:01Z"
        closed["evidence"].append(conflicting)
        self.assertEqual("DISPUTED", evaluate_case(self.suite, closed)["outcome"])

    def test_oracle_rejects_answer_leakage(self) -> None:
        leaked = deepcopy(self.suite["cases"][0])
        leaked["expected_outcome"] = "CLOSED"
        with self.assertRaisesRegex(ValueError, "forbidden answer fields"):
            evaluate_case(self.suite, leaked)


if __name__ == "__main__":
    unittest.main()
