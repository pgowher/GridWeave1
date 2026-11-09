from __future__ import annotations

from copy import deepcopy
import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = REPO_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.reference_closure_oracle import evaluate_case, materialize_case  # noqa: E402
from tests.reference_evidence_grade_oracle import evaluate_suite  # noqa: E402


class ModelV10ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(
            (REPO_ROOT / "tests" / "golden" / "model_v1_0_validation_cases.json").read_text(encoding="utf-8")
        )
        cls.closure = json.loads(
            (PROJECT_ROOT / "Thesis_Docs-" / "Formal_Model" / "Closure" / "Worked_Cases_v1.json").read_text(encoding="utf-8")
        )
        registry = json.loads(
            (REPO_ROOT / "evidence" / "evidence_grade_profiles_v1.json").read_text(encoding="utf-8")
        )
        grade_cases = json.loads(
            (REPO_ROOT / "evidence" / "evidence_grade_cases_v1.json").read_text(encoding="utf-8")
        )
        cls.grade_result = evaluate_suite(registry, grade_cases)
        cls.closure_by_id = {row["case_id"]: row for row in cls.closure["cases"]}
        cls.validation_by_class = {row["class"]: row for row in cls.catalog["cases"]}

    def test_suite_contains_exact_required_counterexample_classes(self) -> None:
        self.assertFalse(self.catalog["verifier_input_allowed"])
        self.assertEqual(
            {
                "omitted_derivative",
                "retained_backup",
                "invalid_exception",
                "contradictory_receipts",
                "incomplete_visibility",
            },
            set(self.validation_by_class),
        )

    def test_omitted_derivative_disclosure_expands_scope_and_prevents_false_closure(self) -> None:
        spec = self.validation_by_class["omitted_derivative"]
        result = evaluate_case(self.closure, self.closure_by_id[spec["source"]])
        self.assertEqual(spec["expected_outcome"], result["outcome"])
        self.assertIn(spec["expected_required_identifier"], result["obligation_ids"])
        self.assertNotIn(spec["expected_required_identifier"], result["resolved_obligation_ids"])

    def test_retained_backup_adds_an_unresolved_obligation(self) -> None:
        spec = self.validation_by_class["retained_backup"]
        base = materialize_case(self.closure, self.closure_by_id[spec["source"]])
        base["case_id"] = spec["case_id"]
        base["replicas"].append(
            {
                "replica_id": "I-BACKUP",
                "asset_id": "A0",
                "repository_id": "R-BACKUP",
                "custodian_id": "P-BACKUP",
                "replica_class": "BACKUP",
                "status": "DECLARED",
                "authenticated": True,
            }
        )
        result = evaluate_case(self.closure, base)
        self.assertEqual(spec["expected_outcome"], result["outcome"])
        self.assertIn(spec["expected_required_identifier"], result["obligation_ids"])
        self.assertNotIn(spec["expected_required_identifier"], result["resolved_obligation_ids"])

    def test_invalid_exception_resolves_nothing(self) -> None:
        spec = self.validation_by_class["invalid_exception"]
        result = evaluate_case(self.closure, self.closure_by_id[spec["source"]])
        self.assertEqual(spec["expected_outcome"], result["outcome"])
        self.assertFalse(result["predicates"][spec["expected_false_predicate"]])
        self.assertEqual([], result["resolved_obligation_ids"])

    def test_contradictory_receipts_are_disputed_at_both_layers(self) -> None:
        spec = self.validation_by_class["contradictory_receipts"]
        closure_result = evaluate_case(self.closure, self.closure_by_id[spec["closure_source"]])
        grade_result = self.grade_result["bundles"][spec["grade_source"]]
        self.assertEqual(spec["expected_outcome"], closure_result["outcome"])
        self.assertEqual(spec["expected_grade_status"], grade_result["status"])
        self.assertIsNone(grade_result["grade"])

    def test_incomplete_visibility_has_an_explicit_indistinguishability_boundary(self) -> None:
        spec = self.validation_by_class["incomplete_visibility"]
        hidden = self.closure_by_id[spec["source"]]
        projected = materialize_case(self.closure, hidden)
        projected["assets"] = [row for row in projected["assets"] if row["asset_id"] != "A1"]
        projected["lineage"] = []
        projected["replicas"] = [row for row in projected["replicas"] if row["asset_id"] != "A1"]
        hidden_result = evaluate_case(self.closure, hidden)
        projected_result = evaluate_case(self.closure, projected)
        self.assertEqual(spec["expected_outcome"], hidden_result["outcome"])
        self.assertEqual(hidden_result, projected_result)

    def test_validation_catalog_is_deterministic_under_case_order(self) -> None:
        reversed_catalog = deepcopy(self.catalog)
        reversed_catalog["cases"].reverse()
        self.assertEqual(
            {row["case_id"]: row for row in self.catalog["cases"]},
            {row["case_id"]: row for row in reversed_catalog["cases"]},
        )


if __name__ == "__main__":
    unittest.main()
