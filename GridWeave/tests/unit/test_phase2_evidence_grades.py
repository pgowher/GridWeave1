from __future__ import annotations

import csv
from copy import deepcopy
import json
import random
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = REPO_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

from tests.reference_evidence_grade_oracle import evaluate_receipt, evaluate_suite  # noqa: E402


REGISTRY_PATH = REPO_ROOT / "evidence" / "evidence_grade_profiles_v1.json"
FIXTURE_PATH = REPO_ROOT / "evidence" / "evidence_grade_cases_v1.json"
RECEIPT_PROFILES_PATH = REPO_ROOT / "evidence" / "receipt_profiles_v1.json"
CONTRACT_PATH = REPO_ROOT / "schemas" / "htgl_contract_v1.json"
FORMAL_DIR = PROJECT_ROOT / "Thesis_Docs-" / "Formal_Model" / "Evidence_Grades"
RECEIPT_MANUAL_PATH = FORMAL_DIR / "Receipt_Grade_Manual_Evaluation.csv"
BUNDLE_MANUAL_PATH = FORMAL_DIR / "Bundle_Grade_Manual_Evaluation.csv"


def _optional(value: str) -> str | None:
    return value or None


def _list(value: str) -> list[str]:
    return [] if not value else value.split("|")


def _boolean(value: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError(f"invalid Boolean {value!r}")
    return value == "true"


class Phase2EvidenceGradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.result = evaluate_suite(cls.registry, cls.suite)
        with RECEIPT_MANUAL_PATH.open(newline="", encoding="utf-8") as handle:
            cls.receipt_manual = {row["receipt_id"]: row for row in csv.DictReader(handle)}
        with BUNDLE_MANUAL_PATH.open(newline="", encoding="utf-8") as handle:
            cls.bundle_manual = {row["bundle_id"]: row for row in csv.DictReader(handle)}

    def test_registry_exactly_covers_every_existing_receipt_type(self) -> None:
        source_profiles = json.loads(RECEIPT_PROFILES_PATH.read_text(encoding="utf-8"))
        source_types = {row["evidence_type"] for row in source_profiles["profiles"]}
        registry_types = {row["evidence_type"] for row in self.registry["receipt_types"]}
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        contract_types = set(contract["dictionaries"]["evidence_type"])
        self.assertEqual(source_types, registry_types)
        self.assertEqual(contract_types, registry_types)
        self.assertEqual(len(registry_types), len(self.registry["receipt_types"]))
        source_by_type = {row["evidence_type"]: row for row in source_profiles["profiles"]}
        for profile in self.registry["receipt_types"]:
            source = source_by_type[profile["evidence_type"]]
            self.assertEqual(source["primitive"], profile["primitive"])
            self.assertEqual(source["requires_key"], profile["requires_key"])
            self.assertEqual(source["requires_anchor"], profile["requires_anchor"])

    def test_every_registered_type_has_a_successfully_graded_atomic_fixture(self) -> None:
        types_with_grade = {
            raw["evidence_type"]
            for raw in self.suite["receipts"]
            if self.result["receipts"][raw["receipt_id"]]["status"] == "GRADED"
        }
        self.assertEqual(
            {row["evidence_type"] for row in self.registry["receipt_types"]},
            types_with_grade,
        )

    def test_all_emitted_reasons_are_registered(self) -> None:
        rejection_reasons = {
            row["rejection_reason"]
            for row in self.result["receipts"].values()
            if row["rejection_reason"]
        }
        downgrade_reasons = {
            reason
            for row in self.result["receipts"].values()
            for reason in row["downgrade_reasons"]
        } | {
            reason
            for row in self.result["bundles"].values()
            for reason in row["downgrade_reasons"]
        }
        self.assertLessEqual(rejection_reasons, set(self.registry["rejection_precedence"]))
        self.assertLessEqual(downgrade_reasons, set(self.registry["downgrade_reasons"]))

    def test_grade_frontiers_form_a_strict_nested_chain(self) -> None:
        self.assertEqual([f"E{index}" for index in range(6)], self.registry["grade_order"])
        capabilities = [set(row["capabilities"]) for row in self.registry["grades"]]
        self.assertEqual(6, len(capabilities))
        for weaker, stronger in zip(capabilities, capabilities[1:]):
            self.assertLess(weaker, stronger)

    def test_every_atomic_receipt_has_exact_manual_grade_or_rejection(self) -> None:
        self.assertEqual(set(self.receipt_manual), set(self.result["receipts"]))
        for receipt_id, observed in self.result["receipts"].items():
            manual = self.receipt_manual[receipt_id]
            self.assertEqual(manual["manual_status"], observed["status"], receipt_id)
            self.assertEqual(_optional(manual["manual_grade"]), observed["grade"], receipt_id)
            self.assertEqual(_optional(manual["rejection_reason"]), observed["rejection_reason"], receipt_id)
            self.assertEqual(_list(manual["downgrade_reasons"]), observed["downgrade_reasons"], receipt_id)
            self.assertEqual(_boolean(manual["closure_admissible"]), observed["closure_admissible"], receipt_id)
            self.assertEqual(_boolean(manual["physical_destruction_concluded"]), observed["physical_destruction_concluded"], receipt_id)
            self.assertEqual(_optional(manual["manual_conclusion"]), observed["conclusion"], receipt_id)

    def test_every_bundle_has_exact_manual_result(self) -> None:
        self.assertEqual(set(self.bundle_manual), set(self.result["bundles"]))
        for bundle_id, observed in self.result["bundles"].items():
            manual = self.bundle_manual[bundle_id]
            self.assertEqual(manual["manual_status"], observed["status"], bundle_id)
            self.assertEqual(_optional(manual["manual_grade"]), observed["grade"], bundle_id)
            self.assertEqual(_optional(manual["reason"]), observed["reason"], bundle_id)
            self.assertEqual(_list(manual["downgrade_reasons"]), observed["downgrade_reasons"], bundle_id)
            self.assertEqual(_list(manual["missing_receipt_ids"]), observed["missing_receipt_ids"], bundle_id)
            self.assertEqual(_boolean(manual["physical_destruction_concluded"]), observed["physical_destruction_concluded"], bundle_id)
            self.assertEqual(_optional(manual["manual_conclusion"]), observed["conclusion"], bundle_id)

    def test_fixture_exercises_every_grade_conflict_and_missing_evidence(self) -> None:
        grades = {row["grade"] for row in self.result["bundles"].values() if row["grade"]}
        self.assertEqual(set(self.registry["grade_order"]), grades)
        self.assertEqual("DISPUTED", self.result["bundles"]["B-CONFLICT"]["status"])
        self.assertEqual(
            ["R-NOT-PRESENT"],
            self.result["bundles"]["B-MISSING-ORDERING"]["missing_receipt_ids"],
        )

    def test_expiry_and_corroboration_failures_downgrade_without_grade_inflation(self) -> None:
        expired = self.result["bundles"]["B-EXPIRED-MECHANISM"]
        non_independent = self.result["bundles"]["B-NONINDEPENDENT-CORROBORATION"]
        below_quorum = self.result["bundles"]["B-MISSING-CORROBORATION"]
        self.assertEqual("E3", expired["grade"])
        self.assertIn("MECHANISM_ATTESTATION_EXPIRED", expired["downgrade_reasons"])
        self.assertEqual("E4", non_independent["grade"])
        self.assertIn("CORROBORATION_NOT_INDEPENDENT", non_independent["downgrade_reasons"])
        self.assertEqual("E4", below_quorum["grade"])
        self.assertIn("CORROBORATION_BELOW_QUORUM", below_quorum["downgrade_reasons"])

    def test_rejection_precedence_is_deterministic(self) -> None:
        broken = {
            "receipt_id": "R-MULTI-FAIL",
            "evidence_type": "not_registered",
            "canonical_valid": False,
            "obligation_bound": False,
            "provenance_complete": False,
        }
        observed = evaluate_receipt(self.registry, self.suite["receipt_defaults"], broken)
        self.assertEqual("REJECTED", observed["status"])
        self.assertEqual("UNKNOWN_RECEIPT_TYPE", observed["rejection_reason"])

    def test_evaluation_is_collection_order_invariant(self) -> None:
        expected = self.result
        for seed in range(10):
            altered = deepcopy(self.suite)
            rng = random.Random(seed)
            rng.shuffle(altered["receipts"])
            rng.shuffle(altered["bundles"])
            for bundle in altered["bundles"]:
                rng.shuffle(bundle["support_receipt_ids"])
            self.assertEqual(expected, evaluate_suite(self.registry, altered))

    def test_no_grade_or_conclusion_asserts_physical_destruction(self) -> None:
        self.assertTrue(all(not row["physical_destruction_concluded"] for row in self.result["receipts"].values()))
        self.assertTrue(all(not row["physical_destruction_concluded"] for row in self.result["bundles"].values()))
        serialized = json.dumps(self.registry).lower()
        self.assertIn("no evidence grade", self.registry["proof_limit_statement"].lower())
        self.assertNotIn('"permits": ["physical_destruction', serialized)

    def test_reference_oracle_is_not_imported_by_production_code(self) -> None:
        offenders = []
        for path in (REPO_ROOT / "src").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "reference_evidence_grade_oracle" in text:
                offenders.append(path)
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
