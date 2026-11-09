from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import CORE_VALIDATION_CHECK_IDS  # noqa: E402
from htgl_dataset_generator.schemas import load_contract  # noqa: E402
from htgl_dataset_generator.validation import (  # noqa: E402
    ProductionRuleViolation,
    audit_repository_final_rules,
    validate_population_metric_eligibility,
    validate_publication_gate,
    validate_required_check_execution,
    validate_release_table_privacy,
)


CLAIM_MATRIX = {
    "represented_population": 100,
    "materialized_rows": 1,
    "executed_operations": None,
    "generator_boundary": "benchmark_artifacts_only_no_htgl_consensus_ledger_real_erasure_legal_enforcement_or_utility_deployment",
    "legal_compliance_claim": False,
    "real_deletion_claim": False,
    "cryptographic_proof_scope": "configured synthetic evidence profile only",
    "operational_execution_claim": False,
}


class ProductionRulesTests(unittest.TestCase):
    def _golden(self):
        return json.loads((REPO_ROOT / "tests" / "golden" / "golden_fixture_v1.json").read_text())

    def _complete_validation_issues(self):
        template = copy.deepcopy(self._golden()["validation_issue"][0])
        rows = []
        for check_id in CORE_VALIDATION_CHECK_IDS:
            row = copy.deepcopy(template)
            row["check_id"] = check_id
            row["severity"] = "fatal"
            row["status"] = "pass"
            row["observed_value"] = "complete-core-control"
            row["expected_condition"] = "mandatory core check passes"
            row["affected_record_ids"] = []
            row["message"] = "check executed and acceptance condition satisfied"
            row["validator_version"] = "S13.joint-validator.v1"
            rows.append(row)
        return rows

    def test_current_repository_passes_final_production_audit(self) -> None:
        report = audit_repository_final_rules(REPO_ROOT)

        self.assertTrue(report.passed, report.issues)
        self.assertGreater(report.scanned_python_files, 0)
        self.assertEqual(3, report.checked_configs)

    def test_source_audit_detects_forbidden_nondeterminism(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "src" / "htgl_dataset_generator"
            source_root.mkdir(parents=True)
            random_call = "random" + ".random()"
            time_call = "time" + ".time()"
            uuid_call = "uuid" + ".uuid4()"
            (source_root / "bad_generation.py").write_text(
                "\n".join(
                    [
                        "import random",
                        "import time",
                        "import uuid",
                        "",
                        "def build_bad_row():",
                        f"    return {random_call}, {time_call}, {uuid_call}",
                    ]
                ),
                encoding="utf-8",
            )

            report = audit_repository_final_rules(root, config_paths=())

        self.assertFalse(report.passed)
        messages = " ".join(issue.message for issue in report.issues)
        self.assertIn("random module import", messages)
        self.assertIn("wall-clock time", messages)
        self.assertIn("UUID4", messages)

    def test_config_audit_detects_bare_jsonl_adapter_when_resolution_is_bypassed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "htgl_dataset_generator").mkdir(parents=True)
            (root / "src" / "htgl_dataset_generator" / "__init__.py").write_text("", encoding="utf-8")
            config_dir = root / "configs"
            config_dir.mkdir()
            raw = json.loads((REPO_ROOT / "configs" / "reference_10k.json").read_text())
            raw["output"]["adapters"]["value"] = ["jsonl", "xes", "jsonld"]
            (config_dir / "bad_jsonl.json").write_text(json.dumps(raw), encoding="utf-8")

            report = audit_repository_final_rules(root)

        self.assertFalse(report.passed)
        messages = " ".join(issue.message for issue in report.issues)
        self.assertIn("bare jsonl is ambiguous", messages.lower())

    def test_public_release_blocks_restricted_and_truth_tables(self) -> None:
        contract = load_contract()

        with self.assertRaisesRegex(ProductionRuleViolation, "privacy_class=evaluator_only"):
            validate_release_table_privacy(["policy_decision_truth"], contract=contract)
        with self.assertRaisesRegex(ProductionRuleViolation, "privacy_class=restricted"):
            validate_release_table_privacy(["arrival"], contract=contract)
        with self.assertRaisesRegex(ProductionRuleViolation, "observer release cannot include"):
            validate_release_table_privacy(
                ["policy_decision_truth"],
                release_profile="observer",
                contract=contract,
            )
        with self.assertRaisesRegex(ProductionRuleViolation, "observer release cannot include"):
            validate_release_table_privacy(
                ["observer_event"],
                release_profile="observer",
                contract=contract,
            )
        validate_release_table_privacy(["run_metric", "artifact_manifest"], contract=contract)

    def test_publication_gate_accepts_complete_golden_control_tables(self) -> None:
        golden = self._golden()
        tables = {
            "validation_issue": self._complete_validation_issues(),
            "run_metric": golden["run_metric"],
            "artifact_manifest": golden["artifact_manifest"],
        }

        validate_publication_gate(tables, claim_matrix=CLAIM_MATRIX, contract=load_contract())

    def test_publication_gate_blocks_unresolved_validation_issue(self) -> None:
        golden = self._golden()
        issues = self._complete_validation_issues()
        issues[0]["severity"] = "fatal"
        issues[0]["status"] = "fail"
        tables = {
            "validation_issue": issues,
            "run_metric": golden["run_metric"],
            "artifact_manifest": golden["artifact_manifest"],
        }

        with self.assertRaisesRegex(ProductionRuleViolation, "unresolved"):
            validate_publication_gate(tables, claim_matrix=CLAIM_MATRIX, contract=load_contract())

    def test_publication_gate_blocks_legal_and_deletion_claims(self) -> None:
        golden = self._golden()
        tables = {
            "validation_issue": golden["validation_issue"],
            "run_metric": golden["run_metric"],
            "artifact_manifest": golden["artifact_manifest"],
        }
        legal_claim = dict(CLAIM_MATRIX)
        legal_claim["legal_compliance_claim"] = True
        deletion_claim = dict(CLAIM_MATRIX)
        deletion_claim["real_deletion_claim"] = True

        with self.assertRaisesRegex(ProductionRuleViolation, "legal compliance"):
            validate_publication_gate(tables, claim_matrix=legal_claim, contract=load_contract())
        with self.assertRaisesRegex(ProductionRuleViolation, "real deletion"):
            validate_publication_gate(tables, claim_matrix=deletion_claim, contract=load_contract())

    def test_weighted_population_metrics_require_valid_inclusion_probabilities(self) -> None:
        golden = self._golden()
        metric = copy.deepcopy(golden["run_metric"])
        metric[0]["weighting"] = "HT"
        metric[0]["metric_name"] = "represented_population_estimate"

        with self.assertRaisesRegex(ProductionRuleViolation, "sample_membership"):
            validate_population_metric_eligibility(metric, None)

        validate_population_metric_eligibility(metric, golden["sample_membership"])

    def test_required_check_gate_blocks_missing_unexecuted_and_unjustified_rows(self) -> None:
        complete = self._complete_validation_issues()
        with self.assertRaisesRegex(ProductionRuleViolation, "missing required"):
            validate_required_check_execution(complete[1:])

        unexecuted = copy.deepcopy(complete)
        unexecuted[0]["status"] = "not_executed"
        with self.assertRaisesRegex(ProductionRuleViolation, "unresolved"):
            validate_required_check_execution(unexecuted)

        unjustified = copy.deepcopy(complete)
        unjustified[0]["status"] = "not_applicable"
        unjustified[0]["message"] = "not needed"
        with self.assertRaisesRegex(ProductionRuleViolation, "without explicit justification"):
            validate_required_check_execution(unjustified)


if __name__ == "__main__":
    unittest.main()
