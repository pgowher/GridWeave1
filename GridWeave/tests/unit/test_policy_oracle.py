from __future__ import annotations

import copy
from collections import Counter
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.catalog import build_catalog  # noqa: E402
from htgl_dataset_generator.config import load_config, resolve_config, resolve_config_file  # noqa: E402
from htgl_dataset_generator.dag import build_causal_dag  # noqa: E402
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_policy  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.policy import (  # noqa: E402
    PolicyLanguageError,
    PolicyOracleError,
    PolicyPackageError,
    SafePolicyEvaluator,
    build_policy_oracle,
    evaluate_expression,
    evaluate_golden_suite,
    load_policy_package,
    normalize_policy_facts,
    validate_expression,
)
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.world import build_federated_world  # noqa: E402


class PolicyOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        cls.contract = load_contract()
        cls.world = build_federated_world(cls.resolved, contract=cls.contract)
        cls.catalog = build_catalog(cls.resolved, world=cls.world, contract=cls.contract)
        cls.dag = build_causal_dag(
            cls.resolved,
            world=cls.world,
            catalog=cls.catalog,
            contract=cls.contract,
        )
        cls.package = load_policy_package(cls.resolved, contract=cls.contract)
        cls.evaluator = SafePolicyEvaluator(cls.package)
        cls.policy = build_policy_oracle(
            cls.resolved,
            world=cls.world,
            catalog=cls.catalog,
            causal_dag=cls.dag,
            contract=cls.contract,
        )

    def test_policy_package_covers_all_rule_kinds_with_schema_valid_rows(self) -> None:
        self.assertEqual(
            set(self.contract.dictionary_values("rule_kind")),
            {rule.rule_kind for rule in self.package.rules},
        )
        self.assertRegex(self.package.package_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(self.package.package_sha256, load_policy_package(self.resolved).package_sha256)
        for row in self.package.rule_records():
            validate_record(self.contract, "policy_rule", row)
            self.assertRegex(str(row["source_sha256"]), r"^[0-9a-f]{64}$")

    def test_condition_language_rejects_code_and_unknown_fields(self) -> None:
        with self.assertRaisesRegex(PolicyLanguageError, "unsupported expression operator"):
            validate_expression({"op": "python", "code": "__import__('os').system('whoami')"})
        with self.assertRaisesRegex(PolicyLanguageError, "unknown policy fact field"):
            validate_expression({"op": "eq", "field": "runtime.__class__", "value": "x"})
        facts = normalize_policy_facts(self._base_facts())
        self.assertTrue(
            evaluate_expression(
                {"op": "contains", "field": "object.allowed_purpose_ids", "value": "PURPOSE-BILLING"},
                facts,
            )
        )
        non_finite = self._base_facts()
        non_finite["replica.count"] = float("nan")
        with self.assertRaisesRegex(PolicyLanguageError, "must be finite"):
            normalize_policy_facts(non_finite)

    def test_golden_suite_has_exact_accuracy_and_conflict_agreement(self) -> None:
        result = evaluate_golden_suite(self.package, self.evaluator)

        self.assertEqual(9, result.case_count)
        self.assertEqual(result.case_count, result.exact_match_count)
        self.assertEqual(1.0, result.decision_accuracy)
        self.assertEqual(1.0, result.conflict_resolution_agreement)
        self.assertGreaterEqual(result.conflict_case_count, 1)
        self.assertEqual((), result.failures)

    def test_oracle_emits_one_traced_decision_per_finalized_event(self) -> None:
        self.assertEqual(len(self.dag.governance_events), len(self.policy.policy_decisions))
        self.assertEqual(0, self.policy.diagnostics[self.resolved.run.scenario_id].violation_count)
        self.assertEqual(1.0, self.policy.diagnostics[self.resolved.run.scenario_id].rule_trace_coverage)
        self.assertEqual(1.0, self.policy.diagnostics[self.resolved.run.scenario_id].explanation_coverage)
        for row in self.policy.policy_decisions:
            validate_record(self.contract, "policy_decision_truth", row)
            self.assertTrue(row["applied_rule_ids"])
            self.assertTrue(row["conflict_resolution_trace"])
            self.assertTrue(row["explanation_code"])

    def test_cross_region_truth_is_derived_only_from_actor_regions(self) -> None:
        same_region = self._base_facts()
        same_region["derived.is_cross_region"] = True
        normalized_same = normalize_policy_facts(same_region)
        self.assertFalse(normalized_same["derived.is_cross_region"])

        different_region = self._base_facts()
        different_region["actor.destination.region"] = "REGION-B"
        different_region["actor.destination.jurisdiction"] = "JUR-B"
        different_region["derived.is_cross_region"] = False
        normalized_different = normalize_policy_facts(different_region)
        self.assertTrue(normalized_different["derived.is_cross_region"])
        self.assertTrue(normalized_different["derived.is_cross_jurisdiction"])

    def test_policy_outputs_are_deterministic_and_write_as_parquet(self) -> None:
        repeated = build_policy_oracle(
            self.resolved,
            world=self.world,
            catalog=self.catalog,
            causal_dag=self.dag,
            contract=self.contract,
        )
        self.assertEqual(
            canonical_records_digest(self.policy.policy_rules),
            canonical_records_digest(repeated.policy_rules),
        )
        self.assertEqual(
            canonical_records_digest(self.policy.policy_decisions),
            canonical_records_digest(repeated.policy_decisions),
        )

        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(self.policy.table_records(), Path(tmp), contract=self.contract)
            self.assertEqual({"policy_rule", "policy_decision_truth"}, set(written))
            for table_name, path in written.items():
                observed = pq.read_table(path)
                self.assertEqual(len(self.policy.table_records()[table_name]), observed.num_rows)
                self.assertEqual(
                    f"htgl.dataset.v1.{table_name}".encode("utf-8"),
                    observed.schema.metadata[b"schema_id"],
                )

    def test_tampered_golden_expected_outcome_blocks_oracle(self) -> None:
        source_path = REPO_ROOT / "policies" / "golden" / "htgl_reference_policy_cases_v1.json"
        raw = json.loads(source_path.read_text(encoding="utf-8"))
        raw["cases"][0]["expected"]["expected_action"] = "deny"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered_golden.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(PolicyOracleError, "golden policy suite"):
                build_policy_oracle(
                    self.resolved,
                    causal_dag=self.dag,
                    world=self.world,
                    catalog=self.catalog,
                    golden_path=path,
                    contract=self.contract,
                )

    def test_golden_suite_missing_required_category_fails_closed(self) -> None:
        source_path = REPO_ROOT / "policies" / "golden" / "htgl_reference_policy_cases_v1.json"
        raw = json.loads(source_path.read_text(encoding="utf-8"))
        raw["cases"] = [
            case for case in raw["cases"] if case["category"] != "retention_exception"
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "incomplete_golden.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(PolicyPackageError, "missing required case categories"):
                evaluate_golden_suite(self.package, self.evaluator, path)

    def test_policy_package_rejects_condition_language_injection(self) -> None:
        package_path = REPO_ROOT / "policies" / "htgl_reference_policy_v1.json"
        raw = json.loads(package_path.read_text(encoding="utf-8"))
        raw["rules"][0]["condition"] = {"op": "python", "code": "open('forbidden', 'w')"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad_package.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(PolicyPackageError, "unsupported expression operator"):
                load_policy_package(self.resolved, path, contract=self.contract)

    def test_every_replicate_runs_through_independent_policy_truth(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["run"]["replicate_count"]["value"] = 2
        raw["validation"]["repetition_count"]["value"] = 2
        resolved = resolve_config(raw)

        results = orchestrate_pipeline_through_policy(resolved, worker_count=2)

        self.assertEqual([0, 1], [result.run_plan.replicate_id for result in results])
        self.assertEqual(
            results[0].table_digests["policy_rule"],
            results[1].table_digests["policy_rule"],
        )
        self.assertNotEqual(
            results[0].table_digests["policy_decision_truth"],
            results[1].table_digests["policy_decision_truth"],
        )

    def test_balanced_all_family_run_exercises_actions_and_duties(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "reference_10k.json"))
        families = tuple(raw["workflows"]["families"]["value"])
        raw["arrivals"]["base_rates_per_day"]["value"] = {
            family: 0.01 for family in families
        }
        raw["arrivals"]["conditioned_total"]["value"] = 200

        policy = build_policy_oracle(resolve_config(raw), contract=self.contract)
        actions = Counter(row["expected_action"] for row in policy.policy_decisions)

        self.assertEqual({"allow", "erase", "escalate", "no_op", "notify", "retain"}, set(actions))
        self.assertGreater(sum(bool(row["requires_retention"]) for row in policy.policy_decisions), 0)
        self.assertGreater(sum(bool(row["requires_erasure"]) for row in policy.policy_decisions), 0)
        self.assertEqual(0, sum(bool(row["is_violation"]) for row in policy.policy_decisions))

    @staticmethod
    def _base_facts() -> dict[str, object]:
        return {
            "event.id": "FACT-EVENT-0001",
            "event.type": "processing_started",
            "event.family": "collection_processing",
            "event.timestamp": "2026-01-01T10:00:00Z",
            "workflow.type": "collection_processing",
            "workflow.state_before": "active",
            "workflow.state_after": "fulfilled",
            "actor.source.region": "REGION-A",
            "actor.source.jurisdiction": "JUR-A",
            "actor.destination.region": "REGION-A",
            "actor.destination.jurisdiction": "JUR-A",
            "actor.destination.class": "processor",
            "relationship.source_to_destination": ["processes_for"],
            "object.type": "meter_interval",
            "object.allowed_purpose_ids": ["PURPOSE-BILLING"],
            "purpose.id": "PURPOSE-BILLING",
            "database.region": "REGION-A",
            "state.consent": "granted",
            "state.retention": "active",
            "state.erasure": "not_requested",
            "retention.has_exception": False,
            "observed.action": "allow",
        }


if __name__ == "__main__":
    unittest.main()
