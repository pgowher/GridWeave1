from __future__ import annotations

from dataclasses import replace
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.paegen import (  # noqa: E402
    REQUIRED_SMART_GRID_SCENARIOS,
    compile_smart_grid_benchmark,
    load_smart_grid_scenarios,
    validate_paegen_build,
)


class PaEGenSmartGridScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.definitions = load_smart_grid_scenarios()
        cls.build = compile_smart_grid_benchmark(cls.definitions)

    def test_catalog_contains_exactly_seven_required_lifecycles(self) -> None:
        self.assertEqual(7, len(self.definitions))
        self.assertEqual(
            REQUIRED_SMART_GRID_SCENARIOS,
            {item.scenario_id for item in self.definitions},
        )
        self.assertEqual(
            {
                "DEMAND_RESPONSE_TERMINATION",
                "SUPPLIER_SWITCHING",
                "CONSENT_WITHDRAWAL",
                "EV_CHARGING_TERMINATION",
                "RETENTION_EXPIRY",
                "REGULATORY_ERASURE",
                "BILLING_SETTLEMENT_EXCEPTION",
            },
            {item.payload["lifecycle_trigger"] for item in self.definitions},
        )

    def test_every_profile_is_referentially_closed_and_synthetic_only(self) -> None:
        for definition in self.definitions:
            profile = definition.payload
            self.assertEqual("synthetic_only", profile["synthetic_data_profile"]["mode"])
            self.assertTrue(profile["synthetic_data_profile"]["direct_identifiers_prohibited"])
            self.assertGreaterEqual(len(profile["organizations"]), 2)
            self.assertGreaterEqual(len(profile["repositories"]), 2)
            self.assertGreaterEqual(len(profile["assets"]), 2)
            self.assertGreaterEqual(len(profile["obligations"]), 2)
            self.assertTrue(profile["observable_metadata"]["visible_fields"])
            self.assertTrue(all(
                standard["authoritative_url"].startswith("https://")
                for standard in profile["standards_basis"]
            ))
            self.assertEqual(
                {asset["asset_id"] for asset in profile["assets"]},
                {
                    asset_id
                    for obligation in profile["obligations"]
                    for asset_id in obligation["asset_ids"]
                },
            )

    def test_loader_rejects_assets_outside_the_obligation_set(self) -> None:
        source = next(
            definition for definition in self.definitions
            if all(len(row["asset_ids"]) == 1 for row in definition.payload["obligations"])
        )
        payload = json.loads(json.dumps(source.payload))
        payload["obligations"].pop()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "uncovered.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside the declared obligation set"):
                load_smart_grid_scenarios(temporary, require_canonical_catalog=False)

    def test_each_scenario_has_exact_three_controlled_variant_classes(self) -> None:
        expected_classes = {
            "successful_closure",
            "partial_or_unverifiable",
            "adversarial_or_disputed",
        }
        for definition in self.definitions:
            variants = definition.payload["variants"]
            self.assertEqual(3, len(variants))
            self.assertEqual(expected_classes, {item["variant_class"] for item in variants})
            by_class = {item["variant_class"]: item for item in variants}
            self.assertIn(by_class["successful_closure"]["expected_closure"], {"CLOSED", "CLOSED_WITH_EXCEPTIONS"})
            self.assertIn(by_class["partial_or_unverifiable"]["expected_closure"], {"PARTIALLY_CLOSED", "UNVERIFIABLE"})
            self.assertEqual("DISPUTED", by_class["adversarial_or_disputed"]["expected_closure"])

    def test_all_21_cases_validate_and_match_independently_derived_outcomes(self) -> None:
        validate_paegen_build(self.build)
        self.assertEqual(21, len(self.build.replicas))
        by_scenario: dict[str, list[object]] = {}
        for replica in self.build.replicas:
            by_scenario.setdefault(replica.scenario_id, []).append(replica)
            self.assertEqual(1, len(replica.ground_truth.payload["cases"]))
            case = replica.ground_truth.payload["cases"][0]
            self.assertTrue(case["obligation_graph"]["relationship_edges"])
            self.assertTrue(case["obligation_graph"]["obligations"])
            self.assertEqual(
                len(case["obligation_graph"]["obligations"]), len(case["dispositions"])
            )
        self.assertTrue(all(len(items) == 3 for items in by_scenario.values()))

    def test_billing_success_is_closed_with_a_valid_bounded_exception(self) -> None:
        replica = next(
            item for item in self.build.replicas
            if item.scenario_id == "PBE-SG-BILLING-SETTLEMENT-EXCEPTION"
            and item.ground_truth.payload["variant_class"] == "successful_closure"
        )
        case = replica.ground_truth.payload["cases"][0]
        self.assertEqual("CLOSED_WITH_EXCEPTIONS", case["closure_ground_truth"]["outcome"])
        self.assertEqual(1, len(case["exceptions"]))
        self.assertTrue(case["exceptions"][0]["valid"])
        public_records = next(iter(replica.observer_views.values())).payload["records"]
        declaration = next(row for row in public_records if row["record_type"] == "case_declaration")
        self.assertEqual(2555, declaration["declared_exceptions"][0]["maximum_retention_days"])

    def test_observer_projections_do_not_disclose_variant_or_closure_truth(self) -> None:
        forbidden = (
            "variant_id",
            "variant_class",
            "expected_closure",
            "closure_ground_truth",
            "verification_status_truth",
            "truth_matches_declared",
        )
        for replica in self.build.replicas:
            text = json.dumps(
                [item.payload for item in replica.observer_views.values()], sort_keys=True
            )
            for token in forbidden:
                self.assertNotIn(token, text)

    def test_contradictory_claim_dispositions_remain_observable(self) -> None:
        disputed = [
            replica for replica in self.build.replicas
            if replica.ground_truth.payload["variant_class"] == "adversarial_or_disputed"
        ]
        self.assertEqual(7, len(disputed))
        for replica in disputed:
            definition = next(
                row for row in self.definitions if row.scenario_id == replica.scenario_id
            )
            self.assertEqual(
                "visible",
                definition.payload["observable_metadata"]["claim_disposition_visibility"],
            )
            declaration = next(
                row for row in next(iter(replica.observer_views.values())).payload["records"]
                if row["record_type"] == "case_declaration"
            )
            claims_by_obligation: dict[str, set[str]] = {}
            for receipt in declaration["submitted_evidence"]:
                claims_by_obligation.setdefault(receipt["obligation_id"], set()).add(
                    receipt["claimed_disposition"]
                )
            self.assertTrue(
                any(len(claims) > 1 for claims in claims_by_obligation.values()),
                replica.scenario_id,
            )

    def test_same_seed_is_identical_and_different_seed_changes_case_identity(self) -> None:
        repeated = compile_smart_grid_benchmark(self.definitions)
        alternate = compile_smart_grid_benchmark(self.definitions, root_seed="PAEBENCH-SMART-GRID-v1-ALT")
        self.assertEqual(
            [item.ground_truth.sha256 for item in self.build.replicas],
            [item.ground_truth.sha256 for item in repeated.replicas],
        )
        self.assertNotEqual(
            self.build.replicas[0].ground_truth.payload["cases"][0]["case_id"],
            alternate.replicas[0].ground_truth.payload["cases"][0]["case_id"],
        )
        self.assertEqual(
            self.build.replicas[0].ground_truth.payload["cases"][0]["closure_ground_truth"]["outcome"],
            alternate.replicas[0].ground_truth.payload["cases"][0]["closure_ground_truth"]["outcome"],
        )

    def test_declared_expected_outcome_is_checked_not_copied(self) -> None:
        source = self.definitions[0]
        payload = json.loads(json.dumps(source.payload))
        payload["variants"][0]["expected_closure"] = "DISPUTED"
        tampered = replace(source, payload=payload)
        with self.assertRaisesRegex(ValueError, "derived .* declared"):
            compile_smart_grid_benchmark((tampered,))

    def test_researcher_can_add_schema_valid_scenario_without_oracle_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = json.loads(json.dumps(self.definitions[0].payload))
            payload["scenario_id"] = "PBE-SG-RESEARCHER-EXTENSION"
            payload["title"] = "Researcher-defined synthetic extension"
            payload["lifecycle_trigger"] = "RESEARCHER_DEFINED_TRIGGER"
            path = Path(temporary) / "researcher_extension.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            definitions = load_smart_grid_scenarios(
                temporary, require_canonical_catalog=False
            )
            build = compile_smart_grid_benchmark(definitions)
            validate_paegen_build(build)
            self.assertEqual(3, len(build.replicas))
            self.assertEqual(
                {"PBE-SG-RESEARCHER-EXTENSION"},
                {item.scenario_id for item in build.replicas},
            )


if __name__ == "__main__":
    unittest.main()
