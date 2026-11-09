from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.paegen import (  # noqa: E402
    compile_adversarial_campaign,
    compile_smart_grid_benchmark,
    export_adversarial_campaign,
    load_adversarial_controls,
    validate_adversarial_campaign,
)


class PaEGenAdversarialCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controls = load_adversarial_controls()
        cls.campaign = compile_adversarial_campaign(cls.controls)
        cls.by_type = {item.attack_type: item for item in cls.campaign.fixtures}

    def _records(self, attack_type: str):
        fixture = self.by_type[attack_type]
        return next(iter(fixture.observer_views.values())).payload["records"]

    def _declaration(self, attack_type: str):
        return next(row for row in self._records(attack_type) if row["record_type"] == "case_declaration")

    def test_exact_independent_attack_coverage_and_expected_outcomes(self) -> None:
        expected = {
            "MISSING_RECIPIENT", "HIDDEN_DERIVATIVE", "FORGED_RECEIPT", "MALFORMED_RECEIPT",
            "REPLAY", "BACKDATING", "CONTRADICTION", "DELAY", "COLLUSION", "INCOMPLETE_LINEAGE",
        }
        self.assertEqual(10, len(self.campaign.fixtures))
        self.assertEqual(expected, set(self.by_type))
        self.assertTrue(all(item.expected_oracle_outcome for item in self.campaign.fixtures))
        self.assertTrue(all(item.expected_verifier_outcome for item in self.campaign.fixtures))
        self.assertTrue(all(item.expected_detection for item in self.campaign.fixtures))

    def test_campaign_artifacts_schemas_digests_and_privacy_validate(self) -> None:
        validate_adversarial_campaign(self.campaign, self.controls)
        for fixture in self.campaign.fixtures:
            self.assertEqual("restricted", next(iter(fixture.observer_views.values())).payload["access_class"])
            self.assertNotEqual(fixture.clean_ground_truth.sha256, fixture.attacked_ground_truth.sha256)

    def test_clean_trace_is_unchanged_and_shared_by_paired_counterfactuals(self) -> None:
        missing = self.by_type["MISSING_RECIPIENT"]
        replay = self.by_type["REPLAY"]
        self.assertEqual(missing.scenario_id, replay.scenario_id)
        self.assertEqual(missing.clean_ground_truth.sha256, replay.clean_ground_truth.sha256)
        self.assertEqual(
            "CLOSED",
            missing.clean_ground_truth.payload["cases"][0]["closure_ground_truth"]["outcome"],
        )

    def test_receipt_attacks_emit_raw_detectable_signals_without_labels(self) -> None:
        forged = self._declaration("FORGED_RECEIPT")["submitted_evidence"]
        self.assertTrue(any(row.get("authenticator") == "00-invalid-synthetic-signature" for row in forged))

        malformed = self._declaration("MALFORMED_RECEIPT")["submitted_evidence"]
        self.assertTrue(any("canonical_digest" in row and row["canonical_digest"] is None for row in malformed))

        replayed = self._declaration("REPLAY")["submitted_evidence"]
        replay_ids = [row["receipt_id"] for row in replayed]
        self.assertLess(len(set(replay_ids)), len(replay_ids))

        backdated = self.by_type["BACKDATING"]
        accepted = datetime.fromisoformat(
            backdated.attacked_ground_truth.payload["cases"][0]["accepted_at"].replace("Z", "+00:00")
        )
        issued = min(
            datetime.fromisoformat(row["issued_at"].replace("Z", "+00:00"))
            for row in self._declaration("BACKDATING")["submitted_evidence"]
        )
        self.assertLess(issued, accepted)

        contradiction = self._declaration("CONTRADICTION")["submitted_evidence"]
        self.assertEqual({"ERASED", "RETAINED"}, {row["claimed_disposition"] for row in contradiction if "claimed_disposition" in row})

        delay_fixture = self.by_type["DELAY"]
        case = delay_fixture.attacked_ground_truth.payload["cases"][0]
        deadline_by_obligation = {
            row["obligation_id"]: datetime.fromisoformat(row["deadline"].replace("Z", "+00:00"))
            for row in case["obligation_graph"]["obligations"]
        }
        self.assertTrue(any(
            datetime.fromisoformat(row["issued_at"].replace("Z", "+00:00")) > deadline_by_obligation[row["obligation_id"]]
            for row in self._declaration("DELAY")["submitted_evidence"]
        ))

    def test_hidden_topology_and_collusion_are_not_leaked(self) -> None:
        baseline = compile_smart_grid_benchmark(root_seed="PAEBENCH-ADVERSARIAL-v1")
        successful = {
            item.scenario_id: item for item in baseline.replicas
            if item.ground_truth.payload["variant_class"] == "successful_closure"
        }
        for attack_type in ("MISSING_RECIPIENT", "HIDDEN_DERIVATIVE"):
            fixture = self.by_type[attack_type]
            clean_records = successful[fixture.scenario_id].observer_views["OBS-SG-AUDITOR"].payload["records"]
            self.assertEqual(clean_records, self._records(attack_type))
            self.assertEqual("NOT_DETECTABLE", fixture.expected_detection)
            self.assertEqual("INDETERMINATE_BY_VIEW", fixture.expected_verifier_outcome)

        collusion = self.by_type["COLLUSION"]
        collusive_evidence = self._declaration("COLLUSION")["submitted_evidence"]
        claims_by_obligation: dict[str, set[str]] = {}
        for row in collusive_evidence:
            if "claimed_disposition" in row:
                claims_by_obligation.setdefault(row["obligation_id"], set()).add(
                    row["claimed_disposition"]
                )
        self.assertGreaterEqual(sum(len(claims) for claims in claims_by_obligation.values()), 2)
        self.assertTrue(all(len(claims) == 1 for claims in claims_by_obligation.values()))
        observer_text = json.dumps(self._records("COLLUSION"), sort_keys=True)
        self.assertNotIn("collusion_truth", observer_text)
        self.assertNotIn("DISPUTED", observer_text)
        self.assertEqual("IND-COLLUSIVE-CONSISTENCY", collusion.indistinguishability_class)

    def test_incomplete_lineage_projection_removes_parent_edges_only_from_view(self) -> None:
        declaration = self._declaration("INCOMPLETE_LINEAGE")
        self.assertTrue(all("parent_asset_ids" not in row for row in declaration["assets"]))
        fixture = self.by_type["INCOMPLETE_LINEAGE"]
        relationships = fixture.attacked_ground_truth.payload["cases"][0]["obligation_graph"]["relationship_edges"]
        self.assertTrue(any(row["edge_type"] == "derived_from" for row in relationships))
        self.assertEqual("CLOSED", fixture.expected_oracle_outcome)
        self.assertEqual("UNVERIFIABLE", fixture.expected_verifier_outcome)

    def test_all_restricted_views_exclude_truth_and_hidden_topology_fields(self) -> None:
        forbidden = self.controls.forbidden_fields | self.controls.hidden_topology_fields
        for fixture in self.campaign.fixtures:
            payload = next(iter(fixture.observer_views.values())).payload
            text = json.dumps(payload, sort_keys=True)
            for key in forbidden:
                self.assertNotIn(f'"{key}"', text)

    def test_same_seed_reproduces_campaign_exactly(self) -> None:
        repeated = compile_adversarial_campaign(self.controls)
        self.assertEqual(
            [item.attacked_ground_truth.sha256 for item in self.campaign.fixtures],
            [item.attacked_ground_truth.sha256 for item in repeated.fixtures],
        )
        self.assertEqual(
            [next(iter(item.observer_views.values())).sha256 for item in self.campaign.fixtures],
            [next(iter(item.observer_views.values())).sha256 for item in repeated.fixtures],
        )

    def test_export_keeps_expectations_and_truth_out_of_observer_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = export_adversarial_campaign(self.campaign, Path(temporary) / "campaign")
            observer_files = tuple((result.output_root / "observer-input").rglob("*.json"))
            self.assertEqual(10, len(observer_files))
            text = "\n".join(path.read_text(encoding="utf-8") for path in observer_files)
            self.assertNotIn("expected_oracle_outcome", text)
            self.assertNotIn("closure_ground_truth", text)
            self.assertTrue((result.output_root / "clean-ground-truth").is_dir())
            self.assertTrue((result.output_root / "attacked-ground-truth").is_dir())
            self.assertTrue((result.output_root / "expectations").is_dir())
            repeated = export_adversarial_campaign(self.campaign, result.output_root)
            self.assertEqual(result.export_digest, repeated.export_digest)

    def test_wrong_expected_outcome_is_rejected(self) -> None:
        fixtures = list(self.controls.fixtures)
        fixtures[0] = dict(fixtures[0], expected_oracle_outcome="UNVERIFIABLE")
        tampered = replace(self.controls, fixtures=tuple(fixtures))
        with self.assertRaisesRegex(ValueError, "derived oracle outcome"):
            compile_adversarial_campaign(tampered)


if __name__ == "__main__":
    unittest.main()
