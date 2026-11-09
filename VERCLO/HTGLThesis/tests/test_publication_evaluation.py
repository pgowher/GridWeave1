from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation import (
    FaultInjector,
    FaultKind,
    FaultSpec,
    PBFTFaultProfile,
    SimulatedPBFTClient,
    build_reference_scenarios,
    run_reference_campaign,
)
from evidence import BackendValidation
from run_publication_evaluation import render_artifacts


class PublicationEvaluationTests(unittest.TestCase):
    def test_fault_injector_is_ordered_deterministic_and_rejects_unknown_targets(
        self,
    ) -> None:
        clean = next(
            row for row in build_reference_scenarios() if row.scenario_id == "C-CLEAN"
        )
        receipt_id = clean.receipts[0].receipt_id
        with self.assertRaisesRegex(ValueError, "fault targets do not exist"):
            FaultInjector().inject(
                clean.case,
                clean.receipts,
                {receipt_id: clean.backend._validations[receipt_id]},
                (FaultSpec(FaultKind.OMIT_RECEIPT, ("NOT-A-RECEIPT",)),),
            )

        validations = {
            row.receipt_id: BackendValidation("publication-test")
            for row in clean.receipts
        }
        faults = (
            FaultSpec(FaultKind.CORRUPT_AUTHENTICATOR, (receipt_id,)),
            FaultSpec(FaultKind.EQUIVOCATE_DISPOSITION, (receipt_id,)),
        )
        first = FaultInjector().inject(clean.case, clean.receipts, validations, faults)
        second = FaultInjector().inject(clean.case, clean.receipts, validations, faults)
        self.assertEqual(first, second)
        clone_id = f"{receipt_id}::EQUIVOCATED"
        self.assertFalse(first.validations[clone_id].authenticator_valid)
        self.assertEqual(
            (FaultKind.CORRUPT_AUTHENTICATOR, FaultKind.EQUIVOCATE_DISPOSITION),
            first.applied_faults,
        )

    def test_distributed_fault_profiles_enforce_threshold_commitment_and_identity(
        self,
    ) -> None:
        scenarios = {row.scenario_id: row for row in build_reference_scenarios()}
        accepted = scenarios["D-CRASH-WITHIN-THRESHOLD"]
        rejected_ids = (
            "D-QUORUM-LOSS",
            "D-NETWORK-PARTITION",
            "D-COMMITMENT-EQUIVOCATION",
            "D-DUPLICATE-IDENTITY",
        )
        obligation = accepted.case.graph.obligations[0]
        result = accepted.backend.validate(
            accepted.receipts[0], obligation, accepted.case.accepted_at
        )
        self.assertTrue(result.verification_material_available)
        for scenario_id in rejected_ids:
            with self.subTest(scenario_id=scenario_id):
                scenario = scenarios[scenario_id]
                validation = scenario.backend.validate(
                    scenario.receipts[0],
                    scenario.case.graph.obligations[0],
                    scenario.case.accepted_at,
                )
                self.assertFalse(validation.verification_material_available)

        with self.assertRaisesRegex(ValueError, "unknown validators"):
            SimulatedPBFTClient(
                ("V1", "V2", "V3", "V4"),
                PBFTFaultProfile(crashed_validator_ids=("V5",)),
            )

    def test_reference_campaign_compares_policies_and_verclo_matches_every_oracle_label(
        self,
    ) -> None:
        report = run_reference_campaign().to_dict()
        self.assertEqual(17, report["scenario_count"])
        self.assertGreaterEqual(len(report["fault_families"]), 12)
        self.assertEqual(1.0, report["metrics"]["verclo"]["accuracy"])
        self.assertEqual(0.0, report["metrics"]["verclo"]["false_acceptance_rate"])
        self.assertEqual(0.0, report["metrics"]["verclo"]["false_rejection_rate"])
        self.assertGreater(
            report["metrics"]["receipt-presence"]["false_acceptance_rate"], 0.0
        )
        self.assertGreater(
            report["metrics"]["authenticated-receipt"]["false_acceptance_rate"], 0.0
        )
        self.assertGreater(
            report["metrics"]["evidence-grade"]["false_acceptance_rate"], 0.0
        )
        self.assertTrue(
            all(row["decisions"]["verclo"]["correct"] for row in report["results"])
        )

    def test_publication_artifacts_are_byte_reproducible_and_self_hashing(self) -> None:
        first = render_artifacts()
        second = render_artifacts()
        self.assertEqual(first, second)
        report = json.loads(first["campaign_report.json"])
        self.assertEqual(64, len(report["report_sha256"]))
        self.assertIn("campaign_report.json", first["SHA256SUMS"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in first.items():
                (root / name).write_text(content, encoding="utf-8")
            self.assertEqual(
                first["campaign_report.json"],
                (root / "campaign_report.json").read_text(),
            )


if __name__ == "__main__":
    unittest.main()
