from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from htgl_dataset_generator.experiments import (  # noqa: E402
    FinalReleaseCheck,
    FinalReleaseGateError,
    FinalReleaseGateResult,
    build_factorial_study_plan,
    complete_staged_report_gate,
    default_study_resource_budget,
    require_complete_publication_selection,
)
from htgl_dataset_generator.experiments.release_gate import (  # noqa: E402
    REQUIRED_FINAL_REPORTS,
)


class FinalReleaseSelectionTests(unittest.TestCase):
    def test_default_pairwise_plan_fails_before_execution_on_blocked_cells(self) -> None:
        plan = build_factorial_study_plan("FINAL-GATE-PREFLIGHT")
        eligible = [
            item.condition_id
            for item in plan.conditions
            if item.feasibility_status == "eligible"
        ]
        with self.assertRaisesRegex(
            FinalReleaseGateError, "resource or capability blocked conditions"
        ):
            require_complete_publication_selection(plan, eligible)

    def test_exact_finite_eligible_design_passes_selection_contract(self) -> None:
        selected_levels = {
            "represented_population_N": ("N-450M",),
            "materialized_row_target_n": ("n-1E4",),
            "region_count": ("REGIONS-3",),
            "organization_graph_density": ("ORG-SPARSE",),
            "arrival_model": ("ARR-CONDITIONED-NHPP",),
            "workflow_mix": ("WF-BALANCED-RIGHTS",),
            "anomaly_prevalence": ("ANOM-0",),
            "visibility_profile": ("VIS-ROLE-BASED",),
            "evidence_profile": ("EVID-DIGEST",),
            "physical_backend": ("PHYS-PROCEDURAL",),
            "sampling_profile": ("SAMPLE-STRATIFIED",),
        }
        budget = replace(
            default_study_resource_budget(),
            maximum_conditions=1,
            maximum_replicates=30,
            maximum_total_materialized_rows=300_000,
        )
        plan = build_factorial_study_plan(
            "FINAL-GATE-FINITE",
            design_mode="full_factorial",
            selected_level_ids=selected_levels,
            resource_budget=budget,
        )
        condition_id = plan.conditions[0].condition_id
        self.assertEqual(
            (condition_id,),
            require_complete_publication_selection(plan, (condition_id,)),
        )
        with self.assertRaisesRegex(FinalReleaseGateError, "does not equal"):
            require_complete_publication_selection(plan, ())


class FinalReleaseReportGateTests(unittest.TestCase):
    def _staging(self, root: Path) -> tuple[Path, FinalReleaseGateResult]:
        report_root = root / "publication" / "reports"
        report_root.mkdir(parents=True)
        source = root / "study" / "source.parquet"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"immutable-source-bytes")
        for name in REQUIRED_FINAL_REPORTS:
            if name == "publication_items.json":
                continue
            path = report_root / name
            if name == "quality_report.json":
                path.write_text(
                    json.dumps({"format": "htgl.factorial-study-quality-report.v1"}),
                    encoding="utf-8",
                )
            elif name == "claim_matrix.csv":
                path.write_text(
                    "claim_id,evidence_class,claim_text,validation_gate,claim_status\n",
                    encoding="utf-8",
                )
            elif name == "license.md":
                path.write_text("License status: NO-LICENSE-GRANT\n", encoding="utf-8")
            elif path.suffix == ".json":
                path.write_text("{}", encoding="utf-8")
            else:
                path.write_text("qualified benchmark report\n", encoding="utf-8")
        items = {
            "format": "htgl.publication-item-lineage.v1",
            "items": [
                {
                    "item_id": "T-TEST",
                    "item_kind": "table",
                    "output_path": "publication/reports/claim_matrix.csv",
                    "sources": [
                        {
                            "relative_path": "study/source.parquet",
                            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        }
                    ],
                }
            ],
        }
        (report_root / "publication_items.json").write_text(
            json.dumps(items), encoding="utf-8"
        )
        preliminary_check = FinalReleaseCheck(
            "PRELIMINARY-REAL-EVIDENCE", 1, "pass", "1", "1",
            "preliminary evidence passed",
        )
        preliminary = FinalReleaseGateResult(
            "REPORT-GATE-TEST", (preliminary_check,), True, "0" * 64
        )
        return source, preliminary

    def test_staged_report_gate_verifies_documents_lineage_and_wording(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _source, preliminary = self._staging(root)
            result = complete_staged_report_gate(preliminary, root)
            self.assertTrue(result.eligible)
            self.assertEqual(
                {"FINAL-DOCUMENTS-001", "FINAL-PAPER-LINEAGE-001", "FINAL-WORDING-001"},
                {item.check_id for item in result.checks if item.check_id.startswith("FINAL-")},
            )

    def test_staged_report_gate_detects_source_mutation_and_forbidden_wording(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, preliminary = self._staging(root)
            source.write_bytes(b"mutated")
            (root / "publication" / "reports" / "data_card.md").write_text(
                "HTGL handled 450 million users", encoding="utf-8"
            )
            with self.assertRaises(FinalReleaseGateError) as raised:
                complete_staged_report_gate(preliminary, root)
            failed = {
                item.check_id for item in raised.exception.checks if item.status == "fail"
            }
            self.assertEqual(
                {"FINAL-PAPER-LINEAGE-001", "FINAL-WORDING-001"}, failed
            )


if __name__ == "__main__":
    unittest.main()
