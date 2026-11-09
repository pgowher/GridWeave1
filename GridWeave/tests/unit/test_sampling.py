from __future__ import annotations

from dataclasses import asdict, replace
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import load_config, resolve_config  # noqa: E402
from htgl_dataset_generator.experiments import (  # noqa: E402
    orchestrate_pipeline_through_sampling,
)
from htgl_dataset_generator.io import write_sampling_artifact_bundle  # noqa: E402
from htgl_dataset_generator.policy.language import canonical_json  # noqa: E402
from htgl_dataset_generator.sampling import (  # noqa: E402
    EstimatorEligibilityError,
    PrimaryUnit,
    ProbabilityDesignResult,
    SamplingBuildError,
    UnitKey,
    build_dependency_closure,
    draw_probability_design,
    hajek_total,
    horvitz_thompson_total,
    induced_inclusion_probability,
    validate_sampling_build,
)
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import CounterRng  # noqa: E402
from htgl_dataset_generator.validation import (  # noqa: E402
    ProductionRuleViolation,
    validate_population_metric_eligibility,
)


DESIGN_TYPES = {
    "census",
    "stratified",
    "PPS",
    "cluster",
    "nested_common_random_numbers",
}
PRIMARY_DEFINITIONS = {
    "workflow": "workflow=region_id:event_family",
    "cohort": "cohort=region_id:sampling_stratum",
    "actor": "actor=region_id:actor_class",
    "object": "object=region_id:object_type",
    "time_bin": "time_bin=region_id:time_bin",
    "dependency_component": "dependency_component=region_id:component_size_band",
}


class DependencyClosedSamplingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.resolved = resolve_config(
            load_config(REPO_ROOT / "configs" / "small_deterministic.json")
        )
        cls.result = orchestrate_pipeline_through_sampling(cls.resolved)[0]
        cls.artifacts = cls.result.artifacts
        cls.build = cls.artifacts.sampling
        observers = cls.artifacts.through_observers
        anomalies = observers.through_anomalies
        evidence = anomalies.through_evidence
        obligations = evidence.through_obligations
        policy = obligations.through_policy
        cls.dag = policy.through_dag
        cls.observers = observers.observers
        cls.obligations = obligations.evidence_obligations
        cls.receipts = evidence.evidence_receipts

    def test_all_configured_designs_emit_schema_valid_probability_rows(self) -> None:
        self.assertEqual(20, len(self.build.sampling_designs))
        self.assertEqual(DESIGN_TYPES, {row["design_type"] for row in self.build.sampling_designs})
        self.assertEqual(
            {"workflow", "cohort"},
            {row["primary_unit_type"] for row in self.build.sampling_designs},
        )
        for row in self.build.sampling_designs:
            validate_record(self.contract, "sampling_design", row)
            self.assertIn("component=S12.sampling", row["design_seed_stream"])
        keys = set()
        reasons = set()
        for row in self.build.sample_memberships:
            validate_record(self.contract, "sample_membership", row)
            key = (row["sample_design_id"], row["unit_type"], row["unit_id"])
            self.assertNotIn(key, keys)
            keys.add(key)
            probability = row["first_order_inclusion_probability"]
            self.assertGreater(probability, 0.0)
            self.assertLessEqual(probability, 1.0)
            self.assertAlmostEqual(1.0 / probability, row["design_weight"], places=11)
            self.assertEqual(row["design_weight"], row["analysis_weight"])
            self.assertTrue(row["estimator_eligible"])
            self.assertIsNotNone(row["primary_unit_id"])
            reasons.add(row["selection_reason"])
        self.assertTrue({"primary_draw", "closure_added", "census"} <= reasons)

    def test_closed_form_induced_probabilities_match_finite_design_formulas(self) -> None:
        units = tuple(
            PrimaryUnit(
                key=UnitKey("workflow", f"u{index}"),
                scenario_id="s",
                stratum_id="a" if index < 2 else "b",
                size_measure=float(index + 1),
                represented_value=float(index + 1),
                crn_key=f"k{index}",
                seed_event_ids=(),
            )
            for index in range(4)
        )
        by_id = {item.key.unit_id: item for item in units}
        global_result = ProbabilityDesignResult(
            design_type="cluster",
            target_size=2,
            selected_primary_unit_ids=("u0", "u1"),
            primary_inclusion_probabilities={item.key.unit_id: 0.5 for item in units},
            stratum_population_counts={"ALL": 4},
            stratum_sample_counts={"ALL": 2},
            pps_single_draw_probabilities={},
            pps_draw_count=0,
            exact_inclusion_probabilities=True,
        )
        self.assertAlmostEqual(
            5.0 / 6.0,
            induced_inclusion_probability(global_result, ("u0", "u1"), by_id),
        )
        stratified = replace(
            global_result,
            design_type="stratified",
            stratum_population_counts={"a": 2, "b": 2},
            stratum_sample_counts={"a": 1, "b": 1},
        )
        self.assertAlmostEqual(
            0.75,
            induced_inclusion_probability(stratified, ("u0", "u2"), by_id),
        )
        pps = replace(
            global_result,
            design_type="PPS",
            pps_single_draw_probabilities={"u0": 0.1, "u1": 0.2, "u2": 0.3, "u3": 0.4},
            pps_draw_count=2,
        )
        self.assertAlmostEqual(
            0.51,
            induced_inclusion_probability(pps, ("u0", "u1"), by_id),
        )

    def test_nested_crn_priority_samples_are_nested_and_order_invariant(self) -> None:
        units = tuple(
            PrimaryUnit(
                UnitKey("workflow", f"u{index:02d}"),
                "scenario",
                "stratum",
                1.0,
                1.0,
                f"common-{index:02d}",
                (),
            )
            for index in range(20)
        )
        rng = CounterRng("11" * 32)
        small = draw_probability_design(
            units,
            design_type="nested_common_random_numbers",
            target_size=5,
            rng=rng,
            draw_label="nested",
            use_crn_keys=True,
        )
        large = draw_probability_design(
            tuple(reversed(units)),
            design_type="nested_common_random_numbers",
            target_size=10,
            rng=rng,
            draw_label="nested",
            use_crn_keys=True,
        )
        self.assertTrue(
            set(small.selected_primary_unit_ids)
            <= set(large.selected_primary_unit_ids)
        )

    def test_estimator_families_share_the_same_realized_probability_sample(self) -> None:
        designs_by_draw = {}
        for row in self.build.sampling_designs:
            draw_key = (
                row["scenario_id"],
                row["design_type"],
                row["primary_unit_type"],
                row["stratum_definition"],
                row["target_sample_size"],
                row["closure_policy"],
                row["common_random_number_group"],
            )
            designs_by_draw.setdefault(draw_key, []).append(row)

        memberships_by_design = {}
        for row in self.build.sample_memberships:
            memberships_by_design.setdefault(row["sample_design_id"], []).append(
                tuple(
                    row[field]
                    for field in (
                        "unit_type",
                        "unit_id",
                        "stratum_id",
                        "first_order_inclusion_probability",
                        "design_weight",
                        "selection_reason",
                        "primary_unit_id",
                        "analysis_weight",
                        "estimator_eligible",
                    )
                )
            )

        for draw_key, design_rows in designs_by_draw.items():
            self.assertEqual(
                {"Horvitz_Thompson", "Hajek"},
                {row["estimator_family"] for row in design_rows},
                draw_key,
            )
            self.assertEqual(2, len(design_rows), draw_key)
            first, second = design_rows
            self.assertEqual(
                sorted(memberships_by_design[first["sample_design_id"]]),
                sorted(memberships_by_design[second["sample_design_id"]]),
                draw_key,
            )

    def test_all_six_primary_unit_registries_produce_complete_closure(self) -> None:
        namespace = "0d7b5cd6-053f-50cb-bc01-e05ad5cf688c"
        for unit_type, definition in PRIMARY_DEFINITIONS.items():
            sampling_config = replace(
                self.resolved.sampling,
                primary_unit_types=(unit_type,),
                strata_definitions=(definition,),
            )
            closure = build_dependency_closure(
                scenario_id=self.resolved.run.selected_scenario_ids[0],
                namespace=namespace,
                sampling_config=sampling_config,
                primary_unit_type=unit_type,
                world=self.dag.world,
                catalog=self.dag.catalog,
                dag=self.dag.causal_dag,
                obligations=self.obligations,
                receipts=self.receipts,
            )
            self.assertTrue(closure.primary_units, unit_type)
            self.assertEqual(
                {item.key.unit_id for item in closure.primary_units},
                set(closure.members_by_primary),
            )
            for key, causes in closure.causes_by_member.items():
                self.assertTrue(causes, key)
                self.assertIn(key, closure.population_units)
            unit_types = {key.unit_type for key in closure.population_units}
            self.assertIn(unit_type, unit_types)
            if any(item.seed_event_ids for item in closure.primary_units):
                self.assertIn("event", unit_types)
                self.assertIn("workflow", unit_types)

    def test_each_declared_closure_policy_adds_only_its_typed_dependencies(self) -> None:
        namespace = "0d7b5cd6-053f-50cb-bc01-e05ad5cf688c"
        unit_types_by_policy = {}
        for policy in (
            "ancestor",
            "descendant",
            "replica",
            "evidence",
            "full_dependency_closure",
        ):
            sampling_config = replace(
                self.resolved.sampling,
                primary_unit_types=("workflow",),
                strata_definitions=(PRIMARY_DEFINITIONS["workflow"],),
                closure_policy=policy,
            )
            closure = build_dependency_closure(
                scenario_id=self.resolved.run.selected_scenario_ids[0],
                namespace=namespace,
                sampling_config=sampling_config,
                primary_unit_type="workflow",
                world=self.dag.world,
                catalog=self.dag.catalog,
                dag=self.dag.causal_dag,
                obligations=self.obligations,
                receipts=self.receipts,
            )
            unit_types_by_policy[policy] = {
                key.unit_type for key in closure.population_units
            }
        self.assertNotIn("replica", unit_types_by_policy["ancestor"])
        self.assertNotIn("evidence", unit_types_by_policy["descendant"])
        self.assertIn("replica", unit_types_by_policy["replica"])
        self.assertNotIn("evidence", unit_types_by_policy["replica"])
        self.assertIn("evidence", unit_types_by_policy["evidence"])
        self.assertNotIn("replica", unit_types_by_policy["evidence"])
        self.assertTrue(
            {"event", "workflow", "object", "replica", "evidence"}
            <= unit_types_by_policy["full_dependency_closure"]
        )

    def test_estimators_fail_closed_and_recover_known_toy_totals(self) -> None:
        values = ((10.0, 0.5), (20.0, 1.0))
        self.assertEqual(
            40.0,
            horvitz_thompson_total(values, estimator_eligible=True),
        )
        self.assertAlmostEqual(
            80.0 / 3.0,
            hajek_total(
                values,
                population_unit_count=2,
                estimator_eligible=True,
            ),
        )
        with self.assertRaisesRegex(EstimatorEligibilityError, "prohibited"):
            horvitz_thompson_total(values, estimator_eligible=False)
        with self.assertRaises(EstimatorEligibilityError):
            hajek_total(
                ((1.0, 0.0),),
                population_unit_count=1,
                estimator_eligible=True,
            )

    def test_known_total_simulations_metrics_and_baselines_obey_claim_gate(self) -> None:
        self.assertEqual(60, len(self.build.known_total_diagnostics))
        self.assertTrue(all(item.passed for item in self.build.known_total_diagnostics))
        self.assertLessEqual(
            max(abs(item.relative_bias) for item in self.build.known_total_diagnostics),
            self.resolved.sampling.maximum_absolute_relative_bias,
        )
        self.assertGreaterEqual(
            min(item.ci_coverage for item in self.build.known_total_diagnostics),
            self.resolved.sampling.minimum_ci_coverage,
        )
        self.assertGreater(
            max(item.relative_rmse for item in self.build.known_total_diagnostics),
            0.0,
        )
        estimate_metrics = [
            row for row in self.build.run_metrics if str(row["metric_name"]).endswith(".estimate")
        ]
        self.assertEqual(60, len(estimate_metrics))
        self.assertEqual({"HT", "Hajek"}, {row["weighting"] for row in estimate_metrics})
        validate_population_metric_eligibility(
            self.build.run_metrics,
            self.build.sample_memberships,
        )
        self.assertTrue(self.build.baselines)
        self.assertFalse([item for item in self.build.baselines if item.estimator_eligible])
        self.assertEqual(
            {
                "BASELINE-FIRST-N-TRUNCATION",
                "BASELINE-SIMPLE-RANDOM-EVENT-ROWS",
                "BASELINE-UNWEIGHTED-WORKFLOW",
                "BASELINE-POSTHOC-ANALYTIC-WEIGHT",
            },
            {item.baseline_id for item in self.build.baselines},
        )

    def test_N_n_q_are_separate_and_no_execution_metric_is_invented(self) -> None:
        self.assertEqual(
            {
                "represented_population_N": 100,
                "materialized_row_target_n": 25,
                "executed_operation_target_q": None,
            },
            dict(self.build.scale_semantics),
        )
        metric_names = {str(row["metric_name"]) for row in self.build.run_metrics}
        self.assertIn("scale.represented_population_N", metric_names)
        self.assertIn("scale.materialized_row_target_n", metric_names)
        self.assertNotIn("scale.executed_operation_target_q", metric_names)

    def test_tampered_probability_or_ineligible_estimate_fails_validation(self) -> None:
        memberships = list(self.build.sample_memberships)
        memberships[0] = dict(
            memberships[0],
            first_order_inclusion_probability=(
                memberships[0]["first_order_inclusion_probability"] / 2.0
            ),
        )
        tampered = replace(self.build, sample_memberships=tuple(memberships))
        with self.assertRaisesRegex(SamplingBuildError, "design_weight != 1/pi"):
            validate_sampling_build(tampered, self.resolved, contract=self.contract)

        memberships = list(self.build.sample_memberships)
        memberships[0] = dict(memberships[0], estimator_eligible=False)
        ineligible = replace(self.build, sample_memberships=tuple(memberships))
        with self.assertRaisesRegex(SamplingBuildError, "ineligible design"):
            validate_sampling_build(ineligible, self.resolved, contract=self.contract)
        with self.assertRaises(ProductionRuleViolation):
            validate_population_metric_eligibility(
                self.build.run_metrics,
                memberships,
            )

    def test_worker_count_and_parquet_bundle_are_reproducible(self) -> None:
        parallel = orchestrate_pipeline_through_sampling(
            self.resolved, worker_count=3
        )[0]
        self.assertEqual(self.result.table_digests, parallel.table_digests)
        self.assertEqual(
            canonical_json([asdict(item) for item in self.build.closure_provenance]),
            canonical_json(
                [asdict(item) for item in parallel.artifacts.sampling.closure_provenance]
            ),
        )
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            first = write_sampling_artifact_bundle(
                self.build, Path(temporary) / "first"
            )
            second = write_sampling_artifact_bundle(
                self.build, Path(temporary) / "second"
            )
            self.assertEqual(first.manifest_sha256, second.manifest_sha256)
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual("parquet_zstd", manifest["authoritative_storage"])
            self.assertFalse(manifest["json_authority"])
            self.assertIsNone(
                manifest["scale_semantics"]["executed_operation_target_q"]
            )
            parquet_file = pq.ParquetFile(
                first.root / "evaluator_only" / "sample_membership.parquet"
            )
            self.assertEqual(
                "ZSTD", parquet_file.metadata.row_group(0).column(0).compression
            )
            parquet_file.close()


if __name__ == "__main__":
    unittest.main()
