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

from htgl_dataset_generator.config import resolve_config_file  # noqa: E402
from htgl_dataset_generator.experiments import (  # noqa: E402
    FactorialStudyPlan,
    PrecisionJustification,
    StudyCondition,
    StudyPackageError,
    StudyPackageOptions,
    StudyPlanningError,
    build_factorial_study_plan,
    compile_condition_config,
    compile_study_evidence_package,
    default_study_resource_budget,
    execute_factorial_study,
    full_factorial_condition_count,
    load_factorial_study_registry,
    planned_study_execution,
    required_repetition_count,
)
from htgl_dataset_generator.artifacts.canonical import domain_sha256  # noqa: E402


class FactorialStudyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_factorial_study_registry()
        cls.base_450m = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")

    def test_registry_exactly_covers_controlling_axes_and_full_cardinality(self) -> None:
        self.assertEqual(11, len(self.registry.axes))
        self.assertEqual(6_220_800, full_factorial_condition_count(self.registry))
        self.assertEqual(
            [10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 450_000_000],
            [item.value for item in self.registry.axis("represented_population_N").levels],
        )
        self.assertEqual(
            {"conditioned_NHPP", "unconditioned_NHPP", "MMPP", "Hawkes"},
            {item.value for item in self.registry.axis("arrival_model").levels},
        )
        self.assertFalse(
            self.registry.axis("sampling_profile").levels[-1].claim_eligible
        )
        self.assertEqual(self.registry.sha256, load_factorial_study_registry().sha256)

    def test_full_factorial_refuses_implicit_budget_overrun(self) -> None:
        with self.assertRaisesRegex(StudyPlanningError, "6220800 conditions"):
            build_factorial_study_plan("STUDY-FULL", design_mode="full_factorial")

    def test_pairwise_plan_is_deterministic_complete_and_explicit_about_exclusions(self) -> None:
        first = build_factorial_study_plan("STUDY-PAIRWISE")
        second = build_factorial_study_plan("STUDY-PAIRWISE")
        self.assertEqual(first.plan_sha256, second.plan_sha256)
        self.assertEqual(first.conditions, second.conditions)
        self.assertEqual(first.pairwise_requirement_count, first.pairwise_covered_count)
        self.assertLess(first.selected_condition_count, first.full_factorial_condition_count)
        self.assertIn("not a full factorial", first.design_scope_statement)
        for axis in self.registry.axes:
            observed = {
                condition.factor_level_ids[axis.axis_id]
                for condition in first.conditions
            }
            self.assertEqual({level.level_id for level in axis.levels}, observed)
        structural = [
            item for item in first.conditions if item.feasibility_status == "structurally_ineligible"
        ]
        blocked = [item for item in first.conditions if item.feasibility_status == "blocked"]
        self.assertTrue(structural)
        self.assertTrue(blocked)
        self.assertTrue(
            all(
                item.materialized_row_target_n > item.represented_population_N
                for item in structural
            )
        )
        self.assertTrue(
            any(
                "missing_capability:materialize_1e7_rows" in item.feasibility_reasons
                for item in blocked
            )
        )
        self.assertTrue(
            all(item.executed_operation_target_q is None for item in first.conditions)
        )

    def test_repetition_override_requires_a_computed_precision_contract(self) -> None:
        with self.assertRaisesRegex(StudyPlanningError, "requires a pinned"):
            required_repetition_count(29, None)
        justification = PrecisionJustification(
            method="normal_half_width_v1",
            confidence_level=0.95,
            target_half_width=0.1,
            pilot_standard_deviation=0.2,
            pilot_repetitions=10,
            source_label="controlled_synthetic",
            source_id="PILOT-STUDY-v1",
        )
        with self.assertRaisesRegex(StudyPlanningError, "below precision-derived"):
            required_repetition_count(10, justification)
        self.assertEqual(16, required_repetition_count(16, justification))

    def test_condition_compiler_resolves_scale_topology_and_exact_models(self) -> None:
        selected = {
            "represented_population_N": ("N-450M",),
            "materialized_row_target_n": ("n-1E5",),
            "region_count": ("REGIONS-30",),
            "organization_graph_density": ("ORG-DENSE",),
            "arrival_model": ("ARR-HAWKES",),
            "workflow_mix": ("WF-ERASURE-HEAVY",),
            "anomaly_prevalence": ("ANOM-1PCT",),
            "visibility_profile": ("VIS-COLLUSION",),
            "evidence_profile": ("EVID-MIXED",),
            "physical_backend": ("PHYS-SMARTDS-STYLE-SYNTHETIC",),
            "sampling_profile": ("SAMPLE-CLUSTER-PPS",),
        }
        budget = replace(default_study_resource_budget(), maximum_conditions=1)
        plan = build_factorial_study_plan(
            "STUDY-CONFIG-COMPILE",
            design_mode="full_factorial",
            selected_level_ids=selected,
            resource_budget=budget,
        )
        condition = plan.conditions[0]
        first = compile_condition_config(
            self.base_450m, condition, study_id=plan.study_id
        )
        second = compile_condition_config(
            self.base_450m, condition, study_id=plan.study_id
        )
        self.assertEqual(first.config_sha256, second.config_sha256)
        self.assertEqual(450_000_000, first.claim_scale.represented_population)
        self.assertEqual(100_000, first.claim_scale.materialized_row_target)
        self.assertIsNone(first.claim_scale.executed_operation_target)
        self.assertFalse(first.claim_scale.operational_claim_allowed)
        self.assertEqual(30, len(first.world.regions))
        self.assertEqual(450_000_000, sum(item["represented_count"] for item in first.world.cohorts))
        self.assertEqual(("Hawkes",), first.arrivals.model_classes)
        self.assertIsNone(first.arrivals.conditioned_total)
        self.assertIn("branching", first.arrivals.hawkes_parameters)
        self.assertEqual("smart_ds_style_synthetic", first.physical.backend)
        self.assertEqual(
            "controlled_synthetic_template_analytic:v1",
            first.physical.solver_backend,
        )
        self.assertIn("PPS", first.sampling.design_types)
        self.assertIn("nested_common_random_numbers", first.sampling.design_types)
        self.assertEqual(30, first.run.replicate_count)
        self.assertEqual(self.base_450m.run.root_seed, first.run.root_seed)
        self.assertEqual(5, len(self.base_450m.world.regions))


class FactorialStudyArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        cls.plan = build_factorial_study_plan("STUDY-ARTIFACT-TEST")
        cls.build = planned_study_execution(cls.base, cls.plan)

    def test_plan_only_package_is_manifested_zstd_and_not_publication_eligible(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            result = compile_study_evidence_package(self.build, temporary)
            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertFalse(result.publication_eligible)
            self.assertFalse(manifest["json_authority"])
            self.assertEqual("parquet_zstd", manifest["authoritative_storage"])
            self.assertIn("N is represented", manifest["represented_population_execution_boundary"])
            manifested = {item["relative_path"] for item in manifest["artifacts"]}
            actual = {
                path.relative_to(result.package_root).as_posix()
                for path in result.package_root.rglob("*")
                if path.is_file()
                and path.name not in {"manifest.json", ".htgl-generator-owned.json"}
            }
            self.assertEqual(actual, manifested)
            condition_rows = pq.read_table(
                result.package_root / "study" / "condition_matrix.parquet"
            ).to_pylist()
            self.assertEqual(self.plan.selected_condition_count, len(condition_rows))
            self.assertTrue(
                all("represented_population_N" in row for row in condition_rows)
            )
            claim_rows = pq.read_table(
                result.package_root / "study" / "scale_claim_matrix.parquet"
            ).to_pylist()
            self.assertTrue(all(row["executed_operations_sum_q"] is None for row in claim_rows))
            for path in result.package_root.rglob("*.parquet"):
                parquet = pq.ParquetFile(path)
                try:
                    self.assertTrue(parquet.schema_arrow.metadata[b"schema_fingerprint"])
                    for group_index in range(parquet.metadata.num_row_groups):
                        group = parquet.metadata.row_group(group_index)
                        for column_index in range(group.num_columns):
                            self.assertEqual("ZSTD", group.column(column_index).compression)
                finally:
                    parquet.close()

    def test_diagnostic_package_is_byte_reproducible_and_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as first_root, tempfile.TemporaryDirectory() as second_root:
            first = compile_study_evidence_package(self.build, first_root)
            second = compile_study_evidence_package(self.build, second_root)
            self.assertEqual(first.semantic_digest, second.semantic_digest)
            self.assertEqual(first.byte_digest, second.byte_digest)
            self.assertEqual(first.manifest_path.read_bytes(), second.manifest_path.read_bytes())
            reused = compile_study_evidence_package(
                self.build,
                first_root,
                options=StudyPackageOptions(collision_policy="reuse_identical"),
            )
            self.assertTrue(reused.reused_existing_package)

    def test_publication_mode_refuses_missing_execution_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(StudyPackageError, "publication package blocked"):
                compile_study_evidence_package(
                    self.build,
                    temporary,
                    options=StudyPackageOptions(package_kind="publication"),
                )

    def test_injected_failure_never_promotes_partial_study_package(self) -> None:
        def fail(phase: str, _root: Path) -> None:
            if phase == "before_promotion":
                raise RuntimeError("injected study writer failure")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "injected study writer failure"):
                compile_study_evidence_package(
                    self.build,
                    temporary,
                    options=StudyPackageOptions(failure_injector=fail),
                )
            self.assertFalse((Path(temporary) / f"run_{self.plan.study_id}").exists())
            recovery = tuple(Path(temporary).glob("*.recovery.*.json"))
            self.assertEqual(1, len(recovery))
            payload = json.loads(recovery[0].read_text(encoding="utf-8"))
            self.assertEqual("compilation_failed", payload["phases"][-1]["phase"])


class FactorialStudyRealPipelineIntegrationTests(unittest.TestCase):
    def test_real_small_pipeline_remains_diagnostic_without_s15_or_q_evidence(self) -> None:
        base = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        registry = load_factorial_study_registry()
        factor_values = {
            "represented_population_N": 100,
            "materialized_row_target_n": 25,
            "region_count": 2,
            "organization_graph_density": "sparse",
            "arrival_model": "conditioned_NHPP",
            "workflow_mix": "balanced_rights",
            "anomaly_prevalence": 0.0,
            "visibility_profile": "full",
            "evidence_profile": "digest",
            "physical_backend": "procedural",
            "sampling_profile": "stratified",
        }
        factor_ids = {key: f"DIAGNOSTIC-{index:02d}" for index, key in enumerate(factor_values)}
        condition = StudyCondition(
            condition_id="00000000-0000-5000-8000-000000000021",
            ordinal=0,
            factor_level_ids=factor_ids,
            factor_values=factor_values,
            represented_population_N=100,
            materialized_row_target_n=25,
            executed_operation_target_q=None,
            repetitions=1,
            common_random_group="SMALL-DIAGNOSTIC-CRN-v1",
            estimator_eligible=True,
            feasibility_status="eligible",
            feasibility_reasons=(),
            projected_materialized_rows=25,
            projected_stored_bytes_upper_bound=50_000,
        )
        precision = PrecisionJustification(
            method="normal_half_width_v1",
            confidence_level=0.95,
            target_half_width=1.0,
            pilot_standard_deviation=0.0,
            pilot_repetitions=2,
            source_label="controlled_synthetic",
            source_id="DETERMINISTIC-INTEGRATION-FIXTURE-v1",
        )
        plan = FactorialStudyPlan(
            study_id="STUDY-REAL-SMALL",
            registry=registry,
            design_mode="diagnostic_single_cell",
            design_scope_statement="single real-pipeline integration condition; no factorial claim",
            requested_repetitions=1,
            required_repetitions=1,
            precision_justification=precision,
            full_factorial_condition_count=1,
            selected_condition_count=1,
            pairwise_requirement_count=0,
            pairwise_covered_count=0,
            conditions=(condition,),
            plan_sha256=domain_sha256("test-real-small-plan", factor_values),
        )
        build = execute_factorial_study(base, plan, condition_ids=(condition.condition_id,))
        row = build.replicate_evidence[0]
        self.assertEqual("executed", row.execution_status, row.failure_message)
        self.assertGreater(row.materialized_governance_event_rows_n or 0, 0)
        self.assertGreater(row.retained_metric_count, 0)
        self.assertEqual("not_finalized", row.validation_status)
        self.assertIsNone(row.executed_operations_q)
        self.assertTrue(build.run_metrics)
        self.assertTrue(build.factor_metrics)
        self.assertTrue(build.metric_aggregates)
        self.assertEqual(
            {"visibility_profile", "evidence_profile", "sampling_profile"},
            {row["axis_id"] for row in build.factor_metrics},
        )
        self.assertTrue(
            all(row["represented_population_N"] == 100 for row in build.factor_metrics)
        )
        self.assertTrue(build.validation_issues)
        self.assertFalse(build.publication_eligible)
        self.assertEqual(
            "not_supported_missing_execution_evidence",
            build.scale_claims[0].claim_status,
        )
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            package = compile_study_evidence_package(build, temporary)
            factor_rows = pq.read_table(
                package.package_root / "metrics" / "study_factor_metric.parquet"
            ).to_pylist()
            aggregate_rows = pq.read_table(
                package.package_root / "metrics" / "study_metric_aggregate.parquet"
            ).to_pylist()
            self.assertEqual(len(build.factor_metrics), len(factor_rows))
            self.assertEqual(len(build.metric_aggregates), len(aggregate_rows))
            self.assertTrue(all(row["executed_operation_target_q"] is None for row in factor_rows))


if __name__ == "__main__":
    unittest.main()
