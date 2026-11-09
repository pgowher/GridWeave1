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
    build_metrics_for_validation_result,
    orchestrate_pipeline_through_validation,
)
from htgl_dataset_generator.io import write_metrics_artifact_bundle  # noqa: E402
from htgl_dataset_generator.metrics import (  # noqa: E402
    MetricConditionSeries,
    MetricObservationProvenance,
    MetricRegistryError,
    MetricsBuild,
    MetricsEngineError,
    PhysicalCalibrationReference,
    PhysicalReferenceObservation,
    PrivacySourceReference,
    aggregate_replicate_metrics,
    build_paired_crn_comparisons,
    load_metric_registry,
    validate_metric_execution_for_publication,
    validate_metrics_build,
    weighted_ks_2sample,
    weighted_wasserstein_1d,
)
from htgl_dataset_generator.seeds import content_id  # noqa: E402
from htgl_dataset_generator.validation import PerformanceObservation  # noqa: E402


MANDATORY_KEYS = {
    "meter_energy_wasserstein", "meter_energy_ks", "acf_error_l1",
    "count_mean_ratio", "dispersion_index", "time_rescaling_ks", "bin_deviance",
    "fk_violation_count", "transition_conformance_rate", "causal_orphan_rate",
    "golden_decision_accuracy", "target_violation_success", "collateral_violation_rate",
    "obligation_coverage", "sufficiency_precision_recall", "visible_event_coverage",
    "sealed_truth_leakage", "effective_sample_size", "relative_bias_known_total",
    "ci_coverage", "deterministic_digest_match", "manifest_coverage",
    "generation_rows_per_second", "peak_resident_memory_bytes",
    "der_energy_balance_error", "workflow_completion_rate",
    "conflict_resolution_agreement", "pair_non_target_predictability",
    "receipt_timeliness_rate", "contradiction_detection_rate",
    "verification_cost", "visible_edge_coverage", "closure_expansion_factor",
    "weight_reconciliation_error", "design_effect", "cross_excitation_error",
    "mmpp_regime_occupancy_error",
}


class MetricsEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        cls.validation_result = orchestrate_pipeline_through_validation(cls.resolved)[0]
        cls.default_pipeline = build_metrics_for_validation_result(
            cls.resolved,
            cls.validation_result,
        )
        cls.default = cls.default_pipeline.metrics

    def test_registry_is_stable_complete_and_has_no_uncontrolled_thresholds(self) -> None:
        left = load_metric_registry()
        right = load_metric_registry()
        self.assertEqual(left.sha256, right.sha256)
        self.assertTrue(MANDATORY_KEYS <= set(left.definitions))
        self.assertEqual(
            {
                "physical", "temporal", "topology", "workflow", "policy", "anomaly",
                "evidence", "observer", "sampling", "privacy", "artifact", "performance",
            },
            {item.domain for item in left.definitions.values()},
        )
        raw = json.loads(
            (SRC_ROOT / "htgl_dataset_generator" / "metrics" / "metric_registry_v1.json").read_text(
                encoding="utf-8"
            )
        )
        raw["definitions"][0]["threshold"] = {
            "operator": "<=", "value": 0.5, "basis": "arbitrary", "source_id": "none"
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid_registry.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(MetricRegistryError, "arbitrary threshold basis"):
                load_metric_registry(path)

    def test_default_build_is_registry_complete_and_does_not_fake_external_evidence(self) -> None:
        validate_metrics_build(self.default)
        statuses = {item.metric_key: item.status for item in self.default.execution_records}
        self.assertEqual(set(statuses), set(self.default.registry.definitions))
        for key in (
            "deterministic_digest_match", "manifest_coverage",
            "generation_rows_per_second", "peak_resident_memory_bytes",
        ):
            self.assertEqual("not_executed", statuses[key])
        for key in (
            "meter_energy_wasserstein", "meter_energy_ks", "acf_error_l1",
            "load_factor_error", "peak_timing_distance", "exact_duplicate_rate",
            "nearest_neighbor_ratio", "membership_inference_auc",
            "attribute_inference_gain", "network_solver_convergence_rate",
            "cross_excitation_error", "mmpp_regime_occupancy_error",
        ):
            self.assertEqual("not_applicable", statuses[key], key)
        with self.assertRaisesRegex(
            MetricsEngineError,
            "publication-blocking metric status 'not_executed'",
        ):
            validate_metric_execution_for_publication(self.default)
        emitted = {str(row["metric_name"]) for row in self.default.run_metrics}
        self.assertFalse({"manifest_coverage", "deterministic_digest_match"} & emitted)
        self.assertEqual(len(self.default.run_metrics), len(self.default.provenance))
        self.assertTrue(all(item.scope_json and item.denominator_unit for item in self.default.provenance))
        self.assertTrue(all(item.uncertainty_reason for item in self.default.provenance))

    def test_controlled_physical_profile_rejects_calibrated_fidelity_input(self) -> None:
        through_sampling = self.validation_result.artifacts.through_sampling
        through_dag = (
            through_sampling.through_observers.through_anomalies.through_evidence
            .through_obligations.through_policy.through_dag
        )
        observations = tuple(
            PhysicalReferenceObservation(
                cohort_id=str(row["cohort_id"]),
                interval_start=str(row["interval_start"]),
                import_energy_kwh=float(row["import_energy_kwh"]),
                represented_meter_count=float(row["represented_meter_count"]),
            )
            for row in through_dag.physical.raw_meter_readings
        )
        physical_reference = PhysicalCalibrationReference(
            reference_id="CALIBRATION-TEST-REFERENCE-v1",
            source_label="calibrated_from_source",
            observations=observations,
            acf_lags=(1, 2, 4),
        )
        privacy_reference = PrivacySourceReference(
            reference_id="PRIVACY-COMPARISON-TEST-v1",
            source_label="calibrated_from_source",
            canonical_record_digests=("a" * 64,),
            comparable_released_record_digests=("a" * 64, "b" * 64),
        )
        row_count = sum(
            len(rows) for rows in self.validation_result.artifacts.prevalidation_table_records().values()
        )
        performance = PerformanceObservation(
            measurement_profile_id=self.resolved.validation.metric_threshold_profile_id,
            generated_row_count=row_count,
            elapsed_seconds=2.0,
            rows_per_second=row_count / 2.0,
            peak_memory_bytes=2_000_000,
            stored_bytes=4_000_000,
            bytes_per_row=4_000_000 / row_count,
            parallel_efficiency=1.0,
            deterministic_digest_equal=True,
        )
        with self.assertRaisesRegex(
            MetricsEngineError, "physical calibration reference is forbidden"
        ):
            build_metrics_for_validation_result(
                self.resolved,
                self.validation_result,
                physical_reference=physical_reference,
                privacy_reference=privacy_reference,
                performance_observation=performance,
            )

        build = build_metrics_for_validation_result(
            self.resolved,
            self.validation_result,
            privacy_reference=privacy_reference,
            performance_observation=performance,
        ).metrics
        values = _single_values(build)
        self.assertNotIn("meter_energy_wasserstein", values)
        self.assertNotIn("meter_energy_ks", values)
        self.assertNotIn("acf_error_l1", values)
        self.assertEqual(0.5, values["exact_duplicate_rate"])
        self.assertEqual(row_count / 2.0, values["generation_rows_per_second"])
        self.assertEqual(2_000_000.0, values["peak_resident_memory_bytes"])

    def test_weighted_distribution_primitives_use_weights(self) -> None:
        self.assertAlmostEqual(
            5.0,
            weighted_wasserstein_1d((0.0,), (1.0,), (5.0,), (10.0,)),
        )
        self.assertAlmostEqual(
            0.8,
            weighted_ks_2sample((0.0, 10.0), (9.0, 1.0), (0.0, 10.0), (1.0, 9.0)),
        )

    def test_replicate_aggregation_and_crn_pairing_are_deterministic(self) -> None:
        resolved = replace(
            self.resolved,
            run=replace(self.resolved.run, replicate_count=3),
            validation=replace(self.resolved.validation, repetition_count=3),
        )
        source_row = next(row for row in self.default.run_metrics if row["metric_name"] == "count_mean_ratio")
        source_provenance = next(
            item for item in self.default.provenance if item.metric_id == source_row["metric_id"]
        )
        baseline_builds = tuple(
            _one_metric_build(self.default, source_row, source_provenance, replicate_id, value)
            for replicate_id, value in enumerate((0.9, 1.0, 1.1))
        )
        treatment_builds = tuple(
            _one_metric_build(self.default, source_row, source_provenance, replicate_id, value)
            for replicate_id, value in enumerate((1.0, 1.2, 1.4))
        )
        first = aggregate_replicate_metrics(treatment_builds, resolved)
        second = aggregate_replicate_metrics(treatment_builds, resolved)
        self.assertEqual(first, second)
        self.assertEqual("estimated", first[0].uncertainty_status)
        self.assertAlmostEqual(1.2, first[0].mean_value)
        group = self.resolved.sampling.common_random_groups[0]
        baseline = MetricConditionSeries(
            "BASELINE-v1", "baseline", group,
            tuple(row for build in baseline_builds for row in build.run_metrics),
            tuple(item for build in baseline_builds for item in build.provenance),
        )
        treatment = MetricConditionSeries(
            "TREATMENT-v1", "treatment", group,
            tuple(row for build in treatment_builds for row in build.run_metrics),
            tuple(item for build in treatment_builds for item in build.provenance),
        )
        comparisons = build_paired_crn_comparisons(baseline, (treatment,), resolved)
        self.assertEqual(1, len(comparisons))
        self.assertEqual((0, 1, 2), comparisons[0].paired_replicate_ids)
        self.assertAlmostEqual(0.2, comparisons[0].mean_difference)
        self.assertIsNotNone(comparisons[0].standardized_effect_size)
        self.assertEqual(
            comparisons,
            build_paired_crn_comparisons(baseline, (treatment,), resolved),
        )

    def test_metrics_bundle_is_zstd_parquet_with_typed_sidecars(self) -> None:
        aggregates = aggregate_replicate_metrics((self.default,), self.resolved)
        with tempfile.TemporaryDirectory() as temporary:
            result = write_metrics_artifact_bundle(
                (self.default,), aggregates, (), temporary
            )
            self.assertEqual(
                {
                    "run_metric.parquet", "observation_provenance.parquet",
                    "metric_execution.parquet", "replicate_summary.parquet",
                    "baselines.parquet",
                },
                set(result.files),
            )
            import pyarrow.parquet as pq

            run_file = pq.ParquetFile(result.files["run_metric.parquet"])
            self.assertEqual(len(self.default.run_metrics), run_file.metadata.num_rows)
            run_file.close()
            summary_file = pq.ParquetFile(result.files["replicate_summary.parquet"])
            self.assertEqual(
                b"htgl.metrics.replicate-summary.v1",
                summary_file.schema_arrow.metadata[b"htgl.schema_id"],
            )
            summary_file.close()
            metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
            self.assertEqual("parquet_zstd", metadata["authoritative_storage"])
            self.assertFalse(metadata["json_authority"])


def _single_values(build: MetricsBuild) -> dict[str, float]:
    result: dict[str, float] = {}
    for row in build.run_metrics:
        key = str(row["metric_name"])
        if key not in result:
            result[key] = float(row["value"])
    return result


def _one_metric_build(
    source: MetricsBuild,
    row: dict[str, object],
    provenance: MetricObservationProvenance,
    replicate_id: int,
    value: float,
) -> MetricsBuild:
    metric_id = content_id(
        "test_metric",
        {"metric_key": row["metric_name"], "replicate_id": replicate_id, "value": value},
    )
    changed_row = dict(row)
    changed_row.update(metric_id=metric_id, replicate_id=replicate_id, value=value)
    changed_provenance = replace(
        provenance,
        metric_id=metric_id,
        replicate_id=replicate_id,
        replicate_set=(replicate_id,),
    )
    return MetricsBuild(
        run_metrics=(changed_row,),
        provenance=(changed_provenance,),
        execution_records=(),
        registry=source.registry,
    )


if __name__ == "__main__":
    unittest.main()
