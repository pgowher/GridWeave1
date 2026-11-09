from __future__ import annotations

from dataclasses import replace
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.baselines.registry import (  # noqa: E402
    REQUIRED_PROFILE_IDS,
    BaselineRegistryError,
    load_baseline_registry,
)
from htgl_dataset_generator.baselines.study import (  # noqa: E402
    build_baseline_paired_comparisons,
    build_baseline_study,
)
from htgl_dataset_generator.config import ResolvedRunPlan, resolve_config_file  # noqa: E402
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_metrics  # noqa: E402
from htgl_dataset_generator.io import write_baseline_artifact_bundle  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import seed_stream_records_for_plan  # noqa: E402


class BaselineStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(
            REPO_ROOT / "configs" / "small_deterministic.json"
        )
        cls.run_group = orchestrate_pipeline_through_metrics(cls.resolved)
        cls.study = build_baseline_study(cls.resolved, cls.run_group.replicates)

    def metric(self, profile_id: str, metric_name: str) -> float:
        matches = [
            item.value
            for item in self.study.metrics
            if item.profile_id == profile_id and item.metric_name == metric_name
        ]
        self.assertEqual(1, len(matches))
        return matches[0]

    def test_registry_is_complete_digest_pinned_and_fails_on_removed_profile(self) -> None:
        registry = load_baseline_registry()
        self.assertEqual(REQUIRED_PROFILE_IDS, frozenset(registry.profiles))
        self.assertRegex(registry.sha256, r"^[0-9a-f]{64}$")
        raw = json.loads(
            (SRC_ROOT / "htgl_dataset_generator" / "baselines" / "baseline_profiles_v1.json")
            .read_text(encoding="utf-8")
        )
        raw["profiles"] = raw["profiles"][:-1]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(BaselineRegistryError, "profile inventory mismatch"):
                load_baseline_registry(path)

    def test_every_profile_executes_with_metrics_crn_and_n_n_q_discipline(self) -> None:
        self.assertEqual(len(REQUIRED_PROFILE_IDS), len(self.study.conditions))
        self.assertTrue(self.study.metrics)
        self.assertTrue(self.study.comparisons)
        component_by_family = {
            "temporal": "S05.arrivals",
            "structure": "P8.baselines",
            "anomaly": "S08.counterfactuals",
            "observer": "S11.projections",
            "sampling": "S12.sampling",
        }
        for condition in self.study.conditions:
            self.assertEqual(self.resolved.claim_scale.represented_population, condition.represented_population)
            self.assertEqual(self.resolved.claim_scale.materialized_row_target, condition.materialized_row_budget)
            self.assertIsNone(condition.executed_operation_count)
            self.assertIn(
                f"component={component_by_family[condition.family]}",
                condition.seed_stream_name,
            )
            self.assertIn("crn=SMALL-DETERMINISTIC-CRN", condition.seed_stream_name)
            self.assertRegex(condition.output_digest, r"^[0-9a-f]{64}$")
        plan = self.run_group.replicates[0].run_plan
        streams = seed_stream_records_for_plan(self.resolved, plan)
        self.assertTrue(
            any(
                "crn=SMALL-DETERMINISTIC-CRN" in str(row["stream_name"])
                and "component=P8.baselines" in str(row["stream_name"])
                for row in streams
            )
        )

    def test_temporal_controls_are_named_honestly_and_emit_model_truth(self) -> None:
        scenario_id = self.resolved.run.scenario_id
        negative = self.study.condition(
            "NEGATIVE-CONTROL-ROUNDED-GAUSSIAN-UNIFORM-BIN-v1", scenario_id, 0
        )
        self.assertFalse(negative.claim_eligible)
        self.assertIn("not exact Poisson or NHPP", negative.exclusion_reason)
        exact = self.study.condition("BASELINE-EXACT-INDEPENDENT-NHPP-v1", scenario_id, 0)
        mmpp = self.study.condition("BASELINE-MMPP-2STATE-v1", scenario_id, 0)
        hawkes = self.study.condition("BASELINE-HAWKES-EXPONENTIAL-v1", scenario_id, 0)
        self.assertGreater(exact.output_record_count, 0)
        self.assertGreater(json.loads(mmpp.diagnostics_json)["regime_event_count"], 0)
        self.assertGreater(json.loads(hawkes.diagnostics_json)["parented_event_count"], 0)

    def test_structure_controls_are_schema_valid_and_ablate_one_layer(self) -> None:
        contract = load_contract()
        iid_samples = [
            json.loads(item.record_json)
            for item in self.study.output_samples
            if item.profile_id == "BASELINE-UNIFORM-IID-RECORD-v1"
        ]
        self.assertTrue(iid_samples)
        for row in iid_samples:
            validate_record(contract, "governance_event", row)
        checks = {
            "ABLATION-NO-CUSTODY-v1": "custody_reference_coverage",
            "ABLATION-NO-CAUSAL-CLOSURE-v1": "causal_edge_coverage",
            "ABLATION-NO-TOPOLOGY-v1": "topology_reference_coverage",
            "ABLATION-NO-POLICY-v1": "policy_trace_coverage",
            "ABLATION-NO-EVIDENCE-v1": "evidence_obligation_coverage",
        }
        for profile_id, metric_name in checks.items():
            self.assertEqual(0.0, self.metric(profile_id, metric_name))
            self.assertGreater(
                self.metric("PROPOSED-GOVERNANCE-COMPLETE-STRUCTURE-v1", metric_name),
                0.0,
            )

    def test_anomaly_observer_and_sampling_controls_keep_truth_boundaries(self) -> None:
        proposed = self.study.condition(
            "PROPOSED-MINIMAL-COUNTERFACTUAL-v1", self.resolved.run.scenario_id, 0
        )
        self.assertGreater(proposed.output_record_count, 0)
        self.assertEqual(1.0, self.metric("PROPOSED-MINIMAL-COUNTERFACTUAL-v1", "target_violation_success"))
        self.assertEqual(0.0, self.metric("PROPOSED-MINIMAL-COUNTERFACTUAL-v1", "collateral_violation_rate"))
        serialized_samples = "\n".join(item.record_json for item in self.study.output_samples)
        self.assertNotIn("protected_pair_id", serialized_samples)
        self.assertTrue(all(item.evaluator_only for item in self.study.output_samples))
        for profile_id in (
            "BASELINE-FIRST-N-TRUNCATION",
            "BASELINE-SIMPLE-RANDOM-EVENT-ROWS",
            "BASELINE-UNWEIGHTED-WORKFLOW",
            "ABLATION-NO-SAMPLING-WEIGHTS-v1",
        ):
            condition = self.study.condition(profile_id, self.resolved.run.scenario_id, 0)
            self.assertFalse(condition.claim_eligible)
            raw_error = next(
                item
                for item in self.study.metrics
                if item.profile_id == profile_id and item.metric_name == "raw_relative_error"
            )
            self.assertEqual(
                "known_total_diagnostic_not_population_estimate_v1",
                raw_error.estimator,
            )

    def test_study_and_parquet_outputs_are_deterministic_and_zstd(self) -> None:
        import pyarrow.parquet as pq

        repeated = build_baseline_study(self.resolved, self.run_group.replicates)
        self.assertEqual(self.study.conditions, repeated.conditions)
        self.assertEqual(self.study.metrics, repeated.metrics)
        self.assertEqual(self.study.comparisons, repeated.comparisons)
        with tempfile.TemporaryDirectory() as temporary:
            written = write_baseline_artifact_bundle(self.study, temporary)
            self.assertEqual(6, len(written.files))
            for relative, path in written.files.items():
                if path.suffix != ".parquet":
                    continue
                parquet = pq.ParquetFile(path)
                try:
                    self.assertGreater(parquet.metadata.num_rows, 0, relative)
                    self.assertEqual(b"ZSTD", parquet.schema_arrow.metadata[b"htgl.compression"])
                    for group_index in range(parquet.metadata.num_row_groups):
                        group = parquet.metadata.row_group(group_index)
                        for column_index in range(group.num_columns):
                            self.assertEqual("ZSTD", group.column(column_index).compression)
                finally:
                    parquet.close()

    def test_paired_uncertainty_requires_and_uses_independent_replicates(self) -> None:
        run = replace(self.resolved.run, replicate_count=3)
        validation = replace(self.resolved.validation, repetition_count=3)
        resolved = replace(self.resolved, run=run, validation=validation)
        metrics = []
        for replicate_id in range(3):
            for item in self.study.metrics:
                profile_shift = (sum(item.profile_id.encode("ascii")) % 5) * 0.01
                metrics.append(
                    replace(
                        item,
                        metric_observation_id=f"{item.metric_observation_id}-{replicate_id}",
                        replicate_id=replicate_id,
                        value=item.value + replicate_id * profile_shift,
                    )
                )
        results = tuple(
            SimpleNamespace(
                run_plan=ResolvedRunPlan(
                    run_id=resolved.run.run_id,
                    scenario_id=resolved.run.scenario_id,
                    replicate_id=replicate_id,
                    config_sha256=resolved.config_sha256,
                )
            )
            for replicate_id in range(3)
        )
        comparisons = build_baseline_paired_comparisons(resolved, metrics, results)
        self.assertEqual(len(self.study.comparisons), len(comparisons))
        self.assertTrue(all(item.status == "estimated" for item in comparisons))
        self.assertTrue(all(item.pair_count == 3 for item in comparisons))
        self.assertTrue(all(item.ci_lower is not None and item.ci_upper is not None for item in comparisons))


if __name__ == "__main__":
    unittest.main()
