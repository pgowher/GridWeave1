from __future__ import annotations

import copy
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
    orchestrate_pipeline_through_observers,
)
from htgl_dataset_generator.io import write_observer_view_bundle  # noqa: E402
from htgl_dataset_generator.observers import (  # noqa: E402
    ObserverProfileError,
    ObserverProjectionError,
    VisibilityLanguageError,
    evaluate_visibility_expression,
    load_observer_profile_bundle,
    scan_observer_releases,
    validate_observer_build,
)
from htgl_dataset_generator.policy.language import canonical_json  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402


PROFILE_IDS = (
    "OBS-FULL-EVALUATOR",
    "OBS-DSO-DIRECT",
    "OBS-AUDITOR-DELAYED",
    "OBS-PUBLIC-LOSSY",
    "OBS-ADVERSARIAL-OMISSION",
    "OBS-COLLUSION-UTILITY-AUDITOR",
)


class ObserverProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.resolved = resolve_config(
            load_config(REPO_ROOT / "configs" / "small_deterministic.json")
        )
        cls.result = orchestrate_pipeline_through_observers(cls.resolved)[0]
        cls.artifacts = cls.result.artifacts
        cls.build = cls.artifacts.observers
        cls.bundle = load_observer_profile_bundle(cls.resolved, contract=cls.contract)
        cls.dag = cls.artifacts.through_anomalies.through_evidence.through_obligations.through_policy.through_dag

    def test_profile_contract_and_safe_visibility_language_are_fail_closed(self) -> None:
        self.assertEqual(PROFILE_IDS, tuple(item.profile_id for item in self.bundle.profiles))
        self.assertEqual(
            {"full", "role_based", "delayed", "lossy", "adversarial_omission", "collusion"},
            {item.mode for item in self.bundle.profiles},
        )
        self.assertEqual(self.resolved.observer.profile_bundle_sha256, self.bundle.bundle_sha256)

        facts = {
            "anomaly.workflow_member": False,
            "event.actor_ids": ("actor-a",),
            "event.database_region": "REGION-A",
            "event.family": "audit",
            "event.id": "event-a",
            "event.source_region": "REGION-A",
            "event.type": "audit_opened",
            "event.workflow_type": "audit",
            "evidence.has_obligation": True,
            "evidence.receipt_count": 1,
            "evidence.types": ("digest",),
            "observer.class": "dso",
            "observer.id": "actor-b",
            "observer.jurisdiction": "JUR-A",
            "observer.region": "REGION-A",
            "observer.relationship_types_to_event_actors": (),
            "policy.is_violation": False,
        }
        inferred_rule = self.bundle.profile("OBS-DSO-DIRECT").visibility_rules[2]
        self.assertTrue(evaluate_visibility_expression(inferred_rule.condition, facts))
        with self.assertRaises(VisibilityLanguageError):
            evaluate_visibility_expression(
                {"op": "python_eval", "value": "__import__('os').system('whoami')"},
                facts,
            )
        with self.assertRaises(VisibilityLanguageError):
            evaluate_visibility_expression(
                {"op": "eq", "field": "truth.violation", "value": True},
                facts,
            )

    def test_profile_bundle_tampering_is_rejected_by_real_digest(self) -> None:
        raw = json.loads(
            (REPO_ROOT / "observers" / "observer_profiles_v1.json").read_text(
                encoding="utf-8"
            )
        )
        raw["loss_profiles"]["LOSS-PUBLIC-v1"]["probability"] = 0.21
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observer_profiles.json"
            path.write_text(canonical_json(raw), encoding="utf-8")
            with self.assertRaisesRegex(ObserverProfileError, "SHA-256"):
                load_observer_profile_bundle(
                    self.resolved, path, contract=self.contract
                )

    def test_canonical_rows_mappings_and_release_views_reconcile(self) -> None:
        event_count = len(self.dag.causal_dag.governance_events)
        self.assertEqual(event_count * len(PROFILE_IDS), len(self.build.observer_events))
        self.assertEqual(len(self.build.observer_events), len(self.build.source_mappings))
        for row in self.build.observer_events:
            validate_record(self.contract, "observer_event", row)
            self.assertEqual("evaluator_only", row["ground_truth_access_class"])

        visible_ids = {
            item.observer_record_id for item in self.build.source_mappings if item.visible
        }
        released_ids = {
            str(record["observer_record_id"])
            for view in self.build.release_views.values()
            for record in view.records
        }
        self.assertEqual(visible_ids, released_ids)
        self.assertTrue(self.build.leakage_diagnostics.passed)
        self.assertEqual(0, self.build.leakage_diagnostics.scanned_record_count - len(released_ids))
        release_text = canonical_json(
            {
                key: view.records
                for key, view in sorted(self.build.release_views.items())
            }
        )
        for mapping in self.build.source_mappings:
            self.assertNotIn(mapping.source_event_id, release_text)
            for pair_id in mapping.protected_pair_ids:
                self.assertNotIn(pair_id, release_text)

    def test_visibility_omission_collusion_and_task_metrics_are_recomputed(self) -> None:
        classes = {str(row["visibility_class"]) for row in self.build.observer_events}
        self.assertTrue({"direct", "shared", "redacted", "delayed", "omitted"} <= classes)
        self.assertTrue(self.build.omission_diagnostics.passed)
        self.assertTrue(all(item.matches for item in self.build.omission_truth))
        self.assertFalse([item for item in self.build.task_results if item.status == "fail"])

        diagnostics = self.build.diagnostics
        full = diagnostics["OBS-FULL-EVALUATOR"]
        self.assertEqual(1.0, full.weighted_visible_event_coverage)
        self.assertEqual(1.0, full.visible_edge_coverage)
        self.assertGreaterEqual(full.evidence_recoverability, 0.9)
        self.assertGreater(diagnostics["OBS-PUBLIC-LOSSY"].transport_loss_rate, 0.0)
        self.assertGreater(
            diagnostics["OBS-ADVERSARIAL-OMISSION"].adversarial_omission_rate,
            0.0,
        )
        collusion = diagnostics["OBS-COLLUSION-UTILITY-AUDITOR"]
        self.assertGreaterEqual(collusion.collusion_gain, 0.0)

        visible_by_profile = {
            profile_id: {
                item.source_event_id
                for item in self.build.source_mappings
                if item.projection_profile_id == profile_id and item.visible
            }
            for profile_id in PROFILE_IDS
        }
        self.assertEqual(
            visible_by_profile["OBS-DSO-DIRECT"]
            | visible_by_profile["OBS-AUDITOR-DELAYED"],
            visible_by_profile["OBS-COLLUSION-UTILITY-AUDITOR"],
        )
        metric_names = {str(row["metric_name"]) for row in self.build.run_metrics}
        for suffix in (
            "visible_event_coverage",
            "visible_edge_coverage",
            "evidence_recoverability",
            "mean_delay_seconds",
            "omission_rate",
            "collusion_gain",
            "sealed_truth_leakage",
            "task_sufficiency_rate",
        ):
            self.assertIn(f"observer.OBS-FULL-EVALUATOR.{suffix}", metric_names)

    def test_leakage_scanner_detects_fields_values_pairs_and_probabilities(self) -> None:
        profile_id = "OBS-PUBLIC-LOSSY"
        view = self.build.release_views[profile_id]
        injected = copy.deepcopy(view.records[0])
        protected_id = self.build.source_mappings[0].source_event_id
        pair_id = "6a8bf5ba-f4bd-5fb7-970f-f4b9d77a1fb8"
        injected["payload"]["source_event_id"] = protected_id
        injected["payload"]["protected_pair_id"] = pair_id
        injected["payload"]["first_order_inclusion_probability"] = 0.5
        injected["payload"]["is_violation"] = "sealed-violation-value"
        views = dict(self.build.release_views)
        views[profile_id] = replace(view, records=(injected,))
        diagnostics = scan_observer_releases(
            views,
            bundle=self.bundle,
            exact_protected_identifiers=(protected_id,),
            pair_identifiers=(pair_id,),
            sealed_truth_values=("sealed-violation-value",),
        )
        self.assertFalse(diagnostics.passed)
        self.assertGreater(diagnostics.exact_identifier_leakage_count, 0)
        self.assertGreater(diagnostics.pair_identifier_leakage_count, 0)
        self.assertGreater(diagnostics.inclusion_probability_leakage_count, 0)
        self.assertGreater(diagnostics.sealed_truth_leakage_count, 0)

    def test_mutated_projection_fails_digest_validation(self) -> None:
        rows = list(self.build.observer_events)
        index = next(
            index
            for index, row in enumerate(rows)
            if row["projection_profile_id"] == "OBS-PUBLIC-LOSSY"
            and row["visibility_class"] != "omitted"
        )
        rows[index] = dict(rows[index], visibility_class="direct")
        mutated = replace(self.build, observer_events=tuple(rows))
        with self.assertRaisesRegex(ObserverProjectionError, "projection digest"):
            validate_observer_build(
                mutated,
                self.resolved,
                world=self.dag.world,
                causal_dag=self.dag.causal_dag,
                bundle=self.bundle,
                scenario_ids=self.resolved.run.selected_scenario_ids,
                contract=self.contract,
            )

    def test_worker_count_does_not_change_observer_truth_or_release_values(self) -> None:
        parallel = orchestrate_pipeline_through_observers(
            self.resolved, worker_count=3
        )[0]
        self.assertEqual(self.result.table_digests, parallel.table_digests)
        left = canonical_json(
            [asdict(item) for item in self.build.source_mappings]
        )
        right = canonical_json(
            [asdict(item) for item in parallel.artifacts.observers.source_mappings]
        )
        self.assertEqual(left, right)
        self.assertEqual(
            canonical_json(
                {
                    key: value.records
                    for key, value in sorted(self.build.release_views.items())
                }
            ),
            canonical_json(
                {
                    key: value.records
                    for key, value in sorted(
                        parallel.artifacts.observers.release_views.items()
                    )
                }
            ),
        )

    def test_writer_separates_protected_truth_and_uses_zstd_parquet(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as temporary:
            result = write_observer_view_bundle(self.build, Path(temporary) / "first")
            repeated = write_observer_view_bundle(
                self.build, Path(temporary) / "second"
            )
            self.assertEqual(result.manifest_sha256, repeated.manifest_sha256)
            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual("parquet_zstd", manifest["authoritative_storage"])
            self.assertFalse(manifest["json_authority"])
            self.assertEqual("evaluator_only", manifest["evaluator_mapping_access_class"])
            public_path = (
                result.root
                / "profiles"
                / "OBS-PUBLIC-LOSSY"
                / "observer_release.parquet"
            )
            public = pq.read_table(public_path)
            self.assertFalse(
                {
                    "source_event_id",
                    "actor_id",
                    "anomaly_instance_id",
                    "protected_pair_id",
                    "first_order_inclusion_probability",
                }
                & set(public.column_names)
            )
            parquet_file = pq.ParquetFile(public_path)
            self.assertEqual(
                "ZSTD",
                parquet_file.metadata.row_group(0).column(0).compression,
            )
            parquet_file.close()
            protected = pq.read_table(
                result.root
                / "evaluator_only"
                / "projection_source_mapping.parquet"
            )
            self.assertIn("source_event_id", protected.column_names)
            manifest_text = result.manifest_path.read_text(encoding="utf-8")
            self.assertNotIn(self.build.source_mappings[0].source_event_id, manifest_text)


if __name__ == "__main__":
    unittest.main()
