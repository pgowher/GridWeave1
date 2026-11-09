from __future__ import annotations

import copy
from datetime import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.anomalies import (  # noqa: E402
    AnomalyRegistryError,
    load_anomaly_contract,
    outcome_by_id,
)
from htgl_dataset_generator.baselines import (  # noqa: E402
    RANDOM_FIELD_PROFILE,
    RANDOM_TRANSITION_PROFILE,
)
from htgl_dataset_generator.config import load_config, resolve_config  # noqa: E402
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_anomalies  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.policy.language import canonical_json  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402


ANOMALY_TYPES = (
    "unauthorized_purpose",
    "missing_erasure_propagation",
    "premature_deletion",
    "false_confirmation",
    "causal_orphan",
    "observer_omission",
    "cross_region_rule_breach",
    "clock_replay_conflict",
)
WORKFLOW_TYPES = (
    "consent",
    "collection_processing",
    "disclosure",
    "access",
    "correction",
    "retention",
    "erasure",
    "audit",
    "operational",
    "incident",
)


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class MinimalCounterfactualAnomalyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["workflows"]["families"]["value"] = list(WORKFLOW_TYPES)
        raw["arrivals"]["base_rates_per_day"]["value"] = {
            name: 0.01 for name in WORKFLOW_TYPES
        }
        raw["arrivals"]["conditioned_total"]["value"] = 100
        raw["claim_scale"]["materialized_row_target"]["value"] = 100
        raw["evidence"]["honest_rate"]["value"] = 1.0
        raw["evidence"]["adversarial_rate"]["value"] = 0.0
        raw["anomaly"]["types"]["value"] = list(ANOMALY_TYPES)
        raw["anomaly"]["prevalence"]["value"] = {name: 0.005 for name in ANOMALY_TYPES}
        cls.resolved = resolve_config(raw)
        cls.result = orchestrate_pipeline_through_anomalies(cls.resolved)[0]
        cls.build = cls.result.artifacts.anomalies
        cls.pairs = {pair.anomaly_type: pair for pair in cls.build.counterfactual_pairs}

    def test_all_eight_targets_are_accepted_once_with_exact_quality_gates(self) -> None:
        self.assertEqual(set(ANOMALY_TYPES), set(self.pairs))
        self.assertEqual(8, len(self.build.anomaly_instances))
        diagnostics = self.build.diagnostics["SCN-SMALL-DETERMINISTIC"]
        self.assertEqual(1.0, diagnostics.target_violation_success_rate)
        self.assertEqual(0.0, diagnostics.protected_collateral_violation_rate)
        self.assertEqual(1.0, diagnostics.mean_edit_cost)
        self.assertEqual({name: 1 for name in sorted(ANOMALY_TYPES)}, diagnostics.anomaly_type_counts)
        for pair in self.pairs.values():
            valid = outcome_by_id(pair.valid_invariant_outcomes)
            invalid = outcome_by_id(pair.invalid_invariant_outcomes)
            self.assertEqual("pass", valid[pair.target_invariant_id].status)
            self.assertEqual("fail", invalid[pair.target_invariant_id].status)
            self.assertFalse(
                [name for name in pair.preserved_invariant_ids if invalid[name].status == "fail"]
            )
            self.assertTrue(pair.search_diagnostics.minimality_proven_within_bound)
            self.assertEqual(1, pair.edit.cost)
            self.assertGreater(pair.selection_probability, 0.0)
            self.assertAlmostEqual(1.0 / pair.selection_probability, pair.analysis_weight)

    def test_each_edit_has_the_declared_minimal_primitive_semantics(self) -> None:
        pair = self.pairs["unauthorized_purpose"]
        self.assertEqual(pair.valid_trace.events.__len__(), pair.invalid_trace.events.__len__())
        event_id = pair.edit.parameter("event_id")
        invalid_event = next(row for row in pair.invalid_trace.events if row["event_id"] == event_id)
        self.assertEqual("PURPOSE-COUNTERFACTUAL-UNAUTHORIZED-v1", invalid_event["policy_purpose_id"])

        pair = self.pairs["missing_erasure_propagation"]
        self.assertEqual(len(pair.valid_trace.receipts) - 1, len(pair.invalid_trace.receipts))
        self.assertNotIn(pair.edit.parameter("receipt_id"), {row["receipt_id"] for row in pair.invalid_trace.receipts})

        pair = self.pairs["premature_deletion"]
        replica = next(
            row for row in pair.invalid_trace.replicas
            if row["replica_id"] == pair.edit.parameter("replica_id")
        )
        self.assertEqual("deleted", replica["deletion_status"])
        self.assertLess(_timestamp(replica["deleted_at"]), _timestamp(replica["deletion_due_at"]))

        pair = self.pairs["false_confirmation"]
        self.assertEqual(pair.valid_trace.receipts, pair.invalid_trace.receipts)
        self.assertEqual("incomplete", pair.invalid_trace.replica_action_status[pair.edit.parameter("replica_id")])

        pair = self.pairs["causal_orphan"]
        self.assertEqual(len(pair.valid_trace.edges) - 1, len(pair.invalid_trace.edges))
        self.assertNotIn(pair.edit.parameter("edge_id"), {row["edge_id"] for row in pair.invalid_trace.edges})

        pair = self.pairs["observer_omission"]
        self.assertEqual(pair.valid_trace.events, pair.invalid_trace.events)
        self.assertEqual(pair.valid_trace.receipts, pair.invalid_trace.receipts)
        self.assertNotIn(pair.edit.parameter("receipt_id"), pair.invalid_trace.observer_visible_receipt_ids)

        pair = self.pairs["cross_region_rule_breach"]
        evaluation = pair.invalid_trace.policy_evaluations[pair.edit.parameter("event_id")]
        self.assertTrue(evaluation["is_cross_region"])
        self.assertEqual("cross_region_rule_breach", evaluation["violation_type"])

        pair = self.pairs["clock_replay_conflict"]
        self.assertEqual(
            [(row["event_id"], row["timestamp"]) for row in pair.valid_trace.events],
            [(row["event_id"], row["timestamp"]) for row in pair.invalid_trace.events],
        )
        parent = next(row for row in pair.invalid_trace.events if row["event_id"] == pair.edit.parameter("parent_event_id"))
        child = next(row for row in pair.invalid_trace.events if row["event_id"] == pair.edit.parameter("child_event_id"))
        self.assertLess(_timestamp(child["recorded_timestamp"]), _timestamp(parent["recorded_timestamp"] or parent["timestamp"]))

    def test_rows_are_schema_valid_and_pair_keys_never_leak(self) -> None:
        pair_ids = {pair.protected_pair_id for pair in self.build.counterfactual_pairs}
        for row in self.build.anomaly_instances:
            validate_record(self.contract, "anomaly_instance", row)
            serialized = canonical_json(row)
            self.assertFalse(any(pair_id in serialized for pair_id in pair_ids))
            self.assertNotIn("protected_pair", serialized)
            self.assertEqual(
                list(self.pairs[row["anomaly_type"]].edit.primitive_changed_field_paths),
                row["changed_field_paths"],
            )

    def test_baselines_are_deterministic_separate_controls_not_anomaly_truth(self) -> None:
        baselines = self.result.artifacts.anomaly_baselines
        self.assertEqual(
            {RANDOM_FIELD_PROFILE: 1, RANDOM_TRANSITION_PROFILE: 1},
            baselines.profile_counts,
        )
        self.assertEqual({}, baselines.table_records())
        transition = next(case for case in baselines.cases if case.profile_id == RANDOM_TRANSITION_PROFILE)
        self.assertIn("INV-WORKFLOW-TRANSITION-LEGAL", transition.failed_invariant_ids)
        anomaly_ids = {row["anomaly_instance_id"] for row in self.build.anomaly_instances}
        self.assertFalse(any(case.source_trace_digest in anomaly_ids for case in baselines.cases))

    def test_anomaly_table_writes_as_zstd_parquet(self) -> None:
        import pyarrow.parquet as pq

        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(
                {"anomaly_instance": self.build.anomaly_instances},
                Path(tmp),
            )
            table = pq.read_table(written["anomaly_instance"])
            self.assertEqual(8, table.num_rows)
            self.assertEqual(b"htgl.dataset.v1.anomaly_instance", table.schema.metadata[b"schema_id"])
            self.assertEqual(
                "ZSTD",
                pq.ParquetFile(written["anomaly_instance"]).metadata.row_group(0).column(0).compression,
            )

    def test_pipeline_is_repeatable_and_authoritative_digest_is_stable(self) -> None:
        repeated = orchestrate_pipeline_through_anomalies(self.resolved, worker_count=2)[0]
        self.assertEqual(self.result.table_digests, repeated.table_digests)
        self.assertEqual(
            [pair.protected_pair_id for pair in self.build.counterfactual_pairs],
            [pair.protected_pair_id for pair in repeated.artifacts.anomalies.counterfactual_pairs],
        )
        self.assertEqual(
            self.result.artifacts.anomaly_baselines.cases,
            repeated.artifacts.anomaly_baselines.cases,
        )

    def test_digest_tampering_and_unbounded_grammar_fail_closed(self) -> None:
        grammar_path = REPO_ROOT / "anomalies" / "edit_grammar_v1.json"
        raw = json.loads(grammar_path.read_text(encoding="utf-8"))
        raw["rules"][0]["primitive_edit_cost"] = self.resolved.anomaly.search_bound + 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(AnomalyRegistryError, "SHA-256"):
                load_anomaly_contract(self.resolved, grammar_path=path, contract=self.contract)


if __name__ == "__main__":
    unittest.main()
