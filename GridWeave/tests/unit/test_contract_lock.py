from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.schemas import (  # noqa: E402
    SchemaValidationError,
    build_model_classes,
    compute_table_fingerprint,
    export_arrow_schema,
    load_contract,
    load_golden_fixture,
    validate_golden_fixture,
    validate_record,
)


EXPECTED_TABLES = (
    "run_scenario",
    "seed_stream",
    "actor",
    "actor_relationship",
    "prosumer_cohort",
    "network_area",
    "local_database",
    "data_object",
    "data_object_replica",
    "raw_meter_reading",
    "raw_der_telemetry",
    "raw_network_state",
    "raw_context_event",
    "arrival",
    "governance_event",
    "event_edge",
    "workflow_instance",
    "policy_rule",
    "policy_decision_truth",
    "anomaly_instance",
    "evidence_obligation",
    "evidence_receipt",
    "observer_event",
    "sampling_design",
    "sample_membership",
    "validation_issue",
    "run_metric",
    "artifact_manifest",
)


class ContractLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract()
        cls.fixture = load_golden_fixture()

    def test_all_target_schemas_resolve_with_stable_ids(self) -> None:
        self.assertEqual(EXPECTED_TABLES, self.contract.table_names)
        self.assertRegex(self.contract.contract_fingerprint, r"^[0-9a-f]{64}$")
        for table in self.contract.tables:
            self.assertEqual(
                f"htgl.dataset.v1.{table.table_name}",
                table.schema_id,
            )
            self.assertEqual(table.schema_fingerprint, compute_table_fingerprint(table))
            self.assertRegex(table.schema_fingerprint, r"^[0-9a-f]{64}$")
            self.assertTrue(table.fields, table.table_name)

    def test_arrow_schema_json_files_match_contract(self) -> None:
        arrow_dir = REPO_ROOT / "schemas" / "arrow"
        for table in self.contract.tables:
            expected = export_arrow_schema(table)
            path = arrow_dir / f"{table.table_name}.arrow.json"
            self.assertTrue(path.exists(), path)
            observed = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(expected, observed)

    def test_generated_models_and_golden_fixture_validate(self) -> None:
        validate_golden_fixture(self.contract, self.fixture)
        models = build_model_classes(self.contract)
        self.assertEqual(set(EXPECTED_TABLES), set(models))
        for table_name, rows in self.fixture.items():
            model = models[table_name]
            for row in rows:
                instance = model(**row)
                self.assertEqual(getattr(instance, "table_name", None), None)
                self.assertEqual(getattr(instance, "_table_name"), table_name)

    def test_missing_column_fails_closed(self) -> None:
        row = dict(self.fixture["run_scenario"][0])
        row.pop("run_id")
        with self.assertRaisesRegex(SchemaValidationError, "missing required columns"):
            validate_record(self.contract, "run_scenario", row)

    def test_non_nullable_null_fails_closed(self) -> None:
        row = dict(self.fixture["run_scenario"][0])
        row["run_id"] = None
        with self.assertRaisesRegex(SchemaValidationError, "null is not allowed"):
            validate_record(self.contract, "run_scenario", row)

    def test_unknown_dictionary_value_fails_closed(self) -> None:
        row = dict(self.fixture["actor"][0])
        row["actor_class"] = "unregistered_actor_class"
        with self.assertRaisesRegex(SchemaValidationError, "not in dictionary actor_class"):
            validate_record(self.contract, "actor", row)

    def test_physical_backend_dictionary_is_controlled_only(self) -> None:
        self.assertEqual(
            (
                "procedural",
                "opensynth_style_synthetic",
                "smart_ds_style_synthetic",
            ),
            self.contract.dictionary_values("physical_backend"),
        )
        row = dict(self.fixture["raw_meter_reading"][0])
        row["generation_backend"] = "opensynth_faraday"
        with self.assertRaisesRegex(
            SchemaValidationError, "not in dictionary physical_backend"
        ):
            validate_record(self.contract, "raw_meter_reading", row)

    def test_unstable_schema_fingerprint_fails_closed(self) -> None:
        source = json.loads((REPO_ROOT / "schemas" / "htgl_contract_v1.json").read_text(encoding="utf-8"))
        source["tables"][0]["fields"][0]["logical_type"] = "large_string"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered_contract.json"
            path.write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SchemaValidationError, "schema fingerprint"):
                load_contract(path)

    def test_golden_fixture_coverage_rules_fail_closed(self) -> None:
        fixture = json.loads(json.dumps(self.fixture))
        fixture["event_edge"] = []
        with self.assertRaisesRegex(SchemaValidationError, "missing non-empty event_edge"):
            validate_golden_fixture(self.contract, fixture)


if __name__ == "__main__":
    unittest.main()
