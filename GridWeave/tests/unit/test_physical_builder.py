from __future__ import annotations

from dataclasses import asdict
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import resolve_config_file  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.physical import (  # noqa: E402
    EXTERNAL_SOLVER_EXECUTION_SUPPORTED,
    PhysicalRawBuild,
    PhysicalValidationError,
    build_physical_raw,
    validate_physical_raw,
)
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.world import build_federated_world  # noqa: E402


class PhysicalBuilderTests(unittest.TestCase):
    def test_reference_scenario_passes_two_backend_modes(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)

        for backend_mode in ("procedural", "opensynth_style_synthetic"):
            with self.subTest(backend_mode=backend_mode):
                physical = build_physical_raw(
                    resolved,
                    world=world,
                    backend_mode=backend_mode,
                    contract=contract,
                )
                diagnostics = physical.diagnostics["SCN-REFERENCE-10K"]
                self.assertEqual(10_000.0, diagnostics.represented_meter_total)
                self.assertEqual(0, diagnostics.validation_issue_count)
                self.assertGreater(diagnostics.min_meter_autocorrelation, 0.20)
                self.assertGreater(diagnostics.trigger_count, 0)
                for table_name, rows in physical.table_records().items():
                    self.assertGreater(len(rows), 0, table_name)
                    for row in rows:
                        validate_record(contract, table_name, row)

    def test_smart_ds_style_synthetic_emits_controlled_topology(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        world = build_federated_world(resolved)
        procedural = build_physical_raw(resolved, world=world, backend_mode="procedural")
        smart_ds_style = build_physical_raw(
            resolved, world=world, backend_mode="smart_ds_style_synthetic"
        )

        self.assertGreater(
            len(smart_ds_style.network_topology), len(procedural.network_topology)
        )
        self.assertGreater(
            len(smart_ds_style.raw_network_states), len(procedural.raw_network_states)
        )
        self.assertTrue(
            any(
                element.element_class == "switch"
                for element in smart_ds_style.network_topology
            )
        )
        self.assertTrue(
            all(
                row["generation_source"] == "controlled_synthetic"
                for row in smart_ds_style.raw_context_events
            )
        )

    def test_physical_outputs_have_typed_governance_trigger_references(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)
        context_ids = {row["context_event_id"] for row in physical.raw_context_events}
        trigger_source_ids = {trigger.source_id for trigger in physical.governance_triggers}
        event_families = set(contract.dictionary_values("event_family"))

        self.assertGreater(len(physical.governance_triggers), 0)
        self.assertTrue(any(row["trigger_event_id"] in context_ids for row in physical.raw_der_telemetry))
        self.assertTrue(trigger_source_ids.issubset(context_ids | {row["network_state_id"] for row in physical.raw_network_states}))
        for trigger in physical.governance_triggers:
            self.assertIn(trigger.event_family, event_families)
            self.assertIn(trigger.source_table, {"raw_context_event", "raw_network_state"})

    def test_physical_generation_is_deterministic(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        world = build_federated_world(resolved)
        first = build_physical_raw(
            resolved, world=world, backend_mode="opensynth_style_synthetic"
        )
        second = build_physical_raw(
            resolved, world=world, backend_mode="opensynth_style_synthetic"
        )

        self.assertEqual(
            canonical_records_digest(first.raw_meter_readings),
            canonical_records_digest(second.raw_meter_readings),
        )
        self.assertEqual(
            canonical_records_digest(first.raw_der_telemetry),
            canonical_records_digest(second.raw_der_telemetry),
        )
        self.assertEqual(
            canonical_records_digest(first.raw_network_states),
            canonical_records_digest(second.raw_network_states),
        )
        self.assertEqual(
            canonical_records_digest(first.raw_context_events),
            canonical_records_digest(second.raw_context_events),
        )
        self.assertEqual(
            canonical_records_digest(asdict(trigger) for trigger in first.governance_triggers),
            canonical_records_digest(asdict(trigger) for trigger in second.governance_triggers),
        )

    def test_external_backend_and_solver_execution_are_explicitly_deferred(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)

        self.assertFalse(EXTERNAL_SOLVER_EXECUTION_SUPPORTED)
        with self.assertRaisesRegex(
            PhysicalValidationError, "external physical backend.*deferred"
        ):
            build_physical_raw(
                resolved, world=world, backend_mode="opensynth_faraday"
            )

    def test_negative_meter_energy_fails_closed(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        physical = build_physical_raw(resolved, world=world)
        rows = [dict(row) for row in physical.raw_meter_readings]
        rows[0]["import_energy_kwh"] = -0.01
        broken = PhysicalRawBuild(
            network_topology=physical.network_topology,
            raw_meter_readings=tuple(rows),
            raw_der_telemetry=physical.raw_der_telemetry,
            raw_network_states=physical.raw_network_states,
            raw_context_events=physical.raw_context_events,
            physical_violations=physical.physical_violations,
            governance_triggers=physical.governance_triggers,
            diagnostics=physical.diagnostics,
        )

        with self.assertRaisesRegex(PhysicalValidationError, "import/export"):
            validate_physical_raw(broken, resolved, world=world)

    def test_der_state_of_charge_fails_closed(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        physical = build_physical_raw(resolved, world=world)
        rows = [dict(row) for row in physical.raw_der_telemetry]
        rows[0]["state_of_charge"] = 1.25
        broken = PhysicalRawBuild(
            network_topology=physical.network_topology,
            raw_meter_readings=physical.raw_meter_readings,
            raw_der_telemetry=tuple(rows),
            raw_network_states=physical.raw_network_states,
            raw_context_events=physical.raw_context_events,
            physical_violations=physical.physical_violations,
            governance_triggers=physical.governance_triggers,
            diagnostics=physical.diagnostics,
        )

        with self.assertRaisesRegex(PhysicalValidationError, "state_of_charge"):
            validate_physical_raw(broken, resolved, world=world)

    def test_physical_raw_tables_write_to_parquet(self) -> None:
        import pyarrow.parquet as pq

        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        physical = build_physical_raw(resolved, world=world, backend_mode="procedural")
        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(physical.table_records(), Path(tmp))
            self.assertEqual(set(physical.table_records()), set(written))
            for table_name, path in written.items():
                observed = pq.read_table(path)
                self.assertEqual(len(physical.table_records()[table_name]), observed.num_rows, table_name)
                self.assertEqual(
                    f"htgl.dataset.v1.{table_name}".encode("utf-8"),
                    observed.schema.metadata[b"schema_id"],
                    table_name,
                )


if __name__ == "__main__":
    unittest.main()
