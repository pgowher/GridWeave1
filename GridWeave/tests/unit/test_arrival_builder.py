from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.arrivals import (  # noqa: E402
    ArrivalGenerationError,
    build_arrivals,
    validate_arrivals,
)
from htgl_dataset_generator.catalog import build_catalog  # noqa: E402
from htgl_dataset_generator.config import load_config, resolve_config, resolve_config_file  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.physical import build_physical_raw  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.world import build_federated_world  # noqa: E402


class ArrivalBuilderTests(unittest.TestCase):
    def _small_dependencies(self):
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)
        return resolved, contract, world, catalog, physical

    def test_conditioned_nhpp_rows_validate_and_have_conditional_marks(self) -> None:
        resolved, contract, world, catalog, physical = self._small_dependencies()
        arrivals = build_arrivals(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            model_class="conditioned_NHPP",
            contract=contract,
        )

        self.assertEqual(25, len(arrivals.arrivals))
        self.assertEqual(len(arrivals.arrivals), len(arrivals.marks))
        self.assertEqual(384, len(arrivals.intensity_bins))
        self.assertTrue(arrivals.diagnostics["SCN-SMALL-DETERMINISTIC"].passed)
        for row in arrivals.arrivals:
            validate_record(contract, "arrival", row)
        for mark in arrivals.marks:
            self.assertIn("workflow:", mark.structural_path[-1])
            self.assertTrue(mark.local_database_id)
            self.assertTrue(mark.data_object_id)
            self.assertTrue(mark.purpose_tag)

    def test_unconditioned_nhpp_is_deterministic_and_schema_valid(self) -> None:
        resolved, contract, world, catalog, physical = self._small_dependencies()
        first = build_arrivals(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            model_class="unconditioned_NHPP",
            contract=contract,
        )
        second = build_arrivals(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            model_class="unconditioned_NHPP",
            contract=contract,
        )

        self.assertEqual(canonical_records_digest(first.arrivals), canonical_records_digest(second.arrivals))
        self.assertTrue(first.diagnostics["SCN-SMALL-DETERMINISTIC"].passed)
        self.assertGreaterEqual(len(first.arrivals), 0)
        for row in first.arrivals:
            validate_record(contract, "arrival", row)

    def test_replicate_id_changes_arrival_stream_without_changing_dependencies(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["run"]["replicate_count"]["value"] = 2
        raw["validation"]["repetition_count"]["value"] = 2
        resolved = resolve_config(raw)
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)

        first = build_arrivals(resolved, world=world, catalog=catalog, physical=physical, replicate_id=0, contract=contract)
        second = build_arrivals(resolved, world=world, catalog=catalog, physical=physical, replicate_id=1, contract=contract)

        self.assertNotEqual(canonical_records_digest(first.arrivals), canonical_records_digest(second.arrivals))
        self.assertEqual(25, len(first.arrivals))
        self.assertEqual(25, len(second.arrivals))

    def test_mmpp_requires_complete_stable_ctmc_parameters_and_emits_regimes(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["arrivals"]["model_classes"]["value"] = ["MMPP"]
        raw["arrivals"]["mmpp_parameters"]["value"] = {
            "states": ["normal", "stress"],
            "initial_distribution": {"normal": 0.85, "stress": 0.15},
            "state_rate_multipliers": {"normal": 1.0, "stress": 2.25},
            "generator_matrix": [[-0.08, 0.08], [0.20, -0.20]],
        }
        resolved = resolve_config(raw)
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)

        arrivals = build_arrivals(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            model_class="MMPP",
            contract=contract,
        )

        self.assertEqual(25, len(arrivals.arrivals))
        self.assertTrue(all(row["regime_id"] is not None for row in arrivals.arrivals))
        self.assertTrue(arrivals.diagnostics["SCN-SMALL-DETERMINISTIC"].passed)

    def test_hawkes_requires_stable_branching_and_records_parent_truth(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["arrivals"]["model_classes"]["value"] = ["Hawkes"]
        raw["arrivals"]["hawkes_parameters"]["value"] = {
            "kernel": "exponential.v1",
            "spectral_radius_bound": 0.8,
            "mean_delay_seconds": 900,
            "background_fraction": 0.70,
            "branching": {"consent": {"access": 0.15}, "access": {"consent": 0.10}},
        }
        resolved = resolve_config(raw)
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)

        arrivals = build_arrivals(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            model_class="Hawkes",
            contract=contract,
        )
        parent_ids = {row["arrival_id"] for row in arrivals.arrivals}
        parented = [row for row in arrivals.arrivals if row["parent_arrival_id"] is not None]

        self.assertGreater(len(parented), 0)
        self.assertTrue(all(row["parent_arrival_id"] in parent_ids for row in parented))
        self.assertEqual(0.0, arrivals.diagnostics["SCN-SMALL-DETERMINISTIC"].cross_excitation_error)
        self.assertTrue(arrivals.diagnostics["SCN-SMALL-DETERMINISTIC"].passed)

    def test_incomplete_advanced_modes_fail_closed(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)

        with self.assertRaisesRegex(ArrivalGenerationError, "MMPP requires parameters"):
            build_arrivals(resolved, world=world, catalog=catalog, physical=physical, model_class="MMPP", contract=contract)
        with self.assertRaisesRegex(ArrivalGenerationError, "Hawkes requires parameters"):
            build_arrivals(resolved, world=world, catalog=catalog, physical=physical, model_class="Hawkes", contract=contract)

    def test_unconditioned_450m_materialization_is_blocked_by_n_guard(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)

        with self.assertRaisesRegex(ArrivalGenerationError, "materialized_row_target"):
            build_arrivals(
                resolved,
                world=world,
                catalog=catalog,
                physical=physical,
                model_class="unconditioned_NHPP",
                contract=contract,
            )

    def test_arrival_table_writes_to_parquet(self) -> None:
        import pyarrow.parquet as pq

        resolved, contract, world, catalog, physical = self._small_dependencies()
        arrivals = build_arrivals(resolved, world=world, catalog=catalog, physical=physical, contract=contract)
        validate_arrivals(arrivals, resolved, world=world, catalog=catalog, contract=contract)
        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(arrivals.table_records(), Path(tmp), contract=contract)
            observed = pq.read_table(written["arrival"])
            self.assertEqual(len(arrivals.arrivals), observed.num_rows)
            self.assertEqual(b"htgl.dataset.v1.arrival", observed.schema.metadata[b"schema_id"])


if __name__ == "__main__":
    unittest.main()
