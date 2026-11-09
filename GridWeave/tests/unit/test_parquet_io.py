from __future__ import annotations

import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.catalog import build_catalog  # noqa: E402
from htgl_dataset_generator.config import resolve_config_file  # noqa: E402
from htgl_dataset_generator.io import (  # noqa: E402
    ParquetDependencyError,
    arrow_schema_for_table,
    write_parquet_dataset,
    write_parquet_table,
    write_parquet_table_with_report,
)
from htgl_dataset_generator.schemas import load_contract  # noqa: E402
from htgl_dataset_generator.world import build_federated_world  # noqa: E402


class ParquetIoTests(unittest.TestCase):
    def test_writer_fails_closed_when_pyarrow_missing(self) -> None:
        original_import = __import__

        def fake_import(name: str, *args, **kwargs):
            if name == "pyarrow" or name.startswith("pyarrow."):
                raise ModuleNotFoundError("No module named 'pyarrow'")
            return original_import(name, *args, **kwargs)

        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        with tempfile.TemporaryDirectory() as tmp:
            with patch("builtins.__import__", side_effect=fake_import):
                with self.assertRaisesRegex(ParquetDependencyError, "pyarrow is required"):
                    write_parquet_table("actor", world.actors, Path(tmp) / "actor.parquet")

    def test_arrow_schema_and_parquet_round_trip(self) -> None:
        import pyarrow.parquet as pq

        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        contract = load_contract()
        schema = arrow_schema_for_table(contract.table("actor"))
        self.assertEqual(b"htgl.dataset.v1.actor", schema.metadata[b"schema_id"])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_parquet_table("actor", world.actors, Path(tmp) / "actor.parquet", contract=contract)
            observed = pq.read_table(path)
            self.assertEqual(len(world.actors), observed.num_rows)
            self.assertEqual(b"htgl.dataset.v1.actor", observed.schema.metadata[b"schema_id"])

    def test_world_and_catalog_tables_write_as_parquet_dataset(self) -> None:
        import pyarrow.parquet as pq

        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        catalog = build_catalog(resolved, world=world)
        tables = {
            "actor": world.actors,
            "network_area": world.network_areas,
            "local_database": catalog.local_databases,
            "data_object": catalog.data_objects,
            "data_object_replica": catalog.data_object_replicas,
        }
        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(tables, Path(tmp))
            self.assertEqual(set(tables), set(written))
            for table_name, rows in tables.items():
                observed = pq.read_table(written[table_name])
                self.assertEqual(len(rows), observed.num_rows, table_name)
                self.assertEqual(
                    f"htgl.dataset.v1.{table_name}".encode("utf-8"),
                    observed.schema.metadata[b"schema_id"],
                    table_name,
                )

    def test_external_sort_is_bounded_deterministic_and_reported(self) -> None:
        import hashlib
        import pyarrow.parquet as pq

        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        rows = tuple(reversed(build_federated_world(resolved).actors))
        self.assertGreater(len(rows), 2)
        with tempfile.TemporaryDirectory() as tmp:
            first = write_parquet_table_with_report(
                "actor",
                rows,
                Path(tmp) / "first.parquet",
                maximum_buffered_rows=2,
                row_group_target_bytes=4_096,
            )
            second = write_parquet_table_with_report(
                "actor",
                rows,
                Path(tmp) / "second.parquet",
                maximum_buffered_rows=2,
                row_group_target_bytes=4_096,
            )
            self.assertGreater(first.external_sort_spill_count, 0)
            self.assertLessEqual(first.maximum_rows_in_memory, 2)
            self.assertEqual(len(rows), first.record_count)
            self.assertEqual(first.sha256, second.sha256)
            self.assertEqual(
                hashlib.sha256(Path(first.path).read_bytes()).hexdigest(),
                first.sha256,
            )
            self.assertEqual(
                pq.read_table(first.path).to_pylist(),
                pq.read_table(second.path).to_pylist(),
            )
            self.assertGreater(first.row_group_count, 0)
            self.assertIsNotNone(first.row_group_efficiency)


if __name__ == "__main__":
    unittest.main()
