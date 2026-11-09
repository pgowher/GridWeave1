from __future__ import annotations

from io import BytesIO
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.adapters import (  # noqa: E402
    AdapterContractError,
    SUPPORTED_ADAPTERS,
    compile_interoperability_adapters,
    load_adapter_registry,
)
from htgl_dataset_generator.config import resolve_config_file  # noqa: E402
from htgl_dataset_generator.experiments import (  # noqa: E402
    orchestrate_pipeline_through_observers,
)
from htgl_dataset_generator.observers import ObserverReleaseView  # noqa: E402
from htgl_dataset_generator.adapters.registry import REGISTRY_PATH  # noqa: E402


class InteroperabilityAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        cls.result = orchestrate_pipeline_through_observers(cls.resolved)[0]
        cls.views = cls.result.artifacts.observers.release_views
        key = (cls.result.run_plan.scenario_id, cls.result.run_plan.replicate_id)
        cls.tables_by_run = {key: cls.result.artifacts.authoritative_table_records()}

    def test_registry_is_pinned_complete_and_stable(self) -> None:
        first = load_adapter_registry()
        second = load_adapter_registry()
        self.assertEqual(SUPPORTED_ADAPTERS, set(first.profiles))
        self.assertEqual(first.sha256, second.sha256)
        self.assertRegex(first.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(
            {"network_area", "raw_network_state"}, set(first.profile("cim").source_schemas)
        )
        self.assertEqual(
            ("raw_meter_reading",), first.profile("green_button").source_schemas
        )

    def test_registry_missing_locked_field_fails_closed(self) -> None:
        raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        del raw["profiles"]["xes"]["mappings"]["observer_release"]["payload.event_type"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broken_registry.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(AdapterContractError, "locked field coverage mismatch"):
                load_adapter_registry(path)

    def test_all_adapters_emit_executable_conformance_and_deterministic_bytes(self) -> None:
        import pyarrow.parquet as pq

        configured = tuple(sorted(SUPPORTED_ADAPTERS))
        with tempfile.TemporaryDirectory() as first_root, tempfile.TemporaryDirectory() as second_root:
            first = compile_interoperability_adapters(
                self.views, self.tables_by_run, configured, Path(first_root)
            )
            second = compile_interoperability_adapters(
                self.views, self.tables_by_run, configured, Path(second_root)
            )
            self.assertEqual(configured, first.configured_adapters)
            self.assertTrue(all(item.passed for item in first.conformance))
            self.assertTrue(all(item.undocumented_field_count == 0 for item in first.conformance))
            self.assertTrue(
                all(item.round_trip_status.startswith("passed") for item in first.conformance)
            )
            self.assertTrue(
                all(item.semantic_equivalence_status.startswith("passed") for item in first.conformance)
            )
            first_bytes = {
                path.relative_to(first_root).as_posix(): path.read_bytes()
                for path in first.output_paths
            }
            second_bytes = {
                path.relative_to(second_root).as_posix(): path.read_bytes()
                for path in second.output_paths
            }
            self.assertEqual(first_bytes, second_bytes)

            mapping_path = Path(first_root) / "publication/adapters/mapping/field_mapping.parquet"
            parquet_file = pq.ParquetFile(mapping_path)
            try:
                metadata = parquet_file.schema_arrow.metadata or {}
                self.assertEqual(b"htgl.adapter.field-mapping.v1", metadata[b"htgl.schema_id"])
                self.assertEqual(first.registry.sha256.encode("ascii"), metadata[b"htgl.mapping_registry_sha256"])
                for group_index in range(parquet_file.metadata.num_row_groups):
                    group = parquet_file.metadata.row_group(group_index)
                    for column_index in range(group.num_columns):
                        self.assertEqual("ZSTD", group.column(column_index).compression)
            finally:
                parquet_file.close()

            unmapped = json.loads(
                (Path(first_root) / "publication/adapters/unmapped_fields.json").read_text(
                    encoding="utf-8"
                )
            )
            conformance = json.loads(
                (Path(first_root) / "publication/adapters/conformance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(0, unmapped["undocumented_field_count"])
            self.assertTrue(conformance["all_passed"])
            self.assertFalse(conformance["adapters_are_authoritative"])

            physical_archives = tuple(
                Path(first_root).glob("publication/adapters/cim/**/*.zip")
            ) + tuple(Path(first_root).glob("publication/adapters/green_button/**/*.zip"))
            self.assertTrue(physical_archives)
            for archive_path in physical_archives:
                with zipfile.ZipFile(archive_path) as archive:
                    self.assertTrue(archive.infolist())
                    self.assertTrue(
                        all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in archive.infolist())
                    )
                metadata_row = first.metadata_overrides[
                    archive_path.relative_to(first_root).as_posix()
                ]
                self.assertEqual("restricted", metadata_row["privacy_class"])
                self.assertFalse(metadata_row["publication_eligible"])

            sqlite_archive = Path(first_root) / "publication/adapters/sqlite/public_observer_index.zip"
            with zipfile.ZipFile(BytesIO(sqlite_archive.read_bytes())) as archive:
                database_bytes = archive.read("observer_index.sqlite")
            database_path = Path(first_root) / "observer_index.sqlite"
            database_path.write_bytes(database_bytes)
            connection = sqlite3.connect(database_path)
            try:
                count = int(connection.execute("SELECT COUNT(*) FROM observer_event").fetchone()[0])
            finally:
                connection.close()
            self.assertEqual(
                sum(len(view.records) for view in self.views.values() if view.access_class == "public"),
                count,
            )

    def test_undocumented_or_evaluator_field_blocks_adapter_output(self) -> None:
        public_key = next(
            key for key, view in sorted(self.views.items()) if view.access_class == "public"
        )
        original = self.views[public_key]
        records = [dict(item) for item in original.records]
        records[0] = dict(records[0])
        records[0]["payload"] = dict(records[0]["payload"])
        records[0]["payload"]["protected_pair_id"] = "sealed-value"
        mutated = dict(self.views)
        mutated[public_key] = ObserverReleaseView(
            profile_id=original.profile_id,
            access_class=original.access_class,
            schema_profile_id=original.schema_profile_id,
            records=tuple(records),
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(AdapterContractError, "forbidden or undocumented"):
                compile_interoperability_adapters(
                    mutated,
                    self.tables_by_run,
                    ("jsonl_debug_view",),
                    Path(temporary),
                )


if __name__ == "__main__":
    unittest.main()
