from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.catalog import (  # noqa: E402
    REQUIRED_OBJECT_TYPES,
    REQUIRED_REPLICA_ROLES,
    CatalogBuildError,
    build_catalog,
    validate_catalog,
)
from htgl_dataset_generator.config import resolve_config_file  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.world import build_federated_world  # noqa: E402


class CatalogBuilderTests(unittest.TestCase):
    def test_catalog_tables_validate_against_locked_schemas(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)

        for table_name, rows in catalog.table_records().items():
            self.assertGreater(len(rows), 0, table_name)
            for row in rows:
                validate_record(contract, table_name, row)

    def test_catalog_covers_required_object_types_and_replica_roles(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        world = build_federated_world(resolved)
        catalog = build_catalog(resolved, world=world)
        diagnostics = catalog.diagnostics["SCN-REPRESENTED-450M"]

        self.assertEqual(set(REQUIRED_OBJECT_TYPES), set(diagnostics.object_counts_by_type))
        self.assertTrue(set(REQUIRED_REPLICA_ROLES).issubset(diagnostics.replica_counts_by_role))
        self.assertEqual(40, diagnostics.local_database_count)
        self.assertEqual(45, diagnostics.data_object_count)
        self.assertEqual(230, diagnostics.replica_count)
        self.assertLess(diagnostics.data_object_count, 1_000)

    def test_every_object_and_replica_resolves_custody_references(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        catalog = build_catalog(resolved, world=world)
        database_ids = {row["database_id"] for row in catalog.local_databases}
        object_ids = {row["data_object_id"] for row in catalog.data_objects}
        replica_ids = {row["replica_id"] for row in catalog.data_object_replicas}
        cohort_keys = {(row["scenario_id"], row["cohort_id"]) for row in world.prosumer_cohorts}

        for row in catalog.data_objects:
            self.assertIn(row["origin_database_id"], database_ids)
            if row["subject_cohort_id"] is not None:
                self.assertIn((row["scenario_id"], row["subject_cohort_id"]), cohort_keys)
            self.assertTrue(row["schema_id"])
            self.assertLessEqual(row["valid_from"], row["valid_to"])

        roles_by_object: dict[str, set[str]] = {}
        for row in catalog.data_object_replicas:
            self.assertIn(row["data_object_id"], object_ids)
            self.assertIn(row["database_id"], database_ids)
            self.assertIsNotNone(row["retention_basis_rule_id"])
            roles_by_object.setdefault(row["data_object_id"], set()).add(row["replica_role"])
        for object_id, roles in roles_by_object.items():
            self.assertIn("primary", roles, object_id)

        valid_ids = database_ids | object_ids | replica_ids
        self.assertTrue(any(edge.edge_type == "derived_from" for edge in catalog.custody_edges))
        for edge in catalog.custody_edges:
            self.assertIn(edge.source_id, valid_ids)
            self.assertIn(edge.target_id, valid_ids)

    def test_catalog_generation_is_deterministic(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        world = build_federated_world(resolved)
        first = build_catalog(resolved, world=world)
        second = build_catalog(resolved, world=world)

        self.assertEqual(canonical_records_digest(first.local_databases), canonical_records_digest(second.local_databases))
        self.assertEqual(canonical_records_digest(first.data_objects), canonical_records_digest(second.data_objects))
        self.assertEqual(
            canonical_records_digest(first.data_object_replicas),
            canonical_records_digest(second.data_object_replicas),
        )

    def test_missing_primary_replica_fails_closed(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        catalog = build_catalog(resolved, world=world)
        first_object_id = catalog.data_objects[0]["data_object_id"]
        replicas = tuple(
            row
            for row in catalog.data_object_replicas
            if not (row["data_object_id"] == first_object_id and row["replica_role"] == "primary")
        )
        broken = type(catalog)(
            local_databases=catalog.local_databases,
            data_objects=catalog.data_objects,
            data_object_replicas=replicas,
            custody_edges=catalog.custody_edges,
            diagnostics=catalog.diagnostics,
        )

        with self.assertRaisesRegex(CatalogBuildError, "missing primary replica"):
            validate_catalog(broken, resolved, world=world)

    def test_unresolved_database_reference_fails_closed(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        catalog = build_catalog(resolved, world=world)
        objects = [dict(row) for row in catalog.data_objects]
        objects[0]["origin_database_id"] = "missing-database"
        broken = type(catalog)(
            local_databases=catalog.local_databases,
            data_objects=tuple(objects),
            data_object_replicas=catalog.data_object_replicas,
            custody_edges=catalog.custody_edges,
            diagnostics=catalog.diagnostics,
        )

        with self.assertRaisesRegex(CatalogBuildError, "unresolved origin database"):
            validate_catalog(broken, resolved, world=world)


if __name__ == "__main__":
    unittest.main()
