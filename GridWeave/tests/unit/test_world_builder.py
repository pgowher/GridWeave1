from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import load_config, resolve_config, resolve_config_file  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.world import (  # noqa: E402
    WorldBuildError,
    build_federated_world,
    validate_federated_world,
)


RELATIONSHIP_SOURCE_CLASSES: Mapping[str, tuple[str, ...]] = {
    "controls": ("dso", "tso"),
    "processes_for": ("processor", "vendor", "supplier", "aggregator"),
    "supplies": ("supplier",),
    "aggregates": ("aggregator",),
    "oversees": ("regulator", "tso", "oversight", "validator"),
    "audits": ("auditor", "regulator"),
    "discloses_to": ("dso", "supplier", "aggregator", "processor", "vendor"),
}

RELATIONSHIP_TARGET_CLASSES: Mapping[str, tuple[str, ...]] = {
    "controls": ("consumer", "prosumer"),
    "processes_for": ("dso", "supplier", "aggregator"),
    "supplies": ("consumer", "prosumer"),
    "aggregates": ("prosumer",),
    "oversees": ("dso", "supplier", "aggregator", "processor", "vendor"),
    "audits": ("dso", "supplier", "aggregator", "processor", "vendor"),
    "discloses_to": ("regulator", "auditor", "tso", "oversight"),
}


class FederatedWorldBuilderTests(unittest.TestCase):
    def test_reference_world_rows_validate_against_locked_schemas(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)

        self.assertGreater(len(world.actors), 0)
        self.assertGreater(len(world.actor_relationships), 0)
        self.assertGreater(len(world.prosumer_cohorts), 0)

        for table_name, rows in world.table_records().items():
            for row in rows:
                validate_record(contract, table_name, row)
        self.assertEqual({row["region_id"] for row in world.network_areas}, set(resolved.world.regions))

    def test_represented_population_reconciles_through_weighted_cohorts(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        world = build_federated_world(resolved)
        total = sum(
            row["represented_consumer_count"] + row["represented_prosumer_count"]
            for row in world.prosumer_cohorts
        )
        regions = {row["region_id"] for row in world.prosumer_cohorts}
        materialized_subject_actors = [
            row for row in world.actors if row["actor_class"] in {"consumer", "prosumer"}
        ]

        self.assertEqual(450_000_000, total)
        self.assertEqual(set(resolved.world.regions), regions)
        self.assertEqual(set(resolved.world.regions), {row["region_id"] for row in world.network_areas})
        self.assertLess(len(materialized_subject_actors), 100)
        self.assertLess(len(world.actors), 10_000)
        self.assertGreaterEqual(len(world.prosumer_cohorts), len(resolved.world.regions))

    def test_450m_world_uses_scale_aware_institutional_topology(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        world = build_federated_world(resolved)
        diagnostics = world.diagnostics["SCN-REPRESENTED-450M"]
        required_classes = {
            "consumer",
            "prosumer",
            "dso",
            "tso",
            "supplier",
            "aggregator",
            "regulator",
            "vendor",
            "auditor",
            "processor",
        }

        self.assertTrue(required_classes.issubset(diagnostics.actor_counts_by_class))
        self.assertEqual(len(resolved.world.regions), diagnostics.materialized_network_area_count)
        self.assertGreater(diagnostics.controller_actor_count, 1)
        self.assertLess(diagnostics.max_controller_represented_population, 450_000_000)
        self.assertEqual(
            dict(sorted(resolved.world.actor_relationship_counts.items())),
            diagnostics.relationship_counts_by_type,
        )

    def test_relationships_obey_role_constraints_and_temporal_bounds(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        world = build_federated_world(resolved)
        actor_by_id = {row["actor_id"]: row for row in world.actors}

        for relationship in world.actor_relationships:
            relationship_type = relationship["relationship_type"]
            source = actor_by_id[relationship["source_actor_id"]]
            target = actor_by_id[relationship["target_actor_id"]]
            self.assertIn(source["actor_class"], RELATIONSHIP_SOURCE_CLASSES[relationship_type])
            self.assertIn(target["actor_class"], RELATIONSHIP_TARGET_CLASSES[relationship_type])
            self.assertLessEqual(relationship["valid_from"], relationship["valid_to"])

    def test_world_generation_is_deterministic(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        first = build_federated_world(resolved)
        second = build_federated_world(resolved)

        self.assertEqual(canonical_records_digest(first.actors), canonical_records_digest(second.actors))
        self.assertEqual(
            canonical_records_digest(first.actor_relationships),
            canonical_records_digest(second.actor_relationships),
        )
        self.assertEqual(
            canonical_records_digest(first.prosumer_cohorts),
            canonical_records_digest(second.prosumer_cohorts),
        )

    def test_builder_supports_all_declared_relationship_types(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["world"]["actor_relationship_counts"]["value"] = {
            relationship_type: 1
            for relationship_type in RELATIONSHIP_SOURCE_CLASSES
        }
        resolved = resolve_config(raw)
        world = build_federated_world(resolved)
        observed = {
            relationship_type: sum(
                1 for row in world.actor_relationships if row["relationship_type"] == relationship_type
            )
            for relationship_type in RELATIONSHIP_SOURCE_CLASSES
        }

        self.assertEqual({relationship_type: 1 for relationship_type in RELATIONSHIP_SOURCE_CLASSES}, observed)

    def test_unknown_relationship_type_fails_before_generation_output(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["world"]["actor_relationship_counts"]["value"] = {"invented_relationship": 1}
        resolved = resolve_config(raw)

        with self.assertRaisesRegex(WorldBuildError, "unknown relationship_type"):
            build_federated_world(resolved)

    def test_invalid_relationship_interval_fails_validation(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        world = build_federated_world(resolved)
        relationships = [dict(row) for row in world.actor_relationships]
        relationships[0]["valid_to"] = "2025-12-31T23:59:59Z"
        broken = type(world)(
            actors=world.actors,
            actor_relationships=tuple(relationships),
            prosumer_cohorts=world.prosumer_cohorts,
            diagnostics=world.diagnostics,
            network_areas=world.network_areas,
        )

        with self.assertRaisesRegex(WorldBuildError, "valid_to earlier"):
            validate_federated_world(broken, resolved)

    def test_single_controller_450m_world_is_rejected(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        world = build_federated_world(resolved)
        seen_controller = False
        actors: list[dict[str, Any]] = []
        for row in world.actors:
            actor = dict(row)
            if "controller" in actor["capabilities"]:
                if seen_controller:
                    actor["capabilities"] = [
                        capability for capability in actor["capabilities"] if capability != "controller"
                    ]
                else:
                    seen_controller = True
            actors.append(actor)
        broken = type(world)(
            actors=tuple(actors),
            actor_relationships=world.actor_relationships,
            prosumer_cohorts=world.prosumer_cohorts,
            diagnostics=world.diagnostics,
            network_areas=world.network_areas,
        )

        with self.assertRaisesRegex(WorldBuildError, "one logical controller"):
            validate_federated_world(broken, resolved)


if __name__ == "__main__":
    unittest.main()
