from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.arrivals import ArrivalBuild, ArrivalMark, build_arrivals  # noqa: E402
from htgl_dataset_generator.catalog import build_catalog  # noqa: E402
from htgl_dataset_generator.config import load_config, resolve_config, resolve_config_file  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.physical import build_physical_raw  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.workflows import (  # noqa: E402
    CONTROLLED_LEGAL_BASIS_LABEL_IDS,
    REQUIRED_WORKFLOW_TYPES,
    SIDE_EFFECT_TYPES,
    WorkflowBuild,
    WorkflowCompilerError,
    build_workflows,
    validate_workflows,
    workflow_definitions,
)
from htgl_dataset_generator.world import build_federated_world  # noqa: E402


EVENT_OBJECT_TYPE: Mapping[str, str] = {
    "consent": "consent",
    "collection_processing": "meter_interval",
    "disclosure": "profile",
    "access": "profile",
    "correction": "meter_interval",
    "retention": "audit_record",
    "erasure": "consent",
    "audit": "audit_record",
    "operational": "operational_command",
    "incident": "operational_command",
}


class WorkflowBuilderTests(unittest.TestCase):
    def _small_dependencies(self):
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)
        arrivals = build_arrivals(resolved, world=world, catalog=catalog, physical=physical, contract=contract)
        return resolved, contract, world, catalog, physical, arrivals

    def _all_family_config(self):
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["workflows"]["families"]["value"] = list(REQUIRED_WORKFLOW_TYPES)
        raw["workflows"]["definition_versions"]["value"] = {
            workflow_type: f"{workflow_type}.v1" for workflow_type in REQUIRED_WORKFLOW_TYPES
        }
        raw["arrivals"]["base_rates_per_day"]["value"] = {
            workflow_type: 0.01 for workflow_type in REQUIRED_WORKFLOW_TYPES
        }
        raw["arrivals"]["conditioned_total"]["value"] = len(REQUIRED_WORKFLOW_TYPES)
        raw["claim_scale"]["materialized_row_target"]["value"] = len(REQUIRED_WORKFLOW_TYPES)
        return resolve_config(raw)

    def _manual_arrivals_for_all_families(self, resolved, world, catalog) -> ArrivalBuild:
        region_id = resolved.world.regions[0]
        cohort = next(row for row in world.prosumer_cohorts if row["region_id"] == region_id)
        actor_by_class: dict[str, dict[str, Any]] = {}
        for actor in world.actors:
            if actor["scenario_id"] == resolved.run.scenario_id and actor["region_id"] == region_id:
                actor_by_class.setdefault(str(actor["actor_class"]), actor)
        fallback_actor = next(row for row in world.actors if row["scenario_id"] == resolved.run.scenario_id)
        arrivals: list[dict[str, Any]] = []
        marks: list[ArrivalMark] = []
        for index, workflow_type in enumerate(REQUIRED_WORKFLOW_TYPES):
            data_object = next(
                row
                for row in catalog.data_objects
                if row["scenario_id"] == resolved.run.scenario_id
                and row["object_type"] == EVENT_OBJECT_TYPE[workflow_type]
            )
            database = next(
                row for row in catalog.local_databases if row["database_id"] == data_object["origin_database_id"]
            )
            arrival_id = f"ARRIVAL-{workflow_type.upper()}-0001"
            timestamp = f"2026-01-01T{index:02d}:00:00Z"
            arrivals.append(
                {
                    "arrival_id": arrival_id,
                    "scenario_id": resolved.run.scenario_id,
                    "replicate_id": 0,
                    "timestamp": timestamp,
                    "arrival_bin": index,
                    "event_family": workflow_type,
                    "region_id": region_id,
                    "subject_cohort_id": data_object.get("subject_cohort_id") or cohort["cohort_id"],
                    "model_class": "conditioned_NHPP",
                    "intensity_per_second": 1.0,
                    "regime_id": None,
                    "parent_arrival_id": None,
                    "anomaly_designated": False,
                    "represented_arrival_count": 1.0,
                }
            )
            source = actor_by_class.get("consumer") or actor_by_class.get("dso") or fallback_actor
            requesting = actor_by_class.get("consumer") or actor_by_class.get("dso") or fallback_actor
            oversight = actor_by_class.get("auditor") or actor_by_class.get("regulator") or fallback_actor
            marks.append(
                ArrivalMark(
                    arrival_id=arrival_id,
                    source_actor_id=str(source["actor_id"]),
                    requesting_actor_id=str(requesting["actor_id"]),
                    controller_actor_id=str(database["controller_actor_id"]),
                    processor_actor_id=str(database["operator_actor_id"]),
                    oversight_actor_id=str(oversight["actor_id"]),
                    local_database_id=str(database["database_id"]),
                    data_object_id=str(data_object["data_object_id"]),
                    purpose_tag=str(data_object["purpose_tags"][0]),
                    jurisdiction_id=str(source["jurisdiction_id"]),
                    workflow_profile_id=resolved.workflows.definition_versions[workflow_type],
                    structural_path=(f"workflow:{workflow_type}",),
                    trigger_id=None,
                )
            )
        return ArrivalBuild(
            arrivals=tuple(arrivals),
            marks=tuple(marks),
            intensity_bins=(),
            diagnostics={},
        )

    def test_workflow_definitions_cover_required_automata_and_side_effects(self) -> None:
        resolved = self._all_family_config()
        definitions = workflow_definitions(resolved)
        side_effects = {
            side_effect
            for definition in definitions.values()
            for transition in definition.transitions
            for side_effect in transition.side_effects
        }

        self.assertEqual(set(REQUIRED_WORKFLOW_TYPES), set(definitions))
        self.assertEqual(set(SIDE_EFFECT_TYPES), side_effects)
        observed_legal_basis_labels = {
            transition.legal_basis_label_id
            for definition in definitions.values()
            for transition in definition.transitions
            if transition.legal_basis_label_id is not None
        }
        self.assertEqual(set(CONTROLLED_LEGAL_BASIS_LABEL_IDS), observed_legal_basis_labels)
        for workflow_type, definition in definitions.items():
            self.assertEqual(f"{workflow_type}.v1", definition.definition_version)
            self.assertGreaterEqual(len(definition.transitions), 2)

    def test_small_workflow_tables_validate_and_reconcile(self) -> None:
        resolved, contract, world, catalog, physical, arrivals = self._small_dependencies()
        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            contract=contract,
        )
        diagnostics = workflows.diagnostics["SCN-SMALL-DETERMINISTIC"]

        self.assertEqual(
            len(arrivals.arrivals) + len(catalog.data_objects),
            len(workflows.workflow_instances),
        )
        self.assertEqual(1.0, diagnostics.transition_conformance_rate)
        self.assertEqual(0, diagnostics.deadline_violation_count)
        self.assertEqual(25 + len(catalog.data_objects), diagnostics.event_edge_count)
        for table_name, rows in workflows.table_records().items():
            self.assertGreater(len(rows), 0, table_name)
            for row in rows:
                validate_record(contract, table_name, row)

    def test_all_required_families_compile_with_side_effects(self) -> None:
        resolved = self._all_family_config()
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)
        arrivals = self._manual_arrivals_for_all_families(resolved, world, catalog)

        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            contract=contract,
        )
        observed_types = {row["workflow_type"] for row in workflows.workflow_instances}
        side_effects = {effect.side_effect_type for effect in workflows.side_effects}

        self.assertEqual(set(REQUIRED_WORKFLOW_TYPES), observed_types)
        self.assertEqual(set(SIDE_EFFECT_TYPES), side_effects)
        self.assertTrue(all(row["event_count"] >= 2 for row in workflows.workflow_instances))
        self.assertTrue(all(row["terminal_event_id"] is not None for row in workflows.workflow_instances))

    def test_horizon_truncation_preserves_a_valid_open_workflow(self) -> None:
        resolved = self._all_family_config()
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)
        base_arrivals = self._manual_arrivals_for_all_families(resolved, world, catalog)
        horizon_end = datetime.fromisoformat(resolved.run.horizon_end.replace("Z", "+00:00")).astimezone(timezone.utc)
        arrivals = [dict(row) for row in base_arrivals.arrivals]
        consent_arrival = next(row for row in arrivals if row["event_family"] == "consent")
        consent_arrival["timestamp"] = (horizon_end - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        truncated_input = ArrivalBuild(
            arrivals=tuple(arrivals),
            marks=base_arrivals.marks,
            intensity_bins=base_arrivals.intensity_bins,
            diagnostics=base_arrivals.diagnostics,
        )

        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=truncated_input,
            contract=contract,
        )
        consent_instance = next(
            row for row in workflows.workflow_instances if row["workflow_type"] == "consent"
        )
        consent_events = [
            row
            for row in workflows.governance_events
            if row["workflow_instance_id"] == consent_instance["workflow_instance_id"]
        ]

        self.assertIsNone(consent_instance["terminal_event_id"])
        self.assertEqual("requested", consent_instance["final_state"])
        self.assertEqual(1, consent_instance["event_count"])
        self.assertTrue(all(row["timestamp"] <= resolved.run.horizon_end for row in consent_events))

    def test_workflow_generation_is_deterministic(self) -> None:
        resolved, contract, world, catalog, physical, arrivals = self._small_dependencies()
        first = build_workflows(resolved, world=world, catalog=catalog, physical=physical, arrivals=arrivals, contract=contract)
        second = build_workflows(resolved, world=world, catalog=catalog, physical=physical, arrivals=arrivals, contract=contract)

        self.assertEqual(canonical_records_digest(first.governance_events), canonical_records_digest(second.governance_events))
        self.assertEqual(canonical_records_digest(first.event_edges), canonical_records_digest(second.event_edges))
        self.assertEqual(canonical_records_digest(first.workflow_instances), canonical_records_digest(second.workflow_instances))

    def test_invalid_transition_sequence_fails_closed(self) -> None:
        resolved, contract, world, catalog, physical, arrivals = self._small_dependencies()
        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            contract=contract,
        )
        events = [dict(row) for row in workflows.governance_events]
        non_root_index = next(index for index, row in enumerate(events) if row["workflow_step_index"] == 1)
        events[non_root_index]["workflow_state_before"] = "not_requested"
        broken = WorkflowBuild(
            governance_events=tuple(events),
            event_edges=workflows.event_edges,
            workflow_instances=workflows.workflow_instances,
            side_effects=workflows.side_effects,
            diagnostics=workflows.diagnostics,
        )

        with self.assertRaisesRegex(WorkflowCompilerError, "illegal state transition"):
            validate_workflows(broken, resolved, arrivals=arrivals, catalog=catalog, contract=contract)

    def test_uncontrolled_legal_basis_label_fails_closed(self) -> None:
        resolved, contract, world, catalog, physical, arrivals = self._small_dependencies()
        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            contract=contract,
        )
        events = [dict(row) for row in workflows.governance_events]
        events[0]["legal_basis_label_id"] = "LBL-UNCONTROLLED"
        broken = WorkflowBuild(
            governance_events=tuple(events),
            event_edges=workflows.event_edges,
            workflow_instances=workflows.workflow_instances,
            side_effects=workflows.side_effects,
            diagnostics=workflows.diagnostics,
        )

        with self.assertRaisesRegex(WorkflowCompilerError, "uncontrolled experimental legal_basis_label_id"):
            validate_workflows(broken, resolved, arrivals=arrivals, catalog=catalog, contract=contract)

    def test_workflow_tables_write_to_parquet(self) -> None:
        import pyarrow.parquet as pq

        resolved, contract, world, catalog, physical, arrivals = self._small_dependencies()
        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            contract=contract,
        )

        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(workflows.table_records(), Path(tmp), contract=contract)
            self.assertEqual(set(workflows.table_records()), set(written))
            for table_name, rows in workflows.table_records().items():
                observed = pq.read_table(written[table_name])
                self.assertEqual(len(rows), observed.num_rows, table_name)
                self.assertEqual(
                    f"htgl.dataset.v1.{table_name}".encode("utf-8"),
                    observed.schema.metadata[b"schema_id"],
                    table_name,
                )

    def test_reference_workflows_have_complete_conformance(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        contract = load_contract()
        world = build_federated_world(resolved, contract=contract)
        catalog = build_catalog(resolved, world=world, contract=contract)
        physical = build_physical_raw(resolved, world=world, contract=contract)
        arrivals = build_arrivals(resolved, world=world, catalog=catalog, physical=physical, contract=contract)
        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            contract=contract,
        )
        diagnostics = workflows.diagnostics["SCN-REFERENCE-10K"]

        self.assertEqual(
            len(arrivals.arrivals) + len(catalog.data_objects),
            diagnostics.workflow_count,
        )
        self.assertEqual(1.0, diagnostics.transition_conformance_rate)
        self.assertEqual(0, diagnostics.deadline_violation_count)
        self.assertEqual(
            diagnostics.workflow_count,
            diagnostics.terminal_workflow_count + diagnostics.open_horizon_workflow_count,
        )
        self.assertEqual(
            set(resolved.workflows.families),
            {str(row["workflow_type"]) for row in workflows.workflow_instances},
        )


if __name__ == "__main__":
    unittest.main()
