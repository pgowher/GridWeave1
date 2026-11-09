from __future__ import annotations

from collections import Counter
import copy
from dataclasses import replace
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
from htgl_dataset_generator.dag import CausalDagBuild, DagValidationError, build_causal_dag, validate_causal_dag  # noqa: E402
from htgl_dataset_generator.io import write_parquet_dataset  # noqa: E402
from htgl_dataset_generator.physical import build_physical_raw  # noqa: E402
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import canonical_records_digest  # noqa: E402
from htgl_dataset_generator.workflows import REQUIRED_WORKFLOW_TYPES, WorkflowBuild, build_workflows  # noqa: E402
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


class CausalDagBuilderTests(unittest.TestCase):
    def _small_dependencies(self):
        resolved = resolve_config_file(REPO_ROOT / "configs" / "small_deterministic.json")
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
        return resolved, contract, world, catalog, physical, arrivals, workflows

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
        actor = next(row for row in world.actors if row["scenario_id"] == resolved.run.scenario_id)
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
            arrival_id = f"ARRIVAL-{workflow_type.upper()}-S07"
            arrivals.append(
                {
                    "arrival_id": arrival_id,
                    "scenario_id": resolved.run.scenario_id,
                    "replicate_id": 0,
                    "timestamp": f"2026-01-01T{index:02d}:00:00Z",
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
            marks.append(
                ArrivalMark(
                    arrival_id=arrival_id,
                    source_actor_id=str(actor["actor_id"]),
                    requesting_actor_id=str(actor["actor_id"]),
                    controller_actor_id=str(database["controller_actor_id"]),
                    processor_actor_id=str(database["operator_actor_id"]),
                    oversight_actor_id=str(actor["actor_id"]),
                    local_database_id=str(database["database_id"]),
                    data_object_id=str(data_object["data_object_id"]),
                    purpose_tag=str(data_object["purpose_tags"][0]),
                    jurisdiction_id=str(actor["jurisdiction_id"]),
                    workflow_profile_id=resolved.workflows.definition_versions[workflow_type],
                    structural_path=(f"workflow:{workflow_type}",),
                    trigger_id=None,
                )
            )
        return ArrivalBuild(arrivals=tuple(arrivals), marks=tuple(marks), intensity_bins=(), diagnostics={})

    def test_small_dag_recomputes_roots_depths_and_closure(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        diagnostics = dag.diagnostics["SCN-SMALL-DETERMINISTIC"]
        incoming = Counter(edge["target_event_id"] for edge in dag.event_edges if edge["required_for_closure"])

        self.assertEqual(0, diagnostics.orphan_non_root_count)
        self.assertEqual(0, diagnostics.disallowed_cycle_count)
        self.assertEqual(0, diagnostics.depth_reconciliation_error_count)
        self.assertGreater(diagnostics.closure_record_count, 0)
        for event in dag.governance_events:
            if event["causal_depth"] == 0:
                self.assertEqual(event["event_id"], event["root_event_id"])
            else:
                self.assertGreater(incoming[event["event_id"]], 0)
        for table_name, rows in dag.table_records().items():
            for row in rows:
                validate_record(contract, table_name, row)

    def test_all_edge_types_are_emitted_for_all_family_traces(self) -> None:
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

        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )

        self.assertEqual(set(contract.dictionary_values("edge_type")), {edge["edge_type"] for edge in dag.event_edges})
        self.assertTrue(any(edge["cross_workflow"] for edge in dag.event_edges))
        target_order_edges = tuple(
            edge
            for edge in dag.event_edges
            if edge["rule_id"] == "S07-TARGET-TEMPORAL-ORDER"
        )
        self.assertTrue(target_order_edges)
        self.assertTrue(
            all(
                edge["edge_type"] == "precedes"
                and edge["cross_workflow"]
                and not edge["required_for_closure"]
                for edge in target_order_edges
            )
        )
        self.assertEqual(0, dag.diagnostics[resolved.run.scenario_id].orphan_non_root_count)

    def test_parent_arrival_emits_cross_workflow_causal_edge(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, _ = self._small_dependencies()
        ordered_arrivals = sorted(
            (dict(row) for row in arrivals.arrivals),
            key=lambda row: (row["timestamp"], row["arrival_id"]),
        )
        parent_arrival_id = str(ordered_arrivals[0]["arrival_id"])
        child_arrival_id = str(ordered_arrivals[1]["arrival_id"])
        ordered_arrivals[1]["parent_arrival_id"] = parent_arrival_id
        arrivals_with_parent = ArrivalBuild(
            arrivals=tuple(ordered_arrivals),
            marks=arrivals.marks,
            intensity_bins=arrivals.intensity_bins,
            diagnostics=arrivals.diagnostics,
        )
        workflows = build_workflows(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals_with_parent,
            contract=contract,
        )
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals_with_parent,
            workflows=workflows,
            contract=contract,
        )
        root_by_arrival = {
            str(event["source_event_id"]): str(event["event_id"])
            for event in dag.governance_events
            if int(event["workflow_step_index"]) == 0
        }
        parent_edge = next(
            edge
            for edge in dag.event_edges
            if edge["source_event_id"] == root_by_arrival[parent_arrival_id]
            and edge["target_event_id"] == root_by_arrival[child_arrival_id]
            and edge["edge_type"] == "causes"
        )
        self.assertTrue(parent_edge["cross_workflow"])
        self.assertTrue(parent_edge["required_for_closure"])
        self.assertIn("S07-ARRIVAL-PARENT-CAUSE", str(parent_edge["rule_id"]))

    def test_unresolved_input_edge_fails_during_normalization(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        edges = [dict(row) for row in workflows.event_edges]
        edges[0]["source_event_id"] = "EVENT-DOES-NOT-EXIST"
        broken_workflows = WorkflowBuild(
            governance_events=workflows.governance_events,
            event_edges=tuple(edges),
            workflow_instances=workflows.workflow_instances,
            side_effects=workflows.side_effects,
            diagnostics=workflows.diagnostics,
        )

        with self.assertRaisesRegex(DagValidationError, "source_event_id does not resolve"):
            build_causal_dag(
                resolved,
                world=world,
                catalog=catalog,
                physical=physical,
                arrivals=arrivals,
                workflows=broken_workflows,
                contract=contract,
            )

    def test_cycle_detection_fails_closed(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        first_edge = dag.event_edges[0]
        cycle_edge = dict(first_edge)
        cycle_edge["edge_id"] = "EDGE-CYCLE-S07-0001"
        cycle_edge["source_event_id"] = first_edge["target_event_id"]
        cycle_edge["target_event_id"] = first_edge["source_event_id"]
        cycle_edge["edge_type"] = "precedes"
        broken = CausalDagBuild(
            governance_events=dag.governance_events,
            event_edges=tuple((*dag.event_edges, cycle_edge)),
            workflow_instances=dag.workflow_instances,
            closure_index=dag.closure_index,
            diagnostics=dag.diagnostics,
        )

        with self.assertRaisesRegex(DagValidationError, "cycle"):
            validate_causal_dag(broken, resolved, contract=contract)

    def test_depth_mismatch_fails_closed(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        events = [dict(row) for row in dag.governance_events]
        target_index = next(index for index, row in enumerate(events) if row["causal_depth"] > 0)
        events[target_index]["causal_depth"] += 1
        broken = CausalDagBuild(
            governance_events=tuple(events),
            event_edges=dag.event_edges,
            workflow_instances=dag.workflow_instances,
            closure_index=dag.closure_index,
            diagnostics=dag.diagnostics,
        )

        with self.assertRaisesRegex(DagValidationError, "causal_depth"):
            validate_causal_dag(broken, resolved, contract=contract)

    def test_cross_workflow_flag_mismatch_fails_closed(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        edges = [dict(row) for row in dag.event_edges]
        edges[0]["cross_workflow"] = not bool(edges[0]["cross_workflow"])
        broken = CausalDagBuild(
            governance_events=dag.governance_events,
            event_edges=tuple(edges),
            workflow_instances=dag.workflow_instances,
            closure_index=dag.closure_index,
            diagnostics=dag.diagnostics,
        )

        with self.assertRaisesRegex(DagValidationError, "cross_workflow flag"):
            validate_causal_dag(broken, resolved, contract=contract)

    def test_closure_membership_drift_fails_closed(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        closure = list(dag.closure_index)
        target_index = next(index for index, record in enumerate(closure) if record.closure_size > 0)
        closure[target_index] = replace(
            closure[target_index],
            member_event_ids=(),
            closure_size=0,
        )
        broken = CausalDagBuild(
            governance_events=dag.governance_events,
            event_edges=dag.event_edges,
            workflow_instances=dag.workflow_instances,
            closure_index=tuple(closure),
            diagnostics=dag.diagnostics,
        )

        with self.assertRaisesRegex(DagValidationError, "closure index does not match"):
            validate_causal_dag(broken, resolved, contract=contract)

    def test_closure_is_stable_under_input_partition_order(self) -> None:
        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        forward = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        shuffled_workflows = WorkflowBuild(
            governance_events=tuple(reversed(workflows.governance_events)),
            event_edges=tuple(reversed(workflows.event_edges)),
            workflow_instances=tuple(reversed(workflows.workflow_instances)),
            side_effects=tuple(reversed(workflows.side_effects)),
            diagnostics=workflows.diagnostics,
        )
        reversed_build = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=shuffled_workflows,
            contract=contract,
        )

        self.assertEqual(
            canonical_records_digest(record.as_record() for record in forward.closure_index),
            canonical_records_digest(record.as_record() for record in reversed_build.closure_index),
        )
        self.assertEqual(canonical_records_digest(forward.event_edges), canonical_records_digest(reversed_build.event_edges))

    def test_dag_tables_write_to_parquet(self) -> None:
        import pyarrow.parquet as pq

        resolved, contract, world, catalog, physical, arrivals, workflows = self._small_dependencies()
        dag = build_causal_dag(
            resolved,
            world=world,
            catalog=catalog,
            physical=physical,
            arrivals=arrivals,
            workflows=workflows,
            contract=contract,
        )
        with tempfile.TemporaryDirectory() as tmp:
            written = write_parquet_dataset(dag.table_records(), Path(tmp), contract=contract)
            self.assertEqual(set(dag.table_records()), set(written))
            for table_name, rows in dag.table_records().items():
                observed = pq.read_table(written[table_name])
                self.assertEqual(len(rows), observed.num_rows, table_name)
                self.assertEqual(
                    f"htgl.dataset.v1.{table_name}".encode("utf-8"),
                    observed.schema.metadata[b"schema_id"],
                    table_name,
                )


if __name__ == "__main__":
    unittest.main()
