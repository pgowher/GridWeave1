from __future__ import annotations

import copy
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from htgl_dataset_generator.config import (  # noqa: E402
    build_run_plan,
    load_config,
    resolve_config,
    resolve_config_file,
)
from htgl_dataset_generator.experiments import (  # noqa: E402
    CheckpointIntegrityError,
    ParallelExecutionError,
    ParallelExecutionPolicy,
    ReplicateContext,
    orchestrate_pipeline_through_dag,
    orchestrate_replicates,
    resolve_execution_capacity,
)
from htgl_dataset_generator.schemas import load_contract, validate_record  # noqa: E402
from htgl_dataset_generator.seeds import (  # noqa: E402
    CounterRng,
    canonical_records_digest,
    deterministic_uuid,
    seed_stream_records,
)


def _row_by_stream(rows: tuple[Mapping[str, Any], ...], stream_name: str) -> Mapping[str, Any]:
    for row in rows:
        if row["stream_name"] == stream_name:
            return row
    raise AssertionError(f"seed stream not found: {stream_name}")


def _scenario_row(
    rows: tuple[Mapping[str, Any], ...],
    *,
    scenario_id: str,
    replicate_id: int,
    component: str,
    partition: str = "global",
) -> Mapping[str, Any]:
    return _row_by_stream(
        rows,
        (
            f"scenario={scenario_id}|replicate={replicate_id:04d}|"
            f"component={component}|partition={partition}"
        ),
    )


def _crn_row(
    rows: tuple[Mapping[str, Any], ...],
    *,
    group: str,
    replicate_id: int,
    component: str,
    partition: str = "global",
) -> Mapping[str, Any]:
    return _row_by_stream(
        rows,
        (
            f"crn={group}|replicate={replicate_id:04d}|"
            f"component={component}|partition={partition}"
        ),
    )


class SeedStreamTests(unittest.TestCase):
    def test_seed_stream_records_are_schema_valid_and_digest_stable(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        contract = load_contract()

        first = seed_stream_records(resolved, contract=contract)
        second = seed_stream_records(resolved, contract=contract)

        self.assertEqual(first, second)
        self.assertEqual(canonical_records_digest(first), canonical_records_digest(reversed(first)))
        self.assertGreater(len(first), 0)
        for row in first:
            validate_record(contract, "seed_stream", row)
            self.assertRegex(str(row["seed_material_hex"]), r"^[0-9a-f]{64}$")
            self.assertRegex(
                str(row["deterministic_id_namespace"]),
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            )

    def test_different_replicates_have_independent_component_streams(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        rows = seed_stream_records(resolved)
        arrivals_seed_materials = {
            _scenario_row(
                rows,
                scenario_id="SCN-REPRESENTED-450M",
                replicate_id=replicate_id,
                component="S05.arrivals",
            )["seed_material_hex"]
            for replicate_id in range(resolved.run.replicate_count)
        }

        self.assertEqual(30, resolved.run.replicate_count)
        self.assertEqual(30, len(build_run_plan(resolved)))
        self.assertEqual(30, len(arrivals_seed_materials))

    def test_deterministic_ids_are_canonical_and_content_sensitive(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        namespace = str(
            _scenario_row(
                seed_stream_records(resolved),
                scenario_id="SCN-REFERENCE-10K",
                replicate_id=0,
                component="S06.workflows",
            )["deterministic_id_namespace"]
        )

        first = deterministic_uuid(namespace, "workflow_instance", {"b": 2, "a": 1})
        second = deterministic_uuid(namespace, "workflow_instance", {"a": 1, "b": 2})
        changed = deterministic_uuid(namespace, "workflow_instance", {"a": 1, "b": 3})

        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_counter_rng_is_addressed_not_order_dependent(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "reference_10k.json")
        seed_material = str(
            _scenario_row(
                seed_stream_records(resolved),
                scenario_id="SCN-REFERENCE-10K",
                replicate_id=0,
                component="S05.arrivals",
            )["seed_material_hex"]
        )

        rng = CounterRng(seed_material)
        direct = rng.uniform("arrival-timestamp", 25)
        _ = [rng.uniform("arrival-timestamp", index) for index in range(50)]
        after_other_draws = rng.uniform("arrival-timestamp", 25)

        self.assertEqual(direct, after_other_draws)
        self.assertNotEqual(direct, rng.uniform("arrival-timestamp", 26))
        self.assertNotEqual(direct, rng.uniform("arrival-mark", 25))
        self.assertGreaterEqual(direct, 0.0)
        self.assertLess(direct, 1.0)

    def test_worker_schedule_does_not_change_replicate_outputs(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        active = 0
        maximum_active = 0
        lock = threading.Lock()

        def pipeline(context: ReplicateContext) -> Mapping[str, Any]:
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.01)
            rng = context.rng("S05.arrivals")
            try:
                return {
                    "scenario_id": context.scenario_id,
                    "replicate_id": context.replicate_id,
                    "arrival_probe": rng.randint("arrival-count", 0, 0, 10_000),
                    "event_id": context.deterministic_id(
                        "S06.workflows",
                        "governance_event",
                        {
                            "scenario_id": context.scenario_id,
                            "replicate_id": context.replicate_id,
                            "ordinal": 0,
                        },
                    ),
                }
            finally:
                with lock:
                    active -= 1

        one_worker = orchestrate_replicates(resolved, pipeline, worker_count=1)
        maximum_active = 0
        seven_workers = orchestrate_replicates(
            resolved,
            pipeline,
            worker_count=7,
            execution_policy=ParallelExecutionPolicy(
                worker_count=7,
                max_in_flight=4,
                memory_budget_bytes=8 * 1024**3,
            ),
        )

        self.assertEqual(30, len(one_worker))
        self.assertEqual(30, len(seven_workers))
        self.assertGreater(maximum_active, 1)
        self.assertLessEqual(maximum_active, 4)
        self.assertEqual(
            canonical_records_digest(result.output for result in one_worker),
            canonical_records_digest(result.output for result in seven_workers),
        )
        self.assertEqual(
            canonical_records_digest(
                {
                    "scenario_id": result.run_plan.scenario_id,
                    "replicate_id": result.run_plan.replicate_id,
                    "seed_stream_digest": result.seed_stream_digest,
                }
                for result in one_worker
            ),
            canonical_records_digest(
                {
                    "scenario_id": result.run_plan.scenario_id,
                    "replicate_id": result.run_plan.replicate_id,
                    "seed_stream_digest": result.seed_stream_digest,
                }
                for result in seven_workers
            ),
        )

    def test_checkpoint_resume_is_verified_and_tampering_fails_closed(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["run"]["replicate_count"]["value"] = 3
        raw["validation"]["repetition_count"]["value"] = 3
        resolved = resolve_config(raw)

        def pipeline(context: ReplicateContext) -> Mapping[str, Any]:
            return {
                "replicate_id": context.replicate_id,
                "probe": context.rng("S05.arrivals").uint64("checkpoint", 0),
            }

        with tempfile.TemporaryDirectory() as tmp:
            original = orchestrate_replicates(
                resolved,
                pipeline,
                worker_count=2,
                execution_policy=ParallelExecutionPolicy(
                    worker_count=2,
                    memory_budget_bytes=4 * 1024**3,
                ),
                checkpoint_dir=tmp,
                checkpoint_namespace="unit-resume",
            )

            def must_not_execute(_context: ReplicateContext) -> Mapping[str, Any]:
                raise AssertionError("verified checkpoints should satisfy every replicate")

            restored = orchestrate_replicates(
                resolved,
                must_not_execute,
                worker_count=2,
                execution_policy=ParallelExecutionPolicy(
                    worker_count=2,
                    memory_budget_bytes=4 * 1024**3,
                ),
                checkpoint_dir=tmp,
                checkpoint_namespace="unit-resume",
                resume=True,
            )
            self.assertEqual(original, restored)

            payload = next(Path(tmp).rglob("*.pickle"))
            damaged = bytearray(payload.read_bytes())
            damaged[len(damaged) // 2] ^= 0x01
            payload.write_bytes(bytes(damaged))
            with self.assertRaisesRegex(CheckpointIntegrityError, "payload digest mismatch"):
                orchestrate_replicates(
                    resolved,
                    must_not_execute,
                    worker_count=1,
                    checkpoint_dir=tmp,
                    checkpoint_namespace="unit-resume",
                    resume=True,
                )

    def test_memory_budget_applies_backpressure_and_can_fail_before_generation(self) -> None:
        resolved = resolve_config_file(REPO_ROOT / "configs" / "represented_450m.json")
        capacity = resolve_execution_capacity(
            resolved,
            ParallelExecutionPolicy(worker_count=8),
            task_count=resolved.run.replicate_count,
        )
        self.assertEqual(1, capacity.effective_worker_count)
        self.assertTrue(capacity.backpressure_active)
        with self.assertRaisesRegex(ParallelExecutionError, "exceeds the declared memory budget"):
            resolve_execution_capacity(
                resolved,
                ParallelExecutionPolicy(
                    worker_count=1,
                    memory_budget_bytes=64 * 1024**2,
                ),
                task_count=1,
            )

    def test_every_configured_replicate_runs_the_stochastic_pipeline_through_dag(self) -> None:
        raw = copy.deepcopy(load_config(REPO_ROOT / "configs" / "small_deterministic.json"))
        raw["run"]["replicate_count"]["value"] = 2
        raw["validation"]["repetition_count"]["value"] = 2
        resolved = resolve_config(raw)

        results = orchestrate_pipeline_through_dag(resolved, worker_count=2)

        self.assertEqual([0, 1], [result.run_plan.replicate_id for result in results])
        for result in results:
            self.assertGreater(len(result.table_digests), 0)
            self.assertIn("actor", result.table_digests)
            self.assertIn("raw_meter_reading", result.table_digests)
            self.assertIn("arrival", result.table_digests)
            self.assertIn("event_edge", result.table_digests)
        for table_name in ("actor", "raw_meter_reading", "arrival", "governance_event", "event_edge"):
            self.assertNotEqual(
                results[0].table_digests[table_name],
                results[1].table_digests[table_name],
                table_name,
            )

    def test_common_random_group_streams_are_shared_without_collapsing_scenario_streams(self) -> None:
        base = load_config(REPO_ROOT / "configs" / "reference_10k.json")
        variant_a = copy.deepcopy(base)
        variant_b = copy.deepcopy(base)
        variant_a["run"]["root_seed"]["value"] = "HTGL-CRN-TEST-SEED"
        variant_b["run"]["root_seed"]["value"] = "HTGL-CRN-TEST-SEED"
        variant_a["run"]["run_id"]["value"] = "RUN-CRN-A"
        variant_b["run"]["run_id"]["value"] = "RUN-CRN-B"
        variant_a["run"]["scenario_id"]["value"] = "SCN-CRN-A"
        variant_b["run"]["scenario_id"]["value"] = "SCN-CRN-B"
        variant_a["run"]["selected_scenario_ids"]["value"] = ["SCN-CRN-A"]
        variant_b["run"]["selected_scenario_ids"]["value"] = ["SCN-CRN-B"]
        variant_a["sampling"]["common_random_groups"]["value"] = ["SHARED-CRN"]
        variant_b["sampling"]["common_random_groups"]["value"] = ["SHARED-CRN"]

        resolved_a = resolve_config(variant_a)
        resolved_b = resolve_config(variant_b)
        rows_a = seed_stream_records(resolved_a)
        rows_b = seed_stream_records(resolved_b)

        self.assertEqual(
            _crn_row(
                rows_a,
                group="SHARED-CRN",
                replicate_id=0,
                component="S05.arrivals",
            )["seed_material_hex"],
            _crn_row(
                rows_b,
                group="SHARED-CRN",
                replicate_id=0,
                component="S05.arrivals",
            )["seed_material_hex"],
        )
        self.assertNotEqual(
            _scenario_row(
                rows_a,
                scenario_id="SCN-CRN-A",
                replicate_id=0,
                component="S05.arrivals",
            )["seed_material_hex"],
            _scenario_row(
                rows_b,
                scenario_id="SCN-CRN-B",
                replicate_id=0,
                component="S05.arrivals",
            )["seed_material_hex"],
        )


if __name__ == "__main__":
    unittest.main()
