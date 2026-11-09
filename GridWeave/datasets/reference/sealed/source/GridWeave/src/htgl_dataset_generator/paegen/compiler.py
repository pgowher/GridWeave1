"""Top-level PaEGen 1.0 compiler over the established generation pipeline."""

from __future__ import annotations

from typing import Iterable

from htgl_dataset_generator.config import ResolvedConfig
from htgl_dataset_generator.experiments import orchestrate_pipeline_through_observers

from ._canonical import artifact
from .models import (
    FECM_MODEL_VERSION,
    PAEGEN_INTERFACE_VERSION,
    PAEGEN_SCHEMA_VERSION,
    PaEGenBuild,
    PaEGenReplica,
)
from .oracle import build_ground_truth_artifact
from .public import build_observer_artifacts


MANIFEST_SCHEMA_ID = "https://pae.local/schema/paegen-scenario-manifest/v1"


def compile_paegen_results(results: Iterable[object]) -> PaEGenBuild:
    """Compile already-generated observer-stage results into PaEGen artifacts."""

    replicas: list[PaEGenReplica] = []
    run_ids: set[str] = set()
    for result in sorted(results, key=lambda item: (item.run_plan.scenario_id, item.run_plan.replicate_id)):
        run_ids.add(result.run_plan.run_id)
        if not result.artifacts.observers.leakage_diagnostics.passed:
            raise ValueError(
                f"scenario={result.run_plan.scenario_id} replicate={result.run_plan.replicate_id}: "
                "observer leakage gate did not pass"
            )
        ground_truth = build_ground_truth_artifact(result)
        observer_views = build_observer_artifacts(
            run_id=result.run_plan.run_id,
            scenario_id=result.run_plan.scenario_id,
            replicate_id=result.run_plan.replicate_id,
            config_sha256=result.run_plan.config_sha256,
            release_views=result.artifacts.observers.release_views,
        )
        manifest_payload = {
            "schema_version": PAEGEN_SCHEMA_VERSION,
            "interface_version": PAEGEN_INTERFACE_VERSION,
            "model_version": FECM_MODEL_VERSION,
            "run_id": result.run_plan.run_id,
            "scenario_id": result.run_plan.scenario_id,
            "replicate_id": result.run_plan.replicate_id,
            "config_sha256": result.run_plan.config_sha256,
            "seed_stream_digest": result.seed_stream_digest,
            "case_count": len(ground_truth.payload["cases"]),
            "sealed_ground_truth": {
                "schema_id": ground_truth.schema_id,
                "sha256": ground_truth.sha256,
            },
            "observer_views": [
                {
                    "observer_profile_id": profile_id,
                    "access_class": item.payload["access_class"],
                    "schema_id": item.schema_id,
                    "sha256": item.sha256,
                    "record_count": item.payload["record_count"],
                }
                for profile_id, item in observer_views.items()
            ],
        }
        manifest = artifact(MANIFEST_SCHEMA_ID, manifest_payload)
        replicas.append(PaEGenReplica(
            scenario_id=result.run_plan.scenario_id,
            replicate_id=result.run_plan.replicate_id,
            ground_truth=ground_truth,
            observer_views=observer_views,
            scenario_manifest=manifest,
        ))
    if not replicas:
        raise ValueError("PaEGen requires at least one generated scenario replicate")
    if len(run_ids) != 1:
        raise ValueError(f"PaEGen results span multiple run IDs: {sorted(run_ids)}")
    return PaEGenBuild(
        run_id=next(iter(run_ids)),
        interface_version=PAEGEN_INTERFACE_VERSION,
        model_version=FECM_MODEL_VERSION,
        replicas=tuple(replicas),
    )


def build_paegen(resolved_config: ResolvedConfig, *, worker_count: int = 1) -> PaEGenBuild:
    """Run the existing generator through observer projection and compile PaEGen v1."""

    return compile_paegen_results(
        orchestrate_pipeline_through_observers(resolved_config, worker_count=worker_count)
    )

