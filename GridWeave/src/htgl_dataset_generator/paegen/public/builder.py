"""Build PaEGen observer inputs solely from pre-sanitized release views."""

from __future__ import annotations

from typing import Mapping

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex
from htgl_dataset_generator.observers import ObserverReleaseView

from .._canonical import artifact
from ..models import (
    FECM_MODEL_VERSION,
    PAEGEN_INTERFACE_VERSION,
    PAEGEN_SCHEMA_VERSION,
    PaEGenArtifact,
)


OBSERVER_SCHEMA_ID = "https://pae.local/schema/paegen-observer-bundle/v1"


def build_observer_artifacts(
    *,
    run_id: str,
    scenario_id: str,
    replicate_id: int,
    config_sha256: str,
    release_views: Mapping[str, ObserverReleaseView],
) -> Mapping[str, PaEGenArtifact]:
    """Package sanitized records without accepting oracle or source-mapping inputs."""

    outputs: dict[str, PaEGenArtifact] = {}
    for profile_id, view in sorted(release_views.items()):
        if view.access_class == "evaluator_only":
            continue
        records = [dict(record) for record in view.records]
        payload = {
            "schema_version": PAEGEN_SCHEMA_VERSION,
            "interface_version": PAEGEN_INTERFACE_VERSION,
            "model_version": FECM_MODEL_VERSION,
            "run_id": run_id,
            "scenario_id": scenario_id,
            "replicate_id": replicate_id,
            "config_sha256": config_sha256,
            "observer_profile_id": profile_id,
            "access_class": view.access_class,
            "record_schema_profile_id": view.schema_profile_id,
            "record_count": len(records),
            "record_digest": sha256_hex(canonical_json_bytes(records)),
            "records": records,
        }
        outputs[profile_id] = artifact(OBSERVER_SCHEMA_ID, payload)
    return dict(sorted(outputs.items()))

