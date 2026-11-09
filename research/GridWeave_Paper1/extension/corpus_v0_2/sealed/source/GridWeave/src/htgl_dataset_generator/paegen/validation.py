"""Machine-readable PaEGen schema and boundary validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .models import PaEGenBuild


SCHEMA_FILES = {
    "https://pae.local/schema/paegen-ground-truth/v1": "paegen-ground-truth-bundle-v1.schema.json",
    "https://pae.local/schema/paegen-observer-bundle/v1": "paegen-observer-bundle-v1.schema.json",
    "https://pae.local/schema/paegen-scenario-manifest/v1": "paegen-scenario-manifest-v1.schema.json",
}
FORBIDDEN_OBSERVER_KEYS = frozenset({
    "closure_ground_truth",
    "ground_truth",
    "omission_truth",
    "source_event_id",
    "source_workflow_id",
    "adversarial_cases",
    "verification_status_truth",
    "is_conformant_world_truth",
})


def _schema_root() -> Path:
    filename = next(iter(SCHEMA_FILES.values()))
    start = Path(__file__).resolve()
    for candidate in (start.parent, *start.parents):
        schema_root = candidate / "schemas"
        if (schema_root / filename).is_file():
            return schema_root
    raise FileNotFoundError(f"cannot locate packaged PaEGen schemas from {start}")


def _walk_keys(value: Any):
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _walk_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_keys(child)


def validate_paegen_build(build: PaEGenBuild, *, schema_root: Path | None = None) -> None:
    """Validate every artifact and reassert the public/oracle isolation boundary."""

    root = schema_root or _schema_root()
    validators = {}
    import json
    for schema_id, filename in SCHEMA_FILES.items():
        schema = json.loads((root / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validators[schema_id] = Draft202012Validator(schema)
    for replica in build.replicas:
        validators[replica.ground_truth.schema_id].validate(replica.ground_truth.payload)
        validators[replica.scenario_manifest.schema_id].validate(replica.scenario_manifest.payload)
        for observer in replica.observer_views.values():
            validators[observer.schema_id].validate(observer.payload)
            leaked = sorted(set(_walk_keys(observer.payload)) & FORBIDDEN_OBSERVER_KEYS)
            if leaked:
                raise ValueError(f"observer artifact contains evaluator-only keys: {leaked}")
