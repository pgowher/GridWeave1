"""Independent campaign validation for schemas, digests, outcomes, and privacy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex

from .compiler import AdversarialCampaign
from .loader import REQUIRED_ATTACK_TYPES, AdversarialControlBundle, load_adversarial_controls


def _find(relative: Path) -> Path:
    start = Path(__file__).resolve()
    for candidate in (start.parent, *start.parents):
        path = candidate / relative
        if path.is_file():
            return path
    raise FileNotFoundError(f"cannot locate {relative.as_posix()} from {start}")


def _keys(value: Any):
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _keys(child)


def validate_adversarial_campaign(
    campaign: AdversarialCampaign,
    controls: AdversarialControlBundle | None = None,
) -> None:
    """Revalidate a compiled campaign without trusting its compiler labels."""

    bundle = controls or load_adversarial_controls()
    schemas = {}
    for name in ("paegen-ground-truth-bundle-v1.schema.json", "paegen-observer-bundle-v1.schema.json"):
        schema = json.loads(_find(Path("schemas") / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schemas[name] = Draft202012Validator(schema)
    types = {fixture.attack_type for fixture in campaign.fixtures}
    if types != REQUIRED_ATTACK_TYPES or len(campaign.fixtures) != len(REQUIRED_ATTACK_TYPES):
        raise ValueError("campaign does not contain exactly one fixture per required attack type")
    if campaign.control_digest != bundle.digest:
        raise ValueError("campaign control digest does not match the loaded controls")
    for fixture in campaign.fixtures:
        schemas["paegen-ground-truth-bundle-v1.schema.json"].validate(
            fixture.clean_ground_truth.payload
        )
        schemas["paegen-ground-truth-bundle-v1.schema.json"].validate(
            fixture.attacked_ground_truth.payload
        )
        if fixture.clean_ground_truth.sha256 != sha256_hex(
            canonical_json_bytes(fixture.clean_ground_truth.payload)
        ):
            raise ValueError(f"{fixture.fixture_id}: clean trace digest mismatch")
        if fixture.attacked_ground_truth.sha256 != sha256_hex(
            canonical_json_bytes(fixture.attacked_ground_truth.payload)
        ):
            raise ValueError(f"{fixture.fixture_id}: attacked trace digest mismatch")
        outcome = fixture.attacked_ground_truth.payload["cases"][0]["closure_ground_truth"]["outcome"]
        if outcome != fixture.expected_oracle_outcome:
            raise ValueError(f"{fixture.fixture_id}: expected oracle outcome mismatch")
        for observer in fixture.observer_views.values():
            schemas["paegen-observer-bundle-v1.schema.json"].validate(observer.payload)
            collisions = set(_keys(observer.payload)) & (
                bundle.forbidden_fields | bundle.hidden_topology_fields
            )
            if collisions:
                raise ValueError(
                    f"{fixture.fixture_id}: restricted projection leaks {sorted(collisions)}"
                )

