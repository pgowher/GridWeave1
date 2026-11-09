"""Load and cross-check anomaly, receipt-attack, and privacy controls."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex

from ..smart_grid import REQUIRED_SMART_GRID_SCENARIOS


REQUIRED_ATTACK_TYPES = frozenset({
    "MISSING_RECIPIENT", "HIDDEN_DERIVATIVE", "FORGED_RECEIPT", "MALFORMED_RECEIPT",
    "REPLAY", "BACKDATING", "CONTRADICTION", "DELAY", "COLLUSION", "INCOMPLETE_LINEAGE",
})


@dataclass(frozen=True)
class AdversarialControlBundle:
    fixtures: tuple[Mapping[str, Any], ...]
    receipt_profiles: Mapping[str, Mapping[str, Any]]
    projection_profiles: Mapping[str, Mapping[str, Any]]
    forbidden_fields: frozenset[str]
    hidden_topology_fields: frozenset[str]
    indistinguishability: Mapping[str, Mapping[str, Any]]
    digest: str


def _find(relative: Path) -> Path:
    start = Path(__file__).resolve()
    for candidate in (start.parent, *start.parents):
        path = candidate / relative
        if path.is_file():
            return path
    raise FileNotFoundError(f"cannot locate {relative.as_posix()} from {start}")


def _load(relative: Path, schema_name: str) -> Mapping[str, Any]:
    payload = json.loads(_find(relative).read_text(encoding="utf-8"))
    schema = json.loads(_find(Path("schemas") / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    return payload


def _by_id(rows: list[Mapping[str, Any]], field: str, label: str) -> Mapping[str, Mapping[str, Any]]:
    result = {str(row[field]): row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"duplicate {label} identifiers")
    return dict(sorted(result.items()))


def load_adversarial_controls() -> AdversarialControlBundle:
    """Load the exact independent attack coverage required by Phase 3.3."""

    attacks = _load(
        Path("anomalies") / "paebench_attack_fixtures_v1.json",
        "paegen-attack-fixtures-v1.schema.json",
    )
    receipts = _load(
        Path("evidence") / "paebench_adversarial_receipts_v1.json",
        "paegen-adversarial-receipts-v1.schema.json",
    )
    projections = _load(
        Path("observers") / "paebench_privacy_projections_v1.json",
        "paegen-privacy-projections-v1.schema.json",
    )
    fixture_rows = list(attacks["fixtures"])
    fixture_ids = _by_id(fixture_rows, "fixture_id", "fixture")
    attack_types = {str(row["attack_type"]) for row in fixture_rows}
    if attack_types != REQUIRED_ATTACK_TYPES or len(fixture_ids) != len(REQUIRED_ATTACK_TYPES):
        raise ValueError(
            f"attack catalog must contain one independent fixture per required type; "
            f"missing={sorted(REQUIRED_ATTACK_TYPES - attack_types)} "
            f"unexpected={sorted(attack_types - REQUIRED_ATTACK_TYPES)}"
        )
    receipt_profiles = _by_id(list(receipts["receipt_attacks"]), "profile_id", "receipt profile")
    projection_profiles = _by_id(list(projections["profiles"]), "profile_id", "projection profile")
    indistinguishability = _by_id(
        list(projections["known_indistinguishability"]), "class_id", "indistinguishability class"
    )
    for fixture in fixture_rows:
        if fixture["scenario_id"] not in REQUIRED_SMART_GRID_SCENARIOS:
            raise ValueError(f"fixture {fixture['fixture_id']} references unknown scenario")
        receipt_id = fixture["receipt_profile_id"]
        if receipt_id is not None:
            if receipt_id not in receipt_profiles:
                raise ValueError(f"fixture {fixture['fixture_id']} references unknown receipt profile")
            if receipt_profiles[receipt_id]["attack_type"] != fixture["attack_type"]:
                raise ValueError(f"fixture {fixture['fixture_id']} receipt attack type mismatch")
        if fixture["projection_profile_id"] not in projection_profiles:
            raise ValueError(f"fixture {fixture['fixture_id']} references unknown projection profile")
        indistinguishability_id = fixture["indistinguishability_class"]
        if indistinguishability_id is not None:
            if indistinguishability_id not in indistinguishability:
                raise ValueError(f"fixture {fixture['fixture_id']} has unknown indistinguishability class")
            if fixture["expected_detection"] != "NOT_DETECTABLE":
                raise ValueError(f"fixture {fixture['fixture_id']} indistinguishability must be non-detectable")
    digest = sha256_hex(canonical_json_bytes({
        "attacks": attacks, "receipts": receipts, "projections": projections
    }))
    return AdversarialControlBundle(
        fixtures=tuple(sorted(fixture_rows, key=lambda row: str(row["fixture_id"]))),
        receipt_profiles=receipt_profiles,
        projection_profiles=projection_profiles,
        forbidden_fields=frozenset(str(item) for item in projections["forbidden_fields"]),
        hidden_topology_fields=frozenset(str(item) for item in projections["hidden_topology_fields"]),
        indistinguishability=indistinguishability,
        digest=digest,
    )

