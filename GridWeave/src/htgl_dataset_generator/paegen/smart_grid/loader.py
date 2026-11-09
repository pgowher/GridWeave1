"""Schema-backed loading and referential validation of scenario profiles."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes, sha256_hex


SCENARIO_SCHEMA_ID = "https://pae.local/schema/paegen-smart-grid-scenario/v1"
SCENARIO_SCHEMA_FILE = "paegen-smart-grid-scenario-v1.schema.json"
REQUIRED_SMART_GRID_SCENARIOS = frozenset({
    "PBE-SG-DEMAND-RESPONSE-TERMINATION",
    "PBE-SG-SUPPLIER-SWITCHING",
    "PBE-SG-CONSENT-WITHDRAWAL",
    "PBE-SG-EV-CHARGING-TERMINATION",
    "PBE-SG-RETENTION-EXPIRY",
    "PBE-SG-REGULATORY-ERASURE",
    "PBE-SG-BILLING-SETTLEMENT-EXCEPTION",
})
REQUIRED_VARIANT_CLASSES = frozenset({
    "successful_closure",
    "partial_or_unverifiable",
    "adversarial_or_disputed",
})


@dataclass(frozen=True)
class SmartGridScenarioDefinition:
    scenario_id: str
    payload: Mapping[str, Any]
    sha256: str
    source_path: Path


def _find_file(relative: Path) -> Path:
    start = Path(__file__).resolve()
    for candidate in (start.parent, *start.parents):
        path = candidate / relative
        if path.exists():
            return path
    raise FileNotFoundError(f"cannot locate {relative.as_posix()} from {start}")


def _default_directory() -> Path:
    return _find_file(Path("configs") / "pae_bench" / "smart_grid")


def _schema_path() -> Path:
    return _find_file(Path("schemas") / SCENARIO_SCHEMA_FILE)


def _unique_ids(rows: list[Mapping[str, Any]], field: str, label: str) -> set[str]:
    values = [str(row[field]) for row in rows]
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label} identifiers")
    return set(values)


def _validate_references(payload: Mapping[str, Any]) -> None:
    organizations = list(payload["organizations"])
    repositories = list(payload["repositories"])
    assets = list(payload["assets"])
    obligations = list(payload["obligations"])
    exceptions = list(payload["exceptions"])
    variants = list(payload["variants"])
    organization_ids = _unique_ids(organizations, "organization_id", "organization")
    repository_ids = _unique_ids(repositories, "repository_id", "repository")
    asset_ids = _unique_ids(assets, "asset_id", "asset")
    obligation_ids = _unique_ids(obligations, "template_id", "obligation template")
    _unique_ids(exceptions, "exception_id", "exception")
    _unique_ids(variants, "variant_id", "variant")
    roles = {str(role) for row in organizations for role in row["roles"]}
    for row in repositories:
        if row["organization_id"] not in organization_ids:
            raise ValueError(f"repository {row['repository_id']} has unknown organization")
    for row in assets:
        if row["repository_id"] not in repository_ids:
            raise ValueError(f"asset {row['asset_id']} has unknown repository")
        unknown = set(row["parent_asset_ids"]) - asset_ids
        if unknown or row["asset_id"] in row["parent_asset_ids"]:
            raise ValueError(f"asset {row['asset_id']} has invalid lineage parents {sorted(unknown)}")
    for row in obligations:
        unknown = set(row["asset_ids"]) - asset_ids
        if unknown:
            raise ValueError(f"obligation {row['template_id']} has unknown assets {sorted(unknown)}")
        if row["responsible_role"] not in roles:
            raise ValueError(f"obligation {row['template_id']} has unassigned responsible role")
    covered_asset_ids = {
        str(asset_id) for row in obligations for asset_id in row["asset_ids"]
    }
    uncovered_asset_ids = asset_ids - covered_asset_ids
    if uncovered_asset_ids:
        raise ValueError(
            "assets outside the declared obligation set "
            f"{sorted(uncovered_asset_ids)}"
        )
    for row in exceptions:
        if row["applies_to_obligation_id"] not in obligation_ids:
            raise ValueError(f"exception {row['exception_id']} has unknown obligation")
    classes = {str(row["variant_class"]) for row in variants}
    if classes != REQUIRED_VARIANT_CLASSES:
        raise ValueError(f"variant classes must be exactly {sorted(REQUIRED_VARIANT_CLASSES)}")
    for variant in variants:
        for mutation in variant["mutations"]:
            if mutation["target_obligation_id"] not in obligation_ids:
                raise ValueError(
                    f"variant {variant['variant_id']} targets unknown obligation "
                    f"{mutation['target_obligation_id']}"
                )


def load_smart_grid_scenarios(
    directory: str | Path | None = None,
    *,
    require_canonical_catalog: bool = True,
) -> tuple[SmartGridScenarioDefinition, ...]:
    """Load schema-valid profiles, optionally enforcing the canonical catalog."""

    root = Path(directory).resolve() if directory is not None else _default_directory()
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    definitions: list[SmartGridScenarioDefinition] = []
    for path in sorted(root.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        validator.validate(payload)
        _validate_references(payload)
        definitions.append(SmartGridScenarioDefinition(
            scenario_id=str(payload["scenario_id"]),
            payload=payload,
            sha256=sha256_hex(canonical_json_bytes(payload)),
            source_path=path,
        ))
    ids = {item.scenario_id for item in definitions}
    if require_canonical_catalog and ids != REQUIRED_SMART_GRID_SCENARIOS:
        raise ValueError(
            f"smart-grid catalog mismatch; missing={sorted(REQUIRED_SMART_GRID_SCENARIOS - ids)} "
            f"unexpected={sorted(ids - REQUIRED_SMART_GRID_SCENARIOS)}"
        )
    return tuple(sorted(definitions, key=lambda item: item.scenario_id))
