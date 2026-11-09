"""Pinned Step 19 field-level interoperability mapping registry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from htgl_dataset_generator.policy.language import canonical_json
from htgl_dataset_generator.schemas import load_contract

from .models import (
    AdapterContractError,
    AdapterProfile,
    AdapterRegistry,
    FieldMapping,
)


REGISTRY_PATH = Path(__file__).with_name("adapter_mappings_v1.json")
SUPPORTED_ADAPTERS = frozenset(
    {"jsonl_debug_view", "csv", "xes", "jsonld", "cim", "green_button", "sqlite"}
)
DISPOSITIONS = frozenset({"mapped", "lossy", "unsupported"})
CARDINALITIES = frozenset({"one_to_one", "one_to_many", "many_to_one", "zero_or_one"})
OBSERVER_SCHEMA = "observer_release"
OBSERVER_TOP_LEVEL_FIELDS = frozenset(
    {
        "observer_record_id",
        "observer_ref",
        "projection_profile_id",
        "visible_timestamp",
        "visibility_class",
        "redacted_field_paths",
        "schema_profile_id",
        "payload",
        "projection_digest",
    }
)
OBSERVER_PAYLOAD_FIELDS = frozenset(
    {
        "actor_classes",
        "causal_parent_refs",
        "database_kind",
        "event_family",
        "event_ref",
        "event_type",
        "evidence_present",
        "evidence_receipt_count",
        "evidence_types",
        "inferred_summary",
        "object_type",
        "policy_purpose_id",
        "workflow_ref",
        "workflow_state_after",
        "workflow_state_before",
    }
)


def load_adapter_registry(path: Path | None = None) -> AdapterRegistry:
    source_path = path.resolve() if path is not None else REGISTRY_PATH
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdapterContractError(f"adapter mapping registry not found: {source_path}") from exc
    except json.JSONDecodeError as exc:
        raise AdapterContractError(f"invalid adapter mapping registry JSON: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise AdapterContractError("adapter mapping registry root must be an object")
    _exact_keys(raw, {"registry_id", "version", "source", "profiles"}, "registry")
    profiles_raw = raw["profiles"]
    if not isinstance(profiles_raw, Mapping):
        raise AdapterContractError("adapter mapping profiles must be an object")
    if set(profiles_raw) != SUPPORTED_ADAPTERS:
        raise AdapterContractError(
            f"adapter registry profile coverage mismatch missing={sorted(SUPPORTED_ADAPTERS-set(profiles_raw))} extra={sorted(set(profiles_raw)-SUPPORTED_ADAPTERS)}"
        )
    profiles = {
        adapter_id: _profile(adapter_id, profile_raw)
        for adapter_id, profile_raw in sorted(profiles_raw.items())
    }
    _validate_locked_source_coverage(profiles)
    digest = hashlib.sha256(canonical_json(raw).encode("utf-8")).hexdigest()
    return AdapterRegistry(
        registry_id=_text(raw["registry_id"], "registry_id"),
        version=_version(raw["version"], "version"),
        source=_text(raw["source"], "source"),
        sha256=digest,
        profiles=profiles,
    )


def _validate_locked_source_coverage(
    profiles: Mapping[str, AdapterProfile],
) -> None:
    contract = load_contract()
    expected = {
        OBSERVER_SCHEMA: OBSERVER_TOP_LEVEL_FIELDS
        | {f"payload.{field}" for field in OBSERVER_PAYLOAD_FIELDS},
        "network_area": frozenset(
            field.name for field in contract.table("network_area").fields
        ),
        "raw_network_state": frozenset(
            field.name for field in contract.table("raw_network_state").fields
        ),
        "raw_meter_reading": frozenset(
            field.name for field in contract.table("raw_meter_reading").fields
        ),
    }
    for adapter_id, profile in profiles.items():
        for source_schema in profile.source_schemas:
            actual = {
                mapping.source_field
                for mapping in profile.mappings
                if mapping.source_schema == source_schema
            }
            wanted = set(expected[source_schema])
            if actual != wanted:
                raise AdapterContractError(
                    f"{adapter_id}.{source_schema}: locked field coverage mismatch "
                    f"missing={sorted(wanted-actual)} extra={sorted(actual-wanted)}"
                )


def _profile(adapter_id: str, raw: Any) -> AdapterProfile:
    if not isinstance(raw, Mapping):
        raise AdapterContractError(f"profile {adapter_id} must be an object")
    _exact_keys(
        raw,
        {
            "mapping_profile_id",
            "profile_version",
            "target_standard",
            "target_standard_version",
            "source_schemas",
            "structural_losses",
            "mapping_defaults",
            "mappings",
        },
        f"profile {adapter_id}",
    )
    source_schemas = _text_tuple(raw["source_schemas"], f"{adapter_id}.source_schemas", True)
    losses = _text_tuple(raw["structural_losses"], f"{adapter_id}.structural_losses", False)
    defaults = _mapping_defaults(adapter_id, raw["mapping_defaults"])
    mappings_raw = raw["mappings"]
    if not isinstance(mappings_raw, Mapping) or not mappings_raw:
        raise AdapterContractError(f"{adapter_id}.mappings must be a non-empty object")
    if set(mappings_raw) != set(source_schemas):
        raise AdapterContractError(
            f"{adapter_id}.mappings source coverage mismatch "
            f"missing={sorted(set(source_schemas)-set(mappings_raw))} "
            f"extra={sorted(set(mappings_raw)-set(source_schemas))}"
        )
    mappings: list[FieldMapping] = []
    seen: set[tuple[str, str]] = set()
    for source_schema, field_map in sorted(mappings_raw.items()):
        if not isinstance(field_map, Mapping) or not field_map:
            raise AdapterContractError(
                f"{adapter_id}.mappings.{source_schema} must be a non-empty object"
            )
        for source_field, target_definition in sorted(field_map.items()):
            label = f"{adapter_id}.mappings.{source_schema}.{source_field}"
            source_field = _text(source_field, f"{label}.source_field")
            key = (source_schema, source_field)
            if key in seen:
                raise AdapterContractError(f"{adapter_id} duplicates field mapping {key}")
            seen.add(key)
            values = _mapping_values(label, target_definition, defaults)
            mappings.append(
                FieldMapping(
                    adapter_id=adapter_id,
                    mapping_profile_id=_text(raw["mapping_profile_id"], "mapping_profile_id"),
                    profile_version=_version(raw["profile_version"], "profile_version"),
                    target_standard=_text(raw["target_standard"], "target_standard"),
                    target_standard_version=_version(
                        raw["target_standard_version"], "target_standard_version"
                    ),
                    source_schema=source_schema,
                    source_field=source_field,
                    target_field=values["target_field"],
                    cardinality=values["cardinality"],
                    transformation=values["transformation"],
                    vocabulary_conversion=values["vocabulary_conversion"],
                    disposition=values["disposition"],
                    rationale=values["rationale"],
                )
            )
    return AdapterProfile(
        adapter_id=adapter_id,
        mapping_profile_id=_text(raw["mapping_profile_id"], "mapping_profile_id"),
        profile_version=_version(raw["profile_version"], "profile_version"),
        target_standard=_text(raw["target_standard"], "target_standard"),
        target_standard_version=_version(raw["target_standard_version"], "target_standard_version"),
        source_schemas=source_schemas,
        structural_losses=losses,
        mappings=tuple(sorted(mappings, key=lambda value: (value.source_schema, value.source_field))),
    )


def _mapping_defaults(adapter_id: str, raw: Any) -> dict[str, Any]:
    label = f"{adapter_id}.mapping_defaults"
    if not isinstance(raw, Mapping):
        raise AdapterContractError(f"{label} must be an object")
    expected = {
        "cardinality",
        "transformation",
        "vocabulary_conversion",
        "disposition",
        "rationale",
    }
    _exact_keys(raw, expected, label)
    return _validated_mapping_values(label, {"target_field": "__default__", **raw})


def _mapping_values(
    label: str, raw: Any, defaults: Mapping[str, Any]
) -> dict[str, Any]:
    if isinstance(raw, str):
        values = {**defaults, "target_field": _text(raw, f"{label}.target_field")}
    elif isinstance(raw, Mapping):
        expected = {
            "target_field",
            "cardinality",
            "transformation",
            "vocabulary_conversion",
            "disposition",
            "rationale",
        }
        _exact_keys(raw, expected, label)
        values = dict(raw)
    else:
        raise AdapterContractError(
            f"{label} must be a target-field string or a complete mapping override"
        )
    return _validated_mapping_values(label, values)


def _validated_mapping_values(label: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    disposition = _text(raw["disposition"], f"{label}.disposition")
    if disposition not in DISPOSITIONS:
        raise AdapterContractError(f"{label} has unknown disposition {disposition!r}")
    cardinality = _text(raw["cardinality"], f"{label}.cardinality")
    if cardinality not in CARDINALITIES:
        raise AdapterContractError(f"{label} has unknown cardinality {cardinality!r}")
    target_field = raw["target_field"]
    if target_field is not None:
        target_field = _text(target_field, f"{label}.target_field")
    if disposition != "unsupported" and target_field is None:
        raise AdapterContractError(f"{label} must name a target field")
    if disposition == "unsupported" and target_field is not None:
        raise AdapterContractError(
            f"{label} unsupported mapping cannot name a target field"
        )
    vocabulary = raw["vocabulary_conversion"]
    if vocabulary is not None:
        vocabulary = _text(vocabulary, f"{label}.vocabulary_conversion")
    return {
        "target_field": target_field,
        "cardinality": cardinality,
        "transformation": _text(raw["transformation"], f"{label}.transformation"),
        "vocabulary_conversion": vocabulary,
        "disposition": disposition,
        "rationale": _text(raw["rationale"], f"{label}.rationale"),
    }


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise AdapterContractError(
            f"{label} keys mismatch missing={sorted(expected-set(value))} extra={sorted(set(value)-expected)}"
        )


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterContractError(f"{label} must be a non-empty string")
    return value


def _version(value: Any, label: str) -> str:
    text = _text(value, label)
    if text.lower() in {"latest", "current", "head", "dev"}:
        raise AdapterContractError(f"{label} cannot use an unpinned version")
    return text


def _text_tuple(value: Any, label: str, non_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (non_empty and not value):
        raise AdapterContractError(f"{label} must be an array")
    result = tuple(_text(item, f"{label}[]") for item in value)
    if len(set(result)) != len(result):
        raise AdapterContractError(f"{label} cannot contain duplicates")
    return result
