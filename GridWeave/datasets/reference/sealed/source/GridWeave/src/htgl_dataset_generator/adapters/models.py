"""Typed Step 19 mapping, loss, conformance, and adapter build models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class AdapterContractError(ValueError):
    """Raised when an adapter would make an undocumented or unsafe projection."""


@dataclass(frozen=True)
class FieldMapping:
    adapter_id: str
    mapping_profile_id: str
    profile_version: str
    target_standard: str
    target_standard_version: str
    source_schema: str
    source_field: str
    target_field: str | None
    cardinality: str
    transformation: str
    vocabulary_conversion: str | None
    disposition: str
    rationale: str


@dataclass(frozen=True)
class AdapterProfile:
    adapter_id: str
    mapping_profile_id: str
    profile_version: str
    target_standard: str
    target_standard_version: str
    source_schemas: tuple[str, ...]
    structural_losses: tuple[str, ...]
    mappings: tuple[FieldMapping, ...]


@dataclass(frozen=True)
class AdapterRegistry:
    registry_id: str
    version: str
    source: str
    sha256: str
    profiles: Mapping[str, AdapterProfile]

    def profile(self, adapter_id: str) -> AdapterProfile:
        try:
            return self.profiles[adapter_id]
        except KeyError as exc:
            raise AdapterContractError(
                f"adapter {adapter_id!r} is not registered in {self.registry_id}"
            ) from exc


@dataclass(frozen=True)
class AdapterConformance:
    adapter_id: str
    mapping_profile_id: str
    source_record_count: int
    output_record_count: int
    runtime_source_fields: tuple[str, ...]
    mapped_field_count: int
    lossy_field_count: int
    unsupported_field_count: int
    undocumented_field_count: int
    round_trip_status: str
    semantic_equivalence_status: str
    output_relative_paths: tuple[str, ...]
    output_sha256: tuple[str, ...]
    passed: bool


@dataclass(frozen=True)
class AdapterBuild:
    registry: AdapterRegistry
    configured_adapters: tuple[str, ...]
    mappings: tuple[FieldMapping, ...]
    conformance: tuple[AdapterConformance, ...]
    output_paths: tuple[Path, ...]
    metadata_overrides: Mapping[str, Mapping[str, object]]

