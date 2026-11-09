"""Stable value objects for the PaEGen 1.0 compatibility interface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


PAEGEN_INTERFACE_VERSION = "1.0.0"
PAEGEN_SCHEMA_VERSION = "1.0.0"
FECM_MODEL_VERSION = "PAE-FECM-v1.0.0"


@dataclass(frozen=True)
class PaEGenArtifact:
    """One canonical JSON artifact and its content digest."""

    schema_id: str
    payload: Mapping[str, Any]
    sha256: str


@dataclass(frozen=True)
class PaEGenReplica:
    """Sealed truth, observer inputs, and safe manifest for one replicate."""

    scenario_id: str
    replicate_id: int
    ground_truth: PaEGenArtifact
    observer_views: Mapping[str, PaEGenArtifact]
    scenario_manifest: PaEGenArtifact


@dataclass(frozen=True)
class PaEGenBuild:
    """Complete deterministic PaEGen output for a resolved run."""

    run_id: str
    interface_version: str
    model_version: str
    replicas: tuple[PaEGenReplica, ...]


@dataclass(frozen=True)
class PaEGenExportResult:
    """Paths and digest for a physically separated PaEGen export."""

    output_root: Path
    sealed_ground_truth_root: Path
    observer_input_root: Path
    manifest_root: Path
    file_count: int
    export_digest: str

