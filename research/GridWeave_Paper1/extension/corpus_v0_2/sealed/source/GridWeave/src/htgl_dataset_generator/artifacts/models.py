"""Typed S15 release, inventory, and transactional publication models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from htgl_dataset_generator.metrics import (
    PhysicalCalibrationReference,
    PrivacySourceReference,
)
from htgl_dataset_generator.validation import PerformanceObservation


class ArtifactCompilerError(RuntimeError):
    """Raised when an S15 release cannot satisfy its production contract."""


class ArtifactCollisionError(ArtifactCompilerError):
    """Raised when a release target conflicts with the declared collision policy."""


class ArtifactIntegrityError(ArtifactCompilerError):
    """Raised when staged bytes, schema metadata, or manifests disagree."""


FailureInjector = Callable[[str, Path], None]


@dataclass(frozen=True)
class DownstreamReplayObservation:
    """Measured result from a downstream implementation or simulator replay.

    The dataset generator does not create this observation.  Callers may attach
    it only after replaying a released workload into a separately identified
    implementation or simulator.  Both workload and result bytes are bound by
    SHA-256 so publication reports can trace ``q`` without treating a configured
    execution target as observed execution.
    """

    run_id: str
    scenario_id: str
    replicate_id: int
    executed_operation_count: int
    implementation_id: str
    implementation_version: str
    software_profile_id: str
    hardware_profile_id: str
    workload_sha256: str
    result_sha256: str
    throughput_operations_per_second: float
    p50_latency_milliseconds: float
    p95_latency_milliseconds: float
    peak_resident_memory_bytes: int


@dataclass(frozen=True)
class ArtifactCompilerOptions:
    """Non-semantic operational controls for deterministic S15 compilation."""

    collision_policy: str = "fail"
    fact_partition_minimum_rows: int = 10_000
    region_partition_minimum_rows: int = 100_000
    minimum_rows_per_region_partition: int = 10_000
    compression_level: int = 9
    require_byte_reproducibility: bool = True
    failure_injector: FailureInjector | None = None


@dataclass(frozen=True)
class ReleaseEvidence:
    """External evidence and calibrated references used to close S13/S14."""

    performance_by_run: Mapping[tuple[str, int], PerformanceObservation]
    physical_reference_by_run: Mapping[
        tuple[str, int], PhysicalCalibrationReference
    ] | None = None
    privacy_reference_by_run: Mapping[
        tuple[str, int], PrivacySourceReference
    ] | None = None
    downstream_replay_by_run: Mapping[
        tuple[str, int], DownstreamReplayObservation
    ] | None = None


@dataclass(frozen=True)
class StoredArtifact:
    """One immutable staged payload and its manifest metadata."""

    relative_path: str
    media_type: str
    schema_id: str | None
    schema_fingerprint: str | None
    record_count: int | None
    uncompressed_bytes: int | None
    stored_bytes: int
    sha256: str
    partition_keys: tuple[str, ...]
    privacy_class: str
    generation_stage: str
    publication_eligible: bool


@dataclass(frozen=True)
class ReleaseBundleResult:
    """One physically isolated access-class bundle and its independent manifests."""

    bundle_id: str
    access_class: str
    release_root: Path
    manifest_path: Path
    manifest_sha256: str
    artifact_manifest_path: Path
    artifact_manifest_sha256: str
    byte_digest: str
    artifact_count: int
    total_stored_bytes: int


@dataclass(frozen=True)
class ArtifactReleaseResult:
    """Successfully promoted, publication-gated S15 release."""

    release_root: Path
    manifest_path: Path
    manifest_sha256: str
    artifact_manifest_path: Path
    artifact_manifest_sha256: str
    semantic_digest: str
    byte_digest: str
    artifact_count: int
    total_stored_bytes: int
    reused_existing_release: bool
    final_validation_by_run: Mapping[
        tuple[str, int], tuple[Mapping[str, object], ...]
    ]
    final_metrics_by_run: Mapping[
        tuple[str, int], tuple[Mapping[str, object], ...]
    ]
    bundles: Mapping[str, ReleaseBundleResult]

    def bundle(self, access_class: str) -> ReleaseBundleResult:
        try:
            return self.bundles[access_class]
        except KeyError as exc:
            raise KeyError(f"release has no {access_class!r} bundle") from exc
