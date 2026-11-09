"""Typed S13 check, evidence-input, and finalized validation models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class ValidationCheckSpec:
    check_id: str
    domain: str
    severity: str
    expected_condition: str
    validator_version: str


@dataclass(frozen=True)
class CheckOutcome:
    status: str
    observed_value: str | None
    affected_record_ids: tuple[str, ...]
    message: str


@dataclass(frozen=True)
class ArtifactVerificationInput:
    """Final stored payloads and their proposed authoritative manifest rows."""

    artifact_payloads: Mapping[str, bytes]
    manifest_rows: tuple[Mapping[str, Any], ...]
    expected_record_counts: Mapping[str, int]
    expected_schema_ids: Mapping[str, str | None]


@dataclass(frozen=True)
class StagePerformanceObservation:
    """Measured runtime and identity evidence for one completed stage."""

    stage_id: str
    operation: str
    generated_row_count: int
    elapsed_seconds: float
    rows_per_second: float
    rss_before_bytes: int
    rss_after_bytes: int
    peak_resident_memory_bytes: int
    table_record_digests: tuple[tuple[str, str], ...]
    stored_bytes: int = 0
    row_group_count: int = 0
    row_group_efficiency: float | None = None
    artifact_sha256: tuple[tuple[str, str], ...] = ()
    serial_elapsed_seconds: float | None = None
    parallel_efficiency: float = 1.0


@dataclass(frozen=True)
class PerformanceObservation:
    """Externally measured generation observations; never generation inputs."""

    measurement_profile_id: str
    generated_row_count: int
    elapsed_seconds: float
    rows_per_second: float
    peak_memory_bytes: int
    stored_bytes: int
    bytes_per_row: float
    parallel_efficiency: float
    deterministic_digest_equal: bool
    requested_worker_count: int = 1
    effective_worker_count: int = 1
    serial_elapsed_seconds: float | None = None
    stage_observations: tuple[StagePerformanceObservation, ...] = ()


@dataclass(frozen=True)
class ReplicateExecutionEvidence:
    scenario_id: str
    replicate_id: int
    seed_stream_digest: str
    retained_metric_count: int


@dataclass(frozen=True)
class ValidationInput:
    resolved: Any
    run_plan: Any
    run_scenario_rows: tuple[Mapping[str, Any], ...]
    seed_stream_rows: tuple[Mapping[str, Any], ...]
    tables: Mapping[str, tuple[Mapping[str, Any], ...]]
    world: Any
    catalog: Any
    physical: Any
    arrivals: Any
    workflows: Any
    causal_dag: Any
    policy: Any
    obligations: Any
    receipts: Any
    anomalies: Any
    observers: Any
    sampling: Any
    replicate_evidence: tuple[ReplicateExecutionEvidence, ...]
    artifact_verification: ArtifactVerificationInput | None = None
    reproducibility_reference_digests: Mapping[str, str] | None = None
    performance_observation: PerformanceObservation | None = None


ValidationRunner = Callable[[ValidationInput], CheckOutcome]


@dataclass(frozen=True)
class RegisteredValidationCheck:
    spec: ValidationCheckSpec
    runner: ValidationRunner


@dataclass(frozen=True)
class ValidationBuild:
    validation_issues: tuple[dict[str, Any], ...]
    required_check_ids: tuple[str, ...]
    executed_check_ids: tuple[str, ...]
    release_eligible: bool
    threshold_profile_id: str
    threshold_profile_sha256: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {"validation_issue": self.validation_issues}
