"""Typed S11 projection truth, release views, oracle results, and metrics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ProjectionSourceMapping:
    observer_record_id: str
    observer_actor_id: str
    projection_profile_id: str
    source_event_id: str
    source_workflow_id: str
    base_visibility_class: str
    final_visibility_class: str
    omission_reason: str | None
    delay_seconds: int
    clock_offset_seconds: int
    source_obligation_ids: tuple[str, ...]
    source_receipt_ids: tuple[str, ...]
    independently_valid_receipt_ids: tuple[str, ...]
    source_anomaly_instance_ids: tuple[str, ...]
    protected_pair_ids: tuple[str, ...]
    collusion_member_record_ids: tuple[str, ...]
    source_event_digest: str

    @property
    def visible(self) -> bool:
        return self.final_visibility_class != "omitted"


@dataclass(frozen=True)
class ObserverReleaseView:
    profile_id: str
    access_class: str
    schema_profile_id: str
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class LeakageFinding:
    profile_id: str
    observer_record_id: str
    finding_type: str
    path: str
    matched_token: str


@dataclass(frozen=True)
class LeakageDiagnostics:
    scanned_profile_count: int
    scanned_record_count: int
    scanned_scalar_count: int
    sealed_truth_leakage_count: int
    forbidden_field_count: int
    exact_identifier_leakage_count: int
    pair_identifier_leakage_count: int
    inclusion_probability_leakage_count: int
    findings: tuple[LeakageFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


@dataclass(frozen=True)
class OmissionOracleTruth:
    observer_record_id: str
    projection_profile_id: str
    source_event_id: str
    expected_visibility_class: str
    observed_visibility_class: str
    expected_omission_reason: str | None
    observed_omission_reason: str | None
    expected_visible_timestamp: str
    observed_visible_timestamp: str
    matches: bool


@dataclass(frozen=True)
class OmissionOracleDiagnostics:
    evaluated_record_count: int
    visibility_mismatch_count: int
    omission_reason_mismatch_count: int
    timestamp_mismatch_count: int
    projection_digest_mismatch_count: int

    @property
    def passed(self) -> bool:
        return (
            self.visibility_mismatch_count == 0
            and self.omission_reason_mismatch_count == 0
            and self.timestamp_mismatch_count == 0
            and self.projection_digest_mismatch_count == 0
        )


@dataclass(frozen=True)
class ObserverTaskResult:
    scenario_id: str
    replicate_id: int
    task_id: str
    profile_id: str
    metric_name: str
    value: float
    required_threshold: float
    status: str
    reason: str


@dataclass(frozen=True)
class ObserverProfileDiagnostics:
    scenario_id: str
    replicate_id: int
    profile_id: str
    mode: str
    observer_actor_id: str
    source_event_count: int
    visible_event_count: int
    omitted_event_count: int
    weighted_visible_event_coverage: float
    visible_edge_coverage: float
    evidence_recoverability: float
    anomaly_event_recoverability: float
    mean_delay_seconds: float
    p95_delay_seconds: float
    maximum_delay_seconds: float
    transport_loss_rate: float
    adversarial_omission_rate: float
    overall_omission_rate: float
    mean_time_to_detection_seconds: float
    projection_payload_bytes: int
    collusion_gain: float
    sealed_truth_leakage_count: int
    task_sufficiency_rate: float


@dataclass(frozen=True)
class ObserverBuild:
    observer_events: tuple[dict[str, Any], ...]
    source_mappings: tuple[ProjectionSourceMapping, ...]
    release_views: Mapping[str, ObserverReleaseView]
    omission_truth: tuple[OmissionOracleTruth, ...]
    omission_diagnostics: OmissionOracleDiagnostics
    leakage_diagnostics: LeakageDiagnostics
    task_results: tuple[ObserverTaskResult, ...]
    diagnostics: Mapping[str, ObserverProfileDiagnostics]
    run_metrics: tuple[dict[str, Any], ...]
    profile_bundle_sha256: str
    frozen_truth_digest: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "observer_event": self.observer_events,
            "run_metric": self.run_metrics,
        }
