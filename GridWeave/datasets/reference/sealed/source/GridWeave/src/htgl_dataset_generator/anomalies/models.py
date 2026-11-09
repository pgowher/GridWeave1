"""Typed evaluator-only counterfactual traces, pairs, and search diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping

from htgl_dataset_generator.policy.language import canonical_json


@dataclass(frozen=True)
class CounterfactualTrace:
    scenario_id: str
    replicate_id: int
    workflow_instance: Mapping[str, Any]
    events: tuple[dict[str, Any], ...]
    edges: tuple[dict[str, Any], ...]
    replicas: tuple[dict[str, Any], ...]
    obligations: tuple[dict[str, Any], ...]
    receipts: tuple[dict[str, Any], ...]
    independently_valid_receipt_ids: frozenset[str]
    policy_evaluations: Mapping[str, Mapping[str, Any]]
    evidence_duty_signatures: Mapping[str, tuple[str, ...]]
    ancestor_closure: Mapping[str, tuple[str, ...]]
    derived_root_event_ids: Mapping[str, str]
    derived_causal_depths: Mapping[str, int]
    observer_required_receipt_ids: frozenset[str]
    observer_visible_receipt_ids: frozenset[str]
    replica_action_status: Mapping[str, str]
    sampling_membership: tuple[dict[str, Any], ...]
    physical_context_digest: str

    @property
    def workflow_id(self) -> str:
        return str(self.workflow_instance["workflow_instance_id"])

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.as_payload()).encode("utf-8")).hexdigest()

    def as_payload(self) -> Mapping[str, Any]:
        return {
            "ancestor_closure": {key: list(value) for key, value in sorted(self.ancestor_closure.items())},
            "derived_causal_depths": dict(sorted(self.derived_causal_depths.items())),
            "derived_root_event_ids": dict(sorted(self.derived_root_event_ids.items())),
            "edges": [dict(row) for row in self.edges],
            "events": [dict(row) for row in self.events],
            "evidence_duty_signatures": {
                key: list(value) for key, value in sorted(self.evidence_duty_signatures.items())
            },
            "independently_valid_receipt_ids": sorted(self.independently_valid_receipt_ids),
            "obligations": [dict(row) for row in self.obligations],
            "observer_required_receipt_ids": sorted(self.observer_required_receipt_ids),
            "observer_visible_receipt_ids": sorted(self.observer_visible_receipt_ids),
            "physical_context_digest": self.physical_context_digest,
            "policy_evaluations": {
                key: dict(value) for key, value in sorted(self.policy_evaluations.items())
            },
            "receipts": [dict(row) for row in self.receipts],
            "replica_action_status": dict(sorted(self.replica_action_status.items())),
            "replicas": [dict(row) for row in self.replicas],
            "replicate_id": self.replicate_id,
            "sampling_membership": [dict(row) for row in self.sampling_membership],
            "scenario_id": self.scenario_id,
            "workflow_instance": dict(self.workflow_instance),
        }


@dataclass(frozen=True)
class CounterfactualEdit:
    operation: str
    cost: int
    primitive_changed_field_paths: tuple[str, ...]
    derived_changed_field_paths: tuple[str, ...]
    parameters: tuple[tuple[str, str], ...]

    def parameter(self, name: str) -> str:
        for key, value in self.parameters:
            if key == name:
                return value
        raise KeyError(name)


@dataclass(frozen=True)
class InvariantOutcome:
    invariant_id: str
    domain: str
    status: str
    details: str

    @property
    def passed(self) -> bool:
        return self.status == "pass"


@dataclass(frozen=True)
class AnomalySearchDiagnostics:
    anomaly_type: str
    target_invariant_id: str
    search_bound: int
    generated_candidate_count: int
    evaluated_candidate_count: int
    rejected_valid_source_count: int
    rejected_target_not_failed_count: int
    rejected_protected_failure_count: int
    rejected_schema_or_physical_count: int
    accepted_cost: int
    lower_cost_candidate_count: int
    minimality_proven_within_bound: bool
    minimality_scope: str


@dataclass(frozen=True)
class CounterfactualPair:
    protected_pair_id: str
    anomaly_instance_id: str
    anomaly_type: str
    target_invariant_id: str
    valid_trace: CounterfactualTrace
    invalid_trace: CounterfactualTrace
    invalid_counterfactual_workflow_id: str
    edit: CounterfactualEdit
    valid_invariant_outcomes: tuple[InvariantOutcome, ...]
    invalid_invariant_outcomes: tuple[InvariantOutcome, ...]
    preserved_invariant_ids: tuple[str, ...]
    search_diagnostics: AnomalySearchDiagnostics
    selection_probability: float
    analysis_weight: float


@dataclass(frozen=True)
class AnomalyDiagnostics:
    scenario_id: str
    replicate_id: int
    anomaly_count: int
    target_violation_success_rate: float
    protected_collateral_violation_rate: float
    mean_edit_cost: float
    anomaly_type_counts: Mapping[str, int]
    mean_candidates_evaluated: float


@dataclass(frozen=True)
class AnomalyBuild:
    anomaly_instances: tuple[dict[str, Any], ...]
    counterfactual_pairs: tuple[CounterfactualPair, ...]
    diagnostics: Mapping[str, AnomalyDiagnostics]
    invariant_registry_sha256: str
    edit_grammar_sha256: str

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {"anomaly_instance": self.anomaly_instances}
