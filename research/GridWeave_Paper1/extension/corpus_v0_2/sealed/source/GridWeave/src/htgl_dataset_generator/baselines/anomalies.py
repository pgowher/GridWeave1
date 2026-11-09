"""Seeded anomaly baselines kept separate from minimal counterfactual truth.

These controls deliberately do not receive target-only acceptance filtering and
never emit ``anomaly_instance`` rows. Their invariant outcomes quantify why
unconstrained corruption is not equivalent to the S08 counterfactual engine.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from htgl_dataset_generator.schemas import ContractSpec
from htgl_dataset_generator.seeds import CounterRng
from htgl_dataset_generator.workflows import workflow_definitions

if TYPE_CHECKING:
    from htgl_dataset_generator.anomalies.invariants import IndependentInvariantChecker
    from htgl_dataset_generator.anomalies.models import CounterfactualTrace, InvariantOutcome


RANDOM_FIELD_PROFILE = "BASELINE-SEEDED-RANDOM-FIELD-CORRUPTION-v1"
RANDOM_TRANSITION_PROFILE = "BASELINE-SEEDED-RANDOM-INVALID-TRANSITION-v1"


@dataclass(frozen=True)
class AnomalyBaselineCase:
    profile_id: str
    source_workflow_id: str
    changed_field_paths: tuple[str, ...]
    source_trace_digest: str
    corrupted_trace: CounterfactualTrace
    invariant_outcomes: tuple[InvariantOutcome, ...]
    failed_invariant_ids: tuple[str, ...]


@dataclass(frozen=True)
class AnomalyBaselineBuild:
    cases: tuple[AnomalyBaselineCase, ...]
    profile_counts: Mapping[str, int]
    mean_failed_invariant_count: float

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        """Baselines are evaluator-only controls and own no authoritative table."""

        return {}


def build_seeded_anomaly_baselines(
    traces: Sequence[CounterfactualTrace],
    *,
    rng: CounterRng,
    checker: IndependentInvariantChecker,
    recompute: Callable[[CounterfactualTrace], CounterfactualTrace],
    contract: ContractSpec,
    profile_ids: Sequence[str],
) -> AnomalyBaselineBuild:
    """Build one deterministic control case per configured baseline profile."""

    ordered = tuple(sorted(traces, key=lambda trace: trace.workflow_id))
    if not ordered:
        raise ValueError("anomaly baselines require at least one valid trace")
    expected = (RANDOM_FIELD_PROFILE, RANDOM_TRANSITION_PROFILE)
    if tuple(profile_ids) != expected:
        raise ValueError(f"baseline profiles must be exactly {expected}")
    cases: list[AnomalyBaselineCase] = []
    for profile_id in profile_ids:
        eligible = (
            ordered
            if profile_id == RANDOM_FIELD_PROFILE
            else tuple(trace for trace in ordered if len(trace.events) >= 2)
        )
        if not eligible:
            raise ValueError(f"baseline profile={profile_id} has no eligible workflow")
        source = eligible[rng.randint(f"baseline-source:{profile_id}", 0, 0, len(eligible) - 1)]
        if profile_id == RANDOM_FIELD_PROFILE:
            corrupted, paths = _random_field_corruption(source, rng)
        else:
            corrupted, paths = _random_invalid_transition(source, rng, contract)
        recomputed = recompute(corrupted)
        outcomes = checker.evaluate(recomputed, reference=source)
        failed = tuple(sorted(item.invariant_id for item in outcomes if item.status == "fail"))
        cases.append(
            AnomalyBaselineCase(
                profile_id=profile_id,
                source_workflow_id=source.workflow_id,
                changed_field_paths=paths,
                source_trace_digest=source.digest(),
                corrupted_trace=recomputed,
                invariant_outcomes=outcomes,
                failed_invariant_ids=failed,
            )
        )
    counts = {profile_id: sum(case.profile_id == profile_id for case in cases) for profile_id in profile_ids}
    return AnomalyBaselineBuild(
        cases=tuple(sorted(cases, key=lambda case: case.profile_id)),
        profile_counts=dict(sorted(counts.items())),
        mean_failed_invariant_count=sum(len(case.failed_invariant_ids) for case in cases) / len(cases),
    )


def _random_field_corruption(
    trace: CounterfactualTrace,
    rng: CounterRng,
) -> tuple[CounterfactualTrace, tuple[str, ...]]:
    events = [dict(row) for row in trace.events]
    event_index = rng.randint(
        f"baseline-random-field-event:{trace.workflow_id}", 0, 0, len(events) - 1
    )
    event = events[event_index]
    fields = ("legal_basis_label_id", "policy_purpose_id", "recorded_timestamp")
    field = fields[rng.randint(f"baseline-random-field-name:{trace.workflow_id}", 0, 0, len(fields) - 1)]
    if field == "legal_basis_label_id":
        event[field] = "LEGAL-BASIS-BASELINE-CORRUPTED-v1"
    elif field == "policy_purpose_id":
        event[field] = "PURPOSE-BASELINE-RANDOM-CORRUPTION-v1"
    else:
        event[field] = event["timestamp"]
    path = f"governance_event[event_id={event['event_id']}].{field}"
    return replace(trace, events=tuple(events)), (path,)


def _random_invalid_transition(
    trace: CounterfactualTrace,
    rng: CounterRng,
    contract: ContractSpec,
) -> tuple[CounterfactualTrace, tuple[str, ...]]:
    events = [dict(row) for row in trace.events]
    event_index = rng.randint(
        f"baseline-invalid-transition-event:{trace.workflow_id}", 0, 0, len(events) - 1
    )
    event = events[event_index]
    definition = workflow_definitions().get(str(trace.workflow_instance["workflow_type"]))
    if definition is None:
        raise ValueError("baseline source workflow definition does not resolve")
    legal = {
        (item.event_type, item.state_before, item.state_after)
        for item in definition.transitions
    }
    alternatives = tuple(
        value
        for value in contract.dictionary_values("workflow_state")
        if value not in {str(event["workflow_state_before"]), str(event["workflow_state_after"])}
        and (
            str(event["event_type"]),
            str(event["workflow_state_before"]),
            value,
        )
        not in legal
    )
    if not alternatives:
        raise ValueError("workflow_state dictionary has no baseline corruption alternative")
    event["workflow_state_after"] = alternatives[
        rng.randint(f"baseline-invalid-transition-state:{trace.workflow_id}", 0, 0, len(alternatives) - 1)
    ]
    path = f"governance_event[event_id={event['event_id']}].workflow_state_after"
    return replace(trace, events=tuple(events)), (path,)
