"""Deterministic omission, delay, loss, and visibility expectation oracle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from htgl_dataset_generator.seeds import CounterRng

from .language import evaluate_validated_visibility_expression
from .profiles import ObserverProfile, ObserverProfileBundle


@dataclass(frozen=True)
class ProjectionExpectation:
    base_visibility_class: str
    final_visibility_class: str
    omission_reason: str | None
    delay_seconds: int
    clock_offset_seconds: int
    visible_timestamp: str


def expected_projection(
    profile: ObserverProfile,
    *,
    event_id: str,
    event_timestamp: str,
    facts: Mapping[str, Any],
    rng: CounterRng,
    bundle: ObserverProfileBundle,
) -> ProjectionExpectation:
    """Recompute one non-collusion projection without trusting emitted labels."""

    if profile.mode == "collusion":
        raise ValueError("collusion expectations derive from member expectations")
    base_class = "omitted"
    omission_reason: str | None = "policy"
    for rule in profile.visibility_rules:
        if evaluate_validated_visibility_expression(rule.condition, facts):
            base_class = rule.visibility_class
            omission_reason = None
            break
    loss = bundle.loss_profiles[profile.loss_profile_id]
    if base_class != "omitted" and rng.uniform(
        f"observer-transport-loss:{profile.profile_id}:{event_id}", 0
    ) < loss.probability:
        omission_reason = "transport_loss"
    if (
        base_class != "omitted"
        and omission_reason is None
        and profile.adversarial_omission_probability > 0.0
        and evaluate_validated_visibility_expression(
            profile.adversarial_omission_condition, facts
        )
        and rng.uniform(f"observer-adversarial-omission:{profile.profile_id}:{event_id}", 0)
        < profile.adversarial_omission_probability
    ):
        omission_reason = "compromise"
    delay = bundle.delay_profiles[profile.delay_profile_id]
    delay_seconds = (
        delay.minimum_seconds
        if delay.minimum_seconds == delay.maximum_seconds
        else rng.randint(
            f"observer-delay:{profile.profile_id}:{event_id}",
            0,
            delay.minimum_seconds,
            delay.maximum_seconds,
        )
    )
    visible_time = _timestamp(event_timestamp) + timedelta(
        seconds=delay_seconds + delay.clock_offset_seconds
    )
    if omission_reason is not None:
        final_class = "omitted"
    elif profile.mode == "lossy":
        final_class = "redacted"
    elif base_class == "inferred":
        final_class = "inferred"
    elif delay_seconds != 0 or delay.clock_offset_seconds != 0:
        final_class = "delayed"
    else:
        final_class = base_class
    return ProjectionExpectation(
        base_visibility_class=base_class,
        final_visibility_class=final_class,
        omission_reason=omission_reason,
        delay_seconds=delay_seconds,
        clock_offset_seconds=delay.clock_offset_seconds,
        visible_timestamp=_format_timestamp(visible_time),
    )


def projection_digest_payload(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "domain": "htgl.observer.projection-digest.v1",
        "observer_record_id": row["observer_record_id"],
        "projection_profile_id": row["projection_profile_id"],
        "visible_timestamp": row["visible_timestamp"],
        "visibility_class": row["visibility_class"],
        "omission_reason": row["omission_reason"],
        "redacted_field_paths": row["redacted_field_paths"],
        "schema_profile_id": row["schema_profile_id"],
        "payload_json": row["payload_json"],
    }


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp is not timezone-aware: {value!r}")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
