"""Deterministic projection decisions used only by the observer compiler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from htgl_dataset_generator.seeds import CounterRng

from .language import evaluate_validated_visibility_expression
from .profiles import ObserverProfile, ObserverProfileBundle


@dataclass(frozen=True)
class CompiledProjection:
    base_visibility_class: str
    final_visibility_class: str
    omission_reason: str | None
    delay_seconds: int
    clock_offset_seconds: int
    visible_timestamp: str


def compile_projection(
    profile: ObserverProfile,
    *,
    event_id: str,
    event_timestamp: str,
    facts: Mapping[str, Any],
    rng: CounterRng,
    bundle: ObserverProfileBundle,
) -> CompiledProjection:
    """Apply visibility, loss, omission, redaction, and clock effects in order."""

    if profile.mode == "collusion":
        raise ValueError("collusion projections must compose frozen member views")
    base_visibility = "omitted"
    omission_reason: str | None = "policy"
    for rule in profile.visibility_rules:
        if evaluate_validated_visibility_expression(rule.condition, facts):
            base_visibility = rule.visibility_class
            omission_reason = None
            break

    loss_probability = bundle.loss_profiles[profile.loss_profile_id].probability
    if base_visibility != "omitted" and rng.uniform(
        f"observer-transport-loss:{profile.profile_id}:{event_id}", 0
    ) < loss_probability:
        omission_reason = "transport_loss"

    eligible_for_adversarial_omission = (
        base_visibility != "omitted"
        and omission_reason is None
        and profile.adversarial_omission_probability > 0.0
        and evaluate_validated_visibility_expression(
            profile.adversarial_omission_condition, facts
        )
    )
    if eligible_for_adversarial_omission and rng.uniform(
        f"observer-adversarial-omission:{profile.profile_id}:{event_id}", 0
    ) < profile.adversarial_omission_probability:
        omission_reason = "compromise"

    delay_profile = bundle.delay_profiles[profile.delay_profile_id]
    if delay_profile.minimum_seconds == delay_profile.maximum_seconds:
        delay_seconds = delay_profile.minimum_seconds
    else:
        delay_seconds = rng.randint(
            f"observer-delay:{profile.profile_id}:{event_id}",
            0,
            delay_profile.minimum_seconds,
            delay_profile.maximum_seconds,
        )
    visible_timestamp = _timestamp(event_timestamp) + timedelta(
        seconds=delay_seconds + delay_profile.clock_offset_seconds
    )

    if omission_reason is not None:
        final_visibility = "omitted"
    elif profile.mode == "lossy":
        final_visibility = "redacted"
    elif base_visibility == "inferred":
        final_visibility = "inferred"
    elif delay_seconds or delay_profile.clock_offset_seconds:
        final_visibility = "delayed"
    else:
        final_visibility = base_visibility
    return CompiledProjection(
        base_visibility_class=base_visibility,
        final_visibility_class=final_visibility,
        omission_reason=omission_reason,
        delay_seconds=delay_seconds,
        clock_offset_seconds=delay_profile.clock_offset_seconds,
        visible_timestamp=_format_timestamp(visible_timestamp),
    )


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp is not timezone-aware: {value!r}")
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
