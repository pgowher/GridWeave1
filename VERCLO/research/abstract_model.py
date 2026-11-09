"""Independent observer-relative decision relation for Experiment 0.

This module deliberately imports no VERCLO implementation. Its input contains
adjudicated abstract facts, not receipts or physical-world truth.
"""

from __future__ import annotations

from dataclasses import dataclass


RESOLVED = frozenset({"COVERED", "EXCEPTED"})
CATEGORIES = frozenset({"COVERED", "EXCEPTED", "MISSING", "INVALID", "LATE", "CONTRADICTORY"})


@dataclass(frozen=True)
class Observation:
    baseline_verifiable: bool
    ready: bool
    conflict_or_challenge: bool
    categories: tuple[str, ...]

    def __post_init__(self) -> None:
        if set(self.categories) - CATEGORIES:
            raise ValueError("unknown abstract obligation category")


def decide(observation: Observation) -> str:
    """PAE-FM-2.2 Eq. (31)-(32) and PAEFECM.Core.decide precedence.

    IN_PROGRESS is the operational pre-decision status; the remaining six
    values are terminal classifications. This is intentionally independent
    from the v1.4 evaluator's control flow.
    """
    if not observation.ready:
        return "IN_PROGRESS"
    if not observation.baseline_verifiable:
        return "UNVERIFIABLE"
    if observation.conflict_or_challenge or "CONTRADICTORY" in observation.categories:
        return "DISPUTED"
    if observation.categories and all(value == "COVERED" for value in observation.categories):
        return "CLOSED"
    if observation.categories and all(value in RESOLVED for value in observation.categories):
        return "CLOSED_WITH_EXCEPTIONS"
    if any(value in RESOLVED for value in observation.categories):
        return "PARTIALLY_CLOSED"
    return "OPEN"


def positive_soundness_holds(observation: Observation) -> bool:
    """Check the conditional soundness consequent for a finite observation."""
    outcome = decide(observation)
    if outcome not in {"CLOSED", "CLOSED_WITH_EXCEPTIONS"}:
        return True
    return (
        observation.baseline_verifiable
        and observation.ready
        and not observation.conflict_or_challenge
        and all(value in RESOLVED for value in observation.categories)
        and bool(observation.categories)
    )
