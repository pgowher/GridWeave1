"""Table-driven C-PaE transition guard evaluator.

This module validates protocol paths only. It deliberately does not implement
VERCLO closure or PaEGen ground-truth logic.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping


CATALOG_FILE = Path(__file__).with_name("cpae_state_machine_v1.json")


@dataclass(frozen=True)
class TransitionResult:
    accepted: bool
    transition_id: str
    prior_phase: str
    next_phase: str
    rejection_code: str | None


def load_protocol_catalog(path: str | Path = CATALOG_FILE) -> Mapping[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate_transition(
    transition_id: str,
    *,
    phase: str,
    actor_role: str,
    facts: Mapping[str, bool],
    catalog: Mapping[str, object] | None = None,
) -> TransitionResult:
    """Apply declared guards in order and never mutate state on rejection."""

    source = catalog or load_protocol_catalog()
    transition = next(
        (row for row in source["transitions"] if row["id"] == transition_id), None
    )
    if transition is None:
        return TransitionResult(False, transition_id, phase, phase, "UNKNOWN_TRANSITION")
    if actor_role not in transition["actor_roles"]:
        return TransitionResult(False, transition_id, phase, phase, "UNAUTHORIZED_ROLE")
    if phase not in transition["from_phases"]:
        return TransitionResult(False, transition_id, phase, phase, "INVALID_STATE_TRANSITION")
    for fact in transition["required_facts"]:
        if facts.get(fact) is not True:
            return TransitionResult(
                False, transition_id, phase, phase, transition["guard_failures"][fact]
            )
    next_phase = phase if transition["to_phase"] == "$SAME" else transition["to_phase"]
    return TransitionResult(True, transition_id, phase, next_phase, None)
