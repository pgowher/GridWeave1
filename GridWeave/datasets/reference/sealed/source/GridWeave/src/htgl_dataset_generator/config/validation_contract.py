"""Stable S13 validation-profile contract shared by config and execution."""

from __future__ import annotations

import re
from typing import Iterable


CHECK_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")

# Profiles may add registered checks, but these joint-validation checks are
# mandatory for every run and cannot be removed by a scenario configuration.
CORE_VALIDATION_CHECK_IDS: tuple[str, ...] = (
    "SCHEMA-001",
    "IDENTITY-001",
    "FK-001",
    "TEMPORAL-001",
    "PHYSICAL-001",
    "TEMPORAL-ARRIVAL-001",
    "WORKFLOW-001",
    "DAG-001",
    "POLICY-001",
    "ANOMALY-001",
    "EVIDENCE-001",
    "OBSERVER-001",
    "SAMPLING-001",
    "N-N-Q-001",
    "PRIVACY-001",
    "PRIVACY-SOURCE-001",
    "RECONCILIATION-001",
    "REPLICATE-001",
    "MANIFEST-001",
    "REPRODUCIBILITY-001",
    "PERFORMANCE-001",
)


class ValidationProfileContractError(ValueError):
    """Raised when a configured validation profile is ambiguous or unstable."""


def resolve_required_check_ids(configured_ids: Iterable[str]) -> tuple[str, ...]:
    """Return the deterministic union of mandatory core and additive checks."""

    configured = tuple(configured_ids)
    if len(configured) != len(set(configured)):
        raise ValidationProfileContractError(
            "validation.required_check_ids contains duplicate check IDs"
        )
    malformed = tuple(
        value
        for value in configured
        if not isinstance(value, str) or CHECK_ID_PATTERN.fullmatch(value) is None
    )
    if malformed:
        raise ValidationProfileContractError(
            f"validation.required_check_ids contains malformed IDs {malformed}"
        )
    return tuple(sorted(set(CORE_VALIDATION_CHECK_IDS) | set(configured)))
