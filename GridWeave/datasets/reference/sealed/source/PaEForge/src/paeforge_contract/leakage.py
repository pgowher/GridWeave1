"""Fail-closed recursive leakage checks for the VERCLO input boundary."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping


class LeakageError(ValueError):
    """Raised when evaluator-only material reaches verifier-visible input."""


def _normalise_key(value: object) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value).strip())
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


# These names describe privileged labels, mappings, hidden state, or precomputed
# decisions. Keep the blocklist redundant with schema allowlists as defence in depth.
FORBIDDEN_KEYS = frozenset(
    {
        "access_class_evaluator_only",
        "attack_class",
        "attack_label",
        "attack_type",
        "behavior_profile",
        "behaviour_profile",
        "closure_decision",
        "closure_ground_truth",
        "closure_label",
        "controlled_by_adversary",
        "direct_identifier",
        "evidence_grade_truth",
        "evidence_sufficiency",
        "expected_closure",
        "expected_obligation_ids",
        "expected_obligations",
        "expected_outcome",
        "hidden_relationships",
        "hidden_topology",
        "injected_fault",
        "omission_truth",
        "operational_payload",
        "personal_data",
        "policy_decision_truth",
        "protected_identifier_mapping",
        "raw_telemetry",
        "receipt_validity_truth",
        "sealed_ground_truth",
        "truth_matches_declared",
        "truth_status",
        "verification_status_truth",
        "world_disposition",
    }
)


def scan_for_leakage(
    value: Any,
    *,
    forbidden_keys: Iterable[str] = FORBIDDEN_KEYS,
    canary_values: Iterable[str] = (),
    path: str = "$",
) -> None:
    """Reject forbidden field names and evaluator canaries at any depth."""

    blocked = {_normalise_key(key) for key in forbidden_keys}
    canaries = {str(item) for item in canary_values if str(item)}
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalised = _normalise_key(key)
            child_path = f"{path}.{key}"
            if normalised in blocked:
                raise LeakageError(f"privileged field at {child_path}: {key}")
            scan_for_leakage(
                child,
                forbidden_keys=blocked,
                canary_values=canaries,
                path=child_path,
            )
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            scan_for_leakage(
                child,
                forbidden_keys=blocked,
                canary_values=canaries,
                path=f"{path}[{index}]",
            )
        return
    if isinstance(value, str) and value in canaries:
        raise LeakageError(f"evaluator canary value at {path}")
