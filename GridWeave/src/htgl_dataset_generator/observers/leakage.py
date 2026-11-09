"""Strict non-leakage scanner for sanitized observer release records."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping

from .models import LeakageDiagnostics, LeakageFinding, ObserverReleaseView
from .profiles import ObserverProfileBundle


TRUTH_SET_ID = "FORBID-TRUTH-LABELS"
PAIR_SET_ID = "FORBID-PAIR-IDS"
SEALED_SET_ID = "FORBID-SEALED-IDS"
SAMPLING_SET_ID = "FORBID-SAMPLING-PROBABILITIES"
UUID_TOKEN_PATTERN = re.compile(
    r"(?<![0-9a-fA-F])"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"(?![0-9a-fA-F])"
)


def scan_observer_releases(
    release_views: Mapping[str, ObserverReleaseView],
    *,
    bundle: ObserverProfileBundle,
    exact_protected_identifiers: Iterable[str],
    pair_identifiers: Iterable[str],
    sealed_truth_values: Iterable[str],
) -> LeakageDiagnostics:
    """Scan every released field and scalar without consulting projection labels."""

    forbidden_truth = set(bundle.forbidden_field_sets[TRUTH_SET_ID])
    forbidden_pairs = set(bundle.forbidden_field_sets[PAIR_SET_ID])
    forbidden_sealed = set(bundle.forbidden_field_sets[SEALED_SET_ID])
    forbidden_sampling = set(bundle.forbidden_field_sets[SAMPLING_SET_ID])
    exact_ids = {value for value in exact_protected_identifiers if value}
    pair_ids = {value for value in pair_identifiers if value}
    truth_values = {value for value in sealed_truth_values if value}
    findings: list[LeakageFinding] = []
    scalar_count = 0
    record_count = 0
    for profile_id, view in sorted(release_views.items()):
        for record in view.records:
            record_count += 1
            record_id = str(record.get("observer_record_id", ""))
            serialized = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            for path, key, value in _walk(record):
                if key is not None:
                    if key in forbidden_truth:
                        findings.append(LeakageFinding(profile_id, record_id, "sealed_truth_field", path, key))
                    if key in forbidden_pairs:
                        findings.append(LeakageFinding(profile_id, record_id, "pair_identifier_field", path, key))
                    if key in forbidden_sealed:
                        findings.append(LeakageFinding(profile_id, record_id, "sealed_identifier_field", path, key))
                    if key in forbidden_sampling:
                        findings.append(LeakageFinding(profile_id, record_id, "inclusion_probability_field", path, key))
                if value is None or isinstance(value, (dict, list, tuple)):
                    continue
                scalar_count += 1
                scalar = str(value)
                if scalar in exact_ids:
                    findings.append(LeakageFinding(profile_id, record_id, "exact_protected_identifier", path, scalar))
                if scalar in pair_ids:
                    findings.append(LeakageFinding(profile_id, record_id, "pair_identifier_value", path, scalar))
                if scalar in truth_values:
                    findings.append(LeakageFinding(profile_id, record_id, "sealed_truth_value", path, scalar))
            embedded_identifiers = set(UUID_TOKEN_PATTERN.findall(serialized))
            for pair_id in sorted(embedded_identifiers & pair_ids):
                findings.append(LeakageFinding(profile_id, record_id, "embedded_pair_identifier", "$", pair_id))
            for exact_id in sorted(embedded_identifiers & exact_ids):
                findings.append(LeakageFinding(profile_id, record_id, "embedded_protected_identifier", "$", exact_id))
    unique = {
        (item.profile_id, item.observer_record_id, item.finding_type, item.path, item.matched_token): item
        for item in findings
    }
    ordered = tuple(sorted(unique.values(), key=lambda item: (
        item.profile_id, item.observer_record_id, item.finding_type, item.path, item.matched_token
    )))
    return LeakageDiagnostics(
        scanned_profile_count=len(release_views),
        scanned_record_count=record_count,
        scanned_scalar_count=scalar_count,
        sealed_truth_leakage_count=sum(item.finding_type.startswith("sealed_truth") for item in ordered),
        forbidden_field_count=sum(item.finding_type.endswith("_field") for item in ordered),
        exact_identifier_leakage_count=sum("protected_identifier" in item.finding_type for item in ordered),
        pair_identifier_leakage_count=sum("pair_identifier" in item.finding_type for item in ordered),
        inclusion_probability_leakage_count=sum(item.finding_type == "inclusion_probability_field" for item in ordered),
        findings=ordered,
    )


def _walk(value: Any, path: str = "$", key: str | None = None):
    yield path, key, value
    if isinstance(value, Mapping):
        for child_key in sorted(value):
            yield from _walk(value[child_key], f"{path}.{child_key}", str(child_key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]", None)
