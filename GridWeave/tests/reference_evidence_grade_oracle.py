"""Independent Phase 2.3 evidence-grade reference evaluator.

It consumes only the grade registry and input fixtures.  It deliberately imports
no production ``htgl_dataset_generator`` package.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping


SUCCESS_DISPOSITIONS = {"ERASED", "CRYPTO_ERASED", "APPROVED_TRANSFORM"}


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def evaluate_receipt(
    registry: Mapping[str, Any], defaults: Mapping[str, Any], raw: Mapping[str, Any]
) -> dict[str, Any]:
    forbidden = {"expected_grade", "expected_status", "oracle", "manual"} & set(raw)
    if forbidden:
        raise ValueError(f"grade input contains forbidden answer fields: {sorted(forbidden)}")
    receipt = _merge(defaults, raw)
    profiles = {row["evidence_type"]: row for row in registry["receipt_types"]}
    profile = profiles.get(receipt["evidence_type"])
    rejection: str | None = None
    if profile is None:
        rejection = "UNKNOWN_RECEIPT_TYPE"
    elif not receipt["canonical_valid"]:
        rejection = "MALFORMED_CANONICAL_PAYLOAD"
    elif not receipt["obligation_bound"]:
        rejection = "UNRESOLVED_OBLIGATION_BINDING"
    elif not receipt["provenance_complete"]:
        rejection = "MISSING_PROVENANCE"
    elif _time(receipt["evaluation_time"]) < _time(receipt["not_before"]):
        rejection = "RECEIPT_NOT_YET_VALID"
    elif receipt.get("expires_at") and _time(receipt["evaluation_time"]) >= _time(receipt["expires_at"]):
        rejection = "RECEIPT_EXPIRED"
    elif not receipt["verification_material_available"]:
        rejection = "VERIFICATION_MATERIAL_UNAVAILABLE"
    elif profile["requires_key"] and not receipt["credential_valid_at_event"]:
        rejection = "CREDENTIAL_INVALID_AT_EVENT"
    elif profile["requires_key"] and not receipt["authenticator_valid"]:
        rejection = "INVALID_AUTHENTICATOR"
    elif profile["requires_anchor"] and not receipt["anchor_valid"]:
        rejection = "INVALID_OR_MISSING_ANCHOR"

    downgrade: list[str] = []
    grade: str | None = None
    conclusion: str | None = None
    if rejection is None and profile is not None:
        grade = profile["standalone_grade"]
        conclusion = profile["conclusion"]
        if grade == "E2":
            if receipt["ordering_support_valid"]:
                grade = "E3"
                conclusion = "ORDERED_AUTHENTICATED_ASSERTION"
            else:
                downgrade.append("ORDERING_SUPPORT_MISSING")
        mechanism = receipt["mechanism"]
        if grade == "E3":
            if not mechanism["present"]:
                downgrade.append("MECHANISM_ATTESTATION_MISSING")
            elif mechanism.get("expires_at") and _time(receipt["evaluation_time"]) >= _time(mechanism["expires_at"]):
                downgrade.append("MECHANISM_ATTESTATION_EXPIRED")
            elif mechanism["valid"]:
                grade = "E4"
                conclusion = "MECHANISM_EXECUTION_ASSERTION_UNDER_ASSUMPTIONS"
            else:
                downgrade.append("MECHANISM_ATTESTATION_MISSING")
        if _time(receipt["event_time"]) > _time(receipt["obligation_deadline"]):
            downgrade.append("LATE_FOR_OBLIGATION")

    timely = _time(receipt["event_time"]) <= _time(receipt["obligation_deadline"])
    closure_admissible = bool(
        rejection is None
        and profile is not None
        and profile["terminal_assertion"]
        and receipt["disposition"] in SUCCESS_DISPOSITIONS
        and timely
    )
    return {
        "receipt_id": receipt["receipt_id"],
        "status": "REJECTED" if rejection else "GRADED",
        "grade": grade,
        "rejection_reason": rejection,
        "downgrade_reasons": sorted(set(downgrade)),
        "conclusion": conclusion,
        "closure_admissible": closure_admissible,
        "physical_destruction_concluded": False,
        "obligation_id": receipt["obligation_id"],
        "issuer_id": receipt["issuer_id"],
        "issuer_role": receipt["issuer_role"],
        "trust_domain": receipt["trust_domain"],
        "fault_domain": receipt["fault_domain"],
        "disposition": receipt["disposition"],
        "corroboration_eligible": bool(profile and profile["corroboration_eligible"]),
        "terminal_assertion": bool(profile and profile["terminal_assertion"]),
    }


def evaluate_suite(registry: Mapping[str, Any], suite: Mapping[str, Any]) -> dict[str, Any]:
    receipts = {
        raw["receipt_id"]: evaluate_receipt(registry, suite["receipt_defaults"], raw)
        for raw in suite["receipts"]
    }
    bundles = [evaluate_bundle(registry, suite, raw, receipts) for raw in suite["bundles"]]
    return {"receipts": receipts, "bundles": {row["bundle_id"]: row for row in bundles}}


def evaluate_bundle(
    registry: Mapping[str, Any],
    suite: Mapping[str, Any],
    raw: Mapping[str, Any],
    receipt_results: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    forbidden = {"expected_grade", "expected_status", "oracle", "manual"} & set(raw)
    if forbidden:
        raise ValueError(f"bundle input contains forbidden answer fields: {sorted(forbidden)}")
    grade_order = registry["grade_order"]
    rank = {grade: index for index, grade in enumerate(grade_order)}
    support_ids = raw.get("support_receipt_ids", [])
    missing_ids = sorted(
        receipt_id
        for receipt_id in ([raw.get("primary_receipt_id")] + support_ids)
        if receipt_id is not None and receipt_id not in receipt_results
    )
    primary_id = raw.get("primary_receipt_id")
    downgrade: list[str] = []
    if primary_id is None:
        grade = "E0"
        status = "GRADED"
        reason = None
        conclusion = "CASE_OR_REQUEST_RECORDED"
    elif primary_id not in receipt_results:
        grade = None
        status = "REJECTED"
        reason = "PRIMARY_EVIDENCE_MISSING"
        conclusion = None
    else:
        primary = receipt_results[primary_id]
        if primary["status"] == "REJECTED":
            grade = None
            status = "REJECTED"
            reason = f"PRIMARY_{primary['rejection_reason']}"
            conclusion = None
        elif not primary["terminal_assertion"]:
            grade = primary["grade"]
            status = "GRADED"
            reason = None
            conclusion = primary["conclusion"]
            downgrade.extend(primary["downgrade_reasons"])
        else:
            grade = primary["grade"]
            status = "GRADED"
            reason = None
            conclusion = primary["conclusion"]
            downgrade.extend(primary["downgrade_reasons"])

    available = [receipt_results[item] for item in support_ids if item in receipt_results]
    considered = ([receipt_results[primary_id]] if primary_id in receipt_results else []) + available
    admissible_terminal = [
        row
        for row in considered
        if row["status"] == "GRADED"
        and row["terminal_assertion"]
        and row["obligation_id"] == raw["obligation_id"]
    ]
    conflict = len({row["disposition"] for row in admissible_terminal}) > 1
    if conflict:
        grade = None
        status = "DISPUTED"
        reason = "CONFLICTING_ADMISSIBLE_EVIDENCE"
        conclusion = None
        downgrade = []
    elif status == "GRADED" and grade is not None:
        ordered_support = any(
            row["status"] == "GRADED"
            and row["grade"] in {"E3", "E4"}
            and row["obligation_id"] == raw["obligation_id"]
            for row in available
        )
        if grade == "E2" and ordered_support:
            grade = "E3"
            conclusion = "ORDERED_AUTHENTICATED_ASSERTION"
            downgrade = [item for item in downgrade if item != "ORDERING_SUPPORT_MISSING"]
        if missing_ids:
            downgrade.append("ORDERING_SUPPORT_MISSING")

        if grade == "E4":
            corroborators = [
                row
                for row in available
                if row["status"] == "GRADED"
                and row["corroboration_eligible"]
                and row["obligation_id"] == raw["obligation_id"]
                and row["disposition"] == receipt_results[primary_id]["disposition"]
                and row["issuer_id"] != receipt_results[primary_id]["issuer_id"]
            ]
            required_count = int(raw.get("required_corroborators", 0))
            required_domains = int(raw.get("required_independent_domains", 0))
            independent_pairs = {(row["trust_domain"], row["fault_domain"]) for row in corroborators}
            primary_pair = (
                receipt_results[primary_id]["trust_domain"],
                receipt_results[primary_id]["fault_domain"],
            )
            independent_pairs.discard(primary_pair)
            if required_count and len(corroborators) < required_count:
                downgrade.append("CORROBORATION_BELOW_QUORUM")
            elif required_domains and len(independent_pairs) < required_domains:
                downgrade.append("CORROBORATION_NOT_INDEPENDENT")
            elif required_count or required_domains:
                grade = "E5"
                conclusion = "INDEPENDENTLY_CORROBORATED_MECHANISM_ASSERTION_UNDER_ASSUMPTIONS"

        required_grade = raw.get("required_grade", "E0")
        if rank[grade] < rank[required_grade]:
            downgrade.append("INSUFFICIENT_GRADE_FOR_OBLIGATION")
            status = "REJECTED"
            reason = "INSUFFICIENT_GRADE_FOR_OBLIGATION"

    return {
        "bundle_id": raw["bundle_id"],
        "status": status,
        "grade": grade,
        "reason": reason,
        "downgrade_reasons": sorted(set(downgrade)),
        "missing_receipt_ids": missing_ids,
        "conclusion": conclusion,
        "physical_destruction_concluded": False,
    }
