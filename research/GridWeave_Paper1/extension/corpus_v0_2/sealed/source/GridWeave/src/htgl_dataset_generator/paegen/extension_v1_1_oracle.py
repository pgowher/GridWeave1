"""Independent observer-relative oracle for the PaEBench 1.1 extension.

This module reads released case facts, never a declared closure label or variant
name. It deliberately does not import the extension compiler.
"""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


LABELS = ("CLOSED", "CLOSED_WITH_EXCEPTIONS", "PARTIALLY_CLOSED", "OPEN",
          "DISPUTED", "UNVERIFIABLE", "IN_PROGRESS")
GRADES = {"NONE": -1, "E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp is not timezone aware")
    return parsed


def graph_material(case: Mapping[str, Any]) -> dict[str, Any]:
    return {key: case[key] for key in ("assets", "repositories", "obligations", "policy")}


def receipt_result(receipt: Mapping[str, Any], obligation: Mapping[str, Any],
                   policy: Mapping[str, Any]) -> dict[str, Any]:
    if receipt.get("public_key") is None or receipt.get("signature") is None:
        return {"admissibility": "INSUFFICIENT", "evidence_grade": "NONE",
                "primary_reason_code": "KEY_MATERIAL_UNAVAILABLE"}
    if receipt["public_key"] != policy["principal_public_keys"].get(receipt["issuer_id"]):
        return {"admissibility": "REJECTED", "evidence_grade": "NONE",
                "primary_reason_code": "UNTRUSTED_SIGNING_KEY"}
    signed = {key: receipt[key] for key in
              ("receipt_id", "obligation_id", "issuer_id", "claimed_disposition", "event_time")}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt["public_key"])).verify(
            bytes.fromhex(receipt["signature"]), canonical(signed)
        )
    except (ValueError, InvalidSignature, TypeError):
        return {"admissibility": "REJECTED", "evidence_grade": "NONE",
                "primary_reason_code": "INVALID_AUTHENTICATOR"}
    if (receipt["obligation_id"] != obligation["obligation_id"]
            or receipt["issuer_id"] != obligation["principal_id"]):
        return {"admissibility": "REJECTED", "evidence_grade": "NONE",
                "primary_reason_code": "RECEIPT_BINDING_MISMATCH"}
    if receipt.get("anchor_commitment") and receipt["anchor_commitment"] != digest(signed):
        return {"admissibility": "REJECTED", "evidence_grade": "NONE",
                "primary_reason_code": "ANCHOR_BINDING_MISMATCH"}
    grade = "E4" if receipt.get("mechanism_attestation") else (
        "E3" if receipt.get("anchor_commitment") else "E2"
    )
    if instant(receipt["event_time"]) > instant(obligation["deadline"]):
        return {"admissibility": "REJECTED", "evidence_grade": grade,
                "primary_reason_code": "LATE_FOR_OBLIGATION"}
    if receipt["claimed_disposition"] not in obligation["permitted_dispositions"]:
        return {"admissibility": "ADMISSIBLE", "evidence_grade": grade,
                "primary_reason_code": "VALID_TERMINAL_FAILURE"}
    if GRADES[grade] < GRADES[obligation["evidence_floor"]]:
        return {"admissibility": "INSUFFICIENT", "evidence_grade": grade,
                "primary_reason_code": "GRADE_BELOW_FLOOR"}
    return {"admissibility": "ADMISSIBLE", "evidence_grade": grade,
            "primary_reason_code": "ADMISSIBLE_SUCCESS"}


def evaluate(case: Mapping[str, Any]) -> dict[str, Any]:
    obligations = {row["obligation_id"]: row for row in case["obligations"]}
    receipt_truth: dict[str, dict[str, Any]] = {}
    receipts_by_obligation: dict[str, list[Mapping[str, Any]]] = {key: [] for key in obligations}
    for receipt in case["receipts"]:
        obligation = obligations.get(receipt["obligation_id"])
        if obligation is None:
            raise ValueError("receipt binds unknown obligation")
        receipt_truth[receipt["receipt_id"]] = receipt_result(receipt, obligation, case["policy"])
        receipts_by_obligation[obligation["obligation_id"]].append(receipt)

    expected_commitment = digest(graph_material(case))
    baseline = bool(case.get("scope_commitment") == expected_commitment and obligations)
    categories: dict[str, str] = {}
    for obligation_id, obligation in obligations.items():
        receipts = receipts_by_obligation[obligation_id]
        admissible = [r for r in receipts if receipt_truth[r["receipt_id"]]["admissibility"] == "ADMISSIBLE"]
        claims = {r["claimed_disposition"] for r in admissible}
        if len(claims) > 1:
            category = "CONTRADICTORY"
        else:
            exception = next((row for row in case["exceptions"] if row["obligation_id"] == obligation_id), None)
            valid_exception = bool(
                exception and exception.get("basis_commitment")
                and exception["authority_id"] in case["policy"]["exception_authority_ids"]
                and exception.get("public_key") == case["policy"]["exception_authority_public_keys"].get(
                    exception["authority_id"])
                and instant(exception["effective_at"]) <= instant(obligation["deadline"])
                and instant(case["evaluation_time"]) < instant(exception["expires_at"])
            )
            if valid_exception:
                signed_exception = {key: exception[key] for key in
                                    ("obligation_id", "authority_id", "basis_commitment",
                                     "effective_at", "expires_at")}
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(exception["public_key"])).verify(
                        bytes.fromhex(exception["signature"]), canonical(signed_exception))
                except (ValueError, InvalidSignature, TypeError):
                    valid_exception = False
            if valid_exception:
                category = "EXCEPTED"
            elif any(receipt_truth[r["receipt_id"]]["primary_reason_code"] == "ADMISSIBLE_SUCCESS"
                     for r in admissible):
                category = "COVERED"
            elif not receipts:
                category = "MISSING"
            elif any(receipt_truth[r["receipt_id"]]["primary_reason_code"] == "LATE_FOR_OBLIGATION"
                     for r in receipts):
                category = "LATE"
            else:
                category = "INVALID"
        categories[obligation_id] = category

    ready = bool(obligations and instant(case["evaluation_time"]) >=
                 max(instant(row["deadline"]) for row in obligations.values()))
    values = tuple(categories.values())
    if not ready:
        outcome, reasons = "IN_PROGRESS", ("DECISION_TIME_NOT_REACHED",)
    elif not baseline:
        outcome, reasons = "UNVERIFIABLE", ("BASELINE_NOT_VERIFIABLE",)
    elif "CONTRADICTORY" in values:
        outcome, reasons = "DISPUTED", ("CONFLICTING_ADMISSIBLE_EVIDENCE",)
    elif values and all(value == "COVERED" for value in values):
        outcome, reasons = "CLOSED", ("ALL_OBLIGATIONS_RESOLVED",)
    elif values and all(value in {"COVERED", "EXCEPTED"} for value in values):
        outcome, reasons = "CLOSED_WITH_EXCEPTIONS", ("ALL_OBLIGATIONS_RESOLVED", "VALID_EXCEPTION_PRESENT")
    elif any(value in {"COVERED", "EXCEPTED"} for value in values):
        outcome, reasons = "PARTIALLY_CLOSED", ("SOME_OBLIGATIONS_UNRESOLVED",)
    else:
        outcome, reasons = "OPEN", ("NO_OBLIGATION_RESOLVED",)
    obligation_tuples = sorted([
        [row["asset_id"], row["replica_id"], row["repository_id"], row["principal_id"]]
        for row in obligations.values()
    ])
    return {
        "outcome": outcome, "reason_codes": list(reasons),
        "baseline_status": "VERIFIABLE" if baseline else "UNVERIFIABLE",
        "obligations": obligation_tuples,
        "missing_information_codes": [] if baseline else ["SCOPE_COMMITMENT_UNAVAILABLE"],
        "obligation_categories": dict(sorted(categories.items())),
        "receipt_truth": dict(sorted(receipt_truth.items())),
    }
