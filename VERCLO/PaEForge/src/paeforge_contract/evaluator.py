"""Evaluator-only PaEBench adapter; never import this module in VERCLO."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence

from .canonical import sha256_digest
from .validation import CONTRACT_VERSION, MODEL_VERSION, validate_document


SCHEMA_VERSION = "1.0.0"


def _timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return parsed.isoformat().replace("+00:00", "Z")


def build_evaluation_report(
    *,
    sealed_truth: Mapping[str, Any],
    verclo_result: Mapping[str, Any],
    evaluated_at: datetime | str,
    visibility_attribution: str,
    provenance: Mapping[str, Any],
    obligation_id_map: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Compare truth only after accepting an already frozen VERCLO result."""

    validate_document(verclo_result)
    if sealed_truth.get("access_class") != "evaluator_only":
        raise ValueError("sealed truth must be explicitly evaluator_only")
    truth_case = next(
        (row for row in sealed_truth.get("cases", ()) if row.get("case_id") == verclo_result["case_id"]),
        None,
    )
    if truth_case is None:
        raise ValueError("sealed truth has no matching case_id")
    for label in ("run_id", "scenario_id"):
        if sealed_truth.get(label) != verclo_result[label]:
            raise ValueError(f"sealed truth {label} does not match VERCLO result")
    if sealed_truth.get("replicate_id") != verclo_result["seed"]["replicate_id"]:
        raise ValueError("sealed truth replicate_id does not match VERCLO result")
    if sealed_truth.get("seed_stream_digest") != verclo_result["seed"]["seed_stream_digest"]:
        raise ValueError("sealed truth seed digest does not match VERCLO result")

    expected = truth_case["closure_ground_truth"]["outcome"]
    observed = verclo_result["closure_class"]
    classification = "NOT_FINAL" if observed == "IN_PROGRESS" else ("MATCH" if observed == expected else "MISMATCH")
    mapping = obligation_id_map or {}
    truth_obligations: set[str] = set()
    for row in truth_case["obligation_graph"]["obligations"]:
        source_id = str(row["obligation_id"])
        translated = tuple(map(str, mapping.get(source_id, (source_id,))))
        if not translated:
            raise ValueError(f"empty evaluator obligation mapping for {source_id}")
        truth_obligations.update(translated)
    observed_obligations = {
        row["obligation_id"] for row in verclo_result["obligation_results"]
    }
    closed = {"CLOSED", "CLOSED_WITH_EXCEPTIONS"}
    metrics = {
        "truth_obligation_count": len(truth_obligations),
        "verclo_obligation_count": len(observed_obligations),
        "true_positive_obligations": len(truth_obligations & observed_obligations),
        "false_positive_obligations": len(observed_obligations - truth_obligations),
        "false_negative_obligations": len(truth_obligations - observed_obligations),
        "false_closure": observed in closed and expected not in closed,
        "missed_closure": expected in closed and observed not in closed,
    }
    payload = {
        "schema_id": "https://paeforge.local/schema/evaluation-report/v1",
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "model_version": MODEL_VERSION,
        "data_class": "EVALUATOR_OUTPUT",
        "access_class": "evaluator_only",
        "exchange_id": verclo_result["exchange_id"],
        "run_id": verclo_result["run_id"],
        "scenario_id": verclo_result["scenario_id"],
        "case_id": verclo_result["case_id"],
        "seed": dict(verclo_result["seed"]),
        "evaluated_at": _timestamp(evaluated_at),
        "expected_closure": expected,
        "observed_closure": observed,
        "classification": classification,
        "visibility_attribution": visibility_attribution,
        "metrics": metrics,
        "inputs": {
            "sealed_truth_sha256": sha256_digest(sealed_truth),
            "verclo_result_sha256": sha256_digest(verclo_result),
        },
        "provenance": dict(provenance),
    }
    validate_document(payload)
    return payload
