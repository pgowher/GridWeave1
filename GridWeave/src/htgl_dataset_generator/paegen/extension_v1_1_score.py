"""Task-contract scorer. Opens sealed truth only after predictions are fixed."""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from itertools import combinations
from pathlib import Path
from statistics import median
from typing import Any

from .extension_v1_1 import RELEASE, read_json
from .extension_v1_1_oracle import LABELS, digest, evaluate, graph_material


def macro_f1(truth: list[str], predictions: list[str], labels: list[str]) -> dict:
    rows = {}
    for label in labels:
        support = sum(value == label for value in truth)
        tp = sum(a == label and b == label for a, b in zip(truth, predictions))
        fp = sum(a != label and b == label for a, b in zip(truth, predictions))
        fn = support - tp
        rows[label] = {"support": support, "f1": (2 * tp / (2 * tp + fp + fn))
                       if 2 * tp + fp + fn else None}
    return {"per_class": rows, "macro_f1_all_registered": sum(
        row["f1"] or 0 for row in rows.values()) / len(labels),
        "unsupported_classes": [label for label, row in rows.items() if row["support"] == 0]}


def _by_id(rows: list[dict], field: str) -> dict[str, dict]:
    result = {row[field]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"duplicate prediction {field}")
    return result


def _unique_strings(values: Any, label: str, nonempty: bool = False) -> None:
    if (not isinstance(values, list) or any(not isinstance(x, str) for x in values)
            or len(values) != len(set(values)) or (nonempty and not values)):
        raise ValueError(f"invalid unique string array: {label}")


def validate_predictions(predictions: dict) -> None:
    if set(predictions) != {f"PBE-T{i}" for i in range(1, 7)}:
        raise ValueError("all six task predictions are required")
    for row in predictions["PBE-T1"]:
        if (row.get("outcome") not in LABELS or not isinstance(row.get("abstained"), bool)):
            raise ValueError("invalid PBE-T1 outcome or abstention")
        _unique_strings(row.get("reason_codes"), "T1 reason_codes", True)
    for row in predictions["PBE-T2"]:
        if row.get("baseline_status") not in {"VERIFIABLE", "UNVERIFIABLE"}:
            raise ValueError("invalid PBE-T2 baseline")
        obligations = row.get("obligations")
        if (not isinstance(obligations, list) or any(not isinstance(o, list) or len(o) != 4 or
               any(not isinstance(v, str) for v in o) for o in obligations) or
                len(obligations) != len({tuple(o) for o in obligations})):
            raise ValueError("invalid PBE-T2 obligations")
        _unique_strings(row.get("missing_information_codes"), "T2 missing_information_codes")
    for row in predictions["PBE-T3"]:
        if row.get("admissibility") not in {"ADMISSIBLE", "REJECTED", "INSUFFICIENT"}:
            raise ValueError("invalid PBE-T3 admissibility")
        if row.get("evidence_grade") not in {"NONE", "E0", "E1", "E2", "E3", "E4", "E5"}:
            raise ValueError("invalid PBE-T3 grade")
        if not isinstance(row.get("primary_reason_code"), str) or not row["primary_reason_code"]:
            raise ValueError("invalid PBE-T3 reason")
        _unique_strings(row.get("secondary_reason_codes"), "T3 secondary_reason_codes")
    for row in predictions["PBE-T4"]:
        if row.get("detection_status") not in {"DETECTED", "NOT_DETECTED", "INDISTINGUISHABLE"}:
            raise ValueError("invalid PBE-T4 detection")
        if not isinstance(row.get("attack_family"), str) or not row["attack_family"]:
            raise ValueError("invalid PBE-T4 attack family")
        _unique_strings(row.get("evidence_refs"), "T4 evidence_refs")
    for row in predictions["PBE-T5"]:
        if row.get("claimed_post_repair_outcome") not in LABELS:
            raise ValueError("invalid PBE-T5 outcome")
        _unique_strings(row.get("target_ids"), "T5 target_ids")
        actions = row.get("repair_actions")
        if not isinstance(actions, list) or any(not isinstance(x, dict) or "action" not in x
                                                 for x in actions):
            raise ValueError("invalid PBE-T5 actions")
        if set(row["target_ids"]) != {x["target_id"] for x in actions if "target_id" in x}:
            raise ValueError("PBE-T5 target IDs disagree with actions")
    if len(predictions["PBE-T6"]) != 1:
        raise ValueError("PBE-T6 requires one run")
    run = predictions["PBE-T6"][0]
    if not isinstance(run.get("wall_time_ms"), int) or run["wall_time_ms"] < 0:
        raise ValueError("invalid PBE-T6 wall time")
    manifest = run.get("environment_manifest")
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("details"), dict)
            or manifest.get("sha256") != digest(manifest["details"])):
        raise ValueError("invalid PBE-T6 digest-addressed environment")


def _score_t1(truth: list[dict], predictions: list[dict]) -> dict:
    expected = _by_id(truth, "case_id")
    got = _by_id(predictions, "case_id")
    if expected.keys() != got.keys():
        raise ValueError("PBE-T1 prediction IDs incomplete or extraneous")
    keys = sorted(expected)
    labels = [expected[k]["outcome"] for k in keys]
    output = [got[k]["outcome"] for k in keys]
    if any(value not in LABELS for value in output):
        raise ValueError("invalid closure outcome")
    positives = {"CLOSED", "CLOSED_WITH_EXCEPTIONS"}
    nonclosed = [k for k in keys if expected[k]["outcome"] not in positives]
    return {**macro_f1(labels, output, list(LABELS)),
            "exact_outcome_and_reason_rate": sum(
                expected[k]["outcome"] == got[k]["outcome"] and
                set(expected[k]["reason_codes"]) == set(got[k]["reason_codes"])
                for k in keys) / len(keys),
            "unsafe_positive_closure_rate": sum(got[k]["outcome"] in positives
                                                for k in nonclosed) / len(nonclosed)}


def _score_t2(truth: list[dict], predictions: list[dict]) -> dict:
    expected = _by_id(truth, "case_id")
    got = _by_id(predictions, "case_id")
    if expected.keys() != got.keys():
        raise ValueError("PBE-T2 prediction IDs incomplete or extraneous")
    f1s = []
    for key in expected:
        a = {tuple(x) for x in expected[key]["obligations"]}
        b = {tuple(x) for x in got[key]["obligations"]}
        f1s.append(2 * len(a & b) / (len(a) + len(b)) if a or b else 1.0)
    return {"mean_set_f1": sum(f1s) / len(f1s),
            "baseline_accuracy": sum(expected[k]["baseline_status"] == got[k]["baseline_status"]
                                     for k in expected) / len(expected)}


def _score_t3(truth: list[dict], predictions: list[dict]) -> dict:
    expected = _by_id(truth, "receipt_id")
    got = _by_id(predictions, "receipt_id")
    if expected.keys() != got.keys():
        raise ValueError("PBE-T3 prediction IDs incomplete or extraneous")
    keys = sorted(expected)
    return {**macro_f1([expected[k]["admissibility"] for k in keys],
                       [got[k]["admissibility"] for k in keys],
                       ["ADMISSIBLE", "REJECTED", "INSUFFICIENT"]),
            "primary_reason_accuracy": sum(expected[k]["primary_reason_code"] ==
                                           got[k]["primary_reason_code"] for k in keys) / len(keys),
            "grade_accuracy": sum(expected[k]["evidence_grade"] == got[k]["evidence_grade"]
                                  for k in keys) / len(keys)}


def _score_t4(truth: list[dict], predictions: list[dict]) -> dict:
    expected = _by_id(truth, "case_id")
    got = _by_id(predictions, "case_id")
    if expected.keys() != got.keys():
        raise ValueError("PBE-T4 prediction IDs incomplete or extraneous")
    keys = sorted(expected)
    labels = ["DETECTED", "NOT_DETECTED", "INDISTINGUISHABLE"]
    per_class = macro_f1([expected[k]["detection_status"] for k in keys],
                         [got[k]["detection_status"] for k in keys], labels)
    recall = {}
    for label in labels:
        subset = [k for k in keys if expected[k]["detection_status"] == label]
        recall[label] = (sum(got[k]["detection_status"] == label for k in subset) / len(subset)
                         if subset else None)
    hidden = [k for k in keys if expected[k]["observer_equivalent"] and
              expected[k]["attack_present"]]
    return {"balanced_accuracy": sum(value or 0 for value in recall.values()) / len(labels),
            "recall_by_class": recall, "indistinguishable_false_accusation_rate":
            sum(got[k]["detection_status"] == "DETECTED" for k in hidden) / len(hidden)
            if hidden else None, "class_support": per_class["per_class"]}


def replay_repair(observer: dict, clean: dict, actions: list[dict]) -> dict:
    current = deepcopy(observer)
    clean_receipts = {r["obligation_id"]: r for r in clean["receipts"]
                      if r["claimed_disposition"] != "FAILED"}
    for item in actions:
        action = item["action"]
        target = item.get("target_id")
        if action == "RESTORE_VALID_RECEIPT":
            if target not in clean_receipts:
                raise ValueError("no clean public receipt for target")
            current["receipts"] = [r for r in current["receipts"]
                                   if r["obligation_id"] != target] + [deepcopy(clean_receipts[target])]
        elif action == "RESTORE_SCOPE_COMMITMENT":
            current["scope_commitment"] = digest(graph_material(current))
        elif action == "REMOVE_CONTRADICTORY_RECEIPT":
            if target not in clean_receipts:
                raise ValueError("unknown repair target")
            current["receipts"] = [r for r in current["receipts"]
                                   if not (r["obligation_id"] == target and r["receipt_id"] !=
                                           clean_receipts[target]["receipt_id"])]
        elif action == "WAIT_UNTIL_DEADLINE":
            current["evaluation_time"] = clean["evaluation_time"]
        elif action == "NO_OBSERVER_REPAIR":
            if len(actions) != 1:
                raise ValueError("NO_OBSERVER_REPAIR must stand alone")
        else:
            raise ValueError(f"unknown repair action: {action}")
    return evaluate(current)


def _minimum_repair(observer: dict, clean: dict) -> int | None:
    if evaluate(observer)["outcome"] in {"CLOSED", "CLOSED_WITH_EXCEPTIONS"}:
        return 0
    available = []
    clean_by_obligation = {r["obligation_id"]: r for r in clean["receipts"]
                           if r["claimed_disposition"] != "FAILED"}
    current_by_obligation = defaultdict(list)
    for receipt in observer["receipts"]:
        current_by_obligation[receipt["obligation_id"]].append(receipt)
    for oid, receipt in clean_by_obligation.items():
        if current_by_obligation[oid] != [receipt]:
            available.append({"action": "RESTORE_VALID_RECEIPT", "target_id": oid})
    if observer["scope_commitment"] is None:
        available.append({"action": "RESTORE_SCOPE_COMMITMENT"})
    if observer["evaluation_time"] != clean["evaluation_time"]:
        available.append({"action": "WAIT_UNTIL_DEADLINE"})
    for count in range(1, len(available) + 1):
        for subset in combinations(available, count):
            if replay_repair(observer, clean, list(subset))["outcome"] in {
                    "CLOSED", "CLOSED_WITH_EXCEPTIONS"}:
                return count
    return None


def _score_t5(inputs: list[dict], predictions: list[dict], sealed: dict) -> dict:
    expected = _by_id(inputs, "case_id")
    got = _by_id(predictions, "case_id")
    if expected.keys() != got.keys():
        raise ValueError("PBE-T5 prediction IDs incomplete or extraneous")
    clean_by_family = {}
    for case_id, row in expected.items():
        source = sealed[case_id]
        if source["source_variant_id"] in {"clean", "success", "success-with-retention",
                                            "success-retrained"}:
            clean_by_family[source["source_family_id"]] = row["observer"]
    valid, excess = [], []
    for case_id, row in expected.items():
        clean = clean_by_family[sealed[case_id]["source_family_id"]]
        prediction = got[case_id]
        actions = prediction["repair_actions"]
        result = replay_repair(row["observer"], clean, actions)
        minimum = _minimum_repair(row["observer"], clean)
        valid.append(result["outcome"] == prediction["claimed_post_repair_outcome"] and (
            (minimum == 0 and not actions) or
            (minimum is None and actions == [{"action": "NO_OBSERVER_REPAIR"}]) or
            (minimum is not None and minimum > 0 and result["outcome"] in
             {"CLOSED", "CLOSED_WITH_EXCEPTIONS"})))
        if minimum is not None and result["outcome"] in {"CLOSED", "CLOSED_WITH_EXCEPTIONS"}:
            excess.append(len(actions) - minimum)
    return {"repair_validity": sum(valid) / len(valid),
            "mean_excess_edits_for_closed_repairs": sum(excess) / len(excess) if excess else None,
            "closed_repairs_scored": len(excess)}


def score(prediction_file: Path, release: Path = RELEASE) -> dict[str, Any]:
    predictions = read_json(prediction_file)
    validate_predictions(predictions)
    truth = read_json(release / "sealed-ground-truth/task-truth.json")
    inputs = {f"PBE-T{i}": read_json(release / "task-inputs" / f"PBE-T{i}.json")
              for i in range(1, 7)}
    sealed = {p.stem: read_json(p) for p in (release / "sealed-ground-truth").glob("unit-*.json")}
    results = {"PBE-T1": _score_t1(truth["PBE-T1"], predictions["PBE-T1"]),
               "PBE-T2": _score_t2(truth["PBE-T2"], predictions["PBE-T2"]),
               "PBE-T3": _score_t3(truth["PBE-T3"], predictions["PBE-T3"]),
               "PBE-T4": _score_t4(truth["PBE-T4"], predictions["PBE-T4"]),
               "PBE-T5": _score_t5(inputs["PBE-T5"], predictions["PBE-T5"], sealed)}
    run = predictions["PBE-T6"]
    if len(run) != 1 or run[0]["run_id"] != "PBE-E1-RUN":
        raise ValueError("PBE-T6 requires one registered run")
    run_outputs = _by_id(run[0]["per_case_outputs"], "case_id")
    t1_outputs = _by_id(predictions["PBE-T1"], "case_id")
    if run_outputs.keys() != t1_outputs.keys() or any(
            run_outputs[key] != t1_outputs[key] for key in t1_outputs):
        raise ValueError("PBE-T6 per-case outputs must match the submitted T1 run")
    times = run[0]["per_case_wall_time_ms"]
    if len(times) != len(inputs["PBE-T1"]) or any(not isinstance(x, int) or x < 0 for x in times):
        raise ValueError("PBE-T6 per-case latency coverage invalid")
    if not run[0].get("environment_manifest") or run[0]["peak_rss_bytes"] < 0:
        raise ValueError("PBE-T6 environment or RSS missing")
    gate = inputs["PBE-T6"][0]["correctness_gate"]
    eligible = (results["PBE-T1"]["unsafe_positive_closure_rate"] <= gate["unsafe_close_ceiling"]
                and results["PBE-T2"]["mean_set_f1"] >= gate["t2_set_f1_floor"]
                and results["PBE-T3"]["macro_f1_all_registered"] >= gate["t3_status_macro_f1_floor"])
    ordered = sorted(times)
    results["PBE-T6"] = {"ranking_eligible": eligible, "median_case_latency_ms": median(times),
                         "p95_case_latency_ms": ordered[min(len(ordered)-1, int(.95*len(ordered)))],
                         "peak_rss_bytes": run[0]["peak_rss_bytes"],
                         "environment_manifest": run[0]["environment_manifest"]}
    return results
