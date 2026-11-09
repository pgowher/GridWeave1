"""Focused semantic gates for the new case extension."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from htgl_dataset_generator.paegen.extension_v1_1 import (
    RELEASE, build_case, load_plan, materialize, negative_controls, read_json,
)
from htgl_dataset_generator.paegen.extension_v1_1_oracle import LABELS, canonical, digest, evaluate
from htgl_dataset_generator.paegen.extension_v1_1_score import _minimum_repair, replay_repair, score


def test_all_labels_have_source_derived_support_and_family_splits() -> None:
    build = materialize()
    assert {label for split in build["class_support"].values() for label, n in split.items() if n} == set(LABELS)
    assert len(build["families"]) == 6
    assert all(family["split"] == "test" for family in build["families"] if family["family_id"].startswith("PBE-XD"))
    assert all(unit["sealed"]["closure_ground_truth"] == evaluate(unit["observer"])
               for unit in build["units"])


def test_declared_label_is_rejected_and_hidden_copy_is_indistinguishable() -> None:
    plan, families, _ = load_plan()
    family = families[0]
    clean = build_case(family, family["variants"][0], plan["extension"]["seed"])[0]
    hidden = build_case(family, family["variants"][3], plan["extension"]["seed"])[0]
    assert canonical(clean) == canonical(hidden)
    bad = deepcopy(family["variants"][1])
    bad["expected_closure"] = "CLOSED"
    with pytest.raises(ValueError, match="declared label disagrees"):
        build_case(family, bad, plan["extension"]["seed"])


def test_leak_canaries_and_untrusted_key_are_rejected() -> None:
    build = materialize()
    case, sealed = build["units"][0]["observer"], build["units"][0]["sealed"]
    assert all(negative_controls(case, sealed).values())
    attacked = deepcopy(case)
    attacked["receipts"][0]["public_key"] = "00" * 32
    result = evaluate(attacked)
    assert "UNTRUSTED_SIGNING_KEY" in {row["primary_reason_code"] for row in result["receipt_truth"].values()}


def test_seed_reproduces_exact_observer_bytes() -> None:
    plan, families, _ = load_plan()
    left, _ = build_case(families[1], families[1]["variants"][2], plan["extension"]["seed"])
    right, _ = build_case(families[1], families[1]["variants"][2], plan["extension"]["seed"])
    assert canonical(left) == canonical(right)


def test_open_case_requires_each_missing_receipt_for_closure() -> None:
    plan, families, _ = load_plan()
    family = families[0]
    clean, _ = build_case(family, family["variants"][0], plan["extension"]["seed"])
    opened, _ = build_case(family, family["variants"][1], plan["extension"]["seed"])
    assert _minimum_repair(opened, clean) == len(clean["receipts"])
    actions = [{"action": "RESTORE_VALID_RECEIPT", "target_id": row["obligation_id"]}
               for row in clean["receipts"]]
    assert replay_repair(opened, clean, actions)["outcome"] == "CLOSED"


def test_six_task_scorer_rejects_noop_as_a_repair() -> None:
    truth = read_json(RELEASE / "sealed-ground-truth/task-truth.json")
    predictions = {key: [] for key in truth}
    predictions["PBE-T1"] = [{**row, "abstained": False} for row in truth["PBE-T1"]]
    predictions["PBE-T2"] = truth["PBE-T2"]
    predictions["PBE-T3"] = [{**row, "secondary_reason_codes": []} for row in truth["PBE-T3"]]
    predictions["PBE-T4"] = [{"case_id": row["case_id"],
                              "detection_status": row["detection_status"],
                              "attack_family": "UNKNOWN", "evidence_refs": []}
                             for row in truth["PBE-T4"]]
    predictions["PBE-T5"] = [{"case_id": row["case_id"], "repair_actions": [],
                              "target_ids": [], "claimed_post_repair_outcome": row["reference_outcome"]}
                             for row in truth["PBE-T5"]]
    predictions["PBE-T6"] = [{"run_id": "PBE-E1-RUN", "per_case_outputs": predictions["PBE-T1"],
                              "wall_time_ms": 21, "per_case_wall_time_ms": [1] * 21,
                              "peak_rss_bytes": 1,
                              "environment_manifest": {"details": {}, "sha256": digest({})}}]
    with TemporaryDirectory() as temporary:
        path = Path(temporary) / "internal-contract-check.json"
        path.write_text(json.dumps(predictions))
        result = score(path)
    assert result["PBE-T1"]["macro_f1_all_registered"] == 1
    assert result["PBE-T3"]["macro_f1_all_registered"] == 1
    assert result["PBE-T5"]["repair_validity"] < 1
    assert result["PBE-T6"]["ranking_eligible"]
