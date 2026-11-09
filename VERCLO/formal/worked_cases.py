#!/usr/bin/env python3
"""Adapter and conformance runner for the normative PAE-FM-2.2 fixtures."""

from __future__ import annotations

import csv
import json
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from pae_fecm import (
    Asset,
    Baseline,
    Challenge,
    Disposition,
    Evidence,
    ExceptionClaim,
    Grade,
    Lineage,
    ObserverView,
    Policy,
    Replica,
    Visibility,
    evaluate,
)

HERE = Path(__file__).resolve().parent
CASES = HERE / "fixtures" / "Worked_Cases_v1.json"
MANUAL = HERE / "fixtures" / "Manual_Evaluation_Record.csv"


def _merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _time(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def decode_case(
    defaults: Mapping[str, Any], override: Mapping[str, Any]
) -> ObserverView:
    forbidden = {"expected_outcome", "oracle", "manual"} & set(override)
    if forbidden:
        raise ValueError(
            f"mechanisation input contains forbidden answer fields: {sorted(forbidden)}"
        )
    case = _merge(defaults, override)
    policy = case["policy"]
    baseline = case["baseline"]
    committed = baseline.get("committed_obligation_ids", "AUTO")
    return ObserverView(
        evaluation_time=_time(case["evaluation_time"]),
        case_deadline=_time(case["case_deadline"]),
        root_asset_ids=frozenset(case["root_asset_ids"]),
        policy=Policy(
            applicable_asset_kinds=frozenset(policy["applicable_asset_kinds"]),
            applicable_replica_classes=frozenset(policy["applicable_replica_classes"]),
            allowed_dispositions=frozenset(
                Disposition(row) for row in policy["allowed_dispositions"]
            ),
            minimum_grade=Grade[policy["minimum_grade"]],
            exception_authorities=frozenset(policy["exception_authority_ids"]),
            early_closure_allowed=policy["early_closure_allowed"],
        ),
        baseline=Baseline(
            authorization_valid=baseline["authorization_valid"],
            policy_authenticated=baseline["policy_authenticated"],
            scope_commitment_valid=baseline["scope_commitment_valid"],
            obligation_commitment_valid=baseline["obligation_commitment_valid"],
            graph_available=baseline["graph_available"],
            committed_obligation_ids=(
                None if committed == "AUTO" else frozenset(committed)
            ),
            no_applicable_determination_valid=baseline.get(
                "no_applicable_determination_valid", False
            ),
        ),
        assets=tuple(Asset(row["asset_id"], row["kind"]) for row in case["assets"]),
        lineage=tuple(
            Lineage(
                source=row["source_asset_id"],
                target=row["target_asset_id"],
                visibility=Visibility(row["status"]),
                authenticated=row["authenticated"],
                disclosed_at=(
                    _time(row["disclosed_at"]) if row.get("disclosed_at") else None
                ),
            )
            for row in case["lineage"]
        ),
        replicas=tuple(
            Replica(
                replica_id=row["replica_id"],
                asset_id=row["asset_id"],
                repository_id=row["repository_id"],
                custodian_id=row["custodian_id"],
                replica_class=row["replica_class"],
                visibility=Visibility(row.get("status", "DECLARED")),
                authenticated=row["authenticated"],
                disclosed_at=(
                    _time(row["disclosed_at"]) if row.get("disclosed_at") else None
                ),
                deadline=_time(row["deadline"]) if row.get("deadline") else None,
                minimum_grade=(
                    Grade[row["minimum_grade"]] if row.get("minimum_grade") else None
                ),
                allowed_dispositions=(
                    frozenset(Disposition(item) for item in row["allowed_dispositions"])
                    if row.get("allowed_dispositions")
                    else None
                ),
            )
            for row in case["replicas"]
        ),
        evidence=tuple(
            Evidence(
                evidence_id=row["evidence_id"],
                obligation_id=row["obligation_id"],
                issuer_id=row["issuer_id"],
                disposition=Disposition(row["disposition"]),
                event_time=_time(row["event_time"]),
                grade=Grade[row["grade"]],
                authenticated=row["authenticated"],
                binding_valid=row["binding_valid"],
                integrity_valid=row["integrity_valid"],
                ordering_valid=row["ordering_valid"],
                chain_authenticated=row["continuity"]["chain_authenticated"],
                sequence_contiguous=row["continuity"]["sequence_contiguous"],
                predecessors_available=row["continuity"]["predecessors_available"],
            )
            for row in case["evidence"]
        ),
        exceptions=tuple(
            ExceptionClaim(
                exception_id=row["exception_id"],
                obligation_ids=frozenset(row["obligation_ids"]),
                authority_id=row["authority_id"],
                basis_commitment=row["basis_commitment"],
                effective_at=_time(row["effective_at"]),
                expires_at=_time(row["expires_at"]),
                authenticated=row["authenticated"],
            )
            for row in case["exceptions"]
        ),
        challenges=tuple(
            Challenge(
                challenge_id=row.get("challenge_id", f"challenge-{index}"),
                authenticated=row["authenticated"],
                resolved=row["resolved"],
            )
            for index, row in enumerate(case["challenges"])
        ),
    )


def conformance_report() -> dict[str, Any]:
    suite = json.loads(CASES.read_text(encoding="utf-8"))
    with MANUAL.open(newline="", encoding="utf-8") as handle:
        manual = {row["case_id"]: row for row in csv.DictReader(handle)}
    results = []
    for raw_case in suite["cases"]:
        observed = evaluate(decode_case(suite["defaults"], raw_case))
        expected = manual[raw_case["case_id"]]["manual_outcome"]
        results.append(
            {
                "case_id": raw_case["case_id"],
                "expected": expected,
                "observed": observed.outcome.value,
                "pass": expected == observed.outcome.value,
            }
        )
    return {
        "status": "PASS" if all(row["pass"] for row in results) else "FAIL",
        "cases": len(results),
        "results": results,
    }


def main() -> None:
    report = conformance_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
