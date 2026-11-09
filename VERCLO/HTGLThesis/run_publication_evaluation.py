#!/usr/bin/env python3
"""Run or verify the reproducible VERCLO publication fault campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from evaluation import run_reference_campaign

DEFAULT_OUTPUT = ROOT / "evaluation" / "results" / "reference_campaign_v1"


def _csv_text(fieldnames: list[str], rows: list[dict[str, object]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def render_artifacts(config: str | Path | None = None) -> dict[str, str]:
    report = run_reference_campaign(config).to_dict()
    decision_rows: list[dict[str, object]] = []
    for scenario in report["results"]:
        for policy, decision in scenario["decisions"].items():
            decision_rows.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "fault_family": scenario["fault_family"],
                    "expected_closed": str(scenario["expected_closed"]).lower(),
                    "policy": policy,
                    "accepted_closed": str(decision["accepted_closed"]).lower(),
                    "correct": str(decision["correct"]).lower(),
                    "raw_decision": decision["raw_decision"],
                    "reason_codes": "|".join(decision["reason_codes"]),
                }
            )
    metric_rows = [
        {"policy": policy, **metrics}
        for policy, metrics in sorted(report["metrics"].items())
    ]
    artifacts = {
        "campaign_report.json": json.dumps(report, indent=2, sort_keys=True) + "\n",
        "scenario_decisions.csv": _csv_text(
            [
                "scenario_id",
                "fault_family",
                "expected_closed",
                "policy",
                "accepted_closed",
                "correct",
                "raw_decision",
                "reason_codes",
            ],
            decision_rows,
        ),
        "policy_metrics.csv": _csv_text(
            [
                "policy",
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
                "accuracy",
                "balanced_accuracy",
                "false_acceptance_rate",
                "false_rejection_rate",
            ],
            metric_rows,
        ),
    }
    artifacts["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(content.encode('utf-8')).hexdigest()}  {name}\n"
        for name, content in sorted(artifacts.items())
    )
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that tracked artifacts exactly match a fresh deterministic run",
    )
    args = parser.parse_args()
    artifacts = render_artifacts(args.config)
    if args.check:
        mismatches = [
            name
            for name, content in artifacts.items()
            if not (args.output_dir / name).is_file()
            or (args.output_dir / name).read_text(encoding="utf-8") != content
        ]
        if mismatches:
            print(
                f"FAIL: stale or missing publication artifacts: {', '.join(mismatches)}"
            )
            return 1
        print(
            f"PASS: {len(artifacts) - 1} publication artifacts are reproducible; "
            f"report {json.loads(artifacts['campaign_report.json'])['report_sha256']}"
        )
        return 0

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (args.output_dir / name).write_text(content, encoding="utf-8")
    report = json.loads(artifacts["campaign_report.json"])
    print(
        f"PASS: wrote {report['scenario_count']} scenarios and "
        f"{len(report['policies'])} policy comparisons to {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
