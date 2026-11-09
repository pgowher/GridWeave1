"""Run and materialize the P13 network trust-anchor experiment."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Mapping

from evaluation import NetworkStudyConfig, run_network_backend_study


DEFAULT_OUTPUT = Path(__file__).resolve().parent / "evaluation" / "results" / "p13_network_study_v2"


def _csv(rows: list[Mapping[str, object]], fields: tuple[str, ...]) -> str:
    target = io.StringIO(newline="")
    writer = csv.DictWriter(target, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                field: json.dumps(row[field], sort_keys=True, separators=(",", ":"))
                if isinstance(row[field], (dict, list))
                else row[field]
                for field in fields
            }
        )
    return target.getvalue()


def render_p13_artifacts(report: Mapping[str, object]) -> dict[str, str]:
    artifacts = {
        "network-study-report.json": json.dumps(report, indent=2, sort_keys=True) + "\n",
        "backend-cost-comparison.csv": _csv(
            list(report["backends"]),  # type: ignore[arg-type]
            (
                "backend",
                "repetitions",
                "success_rate",
                "latency_median_ns",
                "latency_p95_ns",
                "messages_median",
                "request_bytes_median",
                "response_bytes_median",
            ),
        ),
        "pbft-fault-matrix.csv": _csv(
            list(report["fault_cases"]),  # type: ignore[arg-type]
            (
                "scenario_id",
                "fault_profile",
                "expected_accepted",
                "accepted",
                "correct",
                "diagnostics",
                "prepare_votes",
                "commit_votes",
                "messages_sent",
            ),
        ),
        "raw-cost-observations.csv": _csv(
            list(report["observations"]),  # type: ignore[arg-type]
            (
                "backend",
                "repetition",
                "accepted",
                "latency_ns",
                "messages_sent",
                "request_bytes",
                "response_bytes",
            ),
        ),
    }
    artifacts["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(content.encode()).hexdigest()}  {name}\n"
        for name, content in sorted(artifacts.items())
    )
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repetitions", type=int, default=15)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()
    report = run_network_backend_study(
        NetworkStudyConfig(args.repetitions, args.warmups, args.timeout)
    )
    artifacts = render_p13_artifacts(report)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (args.output / name).write_text(content, encoding="utf-8")
    print(json.dumps({"output": str(args.output), "study_sha256": report["study_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

