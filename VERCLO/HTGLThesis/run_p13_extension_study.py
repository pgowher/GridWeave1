#!/usr/bin/env python3
"""Run the local or remote P13 TPDS extension study."""

from __future__ import annotations

import argparse
from pathlib import Path

from evaluation.p13_extension_study import (
    ExtensionStudyConfig,
    run_local_extension_study,
    run_remote_extension_study,
    write_extension_results,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evaluation/results/p13_extension_study_v2/report.json"),
    )
    parser.add_argument("--operations", type=int, default=24)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 16])
    parser.add_argument("--committees", type=int, nargs="+", default=[4, 7, 10])
    parser.add_argument("--delivery-strategy", choices=["serial", "parallel_all", "certificate_frontier"], default="serial")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    config = ExtensionStudyConfig(
        concurrency_levels=tuple(args.concurrency),
        operations_per_level=args.operations,
        committee_sizes=tuple(args.committees),
        timeout_seconds=args.timeout,
        delivery_strategy=args.delivery_strategy,
    )
    report = (
        run_remote_extension_study(args.topology, config)
        if args.topology
        else run_local_extension_study(config)
    )
    write_extension_results(report, args.output)
    print(args.output.resolve())
    print(report["study_sha256"])
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
