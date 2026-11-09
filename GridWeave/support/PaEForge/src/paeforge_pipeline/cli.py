"""Command-line entry point for the automated vertical pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .orchestrator import run_pipeline


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="paeforge")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="execute one complete PaEForge experiment")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--run-id")
    run.add_argument("--output-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_pipeline(args.config, run_id=args.run_id, output_root=args.output_root)
    except BaseException as error:
        print(f"PaEForge run failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"run_id": result.run_id, "run_root": str(result.run_root), "manifest": str(result.manifest_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

