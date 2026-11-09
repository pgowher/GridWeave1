"""Read-only validation command for PaEForge exchange artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .exchange import read_verifier_bundle
from .validation import validate_document, validate_verifier_input


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="paeforge-contract")
    subparsers = parser.add_subparsers(dest="command", required=True)
    document = subparsers.add_parser("validate", help="validate one exchange document")
    document.add_argument("path", type=Path)
    document.add_argument("--verifier-input", action="store_true")
    bundle = subparsers.add_parser("validate-bundle", help="validate a VERCLO input directory")
    bundle.add_argument("directory", type=Path)
    bundle.add_argument("--canary", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "validate-bundle":
        read_verifier_bundle(args.directory, canary_values=tuple(args.canary))
        print(f"valid PaEForge verifier bundle: {args.directory}")
        return 0
    payload = json.loads(args.path.read_text(encoding="utf-8"))
    if args.verifier_input:
        validate_verifier_input(payload)
    else:
        validate_document(payload)
    print(f"valid PaEForge document: {args.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
