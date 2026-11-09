"""Run VERCLO on an existing dataset without generating new inputs."""

from __future__ import annotations

from pathlib import Path
import sys


PAEFORGE_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PAEFORGE_ROOT / "src"))

from paeforge_pipeline.cli import main  # noqa: E402


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if not arguments:
        arguments = ["--help"]
    elif arguments[0].startswith("-") and arguments[0] not in {"-h", "--help"}:
        arguments = ["run", *arguments]
    raise SystemExit(main(arguments))
