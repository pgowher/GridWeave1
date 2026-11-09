"""Consume an existing dataset without invoking a generator."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import os
import subprocess
from typing import Sequence

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="paeforge")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="evaluate a previously generated native dataset; no generation")
    run.add_argument("--dataset", required=True, type=Path, help="saved dataset root or its public directory")
    run.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == 'run':
            from .native_dataset import load_public_dataset
            public, _ = load_public_dataset(args.dataset)
            from .io import consumer_source_identity
            paeforge_root = Path(__file__).resolve().parents[2]
            verclo_root = paeforge_root.parent / 'HTGLThesis'
            output = args.output.resolve()
            dataset = args.dataset.resolve()
            protected = (dataset, public, verclo_root, paeforge_root,
                         paeforge_root.parent / 'evidence', paeforge_root.parent / 'provenance',
                         paeforge_root.parent / 'datasets', paeforge_root.parent / 'Thesis_Docs-')
            if any(output.is_relative_to(path) or path.is_relative_to(output) for path in protected):
                raise ValueError('Choose an output directory outside datasets, source and preserved research files')
            if output.exists():
                raise FileExistsError('Choose a new output directory: ' + str(output))
            revision = consumer_source_identity()['source_revision']
            env = dict(os.environ)
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            env['PYTHONPATH'] = os.pathsep.join(map(str, (paeforge_root / 'src', verclo_root / 'src')))
            return subprocess.run([sys.executable, '-m', 'paeforge_pipeline.native_dataset_batch_worker',
                '--public', str(public), '--output', str(output),
                '--source-revision', revision], env=env, check=False).returncode
    except Exception as error:
        print(f"PaEForge run failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

