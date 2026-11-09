#!/usr/bin/env python3
"""Run VERCLO independently on saved public dataset inputs."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SOURCES = (ROOT / 'PaEForge/src', ROOT / 'HTGLThesis/src')


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0].startswith('--') and args[0] not in {'--help', '--version'}:
        args.insert(0, 'run')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version='VERCLO research 1.4.1')
    sub = parser.add_subparsers(dest='command')
    run = sub.add_parser('run', help='Evaluate an existing dataset without generating data')
    run.add_argument('--dataset', type=Path, required=True)
    run.add_argument('--output', type=Path, required=True)
    validate = sub.add_parser('validate', help='Check saved public input files and hashes')
    validate.add_argument('dataset', type=Path)
    evaluate = sub.add_parser('evaluate', help='Compare frozen predictions with saved labels in a separate process')
    evaluate.add_argument('--dataset', type=Path, required=True)
    evaluate.add_argument('--run', type=Path, required=True)
    evaluate.add_argument('--output', type=Path, required=True)
    sub.add_parser('check', help='Check local research files and runtime imports')
    tests = sub.add_parser('tests', help='Run consumer tests; does not generate datasets')
    tests.add_argument('--project', choices=('all', 'verifier', 'pipeline', 'integration', 'formal'), default='all')
    parsed = parser.parse_args(args)
    if parsed.command is None:
        parser.print_help()
        return 0
    sys.dont_write_bytecode = True
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    os.environ['PYTHONPATH'] = os.pathsep.join(map(str, SOURCES))
    for source in reversed(SOURCES):
        sys.path.insert(0, str(source))
    # Launcher-relative paths work from any current working directory.
    def local(path):
        return path if path.is_absolute() else ROOT / path
    if parsed.command == 'run':
        from paeforge_pipeline.cli import main as consume
        return consume(['run', '--dataset', str(local(parsed.dataset)), '--output', str(local(parsed.output))])
    if parsed.command == 'evaluate':
        import subprocess
        return subprocess.run([sys.executable, '-m', 'paeforge_pipeline.dataset_evaluator',
            '--dataset', str(local(parsed.dataset)), '--run', str(local(parsed.run)),
            '--output', str(local(parsed.output))], check=False).returncode
    if parsed.command == 'validate':
        from paeforge_pipeline.native_dataset import load_public_dataset
        try:
            public, index = load_public_dataset(local(parsed.dataset))
        except (ValueError, OSError, KeyError) as error:
            print(f'Dataset validation failed: {error}', file=sys.stderr)
            return 1
        print(f'PASS: {len(index["cases"])} saved public cases in {public}')
        return 0
    import thesis
    return thesis.structure_check() if parsed.command == 'check' else thesis.tests(parsed.project)


if __name__ == '__main__':
    raise SystemExit(main())
