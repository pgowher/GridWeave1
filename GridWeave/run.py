#!/usr/bin/env python3
"""Standalone generation and validation; no downstream verifier execution."""
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parent
SOURCES = (ROOT / 'src', ROOT / 'support/HTGLThesis/src', ROOT / 'support/PaEForge/src')

def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] not in {'generate', 'validate', '--version', '--help', '-h'}:
        print('Use generate or validate. Run VERCLO separately on a saved dataset.', file=sys.stderr)
        return 2
    sys.dont_write_bytecode = True
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    os.environ['PYTHONPATH'] = os.pathsep.join(map(str, SOURCES))
    for path in reversed(SOURCES):
        sys.path.insert(0, str(path))
    os.chdir(ROOT)
    from gridweave.cli import main as cli
    if not args or args[0] in {'--help', '-h'}:
        print('GridWeave standalone dataset generator\n'
              '  ./gridweave generate --output datasets/my-data --seed my-seed --strategy all\n'
              '  ./gridweave validate datasets/my-data\n'
              'Relative dataset paths are resolved inside the GridWeave folder.\n'
              'Use generate --help or validate --help for options.')
        return 0
    return cli(args)

if __name__ == '__main__':
    raise SystemExit(main())
