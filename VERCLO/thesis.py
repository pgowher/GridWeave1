#!/usr/bin/env python3
"""Checks for the contained VERCLO research implementation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
ACTIVE_SOURCES = (ROOT/'HTGLThesis/src', ROOT/'PaEForge/src')
REFERENCE = ROOT / 'datasets/reference'
if not REFERENCE.exists():
    REFERENCE = ROOT.parent / 'GridWeave/datasets/reference'


def environment():
    return dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                PYTHONPATH=os.pathsep.join(map(str, ACTIVE_SOURCES)))


def structure_check():
    required = ('HTGLThesis/src/verclo', 'HTGLThesis/src/protocol',
                'PaEForge/schemas', 'PaEForge/src/paeforge_pipeline/native_dataset.py',
                'PaEForge/src/paeforge_pipeline/dataset_evaluator.py',
                'formal/PAEFECM/Core.lean', 'formal/pae_fecm.py')
    missing = [rel for rel in required if not (ROOT/rel).exists()]
    for rel in ('public/index.json', 'sealed/cases'):
        if not (REFERENCE / rel).exists():
            missing.append(str(REFERENCE / rel))
    probe = "import verclo,erasure,evidence,proof,paeforge_contract,json; print(json.dumps({n:__import__(n).__file__ for n in ['verclo','erasure','evidence','proof','paeforge_contract']}))"
    completed = subprocess.run([sys.executable, '-c', probe], cwd=ROOT, env=environment(),
                               capture_output=True, text=True)
    imports = json.loads(completed.stdout) if completed.returncode==0 else {}
    nonlocal_imports = [n for n,p in imports.items() if not any(Path(p).is_relative_to(s) for s in ACTIVE_SOURCES)]
    report = {'status':'PASS' if not missing and completed.returncode==0 and not nonlocal_imports else 'FAIL',
              'missing':missing,'imports':imports,'nonlocal_imports':nonlocal_imports,
              'import_error':completed.stderr or None,
              'scope':'Local research structure and dependencies; scientific correctness is checked separately'}
    print(json.dumps(report,indent=2))
    return int(report['status']!='PASS')


def tests(project='all'):
    projects = {'verifier':ROOT/'HTGLThesis', 'pipeline':ROOT/'PaEForge',
                'integration':ROOT, 'formal':ROOT/'formal'}
    failures=[]
    for name in projects if project=='all' else (project,):
        cwd=projects[name]
        args=['-m','pytest','-q','-p','no:cacheprovider']
        args += ['test_pae_fecm.py'] if name=='formal' else ['tests']
        print('Checking '+name,flush=True)
        result=subprocess.run([sys.executable,*args],cwd=cwd,env=environment(),check=False)
        if result.returncode:failures.append(name)
    print(json.dumps({'status':'FAIL' if failures else 'PASS','failed_projects':failures,
                      'scope':'Research semantics, protocol, algorithms, saved-data contracts and abstract model'}))
    return int(bool(failures))


def verify_source():
    manifest=json.loads((ROOT/'SOURCE_MANIFEST.json').read_text())
    failures=[rel for rel,value in manifest['files'].items() if not (ROOT/rel).is_file()
              or hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()!=value]
    print(json.dumps({'status':'FAIL' if failures else 'PASS','files':len(manifest['files']),'failures':failures},indent=2))
    return int(bool(failures))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('check','status','verify-source','verify-imports'):sub.add_parser(name)
    test=sub.add_parser('tests');test.add_argument('--project',choices=('all','verifier','pipeline','integration','formal'),default='all')
    args=parser.parse_args()
    if args.command=='check':return structure_check()
    if args.command=='tests':return tests(args.project)
    if args.command in {'verify-source','verify-imports'}:return verify_source()
    print((ROOT/'RESEARCH_STATUS.json').read_text())
    return 0


if __name__=='__main__':raise SystemExit(main())
