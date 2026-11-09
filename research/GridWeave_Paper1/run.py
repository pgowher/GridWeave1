#!/usr/bin/env python3
"""Run GridWeave paper studies using the prepared research environment."""
import argparse,sys
from datetime import datetime
from pathlib import Path
sys.dont_write_bytecode=True
LAB=Path(__file__).resolve().parent
sys.path.insert(0,str(LAB))

def main():
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    full=sub.add_parser('run',help='Execute conformance, semantic adjudication, assessor reuse and utility studies');full.add_argument('--output',type=Path,default=None)
    show=sub.add_parser('report',help='Rebuild the result report from a completed run');show.add_argument('--run',type=Path,required=True)
    sub.add_parser('test',help='Run semantic and fault-construction checks')
    fixtures=sub.add_parser('fixtures',help='Construct the independent native fixture set');fixtures.add_argument('--output',type=Path,required=True)
    assess=sub.add_parser('assess',help='Run either independent assessor on public inputs');assess.add_argument('--dataset',type=Path,required=True);assess.add_argument('--assessor',choices=['graph','sql'],required=True);assess.add_argument('--output',type=Path,required=True)
    adjudicate=sub.add_parser('adjudicate',help='Compare frozen predictions with saved labels');adjudicate.add_argument('--dataset',type=Path,required=True);adjudicate.add_argument('--predictions',type=Path,required=True);adjudicate.add_argument('--assessor',choices=['graph','sql','verclo'],required=True);adjudicate.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    if a.command=='test':
        import subprocess
        return subprocess.call([sys.executable,'-m','unittest','discover','-s',str(LAB/'tests'),'-v'],cwd=LAB)
    if a.command=='fixtures':
        from paper1.fixture_builder import generate
        print(generate(a.output,LAB/'fixtures/semantic_cases_v1.json'));return 0
    if a.command=='assess':
        import subprocess
        dataset=a.dataset.resolve();public=dataset if dataset.name=='public' else dataset/'public'
        return subprocess.call([sys.executable,'-m','paper1.assessor_worker','--public',str(public),'--assessor',a.assessor,'--output',str(a.output.resolve())],cwd=LAB)
    if a.command=='adjudicate':
        from paper1.adjudication import compare
        result=compare(a.dataset,a.predictions,a.assessor,a.output);print(result['status']);return int(result['status']!='PASS')
    from paper1.study import execute,report
    if a.command=='report':report(a.run)
    else:execute(a.output or LAB/'runs'/datetime.now().strftime('%Y%m%d-%H%M%S'))
    return 0
if __name__=='__main__':raise SystemExit(main())
