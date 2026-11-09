"""Public-input-only predictor process. No expected labels are read here."""
import argparse,importlib,sys,time
from pathlib import Path
from .wire import file_hash,load_public,write


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--public',type=Path,required=True);ap.add_argument('--assessor',choices=['graph','sql'],required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    if a.output.exists():raise FileExistsError('Choose a fresh prediction directory')
    public=a.public.resolve();opened=[];owned=set()
    def guard(event,args):
        if event=='open' and args and isinstance(args[0],(str,bytes)):
            p=Path(args[0]).resolve()
            if p.suffix=='.json':
                mode=args[1]
                if isinstance(mode,str) and ('w' in mode or 'a' in mode or 'x' in mode):
                    if not p.is_relative_to(a.output.resolve()):raise PermissionError('Write outside prediction output')
                    owned.add(p);return
                if p in owned:return
                if not p.is_relative_to(public):raise PermissionError('Assessor attempted to read JSON outside the public input root')
                opened.append(str(p.relative_to(public)))
    sys.addaudithook(guard)
    module=importlib.import_module('paper1.'+{'graph':'graph_assessor','sql':'sql_assessor'}[a.assessor]);rows=[]
    a.output.mkdir(parents=True)
    for uid,o,s,p,c in load_public(public):
        start=time.perf_counter();result=module.assess(o,s,p,c)
        write(a.output/(uid+'.json'),dict(unit_id=uid,assessment=result,seconds=time.perf_counter()-start))
        rows.append(dict(unit_id=uid,path=uid+'.json',sha256=file_hash(a.output/(uid+'.json'))))
    forbidden=[n for n in sys.modules if n.startswith(('gridweave','htgl_dataset_generator','verclo','paeforge','erasure','evidence','proof'))]
    if forbidden:raise RuntimeError('Forbidden assessor import: '+repr(forbidden))
    write(a.output/'results-manifest.json',dict(status='COMPLETE',assessor=a.assessor,cases=len(rows),results=rows,public_index_sha256=file_hash(public/'index.json'),forbidden_modules_loaded=forbidden,read_json_paths=sorted(set(opened))))
    print(f'{a.assessor}: {len(rows)} public cases completed')

if __name__=='__main__':main()
