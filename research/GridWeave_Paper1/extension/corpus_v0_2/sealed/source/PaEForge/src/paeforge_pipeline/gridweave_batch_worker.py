"""Batch execution over a public-only GridWeave export; no generator/oracle import."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

from paeforge_contract.canonical import sha256_digest
from paeforge_pipeline.io import write_json
from paeforge_pipeline.verclo_worker import evaluate_bundle


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--public',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-revision',required=True)
    a=p.parse_args();root=a.public.resolve();out=a.output.resolve()
    index=json.loads((root/'index.json').read_text())
    if index['version']!='GridWeave-0.2.0':raise ValueError('unsupported GridWeave export')
    out.mkdir(parents=True,exist_ok=False)
    results=[]
    for entry in index['cases']:
        uid=entry['unit_id']
        if len(uid)!=32 or any(c not in '0123456789abcdef' for c in uid):raise ValueError('invalid unit handle')
        for rel,digest in entry['files'].items():
            path=root/rel
            if path.is_symlink() or not path.resolve().is_relative_to(root) or sha256(path.read_bytes()).hexdigest()!=digest:
                raise ValueError('public file integrity mismatch: '+rel)
        context=root/'configuration'/uid/'verification-context.json'
        result=evaluate_bundle(root/'cases'/uid,root/'configuration'/uid/'policies',
                               source_revision=a.source_revision,
                               configuration_sha256=sha256(context.read_bytes()).hexdigest(),
                               trust_context=context)
        path=out/(uid+'.json');write_json(path,result)
        results.append({'unit_id':uid,'result_sha256':sha256_digest(result),
                        'result_file_sha256':sha256(path.read_bytes()).hexdigest()})
    forbidden=[name for name in sys.modules if name.startswith(('gridweave','htgl_dataset_generator'))]
    if forbidden:raise RuntimeError('generator or oracle imported in verifier worker: '+repr(forbidden))
    write_json(out/'results-manifest.json',{'version':'GridWeave-0.2.0','executed_case_evaluations_q':len(results),
               'generator_or_oracle_modules_loaded':forbidden,'results':results})
    print(json.dumps({'completed_cases':len(results),'generator_or_oracle_modules_loaded':forbidden}))
    return 0


if __name__=='__main__':raise SystemExit(main())
