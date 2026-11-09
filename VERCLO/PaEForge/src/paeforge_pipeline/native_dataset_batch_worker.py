"""Batch execution over a public-only GridWeave export; no generator/oracle import."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

from paeforge_contract.canonical import sha256_digest
from paeforge_pipeline.io import write_json, consumer_source_identity, runtime_identity
from paeforge_pipeline.native_dataset import load_public_dataset
from paeforge_pipeline.verclo_worker import evaluate_bundle


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--public',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-revision',required=True)
    a=p.parse_args();root,index=load_public_dataset(a.public);out=a.output.resolve()
    if out.is_relative_to(root) or root.is_relative_to(out):
        raise ValueError('Output must be outside the public dataset')
    identity = consumer_source_identity()
    if identity['source_revision'] != a.source_revision:
        raise ValueError('Consumer source changed between dispatch and execution')
    out.mkdir(parents=True,exist_ok=False)
    write_json(out/'source-identity.json', identity)
    results=[]
    for entry in index['cases']:
        uid=entry['unit_id']
        context=root/'configuration'/uid/'verification-context.json'
        result=evaluate_bundle(root/'cases'/uid,root/'configuration'/uid/'policies',
                               source_revision=a.source_revision,
                               configuration_sha256=sha256(context.read_bytes()).hexdigest(),
                               trust_context=context,diagnostics_path=out/'diagnostics'/(uid+'.json'))
        path=out/(uid+'.json');write_json(path,result)
        results.append({'unit_id':uid,'result_sha256':sha256_digest(result),
                        'result_file_sha256':sha256(path.read_bytes()).hexdigest(),
                        'diagnostics_sha256':sha256((out/'diagnostics'/(uid+'.json')).read_bytes()).hexdigest()})
    forbidden=[name for name in sys.modules if name.startswith(('gridweave','htgl_dataset_generator'))]
    if forbidden:raise RuntimeError('generator or oracle imported in verifier worker: '+repr(forbidden))
    if consumer_source_identity()['source_revision'] != a.source_revision:
        raise ValueError('Consumer source changed during execution; run is incomplete')
    write_json(out/'results-manifest.json',{'version':'GridWeave-0.2.0','status':'COMPLETE','executed_case_evaluations_q':len(results),
               'public_index_sha256':sha256((root/'index.json').read_bytes()).hexdigest(),
               'source_revision':a.source_revision,
               'source_identity_sha256':sha256((out/'source-identity.json').read_bytes()).hexdigest(),
               'runtime':runtime_identity(),
               'generator_or_oracle_modules_loaded':forbidden,'results':results})
    print(json.dumps({'completed_cases':len(results),'generator_or_oracle_modules_loaded':forbidden}))
    return 0


if __name__=='__main__':raise SystemExit(main())
