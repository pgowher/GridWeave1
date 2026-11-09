"""Compare live closure outcomes with manually specified abstract conditions."""
import argparse
import json
from pathlib import Path

from model_checks import run_cases


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=run_cases()
    cases=[{key:row[key] for key in ('scenario','model_outcome','implementation_outcome',
           'model_alignment','positive_soundness','observed_categories')} for row in result['cases']]
    failures=[row['scenario'] for row in cases if not row['model_alignment'] or not row['positive_soundness']]
    payload={'status':'FAIL' if failures else 'PASS','cases':cases,'failures':failures,
             'scope':'18 manually specified model-to-code cases; finite correspondence, not an unbounded implementation proof'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:json.dump(payload,stream,indent=2);stream.write('\n')
    print(json.dumps({'status':payload['status'],'cases':len(cases),'failures':failures}))
    return int(bool(failures))


if __name__=='__main__':raise SystemExit(main())
