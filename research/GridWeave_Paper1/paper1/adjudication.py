"""Compare frozen public-only assessments with saved or literal fixture labels."""
import csv
from collections import Counter
from pathlib import Path
from .wire import read,write,file_hash,LABELS

FIELDS=('outcome','baseline_verifiable','obligation_categories','receipt_diagnoses')

def expected_labels(dataset):
    root=Path(dataset);manifest=read(root/'dataset-manifest.json');index=read(root/'public/index.json');out={}
    for e in index['cases']:
        rel='sealed/cases/'+e['unit_id']+'.json';p=root/rel
        if manifest['files'][rel]!=file_hash(p):raise ValueError('Expected label integrity failure')
        out[e['unit_id']]=read(p)
    return out

def metrics(rows):
    confusion=Counter((r['expected'],r['actual']) for r in rows);per_class={}
    for label in LABELS:
        tp=confusion[label,label];support=sum(n for (e,a),n in confusion.items() if e==label);predicted=sum(n for (e,a),n in confusion.items() if a==label)
        precision=tp/predicted if predicted else 0.;recall=tp/support if support else 0.;f1=2*precision*recall/(precision+recall) if precision+recall else 0.
        per_class[label]=dict(support=support,predicted=predicted,precision=precision,recall=recall,f1=f1)
    nonclosed=sum(r['expected'] not in ('CLOSED','CLOSED_WITH_EXCEPTIONS') for r in rows);unsafe=sum(r['expected'] not in ('CLOSED','CLOSED_WITH_EXCEPTIONS') and r['actual'] in ('CLOSED','CLOSED_WITH_EXCEPTIONS') for r in rows)
    return dict(cases=len(rows),exact_class_matches=sum(r['expected']==r['actual'] for r in rows),macro_f1=sum(v['f1'] for v in per_class.values())/len(LABELS),per_class=per_class,unsafe_positive_closures=unsafe,unsafe_positive_closure_denominator=nonclosed,unsafe_positive_closure_rate=unsafe/nonclosed if nonclosed else None)

def compare(dataset,predictions,assessor,output):
    root=Path(predictions);manifest=read(root/'results-manifest.json')
    if manifest['status']!='COMPLETE':raise ValueError('Incomplete prediction run')
    expected=expected_labels(dataset);rows=[];disagreements=[];coverage=Counter()
    if {r['unit_id'] for r in manifest['results']}!=set(expected):raise ValueError('Incomplete case coverage')
    for entry in manifest['results']:
        uid=entry['unit_id'];path=root/entry.get('path',uid+'.json');expected_hash=entry.get('sha256',entry.get('result_file_sha256'))
        if file_hash(path)!=expected_hash:raise ValueError('Prediction changed after freeze')
        raw=read(path);saved=expected[uid];truth=saved['truth']
        if assessor=='verclo':
            diag=read(root/'diagnostics'/(uid+'.json'));graph=diag.get('graph') or {}
            actual=dict(outcome=raw['closure_class'],baseline_verifiable=graph.get('baseline_verifiable',False),obligation_categories={r['obligation_id']:r['category'] for r in raw['obligation_results']},receipt_diagnoses={})
            for check in diag['receipt_checks']:
                rid=check.get('receipt_id') or check.get('receipt',{}).get('receipt_id')
                if check['status']!='OUTSIDE_DISCOVERED_SCOPE':actual['receipt_diagnoses'][rid]='AUTHENTICATED_E2' if check['status']=='GRADED' else 'REJECTED'
        else:actual=raw['assessment']
        row=dict(unit_id=uid,assessor=assessor,family=saved['family'],condition=saved['operation'],expected=truth['outcome'],actual=actual['outcome'],class_match=truth['outcome']==actual['outcome'])
        rows.append(row)
        for field in FIELDS:
            # VERCLO explicitly abstains from obligation/evidence scoring when
            # it cannot establish a baseline. The independent checkers still
            # cross-check the saved conditional reconstruction in those cases.
            if assessor=='verclo' and not truth['baseline_verifiable'] and field in ('obligation_categories','receipt_diagnoses'):
                coverage[field+'_not_scored_invalid_baseline']+=len(truth[field]);continue
            coverage[field+'_cases_scored']+=1
            if actual[field]!=truth[field]:
                disagreements.append(dict(unit_id=uid,assessor=assessor,condition=saved['operation'],field=field,expected=truth[field],actual=actual[field],status='UNRESOLVED'))
            if isinstance(truth[field],dict):coverage[field+'_subjects_scored']+=len(truth[field])
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    summary=dict(status='PASS' if not disagreements else 'DISAGREEMENTS',assessor=assessor,dataset_manifest_sha256=file_hash(Path(dataset)/'dataset-manifest.json'),prediction_manifest_sha256=file_hash(root/'results-manifest.json'),disagreement_count=len(disagreements),coverage=dict(coverage),**metrics(rows))
    write(output/'summary.json',summary);write(output/'disagreements.json',disagreements)
    with (output/'cases.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    return summary
