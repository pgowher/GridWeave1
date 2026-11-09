"""Compare frozen VERCLO predictions with saved labels in a separate process."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from hashlib import sha256
import json
from pathlib import Path

from paeforge_contract.canonical import sha256_digest
from paeforge_contract.validation import validate_document
from .io import write_json
from .native_dataset import load_public_dataset

CLASSES = ('CLOSED', 'CLOSED_WITH_EXCEPTIONS', 'PARTIALLY_CLOSED', 'OPEN',
           'DISPUTED', 'UNVERIFIABLE', 'IN_PROGRESS')
CLOSED = {'CLOSED', 'CLOSED_WITH_EXCEPTIONS'}


def read(path):
    return json.loads(Path(path).read_text())


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def csv_file(path, columns, rows):
    with path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def evaluate_saved_run(dataset, run, output):
    dataset, run, output = Path(dataset).resolve(), Path(run).resolve(), Path(output).resolve()
    public, index = load_public_dataset(dataset)
    if dataset.name == 'public':
        dataset = dataset.parent
    for protected in (dataset, run):
        if output.is_relative_to(protected) or protected.is_relative_to(output):
            raise ValueError('Evaluation output must be separate from dataset and predictions')
    manifest = read(run / 'results-manifest.json')
    if manifest.get('status') != 'COMPLETE':
        raise ValueError('Only completed predictions can be evaluated')
    if manifest['public_index_sha256'] != digest(public / 'index.json'):
        raise ValueError('Predictions belong to another public dataset index')
    units = {entry['unit_id']: entry for entry in index['cases']}
    rows = manifest['results']
    if len(rows) != len(units) or {r['unit_id'] for r in rows} != set(units):
        raise ValueError('Prediction coverage does not equal the indexed unit set')
    if manifest['executed_case_evaluations_q'] != len(units):
        raise ValueError('Incorrect executed-case count')
    if manifest['generator_or_oracle_modules_loaded']:
        raise ValueError('Generator/oracle was loaded during prediction')
    if digest(run/'source-identity.json') != manifest['source_identity_sha256']:
        raise ValueError('Source identity was modified after prediction')
    predictions, diagnostics = {}, {}
    # Verify and freeze every prediction before opening any sealed labels.
    for row in rows:
        uid = row['unit_id']
        path = run / (uid + '.json')
        if digest(path) != row['result_file_sha256']:
            raise ValueError('Prediction was modified after freezing: ' + uid)
        result = read(path)
        validate_document(result)
        if sha256_digest(result) != row['result_sha256'] or result['provenance']['source_revision'] != manifest['source_revision']:
            raise ValueError('Prediction identity mismatch: ' + uid)
        for filename, key in (('case-manifest.json','case_manifest_sha256'),
                              ('observer-projection.json','observer_projection_sha256'),
                              ('receipt-stream.json','receipt_stream_sha256')):
            if result['input_commitments'][key] != sha256_digest(read(public/'cases'/uid/filename)):
                raise ValueError('Prediction input commitment mismatch: ' + uid)
        path = run/'diagnostics'/(uid+'.json')
        if digest(path) != row['diagnostics_sha256']:
            raise ValueError('Diagnostics were modified after freezing: ' + uid)
        diagnostics[uid] = read(path)
        predictions[uid] = result
    frozen_manifest_sha256 = digest(run/'results-manifest.json')
    producer = read(dataset/'dataset-manifest.json')
    def sealed(relative):
        path = dataset/relative
        if producer['files'].get(relative) != digest(path):
            raise ValueError('Saved evaluation-label integrity mismatch: ' + relative)
        return read(path)
    pairs = sealed('sealed/pairs.json')
    members = {}
    for pair in pairs:
        for uid in pair['unit_ids']:
            if uid in members:
                raise ValueError('Repeated pair membership')
            members[uid] = pair
    case_unit_resource = producer.get('evaluation_unit') == 'case'
    if case_unit_resource and not pairs:
        members = {uid: {'scale': 1} for uid in units}
    if set(members) != set(units):
        raise ValueError('Pair metadata does not cover exactly the public units')
    case_rows, obligation_rows, receipt_rows = [], [], []
    confusion = Counter()
    for uid, result in sorted(predictions.items()):
        saved = sealed('sealed/cases/'+uid+'.json')
        if saved['unit_id'] != uid:
            raise ValueError('Label unit binding mismatch')
        truth = saved['truth']
        expected, observed = truth['outcome'], result['closure_class']
        if expected not in CLASSES:
            raise ValueError('Unknown expected closure class')
        pair = members[uid]
        actual = {o['obligation_id']:o['category'] for o in result['obligation_results']}
        inferred = {o['obligation_id'] for o in (diagnostics[uid].get('graph') or {}).get('obligations', [])}
        target = truth['obligation_categories']
        scored = truth['baseline_verifiable']
        mismatches = sum(actual.get(oid) != category for oid, category in target.items()) if scored else 0
        extras = len(set(actual)-set(target)) if scored else 0
        case_rows.append({'unit_id':uid,'split':saved['split'],'family':saved['family'],
            'scale':pair['scale'],'operation':saved['operation'],'expected':expected,'observed':observed,
            'match':expected==observed,'false_closure':observed in CLOSED and expected not in CLOSED,
            'missed_closure':expected in CLOSED and observed not in CLOSED,
            'baseline_verifiable':scored,'obligations_expected':len(target),'obligations_discovered':len(inferred),
            'missing_discovered_obligations':len(set(target)-inferred),
            'extra_discovered_obligations':len(inferred-set(target)),
            'category_comparison_scored':scored,'category_mismatches':mismatches+extras,
            'duration_ns':result['execution']['duration_ns'],
            'logical_operations_q':result['execution']['executed_operations_q']})
        for oid in sorted(set(target)|set(actual)):
            obligation_rows.append({'unit_id':uid,'obligation_id':oid,'scored':scored,
                'expected_category':target.get(oid,''),'observed_category':actual.get(oid,''),
                'match':target.get(oid)==actual.get(oid) if scored else '',
                'discovered':oid in inferred})
        for check in diagnostics[uid]['receipt_checks']:
            rid = check.get('receipt_id') or check['receipt']['receipt_id']
            expected_check = truth['receipt_diagnoses'].get(rid)
            observed_check = 'AUTHENTICATED_E2' if check['status']=='GRADED' else 'REJECTED'
            receipt_rows.append({'unit_id':uid,'receipt_id':rid,'status':check['status'],
                'grade':check.get('grade') or '', 'rejection_reason':check.get('rejection_reason') or '',
                'closure_admissible':check.get('closure_admissible',False),
                'expected_authentication':expected_check or '',
                'authentication_scored':scored and expected_check is not None,
                'authentication_match':observed_check==expected_check if scored and expected_check is not None else ''})
        confusion[expected,observed] += 1
    pair_rows = []
    for pair in pairs:
        if pair['operation'] not in {'permutation','hidden_copy_twin'}:
            continue
        left, right = (predictions[uid] for uid in pair['unit_ids'])
        keys = ('closure_class','obligation_results','obligation_sets','visibility_reason_codes','reason_codes')
        pair_rows.append({'pair_id':pair['pair_id'],'operation':pair['operation'],
                          'holds':all(left[k]==right[k] for k in keys)})
    groups = []
    for dimension in ('split','family','operation','scale'):
        for value in sorted({str(r[dimension]) for r in case_rows}):
            selected = [r for r in case_rows if str(r[dimension])==value]
            groups.append({'dimension':dimension,'value':value,'cases':len(selected),
                           'matches':sum(r['match'] for r in selected),
                           'false_closures':sum(r['false_closure'] for r in selected)})
    mismatches = [r for r in case_rows if not r['match'] or r['category_mismatches']
                  or (r['baseline_verifiable'] and (r['missing_discovered_obligations'] or r['extra_discovered_obligations']))]
    receipt_mismatches = sum(r['authentication_scored'] and not r['authentication_match'] for r in receipt_rows)
    summary = {'status':'PASS' if not mismatches and not receipt_mismatches and all(r['holds'] for r in pair_rows) else 'FAIL',
        'cases':len(case_rows),'closure_matches':sum(r['match'] for r in case_rows),
        'closure_accuracy':sum(r['match'] for r in case_rows)/len(case_rows),
        'false_closures':sum(r['false_closure'] for r in case_rows),
        'missed_closures':sum(r['missed_closure'] for r in case_rows),
        'category_mismatches_on_verifiable_scopes':sum(r['category_mismatches'] for r in case_rows),
        'scored_obligation_categories':sum(r['scored'] for r in obligation_rows),
        'scored_receipt_authentication_checks':sum(r['authentication_scored'] for r in receipt_rows),
        'receipt_authentication_mismatches':receipt_mismatches,
        'metamorphic_pairs_checked':len(pair_rows),'metamorphic_failures':sum(not r['holds'] for r in pair_rows),
        'synthetic_source_families_N':len({r['family'] for r in case_rows}),
        'materialized_cases_n':len(case_rows),'executed_case_evaluations_q':len(case_rows),
        'statistical_scope':f"Synthetic cases share {len({r['family'] for r in case_rows})} source families; no independent-sample confidence interval or external generalization claim",
        'oracle_scope':producer.get('label_provenance', 'Saved independently implemented, same-project signed-E2 labels; not independently authored validation'),
        'frozen_prediction_manifest_sha256':frozen_manifest_sha256,
        'producer_dataset_manifest_sha256':digest(dataset/'dataset-manifest.json'),
        'generator_or_oracle_modules_loaded_during_prediction':manifest['generator_or_oracle_modules_loaded'],
        'mismatches':mismatches}
    if digest(run/'results-manifest.json') != frozen_manifest_sha256:
        raise ValueError('Predictions changed during evaluation')
    output.mkdir(parents=True,exist_ok=False)
    write_json(output/'evaluation.json',summary)
    csv_file(output/'cases.csv',list(case_rows[0]),case_rows)
    csv_file(output/'obligations.csv',('unit_id','obligation_id','scored','expected_category','observed_category','match','discovered'),obligation_rows)
    csv_file(output/'receipts.csv',('unit_id','receipt_id','status','grade','rejection_reason','closure_admissible',
                                  'expected_authentication','authentication_scored','authentication_match'),receipt_rows)
    csv_file(output/'confusion_matrix.csv',('expected','observed','count'),
             [{'expected':e,'observed':o,'count':confusion[e,o]} for e in CLASSES for o in CLASSES])
    csv_file(output/'condition_metrics.csv',list(groups[0]),groups)
    csv_file(output/'metamorphic_pairs.csv',('pair_id','operation','holds'),pair_rows)
    write_json(output/'output-manifest.json',{'files':{p.name:digest(p) for p in sorted(output.iterdir())}})
    return summary


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',required=True,type=Path)
    parser.add_argument('--run',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(argv)
    summary=evaluate_saved_run(args.dataset,args.run,args.output)
    print(json.dumps({key:summary[key] for key in ('status','cases','closure_matches','false_closures','missed_closures')}))
    return int(summary['status']!='PASS')


if __name__=='__main__':
    raise SystemExit(main())
