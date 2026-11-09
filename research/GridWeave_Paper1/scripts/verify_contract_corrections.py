#!/usr/bin/env python3
"""Verify corrected code against frozen inputs; never replace historical results."""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
LAB = Path(__file__).resolve().parents[1]
PROJECT = LAB.parents[1]
sys.path.insert(0, str(LAB))
from paper1.wire import file_hash, load_public, read, write
from paper1.adjudication import FIELDS, compare, expected_labels
from paper1.profiling import machine_context


def oracle_at(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.evaluate


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = [*sorted((LAB / 'paper1').glob('*.py')),
               *sorted((LAB / 'tests').glob('*.py')),
               PROJECT / 'GridWeave/src/gridweave/oracle.py', Path(__file__)]
    freeze = {str(p.relative_to(PROJECT)): file_hash(p) for p in sources}
    write(out / 'source-freeze.json', freeze)
    write(out / 'host.json', machine_context())
    identities = read(LAB / 'runs/paper1-study-v1/dataset-identities.json')
    local_datasets = {
        'reference': PROJECT / 'GridWeave/datasets/reference',
        'structural_extension': LAB / 'extension/corpus_v0_2',
        'independent_fixtures': LAB / 'runs/paper1-study-v1/independent_fixtures',
    }
    identities = {
        name: dict(identity, path=str(local_datasets[name]))
        for name, identity in identities.items()
    }
    write(out / 'dataset-identities.json', identities)
    corrected = oracle_at(PROJECT / 'GridWeave/src/gridweave/oracle.py', 'corrected_oracle')
    previous = oracle_at(LAB / 'corrections/2026-11-08-contract-v1/before/GridWeave/src/gridweave/oracle.py',
                         'previous_oracle')
    disagreements, previous_differences, comparisons = [], [], []
    manifest_files = 0
    for name, identity in identities.items():
        dataset = Path(identity['path'])
        assert file_hash(dataset / 'dataset-manifest.json') == identity['manifest_sha256']
        manifest = read(dataset / 'dataset-manifest.json')
        for rel, expected_hash in manifest['files'].items():
            assert file_hash(dataset / rel) == expected_hash, rel
            manifest_files += 1
        expected = expected_labels(dataset)
        labels = []
        for uid, observer, stream, policy, context in load_public(dataset / 'public'):
            truth = expected[uid]['truth']
            actual = corrected(observer, stream, policy, context)
            old = previous(observer, stream, policy, context)
            fields = [field for field in FIELDS if actual[field] != truth[field]]
            old_fields = [field for field in FIELDS if old[field] != truth[field]]
            entry = dict(dataset=name, unit_id=uid, condition=expected[uid]['operation'],
                         expected={field: truth[field] for field in FIELDS},
                         corrected={field: actual[field] for field in FIELDS},
                         differing_fields=fields, previous_differing_fields=old_fields)
            labels.append(entry)
            if fields:
                disagreements.append(entry)
            if old_fields:
                previous_differences.append(entry)
        write(out / 'oracle' / (name + '.json'), labels)
        with tempfile.TemporaryDirectory(prefix='paper1-corrected-public-') as tmp:
            public = Path(tmp) / 'public'
            shutil.copytree(dataset / 'public', public)
            for assessor in ('graph', 'sql'):
                predictions = out / 'predictions' / name / assessor
                predictions.parent.mkdir(parents=True, exist_ok=True)
                completed = subprocess.run([
                    sys.executable, '-m', 'paper1.assessor_worker', '--public', str(public),
                    '--assessor', assessor, '--output', str(predictions)], cwd=LAB,
                    capture_output=True, text=True)
                (out / f'{name}-{assessor}.log').write_text(completed.stdout + completed.stderr)
                assert completed.returncode == 0, completed.stderr
                result = compare(dataset, predictions, assessor, out / 'comparisons' / name / assessor)
                assert result['disagreement_count'] == 0, result
                result['dataset'] = name
                comparisons.append(result)
    assert not disagreements, disagreements
    assert {entry['condition'] for entry in previous_differences} == {'submission_before_event', 'future_submission'}

    # The supplementary probes do not change the existing fixture catalogue.
    spec = importlib.util.spec_from_file_location('contract_probe_helpers', LAB / 'tests/test_contract_corrections.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    rejected = []
    for name, uid, docs, message in helper.malformed_variants():
        public = out / 'malformed_inputs' / name / 'public'
        helper.export_public(public, uid, docs)
        for assessor in ('graph', 'sql'):
            destination = out / 'malformed_predictions' / name / assessor
            completed = subprocess.run([
                sys.executable, '-m', 'paper1.assessor_worker', '--public', str(public),
                '--assessor', assessor, '--output', str(destination)], cwd=LAB,
                capture_output=True, text=True)
            (destination.parent / (assessor + '.log')).write_text(completed.stdout + completed.stderr)
            assert completed.returncode != 0 and message in completed.stderr
            assert not list(destination.glob('*.json'))
            rejected.append(dict(probe=name, assessor=assessor, rejected=True, expected_reason=message))
    from paper1.graph_assessor import assess as graph
    from paper1.sql_assessor import assess as sql
    uid, base, truth = helper.fixture()
    signature_probes = []
    original = base[2]['receipts'][0]['proof']['verification_material_refs'][0]
    for name, refs in [('zero', []), ('two_identical', [original, original]),
                       ('two_distinct', [original, 'ed25519-signature:' + '00' * 64])]:
        docs = deepcopy(base)
        row = docs[2]['receipts'][0]
        row['proof']['verification_material_refs'] = refs
        expected = {field: deepcopy(truth[field]) for field in FIELDS}
        expected['outcome'] = 'PARTIALLY_CLOSED'
        expected['obligation_categories'][row['obligation_id']] = 'INVALID'
        expected['receipt_diagnoses'][row['receipt_id']] = 'REJECTED'
        helper.export_public(out / 'signature_inputs' / name / 'public', uid, docs)
        results = {}
        for label, fn in [('oracle', corrected), ('graph', graph), ('sql', sql)]:
            actual = fn(*docs[1:])
            assert all(actual[field] == expected[field] for field in FIELDS)
            results[label] = {field: actual[field] for field in FIELDS}
        entry = dict(probe=name, expected=expected, assessments=results)
        signature_probes.append(entry)
    write(out / 'signature_probes.json', signature_probes)
    write(out / 'malformed_rejections.json', rejected)
    write(out / 'previous_oracle_differences.json', previous_differences)
    assert freeze == {str(p.relative_to(PROJECT)): file_hash(p) for p in sources}
    record = dict(status='PASS', completed_at=datetime.now(timezone.utc).isoformat(),
                  scope='Separate correction verification; historical 1,914-comparison study unchanged',
                  oracle_case_units=638, oracle_scored_field_disagreements=0,
                  preserved_generated_units=540, preserved_generated_label_changes=0,
                  previous_oracle_disagreeing_existing_fixtures=len(previous_differences),
                  corrected_checker_case_comparisons=sum(row['cases'] for row in comparisons),
                  corrected_checker_scored_field_disagreements=sum(row['disagreement_count'] for row in comparisons),
                  signature_cardinality_probes=len(signature_probes),
                  signature_cardinality_assessments=len(signature_probes)*3,
                  malformed_input_variants=len(rejected)//2, malformed_worker_rejections=len(rejected),
                  original_fixture_catalogue_units=98, dataset_manifest_members_verified=manifest_files,
                  sources_unchanged_during_verification=True, assessment_runs=comparisons)
    write(out / 'summary.json', record)
    write(out / 'output-manifest.json', dict(files={str(p.relative_to(out)): file_hash(p)
                                                   for p in sorted(out.rglob('*')) if p.is_file()}))
    print(json.dumps({k: v for k, v in record.items() if k != 'assessment_runs'}, indent=2))


if __name__ == '__main__':
    main()
