"""Regression checks for the separately recorded November contract correction.

The original 98-fixture catalogue and frozen datasets are not modified.
"""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
PROJECT = LAB.parents[1]
sys.path.insert(0, str(LAB))
from paper1.fixture_builder import STRUCTURES, construct
from paper1.wire import digest, exchange_domain, file_hash, load_public, read, write
from paper1 import graph_assessor, sql_assessor


def load_oracle():
    path = PROJECT / 'GridWeave/src/gridweave/oracle.py'
    spec = importlib.util.spec_from_file_location('contract_test_oracle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.evaluate


def fixture(name='resolved', **expectations):
    spec = dict(name=name, expected='CLOSED', target='COVERED')
    spec.update(expectations)
    return construct(STRUCTURES[0], spec, 0, 'contract-correction-regression-v1')


def export_public(root, uid, docs):
    """Refresh the outer envelope so probes isolate the intended defect."""
    manifest, observer, stream, policy, context = deepcopy(docs)
    observer['projection_commitment'] = exchange_domain(
        'paeforge-observer-projection-v1',
        {k: observer[k] for k in ('observer', 'policy', 'case', 'topology', 'exceptions', 'challenges')})
    stream['stream_commitment'] = exchange_domain('paeforge-receipt-stream-v1', stream['receipts'])
    manifest['artifacts']['observer_projection']['sha256'] = digest(observer)
    manifest['artifacts']['receipt_stream']['sha256'] = digest(stream)
    files = {
        f'cases/{uid}/case-manifest.json': manifest,
        f'cases/{uid}/observer-projection.json': observer,
        f'cases/{uid}/receipt-stream.json': stream,
        f'configuration/{uid}/policies/policy.json': policy,
        f'configuration/{uid}/verification-context.json': context,
    }
    for path, value in files.items():
        write(root / path, value)
    write(root / 'index.json', dict(version='GridWeave-0.2.0', cases=[dict(
        unit_id=uid, split='test', files={path: file_hash(root / path) for path in files})]))


def malformed_variants():
    uid, base, _ = fixture()
    for doc_index, label in ((0, 'manifest'), (1, 'observer')):
        for field in ('profile_id', 'version', 'sha256'):
            docs = deepcopy(base)
            docs[doc_index]['policy'][field] = 'MISMATCH'
            yield label + '_' + field, uid, docs, 'Policy binding mismatch'
    for field in ('profile_id', 'version'):
        docs = deepcopy(base)
        for doc in docs[:2]:
            doc['policy'][field] = 'CONSISTENT-BUT-WRONG'
        yield 'both_' + field, uid, docs, 'Policy binding mismatch'
    docs = deepcopy(base)
    docs[2]['receipts'].append(deepcopy(docs[2]['receipts'][0]))
    yield 'duplicate_receipt', uid, docs, 'Duplicate receipt identifier'


class OracleAdmissionRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oracle = staticmethod(load_oracle())

    def test_submission_boundary_expectations(self):
        for name in ('submission_before_event', 'future_submission'):
            with self.subTest(fixture=name):
                _, docs, expected = fixture(name, expected='PARTIALLY_CLOSED', target='INVALID')
                actual = self.oracle(*docs[1:])
                for field in ('outcome', 'baseline_verifiable', 'obligation_categories', 'receipt_diagnoses'):
                    self.assertEqual(actual[field], expected[field], field)

    def test_zero_or_multiple_signature_references_are_rejected(self):
        _, base, _ = fixture()
        original = base[2]['receipts'][0]['proof']['verification_material_refs'][0]
        variants = ([], [original, original], [original, 'ed25519-signature:' + '00' * 64])
        for references in variants:
            with self.subTest(signature_count=len(references)):
                docs = deepcopy(base)
                receipt = docs[2]['receipts'][0]
                receipt['proof']['verification_material_refs'] = references
                expected = dict(outcome='PARTIALLY_CLOSED', receipt='REJECTED', category='INVALID')
                for assessor in (self.oracle, graph_assessor.assess, sql_assessor.assess):
                    actual = assessor(*docs[1:])
                    self.assertEqual(actual['outcome'], expected['outcome'])
                    self.assertEqual(actual['receipt_diagnoses'][receipt['receipt_id']], expected['receipt'])
                    self.assertEqual(actual['obligation_categories'][receipt['obligation_id']], expected['category'])

    def test_single_signature_remains_accepted(self):
        _, docs, expected = fixture()
        actual = self.oracle(*docs[1:])
        for field in ('outcome', 'baseline_verifiable', 'obligation_categories', 'receipt_diagnoses'):
            self.assertEqual(actual[field], expected[field])


class PublicEnvelopeRegression(unittest.TestCase):
    def test_valid_public_bundle_is_accepted(self):
        uid, docs, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            export_public(Path(tmp), uid, docs)
            self.assertEqual([x[0] for x in load_public(tmp)], [uid])

    def test_policy_bindings_and_duplicate_receipts_are_rejected(self):
        for name, uid, docs, error in malformed_variants():
            with self.subTest(probe=name), tempfile.TemporaryDirectory() as tmp:
                export_public(Path(tmp), uid, docs)
                with self.assertRaisesRegex(ValueError, error):
                    load_public(tmp)

    def test_both_execution_paths_reject_before_writing_predictions(self):
        for name, uid, docs, error in malformed_variants():
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                export_public(root / 'public', uid, docs)
                for assessor in ('graph', 'sql'):
                    with self.subTest(probe=name, assessor=assessor):
                        output = root / assessor
                        result = subprocess.run([
                            sys.executable, '-m', 'paper1.assessor_worker', '--public', str(root / 'public'),
                            '--assessor', assessor, '--output', str(output)], cwd=LAB,
                            capture_output=True, text=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(error, result.stderr)
                        self.assertFalse(list(output.glob('*.json')))

    def test_both_execution_paths_still_predict_valid_inputs(self):
        uid, docs, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_public(root / 'public', uid, docs)
            for assessor in ('graph', 'sql'):
                with self.subTest(assessor=assessor):
                    output = root / assessor
                    result = subprocess.run([
                        sys.executable, '-m', 'paper1.assessor_worker', '--public', str(root / 'public'),
                        '--assessor', assessor, '--output', str(output)], cwd=LAB,
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(read(output / (uid + '.json'))['assessment']['outcome'], 'CLOSED')
                    self.assertEqual(read(output / 'results-manifest.json')['status'], 'COMPLETE')


if __name__ == '__main__':
    unittest.main()
