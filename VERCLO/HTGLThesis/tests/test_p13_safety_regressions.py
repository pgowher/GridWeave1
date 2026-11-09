"""Adversarial schedules for audit F01-F03, with progress controls."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
import json
from copy import deepcopy
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cryptography.exceptions import InvalidSignature
from evaluation.network_study import _fixture, EVALUATION_TIME
from evidence.models import BackendValidation
from proof.decision_wire import BOOLEAN_FIELDS, decision_to_wire, decision_from_wire, decision_digest
from proof.network_backends import (
    PBFTValidatorService, NetworkPBFTClient, NetworkPBFTCluster,
    NetworkSignedValidationBackend, NetworkMerkleValidationBackend,
    serve_signed_authority, serve_merkle_authority, deterministic_private_key,
    _public_bytes, _vote_from_wire, _verify_vote, _verify_view_change,
    _new_view_value, _view_change_bytes, _b64,
)
from proof.validation_backend import PBFTValidationBackend, committee_digest


class Harness:
    def __init__(self, root=None, epoch='regression-epoch'):
        self.keys = {f'V{i}': deterministic_private_key(f'p13-corrected:{i}') for i in range(4)}
        self.public = {k: _public_bytes(v) for k, v in self.keys.items()}
        self.epoch = epoch
        self.decision = BackendValidation('test', anchor_valid=True, ordering_support_valid=True)
        self.services = {k: PBFTValidatorService(k, v, self.public, epoch, self.decision,
            state_path=Path(root)/f'{k}.db' if root else None) for k,v in self.keys.items()}

    def core(self, value='a', view=0, sequence=1):
        return dict(receipt_commitment=value*64, decision_commitment=decision_digest(decision_to_wire(self.decision)),
            view=view, sequence=sequence, membership_epoch=self.epoch, committee_digest=committee_digest(self.public))

    def changes(self, core, ids=None):
        return [self.services[k].handle('/v2/view-change', core)[1] for k in (ids or self.services)]

    def prepare(self, core, changes=None):
        request = {**core, 'view_change_votes': changes or []}
        leader = sorted(self.services)[core['view'] % 4]
        status, vote = self.services[leader].handle('/v2/propose', request)
        if status != 200:
            raise ValueError(str(vote))
        request['leader_vote'] = vote
        votes = []
        for service in self.services.values():
            status, vote = service.handle('/v2/preprepare', request)
            if status == 200:
                votes.append(vote)
        return votes

    def commit(self, core, prepares, ids=None):
        return [self.services[k].handle('/v2/commit', {**core, 'prepare_votes': prepares})[1]
            for k in (ids or self.services)]

    def finalize(self, core, commits):
        return [s.handle('/v2/finalize', {**core, 'commit_votes': commits}) for s in self.services.values()]

    def close(self):
        for s in self.services.values(): s.close()


class P13SafetyRegressions(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.close)
        self.receipt, self.obligation = _fixture()

    def test_finalized_sequence_cannot_change_value_in_later_view(self):
        a = self.h.core()
        commits = self.h.commit(a, self.h.prepare(a))
        self.assertTrue(all(status == 200 for status, _ in self.h.finalize(a, commits)))
        b = self.h.core('b', 1)
        changes = self.h.changes(b)
        self.assertEqual(('a'*64, a['decision_commitment']), _new_view_value(changes, self.h.public, self.h.epoch, 1, 1))
        with self.assertRaisesRegex(ValueError, 'highest prepared'):
            self.h.prepare(b, changes)
        # Retaining the old value in the new view remains live.
        a1 = self.h.core('a', 1)
        commits = self.h.commit(a1, self.h.prepare(a1, changes))
        self.assertTrue(all(status == 200 for status, _ in self.h.finalize(a1, commits)))
        self.assertTrue(all(s.state.summary()['committed'] == 1 for s in self.h.services.values()))

    def test_prepared_value_is_carried_even_without_finalization(self):
        a = self.h.core()
        self.h.commit(a, self.h.prepare(a), ids=['V0','V1','V2'])
        b = self.h.core('b', 1)
        changes = self.h.changes(b, ['V1','V2','V3'])
        with self.assertRaisesRegex(ValueError, 'highest prepared'):
            self.h.prepare(b, changes)
        a1 = self.h.core('a', 1)
        self.assertEqual(4, len(self.h.commit(a1, self.h.prepare(a1, changes))))

    def test_unprepared_proposal_can_be_replaced_after_view_change(self):
        self.h.prepare(self.h.core())  # PREPARE messages alone are not durable prepared certificates.
        b = self.h.core('b', 1)
        changes = self.h.changes(b)
        self.assertIsNone(_new_view_value(changes, self.h.public, self.h.epoch, 1, 1))
        commits = self.h.commit(b, self.h.prepare(b, changes))
        self.assertTrue(all(status == 200 for status, _ in self.h.finalize(b, commits)))

    def test_followers_reject_leader_signed_conflict_and_missing_new_view_proof(self):
        a = self.h.core()
        self.h.commit(a, self.h.prepare(a))
        b = self.h.core('b', 1)
        changes = self.h.changes(b)
        malicious_leader = self.h.services['V1']._sign_vote('PRE-PREPARE', 1, 1, b['receipt_commitment'], b['decision_commitment'])
        for proof in ([], changes):
            with self.subTest(proof_present=bool(proof)), self.assertRaises(ValueError):
                self.h.services['V2'].handle('/v2/preprepare', {**b,
                    'leader_vote': asdict(malicious_leader), 'view_change_votes': proof})

    def test_one_byzantine_view_change_cannot_hide_committed_value(self):
        a = self.h.core()
        self.h.commit(a, self.h.prepare(a), ['V0','V1','V2'])
        b = self.h.core('b', 1)
        changes = self.h.changes(b, ['V0','V1','V3'])
        # V0 is Byzantine: valid signature over a deliberately omitted proof.
        liar = {k:v for k,v in changes[0].items() if k != 'signature'}
        liar['prepared'] = []
        changes[0] = {**liar, 'signature': _b64(self.h.keys['V0'].sign(_view_change_bytes(liar)))}
        self.assertEqual('a'*64, _new_view_value(changes, self.h.public, self.h.epoch, 1, 1)[0])
        with self.assertRaises(ValueError): self.h.prepare(b, changes)

    def test_prepared_state_and_finalized_lock_survive_restart(self):
        for finalized in (False, True):
            with self.subTest(finalized=finalized), tempfile.TemporaryDirectory() as root:
                h = Harness(root)
                a = h.core()
                commits = h.commit(a, h.prepare(a))
                if finalized: h.finalize(a, commits)
                h.close()
                restarted = Harness(root)
                try:
                    b = restarted.core('b', 1)
                    changes = restarted.changes(b)
                    with self.assertRaises(ValueError): restarted.prepare(b, changes)
                    a1 = restarted.core('a', 1)
                    self.assertEqual(4, len(restarted.commit(a1, restarted.prepare(a1, changes))))
                finally: restarted.close()

    def test_view_promise_and_old_commit_are_atomic(self):
        for sequence in range(1, 21):
            a = self.h.core(sequence=sequence)
            prepares = self.h.prepare(a)
            barrier = threading.Barrier(2)
            node = self.h.services['V0']
            def commit():
                barrier.wait()
                return node.handle('/v2/commit', {**a, 'prepare_votes': prepares})
            def change():
                barrier.wait()
                return node.handle('/v2/view-change', {**a, 'view': 1})
            with ThreadPoolExecutor(2) as pool:
                c, v = pool.submit(commit), pool.submit(change)
                c, v = c.result(), v.result()
            self.assertEqual(200, v[0])
            self.assertEqual(c[0] == 200, bool(v[1]['prepared']))
            self.assertEqual(409, node.handle('/v2/commit', {**a, 'prepare_votes': prepares})[0])

    def test_votes_in_every_phase_reject_epoch_or_committee_relabelling(self):
        for phase in ('PRE-PREPARE','PREPARE','COMMIT','FINALIZE'):
            vote = self.h.services['V0']._sign_vote(phase, 0, 1, 'a'*64, self.h.core()['decision_commitment'])
            _verify_vote(vote, phase, self.h.public, self.h.epoch)
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                _verify_vote(vote, phase, self.h.public, 'new-epoch')
            with self.assertRaises(InvalidSignature):
                _verify_vote(replace(vote, membership_epoch='new-epoch'), phase, self.h.public, 'new-epoch')
            rotated = {**self.h.public, 'V3': _public_bytes(deterministic_private_key('rotated'))}
            with self.assertRaises(ValueError): _verify_vote(vote, phase, rotated, self.h.epoch)
            with self.assertRaises(InvalidSignature):
                _verify_vote(replace(vote, committee_digest=committee_digest(rotated)), phase, rotated, self.h.epoch)

    def test_view_change_proof_is_context_bound_and_rejects_duplicate_or_fake_prepared(self):
        core = self.h.core(view=1)
        changes = self.h.changes(core)
        with self.assertRaises(ValueError): _verify_view_change(changes[0], self.h.public, 'new', 1, 1)
        with self.assertRaises(ValueError): _new_view_value([changes[0]]*3, self.h.public, self.h.epoch, 1, 1)
        malicious = {k:v for k,v in changes[0].items() if k != 'signature'}
        malicious['prepared'] = [asdict(self.h.services['V0']._sign_vote('PREPARE', 0, 1, 'a'*64, core['decision_commitment']))]*3
        signed = {**malicious, 'signature': _b64(self.h.keys['V0'].sign(_view_change_bytes(malicious)))}
        with self.assertRaises(ValueError): _verify_view_change(signed, self.h.public, self.h.epoch, 1, 1)

    def test_replica_and_client_reject_legacy_or_wrong_context_databases(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'legacy.db'
            with sqlite3.connect(path) as c: c.execute('CREATE TABLE proposals (view INTEGER)')
            with self.assertRaisesRegex(ValueError, 'legacy'):
                PBFTValidatorService('V0', self.h.keys['V0'], self.h.public, self.h.epoch, self.h.decision, state_path=path)
            h = Harness(root)
            h.close()
            with self.assertRaisesRegex(ValueError, 'context mismatch'): Harness(root, epoch='changed')
            endpoints = {k:'http://127.0.0.1:1' for k in self.h.keys}
            NetworkPBFTClient(endpoints, self.h.public, self.h.epoch, self.h.decision, state_path=Path(root)/'client.db')
            with self.assertRaisesRegex(ValueError, 'context mismatch'):
                NetworkPBFTClient(endpoints, self.h.public, 'changed', self.h.decision, state_path=Path(root)/'client.db')

    def test_decision_wire_rejects_coercion_missing_fields_and_unknown_schema(self):
        wire = decision_to_wire(self.h.decision)
        for field in BOOLEAN_FIELDS:
            for value in ('false', 0, 1, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    decision_from_wire('test', {**wire, field: value})
            incomplete = dict(wire); incomplete.pop(field)
            with self.assertRaises(ValueError): decision_from_wire('test', incomplete)
        with self.assertRaises(ValueError): decision_from_wire('test', {**wire, 'schema': 'v1'})

    def test_all_decision_facts_survive_all_three_network_backends(self):
        positive = replace(self.h.decision, mechanism_present=True, mechanism_valid=True,
            mechanism_expires_at=EVALUATION_TIME+timedelta(days=1), diagnostics=('SOURCE_DIAGNOSTIC',))
        for field in (None, *BOOLEAN_FIELDS):
            decision = replace(positive, **({field:False} if field else {}))
            with self.subTest(negative_field=field):
                for serve, backend_type, identity in ((serve_signed_authority, NetworkSignedValidationBackend, 'AUTH'),
                        (serve_merkle_authority, NetworkMerkleValidationBackend, 'LOG')):
                    service, public = serve(identity, decision)
                    with service:
                        result = backend_type(service.url, identity, public).validate(self.receipt, self.obligation, EVALUATION_TIME)
                    self.assertEqual(decision_to_wire(decision), decision_to_wire(result))
                with NetworkPBFTCluster(tuple(self.h.keys), decision) as cluster:
                    result = cluster.backend().validate(self.receipt, self.obligation, EVALUATION_TIME)
                self.assertEqual(decision_to_wire(decision), decision_to_wire(result))

    def test_adapter_rejects_relabelled_epoch_and_missing_or_forged_finalization(self):
        with NetworkPBFTCluster(tuple(self.h.keys), self.h.decision) as cluster:
            client = cluster.client()
            cert = client.validate_receipt(self.receipt, self.obligation, EVALUATION_TIME)
            def check(certificate, epoch=None):
                class Static:
                    def validate_receipt(self, *args): return certificate
                return PBFTValidationBackend(Static(), 4, 1, validator_public_keys=client.public_keys,
                    membership_epoch=epoch or cert.membership_epoch, require_signed_votes=True).validate(
                    self.receipt, self.obligation, EVALUATION_TIME).verification_material_available
            self.assertTrue(check(cert))
            self.assertFalse(check(replace(cert, membership_epoch='new'), 'new'))
            self.assertFalse(check(replace(cert, signed_finalize_votes=())))
            self.assertFalse(check(replace(cert, signed_finalize_votes=cert.signed_finalize_votes[:2])))
            self.assertFalse(check(replace(cert, signed_finalize_votes=(cert.signed_finalize_votes[0],)*3)))
            votes = list(cert.signed_finalize_votes); votes[0] = replace(votes[0], signature='A'*86)
            self.assertFalse(check(replace(cert, signed_finalize_votes=tuple(votes))))

    def test_unsigned_finalize_responses_cannot_make_client_succeed(self):
        with NetworkPBFTCluster(tuple(self.h.keys), self.h.decision) as cluster:
            client = cluster.client(); original = client._send
            def intercepted(validator, path, payload):
                if path == '/v2/finalize': return {'finalized': True, 'validator_id': validator}
                return original(validator, path, payload)
            client._send = intercepted
            backend = PBFTValidationBackend(client, 4, 1, validator_public_keys=client.public_keys,
                membership_epoch=cluster.membership_epoch, require_signed_votes=True)
            result = backend.validate(self.receipt, self.obligation, EVALUATION_TIME)
            self.assertFalse(result.verification_material_available)
            self.assertEqual(0, client.last_cost['finalized_acks'])
            self.assertGreaterEqual(client.last_cost['commit_votes'], 3)

    def test_concurrent_calls_keep_their_own_certificates_and_costs(self):
        with NetworkPBFTCluster(tuple(self.h.keys), self.h.decision) as cluster:
            backend = cluster.backend(timeout=3)
            def call(index):
                receipt = replace(self.receipt, receipt_id=f'race:{index}')
                result = backend.validate(receipt, self.obligation, EVALUATION_TIME)
                return result, receipt, backend.client.last_certificate, dict(backend.client.last_cost)
            with ThreadPoolExecutor(4) as pool: outcomes = list(pool.map(call, range(12)))
            self.assertEqual(12, len({c.sequence for _,_,c,_ in outcomes}))
            for result, receipt, certificate, cost in outcomes:
                self.assertTrue(result.verification_material_available)
                self.assertEqual(certificate.sequence, cost['sequence'])
                self.assertEqual(PBFTValidationBackend.receipt_commitment(receipt), certificate.receipt_commitment)
                self.assertGreaterEqual(cost['finalized_acks'], 3)

    def test_operation_records_verify_offline_and_retain_failed_calls(self):
        from evaluation.p13_extension_study import _run_load, write_extension_results
        from proof.network_backends import NetworkFaultProfile
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from verify_p13_operation_records import verify_records
        with NetworkPBFTCluster(tuple(self.h.keys), self.h.decision) as cluster:
            row = _run_load(cluster.backend(), 'offline-positive', 2, 4)
        records = json.loads(json.dumps(row['operation_records'], default=lambda v:v.isoformat()))
        contexts = {record['expected_epoch']: record['public_keys'] for record in records}
        self.assertEqual(4, verify_records(records, contexts)['accepted'])
        for mutation in ('epoch', 'signature', 'negative_fact', 'receipt', 'cost'):
            altered = deepcopy(records)
            if mutation == 'epoch': altered[0]['certificate']['membership_epoch'] = 'other'
            elif mutation == 'signature': altered[0]['certificate']['signed_commit_votes'][0]['signature'] = 'A'*86
            elif mutation == 'negative_fact': altered[0]['certificate']['verification_material_available'] = False
            elif mutation == 'receipt': altered[0]['receipt']['receipt_id'] = 'different'
            else: altered[0]['cost']['sequence'] += 1
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, InvalidSignature)):
                verify_records(altered, contexts)
        fault = NetworkFaultProfile(partitioned_validator_ids=('V2','V3'))
        with NetworkPBFTCluster(tuple(self.h.keys), self.h.decision, fault_profile=fault) as cluster:
            failed = _run_load(cluster.backend(), 'offline-negative', 1, 2)
        failed = json.loads(json.dumps(failed, default=lambda v:v.isoformat()))
        self.assertEqual(0, failed['accepted'])
        self.assertEqual(2, len(failed['operation_records']))
        with tempfile.TemporaryDirectory() as out:
            write_extension_results({'load_results':[failed]}, Path(out)/'report.json')
            retained = [json.loads(line) for line in (Path(out)/'operation-records.jsonl').read_text().splitlines()]
            contexts = {record['expected_epoch']: record['public_keys'] for record in retained}
            self.assertEqual(2, verify_records(retained, contexts)['rejected'])

    def test_legacy_authority_endpoints_cannot_drop_new_negative_facts(self):
        from proof.network_backends import SignedAuthorityService, MerkleTransparencyService
        for service_type, old_path in ((SignedAuthorityService, '/v1/validate'),
                                      (MerkleTransparencyService, '/v1/append-and-prove')):
            service = service_type('AUTH', self.h.keys['V0'], replace(self.h.decision,
                verification_material_available=False, assumptions_valid=False))
            self.assertEqual(404, service.handle(old_path, {'receipt_commitment':'a'*64, 'request_id':'test'})[0])


if __name__ == '__main__': unittest.main()
