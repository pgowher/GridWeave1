"""Differential safety tests for the optional algorithm candidates."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import random
import threading
import unittest

from test_verclo_evidence_closure import make_case, receipt, EVALUATION, ACCEPTED
from disputes.models import DisputeClosureState
from erasure import FederatedClosureEvaluator, TemporalEvidenceFrontier, ValidationSnapshot
from evidence import BackendValidation, CustodianReceiptVerifier, ExceptionValidation
from proof import EvidenceGradeEvaluator, DeterministicValidationBackend, NetworkPBFTCluster, NetworkFaultProfile, PBFTValidationBackend
from evaluation.network_study import _fixture, EVALUATION_TIME
from verclo import PolicyRegistry, ObligationGraphBuilder
from verclo.models import AssetDescriptor, LineageEdge

# Do not expose an imported TestCase as a module global to unittest discovery.
def graph_fixture():
    from test_verclo_case_services import VercloCaseServiceTests
    helper = VercloCaseServiceTests(); helper.setUp()
    return helper



class FrontierTests(unittest.TestCase):
    def setUp(self):
        self.case = make_case('FRONTIER', count=8, exception=True)
        self.policy = PolicyRegistry.load()
        self.rows = {f'R{i}': ValidationSnapshot(receipt(o, f'R{i}'), o, BackendValidation('snapshot'), 'epoch-1')
                     for i, o in enumerate(self.case.graph.obligations)}
        self.session = TemporalEvidenceFrontier(self.case, self.policy, 'epoch-1', self.rows.values())

    def full(self, time, mode='indexed', **kwargs):
        # Independent full recomputation, including full snapshot binding checks.
        rows = self.rows
        class Backend:
            def validate(_, r, o, t):
                record = rows[r.receipt_id]
                if record.receipt == r and record.obligation == o:
                    return record.decision
                return BackendValidation('temporal-frontier-snapshot-v1', verification_material_available=False,
                    assumptions_valid=False, diagnostics=('SNAPSHOT_CONTEXT_MISMATCH',))
        return FederatedClosureEvaluator(EvidenceGradeEvaluator(CustodianReceiptVerifier(Backend())),
            self.policy, receipt_matching=mode).evaluate(self.case, [r.receipt for r in rows.values()], time, **kwargs)

    def equivalent(self, time=EVALUATION, **kwargs):
        expected = self.full(time, **kwargs)
        self.assertEqual(expected, self.full(time, mode='scan', **kwargs))
        self.assertEqual(expected, self.session.evaluate(time, **kwargs))
        return expected

    def test_unchanged_and_sparse_changes_reuse_only_unaffected_bundles(self):
        self.equivalent(); self.assertEqual(8, self.session.last_work['bundle_evaluations'])
        self.equivalent(EVALUATION + timedelta(seconds=1))
        self.assertEqual(0, self.session.last_work['bundle_evaluations'])
        self.rows['R0'] = replace(self.rows['R0'], decision=BackendValidation('snapshot', authenticator_valid=False))
        self.session.update(records=[self.rows['R0']]); self.equivalent()
        # Time moved backwards, so conservatively recompute the full cache.
        self.assertEqual(8, self.session.last_work['bundle_evaluations'])
        self.rows['R1'] = replace(self.rows['R1'], decision=BackendValidation('snapshot', assumptions_valid=False))
        self.session.update(records=[self.rows['R1']]); self.equivalent()
        self.assertEqual(1, self.session.last_work['bundle_evaluations'])

    def test_all_temporal_discontinuities_and_backward_clock_match_full_evaluation(self):
        o = self.rows['R0'].obligation
        for i, delta in enumerate((1, 2, 3)):
            row = self.rows[f'R{i}']
            decision = BackendValidation('snapshot', ordering_support_valid=True, mechanism_present=True,
                mechanism_valid=True, mechanism_expires_at=EVALUATION + timedelta(seconds=3))
            r = replace(row.receipt, not_before=EVALUATION + timedelta(seconds=1),
                expires_at=EVALUATION + timedelta(seconds=5), evidence_type='deletion_acknowledgement')
            self.rows[f'R{i}'] = replace(row, receipt=r, decision=decision)
        self.session.update(records=self.rows.values())
        for seconds in (0, 1, 2, 3, 4, 5, 6, 0, 3, 5):
            self.equivalent(EVALUATION + timedelta(seconds=seconds))

    def test_conflicts_override_exceptions_and_retraction_restores_state(self):
        row = self.rows['R7']
        conflicting = ValidationSnapshot(receipt(row.obligation, 'CONFLICT', disposition='FAILED'), row.obligation, row.decision, row.epoch)
        self.rows['CONFLICT'] = conflicting; self.session.update(records=[conflicting])
        checks = (ExceptionValidation('EX-2', True, True),)
        result = self.equivalent(exception_validations=checks)
        self.assertEqual('DISPUTED', result.closure_class)
        self.rows.pop('CONFLICT'); self.session.update(remove_receipt_ids=['CONFLICT'])
        self.equivalent(exception_validations=checks)
        for t in (EVALUATION + timedelta(days=1), EVALUATION + timedelta(days=1, microseconds=1)):
            self.equivalent(t, exception_validations=checks)

    def test_dispute_rejection_and_unrejection_invalidate_cached_evidence(self):
        self.equivalent()
        dispute = DisputeClosureState(self.case.case_id, (), (), None, (), ('R0',), ())
        self.equivalent(dispute_state=dispute)
        self.assertEqual(1, self.session.last_work['bundle_evaluations'])
        self.equivalent()
        self.assertEqual(1, self.session.last_work['bundle_evaluations'])
        self.equivalent(open_challenge_ids=('CHALLENGE',))

    def test_epoch_rotation_discards_old_facts_and_updates_are_atomic(self):
        self.equivalent()
        with self.assertRaises(ValueError): self.session.rotate_epoch('epoch-2', self.rows.values())
        self.assertEqual('epoch-1', self.session.epoch); self.equivalent()
        self.session.rotate_epoch('epoch-2'); self.rows.clear(); self.equivalent()
        old = ValidationSnapshot(receipt(self.case.graph.obligations[0], 'OLD'), self.case.graph.obligations[0], BackendValidation('x'), 'epoch-1')
        with self.assertRaises(ValueError): self.session.update(records=[old])
        self.equivalent()

    def test_case_replacement_never_rebinds_old_validation_facts(self):
        self.equivalent()
        obligations = tuple(replace(o, minimum_evidence_grade='E4') for o in self.case.graph.obligations)
        self.case = replace(self.case, graph=replace(self.case.graph, obligations=obligations), revision=2)
        self.session.replace_case(self.case); self.equivalent()
        self.assertEqual(8, self.session.last_work['bundle_evaluations'])
        for key, row in tuple(self.rows.items()):
            o = next(o for o in obligations if o.obligation_id == row.obligation.obligation_id)
            self.rows[key] = replace(row, obligation=o)
        self.session.update(records=self.rows.values()); self.equivalent()

    def test_invalid_mutable_duplicate_and_foreign_context_inputs_are_rejected(self):
        record = self.rows['R0']; self.equivalent()
        with self.assertRaises(ValueError): self.session.update(records=[record, record], remove_receipt_ids=['R1'])
        with self.assertRaises(ValueError): replace(record, receipt=replace(record.receipt, provenance_refs=['x']))
        with self.assertRaises(ValueError): replace(record, decision=replace(record.decision, authenticator_valid=1))
        with self.assertRaises(ValueError): self.session.evaluate(EVALUATION.replace(tzinfo=None))
        with self.assertRaises(ValueError): self.session.replace_case(replace(self.case,
            graph=replace(self.case.graph, obligations=(record.obligation, record.obligation))))
        with self.assertRaises(ValueError): self.session.update(records=[replace(record,
            receipt=replace(record.receipt, case_id='foreign'))])
        self.equivalent()

    def test_seeded_differential_stream_covers_mutation_expiry_conflict_and_rejection(self):
        rng = random.Random(91827)
        now = EVALUATION
        for step in range(250):
            key = f'R{rng.randrange(16)}'; o = rng.choice(self.case.graph.obligations)
            if rng.random() < .22:
                self.rows.pop(key, None); self.session.update(remove_receipt_ids=[key])
            else:
                r = replace(receipt(o, key, disposition=rng.choice(('ERASED', 'FAILED', 'CRYPTO_ERASED')),
                    evidence_type=rng.choice(('signature', 'digest', 'deletion_acknowledgement', 'audit_finding'))),
                    not_before=now + timedelta(seconds=rng.randrange(-4, 5)),
                    expires_at=now + timedelta(seconds=rng.randrange(1, 8)))
                d = BackendValidation('snapshot', authenticator_valid=rng.random() > .15,
                    ordering_support_valid=True, mechanism_present=True, mechanism_valid=True,
                    mechanism_expires_at=now + timedelta(seconds=3))
                row = ValidationSnapshot(r, o, d, 'epoch-1'); self.rows[key] = row; self.session.update(records=[row])
            now += timedelta(seconds=rng.choice((-2, 0, 1, 3)))
            rejected = tuple(k for k in self.rows if rng.random() < .08)
            dispute = DisputeClosureState(self.case.case_id, (), (), None, (), rejected, ())
            with self.subTest(step=step): self.equivalent(now, dispute_state=dispute)

    def test_frontier_heap_compacts_repeated_replacement_events(self):
        for i in range(180):
            row = replace(self.rows['R0'], receipt=replace(self.rows['R0'].receipt,
                expires_at=EVALUATION + timedelta(days=i + 1)))
            self.rows['R0'] = row; self.session.update(records=[row]); self.equivalent()
        self.assertLessEqual(len(self.session._frontier), 65)

    def test_corroboration_support_and_baseline_changes_match_full_recomputation(self):
        o = self.rows['R0'].obligation
        for key, kind, issuer, role, domain in (
            ('M', 'deletion_acknowledgement', o.custodian_principal_id, 'CUSTODIAN', 'C'),
            ('A1', 'audit_finding', 'AUDITOR-1', 'AUDITOR', 'A1'),
            ('A2', 'audit_finding', 'AUDITOR-2', 'AUDITOR', 'A2'),
            ('L', 'inclusion_proof', 'LOG', 'LOG', 'L')):
            r = replace(receipt(o, key, evidence_type=kind, issuer=issuer, role=role,
                trust_domain=domain, fault_domain=domain), expires_at=EVALUATION+timedelta(seconds=5))
            d = BackendValidation('snapshot', anchor_valid=True, ordering_support_valid=True,
                mechanism_present=key=='M', mechanism_valid=key=='M', mechanism_expires_at=EVALUATION+timedelta(seconds=2))
            self.rows[key] = ValidationSnapshot(r, o, d, 'epoch-1')
        self.session.update(records=self.rows.values())
        for offset in (0, 2, 5): self.equivalent(EVALUATION+timedelta(seconds=offset))
        for baseline in (False, True):
            self.case = replace(self.case, graph=replace(self.case.graph, baseline_verifiable=baseline))
            self.session.replace_case(self.case); self.equivalent()


class LineageTraversalTests(unittest.TestCase):
    def test_graph_and_commitments_equal_across_algorithms_and_input_orders(self):
        helper = graph_fixture()
        policy = helper.registry.get(helper.case.policy_profile_id)
        reference = None
        for mode in ('legacy', 'kahn_bfs', 'fused'):
            for reverse in (False, True):
                graph = ObligationGraphBuilder(traversal=mode).build(view=helper._view(reverse=reverse),
                    root_asset_ids=helper.case.root_asset_ids, accepted_at=ACCEPTED, policy=policy)
                if reference is None: reference = graph
                self.assertEqual(reference, graph)

    def test_disconnected_cycles_and_self_loops_are_rejected(self):
        for edges in ([('b', 'c'), ('c', 'b')], [('b', 'b')]):
            for mode in ('legacy', 'kahn_bfs', 'fused'):
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'acyclic'):
                    if mode == 'legacy': ObligationGraphBuilder._legacy_scope({'a', 'b', 'c'}, edges, ['a'])
                    else: ObligationGraphBuilder._linear_scope({'a', 'b', 'c'}, edges, ['a'], fused=mode == 'fused')

    def test_seeded_dags_parallel_edges_roots_and_permutations_match(self):
        rng = random.Random(271828)
        for size in (0, 1, 5, 35, 100):
            assets = {str(i) for i in range(size)}
            for _ in range(10):
                edges = [(str(a), str(b)) for a in range(size) for b in range(a + 1, size) if rng.random() < .05]
                edges += edges[:4]; rng.shuffle(edges)
                roots = rng.sample(sorted(assets), min(3, size)) + ['unresolved']
                expected = ObligationGraphBuilder._legacy_scope(assets, edges, roots)
                self.assertEqual(expected, ObligationGraphBuilder._linear_scope(assets, edges, roots))
                self.assertEqual(expected, ObligationGraphBuilder._linear_scope(assets, edges, roots, fused=False))


class CertificateDeliveryTests(unittest.TestCase):
    ids = ('V0', 'V1', 'V2', 'V3')
    def setUp(self):
        self.receipt, self.obligation = _fixture()
        self.decision = BackendValidation('validator', anchor_valid=True, ordering_support_valid=True)

    def adapter(self, client, cluster):
        return PBFTValidationBackend(client, len(cluster.services), (len(cluster.services)-1)//3,
            validator_public_keys=client.public_keys, membership_epoch=cluster.membership_epoch, require_signed_votes=True)

    def test_strategies_preserve_quorums_and_reduce_healthy_message_count(self):
        for size in (4, 7, 10):
            for strategy in ('serial', 'parallel_all', 'certificate_frontier'):
                with NetworkPBFTCluster(tuple(f'V{i}' for i in range(size)), self.decision) as cluster:
                    backend = cluster.backend(delivery_strategy=strategy)
                    result = backend.validate(self.receipt, self.obligation, EVALUATION_TIME)
                    cost = backend.client.last_cost; cert = backend.client.last_certificate
                    q = 2*((size-1)//3)+1
                    self.assertTrue(result.verification_material_available)
                    self.assertGreaterEqual(len(cert.signed_finalize_votes), q)
                    self.assertEqual(1+size+2*q if strategy == 'certificate_frontier' else 1+3*size, cost['messages_sent'])

    def test_one_fault_progress_and_two_faults_fail_closed_for_each_strategy(self):
        for strategy in ('parallel_all', 'certificate_frontier'):
            for bad, expected in ((('V3',), True), (('V2', 'V3'), False)):
                for kind in ('partitioned_validator_ids', 'equivocating_validator_ids'):
                    with NetworkPBFTCluster(self.ids, self.decision, fault_profile=NetworkFaultProfile(**{kind: bad})) as cluster:
                        result = cluster.backend(delivery_strategy=strategy).validate(self.receipt, self.obligation, EVALUATION_TIME)
                        self.assertEqual(expected, result.verification_material_available)

    def test_selective_finalize_fallback_first_persists_prepared_proof(self):
        with NetworkPBFTCluster(self.ids, self.decision) as cluster:
            client = cluster.client(delivery_strategy='certificate_frontier'); original = client._send
            lock = threading.Lock(); dropped = []; calls = []
            def send(node, path, payload):
                with lock:
                    calls.append((node, path))
                    if path == '/v2/finalize' and (not dropped or node == dropped[0]):
                        if not dropped: dropped.append(node)
                        return None
                return original(node, path, payload)
            client._send = send
            result = self.adapter(client, cluster).validate(self.receipt, self.obligation, EVALUATION_TIME)
            self.assertTrue(result.verification_material_available)
            self.assertEqual(1, client.last_cost.get('catchup_commits'))
            self.assertEqual(13, client.last_cost['messages_sent'])
            for node, path in calls:
                if path == '/v2/finalize': self.assertLess(calls.index((node, '/v2/commit')), calls.index((node, path)))

    def test_selective_commit_failure_expands_recipient_set(self):
        with NetworkPBFTCluster(self.ids, self.decision) as cluster:
            client = cluster.client(delivery_strategy='certificate_frontier'); original = client._send
            lock = threading.Lock(); dropped = []
            def send(node, path, payload):
                with lock:
                    if path == '/v2/commit' and (not dropped or node == dropped[0]):
                        if not dropped: dropped.append(node)
                        return None
                return original(node, path, payload)
            client._send = send
            self.assertTrue(self.adapter(client, cluster).validate(self.receipt, self.obligation, EVALUATION_TIME).verification_material_available)
            self.assertEqual(12, client.last_cost['messages_sent'])

    def test_optimized_strategies_keep_negative_decisions_and_reject_unsigned_finalize(self):
        for strategy in ('parallel_all', 'certificate_frontier'):
            decision = replace(self.decision, assumptions_valid=False)
            with NetworkPBFTCluster(self.ids, decision) as cluster:
                backend = cluster.backend(delivery_strategy=strategy)
                result = backend.validate(self.receipt, self.obligation, EVALUATION_TIME)
                self.assertFalse(result.assumptions_valid)
                original = backend.client._send
                backend.client._send = lambda node, path, payload: {'finalized': True} if path == '/v2/finalize' else original(node, path, payload)
                self.assertFalse(backend.validate(self.receipt, self.obligation, EVALUATION_TIME).verification_material_available)

    def test_concurrent_selective_certificates_keep_signed_epoch_context(self):
        with NetworkPBFTCluster(self.ids, self.decision) as cluster:
            backend = cluster.backend(timeout=4, delivery_strategy='certificate_frontier')
            def run(i):
                r = replace(self.receipt, receipt_id=f'CONCURRENT-{i}')
                result = backend.validate(r, self.obligation, EVALUATION_TIME)
                return result, backend.client.last_certificate, dict(backend.client.last_cost)
            with ThreadPoolExecutor(4) as pool: results = list(pool.map(run, range(12)))
            self.assertEqual(12, len({c.sequence for _, c, _ in results}))
            for result, cert, cost in results:
                self.assertTrue(result.verification_material_available)
                self.assertEqual(cert.sequence, cost['sequence']); self.assertEqual(11, cost['messages_sent'])
                class Static:
                    def validate_receipt(self, *args): return replace(cert, membership_epoch='relabelled')
                invalid = PBFTValidationBackend(Static(), 4, 1, validator_public_keys=backend.client.public_keys,
                    membership_epoch='relabelled', require_signed_votes=True).validate(self.receipt, self.obligation, EVALUATION_TIME)
                self.assertFalse(invalid.verification_material_available)

    def test_selectively_finalized_value_survives_client_restart_and_cross_view_conflict(self):
        for strategy in ('parallel_all', 'certificate_frontier'):
            with NetworkPBFTCluster(self.ids, self.decision) as cluster:
                first = cluster.backend(delivery_strategy=strategy)
                self.assertTrue(first.validate(self.receipt, self.obligation, EVALUATION_TIME).verification_material_available)
                # A fresh in-memory client reuses sequence 1. The existing
                # prepared/finalized quorum must refuse a conflicting value.
                second = cluster.backend(delivery_strategy=strategy)
                conflict = replace(self.receipt, receipt_id='CONFLICTING-CLIENT')
                self.assertFalse(second.validate(conflict, self.obligation, EVALUATION_TIME).verification_material_available)
                self.assertEqual(1, second.client.last_cost['sequence'])

    def test_selective_strategy_recovers_after_leader_crash(self):
        with NetworkPBFTCluster(self.ids, self.decision,
                fault_profile=NetworkFaultProfile(crashed_validator_ids=('V0',))) as cluster:
            backend = cluster.backend(delivery_strategy='certificate_frontier')
            self.assertTrue(backend.validate(self.receipt, self.obligation, EVALUATION_TIME).verification_material_available)
            self.assertEqual(1, backend.client.last_cost['view'])
            self.assertEqual(3, backend.client.last_cost['finalized_acks'])
