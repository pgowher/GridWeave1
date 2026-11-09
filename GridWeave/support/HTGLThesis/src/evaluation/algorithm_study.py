"""Paired local comparisons. No novelty or WAN-superiority claim is inferred."""
from __future__ import annotations

import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import gc
import json
import os
from pathlib import Path
import platform
import random
import statistics
import time
import tracemalloc

from erasure import FederatedClosureEvaluator, TemporalEvidenceFrontier, ValidationSnapshot
from evidence import BackendValidation, CustodianReceiptVerifier
from proof import EvidenceGradeEvaluator, NetworkPBFTCluster
from verclo.models import (ErasureCase, ObligationGraph, CasePhase, TopologyView,
    AssetDescriptor, RepositoryDescriptor, ReplicaDescriptor, LineageEdge)
from verclo import PolicyRegistry, ObligationGraphBuilder
from .network_study import _fixture, EVALUATION_TIME


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=lambda v: v.isoformat()).encode()


def digest(value): return hashlib.sha256(canonical(value)).hexdigest()


def closure_fixture(size):
    """Public metadata and explicit validation facts, never hidden ground truth."""
    r, o = _fixture()
    obligations = tuple(replace(o, obligation_id=f'O{i:06}', asset_id=f'A{i:06}', replica_id=f'R{i:06}') for i in range(size))
    records = tuple(ValidationSnapshot(replace(r, receipt_id=f'E{i:06}', obligation_id=row.obligation_id,
        asset_id=row.asset_id, replica_id=row.replica_id, expires_at=EVALUATION_TIME + timedelta(seconds=60)),
        row, BackendValidation('benchmark-snapshot', ordering_support_valid=True), 'snapshot-epoch')
        for i, row in enumerate(obligations))
    graph = ObligationGraph(o.case_id, o.dataset_id, o.correlation_id, 1, ('A000000',),
        tuple(row.asset_id for row in obligations), (), obligations, (), (o.custodian_principal_id,), 'a'*64, 'b'*64, True, ())
    case = ErasureCase(o.case_id, 'BENCH', o.dataset_id, o.correlation_id, 'REQUEST', 'REQUESTER', ('A000000',),
        o.policy_profile_id, EVALUATION_TIME, CasePhase.OBLIGATIONS_ACTIVE, 1, graph)
    return case, records


class _FullSnapshotBackend:
    def __init__(self, records): self.records = {r.receipt.receipt_id: r for r in records}
    def validate(self, receipt, obligation, evaluation_time):
        row = self.records[receipt.receipt_id]
        if row.receipt != receipt or row.obligation != obligation:
            raise ValueError('benchmark snapshot binding mismatch')
        return row.decision


class _ExactTimeMemo:
    """Conventional memoization baseline; full input equality includes time/facts."""
    def __init__(self, base, backend): self.base, self.backend, self.cache = base, backend, {}
    def evaluate(self, obligation, receipts, evaluation_time):
        key = (obligation, tuple(receipts), evaluation_time,
               tuple(self.backend.records[r.receipt_id].decision for r in receipts))
        old = self.cache.get(obligation.obligation_id)
        if old is not None and old[0] == key: return old[1]
        result = self.base.evaluate(obligation, receipts, evaluation_time)
        self.cache[obligation.obligation_id] = (key, result)
        return result


def closure_engine(algorithm, case, records, policies):
    if algorithm == 'temporal_frontier': return TemporalEvidenceFrontier(case, policies, 'snapshot-epoch', records)
    backend = _FullSnapshotBackend(records)
    grades = EvidenceGradeEvaluator(CustodianReceiptVerifier(backend))
    if algorithm == 'exact_time_memo': grades = _ExactTimeMemo(grades, backend)
    evaluator = FederatedClosureEvaluator(grades, policies, receipt_matching='scan' if algorithm == 'nested_scan' else 'indexed')
    class Full:
        def update(self, *, records=()): backend.records.update({r.receipt.receipt_id: r for r in records})
        def evaluate(self, instant): return evaluator.evaluate(case, (r.receipt for r in backend.records.values()), instant)
    return Full()


def closure_study(trials, rng):
    observations = []
    algorithms = ['nested_scan', 'indexed_full', 'exact_time_memo', 'temporal_frontier']
    policies = PolicyRegistry.load()
    for size in (32, 512, 2048):
        case, records = closure_fixture(size)
        for scenario in ('cold', 'unchanged_fixed_time', 'unchanged_clock_advance', 'sparse_update', 'dense_update', 'all_expire'):
            when = EVALUATION_TIME + timedelta(seconds=61 if scenario == 'all_expire' else 1 if scenario != 'unchanged_fixed_time' else 0)
            updates = ()
            if scenario in {'sparse_update', 'dense_update'}:
                count = max(1, size//100) if scenario == 'sparse_update' else size
                updates = tuple(replace(row, decision=replace(row.decision, authenticator_valid=False)) for row in records[:count])
            for trial in range(trials):
                order = rng.sample(algorithms, len(algorithms)); expected = None
                for position, algorithm in enumerate(order):
                    if scenario == 'cold':
                        started = time.perf_counter_ns()
                        engine = closure_engine(algorithm, case, records, policies)
                    else:
                        engine = closure_engine(algorithm, case, records, policies)
                        engine.evaluate(EVALUATION_TIME)
                        started = time.perf_counter_ns()
                    engine.update(records=updates)
                    report = engine.evaluate(when)
                    elapsed = time.perf_counter_ns() - started
                    if expected is None: expected = report
                    if report != expected: raise RuntimeError('differential closure failure')
                    observations.append(dict(family='closure', cell=f'n{size}:{scenario}', trial=trial, order=position,
                        algorithm=algorithm, latency_ns=elapsed, result_sha256=digest(asdict(report)),
                        work=getattr(engine, 'last_work', None)))
    memory = []
    case, records = closure_fixture(2048)
    for algorithm in algorithms:
        gc.collect()
        tracemalloc.start()
        engine = closure_engine(algorithm, case, records, policies); engine.evaluate(EVALUATION_TIME)
        current, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        memory.append(dict(algorithm=algorithm, obligations=2048, retained_python_bytes=current, peak_python_bytes=peak,
            scope='Single cold construction and evaluation; excludes prebuilt input and process RSS'))
        del engine
    return observations, memory


def topology_fixture(size, shape):
    ids = tuple(f'A{i:06}' for i in range(size))
    if shape == 'reverse_chain': pairs = [(ids[i], ids[i-1]) for i in range(size-1, 0, -1)]
    elif shape == 'star': pairs = [(ids[-1], node) for node in ids[:-1]]
    elif shape == 'forward_chain': pairs = list(zip(ids, ids[1:]))
    else: pairs = []
    root = ids[0] if shape == 'forward_chain' else ids[-1]
    view = TopologyView('GRAPH-BENCH', 'DATASET', 'CORRELATION', 1,
        tuple(AssetDescriptor(node, 'DATASET', 'interval_reading') for node in ids),
        (RepositoryDescriptor('REPO', 'ORG', 'CUSTODIAN', 'operational'),),
        tuple(ReplicaDescriptor('R'+node, node, 'REPO', 'primary') for node in ids),
        tuple(LineageEdge(f'L{i}', a, b, 'DERIVED_FROM') for i, (a, b) in enumerate(pairs)), None)
    return replace(view, scope_commitment=ObligationGraphBuilder.expected_scope_commitment(view)), (root,)


def graph_study(trials, rng):
    observations = []; policy = PolicyRegistry.load().get('VERCLO-POLICY-TECHNICAL-ERASURE')
    for size in (32, 512, 2048):
        for shape in ('forward_chain', 'reverse_chain', 'star', 'disconnected'):
            view, roots = topology_fixture(size, shape)
            for trial in range(trials):
                expected = None
                for position, algorithm in enumerate(rng.sample(['legacy', 'kahn_bfs', 'fused'], 3)):
                    started = time.perf_counter_ns()
                    report = ObligationGraphBuilder(traversal=algorithm).build(view=view, root_asset_ids=roots,
                        accepted_at=EVALUATION_TIME, policy=policy)
                    elapsed = time.perf_counter_ns() - started
                    if expected is None: expected = report
                    if report != expected: raise RuntimeError('differential graph failure')
                    observations.append(dict(family='graph', cell=f'n{size}:{shape}', trial=trial, order=position,
                        algorithm=algorithm, latency_ns=elapsed, result_sha256=digest(asdict(report))))
    return observations


def network_study(trials, rng):
    observations, records, contexts = [], [], {}
    receipt, obligation = _fixture()
    for size in (4, 7, 10):
        ids = tuple(f'V{i:02}' for i in range(size))
        for profile in ('loopback', 'uniform_10ms', 'slow_tail', 'commit_drop'):
            label = f'n{size}:{profile}'; clusters, backends = {}, {}
            try:
                for strategy in ('serial', 'parallel_all', 'certificate_frontier'):
                    # Fresh distinct epoch per strategy/run; sequence identities
                    # must not collide across independently recreated clusters.
                    # Equal-width epoch labels avoid strategy-name length
                    # contaminating request/response byte comparisons.
                    epoch = f'algorithm:{os.urandom(20).hex()}'
                    c = NetworkPBFTCluster(ids, BackendValidation('algorithm-validator', anchor_valid=True,
                        ordering_support_valid=True), membership_epoch=epoch)
                    c.__enter__(); clusters[strategy] = c
                    backend = c.backend(timeout=3, delivery_strategy=strategy); backends[strategy] = backend
                    original = backend.client._send
                    def send(node, path, payload, original=original, ids=ids, profile=profile):
                        delay = .010 if profile == 'uniform_10ms' else (.080 if node == ids[-1] else .005) if profile == 'slow_tail' else 0
                        if profile == 'commit_drop' and node == ids[0] and path == '/v2/commit':
                            time.sleep(.040); return None
                        if delay: time.sleep(delay)
                        return original(node, path, payload)
                    backend.client._send = send
                    contexts[epoch] = {k: base64.urlsafe_b64encode(v).rstrip(b'=').decode() for k,v in backend.client.public_keys.items()}
                # One warmup for every strategy; warmups retained as signed
                # records but excluded from measured comparison cells.
                for trial in range(-1, trials):
                    for position, strategy in enumerate(rng.sample(list(backends), len(backends))):
                        backend = backends[strategy]
                        r = replace(receipt, receipt_id=f'ALGORITHM:{label}:{trial}')
                        started = time.perf_counter_ns()
                        result = backend.validate(r, obligation, EVALUATION_TIME)
                        elapsed = time.perf_counter_ns() - started
                        cost = dict(backend.client.last_cost)
                        row = dict(operation_id=f'{label}:{strategy}:{trial}', accepted=result.verification_material_available,
                            latency_ns=elapsed, receipt=asdict(r), obligation=asdict(obligation), evaluation_time=EVALUATION_TIME.isoformat(),
                            validation=asdict(result), certificate=asdict(backend.client.last_certificate), cost=cost, error=None,
                            public_keys=contexts[backend.client.membership_epoch], expected_epoch=backend.client.membership_epoch)
                        records.append(row)
                        if not row['accepted']: raise RuntimeError(f'network progress failed: {row["operation_id"]}')
                        if trial >= 0:
                            observations.append(dict(family='network', cell=label, trial=trial, order=position,
                                algorithm=strategy, latency_ns=elapsed, messages_sent=cost['messages_sent'],
                                request_bytes=cost['request_bytes'], response_bytes=cost['response_bytes'], operation_id=row['operation_id']))
            finally:
                for c in clusters.values(): c.__exit__(None, None, None)
    return observations, records, contexts


def summarize(observations, seed):
    groups = {}
    for row in observations: groups.setdefault((row['family'], row['cell'], row['algorithm']), []).append(row)
    summary = []
    for (family, cell, algorithm), rows in sorted(groups.items()):
        row = dict(family=family, cell=cell, algorithm=algorithm, trials=len(rows),
            latency_median_ns=statistics.median(r['latency_ns'] for r in rows),
            latency_min_ns=min(r['latency_ns'] for r in rows), latency_max_ns=max(r['latency_ns'] for r in rows))
        for key in ('messages_sent', 'request_bytes', 'response_bytes'):
            if key in rows[0]: row[key+'_median'] = statistics.median(r[key] for r in rows)
        summary.append(row)
    comparisons = []
    rng = random.Random(seed+1)
    pairs = {'closure': [('nested_scan','indexed_full'),('indexed_full','temporal_frontier'),('exact_time_memo','temporal_frontier')],
             'graph': [('legacy','fused'),('kahn_bfs','fused')],
             'network': [('serial','certificate_frontier'),('parallel_all','certificate_frontier')]}
    for family, cell in sorted({(r['family'],r['cell']) for r in observations}):
        for baseline, candidate in pairs[family]:
            a = {r['trial']:r for r in groups[(family,cell,baseline)]}
            b = {r['trial']:r for r in groups[(family,cell,candidate)]}
            ratios = [a[i]['latency_ns']/b[i]['latency_ns'] for i in sorted(a)]
            boots = sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(2000))
            comparisons.append(dict(family=family,cell=cell,baseline=baseline,candidate=candidate,
                paired_median_speedup=statistics.median(ratios), bootstrap_95_percentile_ci=[boots[49],boots[1949]],
                interpretation='ratio > 1 favors candidate; local paired-trial bootstrap, no multiplicity correction'))
    return summary, comparisons


def run_study(output, trials=15, seed=24092026, include_network=True):
    if trials < 3: raise ValueError('at least three paired trials required')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    rng = random.Random(seed)
    print('Measuring closure algorithms...', flush=True)
    observations, memory = closure_study(trials, rng)
    print('Measuring lineage algorithms...', flush=True)
    observations += graph_study(trials, rng)
    records, contexts = [], {}
    if include_network:
        print('Measuring network delivery strategies...', flush=True)
        network_rows, records, contexts = network_study(trials, rng); observations += network_rows
    summary, comparisons = summarize(observations, seed)
    report = dict(format='verclo.algorithm-study.v1', status='PASS', created_at=started, seed=seed, trials=trials,
        scope='One local host; real loopback HTTP/TCP with explicitly synthetic per-RPC delay cells; no WAN execution',
        novelty='NOT_ESTABLISHED', global_superiority='NOT_ESTABLISHED',
        timing='perf_counter_ns; randomized algorithm order per cell/trial; update plus complete report construction included; input generation and JSON serialization excluded; warm state prepared outside timer except cold cells; no concurrent benchmark families',
        environment=dict(python=platform.python_version(), platform=platform.platform(), processor=platform.processor(), cpu_count=os.cpu_count()),
        observations=len(observations), memory=memory, summary=summary, comparisons=comparisons)
    source_root = Path(__file__).resolve().parents[2]
    report['source_sha256'] = {p.relative_to(source_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((source_root/'src').rglob('*.py'))}
    report['study_sha256'] = digest(report)
    (output/'report.json').write_bytes(json.dumps(report, indent=2).encode()+b'\n')
    (output/'observations.jsonl').write_bytes(b''.join(canonical(r)+b'\n' for r in observations))
    (output/'operation-records.jsonl').write_bytes(b''.join(canonical(r)+b'\n' for r in records))
    (output/'trusted-contexts.json').write_bytes(canonical(contexts)+b'\n')
    return report
