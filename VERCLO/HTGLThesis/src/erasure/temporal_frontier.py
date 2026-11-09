"""Temporal evidence frontier: an experimental incremental closure algorithm.

Only explicitly supplied, immutable validation snapshots are reused. This is
not a cache for a live authority or consensus backend. Snapshot issuers must
supply revocations/changes and rotate the epoch when their trust context changes.
The application-specific composition is a research candidate, not established
worldwide novelty; its indexes, memoization and event heap have known prior art.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import heapq
import threading
from typing import Iterable

from evidence.models import BackendValidation, CustodianReceipt
from evidence.receipt_verifier import CustodianReceiptVerifier
from proof.decision_wire import decision_to_wire, decision_from_wire
from proof.evidence_grade_evaluator import EvidenceGradeEvaluator
from verclo.models import ErasureCase, Obligation
from .federated_closure_evaluator import FederatedClosureEvaluator
from .receipt_partition import ReceiptPartition


@dataclass(frozen=True)
class ValidationSnapshot:
    """Trusted validated facts bound to exact receipt, obligation and epoch.

    Constructing this object is an explicit trust-boundary operation. It does
    not cryptographically authenticate a user's unverified claims by itself.
    """
    receipt: CustodianReceipt
    obligation: Obligation
    decision: BackendValidation
    epoch: str

    def __post_init__(self):
        if type(self.epoch) is not str or not self.epoch:
            raise ValueError("a validation epoch is required")
        if self.receipt.obligation_id != self.obligation.obligation_id:
            raise ValueError("snapshot obligation binding mismatch")
        if any(type(value) is not tuple for value in (self.receipt.provenance_refs,
                self.obligation.permitted_dispositions, self.obligation.evidence_refs)):
            raise ValueError('snapshot sequence fields must be immutable tuples')
        # Defensive canonicalization rejects coercible truth values and removes
        # mutable diagnostics lists from this otherwise frozen record.
        object.__setattr__(self, 'decision', decision_from_wire(
            self.decision.backend_name, decision_to_wire(self.decision)))
        for instant in (self.receipt.not_before, self.receipt.expires_at,
                        self.receipt.event_time, self.receipt.submitted_at, self.obligation.deadline):
            if instant is not None and (not isinstance(instant, datetime) or instant.utcoffset() is None):
                raise ValueError("snapshot timestamps must be timezone-aware")


class _SnapshotBackend:
    name = 'temporal-frontier-snapshot-v1'

    def __init__(self, session): self.session = session

    def validate(self, receipt, obligation, evaluation_time):
        del evaluation_time
        record = self.session._records.get(receipt.receipt_id)
        if (record is None or record.epoch != self.session.epoch
            or record.receipt != receipt or record.obligation != obligation):
            return BackendValidation(self.name, verification_material_available=False,
                assumptions_valid=False, diagnostics=('SNAPSHOT_CONTEXT_MISMATCH',))
        return record.decision


class _FrontierGrades:
    def __init__(self, session):
        self.session = session
        self.base = EvidenceGradeEvaluator(CustodianReceiptVerifier(_SnapshotBackend(session)))

    def evaluate(self, obligation, receipts, evaluation_time):
        s = self.session
        oid = obligation.obligation_id
        if oid in s._cache and oid not in s._dirty:
            s.last_work['bundle_reuses'] += 1
            return s._cache[oid]
        result = self.base.evaluate(obligation, receipts, evaluation_time)
        s.last_work['bundle_evaluations'] += 1
        s.last_work['receipt_evaluations'] += len({r.receipt_id for r in receipts})
        s._cache[oid] = result
        s._dirty.discard(oid)
        generation = s._generations.get(oid, 0) + 1
        s._generations[oid] = generation
        # Only one next discontinuity per obligation is live in the frontier.
        # A new receipt may invalidate an already positive result or expose a
        # contradiction; no early positive exit suppresses evidence evaluation.
        times = []
        for receipt in receipts:
            record = s._records.get(receipt.receipt_id)
            for boundary in (receipt.not_before, receipt.event_time, receipt.submitted_at, receipt.expires_at,
                record.decision.mechanism_expires_at if record else None):
                if boundary is not None and boundary > evaluation_time:
                    times.append(boundary)
        if times:
            heapq.heappush(s._frontier, (min(times), oid, generation))
        return result


class TemporalEvidenceFrontier:
    """A serialized session over one case and explicit validation snapshots.

    Output is the complete existing FederatedClosureReport. Report materializing
    therefore remains O(number of obligations); only grading/validation work is
    incremental. Epoch rotation discards old evidence, never relabels it.
    """
    algorithm_id = 'temporal-evidence-frontier-v1'

    def __init__(self, case: ErasureCase, policies, epoch: str,
                 records: Iterable[ValidationSnapshot] = ()):
        if type(epoch) is not str or not epoch:
            raise ValueError('epoch required')
        self._validate_case(case)
        self._case, self._epoch, self.policies = case, epoch, policies
        self._records = {}
        self._groups = {}
        self._cache = {}
        self._dirty = set()
        self._generations = {}
        self._frontier = []
        self._last_time = None
        self._rejected = set()
        self._lock = threading.RLock()
        self.last_work = {}
        self._grades = _FrontierGrades(self)
        self._evaluator = FederatedClosureEvaluator(self._grades, policies)
        self.update(records=records)

    @property
    def case(self): return self._case

    @property
    def epoch(self): return self._epoch

    @staticmethod
    def _validate_case(case):
        if case.graph is None:
            return
        if case.graph.case_id != case.case_id:
            raise ValueError('graph is bound to another case')
        if type(case.graph.obligations) is not tuple:
            raise ValueError('case obligations must be an immutable tuple')
        seen = set()
        for row in case.graph.obligations:
            if not row.obligation_id or row.obligation_id in seen or row.case_id != case.case_id:
                raise ValueError('case requires unique case-bound obligation IDs')
            if any(type(v) is not tuple for v in (row.permitted_dispositions, row.evidence_refs)):
                raise ValueError('obligation sequence fields must be immutable tuples')
            seen.add(row.obligation_id)

    def _check_records(self, records, epoch):
        rows = tuple(records)
        seen = set()
        for row in rows:
            if not isinstance(row, ValidationSnapshot):
                raise TypeError('validated snapshots required')
            rid = row.receipt.receipt_id
            if rid in seen or not rid:
                raise ValueError('duplicate or empty receipt ID in update')
            if row.epoch != epoch or row.receipt.case_id != self.case.case_id or row.obligation.case_id != self.case.case_id:
                raise ValueError('snapshot case or epoch mismatch')
            seen.add(rid)
        return rows

    def update(self, *, records=(), remove_receipt_ids=()):
        with self._lock:
            rows = self._check_records(records, self.epoch)
            removals = tuple(remove_receipt_ids)
            if any(type(rid) is not str for rid in removals):
                raise ValueError('receipt IDs must be strings')
            # Validate all inputs before changing any session state.
            affected = set()
            for rid in set(removals) | {r.receipt.receipt_id for r in rows}:
                old = self._records.pop(rid, None)
                if old:
                    oid = old.receipt.obligation_id
                    self._groups[oid].pop(rid, None)
                    if not self._groups[oid]:
                        self._groups.pop(oid)
                    affected.add(oid)
            for row in rows:
                rid, oid = row.receipt.receipt_id, row.receipt.obligation_id
                self._records[rid] = row
                self._groups.setdefault(oid, {})[rid] = row.receipt
                affected.add(oid)
            self._dirty.update(affected)
            for oid in affected:
                self._generations[oid] = self._generations.get(oid, 0) + 1
            if len(self._frontier) > max(64, 4 * len(self._groups)):
                self._frontier = [item for item in self._frontier if self._generations.get(item[1]) == item[2]]
                heapq.heapify(self._frontier)

    def replace_case(self, case):
        with self._lock:
            if case.case_id != self.case.case_id:
                raise ValueError('a session cannot switch case identity')
            self._validate_case(case)
            self._case = case
            self._cache.clear(); self._frontier.clear(); self._generations.clear()
            self._dirty = set(self._groups)
            self._last_time = None
            # Old snapshots remain bound to their exact old obligation. Changed
            # obligations reject them until a newly validated record is supplied.

    def rotate_epoch(self, epoch, records=()):
        with self._lock:
            if type(epoch) is not str or not epoch or epoch == self.epoch:
                raise ValueError('a distinct new epoch is required')
            rows = self._check_records(records, epoch)
            self._epoch = epoch
            self._records.clear(); self._groups.clear(); self._cache.clear()
            self._frontier.clear(); self._generations.clear(); self._dirty.clear()
            self._last_time = None
            self.update(records=rows)

    def evaluate(self, evaluation_time, *, exception_validations=(),
                 open_challenge_ids=(), dispute_state=None):
        with self._lock:
            if not isinstance(evaluation_time, datetime) or evaluation_time.utcoffset() is None:
                raise ValueError('evaluation_time must be timezone-aware')
            if dispute_state is not None and dispute_state.case_id != self.case.case_id:
                raise ValueError('dispute state belongs to another case')
            self.last_work = {'bundle_evaluations': 0, 'bundle_reuses': 0,
                'receipt_evaluations': 0, 'frontier_events': 0}
            if self._last_time is not None and evaluation_time < self._last_time:
                self._cache.clear(); self._frontier.clear()
            rejected = set(dispute_state.rejected_evidence_refs) if dispute_state else set()
            for rid in rejected ^ self._rejected:
                if rid in self._records:
                    self._dirty.add(self._records[rid].receipt.obligation_id)
            self._rejected = rejected
            while self._frontier and self._frontier[0][0] <= evaluation_time:
                _, oid, generation = heapq.heappop(self._frontier)
                if self._generations.get(oid) == generation:
                    self._dirty.add(oid)
                    self.last_work['frontier_events'] += 1
            # Group tuples are materialized without a global re-partitioning
            # scan; a full report still necessarily visits every obligation.
            partition = ReceiptPartition({oid: group.values() for oid, group in self._groups.items()})
            report = self._evaluator.evaluate(self.case, partition, evaluation_time,
                exception_validations=exception_validations,
                open_challenge_ids=open_challenge_ids, dispute_state=dispute_state)
            self._last_time = evaluation_time
            return report
