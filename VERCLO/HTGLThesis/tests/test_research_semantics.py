"""Counterexamples at the closure and evidence-capability boundaries."""
from dataclasses import replace
from datetime import timedelta
import unittest

from test_verclo_evidence_closure import make_case, receipt, ACCEPTED, DEADLINE, EVALUATION
from erasure import FederatedClosureEvaluator, TemporalEvidenceFrontier, ValidationSnapshot
from evidence import BackendValidation, CustodianReceiptVerifier, ExceptionValidation
from proof import DeterministicValidationBackend, EvidenceGradeEvaluator
from verclo import PolicyRegistry


class ResearchSemantics(unittest.TestCase):
    def services(self, facts=None, policies=None):
        verifier = CustodianReceiptVerifier(DeterministicValidationBackend(facts, allow_unlisted_for_tests=True))
        grader = EvidenceGradeEvaluator(verifier)
        return verifier, grader, FederatedClosureEvaluator(grader, policies or PolicyRegistry.load())

    def test_unattested_empty_graph_cannot_close_even_if_its_flag_says_verifiable(self):
        case = make_case('EMPTY', count=0)
        _, _, closure = self.services()
        self.assertEqual('UNVERIFIABLE', closure.evaluate(case, (), EVALUATION).closure_class)
        self.assertEqual('IN_PROGRESS', closure.evaluate(case, (), ACCEPTED).closure_class)

    def test_readiness_precedes_invalid_baseline_and_open_challenge(self):
        _, _, closure = self.services()
        for valid in (True, False):
            case = make_case('TIMING', baseline=valid, count=1)
            result = closure.evaluate(case, (), ACCEPTED, open_challenge_ids=('CH-1',))
            self.assertEqual('IN_PROGRESS', result.closure_class)

    def test_exception_is_effective_only_during_its_half_open_interval(self):
        case = make_case('EXCEPTION', count=1, exception=True)
        exception = replace(case.graph.exceptions[0], expires_at=EVALUATION,
                            effective_at=DEADLINE)
        case = replace(case, graph=replace(case.graph, exceptions=(exception,)))
        _, _, closure = self.services()
        checks = (ExceptionValidation('EX-2', True, True),)
        self.assertEqual('CLOSED_WITH_EXCEPTIONS', closure.evaluate(
            case, (), EVALUATION-timedelta(microseconds=1), exception_validations=checks).closure_class)
        self.assertEqual('OPEN', closure.evaluate(case, (), EVALUATION, exception_validations=checks).closure_class)
        self.assertFalse(closure._valid_exception(exception, checks[0], case.graph.obligations[0],
                                                ACCEPTED, {exception.authority_principal_id}))

    def test_future_event_and_future_submission_are_not_available_evidence(self):
        case = make_case('FUTURE', count=1)
        obligation = case.graph.obligations[0]
        verifier, _, _ = self.services()
        for row in (receipt(obligation, 'F', event_time=EVALUATION+timedelta(seconds=1)),
                    replace(receipt(obligation, 'F'), submitted_at=EVALUATION+timedelta(seconds=1))):
            self.assertEqual('RECEIPT_NOT_YET_VALID', verifier.verify(row, obligation, EVALUATION).rejection_reason)

    def test_frontier_reconsiders_a_receipt_when_its_submission_becomes_available(self):
        case = make_case('CACHE', count=1)
        o = case.graph.obligations[0]
        r = replace(receipt(o, 'R'), submitted_at=EVALUATION+timedelta(seconds=1))
        session = TemporalEvidenceFrontier(case, PolicyRegistry.load(), 'epoch',
                                          (ValidationSnapshot(r, o, BackendValidation('snapshot'), 'epoch'),))
        self.assertEqual('OPEN', session.evaluate(EVALUATION).closure_class)
        self.assertEqual('CLOSED', session.evaluate(EVALUATION+timedelta(seconds=1)).closure_class)

    def test_e5_requires_distinct_witnesses_roles_trust_and_fault_domains(self):
        case = make_case('E5', count=1)
        o = case.graph.obligations[0]
        primary = receipt(o, 'M', evidence_type='deletion_acknowledgement')
        a = receipt(o, 'A', evidence_type='audit_finding', issuer='A', role='AUDITOR',
                    trust_domain='TA', fault_domain='FA')
        b = receipt(o, 'B', evidence_type='audit_finding', issuer='B', role='VALIDATOR',
                    trust_domain='TB', fault_domain='FB')
        _, grader, _ = self.services({'M': BackendValidation('fixture', ordering_support_valid=True,
            mechanism_present=True, mechanism_valid=True)})
        def grade(x):
            return grader.evaluate(o, (primary, a, x), EVALUATION,
                                   primary_receipt_id='M', required_grade='E5')
        self.assertEqual('E5', grade(b).grade)
        for x in (replace(b, fault_domain='FA'), replace(b, trust_domain='TA'),
                  replace(b, issuer_principal_id='A'), replace(b, issuer_role='CUSTODIAN'),
                  replace(b, event_time=ACCEPTED+timedelta(seconds=1), submitted_at=ACCEPTED+timedelta(seconds=1))):
            with self.subTest(receipt=x):
                self.assertFalse(grade(x).closure_admissible)
                self.assertNotEqual('E5', grade(x).grade)

    def test_late_higher_grade_does_not_hide_timely_sufficient_evidence(self):
        case = make_case('SELECT', count=1)
        o = case.graph.obligations[0]
        timely = receipt(o, 'ON-TIME')
        late = receipt(o, 'LATE', event_time=DEADLINE+timedelta(seconds=1))
        _, grader, _ = self.services({'LATE': BackendValidation('fixture', ordering_support_valid=True)})
        result = grader.evaluate(o, (timely, late), EVALUATION)
        self.assertTrue(result.closure_admissible)
        self.assertEqual('ON-TIME', result.primary_receipt_id)

    def test_early_policy_requires_terminal_reports_including_authenticated_failure(self):
        case = make_case('EARLY', count=1)
        policies = PolicyRegistry.load()
        profile = replace(policies.get(case.policy_profile_id), early_closure_allowed=True)
        _, _, closure = self.services(policies=PolicyRegistry({profile.profile_id: profile}))
        row = receipt(case.graph.obligations[0], 'FAIL', disposition='FAILED')
        self.assertEqual('OPEN', closure.evaluate(case, (row,), ACCEPTED).closure_class)
        self.assertEqual('IN_PROGRESS', closure.evaluate(case, (), ACCEPTED).closure_class)

    def test_conflicting_duplicate_receipt_ids_are_rejected_in_both_orders(self):
        case = make_case('DUPLICATE', count=1)
        o = case.graph.obligations[0]
        row = receipt(o, 'R')
        _, grader, _ = self.services()
        for rows in ((row, replace(row, disposition='FAILED')), (replace(row, disposition='FAILED'), row)):
            with self.assertRaisesRegex(ValueError, 'conflicting content'):
                grader.evaluate(o, rows, EVALUATION)

    def test_ordering_support_must_bind_the_primary_id_and_claim_commitment(self):
        case = make_case('ORDERING', count=1)
        o = case.graph.obligations[0]
        primary = replace(receipt(o, 'PRIMARY'), claim_commitment='a'*64)
        anchor = receipt(o, 'LOG', evidence_type='inclusion_proof', issuer='LOG')
        _, grader, _ = self.services({'LOG': BackendValidation('fixture', anchor_valid=True)})
        def grade(support):
            return grader.evaluate(o, (primary, support), EVALUATION,
                                   primary_receipt_id='PRIMARY', required_grade='E3')
        self.assertFalse(grade(anchor).closure_admissible)
        linked = replace(anchor, provenance_refs=('receipt:PRIMARY','claim:'+'a'*64))
        self.assertTrue(grade(linked).closure_admissible)
        self.assertFalse(grade(replace(linked, provenance_refs=('receipt:PRIMARY','claim:'+'b'*64))).closure_admissible)


if __name__ == '__main__':
    unittest.main()
