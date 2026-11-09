"""Research-property and real VERCLO boundary checks for GridWeave v0.2."""
from copy import deepcopy
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from gridweave.coverage import Candidate,StateLimitExceeded,select
from gridweave.dataset import generate,validate,run
from gridweave.generation import candidates,base_case,make_pair
from gridweave.oracle import evaluate,encode
from htgl_dataset_generator.paegen import load_smart_grid_scenarios

SCENARIO='PBE-SG-SUPPLIER-SWITCHING'


class CoverageResearchProperties(unittest.TestCase):
    def test_exact_matches_bruteforce_on_twenty_small_problems(self):
        rng=random.Random(573)
        for _ in range(20):
            options=[Candidate(str(i),frozenset(t for t in 'abcde' if rng.random()<.55),rng.randint(1,25)) for i in range(7)]
            goals=frozenset().union(*(c.tags for c in options))
            expected=min(sum(c.cost for c in subset) for size in range(8) for subset in combinations(options,size)
                         if goals<=frozenset().union(*(c.tags for c in subset)))
            result=select(options,strategy='exact')
            self.assertEqual(expected,result['cost_bytes']);self.assertTrue(result['optimal_for_declared_problem'])

    def test_greedy_is_not_mislabeled_exact(self):
        options=[Candidate('a',frozenset('ab'),3),Candidate('b',frozenset('bc'),3),Candidate('c',frozenset('ac'),3)]
        with self.assertRaises(StateLimitExceeded):select(options,strategy='exact',max_states=1)
        r=select(options,strategy='auto',max_states=1)
        self.assertFalse(r['optimal_for_declared_problem']);self.assertTrue(r['state_limit_fallback'])

    def test_optimizer_does_not_depend_on_input_order(self):
        options=[Candidate('a',frozenset('ab'),3),Candidate('b',frozenset('bc'),4),Candidate('c',frozenset('ac'),5)]
        self.assertEqual(select(options),select(list(reversed(options))))

    def test_unreachable_goal_and_duplicate_id_are_rejected(self):
        c=Candidate('a',frozenset('a'),1)
        with self.assertRaises(ValueError):select([c],{'z'})
        with self.assertRaises(ValueError):select([c,c])


class BoundarySynthesisProperties(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.definition=next(d for d in load_smart_grid_scenarios() if d.scenario_id==SCENARIO)
        cls.base,cls.policy,cls.context=base_case(cls.definition,1,'test-seed','source-test')

    def pair(self,operation):return make_pair(self.base,self.policy,'test-seed',operation,'family-test',1)

    def test_manual_reference_and_negative_outcomes(self):
        expected={'omit_one':'PARTIALLY_CLOSED','omit_all':'OPEN','conflict':'DISPUTED',
                  'signature_tamper':'PARTIALLY_CLOSED','scope_gap':'UNVERIFIABLE',
                  'lineage_gap':'UNVERIFIABLE','pre_deadline':'IN_PROGRESS','permutation':'CLOSED'}
        for op,outcome in expected.items():
            with self.subTest(operation=op):self.assertEqual(outcome,self.pair(op)['units'][1]['truth']['outcome'])

    def test_hidden_worlds_have_byte_identical_observations(self):
        a,b=self.pair('hidden_copy_twin')['units']
        self.assertEqual(encode(a['bundle']),encode(b['bundle']))
        self.assertEqual(a['truth'],b['truth']);self.assertNotEqual(a['world_truth'],b['world_truth'])

    def test_exception_expiry_uses_half_open_interval(self):
        a,b=self.pair('exact_expiry')['units']
        self.assertEqual(a['truth']['outcome'],'CLOSED_WITH_EXCEPTIONS')
        self.assertEqual(b['truth']['outcome'],'PARTIALLY_CLOSED')

    def test_receipt_key_is_not_its_own_trust_anchor(self):
        from paeforge_pipeline.gridweave_backend import validation_facts
        observer=deepcopy(self.base[1]);stream=deepcopy(self.base[2]);context=deepcopy(self.context)
        row=stream['receipts'][0]
        context['principal_public_keys'][row['issuer_principal_id']]='00'*32
        checks,_=validation_facts(observer,stream,context)
        self.assertFalse(checks[row['receipt_id']].authenticator_valid)
        self.assertFalse(checks[row['receipt_id']].credential_valid_at_event)

    def test_signature_tamper_is_rejected_by_real_worker_backend(self):
        from paeforge_pipeline.gridweave_backend import validation_facts
        a,b=self.pair('signature_tamper')['units']
        valid,_=validation_facts(a['bundle'][1],a['bundle'][2],a['context'])
        invalid,_=validation_facts(b['bundle'][1],b['bundle'][2],b['context'])
        self.assertTrue(all(x.authenticator_valid for x in valid.values()))
        self.assertEqual(sum(not x.authenticator_valid for x in invalid.values()),1)
        self.assertTrue(all(not x.ordering_support_valid and not x.mechanism_valid for x in valid.values()))

    def test_exception_cannot_be_extended_without_a_new_signature(self):
        from paeforge_pipeline.gridweave_backend import validation_facts
        unit=self.pair('expiry_crossing')['units'][0]
        observer=deepcopy(unit['bundle'][1]);observer['exceptions'][-1]['expires_at']='2099-01-01T00:00:00Z'
        _,checks=validation_facts(observer,unit['bundle'][2],unit['context'])
        self.assertFalse(checks[observer['exceptions'][-1]['exception_id']].authenticated)

    def test_all_scales_and_mutations_of_family_share_split(self):
        family_splits={};groups=set()
        for pair in candidates('first-seed',(1,2),'source-test'):
            family_splits.setdefault(pair['family'],set()).add(pair['split']);groups.add(pair['split'])
        self.assertEqual(groups,{'train','validation','test'})
        self.assertTrue(all(len(x)==1 for x in family_splits.values()))
        other={p['family']:p['split'] for p in candidates('second-seed',(1,),'source-test')}
        self.assertEqual({f:next(iter(s)) for f,s in family_splits.items()},other)


class ExportAndPipelineResearchProperties(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.root=Path(cls.temporary.name)
        cls.data=cls.root/'dataset'
        cls.ready=generate(cls.data,seed='integration-seed',scales=(1,),strategy='all',scenario_ids=[SCENARIO])
        cls.native_output=cls.root/'native-execution'
        cls.native_report=run(cls.data,cls.native_output)
        cls.obligation_template=next(row for path in sorted((cls.native_output/'results').glob('*.json'))
                                     for row in json.loads(path.read_text()).get('obligation_results',[]))

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def test_all_seven_model_classes_and_pair_cost_are_materialized(self):
        self.assertEqual(set(self.ready['class_support']),{'CLOSED','CLOSED_WITH_EXCEPTIONS','PARTIALLY_CLOSED',
                        'OPEN','DISPUTED','UNVERIFIABLE','IN_PROGRESS'})
        self.assertEqual(self.ready['materialized_cases'],self.ready['pairs']*2)
        self.assertEqual(self.ready['q_status'],'NOT_EXECUTED')

    def test_same_seed_reproduces_exact_manifest(self):
        other=self.root/'reproduction'
        result=generate(other,seed='integration-seed',scales=(1,),strategy='all',scenario_ids=[SCENARIO])
        self.assertEqual(self.ready['manifest_sha256'],result['manifest_sha256'])

    def test_existing_output_and_incorrect_trust_pin_fail(self):
        with self.assertRaises(FileExistsError):generate(self.data)
        with self.assertRaises(ValueError):validate(self.data,expected_sha256='0'*64)

    def test_public_projection_rejects_a_label_canary(self):
        from paeforge_contract import validate_verifier_bundle
        from paeforge_contract.leakage import LeakageError
        entry=json.loads((self.data/'public/index.json').read_text())['cases'][0]
        folder=self.data/'public/cases'/entry['unit_id']
        bundle=[json.loads((folder/name).read_text()) for name in ('case-manifest.json','observer-projection.json','receipt-stream.json')]
        bundle[1]['expected_outcome']='CLOSED'
        with self.assertRaises(LeakageError):validate_verifier_bundle(*bundle)
        self.assertNotIn(b'integration-seed',b''.join(p.read_bytes() for p in (self.data/'public').rglob('*.json')))

    def test_real_public_only_worker_consumes_every_case(self):
        result=self.native_report
        self.assertEqual(result['executed_case_evaluations_q'],self.ready['materialized_cases'])
        self.assertEqual(result['generator_or_oracle_modules_loaded_in_worker'],[])
        self.assertEqual(result['mismatches'],[])

    def score_replay(self,name,change,*,baseline_verifiable=True):
        """Change a real native result before freezing a controlled prediction set."""
        from paeforge_contract.canonical import sha256_digest
        output=self.root/name
        index=json.loads((self.data/'public/index.json').read_text())
        uid=next(entry['unit_id'] for entry in index['cases']
                 if json.loads((self.data/'sealed/cases'/(entry['unit_id']+'.json')).read_text())
                 ['truth']['baseline_verifiable']==baseline_verifiable)

        def replay(command,**kwargs):
            shutil.copytree(self.native_output/'results',output/'results')
            result_path=output/'results'/(uid+'.json')
            result=json.loads(result_path.read_text());change(result)
            result_path.write_bytes(encode(result))
            manifest_path=output/'results/results-manifest.json'
            manifest=json.loads(manifest_path.read_text())
            row=next(row for row in manifest['results'] if row['unit_id']==uid)
            row['result_sha256']=sha256_digest(result)
            row['result_file_sha256']=sha256(result_path.read_bytes()).hexdigest()
            manifest_path.write_bytes(encode(manifest))
            return subprocess.CompletedProcess(command,0,stdout='Controlled native-result replay.\n',stderr='')

        with patch('gridweave.dataset.subprocess.run',side_effect=replay):
            return run(self.data,output)

    def test_scorer_accepts_unchanged_native_result_replay(self):
        report=self.score_replay('score-unchanged',lambda result:None)
        self.assertEqual(report['status'],'PIPELINE_EXECUTION_PASSED')
        self.assertEqual(report['mismatch_count'],0)

    def test_scorer_reports_unexpected_obligation(self):
        def add(result):
            row=deepcopy(result['obligation_results'][0])
            row['obligation_id']='OBL-UNEXPECTED-REGRESSION'
            result['obligation_results'].append(row)
            result['obligation_sets'][row['category'].lower()].append(row['obligation_id'])
        report=self.score_replay('score-extra',add)
        self.assertEqual(report['closure_mismatch_count'],0)
        self.assertEqual(report['diagnostic_mismatch_count'],1)
        self.assertEqual(report['mismatch_count'],1)
        difference=report['mismatches'][0]['obligation_category_differences']['OBL-UNEXPECTED-REGRESSION']
        self.assertIsNone(difference['expected'])
        self.assertIsNotNone(difference['actual'])

    def test_scorer_reports_missing_obligation(self):
        removed=[]
        def remove(result):
            row=result['obligation_results'].pop(0);removed.append(row['obligation_id'])
            result['obligation_sets'][row['category'].lower()].remove(row['obligation_id'])
        report=self.score_replay('score-missing',remove)
        self.assertEqual(report['mismatch_count'],1)
        difference=report['mismatches'][0]['obligation_category_differences'][removed[0]]
        self.assertIsNotNone(difference['expected'])
        self.assertIsNone(difference['actual'])

    def test_scorer_reports_category_difference_with_matching_closure(self):
        def change(result):
            row=result['obligation_results'][0]
            result['obligation_sets'][row['category'].lower()].remove(row['obligation_id'])
            row['category']='MISSING' if row['category']!='MISSING' else 'INVALID'
            result['obligation_sets'][row['category'].lower()].append(row['obligation_id'])
        report=self.score_replay('score-category',change)
        self.assertEqual(report['closure_mismatch_count'],0)
        self.assertEqual(report['diagnostic_mismatch_count'],1)
        self.assertEqual(report['mismatch_count'],1)

    def test_scorer_rejects_duplicate_obligations_even_with_unverifiable_baseline(self):
        def duplicate(result):
            if not result['obligation_results']:
                row=deepcopy(self.obligation_template)
                result['obligation_results'].append(row)
                result['obligation_sets'][row['category'].lower()].append(row['obligation_id'])
            row=deepcopy(result['obligation_results'][0])
            row['category']='INVALID' if row['category']!='INVALID' else 'MISSING'
            result['obligation_results'].insert(0,row)
        for baseline in (True,False):
            with self.subTest(baseline_verifiable=baseline):
                with self.assertRaisesRegex(ValueError,'duplicate predicted obligation ID'):
                    self.score_replay('score-duplicate-'+str(baseline),duplicate,baseline_verifiable=baseline)

    def test_scorer_does_not_score_undefined_categories(self):
        def add(result):
            row=deepcopy(self.obligation_template);row['obligation_id']='OBL-UNDEFINED-BASELINE'
            result['obligation_results'].append(row)
            result['obligation_sets'][row['category'].lower()].append(row['obligation_id'])
        report=self.score_replay('score-undefined',add,baseline_verifiable=False)
        self.assertEqual(report['diagnostic_mismatch_count'],0)
        self.assertEqual(report['mismatch_count'],0)


if __name__=='__main__':unittest.main()
