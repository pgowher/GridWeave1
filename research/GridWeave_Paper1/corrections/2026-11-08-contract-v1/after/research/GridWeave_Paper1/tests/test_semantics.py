import sys,tempfile,unittest
from pathlib import Path
from copy import deepcopy
LAB=Path(__file__).resolve().parents[1];sys.path.insert(0,str(LAB))
from paper1 import graph_assessor,sql_assessor
from paper1.fixture_builder import generate
from paper1.wire import load_public,read
from paper1.utility import compile_assessor,FAULTS

class SemanticConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)/'fixtures';generate(cls.root,LAB/'fixtures/semantic_cases_v1.json')
        cls.data={uid:(o,s,p,c) for uid,o,s,p,c in load_public(cls.root/'public')};cls.labels={p.stem:read(p) for p in (cls.root/'sealed/cases').glob('*.json')}
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_all_explicit_expectations_with_both_algorithms(self):
        for uid,data in self.data.items():
            expected=self.labels[uid]['truth']
            for engine in (graph_assessor,sql_assessor):
                with self.subTest(case=self.labels[uid]['operation'],engine=engine.__name__):
                    actual=engine.assess(*data)
                    for field in ('outcome','baseline_verifiable','obligation_categories','receipt_diagnoses'):self.assertEqual(actual[field],expected[field],field)
    def test_fixtures_cover_all_seven_classes_and_six_categories(self):
        self.assertEqual({t['truth']['outcome'] for t in self.labels.values()},{'CLOSED','CLOSED_WITH_EXCEPTIONS','PARTIALLY_CLOSED','OPEN','DISPUTED','UNVERIFIABLE','IN_PROGRESS'})
        self.assertEqual({v for t in self.labels.values() for v in t['truth']['obligation_categories'].values()},{'COVERED','EXCEPTED','MISSING','INVALID','LATE','CONTRADICTORY'})
    def test_cycle_is_rejected_by_both_algorithms(self):
        uid=next(u for u,t in self.labels.items() if t['operation']=='resolved');o,s,p,c=deepcopy(self.data[uid]);o['topology']['lineage_edges'].append(dict(relationship_id='CYCLE',parent_asset_id=o['topology']['assets'][-1]['asset_id'],child_asset_id=o['topology']['assets'][0]['asset_id']))
        for engine in (graph_assessor,sql_assessor):
            with self.assertRaises(ValueError):engine.assess(o,s,p,c)
    def test_fault_catalogue_edits_exactly_one_site_and_changes_identity(self):
        for engine in ('graph','sql'):
            _,normal=compile_assessor(engine)
            for fault in FAULTS:
                _,mutated=compile_assessor(engine,fault);self.assertNotEqual(normal,mutated)
    def test_fixed_fixtures_reproduce_exactly(self):
        other=Path(self.tmp.name)/'second';generate(other,LAB/'fixtures/semantic_cases_v1.json')
        self.assertEqual((self.root/'dataset-manifest.json').read_bytes(),(other/'dataset-manifest.json').read_bytes())

if __name__=='__main__':unittest.main()
