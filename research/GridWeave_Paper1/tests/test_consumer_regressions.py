"""Real native-consumer regressions discovered by the independent fixtures."""
import sys,tempfile,subprocess,shutil,unittest
from pathlib import Path
LAB=Path(__file__).resolve().parents[1];PROJECT=LAB.parents[1];sys.path.insert(0,str(LAB))
from paper1.fixture_builder import generate
from paper1.wire import read,write,file_hash

class ConsumerBoundaryRegression(unittest.TestCase):
    def test_invalid_exception_assertions_do_not_abort_a_batch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);fixture=root/'all';generate(fixture,LAB/'fixtures/semantic_cases_v1.json')
            selected=[]
            for p in (fixture/'sealed/cases').glob('*.json'):
                if read(p)['operation'] in ('exception_unknown_authority','exception_effective_after_deadline'):selected.append(p.stem)
            public=root/'subset/public';entries=[e for e in read(fixture/'public/index.json')['cases'] if e['unit_id'] in selected]
            for entry in entries:
                for rel in entry['files']:
                    p=public/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(fixture/'public'/rel,p)
                label=root/'subset/sealed/cases'/(entry['unit_id']+'.json');label.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(fixture/'sealed/cases'/label.name,label)
            write(public/'index.json',dict(version='GridWeave-0.2.0',cases=entries));write(root/'subset/sealed/pairs.json',[])
            write(root/'subset/dataset-manifest.json',dict(evaluation_unit='case',label_provenance='Explicit fixture expectations',files={str(p.relative_to(root/'subset')):file_hash(p) for p in (root/'subset').rglob('*') if p.is_file()}))
            command=[PROJECT/'VERCLO/verclo','run','--dataset',public,'--output',root/'predictions']
            result=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr)
            for uid in selected:
                self.assertEqual(read(root/'predictions'/(uid+'.json'))['closure_class'],'PARTIALLY_CLOSED')
                self.assertEqual(len(read(root/'predictions/diagnostics'/(uid+'.json'))['exception_admission_failures']),1)
            command=[PROJECT/'VERCLO/verclo','evaluate','--dataset',root/'subset','--run',root/'predictions','--output',root/'evaluation']
            result=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr)
            summary=read(root/'evaluation/evaluation.json');self.assertEqual(summary['status'],'PASS');self.assertEqual(summary['synthetic_source_families_N'],1);self.assertIn('1 source families',summary['statistical_scope']);self.assertEqual(summary['oracle_scope'],'Explicit fixture expectations')

if __name__=='__main__':unittest.main()
