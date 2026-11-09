"""The saved-label evaluator must reject changed or incomplete predictions."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'PaEForge/src'),str(ROOT/'HTGLThesis/src')]
from paeforge_pipeline.dataset_evaluator import evaluate_saved_run
from test_standalone import REFERENCE, copy_cases


class SavedLabelEvaluation(unittest.TestCase):
    def test_pair_comparison_and_prediction_freezing(self):
        source=REFERENCE
        pair=next(p for p in json.loads((source/'sealed/pairs.json').read_text()) if p['operation']=='permutation')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);dataset=root/'dataset';public=dataset/'public'
            copy_cases(public,set(pair['unit_ids']))
            (dataset/'sealed/cases').mkdir(parents=True)
            for uid in pair['unit_ids']:
                shutil.copy2(source/'sealed/cases'/(uid+'.json'),dataset/'sealed/cases'/(uid+'.json'))
            (dataset/'sealed/pairs.json').write_text(json.dumps([pair]))
            files={str(p.relative_to(dataset)):sha256(p.read_bytes()).hexdigest()
                   for p in dataset.rglob('*') if p.is_file()}
            (dataset/'dataset-manifest.json').write_text(json.dumps({'files':files}))
            run=root/'predictions'
            completed=subprocess.run([sys.executable,ROOT/'run.py','run','--dataset',dataset,'--output',run],
                                     capture_output=True,text=True,timeout=60)
            self.assertEqual(completed.returncode,0,completed.stderr)
            summary=evaluate_saved_run(dataset,run,root/'evaluation')
            self.assertEqual(summary['status'],'PASS')
            self.assertEqual(summary['closure_matches'],2)
            self.assertEqual(summary['metamorphic_pairs_checked'],1)
            self.assertTrue((root/'evaluation/receipts.csv').is_file())
            path=run/(pair['unit_ids'][0]+'.json')
            path.write_bytes(path.read_bytes()+b' ')
            shutil.rmtree(dataset/'sealed/cases')
            with self.assertRaisesRegex(ValueError,'modified after freezing'):
                evaluate_saved_run(dataset,run,root/'rejected')
            self.assertFalse((root/'rejected').exists())


if __name__=='__main__':unittest.main()
