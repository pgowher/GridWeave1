"""Exercise saved-data failures and a relocated consumer with no generator tree."""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'PaEForge/src'), str(ROOT / 'HTGLThesis/src')]
from paeforge_pipeline.native_dataset import load_public_dataset
from thesis import REFERENCE


def copy_cases(destination, unit_ids):
    source = REFERENCE / 'public'
    index = json.loads((source / 'index.json').read_text())
    entries = [entry for entry in index['cases'] if entry['unit_id'] in unit_ids]
    if len(entries) != len(unit_ids):
        raise AssertionError('Reference fixture is missing')
    for entry in entries:
        for rel in entry['files']:
            path = destination / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / rel, path)
    index['cases'] = entries
    (destination / 'index.json').write_text(json.dumps(index))


class StandaloneConsumer(unittest.TestCase):
    def test_tampered_or_incompletely_bound_inputs_are_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            public = root / 'data/public'
            copy_cases(public, {'007f666b6b5609a3bbdcb0a975ddb7e5'})
            policy = next(public.glob('configuration/*/policies/policy.json'))
            policy.write_text('{}')
            result = subprocess.run([sys.executable, ROOT / 'run.py', 'run',
                                     '--dataset', root / 'data', '--output', root / 'results'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('integrity mismatch', result.stderr)
            self.assertFalse((root / 'results').exists())
            index = json.loads((public / 'index.json').read_text())
            del index['cases'][0]['files'][str(policy.relative_to(public))]
            (public / 'index.json').write_text(json.dumps(index))
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                load_public_dataset(public)

    def test_relocated_runtime_handles_valid_and_invalid_scope_without_generator(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'copied-verifier'
            root.mkdir()
            shutil.copy2(ROOT / 'run.py', root / 'run.py')
            for project in ('HTGLThesis', 'PaEForge'):
                shutil.copytree(ROOT / project / 'src', root / project / 'src',
                                ignore=shutil.ignore_patterns('__pycache__', '*.egg-info'))
                shutil.copy2(ROOT / project / 'pyproject.toml', root / project / 'pyproject.toml')
            shutil.copytree(ROOT / 'PaEForge/schemas', root / 'PaEForge/schemas')
            copy_cases(root / 'datasets/supplied/public', {
                '007f666b6b5609a3bbdcb0a975ddb7e5', '04f620dd7b700ca27aa38cf94a0cca79'})
            public = root / 'datasets/supplied/public'
            before = {str(p.relative_to(public)): sha256(p.read_bytes()).hexdigest()
                      for p in public.rglob('*') if p.is_file()}
            env = dict(os.environ, PYTHONPATH='', PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([sys.executable, root / 'run.py', '--dataset', 'datasets/supplied',
                                     '--output', 'runs/first'], cwd=temp, env=env,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((root / 'runs/first/results-manifest.json').read_text())
            self.assertEqual(manifest['executed_case_evaluations_q'], 2)
            self.assertEqual(manifest['generator_or_oracle_modules_loaded'], [])
            invalid = json.loads((root / 'runs/first/04f620dd7b700ca27aa38cf94a0cca79.json').read_text())
            self.assertEqual(invalid['closure_class'], 'UNVERIFIABLE')
            after = {str(p.relative_to(public)): sha256(p.read_bytes()).hexdigest()
                     for p in public.rglob('*') if p.is_file()}
            self.assertEqual(before, after)
            self.assertFalse((root / 'GridWeave').exists())


if __name__ == '__main__':
    unittest.main()
