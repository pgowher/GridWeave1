"""The consumer dispatches existing inputs without constructing datasets."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'PaEForge/src'),str(ROOT/'HTGLThesis/src')]
from paeforge_pipeline import cli
import paeforge_pipeline.io

class DatasetSeparation(unittest.TestCase):
    def test_missing_dataset_does_not_start_generation_or_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            missing=Path(temp)/'absent';out=Path(temp)/'output'
            with patch.object(cli.subprocess,'run') as execute,contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['run','--dataset',str(missing),'--output',str(out)]),1)
                execute.assert_not_called()
            self.assertFalse(missing.exists());self.assertFalse(out.exists())

    def test_existing_dataset_dispatch_has_consumer_sources_only(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset=Path(temp)/'dataset';public=dataset/'public';public.mkdir(parents=True)
            from hashlib import sha256
            uid='a'*32
            names=[f'cases/{uid}/{n}.json' for n in ('case-manifest','observer-projection','receipt-stream')]
            names += [f'configuration/{uid}/policies/policy.json',f'configuration/{uid}/verification-context.json']
            files={}
            for name in names:
                path=public/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')
                files[name]=sha256(path.read_bytes()).hexdigest()
            (public/'index.json').write_text(json.dumps({'version':'GridWeave-0.2.0','cases':[{'unit_id':uid,'files':files}]}))
            output=Path(temp)/'output'
            with patch('paeforge_pipeline.io.source_identity',return_value={'source_revision':'consumer-revision'}),patch.object(cli.subprocess,'run') as execute:
                execute.return_value.returncode=0
                self.assertEqual(cli.main(['run','--dataset',str(dataset),'--output',str(output)]),0)
            command=execute.call_args.args[0];env=execute.call_args.kwargs['env']
            self.assertEqual(command[1:3],['-m','paeforge_pipeline.native_dataset_batch_worker'])
            self.assertIn(str(public),command)
            self.assertEqual(env['PYTHONPATH'].split(os.pathsep),[str(ROOT/'PaEForge/src'),str(ROOT/'HTGLThesis/src')])
            self.assertNotIn('generate',command)
            self.assertFalse(output.exists())

    def test_normal_cli_import_does_not_load_generator(self):
        self.assertFalse(any(n=='gridweave' or n.startswith(('gridweave.','htgl_dataset_generator')) for n in sys.modules))

if __name__=='__main__':unittest.main()
