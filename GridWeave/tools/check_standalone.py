"""Generation-only research checks using exclusively this folder's runtime."""
from pathlib import Path
import contextlib
import hashlib
import importlib.metadata
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
SOURCES=(ROOT/'src',ROOT/'support/HTGLThesis/src',ROOT/'support/PaEForge/src')
for p in reversed((ROOT,*SOURCES)):sys.path.insert(0,str(p))
sys.dont_write_bytecode=True
os.environ['PYTHONDONTWRITEBYTECODE']='1'
os.environ['PYTHONPATH']=os.pathsep.join(map(str,SOURCES))
blocked=[]
def guard(frame,event,arg):
    if event!='call' or frame.f_code.co_name not in {'run','evaluate','evaluate_bundle','main'}:return
    filename=frame.f_code.co_filename.replace('\\','/');name=frame.f_code.co_name
    if ((filename.endswith('/gridweave/dataset.py') and name=='run') or
        filename.endswith('/paeforge_pipeline/verclo_worker.py') and name=='evaluate_bundle' or
        filename.endswith('/paeforge_pipeline/gridweave_batch_worker.py') and name=='main' or
        filename.endswith('/erasure/federated_closure_evaluator.py') and name=='evaluate'):
        blocked.append(filename+'::'+name)
        raise RuntimeError('Consumer execution is excluded from generator checks')
sys.setprofile(guard)
from gridweave.dataset import _sources,generate,validate
import gridweave,paeforge_pipeline,verclo,cryptography,jsonschema,pyarrow

def runtime():
    modules={m.__name__:str(Path(m.__file__).resolve()) for m in
        (gridweave,paeforge_pipeline,verclo,cryptography,jsonschema,pyarrow)}
    assert all(Path(p).is_relative_to(ROOT) for p in modules.values()),modules
    assert Path(sys.prefix).resolve().is_relative_to(ROOT)
    return {'python':sys.version,'prefix':sys.prefix,'modules':modules,
        'dependencies':{n:importlib.metadata.version(n) for n in
            ('cryptography','jsonschema','pyarrow','attrs','jsonschema-specifications','referencing','rpds-py','cffi','pycparser')}}

def small(path):
    return generate(path,seed='GRIDWEAVE-PORTABLE-PROOF-2026-10-25',scales=(1,),
        strategy='all',scenario_ids=['PBE-SG-SUPPLIER-SWITCHING'])

if len(sys.argv)>1 and sys.argv[1]=='--portable':
    result=small(Path(sys.argv[2]))
    Path(sys.argv[3]).write_text(json.dumps({'runtime':runtime(),'dataset':result,'blocked':blocked},indent=2)+'\n')
    raise SystemExit(0)

def main():
    record=ROOT/'validation';record.mkdir(exist_ok=True)
    identity=runtime();files,hashes,source_id=_sources()
    assert source_id==json.loads((ROOT/'RESEARCH_FREEZE.json').read_text())['generation_source_id']
    (ROOT/'SOURCE_MANIFEST.json').write_text(json.dumps({'algorithm':'SHA-256',
        'generation_source_id':source_id,'source_roots':{'GridWeave':'.','PaEForge':'support/PaEForge','HTGLThesis':'support/HTGLThesis'},
        'files':hashes,'standalone_interface_files':{rel:hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()
            for rel in ('gridweave','run.py','setup.sh','requirements.txt','tools/check_standalone.py')}},indent=2)+'\n')
    if '--resume' in sys.argv:
        log=(record/'generator-tests.log').read_text()
        assert 'Ran 11 tests' in log and log.rstrip().endswith('OK')
        checked=SimpleNamespace(testsRun=11)
    else:
        from tests.test_gridweave import CoverageResearchProperties,BoundarySynthesisProperties
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in
            (CoverageResearchProperties,BoundarySynthesisProperties))
        with (record/'generator-tests.log').open('w') as log:
            checked=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
        assert checked.wasSuccessful() and checked.testsRun==11
    print('11 generator property tests passed',flush=True)
    # Keep direct execution guards during the larger export without tracing all
    # library calls. The small relocation check also uses the call profiler.
    import gridweave.dataset as dataset_module
    from paeforge_pipeline import verclo_worker,gridweave_batch_worker
    from erasure.federated_closure_evaluator import FederatedClosureEvaluator
    def deny(*args,**kwargs):
        blocked.append('downstream execution entry point')
        raise RuntimeError('Consumer execution is excluded from generator checks')
    dataset_module.run=deny
    verclo_worker.evaluate_bundle=deny
    gridweave_batch_worker.main=deny
    FederatedClosureEvaluator.evaluate=deny
    sys.setprofile(None)
    destination=ROOT/'datasets/reference'
    checkpoint=record/'reference-dataset.json'
    if '--resume' in sys.argv and checkpoint.exists():
        result=json.loads(checkpoint.read_text())
        manifest_path=destination/'dataset-manifest.json'
        assert hashlib.sha256(manifest_path.read_bytes()).hexdigest()==result['manifest_sha256']
        inventory=json.loads(manifest_path.read_text())['files']
        assert {str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file()}==set(inventory)|{'dataset-manifest.json'}
        for rel,pin in inventory.items():
            assert hashlib.sha256((destination/rel).read_bytes()).hexdigest()==pin,rel
    else:
        result=(validate(destination) if destination.exists() else generate(destination,
            seed='GRIDWEAVE-STANDALONE-2026-10-25',scales=(1,2,4),strategy='all'))
        checkpoint.write_text(json.dumps(result,indent=2)+'\n')
    assert result['materialized_cases']==420 and result['pairs']==210
    assert result['q_status']=='NOT_EXECUTED' and result['source_family_split_overlap'] is False
    manifest=json.loads((destination/'dataset-manifest.json').read_text())
    assert manifest['q_executed_downstream_case_evaluations'] is None
    assert set(result['class_support'])=={'CLOSED','CLOSED_WITH_EXCEPTIONS','PARTIALLY_CLOSED','OPEN','DISPUTED','UNVERIFIABLE','IN_PROGRESS'}
    print('420-case reference dataset passed saved-file validation',flush=True)
    sys.setprofile(guard)
    with tempfile.TemporaryDirectory(prefix='gridweave-independent-') as temp:
        temp=Path(temp);original=small(temp/'reference')
        assert original['manifest_sha256']=='788d37fa95131bbc6e7483d41905d7da0014c774364b364aa8fbd934f6dd40bc'
        copy=temp/'GridWeave'
        def portable_ignore(directory,names):
            ignored={n for n in names if n in {'__pycache__','.pytest_cache'} or n.endswith('.egg-info')}
            if Path(directory)==ROOT:ignored.update({'datasets','validation'})
            return ignored
        shutil.copytree(ROOT,copy,symlinks=True,ignore=portable_ignore)
        env=dict(os.environ);env.pop('PYTHONPATH',None)
        with (record/'relocated-process.log').open('w') as log:
            done=subprocess.run([str(copy/'.venv/bin/python'),str(copy/'tools/check_standalone.py'),
                '--portable',str(temp/'reproduced'),str(temp/'portable.json')],cwd=temp,env=env,
                stdout=log,stderr=subprocess.STDOUT,timeout=180)
        assert done.returncode==0,'Inspect relocated-process.log'
        portable=json.loads((temp/'portable.json').read_text())
        assert portable['dataset']['manifest_sha256']==original['manifest_sha256']
        assert portable['blocked']==[]
        negatives={}
        try:validate(temp/'reference',expected_sha256='0'*64)
        except ValueError as e:negatives['wrong_manifest_pin']=str(e)
        else:raise AssertionError('Wrong trust pin accepted')
        entry=json.loads((temp/'reference/public/index.json').read_text())['cases'][0]
        receipt=temp/'reference/public/cases'/entry['unit_id']/'receipt-stream.json'
        receipt.write_bytes(receipt.read_bytes()+b' ')
        try:validate(temp/'reference')
        except ValueError as e:negatives['changed_receipt']=str(e)
        else:raise AssertionError('Changed receipt accepted')
    assert not blocked
    report={'status':'PASS','date':'2026-10-25','workflow':'Standalone generation and dataset validation only',
        'package_version':gridweave.__version__,'generation_source_id':source_id,
        'runtime':identity,'generator_property_tests_passed':checked.testsRun,
        'reference_dataset':result,'reference_directory':'datasets/reference',
        'native_verifier_case_evaluations':0,'blocked_consumer_calls':blocked,
        'relocated_copy':portable,'portable_reproduction_byte_identical':True,
        'negative_integrity_controls':negatives}
    (record/'standalone-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':'PASS','reference_cases':420,'native_verifier_case_evaluations':0,
        'portable_reproduction_byte_identical':True}),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
