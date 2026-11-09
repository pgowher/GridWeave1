"""Immutable GridWeave exports, independent validation and VERCLO execution."""
from collections import Counter,defaultdict
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import tomllib

from .coverage import Candidate,select
from .generation import candidates
from .oracle import encode,evaluate

VERSION='GridWeave-0.2.0'


def _read(path):return json.loads(Path(path).read_text())
def _hash(path):return sha256(Path(path).read_bytes()).hexdigest()
def _write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(encode(value))


def _sources():
    # Source identity is captured before a default seed is drawn or selection runs.
    import paeforge_pipeline,verclo
    project=Path(__file__).resolve().parents[2]
    roots={'GridWeave':project,'PaEForge':Path(paeforge_pipeline.__file__).resolve().parents[2],
           'HTGLThesis':Path(verclo.__file__).resolve().parents[2]}
    files={}
    for label,root in roots.items():
        for sub in ('src','schemas','configs','policies','evidence','observers','anomalies'):
            folder=root/sub
            if folder.is_dir():
                for p in sorted(folder.rglob('*')):
                    if p.is_file() and p.suffix in {'.py','.json'} and not any(x.endswith('.egg-info') or x=='__pycache__' for x in p.parts):
                        files[label+'/'+str(p.relative_to(root))]=p.read_bytes()
        if (root/'pyproject.toml').is_file():
            data=(root/'pyproject.toml').read_bytes();tomllib.loads(data.decode())
            files[label+'/pyproject.toml']=data
    hashes={k:sha256(v).hexdigest() for k,v in files.items()}
    return files,hashes,sha256(encode(hashes)).hexdigest()


def _fresh(path):
    path=Path(path).expanduser().resolve()
    if path.exists():raise FileExistsError('choose a fresh output directory: '+str(path))
    # Retained scientific evidence must never receive new runs.
    source=Path(__file__).resolve().parents[2]
    repository=source.parent
    if (repository/'thesis.py').is_file():
        protected=[repository/x for x in ('evidence','provenance','Thesis_Docs-/Releases','GridWeave/releases','PaEForge/releases','.git')]
        protected += [repository/project/sub for project in ('GridWeave','PaEForge','HTGLThesis') for sub in ('src','schemas','configs')]
        if any(path==p or path.is_relative_to(p) for p in protected):raise ValueError('output is inside preserved evidence or repository metadata')
    return path


def generate(output,*,seed=None,scales=(1,2,4),strategy='auto',max_states=100_000,include_audit=False,scenario_ids=None):
    root=_fresh(output)
    scales=tuple(sorted(set(scales)))
    if not scales or len(scales)>8 or any(type(s) is not int or not 1<=s<=128 for s in scales):
        raise ValueError('provide 1–8 distinct integer scales between 1 and 128')
    source_files,source_hashes,source_id=_sources()
    if seed is None:seed=secrets.token_hex(32)
    if not isinstance(seed,str) or not seed:raise ValueError('seed must be a nonempty string')
    pool=list(candidates(seed,scales,source_id,include_audit,scenario_ids))
    by_split=defaultdict(list)
    for pair in pool:by_split[pair['split']].append(pair)
    chosen=[];optimization={}
    for split,rows in sorted(by_split.items()):
        options=[Candidate(p['pair_id'],frozenset(p['tags']),p['cost']) for p in rows]
        result=select(options,strategy=strategy,max_states=max_states)
        result['baselines']={name:select(options,strategy=name,seed=seed) for name in ('all','greedy','random')}
        optimization[split]=result;ids=set(result['selected_pair_ids'])
        chosen.extend(p for p in rows if p['pair_id'] in ids)
    # All construction and optimization occurs before publishing an output tree.
    root.mkdir(parents=True,exist_ok=False)
    public=root/'public';sealed=root/'sealed';entries=[];pairs=[]
    from paeforge_contract import write_verifier_bundle
    for pair in sorted(chosen,key=lambda p:p['pair_id']):
        units=[]
        for unit in pair['units']:
            uid=unit['unit_id'];case=public/'cases'/uid;config=public/'configuration'/uid
            write_verifier_bundle(case,*unit['bundle'])
            _write(config/'policies/policy.json',unit['policy'])
            _write(config/'verification-context.json',unit['context'])
            paths=sorted([*case.iterdir(),config/'policies/policy.json',config/'verification-context.json'])
            entries.append({'unit_id':uid,'split':pair['split'],
                            'files':{str(p.relative_to(public)):_hash(p) for p in paths}})
            _write(sealed/'cases'/(uid+'.json'),{'unit_id':uid,'family':pair['family'],
                    'split':pair['split'],'operation':pair['operation'],'truth':unit['truth'],'world_truth':unit['world_truth']})
            units.append(uid)
        pairs.append({k:pair[k] for k in ('pair_id','family','split','scale','operation','tags','cost')}|{'unit_ids':units})
    _write(public/'index.json',{'version':VERSION,'cases':sorted(entries,key=lambda x:x['unit_id'])})
    _write(sealed/'pairs.json',pairs)
    _write(sealed/'optimization.json',optimization)
    _write(sealed/'reproduction.json',{'seed':seed,'scales':scales,'strategy':strategy,'max_states':max_states,
             'include_audit':include_audit,'scenario_ids':scenario_ids,
             'seed_visibility':'EVALUATOR_ONLY; do not disclose a holdout seed to predictors'})
    for rel,data in source_files.items():
        p=sealed/'source'/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    _write(sealed/'source-hashes.json',source_hashes)
    inventory={str(p.relative_to(root)):_hash(p) for p in sorted(root.rglob('*')) if p.is_file()}
    manifest={'version':VERSION,'proof_profile':'REAL_ED25519_SYNTHETIC_E2',
              'N_synthetic_source_families':len({p['family'] for p in pool}),
              'n_materialized_cases':len(entries),'materialized_pairs':len(pairs),
              'candidate_pairs':len(pool),'q_executed_downstream_case_evaluations':None,'q_status':'NOT_EXECUTED',
              'source_snapshot_sha256':source_id,'files':inventory,
              'claim_boundary':'Observer-relative synthetic metadata; no physical erasure or field realism claim'}
    _write(root/'dataset-manifest.json',manifest)
    return validate(root)


def validate(dataset,*,expected_sha256=None):
    root=Path(dataset).resolve();manifest_path=root/'dataset-manifest.json'
    if expected_sha256 is not None and _hash(manifest_path)!=expected_sha256:raise ValueError('dataset manifest trust-pin mismatch')
    manifest=_read(manifest_path)
    if manifest['version']!=VERSION:raise ValueError('unsupported dataset version')
    expected=set(manifest['files'])|{'dataset-manifest.json'}
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if expected!=actual:raise ValueError('dataset inventory mismatch')
    for rel,digest in manifest['files'].items():
        p=root/rel
        if not p.resolve().is_relative_to(root) or any(x.is_symlink() for x in (p,*p.parents)) or _hash(p)!=digest:
            raise ValueError('dataset integrity mismatch: '+rel)
    from paeforge_contract import read_verifier_bundle
    from paeforge_contract.leakage import scan_for_leakage
    from paeforge_pipeline.gridweave_backend import CONTEXT_SCHEMA
    from jsonschema import Draft202012Validator
    from verclo import PolicyRegistry
    public=root/'public';index=_read(public/'index.json');truths={};family_splits=defaultdict(set)
    if set(index)!={'version','cases'} or index['version']!=VERSION:raise ValueError('invalid public index')
    seen=set()
    for entry in index['cases']:
        uid=entry['unit_id']
        if uid in seen or len(uid)!=32 or any(c not in '0123456789abcdef' for c in uid):raise ValueError('duplicate or invalid unit ID')
        seen.add(uid)
        required={f'cases/{uid}/{name}' for name in ('case-manifest.json','observer-projection.json','receipt-stream.json')}|{
                  f'configuration/{uid}/policies/policy.json',f'configuration/{uid}/verification-context.json'}
        if set(entry)!= {'unit_id','split','files'} or set(entry['files'])!=required:raise ValueError('incomplete public export entry')
        for rel,digest in entry['files'].items():
            if _hash(public/rel)!=digest:raise ValueError('public input/configuration digest mismatch')
        m,o,s=read_verifier_bundle(public/'cases'/uid)
        policy=_read(public/'configuration'/uid/'policies/policy.json')
        profile=PolicyRegistry.load(public/'configuration'/uid/'policies').get(policy['profile_id'])
        if profile.sha256!=o['policy']['sha256']:raise ValueError('policy binding mismatch')
        context=_read(public/'configuration'/uid/'verification-context.json')
        Draft202012Validator(CONTEXT_SCHEMA).validate(context)
        truth=_read(root/'sealed/cases'/(uid+'.json'))
        if truth['unit_id']!=uid or truth['split']!=entry['split'] or truth['split'] not in {'train','validation','test'}:raise ValueError('split identity mismatch')
        if evaluate(o,s,policy,context)!=truth['truth']:raise ValueError('independent oracle mismatch: '+uid)
        family_splits[truth['family']].add(truth['split']);truths[uid]=truth
    if any(len(splits)!=1 for splits in family_splits.values()):raise ValueError('source family leaks across splits')
    pair_units=[];pairs=_read(root/'sealed/pairs.json');tags=defaultdict(set);pair_cost=0
    for pair in pairs:
        if len(pair['unit_ids'])!=2:raise ValueError('broken control/challenge pair')
        for uid in pair['unit_ids']:
            truth=truths[uid]
            if (truth['family'],truth['split'],truth['operation'])!=(pair['family'],pair['split'],pair['operation']):raise ValueError('pair identity mismatch')
        derived_tags={f"operation:{pair['operation']}",f"family:{pair['family']}",f"scale:{pair['scale']}"}|{
                     'outcome:'+truths[uid]['truth']['outcome'] for uid in pair['unit_ids']}
        if set(pair['tags'])!=derived_tags:raise ValueError('coverage tags do not match independently checked pair facts')
        entry_map={e['unit_id']:e for e in index['cases']}
        actual_pair_bytes=sum((public/rel).stat().st_size for uid in pair['unit_ids'] for rel in entry_map[uid]['files'])
        if pair['cost']!=actual_pair_bytes:raise ValueError('pair cost does not match serialized inputs')
        pair_units.extend(pair['unit_ids']);tags[pair['split']].update(pair['tags']);pair_cost+=pair['cost']
        if pair['operation']=='hidden_copy_twin':
            a,b=pair['unit_ids']
            if any((public/'cases'/a/name).read_bytes()!=(public/'cases'/b/name).read_bytes()
                   for name in ('case-manifest.json','observer-projection.json','receipt-stream.json')):raise ValueError('hidden worlds are distinguishable')
            if truths[a]['world_truth']==truths[b]['world_truth']:raise ValueError('hidden worlds do not differ')
    if len(pair_units)!=len(set(pair_units)) or set(pair_units)!=seen:raise ValueError('orphan or reused pair unit')
    optimization=_read(root/'sealed/optimization.json')
    for split,result in optimization.items():
        if set(result['requested_goals'])!=tags[split]:raise ValueError('diagnostic coverage mismatch')
        selected=sorted(p['pair_id'] for p in pairs if p['split']==split)
        if selected!=result['selected_pair_ids']:raise ValueError('selection witness mismatch')
    input_bytes=sum((public/rel).stat().st_size for entry in index['cases'] for rel in entry['files'])
    if pair_cost!=input_bytes:raise ValueError('serialized-input cost certificate mismatch')
    if len(seen)!=manifest['n_materialized_cases'] or len(pairs)!=manifest['materialized_pairs']:raise ValueError('materialization count mismatch')
    hashes=_read(root/'sealed/source-hashes.json')
    if sha256(encode(hashes)).hexdigest()!=manifest['source_snapshot_sha256']:raise ValueError('source snapshot identity mismatch')
    for rel,digest in hashes.items():
        if _hash(root/'sealed/source'/rel)!=digest:raise ValueError('source snapshot member mismatch')
    for p in sorted(public.rglob('*.json')):scan_for_leakage(_read(p))
    return {'status':'READY_FOR_VERCLO_INPUT','version':VERSION,'dataset':str(root),
            'manifest_sha256':_hash(manifest_path),'materialized_cases':len(seen),'pairs':len(pairs),
            'source_families':len(family_splits),'source_family_split_overlap':False,
            'class_support':dict(sorted(Counter(t['truth']['outcome'] for t in truths.values()).items())),
            'serialized_input_bytes':input_bytes,'proof_profile':'REAL_ED25519_SYNTHETIC_E2',
            'q_status':manifest['q_status'],'scope':'Input, cryptographic fixture and independent-oracle checks; no VERCLO execution implied'}


def run(dataset,output):
    root=Path(dataset).resolve();out=_fresh(output)
    if out.is_relative_to(root):raise ValueError('execution output must be outside the immutable dataset')
    readiness=validate(root)
    out.mkdir(parents=True,exist_ok=False)
    import paeforge_pipeline,verclo
    src=[Path(m.__file__).resolve().parents[1] for m in (paeforge_pipeline,verclo)]
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONPATH']=os.pathsep.join(map(str,src))
    source_id=_read(root/'dataset-manifest.json')['source_snapshot_sha256']
    # Record the actual current verifier separately from the generation snapshot.
    current={label+'/'+str(p.relative_to(base)):_hash(p) for label,base in zip(('PaEForge','HTGLThesis'),src)
             for p in sorted(base.rglob('*.py'))}
    revision=sha256(encode(current)).hexdigest()
    _write(out/'verifier-source-hashes.json',current)
    with tempfile.TemporaryDirectory(prefix='gridweave-public-worker-') as temporary:
        isolated=Path(temporary)/'public';shutil.copytree(root/'public',isolated)
        completed=subprocess.run([sys.executable,'-m','paeforge_pipeline.gridweave_batch_worker',
                    '--public',str(isolated),'--output',str(out/'results'),'--source-revision',revision],
                    cwd=temporary,env=env,capture_output=True,text=True,
                    timeout=max(120,readiness['materialized_cases']*3),check=False)
    (out/'worker.log').write_text(completed.stdout+completed.stderr)
    if completed.returncode:raise RuntimeError('VERCLO batch worker failed; inspect '+str(out/'worker.log'))
    result_manifest=_read(out/'results/results-manifest.json')
    if result_manifest['generator_or_oracle_modules_loaded']:raise ValueError('worker imported generator/oracle')
    index=_read(root/'public/index.json');expected_ids={x['unit_id'] for x in index['cases']}
    if (len(result_manifest['results'])!=len(expected_ids) or result_manifest['executed_case_evaluations_q']!=len(expected_ids)
            or {x['unit_id'] for x in result_manifest['results']}!=expected_ids):raise ValueError('incomplete verifier execution')
    mismatches=[];operation_proxy=0;confusion=Counter();closure_mismatches=0;diagnostic_mismatches=0
    # Predictions are complete and hashed before the parent consults per-case truth.
    from paeforge_contract import validate_document
    for row in result_manifest['results']:
        uid=row['unit_id'];path=out/'results'/(uid+'.json')
        if _hash(path)!=row['result_file_sha256']:raise ValueError('result changed after prediction freeze')
        result=_read(path);validate_document(result)
        truth=_read(root/'sealed/cases'/(uid+'.json'))
        expected=truth['truth']['outcome'];actual=result['closure_class'];confusion[expected+' -> '+actual]+=1
        operation_proxy+=result['execution']['executed_operations_q']
        actual_categories={x['obligation_id']:x['category'] for x in result['obligation_results']}
        if len(actual_categories)!=len(result['obligation_results']):
            raise ValueError('duplicate predicted obligation ID: '+uid)
        expected_categories=truth['truth']['obligation_categories']
        differences={oid:{'expected':expected_categories.get(oid),'actual':actual_categories.get(oid)}
                     for oid in sorted(expected_categories.keys()|actual_categories.keys())
                     if expected_categories.get(oid)!=actual_categories.get(oid)} if truth['truth']['baseline_verifiable'] else {}
        closure_mismatches+=expected!=actual;diagnostic_mismatches+=bool(differences)
        if expected!=actual or differences:
            mismatches.append({'unit_id':uid,'operation':truth['operation'],'expected':expected,'actual':actual,
                               'obligation_category_differences':differences})
    report={'status':'PIPELINE_EXECUTION_PASSED' if not mismatches else 'INPUT_READY_VERIFIER_MODEL_MISMATCHES',
            'dataset_manifest_sha256':readiness['manifest_sha256'],'generation_source_snapshot_sha256':source_id,
            'executed_verifier_source_sha256':revision,'executed_case_evaluations_q':len(expected_ids),
            'worker_reported_operation_proxy_q':operation_proxy,
            'operation_proxy_definition':'Existing worker formula 2 + obligations + receipts; not a measured primitive-operation count',
            'generator_or_oracle_modules_loaded_in_worker':[],
            'frozen_results_manifest_sha256':_hash(out/'results/results-manifest.json'),
            'mismatch_count':len(mismatches),'closure_mismatch_count':closure_mismatches,
            'diagnostic_mismatch_count':diagnostic_mismatches,'mismatches':mismatches,'confusion_counts':dict(sorted(confusion.items())),
            'limits':'Local synthetic E2 fixtures and configured trust roots; no physical deletion, independent authorship or field-validity inference'}
    _write(out/'execution-report.json',report)
    return report
