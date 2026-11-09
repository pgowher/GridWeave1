#!/usr/bin/env python3
"""Generate additional native profiles outside the immutable GridWeave source.

Uses existing GridWeave signing, pair operators and label oracle. This extends
fixture structure; it does not provide independently authored expected labels.
"""
import argparse,copy,hashlib,json,sys,uuid
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

PROJECT=Path(__file__).resolve().parents[3];LAB=Path(__file__).resolve().parents[1];GW=PROJECT/'GridWeave'
sys.dont_write_bytecode=True
for p in reversed([GW/'src',GW/'support/PaEForge/src',GW/'support/HTGLThesis/src']):sys.path.insert(0,str(p))
from gridweave.generation import sign,refresh,make_pair,OPERATIONS,token
from gridweave.oracle import encode,evaluate,instant,_digest
from gridweave.dataset import _sources,_write,_hash,validate
from gridweave.coverage import Candidate,select
from paeforge_contract import write_verifier_bundle


def read(p):return json.loads(p.read_text())


def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();out=a.output.resolve()
 if out.exists():raise FileExistsError('Use a new output path')
 profile_path=LAB/'extension/profiles/structural_profiles_v0_2.json';profiles=read(profile_path)
 source_files,hashes,_=_sources()
 for p in [Path(__file__).resolve(),profile_path]:
  key='Paper1Lab/'+str(p.relative_to(LAB));source_files[key]=p.read_bytes();hashes[key]=_hash(p)
 source_id=hashlib.sha256(encode(hashes)).hexdigest();seed='GRIDWEAVE-PAPER1-STRUCTURAL-PILOT-V0.2-PUBLIC'
 ref=GW/'datasets/reference';pair=next(p for p in read(ref/'sealed/pairs.json') if p['scale']==1 and p['operation']=='omit_one')
 uid=pair['unit_ids'][0];base=ref/'public/cases'/uid
 original=[read(base/n) for n in ['case-manifest.json','observer-projection.json','receipt-stream.json']]
 original_policy=read(ref/'public/configuration'/uid/'policies/policy.json');receipt_template=copy.deepcopy(original[2]['receipts'][0]);pool=[]
 for ordinal,p in enumerate(profiles['profiles']):
  m,o,s=copy.deepcopy(original);prefix='P1-'+p['id'].upper();cid=str(uuid.UUID(hex=token('paper1-case',p['id'])));dataset='DATASET-'+prefix;corr='CORRELATION-'+cid
  for doc in [m,o,s]:
   doc['case_id']=cid;doc['exchange_id']='XCH-'+token(seed,p['id']).upper();doc['run_id']='RUN-PAPER1-'+source_id[:12]
   if 'scenario_id' in doc:doc['scenario_id']='PBE-SG-PAPER1-'+p['id'].upper()
   # The existing exchange schema fixes the producer marker at PaEGen.
   # Extension authorship/version is separately declared in the resource manifest.
   if 'provenance' in doc:doc['provenance'].update(source_revision=source_id)
   if 'provenance' in doc and 'source_bundle_sha256' in doc['provenance']:
    doc['provenance']['source_bundle_sha256']=hashlib.sha256(encode(p)).hexdigest()
  for doc in [m,o,s]:
   if 'seed' in doc:
    doc['seed']['seed_stream_digest']=token(seed,p['id'])+token(p['id'],seed)
    if 'master_seed_commitment' in doc['seed']:doc['seed']['master_seed_commitment']=hashlib.sha256(seed.encode()).hexdigest()
  o['case'].update(dataset_id=dataset,correlation_id=corr,request_id='REQUEST-'+cid,root_asset_ids=[prefix+'-A'+str(i) for i in p['roots']])
  o['case']['metadata']={'profile_id':profiles['version'],'authored_profile':p['id']}
  policy=copy.deepcopy(original_policy);policy.update(profile_id='VERCLO-POLICY-PAPER1-DEFAULT-E2',authorization_basis='DECLARED_SYNTHETIC_LIFECYCLE_PROFILE')
  policy['default_rule'].update(deadline_hours=48,permitted_dispositions=['ERASED'])
  pref={'profile_id':policy['profile_id'],'version':policy['version'],'sha256':_digest('verclo-policy-profile-v1',policy)}
  m['policy']=pref.copy();o['policy']=pref.copy()
  o['evaluation_time']=(instant(o['case']['accepted_at'])+timedelta(hours=50)).isoformat(timespec='microseconds').replace('+00:00','Z')
  top={'assets':[dict(asset_id=prefix+'-A'+str(i),asset_kind=k,dataset_id=dataset,visibility='DECLARED') for i,k in enumerate(p['asset_kinds'])],
       'repositories':[dict(repository_id=prefix+'-R'+str(i),custodian_principal_id=prefix+'-ORG'+str(i%p['custodians']),organization_id=prefix+'-ORG'+str(i%p['custodians']),repository_class='SYNTHETIC_GOVERNANCE_STORE',visibility='DECLARED') for i in range(p['repositories'])],
       'replicas':[dict(asset_id=prefix+'-A'+str(ai),replica_id=str(uuid.UUID(hex=token(p['id'],'replica',j))),repository_id=prefix+'-R'+str(ri),replica_class='primary',visibility='DECLARED') for j,(ai,ri) in enumerate(p['placements'])],
       'lineage_edges':[dict(parent_asset_id=prefix+'-A'+str(ai),child_asset_id=prefix+'-A'+str(bi),relationship_id='REL-'+token(p['id'],ai,bi).upper(),relationship_type='DERIVED_FROM',visibility='DECLARED') for ai,bi in p['edges']],
       'scope_version':1,'graph_available':True,'declared_scope_complete':True,'unresolved_reference_ids':[]}
  material={'case_id':cid,'dataset_id':dataset,'correlation_id':corr,'scope_version':1}
  for key,idkey in [('assets','asset_id'),('repositories','repository_id'),('replicas','replica_id'),('lineage_edges','relationship_id')]:material[key]=sorted(top[key],key=lambda r:r[idkey])
  top['scope_commitment']=_digest('verclo-visible-scope-v1',material);o['topology']=top;o['exceptions']=[];o['challenges']=[]
  reachable=set(p['roots'])
  while True:
   new=reachable|{bi for ai,bi in p['edges'] if ai in reachable}
   if new==reachable:break
   reachable=new
  s['receipts']=[]
  for j,(replica,(ai,ri)) in enumerate(zip(top['replicas'],p['placements'])):
   if ai not in reachable:continue
   repo=top['repositories'][ri];identity=dict(case_id=cid,dataset_id=dataset,correlation_id=corr,asset_id=replica['asset_id'],replica_id=replica['replica_id'],repository_id=repo['repository_id'],custodian_principal_id=repo['custodian_principal_id'],policy_profile_id=policy['profile_id'],policy_version=policy['version'])
   row=copy.deepcopy(receipt_template);row.update(receipt_id='RCP-'+token(p['id'],j).upper(),case_id=cid,asset_id=replica['asset_id'],replica_id=replica['replica_id'],repository_id=repo['repository_id'],issuer_principal_id=repo['custodian_principal_id'],obligation_id='OBL-'+_digest('verclo-obligation-v1',identity)[:32].upper(),disposition='ERASED',fault_domain='FAULT-'+repo['repository_id'],trust_domain='TRUST-'+repo['custodian_principal_id'],provenance_refs=['paper1-profile:'+p['id']])
   s['receipts'].append(row)
  context=sign(o,s,seed);bundle=refresh([m,o,s]);truth=evaluate(bundle[1],bundle[2],policy,context)
  assert truth['outcome']=='CLOSED',(p['id'],truth)
  family=token('paper1-authored-native-profile',p)
  for op in OPERATIONS:
   result=make_pair(bundle,policy,seed,op,family,1);assert result
   result['split']='test';pool.append(result)
 out.mkdir(parents=True);public=out/'public';sealed=out/'sealed';entries=[];pairs=[]
 for pair in sorted(pool,key=lambda p:p['pair_id']):
  units=[]
  for unit in pair['units']:
   uid=unit['unit_id'];case=public/'cases'/uid;cfg=public/'configuration'/uid;write_verifier_bundle(case,*unit['bundle']);_write(cfg/'policies/policy.json',unit['policy']);_write(cfg/'verification-context.json',unit['context'])
   paths=sorted([*case.iterdir(),cfg/'policies/policy.json',cfg/'verification-context.json']);entries.append(dict(unit_id=uid,split='test',files={str(p.relative_to(public)):_hash(p) for p in paths}))
   _write(sealed/'cases'/(uid+'.json'),dict(unit_id=uid,family=pair['family'],split='test',operation=pair['operation'],truth=unit['truth'],world_truth=unit['world_truth']));units.append(uid)
  pairs.append({k:pair[k] for k in ['pair_id','family','split','scale','operation','tags','cost']}|{'unit_ids':units})
 _write(public/'index.json',dict(version='GridWeave-0.2.0',cases=sorted(entries,key=lambda r:r['unit_id'])))
 _write(sealed/'pairs.json',pairs);_write(sealed/'optimization.json',{'test':select([Candidate(p['pair_id'],frozenset(p['tags']),p['cost']) for p in pool],strategy='all')})
 _write(sealed/'reproduction.json',dict(seed=seed,profile=profiles['version'],profiles_file='Paper1Lab/extension/profiles/structural_profiles_v0_2.json',strategy='all',include_audit=False,scales=[1],pilot_public_seed=True))
 for rel,data in source_files.items():
  path=sealed/'source'/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 _write(sealed/'source-hashes.json',hashes)
 inventory={str(p.relative_to(out)):_hash(p) for p in sorted(out.rglob('*')) if p.is_file()}
 _write(out/'dataset-manifest.json',dict(version='GridWeave-0.2.0',resource_version=profiles['version'],N_synthetic_source_families=6,n_materialized_cases=len(entries),materialized_pairs=len(pairs),candidate_pairs=len(pairs),proof_profile='REAL_ED25519_SYNTHETIC_E2',source_snapshot_sha256=source_id,files=inventory,q_executed_downstream_case_evaluations=None,q_status='NOT_EXECUTED',claim_boundary='Authored structural pilot; same generator oracle, not independent adjudication or field validation'))
 print(json.dumps(validate(out),indent=2))

if __name__=='__main__':main()
