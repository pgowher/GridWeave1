"""Wire-format utilities only: no obligation or assessment semantics."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from datetime import datetime

LABELS=('CLOSED','CLOSED_WITH_EXCEPTIONS','PARTIALLY_CLOSED','OPEN','DISPUTED','UNVERIFIABLE','IN_PROGRESS')

def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def domain(name,value):return hashlib.sha256(name.encode()+b'\0'+canonical(value).rstrip(b'\n')).hexdigest()
def exchange_domain(name,value):return hashlib.sha256(name.encode()+b'\0'+canonical(value)).hexdigest()
def read(path):return json.loads(Path(path).read_text())
def write(path,value):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(canonical(value))
def file_hash(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def instant(value):
    v=datetime.fromisoformat(value.replace('Z','+00:00'))
    if v.utcoffset() is None:raise ValueError('Timezone-aware timestamp required')
    return v

def load_public(public):
    root=Path(public).resolve();index=read(root/'index.json');seen=set();bundles=[]
    if index['version']!='GridWeave-0.2.0':raise ValueError('Unsupported native format')
    for entry in index['cases']:
        uid=entry['unit_id']
        if uid in seen or len(uid)!=32 or any(x not in '0123456789abcdef' for x in uid):raise ValueError('Invalid unit ID')
        seen.add(uid)
        required={f'cases/{uid}/{n}' for n in ('case-manifest.json','observer-projection.json','receipt-stream.json')}|{f'configuration/{uid}/policies/policy.json',f'configuration/{uid}/verification-context.json'}
        if set(entry['files'])!=required:raise ValueError('Incomplete public input set')
        for rel,expected in entry['files'].items():
            path=root/rel
            if not path.resolve().is_relative_to(root) or path.is_symlink() or file_hash(path)!=expected:raise ValueError('Public input integrity failure: '+rel)
        m,o,s=(read(root/f'cases/{uid}'/n) for n in ('case-manifest.json','observer-projection.json','receipt-stream.json'))
        policy=read(root/f'configuration/{uid}/policies/policy.json');context=read(root/f'configuration/{uid}/verification-context.json')
        for doc in (o,s):
            if any(doc[k]!=m[k] for k in ('case_id','exchange_id','run_id','scenario_id')):raise ValueError('Exchange identity mismatch')
        if m['artifacts']['observer_projection']['sha256']!=digest(o) or m['artifacts']['receipt_stream']['sha256']!=digest(s):raise ValueError('Case manifest mismatch')
        semantic={k:o[k] for k in ('observer','policy','case','topology','exceptions','challenges')}
        if o['projection_commitment']!=exchange_domain('paeforge-observer-projection-v1',semantic) or s['stream_commitment']!=exchange_domain('paeforge-receipt-stream-v1',s['receipts']):raise ValueError('Exchange commitment mismatch')
        if o['policy']['sha256']!=domain('verclo-policy-profile-v1',policy):raise ValueError('Policy digest mismatch')
        if policy['overrides'] or policy['early_closure_allowed'] or policy['default_rule']['minimum_evidence_grade']!='E2':raise ValueError('Unsupported policy profile')
        if len({e['obligation_id'] for e in o['exceptions']})!=len(o['exceptions']):raise ValueError('Multiple exceptions per obligation are outside the study profile')
        bundles.append((uid,o,s,policy,context))
    return bundles
