"""GraphSpec: direct graph traversal and per-obligation evidence assessment.

No imports from GridWeave, VERCLO, PaEForge or the SQL assessor. Independently
implemented in this task after inspecting the existing profile; not blind or
independently human-authored. wire supplies serialization and time parsing only.
"""
from collections import defaultdict,deque
from datetime import timedelta
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .wire import canonical,domain,instant

TERMINAL_TYPES={'signature','deletion_acknowledgement','replica_attestation','audit_finding'}

def _verify(key,signature,value):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature),canonical(value))
        return True
    except (TypeError,ValueError,InvalidSignature):return False

def _scope_matches(top,case,case_id):
    value=dict(case_id=case_id,dataset_id=case['dataset_id'],correlation_id=case['correlation_id'],scope_version=top['scope_version'])
    for field,idkey in [('assets','asset_id'),('repositories','repository_id'),('replicas','replica_id'),('lineage_edges','relationship_id')]:value[field]=sorted(top[field],key=lambda row:row[idkey])
    return top.get('scope_commitment') == domain('verclo-visible-scope-v1',value)

def _reachable(top,roots):
    children=defaultdict(list);indegree={a['asset_id']:0 for a in top['assets']}
    for edge in top['lineage_edges']:
        a,b=edge['parent_asset_id'],edge['child_asset_id']
        if a not in indegree or b not in indegree:raise ValueError('Dangling lineage')
        children[a].append(b);indegree[b]+=1
    queue=deque(a for a,n in indegree.items() if not n);visited=0
    while queue:
        a=queue.popleft();visited+=1
        for b in children[a]:
            indegree[b]-=1
            if not indegree[b]:queue.append(b)
    if visited!=len(indegree):raise ValueError('Cyclic lineage')
    reached=set(roots);frontier=deque(roots)
    while frontier:
        for b in children[frontier.popleft()]:
            if b not in reached:reached.add(b);frontier.append(b)
    return reached

def _eligible_replicas(top):return list(top['replicas'])

def assess(observer,stream,policy,context):
    top=observer['topology'];case=observer['case'];now=instant(observer['evaluation_time']);deadline=instant(case['accepted_at'])+timedelta(hours=policy['default_rule']['deadline_hours'])
    for field,idkey in [('assets','asset_id'),('repositories','repository_id'),('replicas','replica_id'),('lineage_edges','relationship_id')]:
        if len({r[idkey] for r in top[field]})!=len(top[field]):raise ValueError('Duplicate topology identity')
    assets={r['asset_id']:r for r in top['assets']};repos={r['repository_id']:r for r in top['repositories']}
    reachable=_reachable(top,case['root_asset_ids'])
    baseline=bool(top['graph_available'] and top.get('declared_scope_complete') and not top['unresolved_reference_ids'] and set(case['root_asset_ids'])<=assets.keys() and _scope_matches(top,case,observer['case_id']))
    grouped=defaultdict(list)
    for r in stream['receipts']:grouped[r['obligation_id']].append(r)
    obligations={};diagnoses={};reasons={}
    for replica in _eligible_replicas(top):
        if replica['asset_id'] not in assets or replica['repository_id'] not in repos:raise ValueError('Dangling replica')
        if replica['asset_id'] not in reachable:continue
        asset=assets[replica['asset_id']];repo=repos[replica['repository_id']]
        if '*' not in policy['applicable_asset_kinds'] and asset['asset_kind'] not in policy['applicable_asset_kinds']:continue
        if replica['replica_class'] not in policy['applicable_replica_classes']:continue
        identity=dict(case_id=observer['case_id'],dataset_id=case['dataset_id'],correlation_id=case['correlation_id'],asset_id=replica['asset_id'],replica_id=replica['replica_id'],repository_id=repo['repository_id'],custodian_principal_id=repo['custodian_principal_id'],policy_profile_id=policy['profile_id'],policy_version=policy['version'])
        oid='OBL-'+domain('verclo-obligation-v1',identity)[:32].upper();matching=grouped[oid];dispositions=set();covered=False;late=False
        for r in matching:
            payload={k:v for k,v in r.items() if k not in ('proof','sequence','claim_commitment')};proof=r['proof'];key=context['principal_public_keys'].get(r['issuer_principal_id'],'')
            signatures=[x.split(':',1)[1] for x in proof['verification_material_refs'] if x.startswith('ed25519-signature:')]
            errors=[]
            if any(r[k]!=identity[k] for k in ('case_id','asset_id','replica_id','repository_id')):errors.append('SUBJECT_BINDING')
            if r['issuer_principal_id']!=repo['custodian_principal_id']:errors.append('ISSUER_BINDING')
            if not r['provenance_refs']:errors.append('MISSING_PROVENANCE')
            if not key or len(signatures)!=1 or proof['format']!='GRIDWEAVE-ED25519-E2-v1' or proof.get('credential_ref')!='ed25519:'+key:errors.append('VERIFICATION_MATERIAL')
            if r['claim_commitment']!=sha256(canonical(payload)).hexdigest():errors.append('CLAIM_COMMITMENT')
            if not errors and not _verify(key,signatures[0],payload):errors.append('SIGNATURE')
            if instant(r['submitted_at'])<instant(r['event_time']) or instant(r['not_before'])>now or instant(r['event_time'])>now or instant(r['submitted_at'])>now or ('expires_at' in r and now>=instant(r['expires_at'])):errors.append('RECEIPT_TIME')
            diagnoses[r['receipt_id']]='REJECTED' if errors else 'AUTHENTICATED_E2';reasons[r['receipt_id']]=errors
            if errors or r['evidence_type'] not in TERMINAL_TYPES:continue
            dispositions.add(r['disposition']);timely=instant(r['event_time'])<=deadline
            late=late or not timely;covered=covered or (timely and r['disposition'] in policy['default_rule']['permitted_dispositions'])
        exception_ok=False
        exception=next((e for e in observer['exceptions'] if e['obligation_id']==oid),None)
        if exception:
            key=context['exception_authority_public_keys'].get(exception['authority_principal_id'],'');sig=context['exception_signatures'].get(exception['exception_id'],'')
            exception_ok=bool(key and exception['authority_principal_id'] in policy['exception_authority_ids'] and instant(exception['effective_at'])<=deadline and instant(exception['effective_at'])<=now and now < instant(exception['expires_at']) and _verify(key,sig,exception))
        if len(dispositions) > 1:category='CONTRADICTORY'
        elif exception_ok:category='EXCEPTED'
        elif covered:category='COVERED'
        elif late:category='LATE'
        elif not matching:category='MISSING'
        else:category='INVALID'
        obligations[oid]=category
    baseline=baseline and bool(obligations)
    categories=list(obligations.values())
    if now < deadline:outcome='IN_PROGRESS'
    elif not baseline:outcome='UNVERIFIABLE'
    elif 'CONTRADICTORY' in categories or any(c['status']=='OPEN' for c in observer['challenges']):outcome='DISPUTED'
    elif all(c=='COVERED' for c in categories):outcome='CLOSED'
    elif all(c in ('COVERED','EXCEPTED') for c in categories):outcome='CLOSED_WITH_EXCEPTIONS'
    elif any(c in ('COVERED','EXCEPTED') for c in categories):outcome='PARTIALLY_CLOSED'
    else:outcome='OPEN'
    return dict(outcome=outcome,baseline_verifiable=baseline,obligation_categories=dict(sorted(obligations.items())),receipt_diagnoses=dict(sorted(diagnoses.items())),receipt_reasons=reasons)
