"""Independent specification oracle for GridWeave's declared signed-E2 profile.

No imports from VERCLO, PaEForge evaluators, generation or coverage selection.
This oracle is independently implemented, not independently authored. It has
explicit scope: default per-replica rules, no overrides, no early closure,
signed E2 terminal receipts and signed exceptions, acyclic visible lineage.
"""
from datetime import datetime,timedelta
from hashlib import sha256
from graphlib import TopologicalSorter
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def encode(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()


def instant(value):
    d=datetime.fromisoformat(value.replace("Z","+00:00"))
    if d.utcoffset() is None:raise ValueError("timezone-aware times required")
    return d


def _digest(domain,value):
    return sha256(domain.encode()+b"\0"+encode(value).rstrip(b"\n")).hexdigest()


def _signature(key,signature,payload):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature),encode(payload))
        return True
    except (ValueError,TypeError,InvalidSignature):return False


def evaluate(observer,stream,policy,context):
    if policy['overrides'] or policy['early_closure_allowed'] or policy['default_rule']['minimum_evidence_grade']!='E2':
        raise ValueError("outside the signed-E2 oracle profile")
    top=observer['topology'];case=observer['case'];now=instant(observer['evaluation_time'])
    deadline=instant(case['accepted_at'])+timedelta(hours=policy['default_rule']['deadline_hours'])
    assets={a['asset_id']:a for a in top['assets']}
    repos={x['repository_id']:x for x in top['repositories']}
    reachable=set(case['root_asset_ids']);edges=top['lineage_edges']
    for name,key in [('assets','asset_id'),('repositories','repository_id'),('replicas','replica_id'),('lineage_edges','relationship_id')]:
        if len({r[key] for r in top[name]})!=len(top[name]):raise ValueError('duplicate topology identifier')
    parents={a:set() for a in assets}
    for e in edges:
        if e['child_asset_id'] not in assets or e['parent_asset_id'] not in assets:raise ValueError('dangling lineage edge')
        parents[e['child_asset_id']].add(e['parent_asset_id'])
    tuple(TopologicalSorter(parents).static_order())
    if any(r['asset_id'] not in assets or r['repository_id'] not in repos for r in top['replicas']):raise ValueError('dangling replica binding')
    # Deliberately conventional fixed-point baseline, separate from core Kahn traversal.
    while True:
        new=reachable|{e['child_asset_id'] for e in edges if e['parent_asset_id'] in reachable}
        if new==reachable:break
        reachable=new
    material={'case_id':observer['case_id'],'dataset_id':case['dataset_id'],
              'correlation_id':case['correlation_id'],'scope_version':top['scope_version']}
    keys={'assets':'asset_id','repositories':'repository_id','replicas':'replica_id','lineage_edges':'relationship_id'}
    for name,key in keys.items():material[name]=sorted(top[name],key=lambda x:x[key])
    baseline=bool(top['graph_available'] and top['declared_scope_complete'] and
                  not top['unresolved_reference_ids'] and set(case['root_asset_ids'])<=assets.keys() and
                  top['scope_commitment']==_digest('verclo-visible-scope-v1',material))
    categories={};receipts=stream['receipts'];receipt_diagnoses={}
    for replica in top['replicas']:
        if replica['asset_id'] not in reachable:continue
        asset=assets[replica['asset_id']];repo=repos[replica['repository_id']]
        if ('*' not in policy['applicable_asset_kinds'] and asset['asset_kind'] not in policy['applicable_asset_kinds']):continue
        if replica['replica_class'] not in policy['applicable_replica_classes']:continue
        identity={'case_id':observer['case_id'],'dataset_id':case['dataset_id'],
                  'correlation_id':case['correlation_id'],'asset_id':replica['asset_id'],
                  'replica_id':replica['replica_id'],'repository_id':replica['repository_id'],
                  'custodian_principal_id':repo['custodian_principal_id'],
                  'policy_profile_id':policy['profile_id'],'policy_version':policy['version']}
        oid='OBL-'+_digest('verclo-obligation-v1',identity)[:32].upper()
        claims=set();success=False;late=False;matching=[]
        for row in receipts:
            if row['obligation_id']!=oid:continue
            matching.append(row)
            binding=all(row[k]==identity[k] for k in ('case_id','asset_id','replica_id','repository_id'))
            signed={k:v for k,v in row.items() if k not in {'sequence','proof','claim_commitment'}}
            proof=row['proof'];key=context['principal_public_keys'].get(row['issuer_principal_id'],'')
            refs=proof['verification_material_refs']
            sig=next((x.removeprefix('ed25519-signature:') for x in refs if x.startswith('ed25519-signature:')),'')
            valid=(binding and row['issuer_principal_id']==repo['custodian_principal_id'] and
                   row['provenance_refs'] and proof['format']=='GRIDWEAVE-ED25519-E2-v1' and key and
                   proof.get('credential_ref')=='ed25519:'+key and
                   row['claim_commitment']==sha256(encode(signed)).hexdigest() and
                   _signature(key,sig,signed) and instant(row['not_before'])<=now and
                   instant(row['event_time'])<=now and
                   ('expires_at' not in row or now<instant(row['expires_at'])))
            receipt_diagnoses[row['receipt_id']]='AUTHENTICATED_E2' if valid else 'REJECTED'
            if not valid:continue
            if row['evidence_type'] not in {'signature','deletion_acknowledgement','replica_attestation','audit_finding'}:continue
            claims.add(row['disposition'])
            timely=instant(row['event_time'])<=deadline
            late|=not timely
            success|=timely and row['disposition'] in policy['default_rule']['permitted_dispositions']
        exception=next((x for x in observer['exceptions'] if x['obligation_id']==oid),None)
        exception_valid=False
        if exception:
            key=context['exception_authority_public_keys'].get(exception['authority_principal_id'],'')
            sig=context['exception_signatures'].get(exception['exception_id'],'')
            exception_valid=bool(key and exception['authority_principal_id'] in policy['exception_authority_ids'] and
                                 instant(exception['effective_at'])<=deadline and
                                 instant(exception['effective_at'])<=now<instant(exception['expires_at']) and
                                 _signature(key,sig,exception))
        categories[oid]=('CONTRADICTORY' if len(claims)>1 else 'EXCEPTED' if exception_valid else
                         'COVERED' if success else 'LATE' if late else 'MISSING' if not matching else 'INVALID')
    baseline=baseline and bool(categories)
    values=list(categories.values())
    # Explicit Model-v1 timing-first specification. Core deviations are reported,
    # never used to relabel generated ground truth.
    if now<deadline:outcome='IN_PROGRESS'
    elif not baseline:outcome='UNVERIFIABLE'
    elif 'CONTRADICTORY' in values or any(x['status']=='OPEN' for x in observer['challenges']):outcome='DISPUTED'
    elif all(x=='COVERED' for x in values):outcome='CLOSED'
    elif all(x in {'COVERED','EXCEPTED'} for x in values):outcome='CLOSED_WITH_EXCEPTIONS'
    elif any(x in {'COVERED','EXCEPTED'} for x in values):outcome='PARTIALLY_CLOSED'
    else:outcome='OPEN'
    return {'outcome':outcome,'baseline_verifiable':baseline,'obligation_categories':dict(sorted(categories.items())),
            'receipt_diagnoses':dict(sorted(receipt_diagnoses.items())),
            'specification':'GridWeave signed-E2 Model-v1 subset; half-open exception expiry; timing precedes baseline'}
