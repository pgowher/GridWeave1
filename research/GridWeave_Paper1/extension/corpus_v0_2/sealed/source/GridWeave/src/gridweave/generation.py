"""Dependency-preserving scale expansion and authenticated boundary-pair synthesis."""
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from jsonschema import Draft202012Validator

from htgl_dataset_generator.paegen import compile_smart_grid_benchmark,load_smart_grid_scenarios
from htgl_dataset_generator.paegen.smart_grid.loader import SmartGridScenarioDefinition,_validate_references,_schema_path
from htgl_dataset_generator.artifacts.canonical import canonical_json_bytes as legacy_canonical
from paeforge_contract import build_case_manifest,build_observer_projection,build_receipt_stream
from paeforge_contract.canonical import domain_digest
from paeforge_pipeline.projection import build_projection,translated_policy

from .oracle import encode,evaluate,instant,_digest

FORMAT='GRIDWEAVE-ED25519-E2-v1'
OPERATIONS=('omit_one','omit_all','conflict','signature_tamper','scope_gap',
            'lineage_gap','pre_deadline','expiry_crossing','permutation','hidden_copy_twin')
AUDIT_OPERATIONS=('exact_expiry','baseline_timing_precedence','future_event')


def token(*parts):return sha256(encode(parts)).hexdigest()[:32]


def _stamp(value):return value.isoformat(timespec='microseconds').replace('+00:00','Z')


def _key(seed,principal):
    return Ed25519PrivateKey.from_private_bytes(sha256(encode(('gridweave-synthetic-key-v1',seed,principal))).digest())


def _public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()


def sign(observer,stream,seed):
    principals={r['custodian_principal_id'] for r in observer['topology']['repositories']}
    authorities={'AUTHORITY-RETENTION-REVIEW'}
    context={'version':FORMAT,'principal_public_keys':{p:_public(_key(seed,p)) for p in sorted(principals)},
             'exception_authority_public_keys':{p:_public(_key(seed,p)) for p in sorted(authorities)},
             'exception_signatures':{}}
    for row in stream['receipts']:
        claim={k:v for k,v in row.items() if k not in {'proof','sequence','claim_commitment'}}
        key=_key(seed,row['issuer_principal_id'])
        row['claim_commitment']=sha256(encode(claim)).hexdigest()
        row['proof']={'format':FORMAT,'credential_ref':'ed25519:'+_public(key),
                      'verification_material_refs':['ed25519-signature:'+key.sign(encode(claim)).hex()]}
    for row in observer['exceptions']:
        context['exception_signatures'][row['exception_id']]=_key(seed,row['authority_principal_id']).sign(encode(row)).hex()
    return context


def refresh(bundle):
    m,o,s=bundle
    semantic={k:o[k] for k in ('observer','policy','case','topology','exceptions','challenges')}
    o['projection_commitment']=domain_digest('paeforge-observer-projection-v1',semantic)
    for i,row in enumerate(s['receipts']):row['sequence']=i
    s['stream_commitment']=domain_digest('paeforge-receipt-stream-v1',s['receipts'])
    m=build_case_manifest(exchange_id=m['exchange_id'],run_id=m['run_id'],scenario_id=m['scenario_id'],
                          case_id=m['case_id'],seed=m['seed'],policy=m['policy'],observer_projection=o,
                          receipt_stream=s,provenance=m['provenance'])
    return [m,o,s]


def scaled_definition(definition,scale):
    p=deepcopy(definition.payload)
    # New explicitly declared profile; historical E3/E4 scenario files are untouched.
    p['policy_profile']['evidence_floor']='E2'
    p['policy_profile']['profile_id']+='-GRIDWEAVE02'
    # The retained scenario-interface schema fixes its policy version at v1;
    # the new profile ID, package version and signed-E2 contract distinguish it.
    p['policy_profile']['version']='1.0.0'
    for repo in p['repositories']:repo['observable']=True
    p['observable_metadata']['claim_disposition_visibility']='visible'
    assets=[];obligations=[];exceptions=[]
    for i in range(scale):
        suffix=f'-GW{i:04d}'
        for source in definition.payload['assets']:
            row=deepcopy(source);row['asset_id']+=suffix
            row['parent_asset_ids']=[x+suffix for x in row['parent_asset_ids']];assets.append(row)
        for source in definition.payload['obligations']:
            row=deepcopy(source);row['template_id']+=suffix
            row['asset_ids']=[x+suffix for x in row['asset_ids']];obligations.append(row)
        for source in definition.payload['exceptions']:
            row=deepcopy(source);row['exception_id']+=suffix;row['applies_to_obligation_id']+=suffix;exceptions.append(row)
    p['assets']=assets;p['obligations']=obligations;p['exceptions']=exceptions
    for row in p['variants']:
        row['mutations']=[dict(x,target_obligation_id=x['target_obligation_id']+f'-GW{i:04d}')
                          for i in range(scale) for x in row['mutations']]
    import json
    Draft202012Validator(json.loads(_schema_path().read_text())).validate(p)
    _validate_references(p)
    return SmartGridScenarioDefinition(definition.scenario_id,p,sha256(legacy_canonical(p)).hexdigest(),definition.source_path)


def base_case(definition,scale,seed,source_revision):
    d=scaled_definition(definition,scale)
    replica=compile_smart_grid_benchmark([d],root_seed=seed).replicas[0]
    policy=translated_policy(d.payload)
    ref={'profile_id':policy['profile_id'],'version':policy['version'],
         'sha256':_digest('verclo-policy-profile-v1',policy),'minimum_evidence_grade':'E2'}
    projection=build_projection(scenario=d.payload,paegen_replica=replica,observer_profile_id='OBS-SG-AUDITOR',
                  projection_config={'expose_visible_repository_bindings':True,'access_class':'restricted',
                                     'profile_id':'GRIDWEAVE-SIGNED-E2-v1','profile_version':'0.2.0',
                                     'scope_completeness_mode':'source_audited'},
                  policy_ref=ref,root_seed=seed,paegen_source_revision=source_revision,
                  generated_at=d.payload['time_origin'])
    bundle=deepcopy([projection.manifest,projection.observer_projection,projection.receipt_stream])
    bundle[1]['evaluation_time']=_stamp(instant(bundle[1]['case']['accepted_at'])+
                                     timedelta(hours=policy['default_rule']['deadline_hours']+2))
    context=sign(bundle[1],bundle[2],seed);bundle=refresh(bundle)
    truth=evaluate(bundle[1],bundle[2],policy,context)
    if truth['outcome'] not in {'CLOSED','CLOSED_WITH_EXCEPTIONS'}:
        raise ValueError('reference profile does not close under signed E2: '+d.scenario_id+' '+str(truth))
    return bundle,policy,context


def make_pair(base,policy,seed,operation,family,scale):
    control=deepcopy(base);challenge=deepcopy(base)
    o=challenge[1];s=challenge[2]
    excepted={r['obligation_id'] for r in o['exceptions']}
    target=next(r['obligation_id'] for r in s['receipts'] if r['obligation_id'] not in excepted)
    rows=[r for r in s['receipts'] if r['obligation_id']==target]
    if operation=='omit_one':s['receipts']=[r for r in s['receipts'] if r['obligation_id']!=target]
    elif operation=='omit_all':s['receipts']=[];o['exceptions']=[]
    elif operation=='conflict':
        row=deepcopy(rows[0]);row['receipt_id']='RCP-'+token(seed,operation,target).upper();row['disposition']='FAILED';s['receipts'].append(row)
    elif operation=='scope_gap':o['topology']['declared_scope_complete']=False
    elif operation=='lineage_gap':
        if not o['topology']['lineage_edges']:return None
        # Keep the old scope commitment: this is an authenticated-scope defect,
        # not a claim that undisclosed operational lineage is discoverable.
        o['topology']['lineage_edges'].pop()
    elif operation in {'pre_deadline','baseline_timing_precedence'}:
        o['evaluation_time']=_stamp(instant(o['case']['accepted_at'])+
            timedelta(hours=policy['default_rule']['deadline_hours'])-timedelta(microseconds=1))
        if operation=='baseline_timing_precedence':o['topology']['declared_scope_complete']=False
    elif operation in {'expiry_crossing','exact_expiry'}:
        expiry=instant(o['evaluation_time'])+timedelta(hours=1)
        exception={'exception_id':'EXC-'+token(seed,target,'expiry').upper(),'obligation_id':target,
                   'authority_principal_id':'AUTHORITY-RETENTION-REVIEW',
                   'basis_commitment':sha256(encode(('synthetic-bounded-retention',target))).hexdigest(),
                   'effective_at':o['case']['accepted_at'],'expires_at':_stamp(expiry)}
        for b in (control,challenge):
            b[1]['exceptions'].append(deepcopy(exception))
            b[2]['receipts']=[r for r in b[2]['receipts'] if r['obligation_id']!=target]
        control[1]['evaluation_time']=_stamp(expiry-timedelta(microseconds=1))
        o['evaluation_time']=_stamp(expiry if operation=='exact_expiry' else expiry+timedelta(microseconds=1))
    elif operation=='permutation':
        for name in ('assets','repositories','replicas','lineage_edges'):o['topology'][name].reverse()
        s['receipts'].reverse()
    elif operation=='future_event':rows[0]['event_time']=_stamp(instant(o['evaluation_time'])+timedelta(hours=1))
    elif operation not in {'signature_tamper','hidden_copy_twin'}:raise ValueError(operation)
    contexts=[sign(b[1],b[2],seed) for b in (control,challenge)]
    if operation=='signature_tamper':
        ref=rows[0]['proof']['verification_material_refs'][0]
        rows[0]['proof']['verification_material_refs']=[ref[:-2]+('ff' if ref[-2:]!='ff' else '00')]
    bundles=[refresh(b) for b in (control,challenge)]
    truths=[evaluate(b[1],b[2],policy,c) for b,c in zip(bundles,contexts)]
    if operation in {'permutation','hidden_copy_twin'} and truths[0]!=truths[1]:raise AssertionError('metamorphic invariant violated')
    if operation=='hidden_copy_twin' and encode(bundles[0])!=encode(bundles[1]):raise AssertionError('latent twins differ publicly')
    pid=token(seed,family,scale,operation,'pair')
    units=[]
    for i,(bundle,context,truth) in enumerate(zip(bundles,contexts,truths)):
        uid=token(seed,pid,i,'unit')
        units.append({'unit_id':uid,'bundle':bundle,'context':context,'policy':policy,'truth':truth,
                      'world_truth':{'undeclared_copy_present':operation=='hidden_copy_twin' and i==1}})
    tags={f'operation:{operation}',f'family:{family}',f'scale:{scale}'}|{'outcome:'+t['outcome'] for t in truths}
    cost=sum(sum(len(encode(x)) for x in u['bundle'])+len(encode(u['context']))+len(encode(policy)) for u in units)
    return {'pair_id':pid,'family':family,'scale':scale,'operation':operation,'tags':sorted(tags),'cost':cost,'units':units}


def candidates(seed,scales,source_revision,include_audit=False,scenario_ids=None):
    definitions=load_smart_grid_scenarios()
    if scenario_ids:
        unknown=set(scenario_ids)-{d.scenario_id for d in definitions}
        if unknown:raise ValueError('unknown scenarios: '+repr(sorted(unknown)))
        definitions=tuple(d for d in definitions if d.scenario_id in scenario_ids)
    families=sorted(token('source-family-v1',d.sha256) for d in definitions)
    # Partition is independent of seed, scale, mutation and closure label.
    partitions={f:('train','validation','test')[i%3] for i,f in enumerate(families)}
    for d in definitions:
        family=token('source-family-v1',d.sha256)
        for scale in scales:
            base,policy,_=base_case(d,scale,seed,source_revision)
            for op in (*OPERATIONS,*(AUDIT_OPERATIONS if include_audit else ())):
                pair=make_pair(base,policy,seed,op,family,scale)
                if pair:
                    pair['split']=partitions[family];yield pair
