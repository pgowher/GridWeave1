"""Real Ed25519 validation for explicitly configured synthetic GridWeave worlds.

Trust roots are run configuration, not keys asserted by a receipt. No ordering,
mechanism or physical deletion capability is fabricated. This profile supports
E2, never upgrades a bare signature to E3/E4/E5.
"""
from hashlib import sha256
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from paeforge_contract.canonical import canonical_json_bytes

FORMAT='GRIDWEAVE-ED25519-E2-v1'
BACKEND='gridweave-ed25519-e2-v1'
_KEY={'type':'string','pattern':'^[0-9a-f]{64}$'}
CONTEXT_SCHEMA={'type':'object','additionalProperties':False,
 'required':['version','principal_public_keys','exception_authority_public_keys','exception_signatures'],
 'properties':{'version':{'const':FORMAT},
 'principal_public_keys':{'type':'object','additionalProperties':_KEY},
 'exception_authority_public_keys':{'type':'object','additionalProperties':_KEY},
 'exception_signatures':{'type':'object','additionalProperties':{'type':'string','pattern':'^[0-9a-f]{128}$'}}}}


def _verify(key,signature,claim):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature),canonical_json_bytes(claim))
        return True
    except (TypeError,ValueError,InvalidSignature):return False


def validation_facts(observer,stream,context):
    from evidence import BackendValidation,ExceptionValidation
    Draft202012Validator(CONTEXT_SCHEMA).validate(context)
    repos={x['repository_id']:x for x in observer['topology']['repositories']}
    checks={}
    for row in stream['receipts']:
        proof=row['proof'];key=context['principal_public_keys'].get(row['issuer_principal_id'])
        signatures=[x.removeprefix('ed25519-signature:') for x in proof['verification_material_refs'] if x.startswith('ed25519-signature:')]
        available=bool(key and len(signatures)==1 and proof['format']==FORMAT)
        principal_bound=bool(row['repository_id'] in repos and
                             repos[row['repository_id']]['custodian_principal_id']==row['issuer_principal_id'])
        credential=bool(available and principal_bound and proof.get('credential_ref')=='ed25519:'+key)
        claim={k:v for k,v in row.items() if k not in {'proof','sequence','claim_commitment'}}
        authenticated=bool(credential and row['claim_commitment']==sha256(canonical_json_bytes(claim)).hexdigest() and
                           _verify(key,signatures[0],claim))
        checks[row['receipt_id']]=BackendValidation(
            backend_name=BACKEND,verification_material_available=available,
            credential_valid_at_event=credential,authenticator_valid=authenticated,
            anchor_valid=False,ordering_support_valid=False,mechanism_present=False,
            mechanism_valid=False,assumptions_valid=True,
            diagnostics=('REAL_ED25519_CHECK','SYNTHETIC_WORLD_TRUST_ROOTS','NO_ORDERING_OR_ERASURE_ATTESTATION'))
    exceptions={}
    for row in observer['exceptions']:
        key=context['exception_authority_public_keys'].get(row['authority_principal_id'],'')
        signature=context['exception_signatures'].get(row['exception_id'],'')
        ok=bool(key and _verify(key,signature,row))
        exceptions[row['exception_id']]=ExceptionValidation(row['exception_id'],ok,ok,bool(key),('REAL_ED25519_EXCEPTION_CHECK',))
    return checks,exceptions
