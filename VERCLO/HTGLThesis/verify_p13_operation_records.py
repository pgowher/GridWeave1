#!/usr/bin/env python3
"""Verify P13 v2 operation certificates without importing the live adapter.

The supplied trust-context file maps epoch to validator public keys and must be
pinned from the experiment deployment configuration. This verifies recorded
signatures, not geographic independence, unobserved execution or universal safety.
"""
import argparse
import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FLAGS = ('verification_material_available','credential_valid_at_event','authenticator_valid',
    'anchor_valid','ordering_support_valid','mechanism_present','mechanism_valid','assumptions_valid')


def canonical(value, *, receipt=False):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=not receipt).encode()


def digest(domain,value,*,receipt=False):
    return hashlib.sha256(domain.encode()+b'\0'+canonical(value,receipt=receipt)).hexdigest()


def decode(value):
    if type(value) is not str or '=' in value: raise ValueError('invalid base64url')
    raw=base64.b64decode(value+'='*(-len(value)%4),altchars=b'-_',validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode()!=value: raise ValueError('noncanonical base64url')
    return raw


def verify_record(row, contexts):
    cert=row['certificate']
    if not isinstance(cert,dict):
        if row['accepted']: raise ValueError('accepted operation lacks certificate')
        return None
    epoch=row['expected_epoch']
    keys=contexts[epoch]
    if keys != row['public_keys'] or cert['membership_epoch'] != epoch:
        raise ValueError('untrusted committee or epoch')
    n=len(keys)
    if n<4 or (n-1)%3 or len(set(keys.values()))!=n: raise ValueError('invalid committee')
    committee=digest('VERCLO-PBFT-COMMITTEE-v2',keys)
    receipt=dict(row['receipt'])
    for name in ('event_time','submitted_at','not_before','expires_at'):
        if receipt[name] is not None:
            receipt[name]=datetime.fromisoformat(receipt[name]).isoformat(timespec='microseconds').replace('+00:00','Z')
    receipt_hash=digest('verclo-custodian-receipt-v1',receipt,receipt=True)
    if cert['receipt_commitment'] != receipt_hash: raise ValueError('receipt binding mismatch')
    facts={name:cert[name] for name in FLAGS}
    if any(type(v) is not bool for v in facts.values()): raise ValueError('nonboolean decision fact')
    if not isinstance(cert['diagnostics'],list) or any(type(x) is not str for x in cert['diagnostics']):
        raise ValueError('invalid diagnostics')
    expiry=cert['mechanism_expires_at']
    if expiry is not None and (type(expiry) is not str or datetime.fromisoformat(expiry).utcoffset() is None):
        raise ValueError('invalid expiry')
    facts.update(schema='verclo.validation-decision.v2',mechanism_expires_at=expiry,diagnostics=cert['diagnostics'])
    decision=digest('VERCLO-VALIDATION-DECISION-v2',facts)
    sequence,view=cert['sequence'],cert['view']
    if type(sequence) is not int or sequence<1 or type(view) is not int or view<0: raise ValueError('invalid position')
    if sorted(cert['validator_ids'])!=sorted(keys): raise ValueError('validator set mismatch')
    quorum=2*((n-1)//3)+1
    counts={}
    for phase,field in (('COMMIT','signed_commit_votes'),('FINALIZE','signed_finalize_votes')):
        seen=set()
        for vote in cert[field]:
            identity=vote['validator_id']
            if identity in seen or identity not in keys: raise ValueError('duplicate or unknown signer')
            expected=dict(validator_id=identity,phase=phase,view=view,sequence=sequence,
                receipt_commitment=receipt_hash,decision_commitment=decision,membership_epoch=epoch,
                committee_digest=committee)
            supplied={k:v for k,v in vote.items() if k!='signature'}
            if supplied!=expected or type(vote['view']) is not int or type(vote['sequence']) is not int:
                raise ValueError('vote binding mismatch')
            Ed25519PublicKey.from_public_bytes(decode(keys[identity])).verify(
                decode(vote['signature']),b'VERCLO-PBFT-VOTE-v2\0'+canonical(expected))
            seen.add(identity)
        counts[phase]=len(seen)
        if phase=='COMMIT' and sorted(seen)!=sorted(cert['approving_validator_ids']):
            raise ValueError('approval set mismatch')
    certificate_valid=all(count>=quorum for count in counts.values())
    material=certificate_valid and cert['verification_material_available']
    if type(row['accepted']) is not bool or row['accepted'] != material: raise ValueError('acceptance mismatch')
    validation=row['validation']
    if validation:
        for flag in FLAGS:
            expected=material if flag=='verification_material_available' else cert[flag]
            if validation[flag] is not expected: raise ValueError('transport changed decision facts')
    if row['cost']['sequence']!=sequence or row['cost']['view']!=view: raise ValueError('cost belongs to another operation')
    if row['cost']['commit_votes']!=counts['COMMIT'] or row['cost']['finalized_acks']!=counts['FINALIZE']:
        raise ValueError('cost vote counts mismatch')
    return (epoch,committee,sequence,receipt_hash,decision) if certificate_valid else None


def verify_records(rows,contexts):
    finalized={}; seen=set(); signatures=0; accepted=0
    for row in rows:
        operation=row['operation_id']
        if operation in seen: raise ValueError('duplicate operation identifier')
        seen.add(operation)
        key=verify_record(row,contexts)
        if key:
            context,value=key[:3],key[3:]
            if context in finalized and finalized[context]!=value: raise ValueError('conflicting finalized sequence')
            finalized[context]=value
            signatures+=len(row['certificate']['signed_commit_votes'])+len(row['certificate']['signed_finalize_votes'])
        accepted+=row['accepted']
    return dict(status='PASS',operations=len(rows),accepted=accepted,rejected=len(rows)-accepted,
        verified_signatures=signatures,finalized_sequences=len(finalized),
        scope='Offline verification against supplied pinned public keys; no independent hardware or WAN attestation')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('records',type=Path)
    p.add_argument('--trusted-contexts',type=Path,required=True)
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    rows=[json.loads(line) for line in args.records.read_text().splitlines() if line.strip()]
    report=verify_records(rows,json.loads(args.trusted_contexts.read_text()))
    report['records_sha256']=hashlib.sha256(args.records.read_bytes()).hexdigest()
    report['trusted_contexts_sha256']=hashlib.sha256(args.trusted_contexts.read_bytes()).hexdigest()
    value=json.dumps(report,indent=2)+'\n'
    if args.output:
        with args.output.open('x') as f:f.write(value)
    print(value,end='')
    return 0


if __name__=='__main__':raise SystemExit(main())
