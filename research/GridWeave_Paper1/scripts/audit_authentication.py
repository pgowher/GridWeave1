#!/usr/bin/env python3
"""Check saved receipt signatures without importing GridWeave or its oracle.

Checks signature, claim digest, pinned issuer key and credential key binding.
Does NOT adjudicate time, obligation scope, policy sufficiency or final labels.
"""
import argparse,hashlib,json
from collections import Counter,defaultdict
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def read(p):return json.loads(p.read_text())
def encode(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dataset',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
 root=a.dataset;counts=Counter();by_unit={};pairs=read(root/'sealed/pairs.json')
 for entry in read(root/'public/index.json')['cases']:
  uid=entry['unit_id'];context=read(root/'public/configuration'/uid/'verification-context.json');stream=read(root/'public/cases'/uid/'receipt-stream.json');c=Counter()
  for row in stream['receipts']:
   payload={k:v for k,v in row.items() if k not in ['proof','sequence','claim_commitment']};b=encode(payload);proof=row['proof'];key=context['principal_public_keys'].get(row['issuer_principal_id'])
   sigs=[s.removeprefix('ed25519-signature:') for s in proof['verification_material_refs'] if s.startswith('ed25519-signature:')]
   ok=bool(key and len(sigs)==1 and proof['credential_ref']=='ed25519:'+key and row['claim_commitment']==hashlib.sha256(b).hexdigest())
   if ok:
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(sigs[0]),b)
    except (InvalidSignature,ValueError,TypeError):ok=False
   c['valid' if ok else 'invalid']+=1
  counts.update(c);by_unit[uid]=dict(c)
 summary=[]
 for op in sorted({p['operation'] for p in pairs}):
  control=Counter();challenge=Counter()
  for p in pairs:
   if p['operation']==op:
    control.update(by_unit[p['unit_ids'][0]]);challenge.update(by_unit[p['unit_ids'][1]])
  summary.append(dict(operation=op,control=dict(control),challenge=dict(challenge)))
 for p in pairs:
  c=by_unit[p['unit_ids'][1]]
  if p['operation']=='signature_tamper':assert c.get('invalid',0)==1
  elif p['operation']=='conflict':assert c.get('invalid',0)==0
 report=dict(date='2026-11-05',manifest_sha256=hashlib.sha256((root/'dataset-manifest.json').read_bytes()).hexdigest(),method='Standalone cryptography Ed25519 verification with explicit payload canonicalization; no generator or oracle imports',scope='Cryptographic receipt checks only; not independent semantic labels or physical action verification',counts=dict(counts),operation_counts=summary,per_unit=by_unit)
 a.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['counts','scope','operation_counts']},indent=2))

if __name__=='__main__':main()
