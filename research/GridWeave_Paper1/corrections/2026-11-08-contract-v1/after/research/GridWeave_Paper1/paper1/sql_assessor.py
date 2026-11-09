"""RelationalSpec: recursive SQLite reachability and relational evidence joins.

Shares wire utilities and envelope/profile admission with GraphSpec. Assessment, scope reconstruction,
receipt checking and category aggregation do not call either existing oracle.
"""
import sqlite3
from datetime import timedelta
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .wire import canonical,domain,instant

REACH_SQL='''WITH RECURSIVE reach(asset) AS (
 SELECT asset FROM roots UNION SELECT e.child FROM edges e JOIN reach ON e.parent=reach.asset
) SELECT c.replica,c.asset,c.repository,r.principal,a.kind,c.kind
FROM copies c JOIN reach ON reach.asset=c.asset JOIN assets a ON a.asset=c.asset
JOIN repositories r ON r.repository=c.repository
WHERE asset_applies(a.kind) AND replica_applies(c.kind)'''
CATEGORY_SQL='''SELECT o.oid,
 CASE WHEN count(DISTINCT CASE WHEN v.valid=1 AND v.terminal=1 THEN v.disposition END)>1 THEN 'CONTRADICTORY'
 WHEN EXISTS(SELECT 1 FROM exceptions x WHERE x.oid=o.oid AND x.auth=1 AND x.effective<=:deadline AND x.effective<=:now AND :now<x.expiry) THEN 'EXCEPTED'
 WHEN max(CASE WHEN v.valid=1 AND v.terminal=1 AND v.event<=:deadline AND v.permitted=1 THEN 1 ELSE 0 END)=1 THEN 'COVERED'
 WHEN max(CASE WHEN v.valid=1 AND v.terminal=1 AND v.event>:deadline THEN 1 ELSE 0 END)=1 THEN 'LATE'
 WHEN count(v.rid)=0 THEN 'MISSING' ELSE 'INVALID' END AS category
FROM obligations o LEFT JOIN validated v ON o.oid=v.oid GROUP BY o.oid ORDER BY o.oid'''
OUTCOME_SQL='''SELECT CASE WHEN :now<:deadline THEN 'IN_PROGRESS'
 WHEN :baseline=0 THEN 'UNVERIFIABLE'
 WHEN EXISTS(SELECT 1 FROM categories WHERE category='CONTRADICTORY') OR :open_challenge=1 THEN 'DISPUTED'
 WHEN NOT EXISTS(SELECT 1 FROM categories WHERE category!='COVERED') THEN 'CLOSED'
 WHEN NOT EXISTS(SELECT 1 FROM categories WHERE category NOT IN ('COVERED','EXCEPTED')) THEN 'CLOSED_WITH_EXCEPTIONS'
 WHEN EXISTS(SELECT 1 FROM categories WHERE category IN ('COVERED','EXCEPTED')) THEN 'PARTIALLY_CLOSED'
 ELSE 'OPEN' END'''


def _authenticate(key,signature,payload):
    if not key or not signature:return False
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature),canonical(payload))
    except (ValueError,TypeError,InvalidSignature):return False
    return True

def _microseconds(value):
    from datetime import datetime,timezone
    delta=instant(value)-datetime(1970,1,1,tzinfo=timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000+delta.microseconds

def _scope_ok(observer):
    t=observer['topology'];c=observer['case'];record={'case_id':observer['case_id'],'dataset_id':c['dataset_id'],'correlation_id':c['correlation_id'],'scope_version':t['scope_version']}
    for name,key in [('assets','asset_id'),('repositories','repository_id'),('replicas','replica_id'),('lineage_edges','relationship_id')]:record[name]=sorted(t[name],key=lambda r:r[key])
    return t.get('scope_commitment') == domain('verclo-visible-scope-v1',record)

def assess(observer,stream,policy,context):
    top=observer['topology'];case=observer['case'];now=_microseconds(observer['evaluation_time']);deadline=_microseconds(case['accepted_at'])+int(policy['default_rule']['deadline_hours']*3600*1000000)
    con=sqlite3.connect(':memory:')
    try:
        con.executescript('''CREATE TABLE assets(asset TEXT PRIMARY KEY,kind TEXT);CREATE TABLE repositories(repository TEXT PRIMARY KEY,principal TEXT);
        CREATE TABLE copies(replica TEXT PRIMARY KEY,asset TEXT,repository TEXT,kind TEXT);CREATE TABLE edges(parent TEXT,child TEXT);
        CREATE TABLE roots(asset TEXT PRIMARY KEY);CREATE TABLE obligations(oid TEXT PRIMARY KEY,asset TEXT,replica TEXT,repository TEXT,principal TEXT);
        CREATE TABLE claims(rid TEXT PRIMARY KEY,oid TEXT,asset TEXT,replica TEXT,repository TEXT,issuer TEXT,caseid TEXT,disposition TEXT,event INTEGER,terminal INTEGER,permitted INTEGER,auth INTEGER,timeok INTEGER);
        CREATE TABLE exceptions(oid TEXT PRIMARY KEY,auth INTEGER,effective INTEGER,expiry INTEGER);CREATE TABLE categories(oid TEXT PRIMARY KEY,category TEXT);''')
        con.executemany('INSERT INTO assets VALUES(?,?)',[(r['asset_id'],r['asset_kind']) for r in top['assets']]);con.executemany('INSERT INTO repositories VALUES(?,?)',[(r['repository_id'],r['custodian_principal_id']) for r in top['repositories']]);con.executemany('INSERT INTO copies VALUES(?,?,?,?)',[(r['replica_id'],r['asset_id'],r['repository_id'],r['replica_class']) for r in top['replicas']]);con.executemany('INSERT INTO edges VALUES(?,?)',[(r['parent_asset_id'],r['child_asset_id']) for r in top['lineage_edges']]);con.executemany('INSERT INTO roots VALUES(?)',[(r,) for r in case['root_asset_ids']])
        if len({r['relationship_id'] for r in top['lineage_edges']})!=len(top['lineage_edges']):raise ValueError('Duplicate lineage identity')
        if con.execute('SELECT count(*) FROM edges WHERE parent NOT IN (SELECT asset FROM assets) OR child NOT IN (SELECT asset FROM assets)').fetchone()[0] or con.execute('SELECT count(*) FROM copies WHERE asset NOT IN (SELECT asset FROM assets) OR repository NOT IN (SELECT repository FROM repositories)').fetchone()[0]:raise ValueError('Dangling topology')
        if con.execute('WITH RECURSIVE paths(a,b) AS (SELECT parent,child FROM edges UNION SELECT paths.a,edges.child FROM paths JOIN edges ON paths.b=edges.parent) SELECT count(*) FROM paths WHERE a=b').fetchone()[0]:raise ValueError('Cyclic lineage')
        con.create_function('asset_applies',1,lambda k:'*' in policy['applicable_asset_kinds'] or k in policy['applicable_asset_kinds']);con.create_function('replica_applies',1,lambda k:k in policy['applicable_replica_classes'])
        for replica,asset,repository,principal,_,_ in con.execute(REACH_SQL).fetchall():
            subject=dict(case_id=observer['case_id'],dataset_id=case['dataset_id'],correlation_id=case['correlation_id'],asset_id=asset,replica_id=replica,repository_id=repository,custodian_principal_id=principal,policy_profile_id=policy['profile_id'],policy_version=policy['version'])
            oid='OBL-'+domain('verclo-obligation-v1',subject)[:32].upper();con.execute('INSERT INTO obligations VALUES(?,?,?,?,?)',(oid,asset,replica,repository,principal))
        for r in stream['receipts']:
            payload=dict(r)
            for field in ('proof','sequence','claim_commitment'):payload.pop(field,None)
            proof=r['proof'];key=context['principal_public_keys'].get(r['issuer_principal_id'],'');references=[x[len('ed25519-signature:'):] for x in proof['verification_material_refs'] if x.startswith('ed25519-signature:')]
            auth=bool(len(references)==1 and key and r['provenance_refs'] and proof['format']=='GRIDWEAVE-ED25519-E2-v1' and proof.get('credential_ref')=='ed25519:'+key and sha256(canonical(payload)).hexdigest()==r['claim_commitment'] and _authenticate(key,references[0],payload))
            timeok=_microseconds(r['event_time'])<=_microseconds(r['submitted_at'])<=now and _microseconds(r['not_before'])<=now and ('expires_at' not in r or now<_microseconds(r['expires_at']))
            values=(r['receipt_id'],r['obligation_id'],r['asset_id'],r['replica_id'],r['repository_id'],r['issuer_principal_id'],r['case_id'],r['disposition'],_microseconds(r['event_time']),r['evidence_type'] in {'signature','deletion_acknowledgement','replica_attestation','audit_finding'},r['disposition'] in policy['default_rule']['permitted_dispositions'],auth,timeok)
            con.execute('INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',values)
        for x in observer['exceptions']:
            key=context['exception_authority_public_keys'].get(x['authority_principal_id'],'');sig=context['exception_signatures'].get(x['exception_id'],'')
            auth=bool(x['authority_principal_id'] in policy['exception_authority_ids'] and _authenticate(key,sig,x))
            con.execute('INSERT OR IGNORE INTO exceptions VALUES(?,?,?,?)',(x['obligation_id'],auth,_microseconds(x['effective_at']),_microseconds(x['expires_at'])))
        con.execute('''CREATE VIEW validated AS SELECT c.*, CASE WHEN c.auth=1 AND c.timeok=1 AND c.caseid=expected_case() AND c.asset=o.asset AND c.replica=o.replica AND c.repository=o.repository AND c.issuer=o.principal THEN 1 ELSE 0 END AS valid FROM claims c JOIN obligations o ON o.oid=c.oid''')
        con.create_function('expected_case',0,lambda:observer['case_id'])
        params={'now':now,'deadline':deadline};categories=dict(con.execute(CATEGORY_SQL,params).fetchall());con.executemany('INSERT INTO categories VALUES(?,?)',categories.items())
        roots_known=not con.execute('SELECT count(*) FROM roots WHERE asset NOT IN (SELECT asset FROM assets)').fetchone()[0]
        baseline=bool(top['graph_available'] and top.get('declared_scope_complete') and not top['unresolved_reference_ids'] and roots_known and _scope_ok(observer) and categories)
        params.update(baseline=baseline,open_challenge=any(x['status']=='OPEN' for x in observer['challenges']))
        outcome=con.execute(OUTCOME_SQL,params).fetchone()[0]
        diagnoses={rid:('AUTHENTICATED_E2' if valid else 'REJECTED') for rid,valid in con.execute('SELECT rid,valid FROM validated')}
        return dict(outcome=outcome,baseline_verifiable=baseline,obligation_categories=categories,receipt_diagnoses=dict(sorted(diagnoses.items())))
    finally:con.close()
