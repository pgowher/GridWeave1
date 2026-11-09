#!/usr/bin/env python3
"""Read-only corpus census, exact graph-equivalence counts and audit checks.

Uses no GridWeave oracle or generator. Graph classes ignore identifiers. Asset
DAG classes retain directed lineage only. Custody classes additionally retain
assets, replicas, repositories, custodians and relation types. Semantic custody
classes also retain asset kind, replica class and repository class. Flags,
times, policy, roots and receipts are NOT part of graph equivalence.
"""
import argparse, csv, hashlib, json
from collections import Counter, defaultdict
from pathlib import Path


def read(p): return json.loads(p.read_text())
def digest(b): return hashlib.sha256(b).hexdigest()
def encoded(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()


def graph(top, mode):
    nodes={}; edges={}
    for a in top['assets']:
        nodes['a:'+a['asset_id']]='asset'+(':'+a['asset_kind'] if mode=='semantic' else '')
    for e in top['lineage_edges']:
        edges['a:'+e['parent_asset_id'],'a:'+e['child_asset_id']]='lineage'
    if mode!='asset':
        for r in top['repositories']:
            nodes['r:'+r['repository_id']]='repository'+(':'+r['repository_class'] if mode=='semantic' else '')
            nodes['p:'+r['custodian_principal_id']]='custodian'
            edges['r:'+r['repository_id'],'p:'+r['custodian_principal_id']]='custodian'
        for r in top['replicas']:
            nodes['c:'+r['replica_id']]='replica'+(':'+r['replica_class'] if mode=='semantic' else '')
            edges['a:'+r['asset_id'],'c:'+r['replica_id']]='replica'
            edges['c:'+r['replica_id'],'r:'+r['repository_id']]='repository'
    return nodes,edges


def local_signatures(g):
    n,e=g
    return {v:(n[v],tuple(sorted(Counter((t,n[b]) for (a,b),t in e.items() if a==v).items())),
                    tuple(sorted(Counter((t,n[a]) for (a,b),t in e.items() if b==v).items()))) for v in n}


def invariant(g):
    return (len(g[0]),len(g[1]),tuple(sorted(Counter(local_signatures(g).values()).items())))


def isomorphic(g,h):
    if invariant(g)!=invariant(h): return False
    gn,ge=g; hn,he=h
    gs=local_signatures(g); hs=local_signatures(h)
    choices={a:[b for b in hn if gs[a]==hs[b]] for a in gn}
    mapping={}; used=set()
    def match():
        if len(mapping)==len(gn): return True
        remaining=[a for a in gn if a not in mapping]
        a=min(remaining,key=lambda a:(sum(b not in used for b in choices[a]),
             -sum((a,x) in ge or (x,a) in ge for x in mapping)))
        for b in choices[a]:
            if b in used: continue
            if ge.get((a,a))!=he.get((b,b)): continue
            if any(ge.get((a,x))!=he.get((b,y)) or ge.get((x,a))!=he.get((y,b)) for x,y in mapping.items()): continue
            mapping[a]=b;used.add(b)
            if match(): return True
            del mapping[a];used.remove(b)
        return False
    return match()


class Classes:
    def __init__(self): self.groups=defaultdict(list);self.count=0
    def add(self,g):
        bucket=self.groups[invariant(g)]
        for representative,label in bucket:
            if isomorphic(g,representative):return label
        self.count+=1;label=self.count;bucket.append((g,label));return label


def graph_checks():
    g=({'a':'asset','b':'asset','c':'asset'},{('a','b'):'lineage',('b','c'):'lineage'})
    h=({'x':'asset','y':'asset','z':'asset'},{('x','y'):'lineage',('y','z'):'lineage'})
    assert isomorphic(g,h)
    assert not isomorphic(g,(h[0],{('x','y'):'lineage',('x','z'):'lineage'}))
    cycle=({str(i):'x' for i in range(6)},{(str(i),str((i+1)%6)):'e' for i in range(6)})
    triangles=(cycle[0],{(str(i),str((i//3)*3+(i+1)%3)):'e' for i in range(6)})
    assert invariant(cycle)==invariant(triangles) and not isomorphic(cycle,triangles)


def structure_metrics(top):
    nodes={a['asset_id'] for a in top['assets']};children=defaultdict(list);indeg=Counter()
    for e in top['lineage_edges']:
        children[e['parent_asset_id']].append(e['child_asset_id']);indeg[e['child_asset_id']]+=1
    queue=[a for a in nodes if not indeg[a]];depth={a:0 for a in queue};processed=0
    for a in queue:
        processed+=1
        for b in children[a]:
            depth[b]=max(depth.get(b,0),depth[a]+1);indeg[b]-=1
            if indeg[b]==0:queue.append(b)
    assert processed==len(nodes), 'cycle in asset graph'
    return dict(assets=len(nodes),replicas=len(top['replicas']),repositories=len(top['repositories']),
        custodians=len({r['custodian_principal_id'] for r in top['repositories']}),
        max_replicas_per_asset=max(Counter(r['asset_id'] for r in top['replicas']).values(),default=0),
        lineage_edges=len(top['lineage_edges']),lineage_depth=max(depth.values(),default=0),
        max_lineage_fanout=max(map(len,children.values()),default=0))


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dataset',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--source-root',type=Path);args=ap.parse_args()
    graph_checks();root=args.dataset.resolve();out=args.out;out.mkdir(parents=True,exist_ok=True)
    manifest=read(root/'dataset-manifest.json');pairs=read(root/'sealed/pairs.json');index=read(root/'public/index.json')['cases']
    by_id={x['unit_id']:x for x in index};assert len(by_id)==len(index)
    roles={uid:(role,p) for p in pairs for uid,role in zip(p['unit_ids'],['control','challenge'])}
    assert len(roles)==2*len(pairs)==len(index)
    classes={k:Classes() for k in ['asset','custody','semantic']};input_hashes={};case_rows=[];truths={};family_splits=defaultdict(set)
    for entry in index:
        uid=entry['unit_id'];role,pair=roles[uid];base=root/'public/cases'/uid;cfg=root/'public/configuration'/uid
        o=read(base/'observer-projection.json');s=read(base/'receipt-stream.json');t=read(root/'sealed/cases'/(uid+'.json'));truths[uid]=t
        data=[(base/n).read_bytes() for n in ['case-manifest.json','observer-projection.json','receipt-stream.json']]+[(cfg/'policies/policy.json').read_bytes(),(cfg/'verification-context.json').read_bytes()]
        input_hashes[uid]=digest(encoded([x.hex() for x in data]))
        family_splits[t['family']].add(entry['split'])
        row=dict(unit_id=uid,role=role,pair_id=pair['pair_id'],family=pair['family'],scenario=o['scenario_id'],scale=pair['scale'],operation=pair['operation'],split=entry['split'],outcome=t['truth']['outcome'],receipts=len(s['receipts']),exceptions=len(o['exceptions']),**structure_metrics(o['topology']))
        for k,c in classes.items():row[k+'_structure_class']=c.add(graph(o['topology'],k))
        case_rows.append(row)
    controls=[r for r in case_rows if r['role']=='control'];challenges=[r for r in case_rows if r['role']=='challenge']
    hidden=[p for p in pairs if p['operation']=='hidden_copy_twin']
    hidden_ok=sum(input_hashes[p['unit_ids'][0]]==input_hashes[p['unit_ids'][1]] and truths[p['unit_ids'][0]]['truth']==truths[p['unit_ids'][1]]['truth'] and truths[p['unit_ids'][0]]['world_truth']!=truths[p['unit_ids'][1]]['world_truth'] for p in hidden)
    op_rows=[]
    for op in sorted({p['operation'] for p in pairs}):
        ps=[p for p in pairs if p['operation']==op];transitions=Counter(truths[p['unit_ids'][0]]['truth']['outcome']+' -> '+truths[p['unit_ids'][1]]['truth']['outcome'] for p in ps)
        op_rows.append(dict(operation=op,pairs=len(ps),transitions=dict(sorted(transitions.items()))))
    # A frozen corpus identifies the generator that produced it. The active
    # generator has a later source identity after the contract correction.
    if args.source_root is None:
        source_root = root / 'sealed/source'
        source_hashes = read(root / 'sealed/source-hashes.json')
        source_paths = {key: source_root / key for key in source_hashes}
    else:
        source_root = args.source_root.resolve()
        source_manifest = read(source_root / 'SOURCE_MANIFEST.json')
        source_hashes = source_manifest['files']
        source_paths = {}
        for key in source_hashes:
            owner, relative = key.split('/', 1)
            source_paths[key] = source_root / source_manifest['source_roots'][owner] / relative
    source_errors = [
        key for key, path in source_paths.items()
        if not path.is_file() or digest(path.read_bytes()) != source_hashes[key]
    ]
    report={
      'audit_date':'2026-11-05','dataset':str(root),'manifest_sha256':digest((root/'dataset-manifest.json').read_bytes()),
      'method':'Direct file census and exact directed graph isomorphism; no generator oracle imports',
      'limitations':['Not independent human adjudication','Graph equivalence excludes roots, policy, receipts, times, visibility and scope flags','Byte identity measures saved input equivalence; not semantic case equivalence','No new assessor utility or clean environment study'],
      'counts':dict(case_units=len(index),pairs=len(pairs),source_families=len(family_splits),control_units=len(controls),challenge_units=len(challenges),distinct_control_inputs=len({input_hashes[r['unit_id']] for r in controls}),distinct_all_inputs=len(set(input_hashes.values())),family_scale_groups=len({(p['family'],p['scale']) for p in pairs})),
      'structures':{k:dict(all_case_classes=c.count,control_classes=len({r[k+'_structure_class'] for r in controls}),definition={'asset':'Asset nodes and directed lineage only','custody':'Asset, replica, repository and custodian node types; directed relation types','semantic':'Custody graph plus asset kind, replica class and repository class'}[k]) for k,c in classes.items()},
      'structure_ranges':{k:dict(min=min(r[k] for r in case_rows),max=max(r[k] for r in case_rows),distribution=dict(sorted(Counter(r[k] for r in case_rows).items()))) for k in ['assets','replicas','repositories','custodians','max_replicas_per_asset','lineage_edges','lineage_depth','max_lineage_fanout']},
      'outcomes':dict(sorted(Counter(r['outcome'] for r in case_rows).items())),
      'splits':{split:dict(units=sum(r['split']==split for r in case_rows),families=sum(split in s for s in family_splits.values())) for split in ['train','validation','test']},
      'operation_transitions':op_rows,
      'checks':dict(exact_isomorphism_sanity_checks='PASS',family_split_overlap=any(len(s)>1 for s in family_splits.values()),hidden_copy_pairs=len(hidden),hidden_copy_pairs_equal_full_input_and_observer_truth_but_different_world=hidden_ok,frozen_source_files_checked=len(source_hashes),frozen_source_errors=source_errors),
      'serialized_public_input_bytes':sum((root/'public'/rel).stat().st_size for e in index for rel in e['files']),
      'tracked_profile':manifest['proof_profile'],'q_status':manifest['q_status']}
    for mode in classes:
        groups=defaultdict(set)
        for row in case_rows:groups[row[mode+'_structure_class']].add(row['split'])
        report['structures'][mode]['classes_shared_across_splits']=sum(len(s)>1 for s in groups.values())
    assert not source_errors and not report['checks']['family_split_overlap'] and hidden_ok==len(hidden)
    for name,rows in [('case_census.csv',case_rows)]:
        with (out/name).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (out/'reference_audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['counts','structures','checks','structure_ranges']},indent=2))

if __name__=='__main__':main()
