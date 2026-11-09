"""Repeatable matched-budget utility experiment on two assessor implementations.

Faults target new assessor implementations, never the generator label oracle.
Counts concern deliberate mutants and declared fixtures, not a population of bugs.
"""
import ast,csv,hashlib,json,time
from pathlib import Path
from .wire import read,write,file_hash,load_public
from .adjudication import expected_labels,FIELDS

FAULTS={
 'signature_bypass':'Accept cryptographic signatures without verification',
 'contradiction_suppression':'Suppress contradictory authenticated dispositions',
 'declared_scope_bypass':'Ignore the declared scope-completeness flag',
 'scope_commitment_bypass':'Ignore the scope commitment comparison',
 'exception_expiry_bypass':'Accept an exception after expiry',
 'deadline_precedence_bypass':'Skip the IN_PROGRESS timing branch',
 'roots_only':'Reconstruct obligations for roots but not descendants',
 'replica_collapse':'Keep one replica per asset instead of every applicable replica'}

class Mutate(ast.NodeTransformer):
    def __init__(self,assessor,fault):self.assessor=assessor;self.fault=fault;self.edits=0
    def visit_FunctionDef(self,node):
        node=self.generic_visit(node)
        target={'signature_bypass':'_verify' if self.assessor=='graph' else '_authenticate','scope_commitment_bypass':'_scope_matches' if self.assessor=='graph' else '_scope_ok','roots_only':'_reachable' if self.assessor=='graph' else '', 'replica_collapse':'_eligible_replicas' if self.assessor=='graph' else ''}.get(self.fault)
        if target and node.name==target:
            code={'signature_bypass':'return True','scope_commitment_bypass':'return True','roots_only':'return set(roots)','replica_collapse':'return list({r["asset_id"]: r for r in top["replicas"]}.values())'}[self.fault]
            node.body=ast.parse(code).body;self.edits+=1
        return node
    def visit_Compare(self,node):
        node=self.generic_visit(node);text=ast.unparse(node)
        if self.assessor=='graph':
            match={'contradiction_suppression':'len(dispositions) > 1','exception_expiry_bypass':"now < instant(exception['expires_at'])",'deadline_precedence_bypass':'now < deadline'}.get(self.fault)
            if match and text==match:self.edits+=1;return ast.Constant(self.fault=='exception_expiry_bypass')
        return node
    def visit_Call(self,node):
        node=self.generic_visit(node)
        if self.fault=='declared_scope_bypass' and ast.unparse(node)=="top.get('declared_scope_complete')":self.edits+=1;return ast.Constant(True)
        return node
    def visit_Assign(self,node):
        node=self.generic_visit(node)
        if self.assessor!='sql' or not isinstance(node.value,ast.Constant) or not isinstance(node.value.value,str):return node
        name=ast.unparse(node.targets[0]);text=node.value.value;replace=None
        if self.fault=='contradiction_suppression' and name=='CATEGORY_SQL':replace=("count(DISTINCT CASE WHEN v.valid=1 AND v.terminal=1 THEN v.disposition END)>1","0=1")
        if self.fault=='exception_expiry_bypass' and name=='CATEGORY_SQL':replace=(':now<x.expiry','1=1')
        if self.fault=='deadline_precedence_bypass' and name=='OUTCOME_SQL':replace=(':now<:deadline','0=1')
        if self.fault=='roots_only' and name=='REACH_SQL':replace=('SELECT asset FROM roots UNION SELECT e.child FROM edges e JOIN reach ON e.parent=reach.asset','SELECT asset FROM roots')
        if self.fault=='replica_collapse' and name=='REACH_SQL':replace=('WHERE asset_applies(a.kind)','WHERE c.replica=(SELECT min(c2.replica) FROM copies c2 WHERE c2.asset=c.asset) AND asset_applies(a.kind)')
        if replace:
            if text.count(replace[0])!=1:raise ValueError('Fault source match changed: '+self.fault)
            node.value=ast.Constant(text.replace(*replace));self.edits+=1
        return node

def compile_assessor(assessor,fault=None):
    path=Path(__file__).parent/(assessor+'_assessor.py');tree=ast.parse(path.read_text())
    if fault:
        transform=Mutate(assessor,fault);tree=transform.visit(tree)
        if transform.edits!=1:raise ValueError(f'Expected one semantic edit: {assessor} {fault} {transform.edits}')
    ast.fix_missing_locations(tree);rendered=ast.unparse(tree);ns={'__name__':'paper1.fault_'+assessor+'_'+str(fault),'__package__':'paper1'};exec(compile(tree,str(path), 'exec'),ns)
    return ns['assess'],hashlib.sha256(rendered.encode()).hexdigest()

def run(datasets,independent,out,repetitions=5,budget=40):
    out=Path(out);out.mkdir(parents=True,exist_ok=False);all_inputs={};expected={};costs={};positive_unique={};pairs=[]
    for ds in datasets:
        ds=Path(ds);data={uid:(o,s,p,c) for uid,o,s,p,c in load_public(ds/'public')};all_inputs.update(data);expected.update({uid:v['truth'] for uid,v in expected_labels(ds).items()})
        costs.update({e['unit_id']:sum((ds/'public'/rel).stat().st_size for rel in e['files']) for e in read(ds/'public/index.json')['cases']})
        for p in read(ds/'sealed/pairs.json'):
            pairs.append(p);uid=p['unit_ids'][0];fingerprint=hashlib.sha256(json.dumps(data[uid],sort_keys=True).encode()).hexdigest();positive_unique.setdefault(fingerprint,uid)
    independent=Path(independent);all_inputs.update({uid:(o,s,p,c) for uid,o,s,p,c in load_public(independent/'public')});expected.update({uid:v['truth'] for uid,v in expected_labels(independent).items()})
    costs.update({e['unit_id']:sum((independent/'public'/rel).stat().st_size for rel in e['files']) for e in read(independent/'public/index.json')['cases']})
    ordinary=[r['unit_id'] for r in read(independent/'sealed/fixture-catalogue.json')['cases'] if r['track']=='ordinary_positive'];controls=list(positive_unique.values());ops=sorted({p['operation'] for p in pairs})
    if budget!=4*len(ops) or budget>min(len(ordinary),len(controls)):raise ValueError('Budget must allow two complete pairs per operation and available distinct positive fixtures')
    implementations={};identities={}
    for assessor in ('graph','sql'):
        for fault in FAULTS:
            name=assessor+'/'+fault;implementations[name],identities[name]=compile_assessor(assessor,fault)
    selected={}
    for repeat in range(repetitions):
        def rank(value):return hashlib.sha256(f'utility-v1:{repeat}:{value}'.encode()).hexdigest()
        chosen=[]
        for op in ops:chosen.extend(sorted((p for p in pairs if p['operation']==op),key=lambda p:rank(p['pair_id']))[:2])
        selected[str(repeat)]={'ordinary_positive':sorted(ordinary,key=rank)[:budget],'gridweave_positive':sorted(controls,key=rank)[:budget],'gridweave_pairs':[u for p in chosen for u in p['unit_ids']]}
    # Freeze transforms, fixture choices and source identities before evaluation.
    write(out/'study-freeze.json',dict(study_version='1.0',mutant_identities=identities,fault_catalogue=FAULTS,selected_cases=selected,case_budget=budget,repetitions=repetitions,source_hashes={p.name:file_hash(p) for p in Path(__file__).parent.glob('*.py')}))
    observations=[];aggregates=[]
    for repeat,conditions in selected.items():
        for name,fn in implementations.items():
            for condition,units in conditions.items():
                mismatches=0;class_errors=0;elapsed=0.;subjects=set();byte_cost=0;witness_saved=False
                for uid in units:
                    start=time.perf_counter();actual=fn(*all_inputs[uid]);seconds=time.perf_counter()-start;elapsed+=seconds
                    fields=[f for f in FIELDS if actual[f]!=expected[uid][f]];mismatches+=bool(fields);class_errors+=actual['outcome']!=expected[uid]['outcome']
                    if fields and not witness_saved:
                        write(out/'witnesses'/(repeat+'-'+name.replace('/','-')+'-'+condition+'.json'),dict(unit_id=uid,mutant=name,condition=condition,repetition=int(repeat),differing_fields=fields,expected=expected[uid],actual=actual));witness_saved=True
                    observations.append(dict(repetition=int(repeat),mutant=name,condition=condition,unit_id=uid,detected=bool(fields),differing_fields=';'.join(fields),expected_class=expected[uid]['outcome'],actual_class=actual['outcome'],seconds=seconds))
                    subjects.add(hashlib.sha256(json.dumps(all_inputs[uid],sort_keys=True).encode()).hexdigest())
                    byte_cost+=costs[uid]
                aggregates.append(dict(repetition=int(repeat),mutant=name,assessor=name.split('/')[0],fault=name.split('/')[1],condition=condition,executions=len(units),distinct_semantic_inputs=len(subjects),mismatch_cases=mismatches,class_errors=class_errors,detected=bool(mismatches),assessment_seconds=elapsed,serialized_executed_input_bytes=byte_cost))
    summaries=[]
    for repeat in range(repetitions):
        found={condition:{r['mutant'] for r in aggregates if r['repetition']==repeat and r['condition']==condition and r['detected']} for condition in selected[str(repeat)]}
        summaries.append(dict(repetition=repeat,detected={k:len(v) for k,v in found.items()},unique_pairs_beyond_ordinary=sorted(found['gridweave_pairs']-found['ordinary_positive']),unique_pairs_beyond_gridweave_positive=sorted(found['gridweave_pairs']-found['gridweave_positive']),ordinary_only=sorted(found['ordinary_positive']-found['gridweave_pairs'])))
    survivors=[name for name in implementations if not any(r['mutant']==name and r['detected'] for r in aggregates)]
    report=dict(status='COMPLETE',fault_model='Eight deliberate fault families in two independent assessor implementations; sixteen mutants',mutants=len(implementations),fault_families=len(FAULTS),case_budget_per_condition=budget,repetitions=repetitions,total_case_evaluations=len(observations),repetition_summaries=summaries,survived_all_conditions=survivors,equivalence_policy='Surviving mutants remain in the denominator; survival is not proof of equivalence',limits=['Same-task nonblind authorship; not independent human adjudication','Seeded faults are distinct executable ablations, not sampled real defects','Shared wire utilities, envelope/profile validation and cryptography primitives; graph/SQL assessment logic is separate','Five deterministic subsets are repeated measurements, not independent source populations','Assessment timings exclude input loading and are not a stable performance ranking'])
    write(out/'summary.json',report)
    for name,rows in [('case_observations.csv',observations),('mutant_condition_results.csv',aggregates)]:
        with (out/name).open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    return report
