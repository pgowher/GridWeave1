"""One-command execution of the paper's prototype studies."""
import csv,json,os,shutil,subprocess,sys,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
from .wire import read,write,file_hash
from .fixture_builder import generate
from .adjudication import compare
from .utility import run as utility_run
from .profiling import run as profile_run

LAB=Path(__file__).resolve().parents[1];PROJECT=LAB.parents[1]

def command(args,log,cwd=LAB):
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1');start=time.perf_counter()
    with Path(log).open('w') as stream:
        result=subprocess.run(list(map(str,args)),cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError(f'Command failed ({result.returncode}); inspect {log}')
    return time.perf_counter()-start

def report(run):
    run=Path(run);summary=read(run/'study_summary.json');lines=['# GridWeave paper 1 executable study results','',f"Study {summary['study_version']}. Status {summary['status']}. All counts describe the declared synthetic signed E2 profile.",'','## Semantic assessment and adjudication','', '| Dataset | Assessor | Cases | Class matches | Field disagreements |','| --- | --- | --- | --- | --- |']
    for row in summary['assessment_runs']:lines.append(f"| {row['dataset']} | {row['assessor']} | {row['cases']} | {row['exact_class_matches']} | {row['disagreement_count']} |")
    lines+=['','The graph and SQLite checkers share wire utilities and envelope/profile validation, while their assessment algorithms are separate; they import neither the generator nor VERCLO assessment code. VERCLO is a separate related consumer. All read public input copies only. These are independent implementations with same-task nonblind AI authorship, not human-independent judgments. The separate fixture catalogue supplies ordinary positive constructions and explicit semantic boundary expectations; counts and catalogue versions are recorded below.','', '## Matched-budget testing utility','', '| Repetition | Ordinary positive detected | GridWeave positive detected | GridWeave pairs detected | Pair-only beyond ordinary |','| --- | --- | --- | --- | --- |']
    for row in summary['utility']['repetition_summaries']:
        d=row['detected'];lines.append(f"| {row['repetition']} | {d['ordinary_positive']} | {d['gridweave_positive']} | {d['gridweave_pairs']} | {len(row['unique_pairs_beyond_ordinary'])} |")
    lines+=['',f"The experiment uses {summary['utility']['mutants']} deliberate mutants from eight fault families across two assessor implementations, {summary['utility']['case_budget_per_condition']} executions per condition, and {summary['utility']['repetitions']} deterministic subset repetitions. Detection includes incorrect obligation or receipt diagnoses as well as incorrect case classes. It does not estimate a population of real bugs.",'','## Generation cost and byte reproduction','', '| Corpus | Repetitions | Median seconds including validation | Median peak child MiB |','| --- | --- | --- | --- |']
    for name,value in summary['generation_profile']['corpora'].items():lines.append(f"| {name} | {summary['generation_profile']['repetitions_per_corpus']} | {value['median_wall_seconds']:.2f} | {value['median_peak_child_rss_bytes']/1048576:.2f} |")
    lines+=['', 'All measured regenerations reproduced their recorded corpus manifests byte for byte in the existing research environment. Memory is the peak resident memory of each generator child process, not summed process-tree memory.','', '## Readiness and limits','', 'The current-workspace prototype has a runnable study, frozen outputs, machine-readable disagreement records, conformance checks and raw utility observations. Licensing, clean dependency installations and public release are outside the requested completion scope. Higher evidence grades, physical deletion, undisclosed-copy detection, field realism and independent human adjudication are not claimed.','', 'Run definitions, source identities, predictions, comparisons and fault observations are retained beside this report. A disagreement must be inspected; this runner never rewrites a saved label to force agreement.']
    if summary['generation_profile'].get('generation_source_mode')=='RECORDED_GENERATION_SOURCE_REPLAY':
        lines+=['', 'Generation byte reproduction executes the verified source snapshots saved with the corpora. Snapshot preparation is outside the timed generator-child interval. This is recorded-source replay, not a timing claim for the active corrected generator. This run\'s hardware and dependency metadata are in generation_profile/host.json and do not backfill historical measurements.']
    (run/'REPORT.md').write_text('\n'.join(lines)+'\n')

def execute(output):
    out=Path(output).resolve()
    if out.exists():raise FileExistsError('Choose a fresh study output directory')
    out.mkdir(parents=True);config=read(LAB/'config/study_v1.json');stages=[]
    executable_sources=[*sorted((LAB/'paper1').glob('*.py')),*sorted((LAB/'tests').glob('*.py')),LAB/'run.py',LAB/'config/study_v1.json',LAB/'fixtures/semantic_cases_v1.json',LAB/'SEMANTIC_SPECIFICATION.md',PROJECT/'GridWeave/src/gridweave/oracle.py']
    freeze={str(p.relative_to(PROJECT)):file_hash(p) for p in executable_sources};write(out/'source-freeze.json',freeze);write(out/'study_config.json',config)
    seconds=command([sys.executable,'-m','unittest','discover','-s',LAB/'tests','-v'],out/'tests.log');stages.append(dict(stage='conformance_tests',seconds=seconds,status='PASS'))
    fixture_root=out/'independent_fixtures';fixture_record=generate(fixture_root,LAB/'fixtures/semantic_cases_v1.json');write(out/'fixture_generation.json',fixture_record)
    datasets={'reference':PROJECT/'GridWeave/datasets/reference','structural_extension':LAB/'extension/corpus_v0_2','independent_fixtures':fixture_root}
    write(out/'dataset-identities.json',{name:dict(path=str(path),manifest_sha256=file_hash(path/'dataset-manifest.json'),public_index_sha256=file_hash(path/'public/index.json')) for name,path in datasets.items()})
    assessments=[]
    for name,path in datasets.items():
        with tempfile.TemporaryDirectory(prefix='paper1-public-only-') as temporary:
            public=Path(temporary)/'public';shutil.copytree(path/'public',public)
            for assessor in config['assessors']:
                predictions=out/'predictions'/name/assessor;predictions.parent.mkdir(parents=True,exist_ok=True);logs=out/'logs';logs.mkdir(exist_ok=True)
                if assessor=='verclo':args=[PROJECT/'VERCLO/verclo','run','--dataset',public,'--output',predictions]
                else:args=[sys.executable,'-m','paper1.assessor_worker','--public',public,'--assessor',assessor,'--output',predictions]
                elapsed=command(args,logs/(name+'-'+assessor+'.log'))
                comparison=compare(path,predictions,assessor,out/'adjudication'/name/assessor);comparison['dataset']=name;comparison['execution_wall_seconds']=elapsed;assessments.append(comparison)
                print(f"{name} / {assessor}: {comparison['exact_class_matches']}/{comparison['cases']} classes, {comparison['disagreement_count']} field disagreements",flush=True)
    write(out/'adjudication_summary.json',assessments)
    disagreements=sum(r['disagreement_count'] for r in assessments)
    if disagreements:
        write(out/'study_summary.json',dict(status='ADJUDICATION_REQUIRED',study_version=config['study_version'],assessment_runs=assessments,disagreement_count=disagreements));raise RuntimeError(f'{disagreements} semantic disagreements preserved in {out}/adjudication')
    utility=utility_run([datasets['reference'],datasets['structural_extension']],fixture_root,out/'utility',config['utility_repetitions'],config['utility_case_budget'])
    generation_profile=profile_run(PROJECT,LAB,out/'generation_profile',config['generation_repetitions'])
    current={str(p.relative_to(PROJECT)):file_hash(p) for p in executable_sources}
    if current!=freeze:raise RuntimeError('Study implementation changed during execution')
    summary=dict(status='COMPLETE',study_version=config['study_version'],completed_at=datetime.now(timezone.utc).isoformat(),assessment_runs=assessments,disagreement_count=0,utility=utility,generation_profile=generation_profile,source_unchanged_during_study=True,conformance_tests='PASS',fixtures=fixture_record,stages=stages,scope=config['scope'],excluded_completion_requirements=config['excluded_completion_requirements'])
    write(out/'study_summary.json',summary);report(out)
    files={str(p.relative_to(out)):file_hash(p) for p in out.rglob('*') if p.is_file()};write(out/'output-manifest.json',dict(files=files));write(LAB/'LATEST_STUDY.json',dict(path=str(out),study_summary_sha256=file_hash(out/'study_summary.json'),status=summary['status']))
    print(f'COMPLETE: {out}/REPORT.md',flush=True);return summary
