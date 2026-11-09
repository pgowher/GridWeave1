"""Current-host repeated generation cost and byte-reproduction measurements."""
import os,platform,subprocess,sys,tempfile,time,statistics
from pathlib import Path
from .wire import read,write,file_hash


def run(project,lab,out,repetitions=3):
    project=Path(project);lab=Path(lab);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    if not hasattr(os,'wait4'):raise RuntimeError('This declared measurement profile requires a wait4-capable host')
    expected={'reference':file_hash(project/'GridWeave/datasets/reference/dataset-manifest.json'),'structural_extension':file_hash(lab/'extension/corpus_v0_2/dataset-manifest.json')}
    baseline=read(project/'GridWeave/datasets/reference/sealed/reproduction.json');rows=[]
    for name in expected:
        for repetition in range(repetitions):
            with tempfile.TemporaryDirectory(prefix='paper1-generation-profile-') as temporary:
                destination=Path(temporary)/'dataset'
                if name=='reference':
                    args=[project/'GridWeave/.venv/bin/python',project/'GridWeave/run.py','generate','--output',destination,'--seed',baseline['seed'],'--scales',*map(str,baseline['scales']),'--strategy',baseline['strategy'],'--max-states',str(baseline['max_states'])]
                    if baseline['include_audit']:args.append('--include-audit')
                else:args=[project/'GridWeave/.venv/bin/python',lab/'scripts/build_structural_pilot.py','--output',destination]
                log=out/f'{name}-{repetition}.log';started=time.perf_counter()
                with log.open('w') as stream:
                    process=subprocess.Popen(list(map(str,args)),cwd=project,stdout=stream,stderr=subprocess.STDOUT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
                    _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                seconds=time.perf_counter()-started
                if process.returncode:raise RuntimeError('Generation profile failed: '+str(log))
                actual=file_hash(destination/'dataset-manifest.json');rss=usage.ru_maxrss*(1 if sys.platform=='darwin' else 1024)
                row=dict(dataset=name,repetition=repetition,wall_seconds=seconds,peak_child_rss_bytes=rss,manifest_sha256=actual,byte_identical=actual==expected[name],public_input_bytes=sum(p.stat().st_size for p in (destination/'public').rglob('*') if p.is_file()),total_output_bytes=sum(p.stat().st_size for p in destination.rglob('*') if p.is_file()))
                rows.append(row);write(out/'observations.json',rows)
                if not row['byte_identical']:raise RuntimeError('Byte reproduction differed; raw artifacts remain identified in '+str(log))
                print(f"Generation profile {name} {repetition+1}/{repetitions}: {seconds:.2f} s, {rss/1048576:.2f} MiB",flush=True)
    report=dict(status='COMPLETE',platform=platform.platform(),python=sys.version,existing_dependency_environment=True,generation_includes_validation=True,memory_definition='Peak resident memory of each specific generator child from wait4, not summed process-tree memory',repetitions_per_corpus=repetitions,all_byte_identical=all(r['byte_identical'] for r in rows),corpora={name:dict(median_wall_seconds=statistics.median(r['wall_seconds'] for r in rows if r['dataset']==name),min_wall_seconds=min(r['wall_seconds'] for r in rows if r['dataset']==name),max_wall_seconds=max(r['wall_seconds'] for r in rows if r['dataset']==name),median_peak_child_rss_bytes=statistics.median(r['peak_child_rss_bytes'] for r in rows if r['dataset']==name)) for name in expected})
    write(out/'summary.json',report);return report
