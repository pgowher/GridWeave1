"""Recorded-source generation cost and byte-reproduction measurements."""
import json,os,platform,subprocess,sys,tempfile,time,statistics
from datetime import datetime,timezone
from importlib.metadata import version,PackageNotFoundError
from pathlib import Path
from .wire import read,write,file_hash
from .replay import prepare_generation_replay


def machine_context():
    """Capture this execution's host; never backfill historical measurements."""
    model=platform.processor() or None
    cpuinfo=Path('/proc/cpuinfo')
    if cpuinfo.is_file():
        model=next((line.split(':',1)[1].strip() for line in cpuinfo.read_text().splitlines()
                    if line.startswith('model name')),model)
    try:ram=os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')
    except (ValueError,OSError,AttributeError):ram=None
    dependencies={}
    for name in ('cryptography','jsonschema','pyarrow'):
        try:dependencies[name]=version(name)
        except PackageNotFoundError:dependencies[name]=None
    return dict(captured_at=datetime.now(timezone.utc).isoformat(),platform=platform.platform(),
                python=sys.version,python_executable=sys.executable,cpu_model=model,
                logical_cpus=os.cpu_count(),physical_memory_bytes=ram,dependencies=dependencies,
                provenance='Captured before this execution; not historical-run hardware metadata')


def run(project,lab,out,repetitions=3):
    project=Path(project);lab=Path(lab);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    if not hasattr(os,'wait4'):raise RuntimeError('This declared measurement profile requires a wait4-capable host')
    corpora={'reference':project/'GridWeave/datasets/reference',
             'structural_extension':lab/'extension/corpus_v0_2'}
    expected={name:file_hash(root/'dataset-manifest.json') for name,root in corpora.items()}
    baseline=read(corpora['reference']/'sealed/reproduction.json');rows=[];sources={}
    write(out/'host.json',machine_context())
    for name,corpus in corpora.items():
        # Snapshot preparation is outside the timed generator-child interval.
        with tempfile.TemporaryDirectory(prefix='paper1-recorded-source-') as source_tmp:
            replay=prepare_generation_replay(project,corpus,Path(source_tmp)/'project',
                                             extension=name=='structural_extension')
            sources[name]={k:replay[k] for k in ('source_snapshot_sha256','source_files')}
            sources[name]['mode']='RECORDED_GENERATION_SOURCE_REPLAY'
            write(out/'generation_sources.json',sources)
            for repetition in range(repetitions):
                with tempfile.TemporaryDirectory(prefix='paper1-generation-profile-') as temporary:
                    destination=Path(temporary)/'dataset'
                    if name=='reference':
                        bootstrap=('import sys,json; from gridweave.dataset import generate; '
                                   'generate(sys.argv[1],**json.loads(sys.argv[2]))')
                        settings={k:baseline[k] for k in ('seed','scales','strategy','max_states','include_audit')}
                        settings['scenario_ids']=baseline.get('scenario_ids')
                        args=[project/'GridWeave/.venv/bin/python','-c',bootstrap,destination,json.dumps(settings)]
                        cwd=replay['gridweave']
                    else:
                        args=[project/'GridWeave/.venv/bin/python',replay['lab']/'scripts/build_structural_pilot.py',
                              '--output',destination]
                        cwd=replay['project']
                    log=out/f'{name}-{repetition}.log';started=time.perf_counter()
                    with log.open('w') as stream:
                        process=subprocess.Popen(list(map(str,args)),cwd=cwd,stdout=stream,
                                                 stderr=subprocess.STDOUT,env=replay['env'])
                        _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                    seconds=time.perf_counter()-started
                    if process.returncode:raise RuntimeError('Generation profile failed: '+str(log))
                    actual=file_hash(destination/'dataset-manifest.json');rss=usage.ru_maxrss*(1 if sys.platform=='darwin' else 1024)
                    row=dict(dataset=name,repetition=repetition,wall_seconds=seconds,peak_child_rss_bytes=rss,
                             manifest_sha256=actual,byte_identical=actual==expected[name],
                             source_mode='RECORDED_GENERATION_SOURCE_REPLAY',
                             generation_source_snapshot_sha256=replay['source_snapshot_sha256'],
                             public_input_bytes=sum(p.stat().st_size for p in (destination/'public').rglob('*') if p.is_file()),
                             total_output_bytes=sum(p.stat().st_size for p in destination.rglob('*') if p.is_file()))
                    rows.append(row);write(out/'observations.json',rows)
                    if not row['byte_identical']:raise RuntimeError('Recorded-source byte reproduction differed; inspect '+str(log))
                    print(f"Generation profile {name} {repetition+1}/{repetitions}: {seconds:.2f} s, {rss/1048576:.2f} MiB",flush=True)
    report=dict(status='COMPLETE',platform=platform.platform(),python=sys.version,existing_dependency_environment=True,
                host_metadata_file='host.json',host_metadata_sha256=file_hash(out/'host.json'),
                generation_source_mode='RECORDED_GENERATION_SOURCE_REPLAY',generation_includes_validation=True,
                snapshot_preparation_in_timed_interval=False,
                memory_definition='Peak resident memory of each specific generator child from wait4, not summed process-tree memory',
                repetitions_per_corpus=repetitions,all_byte_identical=all(r['byte_identical'] for r in rows),
                corpora={name:dict(median_wall_seconds=statistics.median(r['wall_seconds'] for r in rows if r['dataset']==name),
                                  min_wall_seconds=min(r['wall_seconds'] for r in rows if r['dataset']==name),
                                  max_wall_seconds=max(r['wall_seconds'] for r in rows if r['dataset']==name),
                                  median_peak_child_rss_bytes=statistics.median(r['peak_child_rss_bytes'] for r in rows if r['dataset']==name))
                         for name in expected})
    write(out/'summary.json',report);return report
