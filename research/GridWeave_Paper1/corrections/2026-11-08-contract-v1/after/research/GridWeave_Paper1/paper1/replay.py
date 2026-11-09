"""Materialize recorded generation sources without altering frozen corpora.

Historical byte reproduction executes its recorded snapshot, since an active
source correction changes hashes even when none of the saved labels change.
"""
import os
import shutil
from pathlib import Path
from .wire import file_hash, read


def prepare_generation_replay(project, dataset, destination, *, extension=False):
    project, dataset, destination = map(Path, (project, dataset, destination))
    destination.mkdir(parents=True, exist_ok=False)
    mapping = {
        'GridWeave': destination / 'GridWeave',
        'PaEForge': destination / 'GridWeave/support/PaEForge',
        'HTGLThesis': destination / 'GridWeave/support/HTGLThesis',
        'Paper1Lab': destination / 'research/GridWeave_Paper1',
    }
    hashes = read(dataset / 'sealed/source-hashes.json')
    for name, expected in hashes.items():
        parts = Path(name).parts
        if len(parts) < 2 or parts[0] not in mapping or '..' in parts:
            raise ValueError('Invalid recorded source path')
        source = dataset / 'sealed/source' / name
        if file_hash(source) != expected:
            raise ValueError('Recorded generation source changed: ' + name)
        target = mapping[parts[0]].joinpath(*parts[1:])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    if extension:
        shutil.copytree(project / 'GridWeave/datasets/reference',
                        destination / 'GridWeave/datasets/reference')
    paths = [mapping[name] / 'src' for name in ('GridWeave', 'PaEForge', 'HTGLThesis')]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PYTHONPATH=os.pathsep.join(map(str, paths)))
    return dict(project=destination, gridweave=mapping['GridWeave'],
                lab=mapping['Paper1Lab'], env=env,
                source_snapshot_sha256=read(dataset / 'dataset-manifest.json')['source_snapshot_sha256'],
                source_files=len(hashes))
