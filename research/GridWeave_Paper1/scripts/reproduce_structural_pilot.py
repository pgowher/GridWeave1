#!/usr/bin/env python3
"""Regenerate the structural extension using its saved generation source."""
import argparse
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

LAB = Path(__file__).resolve().parents[1]
PROJECT = LAB.parents[1]
sys.path.insert(0, str(LAB))

from paper1.replay import prepare_generation_replay
from paper1.wire import file_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True, help='Frozen structural extension')
    parser.add_argument('--record', type=Path, required=True, help='Output JSON path')
    args = parser.parse_args()
    reference = args.reference.resolve()
    python = PROJECT / 'GridWeave/.venv/bin/python'

    with tempfile.TemporaryDirectory(prefix='gridweave-extension-replay-') as temp:
        temporary = Path(temp)
        replay = prepare_generation_replay(PROJECT, reference, temporary / 'project', extension=True)
        destination = temporary / 'corpus'
        builder = replay['lab'] / 'scripts/build_structural_pilot.py'
        started = time.perf_counter()
        result = subprocess.run([python, builder, '--output', destination],
                                cwd=replay['project'], env=replay['env'],
                                capture_output=True, text=True)
        seconds = time.perf_counter() - started
        args.record.with_suffix('.log').write_text(result.stdout + result.stderr)
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        report = {
            'exit_code': result.returncode,
            'wall_seconds': seconds,
            'peak_child_rss_bytes': peak * (1 if sys.platform == 'darwin' else 1024),
            'generation_includes_validation': True,
            'generation_source_mode': 'RECORDED_GENERATION_SOURCE_REPLAY',
            'source_snapshot_sha256': replay['source_snapshot_sha256'],
            'repetitions': 1,
        }
        if result.returncode == 0:
            report['reference_manifest_sha256'] = file_hash(reference / 'dataset-manifest.json')
            report['reproduced_manifest_sha256'] = file_hash(destination / 'dataset-manifest.json')
            report['byte_identical'] = report['reference_manifest_sha256'] == report['reproduced_manifest_sha256']
    args.record.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return int(not report.get('byte_identical', False))


if __name__ == '__main__':
    raise SystemExit(main())
