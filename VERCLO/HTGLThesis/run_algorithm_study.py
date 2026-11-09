#!/usr/bin/env python3
"""Run paired algorithm comparisons into a new evidence directory."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent/'src'))
from evaluation.algorithm_study import run_study

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--trials', type=int, default=15)
    p.add_argument('--seed', type=int, default=24092026)
    p.add_argument('--skip-network', action='store_true')
    a = p.parse_args()
    report = run_study(a.output, a.trials, a.seed, not a.skip_network)
    print(f"{report['status']}: {report['observations']} raw observations; novelty NOT_ESTABLISHED")
