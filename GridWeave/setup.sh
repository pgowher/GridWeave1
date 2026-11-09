#!/usr/bin/env bash
set -euo pipefail
gridweave_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
gridweave_python="${PYTHON:-python3}"
"$gridweave_python" -m venv --copies "$gridweave_root/.venv"
"$gridweave_root/.venv/bin/python" -m pip install -r "$gridweave_root/requirements.txt"
"$gridweave_root/gridweave" --version
