#!/usr/bin/env bash
set -euo pipefail
verclo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
verclo_python="${PYTHON:-python3}"
verclo_system=false
verclo_research=false
for verclo_arg in "$@"; do
    case "$verclo_arg" in
        --use-system-packages) verclo_system=true ;;
        --research) verclo_research=true ;;
        *) echo "Usage: setup.sh [--use-system-packages] [--research]" >&2; exit 2 ;;
    esac
done
verclo_venv_args=(--copies)
if "$verclo_system"; then verclo_venv_args+=(--system-site-packages); fi
"$verclo_python" -m venv "${verclo_venv_args[@]}" "$verclo_root/.venv"
if ! "$verclo_system"; then
    "$verclo_root/.venv/bin/python" -m pip install -r "$verclo_root/requirements.txt"
    if "$verclo_research"; then
        "$verclo_root/.venv/bin/python" -m pip install -r "$verclo_root/environment/requirements-research.txt"
    fi
fi
"$verclo_root/verclo" check
