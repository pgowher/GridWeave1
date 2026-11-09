# Source this file from Bash: source environment/activate.sh
_thesis_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -f "$_thesis_root/.venv/bin/activate" ]]; then
    echo "Run bash environment/bootstrap.sh first." >&2
    return 1
fi
source "$_thesis_root/.venv/bin/activate"
export PHD_PROJECT_ROOT="$_thesis_root"
export THESIS_ROOT="$_thesis_root"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$_thesis_root/HTGLThesis/src:$_thesis_root/PaEForge/src"
unset _thesis_root
