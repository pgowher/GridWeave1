"""Run artifact I/O and source identity helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
from typing import Any, Iterable, Mapping

from paeforge_contract.canonical import canonical_json_bytes


EXCLUDED_PARTS = frozenset({".git", ".pytest_cache", "__pycache__", "build", "dist", "output", "releases"})
IDENTITY_SUFFIXES = frozenset({".py", ".json", ".toml", ".md"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_bytes_immutable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_file() and not path.is_symlink() and path.read_bytes() == payload:
            return
        raise FileExistsError(f"refusing to replace run artifact: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    write_bytes_immutable(path, canonical_json_bytes(payload))


def read_json(path: Path) -> Mapping[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class StructuredRunLog:
    def __init__(self, path: Path, run_id: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.run_id = run_id
        self.sequence = 0

    def emit(self, stage: str, event: str, status: str, **details: Any) -> None:
        row = {
            "schema_version": "1.0.0",
            "sequence": self.sequence,
            "timestamp": utc_now(),
            "run_id": self.run_id,
            "stage": stage,
            "event": event,
            "status": status,
            "details": details,
        }
        encoded = canonical_json_bytes(row)
        with self.path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        self.sequence += 1


def source_identity(name: str, root: Path) -> Mapping[str, Any]:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if set(relative.parts) & EXCLUDED_PARTS:
            continue
        if path.suffix not in IDENTITY_SUFFIXES and path.name != "MODEL_VERSION":
            continue
        files.append(
            {"path": relative.as_posix(), "bytes": path.stat().st_size, "sha256": sha256_file(path)}
        )
    aggregate = hashlib.sha256(canonical_json_bytes(files)).hexdigest()
    git_head = None
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            capture_output=True, text=True, timeout=10,
        )
        git_head = completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    revision = f"git:{git_head};tree:{aggregate}" if git_head else f"tree:{aggregate}"
    return {
        "name": name,
        "root": str(root),
        "git_head": git_head,
        "tree_sha256": aggregate,
        "file_count": len(files),
        "source_revision": revision,
        "files": files,
    }


def runtime_identity() -> Mapping[str, Any]:
    return {
        "python_version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
    }


def artifact_inventory(root: Path, excluded: Iterable[Path] = ()) -> list[Mapping[str, Any]]:
    blocked = {path.resolve() for path in excluded}
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() in blocked:
            continue
        relative = path.relative_to(root).as_posix()
        schema_id = None
        if path.suffix == ".json":
            try:
                payload = read_json(path)
                schema_id = payload.get("schema_id")
            except (OSError, json.JSONDecodeError):
                pass
        rows.append(
            {"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path), "schema_id": schema_id}
        )
    return rows

