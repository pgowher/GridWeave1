"""Cross-platform atomic replacement with bounded Windows sharing retries."""

from __future__ import annotations

import os
from pathlib import Path
import threading


_WINDOWS_TRANSIENT_REPLACE_ERRORS = frozenset({5, 32})
_RETRY_DELAYS_SECONDS = (0.005, 0.01, 0.02, 0.04, 0.08, 0.16, 0.32)
_WAIT_EVENT = threading.Event()


def atomic_replace(source: str | Path, target: str | Path) -> None:
    """Atomically replace a path, retrying only transient Windows access errors."""

    source_path = Path(source)
    target_path = Path(target)
    for attempt in range(len(_RETRY_DELAYS_SECONDS) + 1):
        try:
            os.replace(source_path, target_path)
            return
        except PermissionError as exc:
            winerror = getattr(exc, "winerror", None)
            retryable = (
                os.name == "nt"
                and winerror in _WINDOWS_TRANSIENT_REPLACE_ERRORS
                and attempt < len(_RETRY_DELAYS_SECONDS)
            )
            if not retryable:
                raise
            _WAIT_EVENT.wait(_RETRY_DELAYS_SECONDS[attempt])


__all__ = ["atomic_replace"]
