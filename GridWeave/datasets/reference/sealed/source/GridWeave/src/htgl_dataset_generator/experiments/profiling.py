"""Measured stage telemetry kept outside deterministic generation semantics."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
import threading
import time
from typing import Any, Callable, Mapping, Sequence, TypeVar

from htgl_dataset_generator.seeds import canonical_records_digest
from htgl_dataset_generator.validation import StagePerformanceObservation


T = TypeVar("T")


class StageProfilingError(RuntimeError):
    """Raised when a stage observation cannot satisfy its measurement contract."""


@dataclass(frozen=True)
class _MemorySample:
    before_bytes: int
    after_bytes: int
    peak_bytes: int


class _ResidentMemorySampler:
    def __init__(self, interval_seconds: float = 0.01) -> None:
        self.interval_seconds = interval_seconds
        self.before_bytes = _current_resident_memory_bytes()
        self.peak_bytes = self.before_bytes
        self.after_bytes = self.before_bytes
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._sample,
            name="htgl-rss-sampler",
            daemon=True,
        )

    def __enter__(self) -> "_ResidentMemorySampler":
        self._thread.start()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, self.interval_seconds * 10))
        if self._thread.is_alive():
            raise StageProfilingError("resident-memory sampler did not terminate")
        self.after_bytes = _current_resident_memory_bytes()
        self.peak_bytes = max(self.peak_bytes, self.after_bytes)

    def observation(self) -> _MemorySample:
        return _MemorySample(self.before_bytes, self.after_bytes, self.peak_bytes)

    def _sample(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.peak_bytes = max(self.peak_bytes, _current_resident_memory_bytes())


class StageProfiler:
    """Collect one observation for every executed semantic pipeline stage."""

    def __init__(self) -> None:
        self._observations: list[StagePerformanceObservation] = []

    @property
    def observations(self) -> tuple[StagePerformanceObservation, ...]:
        return tuple(self._observations)

    def measure(
        self,
        stage_id: str,
        operation: str,
        function: Callable[[], T],
        *,
        table_records: Callable[[T], Mapping[str, Sequence[Mapping[str, Any]]]],
    ) -> T:
        if any(item.stage_id == stage_id for item in self._observations):
            raise StageProfilingError(f"stage {stage_id} was measured more than once")
        started = time.perf_counter()
        with _ResidentMemorySampler() as memory:
            result = function()
        elapsed = time.perf_counter() - started
        if elapsed <= 0:
            raise StageProfilingError(f"stage {stage_id} elapsed time must be positive")
        tables = dict(sorted(table_records(result).items()))
        row_count = sum(len(rows) for rows in tables.values())
        sample = memory.observation()
        self._observations.append(
            StagePerformanceObservation(
                stage_id=stage_id,
                operation=operation,
                generated_row_count=row_count,
                elapsed_seconds=elapsed,
                rows_per_second=row_count / elapsed if row_count else 0.0,
                rss_before_bytes=sample.before_bytes,
                rss_after_bytes=sample.after_bytes,
                peak_resident_memory_bytes=sample.peak_bytes,
                table_record_digests=tuple(
                    (table_name, canonical_records_digest(rows))
                    for table_name, rows in tables.items()
                ),
            )
        )
        return result


def _current_resident_memory_bytes() -> int:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        process = kernel32.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            raise StageProfilingError(
                f"GetProcessMemoryInfo failed with Win32 error {ctypes.get_last_error()}"
            )
        return int(counters.WorkingSetSize)

    statm = "/proc/self/statm"
    if os.path.isfile(statm):
        with open(statm, "r", encoding="ascii") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))

    import resource

    maximum = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return maximum if sys.platform == "darwin" else maximum * 1024


__all__ = ["StageProfiler", "StageProfilingError"]
