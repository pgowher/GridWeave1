"""Automated PaEForge vertical experiment pipeline.

Imports are lazy so ``python -m paeforge_pipeline.verclo_worker`` cannot load
the oracle-side orchestrator or evaluator through package initialization.
"""

from __future__ import annotations

from typing import Any


__all__ = ["PipelineResult", "run_pipeline"]
__version__ = "1.0.0"


def __getattr__(name: str) -> Any:
    if name in {"PipelineResult", "run_pipeline"}:
        from .orchestrator import PipelineResult, run_pipeline

        return {"PipelineResult": PipelineResult, "run_pipeline": run_pipeline}[name]
    raise AttributeError(name)
