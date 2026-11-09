"""Canonical executable smart-grid scenarios for PaEBench."""

from .compiler import compile_smart_grid_benchmark
from .loader import (
    REQUIRED_SMART_GRID_SCENARIOS,
    SmartGridScenarioDefinition,
    load_smart_grid_scenarios,
)

__all__ = [
    "REQUIRED_SMART_GRID_SCENARIOS",
    "SmartGridScenarioDefinition",
    "compile_smart_grid_benchmark",
    "load_smart_grid_scenarios",
]

