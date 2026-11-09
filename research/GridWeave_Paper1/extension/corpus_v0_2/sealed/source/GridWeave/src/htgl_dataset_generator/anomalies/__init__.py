"""Minimal counterfactual anomaly contracts and production engine."""

from .engine import (
    ANOMALY_COMPONENT,
    AnomalyGenerationError,
    build_anomaly_baselines,
    build_anomalies,
    build_minimal_counterfactual_comparison,
    validate_anomaly_build,
)
from .invariants import IndependentInvariantChecker, InvariantEvaluationError, outcome_by_id
from .models import (
    AnomalyBuild,
    AnomalyDiagnostics,
    AnomalySearchDiagnostics,
    CounterfactualEdit,
    CounterfactualPair,
    CounterfactualTrace,
    InvariantOutcome,
)
from .registry import (
    AnomalyRegistryError,
    EditGrammar,
    EditGrammarRule,
    InvariantDefinition,
    InvariantRegistry,
    load_anomaly_contract,
)

__all__ = [
    "ANOMALY_COMPONENT",
    "AnomalyBuild",
    "AnomalyDiagnostics",
    "AnomalyGenerationError",
    "AnomalyRegistryError",
    "AnomalySearchDiagnostics",
    "CounterfactualEdit",
    "CounterfactualPair",
    "CounterfactualTrace",
    "EditGrammar",
    "EditGrammarRule",
    "IndependentInvariantChecker",
    "InvariantDefinition",
    "InvariantEvaluationError",
    "InvariantOutcome",
    "InvariantRegistry",
    "build_anomalies",
    "build_anomaly_baselines",
    "build_minimal_counterfactual_comparison",
    "load_anomaly_contract",
    "outcome_by_id",
    "validate_anomaly_build",
]
