"""Workflow automata and governance event compilation."""

from .builder import (
    CONTROLLED_LEGAL_BASIS_LABEL_IDS,
    REQUIRED_WORKFLOW_TYPES,
    SIDE_EFFECT_TYPES,
    WorkflowBuild,
    WorkflowCompilerError,
    WorkflowDefinition,
    WorkflowDiagnostics,
    WorkflowSideEffect,
    build_workflows,
    validate_workflows,
    workflow_definitions,
)

__all__ = [
    "CONTROLLED_LEGAL_BASIS_LABEL_IDS",
    "REQUIRED_WORKFLOW_TYPES",
    "SIDE_EFFECT_TYPES",
    "WorkflowBuild",
    "WorkflowCompilerError",
    "WorkflowDefinition",
    "WorkflowDiagnostics",
    "WorkflowSideEffect",
    "build_workflows",
    "validate_workflows",
    "workflow_definitions",
]
