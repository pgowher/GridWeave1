"""VERCLO metadata-only case and obligation services."""

__version__ = "1.4.0"
RELEASE_NAME = "VERCLO-v1.4.0"
PROTOCOL_VERSION = "C-PAE-1.0.0"
MODEL_VERSION = "PAE-FECM-v1.0.0"

from .case_manager import ErasureCaseManager
from .graph_builder import ObligationGraphBuilder
from .models import (
    AssetDescriptor,
    CasePhase,
    ErasureCase,
    ExceptionAssertion,
    LineageEdge,
    Obligation,
    ObligationGraph,
    ObligationStatus,
    ReplicaDescriptor,
    RepositoryDescriptor,
    TopologyView,
    Visibility,
)
from .policy import PolicyProfile, PolicyRegistry

__all__ = [
    "AssetDescriptor", "CasePhase", "ErasureCase", "ErasureCaseManager",
    "ExceptionAssertion", "LineageEdge", "Obligation", "ObligationGraph",
    "ObligationGraphBuilder", "ObligationStatus", "PolicyProfile", "PolicyRegistry",
    "ReplicaDescriptor", "RepositoryDescriptor", "TopologyView", "Visibility",
    "__version__", "RELEASE_NAME", "PROTOCOL_VERSION", "MODEL_VERSION",
]
