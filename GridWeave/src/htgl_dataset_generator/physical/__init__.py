"""Physical raw backend interfaces, generation, and validation."""

from .builder import (
    BasePhysicalBackend,
    EXTERNAL_SOLVER_EXECUTION_SUPPORTED,
    GovernanceTrigger,
    NetworkTopologyElement,
    OpenSynthStyleSyntheticBackend,
    PhysicalDiagnostics,
    PhysicalRawBuild,
    PhysicalValidationError,
    ProceduralPhysicalBackend,
    SmartDsStyleSyntheticBackend,
    build_physical_raw,
    validate_physical_raw,
)

__all__ = [
    "BasePhysicalBackend",
    "EXTERNAL_SOLVER_EXECUTION_SUPPORTED",
    "GovernanceTrigger",
    "NetworkTopologyElement",
    "OpenSynthStyleSyntheticBackend",
    "PhysicalDiagnostics",
    "PhysicalRawBuild",
    "PhysicalValidationError",
    "ProceduralPhysicalBackend",
    "SmartDsStyleSyntheticBackend",
    "build_physical_raw",
    "validate_physical_raw",
]
