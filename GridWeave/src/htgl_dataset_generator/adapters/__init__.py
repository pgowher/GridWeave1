"""Step 19 interoperability projection and conformance API."""

from .models import (
    AdapterBuild,
    AdapterConformance,
    AdapterContractError,
    AdapterProfile,
    AdapterRegistry,
    FieldMapping,
)
from .compiler import compile_interoperability_adapters
from .registry import SUPPORTED_ADAPTERS, load_adapter_registry

__all__ = [
    "AdapterBuild",
    "AdapterConformance",
    "AdapterContractError",
    "AdapterProfile",
    "AdapterRegistry",
    "FieldMapping",
    "SUPPORTED_ADAPTERS",
    "compile_interoperability_adapters",
    "load_adapter_registry",
]
