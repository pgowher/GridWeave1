"""Network middleware for the oracle-isolated PaEForge verifier boundary.

The package root exposes only transport-safe helpers.  It deliberately does not
import the verifier implementation or evaluator adapter.
"""

from .protocol import (
    MAX_REQUEST_BYTES,
    MIDDLEWARE_VERSION,
    MiddlewareError,
    build_envelope_from_run,
    validate_envelope,
)

__all__ = [
    "MAX_REQUEST_BYTES",
    "MIDDLEWARE_VERSION",
    "MiddlewareError",
    "build_envelope_from_run",
    "validate_envelope",
]
