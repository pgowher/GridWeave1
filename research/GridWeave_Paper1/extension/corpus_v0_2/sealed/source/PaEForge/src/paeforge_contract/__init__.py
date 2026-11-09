"""PaEForge v1 oracle-isolated exchange contracts."""

from .adapters import (
    VercloInputAdapter,
    build_case_manifest,
    build_observer_projection,
    build_receipt_stream,
    build_verclo_result,
)
from .canonical import canonical_json_bytes, sha256_digest, verclo_obligation_id
from .exchange import read_verifier_bundle, write_verifier_bundle
from .validation import (
    ContractError,
    LeakageError,
    validate_document,
    validate_verifier_bundle,
    validate_verifier_input,
)

__all__ = [
    "ContractError",
    "LeakageError",
    "VercloInputAdapter",
    "build_case_manifest",
    "build_observer_projection",
    "build_receipt_stream",
    "build_verclo_result",
    "canonical_json_bytes",
    "read_verifier_bundle",
    "sha256_digest",
    "validate_document",
    "validate_verifier_bundle",
    "validate_verifier_input",
    "verclo_obligation_id",
    "write_verifier_bundle",
]

__version__ = "1.0.0"
