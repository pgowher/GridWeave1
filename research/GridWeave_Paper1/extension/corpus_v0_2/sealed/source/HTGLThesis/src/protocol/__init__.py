"""Machine-readable C-PaE v1 protocol contracts."""

from .state_machine import TransitionResult, evaluate_transition, load_protocol_catalog
from .crypto import (
    KeyRecord,
    KeyRegistry,
    body_digest,
    canonicalize,
    message_digest,
    sign_message,
    verify_authenticated_message,
)
from .validation import AuthenticatedReplayGuard, ReplayGuard, validate_message

PROTOCOL_VERSION = "C-PAE-1.0.0"
MODEL_VERSION = "PAE-FECM-v1.0.0"

__all__ = [
    "MODEL_VERSION", "PROTOCOL_VERSION", "TransitionResult",
    "AuthenticatedReplayGuard", "KeyRecord", "KeyRegistry", "ReplayGuard",
    "body_digest", "canonicalize", "evaluate_transition", "load_protocol_catalog",
    "message_digest", "sign_message", "validate_message", "verify_authenticated_message",
]
