"""Historical evidence verification bindings; these do not authorize execution."""

from ._core import (
    verify_evidence_attester_signature,
    verify_evidence_integrity,
)

__all__ = [
    "verify_evidence_attester_signature",
    "verify_evidence_integrity",
]