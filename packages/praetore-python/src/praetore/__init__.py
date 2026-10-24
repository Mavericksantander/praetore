"""Thin Python bindings to the Rust PRÆTORE evidence verifier."""

from ._core import (
    verify_evidence_attester_signature,
    verify_evidence_integrity,
)

__all__ = [
    "verify_evidence_attester_signature",
    "verify_evidence_integrity",
]