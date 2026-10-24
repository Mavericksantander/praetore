"""Compatibility import surface for the verify-only Python package."""

from . import verify_evidence_attester_signature, verify_evidence_integrity

__all__ = [
    "verify_evidence_attester_signature",
    "verify_evidence_integrity",
]