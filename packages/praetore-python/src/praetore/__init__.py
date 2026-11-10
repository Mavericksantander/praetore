"""Historical evidence verification bindings; these do not authorize execution."""

from ._core import (
    gateway_receipt_finality,
    verify_evidence_attester_signature,
    verify_evidence_integrity,
    verify_final_gateway_receipt,
    verify_gateway_receipt,
)

__all__ = [
    "gateway_receipt_finality",
    "verify_evidence_attester_signature",
    "verify_evidence_integrity",
    "verify_final_gateway_receipt",
    "verify_gateway_receipt",
]