def verify_evidence_integrity(evidence_json: str) -> bool:
    """Verify historical evidence integrity, not current authorization."""
    ...

def verify_evidence_attester_signature(
    evidence_json: str, attester_public_key_hex: str
) -> bool:
    """Verify historical evidence authenticity, not current authorization."""
    ...

def verify_gateway_receipt(
    receipt_json: str,
    execution_public_key_hex: str,
    key_id: str,
    evidence_attester_public_key_hex: str,
) -> bool:
    """Verify a historical gateway receipt; True does not mean its state is final."""
    ...

def verify_final_gateway_receipt(
    receipt_json: str,
    execution_public_key_hex: str,
    key_id: str,
    evidence_attester_public_key_hex: str,
) -> bool:
    """Verify a historical gateway receipt and require its signed state to be final."""
    ...

def gateway_receipt_finality(
    receipt_json: str,
    execution_public_key_hex: str,
    key_id: str,
    evidence_attester_public_key_hex: str,
) -> tuple[bool, str | None] | None:
    """None unless the receipt verifies; else (final, non_final_reason).

    non_final_reason is "awaiting_approval" (schema v5),
    "awaiting_approval_or_legacy", "outcome_unknown" or None.
    """
    ...
