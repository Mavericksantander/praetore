def verify_evidence_integrity(evidence_json: str) -> bool:
    """Verify historical evidence integrity, not current authorization."""
    ...

def verify_evidence_attester_signature(
    evidence_json: str, attester_public_key_hex: str
) -> bool:
    """Verify historical evidence authenticity, not current authorization."""
    ...
