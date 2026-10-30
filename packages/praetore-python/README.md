# PRÆTORE Python bindings

This package exposes Rust-backed offline evidence verification only:

```python
import praetore

intact = praetore.verify_evidence_integrity(evidence_json)
authentic = praetore.verify_evidence_attester_signature(
    evidence_json, trusted_attester_public_key_hex
)

receipt_ok = praetore.verify_gateway_receipt(
    receipt_json,
    trusted_execution_public_key_hex,
    "execution-key-id",
    trusted_evidence_attester_public_key_hex,
)
```

`verify_gateway_receipt` checks a gateway receipt's signed execution
attestation (schema v1, v2 or v3) and the evidence `attester_signature`
against the pinned evidence attester key. It rejects an unknown or tampered
`not_dispatched_reason` and a missing, forged or foreign evidence signature.

All functions return `False` for malformed, tampered, or unverifiable input.
The public key must be a trusted Ed25519 key provisioned independently from the
evidence. These functions verify historical evidence integrity or attester
authenticity only: they do not check current freshness, replay state, policy,
or permission to execute an action. A `True` result is never an execution
authorization.

Policy evaluation and authority issuance are intentionally not implemented in
Python; use `praetore-core` so Rust remains the source of truth. Build/install
from this directory with `python -m pip install .`. The package requires a Rust
toolchain because Maturin compiles its PyO3 extension.

Run package tests with:

```sh
python -m unittest discover -s tests
```
