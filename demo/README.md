# Receipt verification demo

One command:

```sh
./demo/verify-receipt.sh
```

It runs `crates/praetore-receipt/examples/demo_receipt_verify.rs`
(requires the `signing` feature, enabled by the script) and:

1. Derives a **DEMO/TEST-ONLY** Ed25519 key from a fixed, public seed.
   Anyone can recompute it. Never use it to sign anything real.
2. Issues and signs a fictitious gateway receipt (high-assurance evidence
   plus a signed execution attestation).
3. Verifies the receipt with `verify_gateway_receipt_json` using only the
   public key and key id. The verification function never receives the
   private key.
4. Changes one byte of the receipt and shows the rejection with the exact
   error:
   - 4a: one hex digit of the execution attestation signature →
     `InvalidSignature`.
   - 4b: one byte of the recorded output (`rows` 3 → 4) → `InvalidPayload`.

Exit code is 0 only if step 3 passes and both tampered copies are rejected
with the expected error; otherwise non-zero. CI runs it in `assurance.yml`.

Scope: on `main`, `verify_gateway_receipt_json` checks the execution
attestation and its binding to the embedded evidence. It does not verify the
evidence attester signature; that is the subject of a separate open change.
The demo proves integrity of a historical record only; it does not authorize
anything.
