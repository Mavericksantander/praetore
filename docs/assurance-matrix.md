# Assurance traceability matrix

This matrix describes implemented checks and their routine CI coverage. Green
tests are evidence for the listed properties, not certification or proof of
absence of defects.

| Requirement | Implementation | Test / evidence | CI job |
|---|---|---|---|
| Stable canonical encoding and policy digest | `crates/praetore-core/src/canonical.rs`, `policy.rs` | `policy_canonical_bytes_match_committed_golden_vector`, `policy_digest_matches_canonical_golden_value`; `docs/golden/canonical-policy-v1.json` | `rust` |
| Duplicate-key and bounded JSON input handling | core canonical parser and `Authority::from_json` | canonical, policy, authority, evidence, and pin parser unit tests | `rust`, `fuzz-smoke` |
| Offline evidence integrity and attester authentication | `crates/praetore-verify/src/main.rs` | `evidence_command_verifies_trusted_signature_intent_and_authority`, tampering and wrong-pin integration cases | `rust` |
| Signed authority and optional subject-key comparison | verifier authority command and `TrustedAuthorityIssuer::verify_authority_at` | `authority_and_policy_digest_commands_verify_and_report_stable_results` | `rust` |
| Policy digest reporting | `Policy::from_json` and `Policy::digest` in verifier | policy digest integration case and golden-vector unit tests | `rust` |
| Parser/evaluator no-panic exploration | `fuzz/fuzz_targets/*.rs` | Five seeded libFuzzer target corpora | `fuzz-smoke` (10 seconds per target) |
| Dependency advisory gate | committed `Cargo.lock` and RustSec audit | `cargo audit --locked` | `audit` |
| Python verification behavior stays Rust-backed | `crates/praetore-python/src/lib.rs` and `praetore` package | `packages/praetore-python/tests/test_verify.py` | `python-verify` |
| Rust tests, lint, format, patch hygiene | workspace CI workflow | workspace test suite; Clippy `-D warnings`; workspace and fuzz rustfmt; `git diff --check` | `rust` |
| Software inventory | CycloneDX Cargo integration | SBOMs for all three Rust packages and standalone fuzz package uploaded as CI artifacts | `sbom` |
| Release binary integrity | tag-triggered verifier build/checksum job | `SHA256SUMS` uploaded with release binary | `release-integrity` |

## Scope limitations

- The verifier requires external attester pins and never treats a key embedded
  in evidence or authority as a trust anchor. Pin distribution is outside the
  CLI. `--require-intent` is only accepted with external issuer pins.
- Standalone authority verification can compare subject-key binding against an
  `AgentIdentity` only when the optional `--agent` input is provided.
- Fuzz CI runs bounded smoke intervals. It is not an exhaustive campaign.
- Python exposes evidence verification only. Policy evaluation and authority
  verification remain in Rust/CLI.
- CI produces an SBOM and checksums, but does not sign releases, attest
  artifacts, or protect the hosted runner/build supply chain.
