# Operations runbooks

These are operator procedures for deployments embedding the library. Praetore
Core does not persist trust state, distribute keys or policies, manage a secure
clock, or control application rollout. Use the `HighAssuranceConfig` production
profile and an authenticated configuration channel.

## Issuer key rotation

1. Generate the replacement Ed25519 issuer key in the approved key-protection
   boundary; do not place its private key in a pin document.
2. Export a new issuer pin with a bounded validity window overlapping the
   currently trusted pin. Validate and authenticate the pin document through
   the deployment's independent configuration channel.
3. Deploy both pins and confirm the effective configuration has the expected
   issuer names, key IDs, algorithms, and validity windows.
4. Issue new authorities with the replacement key and verify a staged
   authorization, including offline evidence verification.
5. After all old authorities have expired or been replaced, remove the old
   pin. Do not extend old pin validity merely to avoid an operational outage.
6. For suspected compromise, remove the affected pin immediately, reject
   authorities signed by it, and reissue necessary authorities. Expect fail
   closed behavior until a replacement pin is distributed.

## Agent key compromise

1. Stop or isolate the affected agent and prevent further use of its private
   key.
2. Remove or replace authorities bound to the compromised agent public key.
   The core has no revocation list or replay cache; a still-valid authority
   remains verifiable until relying deployments stop trusting it or it expires.
3. Provision a new agent key using the approved key-protection mechanism,
   issue a new subject-bound authority, and verify a signed request end to end.
4. Preserve existing evidence and separately identify the compromise window;
   do not rewrite evidence or claim the old signatures identify the legitimate
   agent operator.

## Policy rollback or substitution

1. Treat every policy digest as an immutable deployment identifier. Before
   rollout, calculate the digest using the crate's canonical codec and compare
   it to the independently approved pin.
2. For an approved rollback, explicitly approve and deploy the prior policy
   digest through the protected configuration channel. The core does not
   maintain monotonic policy version state, so deployment controls must prevent
   an unapproved rollback.
3. If the configured policy does not match its pin, do not downgrade to
   Development or remove the pin to restore service. Restore the approved
   policy/configuration pair and investigate the mismatch.
4. Confirm evaluation output includes the expected policy ID, version, and
   digest before resuming dependent operations.

## Clock source and validity boundaries

1. Provide a monitored UTC clock appropriate to the deployment's risk profile.
   The library applies exact inclusive `not_before` / `not_after` checks and
   adds no skew tolerance.
2. Keep operational margin when issuing authorities and issuer pins to account
   for measured clock uncertainty. Do not widen validity windows as a substitute
   for repairing clock synchronization.
3. Alert on clock-health loss and stop authorization if the configured clock
   cannot be trusted. The core cannot distinguish a correct clock from a
   manipulated host clock.
4. In tests and incident replay, use a fixed clock and preserve the exact
   timestamp supplied to evaluation.

## Production profile checks

Before deployment, verify that:

- engine construction uses `AuthorizationEngine::production`, not `new`,
  `with_clock`, or `development`;
- the policy digest matches an approved pin;
- issuer pins are non-empty, time-bounded, and active;
- an evidence attester key is configured separately from agent and issuer
  keys, and evidence consumers trust its public key out of band;
- the application fails closed on configuration errors and does not silently
  retry in Development mode.

The library does not authenticate deployment configuration, protect the host
process, or provide a signed deployment/rollback mechanism.

## Offline evidence and authority verification

Build the verifier from the locked workspace:

```sh
cargo install --path crates/praetore-verify --locked
# Or produce a local release binary:
cargo build --release --locked --package praetore-verify
```

Use an attester pin file containing the independently provisioned lowercase
hex Ed25519 public key. Issuer pins are supplied as JSON Lines, one
`TrustedAuthorityIssuer::export_pin_json()` document per line. Do not derive
trust pins from the evidence or authority being verified.

```sh
target/release/praetore-verify evidence \
  --evidence evidence.json \
  --attester-pin attester-public-key.hex \
  --issuer-pins issuer-pins.jsonl \
  --require-intent \
  --format json
```

`--issuer-pins` on evidence verification additionally validates the authority
signature, pin validity, and authority subject-key binding against the
evidence agent. `--require-intent` requires `--issuer-pins`, preventing an
intent signature from being accepted under only a self-asserted embedded
agent key. For standalone authority documents, `--agent agent.json` is
optional; without it, the CLI verifies the signed subject-key hash is present
but cannot compare it to a separately supplied agent identity. Use JSON output
for machine consumption and check both exit status and `code`.

`praetore-verify policy-digest --policy policy.json --format json` prints the
canonical policy digest. This command computes a digest; it does not establish
that the policy is approved. Compare the result with the independently
provisioned production pin.

The Python package provides Rust-backed integrity and attester signature
verification only. It does not evaluate policies or establish trust in a
public key supplied by an untrusted caller.

## Release artifact integrity

For a `v*` tag, CI builds `praetore-verify` and uploads the binary and
`SHA256SUMS` as a workflow artifact. CI also uploads CycloneDX workspace SBOM
files. Follow the signed-tag procedure in [CONTRIBUTING.md](../CONTRIBUTING.md),
download those artifacts, verify the checksum, and publish them with the
release. CI does not sign artifacts or create releases automatically.
