# Contributing

## Local validation

Use Rust 1.88 or newer for workspace builds. Run these checks before opening a
pull request:

```sh
cargo test --workspace --locked
cargo run --locked --package praetore-core --example high_assurance
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
git diff --check
```

Security advisory checks use RustSec's database:

```sh
cargo install cargo-audit --version 0.22.2 --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
```

Canonical policy digest, authority, intent, evidence, and agent-key
fingerprint golden vectors are checked by core unit tests in the workspace
test command above. Treat `docs/golden/*-v1.json` as compatibility fixtures;
codec changes require a deliberate versioned migration.

The PostgreSQL replay adapter's integration tests need a disposable database.
The CI job provides one and runs duplicate-client, concurrent-claim, and
connection-loss/recovery tests:

```sh
export PRAETORE_TEST_DATABASE_URL=postgres://localhost:5432/praetore_test
cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored claim_is_unique_and_survives_a_new_client
cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored concurrent_connections_allow_exactly_one_claim
cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored a_lost_database_connection_fails_closed_and_a_new_client_recovers
```

Do not use a production database: tests intentionally retain claims and apply
the test migration. A separate staged test,
`replay_claim_survives_server_restart`, uses a fixed test claim ID and requires
a server restart between `PRAETORE_TEST_RESTART_PHASE=before` and
`PRAETORE_TEST_RESTART_PHASE=after`. Run it only against a disposable cluster
that you can stop and restart; CI does not orchestrate this service lifecycle.

A second staged test,
`postgres_journal_survives_server_restart_without_automatic_dispatch`, works
the same way with `PRAETORE_TEST_JOURNAL_RESTART_PHASE`: run it with
`PRAETORE_TEST_JOURNAL_RESTART_PHASE=before`, restart the PostgreSQL server,
then run it with `PRAETORE_TEST_JOURNAL_RESTART_PHASE=after`. The same
disposable-cluster requirement applies.

Running `cargo test -- --ignored` without the phase variables exits with code
101, because both restart tests intentionally abort when their phase variable
is unset. For a bulk run, skip them, then run each restart test in two phases:

```sh
cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored \
  --skip replay_claim_survives_server_restart \
  --skip postgres_journal_survives_server_restart_without_automatic_dispatch

PRAETORE_TEST_RESTART_PHASE=before cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored --exact replay_claim_survives_server_restart
# restart the PostgreSQL server
PRAETORE_TEST_RESTART_PHASE=after cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored --exact replay_claim_survives_server_restart

PRAETORE_TEST_JOURNAL_RESTART_PHASE=before cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored --exact postgres_journal_survives_server_restart_without_automatic_dispatch
# restart the PostgreSQL server
PRAETORE_TEST_JOURNAL_RESTART_PHASE=after cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored --exact postgres_journal_survives_server_restart_without_automatic_dispatch
```

To refresh the standalone fuzzer lockfile when its manifest changes, run
`cargo generate-lockfile --manifest-path fuzz/Cargo.toml`, then audit and fuzz
the resulting locked dependency graph.

## Fuzzing

Install a nightly toolchain with LLVM sanitizer support and `cargo-fuzz`, then
run a short smoke campaign from the repository root:

```sh
rustup toolchain install nightly --profile minimal --component llvm-tools-preview
cargo +nightly install cargo-fuzz --locked
cargo +nightly check --manifest-path fuzz/Cargo.toml --locked
cargo +nightly fuzz run --fuzz-dir fuzz canonical_json -- -max_total_time=10
cargo +nightly fuzz run --fuzz-dir fuzz policy_parse -- -max_total_time=10
cargo +nightly fuzz run --fuzz-dir fuzz authority_verify -- -max_total_time=10
cargo +nightly fuzz run --fuzz-dir fuzz evidence_verify -- -max_total_time=10
cargo +nightly fuzz run --fuzz-dir fuzz engine_evaluate_dev -- -max_total_time=10
cargo +nightly fuzz run --fuzz-dir fuzz engine_evaluate_high_assurance -- -max_total_time=10
```

Remove the time limit for longer local campaigns. Review and minimize fuzz
artifacts before adding a reproducer to a checked-in corpus. Corpus inputs use
deterministic test keys; never add production private keys or trust-store
material.

## Python verifier

The Python package is a thin PyO3 wrapper over `praetore-core`. It intentionally
does not implement policy evaluation or authority issuance in Python.

```sh
python -m pip install ./packages/praetore-python
python -m unittest discover -s packages/praetore-python/tests -v
```

## SBOM and releases

CI generates CycloneDX JSON SBOMs for each Rust package and the standalone
fuzzer, then uploads them as artifacts. To generate them locally:

```sh
cargo install cargo-cyclonedx --version 0.5.9 --locked
cargo cyclonedx --manifest-path crates/praetore-core/Cargo.toml --format json --all
cargo cyclonedx --manifest-path crates/praetore-verify/Cargo.toml --format json --all
cargo cyclonedx --manifest-path crates/praetore-python/Cargo.toml --format json --all
cargo cyclonedx --manifest-path crates/praetore-replay-postgres/Cargo.toml --format json --all
cargo cyclonedx --manifest-path crates/praetore-gateway/Cargo.toml --format json --all
cargo cyclonedx --manifest-path fuzz/Cargo.toml --format json --all
```

A pushed `vX.Y.Z` tag builds the `praetore-verify` binary and the
`praetore-mcp` archives (Linux x86_64, macOS arm64 and x86_64), writes one
`SHA256SUMS` (also kept as the `release-assets-vX.Y.Z` workflow artifact),
signs it with Sigstore keyless signing (`SHA256SUMS.sigstore.json`, a
short-lived certificate for this workflow's GitHub OIDC identity, logged in
Rekor), and creates the GitHub Release with those files and the tag's
`CHANGELOG.md` section as notes (`scripts/release-notes.sh`; a tag without a
dated section fails, and an existing release is never overwritten). Tags with
a `-` suffix are marked as pre-releases. The same checks, with a throwaway
key instead of keyless signing, run on every PR. Before pushing a release tag:

1. Update the `Unreleased` section in `CHANGELOG.md` and verify the release
   version matches the workspace package version.
2. Run the complete CI assurance workflow and review the audit and SBOM
   artifacts.
3. Create and verify a signed annotated tag using an authorized release key:

   ```sh
   git tag -s vX.Y.Z -m "PRÆTORE vX.Y.Z"
   git verify-tag vX.Y.Z
   git push origin vX.Y.Z
   ```

4. Check the GitHub Release that CI created: verify the `SHA256SUMS`
   signature and checksums as below, and attach the corresponding SBOM from
   the workflow artifacts.

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/Mavericksantander/praetore/.github/workflows/assurance.yml@refs/tags/vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

CI holds no long-lived signing key and does not create or sign tags. The
macOS binaries are not signed or notarized (that needs an Apple Developer
account).