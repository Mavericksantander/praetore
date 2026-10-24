# Contributing

## Local validation

Use Rust 1.85 or newer for workspace builds. Run these checks before opening a
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

The canonical policy digest golden vector is checked by core unit tests in the
workspace test command above.

The PostgreSQL replay adapter's integration tests need a disposable database.
The CI job provides one and runs:

```sh
PRAETORE_TEST_DATABASE_URL=postgres://user:password@localhost/praetore_test \
  cargo test -p praetore-replay-postgres --locked --test postgres -- --ignored
```

Do not use a production database: tests intentionally retain claims and apply
the test migration.

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
cargo cyclonedx --manifest-path fuzz/Cargo.toml --format json --all
```

Release tags also build the `praetore-verify` binary and publish a `SHA256SUMS`
file as a workflow artifact. Before publishing a release:

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

4. Download the `release-assets-vX.Y.Z` artifact, verify `SHA256SUMS`, and
   publish the binary, checksum, and corresponding SBOM through the approved
   release channel.

CI does not hold signing keys, create signed tags, or attest release artifacts.