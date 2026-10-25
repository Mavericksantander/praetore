# Pre-user high-assurance deployment gates

This is a deployment acceptance checklist, not a certification claim. No
external or operational user should rely on PRÆTORE for a high-consequence
decision until every gate applicable to that deployment is evidenced and
approved by named technical and operational owners.

## Current engineering state

- [x] Rust authorization core, signed identity/authority/intent, policy pin,
  attested evidence, and offline verifier exist.
- [x] HighAssurance requires a caller-owned replay guard and fails closed when
  the guard is missing, unavailable, or reports a duplicate request.
- [x] Unit tests cover replay guard requirement, concurrent duplicate
  evaluation, and storage-unavailable failure behavior.
- [ ] Independent review of the current candidate after the versioned
  HighAssurance security remediation. Earlier reviews are not release signoff
  and did not cover the current candidate or deployment-specific adapters.
- [x] Optional PostgreSQL adapter uses an atomic primary-key claim, requests
  synchronous primary WAL commit, and includes disposable-service concurrency
  and persistence integration tests.
- [ ] Hosted assurance workflow passes on the final candidate commit.
- [ ] Repository branch protection requires all assurance checks and disallows
  unreviewed direct changes to the release branch.
- [ ] PostgreSQL adapter integration job passes in hosted CI.
- [ ] The target database's synchronous replication, fencing, backup/restore,
  capacity exhaustion, and outage behavior are tested and approved.

## Required deployment evidence

For each target deployment, retain evidence for every applicable item:

1. **Trust configuration:** issuer and attester key custody, independent pin
   distribution, rotation/compromise procedures, protected policy digests, and
   prevention or detection of unauthorized rollback.
2. **Replay persistence:** a linearizable one-time claim shared by all engine
   instances, durable across restart/failover, no silent eviction or rollback,
   bounded-capacity fail-closed behavior, and recovery tests. The core trait
   does not supply this backend.
3. **Execution boundary:** prove that the protected action is performed only
   after the intended authorization result, and define recovery for a process
   crash between claim, result delivery, and action execution. PRÆTORE does not
   make authorization and application side effects atomic. Use the
   [tool gateway integration pattern](tool-gateway-integration.md) as a
   baseline for bypass controls, action binding, journaling, and crash
   reconciliation; validate it against the actual downstream tool semantics.
   The workspace `praetore-gateway` crate is a synchronous reference only; it
   does not provide a production gateway service or durable journal by itself.
   The gateway-side mTLS dispatcher and Kubernetes supervisor/Job lifecycle
   now exist. The production tool-runner image, durable recovery of in-flight
   worker results, operator cleanup after supervisor interruption, and live
   cluster tests remain outstanding. The Firecracker/Kata and per-invocation
   Job manifests remain deployment templates only: no sandbox claim is
   established until the complete path and target cluster are tested. Validate the
   `ValidatingAdmissionPolicy` CEL expressions against the target Kubernetes
   API server and demonstrate that privileged images, altered commands,
   retries, extra volumes, and worker API access are rejected.
4. **Time and validity:** monitored trusted time, measured skew, alerting and
   fail-closed behavior when clock health is lost. The library adds no skew
   tolerance and cannot identify a manipulated host clock.
5. **Host and key protection:** operating-system hardening, process isolation,
   secrets handling, key custody/HSM policy if required, access control, logs,
   backups, and incident response. These are outside the core.
6. **Supply chain and release:** reviewed dependency changes, signed source
   tags, independently verified release checksums/SBOM, protected build
   provenance, action/toolchain pinning policy, and a reproducible release
   procedure. Current CI does not sign or attest artifacts.
7. **Adversarial verification:** independent review of the final commit and
   deployment adapter, extended fuzz campaigns, negative end-to-end scenarios,
   concurrency testing, and a documented remediation/exception process.
8. **Operational ownership:** named approvers for policy and key changes,
   monitoring and on-call responsibilities, stop/recovery procedures, and
   explicit acceptance of residual risks.

## Stop conditions

Do not enable authorization if any required pin is missing, expired, or
mismatched; the policy digest is not approved; replay storage is unavailable,
full, inconsistent, or rolled back; the clock is unhealthy; evidence cannot be
verified; or the application would fall back to Development mode. Do not treat
a green CI run, this checklist, or the independent code review as a military
certification or accreditation.
