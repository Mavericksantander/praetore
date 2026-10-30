# Runtime security scaffold

Status: hardened deployment scaffolding, not yet an end-to-end sandbox
service or trusted-time implementation. The repository now includes the
supervisor control service, but the reviewed production runner and validated
cluster operation are still outstanding. The manifests specify the intended
least-privilege boundary.

## Agent sandbox

[`deploy/kubernetes/agent-sandbox-pod.template.yaml`](../deploy/kubernetes/agent-sandbox-pod.template.yaml)
is a Pod template with a dedicated `praetore-firecracker` RuntimeClass, non-root
execution, a read-only root filesystem, the default seccomp profile, dropped
Linux capabilities, bounded resources, and no host namespaces or service
account token. It is paired with
[`firecracker-runtime-class.yaml`](../deploy/kubernetes/firecracker-runtime-class.yaml)
and a namespace configured for Kubernetes Pod Security `restricted`. Replace
the image and workload name before use. The cluster operator must install and
configure Kata Containers with its Firecracker hypervisor handler named
`kata-firecracker` (or update the RuntimeClass handler to the installed
name), expose a node label only on compatible nodes, and verify the Firecracker
jailer and host KVM configuration. Kubernetes RuntimeClass merely selects a
CRI handler; it does not install, attest, or configure that runtime.

Firecracker requires a Linux/KVM-capable host. On AWS this usually means
bare-metal instances; confirm the supported architecture, kernel, KVM access,
CRI/runtime versions, guest kernel and root filesystem with the chosen Kata
deployment. Do not grant the agent container `/dev/kvm`, privileged mode,
host namespaces, or a hostPath to make a pod work. Run the microVM through
the configured Kata handler and its jailer. The template intentionally has no
direct access to the host virtualization device.

Use it with the
[`mandatory-enforcement.yaml`](../deploy/kubernetes/mandatory-enforcement.yaml)
and, when Cilium is the enforcing CNI,
[`cilium-mandatory-enforcement.yaml`](../deploy/kubernetes/cilium-mandatory-enforcement.yaml),
not as a replacement for them. Apply admission policy that rejects agent
workloads with host networking, privileged containers, added capabilities,
hostPath mounts, unreviewed images, or a different RuntimeClass. Use a
dedicated node pool when the threat model requires it. A Kubernetes
`NetworkPolicy` is effective only with an enforcing CNI, is additive, and does
not by itself constrain node/metadata paths or host-network workloads. Verify
those paths in the target cluster before production.

[`tool-invocation-job.template.yaml`](../deploy/kubernetes/tool-invocation-job.template.yaml)
defines the target execution unit: one Job and one Firecracker-backed
microVM per authorized tool call, with no retries, a fixed runner entrypoint,
an approved digest-pinned image, a read-only one-time invocation Secret,
bounded CPU/memory/storage, a hard deadline, and automatic Job cleanup.
Never construct the container command or image from agent-controlled fields;
map the verified action to an operator-approved tool profile. Pass results
back to the supervisor over authenticated TLS; do not use pod logs as an
application result channel because tool output may contain sensitive data.
The supervisor creates the Job suspended, then creates its one-time Secret
with a Job owner reference, and only then unsuspends the Job. This prevents
the runner from starting before its immutable input Secret exists. Use a deterministic,
non-sensitive execution label derived from the execution key only; store a
full execution-key SHA-256 and action SHA-256 in annotations and the
invocation payload. The 52-character hexadecimal label prefix (208 bits)
fits Kubernetes label limits. Using only the execution key for the Job and
Secret names makes retries idempotent; if that key is presented with a
different action digest, the supervisor must reject it rather than create a
second Job. The durable gateway journal remains the authority for dispatch
uniqueness. Gateway traffic uses mTLS on port 8443; the worker callback uses
server-authenticated TLS and a per-invocation result token on port 8444.

[`sandbox-namespace.yaml`](../deploy/kubernetes/sandbox-namespace.yaml)
establishes a dedicated restricted namespace, a worker ServiceAccount with no
API token, and a supervisor Role scoped to that namespace. Only the supervisor
receives Kubernetes API credentials; its Role is limited to creating, reading,
patching, and deleting Jobs, and creating Secrets and ConfigMaps. ConfigMaps
are immutable, payload-free execution claims that remain after Job TTL cleanup;
their deterministic names prevent the same key from creating a second Job
after restart or TTL expiry. The namespace quota caps ConfigMaps at 10,000;
when exhausted, new invocations fail closed. Claims cannot be updated, and the
supervisor cannot delete them. Claims are a second, Kubernetes-side duplicate
guard: the PostgreSQL journal is the authority for dispatch uniqueness (a key
whose journal row has left `authorized`/`approved_pending_dispatch` is never
dispatched again). Reclaim capacity with an operator-owned retention job
running as `system:serviceaccount:praetore-security:claim-retention` (Role
`praetore-sandbox-claim-retention`, the only identity admission lets delete a
claim besides namespace deletion). It must delete a claim only after
confirming, with a read-only journal query, that the matching execution key is
terminal (`executed`, `confirmed`, `failed`, or `not_dispatched` with a
reason) and never for `dispatched` or `outcome_unknown`. The retention job is
not part of this repository. The supervisor's Job deletion is used only to
clean up a still-suspended Job when input provisioning fails. It cannot list
workloads or read Secret contents through the API; invocation Secrets are
immutable and Kubernetes garbage collection owns their cleanup. The gateway
must call the supervisor through a separately authenticated service boundary
and must not receive permission to create Jobs or Secrets.

The supervisor revalidates the authority and action structures on gateway
dispatch, then binds the worker callback to the result-token hash, exact
action digest, and execution-key hash stored on the Job. The token and action
digests are first compared against the in-memory pending execution, so a
callback for an unknown key or with a wrong token is refused before any
Kubernetes API request; the Job annotations are then checked as well. Digest
comparisons use a constant-time primitive and the one-shot pending result is
removed only after all bindings match. The callback listener closes excess
connections at accept instead of queueing them, allows at most four
concurrent connections per peer IP, enforces a 5 s header read timeout and
closes each connection after 20 s, so one pod cannot hold the listener's 128
connection slots. This authenticates possession of the per-invocation
bearer token, not the truthfulness of the runner's output; compromised runner
code can still submit a false result for its own invocation. The callback and
restart path still need integration tests against a representative cluster.

Install
[`sandbox-admission-and-capacity.yaml`](../deploy/kubernetes/sandbox-admission-and-capacity.yaml)
before enabling supervisor credentials. Its fail-closed
`ValidatingAdmissionPolicy` rules require single-shot immutable Jobs, the
Firecracker RuntimeClass, a fixed command, a digest-pinned approved runner
image, non-root/read-only execution, strict volume mounts, immutable
invocation Secrets, and namespace quotas/limits. Rules that inspect objects
read `oldObject` on DELETE (where `object` is null). The ConfigMap policy only
governs execution claims (`claim-*` names or the `execution-claim` label), the
`praetore-sandbox-supervisor-ca` ConfigMap (TLS provisioner only) and the
supervisor's own requests (create claims only); `kube-root-ca.crt` and other
operator ConfigMaps are left to RBAC. The Job policy does not apply to updates
by the garbage collector, TTL-after-finished or Job controllers that only
remove finalizers from a Job that is being deleted, so Foreground deletion
(used by the TTL controller and by supervisor cleanup) can complete. Replace
those controller identities with the ones the cluster actually uses
(`system:kube-controller-manager` when controllers do not use per-controller
ServiceAccounts). The policy is intentionally
bound to Kubernetes 1.30+ and the example runner image pattern must be changed
to the exact reviewed image repository before use. It also prevents the
supervisor ServiceAccount from creating its own TLS certificate and restricts
Job, invocation Secret, and execution-claim creation to the appropriate
supervisor/provisioner identities. Jobs can only be created
suspended, then unsuspended without changing their action or pod template.
Provision
the immutable `praetore-supervisor-tls` Secret with a separate operator-owned
TLS-provisioner ServiceAccount (`system:serviceaccount:praetore-security:tls-provisioner`
in the template); change the CEL identity to the exact certificate-controller
principal used by the cluster. Rotate the immutable Secret by deleting and
recreating it, then restart the supervisor and gateway so they reload keys.
Test CEL evaluation with
the target API server; YAML parsing alone does not validate admission rules.
These admission and network templates have not been tested on a cluster; CI
checks YAML syntax only.
Add supervisor-side request/concurrency limits as well, because namespace
quotas are shared capacity limits, not per-tenant fairness controls.

[`sandbox-network-policy.yaml`](../deploy/kubernetes/sandbox-network-policy.yaml)
provides a portable NetworkPolicy baseline: sandbox ingress is denied except
gateway mTLS on supervisor port 8443 and worker callbacks over TLS on port
8444. Workers can egress only to the callback, their egress proxy, and cluster
DNS. Workers and the gateway use different proxies: workers use
`egress-proxy` (the Service name fixed in the supervisor Job spec and in
admission), which accepts only `tool-invocation` pods and may reach only
public addresses (generic profile) or the listed FQDNs (Cilium profile); the
gateway uses `gateway-egress-proxy`, which accepts only the gateway and is the
only source the `praetore-tools` policies accept. A tool runner therefore
cannot reach a protected tool through a proxy. Run the two proxies as
separate Deployments with distinct `app.kubernetes.io/name` labels.
The main
[`mandatory-enforcement.yaml`](../deploy/kubernetes/mandatory-enforcement.yaml)
also allows the gateway to reach the supervisor on port 8443. The generic
profile requires a CNI that enforces NetworkPolicy. The Cilium supervisor
ingress policy provides the same gateway/worker paths, and its proxy policy
permits worker HTTPS proxy traffic. This generic profile cannot portably
select the Kubernetes API server for supervisor egress; restrict that path
with the cluster firewall or use the Cilium profile, which allows the
supervisor's API access explicitly. Do not combine the generic and Cilium
profiles.

Enable encryption at rest for Secrets, use one-time credentials with short
expiry, and configure operator-managed TLS key material separately from
invocation inputs. The supervisor Role intentionally has no pod-log
permission; it must not use logs to retrieve action output. The Job template
also expects a trusted `praetore-sandbox-supervisor-ca` ConfigMap and a
supervisor Service on ports 8443 and 8444. Provision the matching
`praetore-supervisor-tls` Secret through an operator-owned certificate
controller; do not grant the supervisor permission to create or rotate its
own TLS identity. Configure the gateway client to validate the supervisor
certificate and authenticate with mTLS. Tool profiles use the configured
egress proxy; network policy must still block direct egress if a runner
ignores proxy environment variables.

The gateway now has a `sandbox` adapter that sends the verified tenant,
execution key, exact action and action digest to a startup-configured
supervisor endpoint using mutual TLS. Configure
`PRAETORE_GATEWAY_SANDBOX_SUPERVISOR_URL`,
`PRAETORE_GATEWAY_SANDBOX_CA_FILE`, and
`PRAETORE_GATEWAY_SANDBOX_CLIENT_IDENTITY_FILE`, plus the normal issuer
bindings, audience, and trusted-clock settings. The client rejects non-HTTPS
URLs and redirects, bounds request/response sizes, and reports transport or
protocol failures as ambiguous outcomes; it never retries a tool call itself.
`POST /v1/executions` carries schema version 1, the tenant-scoped execution
key, verified authority, exact normalized action, and action digest. Its
`Idempotency-Key` is the tenant, agent, and request UUID tuple. A successful
response is a serialized `DispatchReport`. The reconciliation endpoint is
`GET /v1/executions/{tenant}/{agent}/{request}` and must return schema version
1, the same action digest, a status, and output only when independently
established. The supervisor must treat the idempotency key and action binding
as a single-use key, and reconciliation must remain conservative.

The repository now includes a supervisor binary and a Kubernetes-backed
single-shot Job path. Before creating a Job, the supervisor writes an
immutable ConfigMap claim for the execution key and action digest. Claims
survive Job TTL cleanup; duplicate keys fail closed, and quota exhaustion
blocks new runs until the claim-retention job (above) removes claims of
terminal executions or capacity is expanded after review. Gateway mTLS is isolated on supervisor port 8443; the
worker result callback uses server-authenticated TLS plus its one-time token
on port 8444. The Job is created suspended, its immutable owner-referenced
input Secret is created, then the supervisor starts the Job. This ordering
prevents a worker from racing Secret creation. Admission allows only the
supervisor ServiceAccount to create/start Jobs and invocation Secrets. The
supervisor has one replica because in-flight callback waiters are in memory;
after a crash the gateway outcome is `Unknown`, and a suspended orphan may
require operator cleanup. The persistent claim still prevents a second Job
for that execution key.

Install
[`sandbox-supervisor.template.yaml`](../deploy/kubernetes/sandbox-supervisor.template.yaml)
after replacing both digest-pinned images, tenant/action/profile routes, TLS
material, and the gateway-client CA. The supervisor profile maps an exact
tenant/action/target/capability tuple to a tool profile; agent input cannot
select an image, command, endpoint, or profile. The repository does not
contain the production tool-runner image implementation. Do not select
`PRAETORE_GATEWAY_ADAPTER=sandbox` for production until that runner, TLS
provisioning, target cluster, and adversarial tests have been independently
validated. This path does not attest the microVM or establish an application
side-effect transaction.

## Trusted clock seam

The `praetore-gateway-demo` HTTP adapter now selects
`AuthorizationEngine::production_with_trusted_clock` and uses
`praetore_gateway_service::chrony_clock::ChronyClock`. Configure:

```text
PRAETORE_GATEWAY_ADAPTER=http
PRAETORE_GATEWAY_CHRONYC_PATH=/usr/bin/chronyc
PRAETORE_GATEWAY_CHRONY_POLL_INTERVAL_MS=500
PRAETORE_GATEWAY_CHRONY_MAX_SAMPLE_AGE_MS=2000
PRAETORE_GATEWAY_CHRONY_MAX_ERROR_MS=100
```

The adapter runs the fixed `chronyc -n tracking` query in a background
monitor with a one-second process timeout, accepts only a normal leap status
and a real stratum/reference, and calculates the conservative error bound as
`abs(system offset) + root dispersion + root delay / 2`. It fails startup if
the first health sample is unsynchronized or outside the configured bound.
At evaluation time, a stale sample, query failure, excessive error, or wall
clock rollback returns `TRUSTED_CLOCK_UNAVAILABLE`; there is no fallback.
The health poll is asynchronous, so the authorization path does not spawn a
process for every request.

This checks Chrony's reported synchronization while using the host's UTC
system clock as the timestamp. It is not a hardware-secure clock, independent
time attestation, or proof that NTP sources are trustworthy. The host operator
must authenticate and monitor the configured time sources, set the maximum
acceptable error for the risk, and ensure chronyd disciplines the same kernel
clock used by the gateway. Give the gateway access only to a chronyd control
endpoint whose OS permissions and chronyd policy prevent mutating commands;
if that cannot be enforced, use a separate read-only health broker (not
included here) instead of exposing the chronyd command socket. Do not mount a
writable host clock socket or grant `CAP_SYS_TIME` to the gateway.

`production` and `production_with_clock` remain available but only use their
configured clock value and do not prove its health. The core-level
`TrustedClock` contract and `production_with_trusted_clock` are available for
other adapters. Host clock source authentication, maximum uncertainty,
synchronization monitoring and operational alerts remain deployment
responsibilities.

## Network access control

The gateway HTTP adapter now requires an explicit egress proxy. Fixed
startup-configured HTTPS routes still prevent the agent from selecting an
arbitrary URL, method, or credential. The standard NetworkPolicy example
allows gateway egress to PostgreSQL, DNS, and the proxy, but no longer allows
direct gateway-to-tool traffic. The Cilium policy template additionally
restricts proxy egress to in-cluster protected tools and explicitly listed
external FQDNs.

Before applying
[`cilium-mandatory-enforcement.yaml`](../deploy/kubernetes/cilium-mandatory-enforcement.yaml),
replace `api.example.com` and its subdomains with the exact approved
destinations in both `toFQDNs` and DNS L7 rules; remove unused entries. Also
replace the example in-cluster DNS names with the actual gateway, database and
proxy Service names, including the trailing dot, and configure clients to use
those fully qualified names rather than search-suffix resolution. The agent
and gateway DNS rules are intentionally narrow to reduce DNS
tunneling/exfiltration. The template assumes endpoint
labels/namespaces and ports shown in the YAML, the Cilium CRDs are installed,
DNS proxy is enabled for FQDN policy, and the Cilium agent is enforcing
policies. Choose this Cilium policy set instead of combining it with the
generic Kubernetes NetworkPolicy set: Kubernetes policies are additive and a
broad Layer-4 DNS allow can defeat DNS Layer-7 restrictions. Inspect effective
policy and remove any broader allows. The egress proxy must independently
enforce the same destination allowlist, validate TLS, reject redirects or
CONNECT destinations outside that list, and avoid becoming an open proxy. The
Rust route parser does not enforce DNS/IP allowlists or prevent an operator
from configuring a prohibited endpoint.

Before enabling a protected tool, verify from actual agent, gateway,
supervisor, and invocation-worker pods that direct paths, redirects, alternate
DNS/IP routes, cloud metadata, node ports, and any service-mesh side paths are
denied as intended. Maintain a route/configuration inventory by tenant and
review changes as security policy. Network reachability controls complement
authorization; neither replaces the other.

Use either the generic sandbox NetworkPolicies or the Cilium profile. Workers
must not reach the Kubernetes API, gateway database, other workers, or one
another. The Cilium profile includes scoped supervisor, worker, and proxy
paths: set the matching supervisor labels and verify the cluster's API-server
entity, DNS proxy, proxy behavior, and TLS identities. Do not deploy the
invocation Job template until the admission policy is installed and the
selected network paths are tested.

## Implementation sequence

1. Install the Firecracker-backed Kata handler on dedicated Linux/KVM nodes,
   restrict RuntimeClass and node-label mutation to cluster administrators,
   and test escape/resource-exhaustion controls.
2. Run the supervisor, persistent claims and one-time Job lifecycle against a disposable cluster.
   Test duplicate requests, create/timeout ambiguity, cleanup, result
   authentication, supervisor and worker crashes, admission denials, and
   no-retry behavior. Add durable result recovery before requiring recovery
   rather than `Unknown` after supervisor restart.
3. Configure chronyd with approved, monitored time sources and a restricted
   query-only command endpoint; test loss of sync, stale status, excessive
   uncertainty, clock rollback, query timeout, and recovery without fallback.
4. Apply the Cilium template with exact tool FQDNs, enforce the same allowlist
   in the proxy/firewall, and test direct egress, DNS rebinding, metadata,
   NodePort, service-mesh and alternate-IP bypasses from real pods.
5. Record runtime image/handler version, clock health/error bound, egress
   policy version and policy digest in deployment telemetry, without logging
   credentials or sensitive tool parameters.

Rust tests cover the clock-health contract, dispatcher protocol and supervisor
Job construction; manifest syntax checks do not validate Kubernetes
admission, Firecracker/Kata operation, Cilium's effective policy, or the
external proxy. Passing repository tests does not verify the external runtime,
clock, CNI, proxy, or cloud network configuration.
