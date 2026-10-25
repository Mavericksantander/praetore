# Runtime security scaffold

Status: integration skeleton, not a production sandbox or trusted-time
implementation. It makes the runtime boundaries explicit while leaving the
cluster-specific isolation backend and trusted time source to deployment
owners.

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

The repository has no process-execution tool adapter or sandbox supervisor
yet. The gateway's `ActionDispatcher` is the integration seam: add an adapter
that submits a typed, bounded tool invocation to the sandbox supervisor;
never run agent-selected shell commands in the gateway process. The template
does not attest the sandbox, isolate the gateway, or guarantee that a
particular cluster runtime is configured correctly.

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

Before enabling a protected tool, verify from the actual agent and gateway
pods that direct paths, redirects, alternate DNS/IP routes, cloud metadata,
node ports, and any service-mesh side paths are denied as intended. Maintain
a route/configuration inventory by tenant and review changes as security
policy. Network reachability controls complement authorization; neither
replaces the other.

## Implementation sequence

1. Install the Firecracker-backed Kata handler on dedicated Linux/KVM nodes,
   restrict RuntimeClass and node-label mutation to cluster administrators,
   and add admission rules plus adversarial escape/resource-exhaustion tests.
2. Configure chronyd with approved, monitored time sources and a restricted
   query-only command endpoint; test loss of sync, stale status, excessive
   uncertainty, clock rollback, query timeout, and recovery without fallback.
3. Apply the Cilium template with exact tool FQDNs, enforce the same allowlist
   in the proxy/firewall, and test direct egress, DNS rebinding, metadata,
   NodePort, service-mesh and alternate-IP bypasses from real pods.
4. Record runtime image/handler version, clock health/error bound, egress
   policy version and policy digest in deployment telemetry, without logging
   credentials or sensitive tool parameters.

Rust tests cover the clock-health contract and repository tests exercise the
dispatcher parser; manifest syntax checks do not validate Kubernetes
admission, Firecracker/Kata operation, Cilium's effective policy, or the
external proxy. Passing repository tests does not verify the external runtime,
clock, CNI, proxy, or cloud network configuration.
