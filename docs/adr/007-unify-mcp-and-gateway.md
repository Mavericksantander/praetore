# ADR-007: Unify praetore-mcp and praetore-gateway

## Status

Proposed. Nothing in this record is implemented or decided.

Base: `main` at `0b01386`. Every path and line cited is from that commit.

## Context

The repository holds two products that share only `praetore-core`.

**praetore-mcp** is a local stdio proxy.

- It starts the MCP server as a child process and relays its stdio
  (`crates/praetore-mcp/src/relay.rs:457-462`).
- It evaluates each `tools/call` with the HighAssurance engine of
  `praetore-core`, with an in-memory replay guard and a local freshness
  provider that has no revocation source
  (`crates/praetore-mcp/src/gate.rs:1045-1050`, `:208-212`, `:235`).
- It keeps in the governed user's home the four keys (issuer, agent,
  attester, approver), the policy, the journal and the approvals
  (`crates/praetore-mcp/src/store.rs:76-121`, `:162-227`;
  `crates/praetore-mcp/src/approvals.rs:1-12`).
- Its only workspace dependency is `praetore-core`
  (`crates/praetore-mcp/Cargo.toml:25`).

**praetore-gateway** is an HTTP server on PostgreSQL.

- Routes: `POST /v1/execute` and the approval flow with a single dispatch
  (`crates/praetore-gateway/src/http_api.rs:496-510`).
- Callers present a bearer token bound to one tenant and one of two roles,
  `Agent` and `Approver` (`http_api.rs:39-52`, `:84-95`, `:160-172`).
- The journal is in PostgreSQL with row-level security per tenant
  (`crates/praetore-replay-postgres/migrations/0016_safety_records.sql:133-136`,
  and the earlier migrations with the same `tenant_isolation` policy).
- `praetore-console` has the approvals inbox and the compliance package
  (`crates/praetore-console/src/paquete.rs:1`).
- It does not speak MCP. This command finds no match (exit 1):
  `rg -c -i 'mcp' crates/praetore-gateway crates/praetore-gateway-service crates/praetore-console crates/praetore-observe crates/praetore-replay-postgres crates/praetore-receipt crates/praetore-sandbox-fs crates/praetore-safety-client crates/praetore-python packages deploy`

### Facts in the code that shape the decision

**H1. The seam on the MCP side exists.** The proxy knows only the
`Evaluator` trait, with one method that returns a `Verdict`
(`crates/praetore-mcp/src/gate.rs:156-158`). `Gate` implements it
(`gate.rs:1238`) and `relay` loads it in one place (`relay.rs:420`).

**H2. Both products already use the same request type.** `Gate` builds an
`AuthorizationRequest` (`gate.rs:1172-1177`) and signs it with the agent key
as a v2 intent (`gate.rs:1182`, `:1202`). The same type is the body of
`POST /v1/execute`, which ends in `Gateway::execute`
(`crates/praetore-gateway/src/lib.rs:1478`).

**H3. The gateway always performs the effect and refuses cooperative
execution.** `Gateway` holds an `ActionDispatcher` that performs the action
(`lib.rs:444`, `:673-679`). Outside the development mode, the API answers
409 to a caller that does not declare that the gateway performs the effect,
and never answers `approved` to a polling agent (`http_api.rs:219-241`;
`crates/praetore-gateway-service/src/exec_mode.rs:32-41`). With a stdio MCP
server the effect happens in the child process, on the user's machine. This
is the centre of the decision: neither option avoids it.

**H4. A gateway has one engine and therefore one policy.** `Gateway` holds a
single `AuthorizationEngine` (`lib.rs:673-675`). In praetore-mcp the policy
is per home.

**H5. Different size limits.** The gateway accepts bodies of up to 64 KiB
(`http_api.rs:25`, `:511`). The proxy accepts lines of up to 32 MiB
(`relay.rs:31`).

**H6. The gateway transport is plain HTTP/1 with JSON.** axum with `http1`,
`json` and `tokio`, with no streaming or SSE
(`crates/praetore-gateway/Cargo.toml:13`), and no TLS on the listener
(`crates/praetore-gateway-service/src/main.rs:714-728`).

**H7. Some defenses exist only in the proxy.** The classification of lines
that parsers may read differently (`crates/praetore-mcp/src/proxy.rs:36-54`)
and the resolution of paths against the local filesystem
(`gate.rs:1137-1140`) live in `praetore-mcp`, not in `praetore-core`.

**H8. There is no federated identity.** The command
`rg -n -i 'jsonwebtoken|\bjwt\b|\bjwks?\b|oidc|openid|saml|oauth|\bsso\b|scim|\bmfa\b|id[_-]token'`
over the whole tree, without `Cargo.lock` and without this record, returns
these lines and no others:

| Match | What it is |
|---|---|
| `scripts/verify-release-signature.sh:4`, `:58` | GitHub Actions OIDC issuer of the release signature |
| `scripts/test-verify-release-signature.sh:37` | test of that script |
| `CONTRIBUTING.md:154`, `:183` | how the release is signed and checked, same identity |
| `docs/operations.md:1355` | the same check, for operators |
| `docs/assurance-matrix.md:46` | the matrix row of that check |
| `docs/tool-gateway-integration.md:636` | the sentence that says the gateway has no OIDC/MFA integration |

Every match but the last is the GitHub Actions OIDC identity that signs
releases. None is an identity of an API caller or of an approver.

## Options

### Option A: praetore-mcp with a gateway backend

The local proxy stays the enforcement point. The gateway decides, records
and holds approvals.

**What changes and where**

| File | Change |
|---|---|
| `crates/praetore-mcp/src/gate.rs:156-158` | No change to the trait. A second implementation of `Evaluator` sends the signed `AuthorizationRequest` to the gateway and turns the receipt into a `Verdict`. |
| `crates/praetore-mcp/src/gate.rs:1045-1050` | In gateway mode no local engine is built, so `MemoryReplayGuard` and `LocalFreshness` leave that path. The local mode keeps them. |
| `crates/praetore-mcp/src/relay.rs:420` | Choose the local or the gateway backend from the home configuration. |
| `crates/praetore-mcp/src/config.rs`, `store.rs:162-227` | Gateway URL and credential. In gateway mode `init` creates only the agent key; the issuer, attester and approver keys are not created in the home. |
| `crates/praetore-mcp/Cargo.toml` | An HTTP client with TLS. `praetore-cli` and `praetore-console` already use blocking `reqwest` with rustls. |
| `crates/praetore-mcp/src/approvals.rs` | Not used in gateway mode. The hold message points to the server inbox. |
| `crates/praetore-gateway/src/http_api.rs:39-44`, `:219-241` | A new role for the delegated enforcement point, and a sanctioned execution mode in which that role, and only that role, claims the single dispatch and reports the result. Today this exists only as a development mode with no guarantees. |
| `crates/praetore-gateway/src/lib.rs:444`, `:1176`, `:1257` | An `ActionDispatcher` that hands the action to the enforcement point instead of performing it, built on `claim_dispatch` and `dispatch`, which already give the single claim. |
| `crates/praetore-gateway/src/http_api.rs:25` | Decide the body limit against the 32 MiB of the proxy (H5). `gate.rs:160-171` already replaces large values with digests, so the signed request is smaller than the original line. |

There is a precedent for handing an action over and receiving the result
later: the sandbox supervisor takes the execution on one route and the
worker returns the result on another
(`crates/praetore-gateway-service/src/sandbox_supervisor.rs:428-437`).

**What it closes of the market gap**

| Gap | Result |
|---|---|
| Keys out of the governed user's hands | Yes for the attester, approver and issuer keys. The agent key stays in the home (see SAF-14). |
| Central audit | Yes. The journal is in PostgreSQL, per tenant, with the existing chained export. |
| Approval with a queue | Yes, with the inbox of `praetore-console`. Notifications are missing. |
| Identity | Partial. It inherits the bearer tokens per tenant. It brings no OIDC. |

**What it does not close.** The governed user still controls the enforcement
point: they can remove the `wrap` from their configuration. They can no
longer forge or rewrite evidence, but a call that does not go through the
proxy leaves no receipt. The known limits of `install` stay open.

**Technical risk: medium.**

- Every `tools/call` costs a network round trip. In enforce, no gateway
  means no call (fail closed). What observe does without a network has to
  be decided.
- The delegated mode touches H3, a deliberate guarantee of the gateway. The
  new role must be a type of its own, apart from `Agent`, so that an agent
  cannot claim its own dispatch.
- H4: the policy has to be per tenant or per MCP server.

**Effort: medium.** This is an estimate, not a measurement. It rests on H1
and H2: the change in `praetore-mcp` is a new implementation of a trait with
one method, and most of the work is the delegated mode of the gateway and
its PostgreSQL tests.

### Option B: the gateway speaks MCP over HTTP

The MCP client connects to the gateway. The gateway classifies, decides and
forwards to the target MCP server. `praetore-mcp` becomes a thin client.

**What changes and where**

| File | Change |
|---|---|
| `crates/praetore-gateway/src/http_api.rs:496-510` | A new MCP route in the router, with sessions and streamed responses. |
| `crates/praetore-gateway/Cargo.toml:13` | A streaming transport (H6) and TLS, or TLS termination in front as a checked requirement. |
| `crates/praetore-mcp/src/proxy.rs`, `json.rs` | Move the classifier and the strict parser to a shared crate. Today they are modules of `praetore-mcp` (`crates/praetore-mcp/src/lib.rs:16`, `:19`) and the gateway does not depend on it (H7). |
| `crates/praetore-gateway/src/lib.rs:444` | An `ActionDispatcher` that is an MCP client of the target server. |
| `crates/praetore-gateway-service/src/http_dispatcher.rs:32-39` | The static routes per tenant and the credential injection (`bearer_token_env`) are reused for remote MCP servers. |
| `crates/praetore-core/src/authorization.rs`, `engine.rs` | MCP clients do not sign intents. Either the gateway signs for the caller, so the agent key moves to the server and the identity is that of the token, or the trust model of the engine changes. This is a change of substance, not of transport. |
| `crates/praetore-mcp/src/gate.rs:1137-1140` | The path check against the local filesystem has no meaning on the server. |

**What it closes of the market gap**

| Gap | Result |
|---|---|
| Keys out of the governed user's hands | Yes, all of them. |
| Central audit | Yes. |
| Approval with a queue | Yes, as in A. |
| Identity | Not by itself, but it requires it: a remote MCP endpoint without federated identity does not pass a security review (market inference, not evidence from the repository). |
| Mandatory enforcement point | Yes for remote MCP servers, with the credential held by the gateway. It is the only option that gives this. |

**What it does not close.** Local stdio MCP servers (filesystem, git, tools
on the developer's machine) cannot run in the gateway. For them the thin
client would have to host the child process and take orders from the
gateway, which is option A with another transport and the same H3.

**Technical risk: high.**

- The MCP protocol has to be implemented on the server side and on the
  client side in a crate that has no MCP code today.
- The agent signature model (the `authorization.rs` row above).
- The MCP specification changed in substance in 2026 (market inference; it
  was not checked against the official specification for this record).

**Effort: high.** An estimate. It covers transport, protocol, extraction of
the classifier, identity and the decision on the agent signature.

### Comparison

| Criterion | A | B |
|---|---|---|
| Local stdio servers | Yes | Not without bringing A back |
| Remote MCP servers | No | Yes |
| Reuses existing code | `Evaluator`, `AuthorizationRequest`, `claim_dispatch`, inbox | Router, HTTP routes, credentials |
| Keeps the proxy defenses (H7) | Yes | They have to move |
| Changes the trust model of the engine | No | Yes |
| Bypass by the user | Possible (remove the wrap) | Not for remote servers |
| Needs OIDC to be sold | Desirable | Required (inference) |
| Risk / effort | Medium / medium | High / high |

## Proposed decision

Do A first and keep B as a second front, built on the server pieces that A
forces into existence.

Reasons:

1. A covers the servers the product governs today and that B cannot cover.
2. A rests on two seams that exist (H1, H2) and does not change the trust
   model of the engine.
3. The delegated mode, the new role and identity are common prerequisites.
   Once they exist for A, B is reduced to transport, protocol and the
   decision on the agent signature.
4. The local mode is not removed. It stays the product for one person
   without a server, and the mode without a network.

## State model (gateway mode, option A)

```
received --classify--> ambiguous ----------------> refused (no request to the gateway)
    |
    +--> signed --POST /v1/execute--> no answer --> refused (enforce)
                      |
                      +- DENY -----------------------> refused
                      +- ALLOW --single claim--> forwarded --result--> closed
                      +- REQUIRE_APPROVAL --> held
                                               +- reject / expiry --> closed, no effect
                                               +- approval --single claim--> forwarded --> closed
```

Invariants the implementation must protect:

- **I1.** The proxy does not forward a `tools/call` to the MCP server
  without a receipt the gateway confirmed for that request.
- **I2.** One approval gives at most one dispatch claim. Today
  `claim_dispatch` guarantees it on the journal (`lib.rs:1169-1176`).
- **I3.** A principal with the `Agent` role cannot claim a dispatch or
  decide an approval.
- **I4.** A line the classifier marks as ambiguous produces no request to
  the gateway in enforce.

## Migration steps

1. **The five blocking fixes of the local mode. Done.** #209 (B-NUM), #214
   (B-POISON), #215 (B-KEYS), #216 (B-PREFIX) and #217 (B-ANCHOR) are merged
   in `main`. They came first because the local mode stays, because #209
   changes which number the gate evaluates in both modes, and because #217
   adds the `UNANCHORED` state
   (`crates/praetore-mcp/src/receipts.rs:193-199`) that step 7 uses.
2. **Choose a backend with no change in behaviour.** Home configuration and
   the selection at `relay.rs:420`, with the local backend as the only one
   available.
3. **Delegated mode in the gateway.** The new role, the dispatch claim by
   the enforcement point and the result report, with tests in the
   PostgreSQL job. It requires replacing or extending the decision
   documented in `ExecMode` (`http_api.rs:219-241`).
4. **Gateway backend in praetore-mcp, enforce only.** The second
   implementation of `Evaluator`. Observe comes in a later delivery.
5. **Approvals on the server.** The hold points to the inbox; the proxy
   reads the status and claims the dispatch.
6. **Keys and agent identity.** In gateway mode `init` creates only the
   agent key and the server issues the authority. This is the scope of
   `docs/proposals/SAF-14-identidad-por-agente.md`, which is a proposal.
7. **External anchor (SAF-13).**
   `docs/proposals/SAF-13-anclaje-del-head-del-journal.md` is a document
   only. It enters in two places:
   - on the server, over the head of the export per tenant
     (`crates/praetore-replay-postgres/src/journal_export.rs:46-52`), one
     place for every proxy;
   - in the local mode, as the way from `UNANCHORED` to anchored that does
     not depend on the user saving the head by hand.
   It comes after step 4, to anchor the journal that is already central,
   and it does not depend on B.
8. **Federated identity** for the API principals. It is common to A and B.
9. **Option B** for remote MCP servers, with the classifier in a shared
   crate.

## Consequences

- `praetore-mcp` gains a network dependency and a second mode. The local
  mode and its guarantees do not change.
- The gateway stops being "always performs the effect" (H3). This is the
  change with the most risk and it needs its own decision record.
- A product question the code does not answer: a policy per tenant or per
  MCP server (H4).

## Verification

Each invariant has to be closed with a type or a test, and with a mutation
that breaks it:

- I1: an integration test that cuts the gateway answer and checks that the
  fake server records no execution.
- I2: covered on the journal side; add the case of two proxies that claim
  at the same time.
- I3: the role of the enforcement point as its own variant of `ApiRole`,
  with one test per route.
- I4: reuse the cases of `crates/praetore-mcp/src/proxy.rs` against the
  gateway backend.

## Not verified

- Nothing was compiled or run for this record. It is a reading of the code.
- The migrations before 0016 and the sandbox supervisor, other than the
  routes cited, come from a reading survey and were not read line by line.
- The efforts are qualitative estimates.
- The statements marked as market inference do not come from the
  repository.
