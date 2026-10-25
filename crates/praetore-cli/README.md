# PRÆTORE local CLI

The `praetore` binary provides a local reference flow backed by PostgreSQL:

```sh
cargo install --path crates/praetore-cli
praetore init ./praetore-local
export PRAETORE_GATEWAY_DATABASE_URL='postgresql://localhost/praetore'
praetore doctor ./praetore-local
praetore run ./praetore-local
```

In another terminal, execute the only supported demo action:

```sh
praetore demo ./praetore-local set greeting hello
```

`init` creates fresh Ed25519 keys and configures their secret files with
owner-only permissions on Unix systems. Key initialization intentionally fails
on platforms where the CLI cannot verify those permissions. The database URL
is supplied by the operator and must refer to local PostgreSQL; the CLI applies
the workspace's replay and execution journal migrations at startup. Do not put
production credentials or production trust anchors in the generated demo
directory.

The HTTP API has no authentication or TLS and binds to IPv4 loopback only.
The built-in policy allows only `demo:set_value` with capability `demo:write`
against `demo-state`; every non-matching action is denied. The adapter has no
network access, and its key/value effects live in memory and disappear when
the gateway stops. PostgreSQL durably records authorization and execution
state, but it does not make downstream effects atomic. A client timeout is
ambiguous, so the CLI does not retry and directs the operator to inspect the
journal.

This command is a development/reference experience, not a production gateway,
secure key custody system, external-agent integration, sandbox, or deployment
readiness claim. Use the main [deployment gates](../../docs/pre-user-pilot-gates.md)
before considering any real tool integration.
