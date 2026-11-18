# praetore-mcp homes

Two homes written by praetore-mcp, without their private keys, for
`tests/praetore_mcp_homes.rs` and for `praetore-mcp`'s
`tests/old_homes.rs`.

* `0.3.6/`: written by praetore-mcp 0.3.6 (tag `v0.3.6`). No receipt
  carries `praetore.approval_id`.
* `approval-id/`: written after 0.3.6. The receipt of the forwarded call
  carries `context["praetore.approval_id"]`.

Each holds four receipts in enforce mode: ALLOW `echo`, DENY `delete`,
REQUIRE_APPROVAL `append` held, then the same `append` forwarded on its
approval. `make_home.py` builds one; see its docstring.
