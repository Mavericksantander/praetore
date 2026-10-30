//! `praetore-mcp`: a local stdio MCP proxy that evaluates every
//! client→server `tools/call` with the PRÆTORE HighAssurance engine and
//! journals the attested evidence. See the crate README for the trust model.

pub mod cli;
pub mod gate;
pub mod install;
pub mod json;
pub mod proxy;
pub mod receipts;
pub mod relay;
pub mod store;
