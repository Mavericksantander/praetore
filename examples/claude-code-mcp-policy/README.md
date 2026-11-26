# Example: praetore-mcp policy for the filesystem MCP server in Claude Code

`policy.json` is a praetore-mcp policy for the filesystem MCP server
(`@modelcontextprotocol/server-filesystem`) that Claude Code starts after
`praetore-mcp install --client claude-code`. It is an example for
AI-enabled systems that use that server, not a policy for your setup.

## What it decides

- Allowed by name: `read_text_file`, `read_multiple_files`,
  `list_directory`, `directory_tree`, `search_files`, `get_file_info` and
  `list_allowed_directories`.
- Denied by name: `write_file`, `edit_file` and `move_file`.
- Every other tool falls to the default deny. No rule asks for an approval.

## Two conditions

- **The MCP server must be named `filesystem`.** Every rule has
  `"target": "filesystem"`, and the target is the server name in the
  Claude Code configuration (the name `install` passes to `wrap --name`).
  Under any other name no rule matches and every call is denied by default.
- **The policy sets no path conditions.** It decides by tool name only.
  An allowed tool reads any path that the filesystem server itself allows
  (the directories you pass to the server). Limit those directories in the
  server's arguments, or add path conditions to the rules.

## Use

```sh
cp examples/claude-code-mcp-policy/policy.json ~/.praetore/mcp/policy.json
praetore-mcp policy check
```

`--dir DIR` (or `$PRAETORE_MCP_HOME`) selects another home. The test
`crates/praetore-mcp/tests/example_policy.rs` checks the file with what
`policy check` runs, and checks one allowed and one denied call.
