//! The README's registration snippet is what a person copies into
//! `<project>/.claude/settings.local.json`. Claude Code reads
//! `disableAllHooks` after settings precedence, and a `true` in a shared
//! `.claude/settings.json` that arrives with the repository disables every
//! hook below it (checked with Claude Code 2.1.332 on 2026-11-26). The
//! snippet therefore pins the key to `false`, and this test fails if it is
//! dropped or changed.

const README: &str = include_str!("../README.md");
const ANCHOR: &str = "registrar el hook en `<proyecto>/.claude/settings.local.json`";

fn registration_snippet() -> serde_json::Value {
    let after = README
        .split_once(ANCHOR)
        .map(|(_, rest)| rest)
        .expect("the README names the settings.local.json registration");
    let block = after
        .split_once("```json\n")
        .and_then(|(_, rest)| rest.split_once("\n```"))
        .map(|(block, _)| block)
        .expect("a ```json block follows the registration sentence");
    serde_json::from_str(block).expect("the registration snippet is valid JSON")
}

#[test]
fn the_registration_snippet_pins_disable_all_hooks_to_false() {
    let snippet = registration_snippet();
    assert_eq!(
        snippet.get("disableAllHooks"),
        Some(&serde_json::Value::Bool(false)),
        "a shared .claude/settings.json with disableAllHooks true would turn the hook off: {snippet}"
    );
}

#[test]
fn the_registration_snippet_registers_the_wrapper_as_a_blocking_pre_tool_use_hook() {
    let snippet = registration_snippet();
    let hook = &snippet["hooks"]["PreToolUse"][0]["hooks"][0];
    assert_eq!(hook["type"], "command", "{snippet}");
    assert!(
        hook["command"]
            .as_str()
            .is_some_and(|command| command.ends_with("/.claude/hooks/praetore-hook.sh")),
        "{snippet}"
    );
    assert_eq!(hook["onFailure"], "block", "{snippet}");
}
