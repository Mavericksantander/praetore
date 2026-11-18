//! `praetore-mcp verify` on homes written by an earlier praetore-mcp. The
//! homes are shared with praetore-verify:
//! `crates/praetore-verify/tests/fixtures/praetore-mcp-homes/` (see its
//! README). They hold no private keys; `verify` reads none.
//!
//! Those decisions stored `created_at` from the hold clock, truncated to
//! the second. The retained receipt's `decided_at` keeps a fraction
//! (`2026-11-17T05:13:18Z` against `2026-11-17T05:13:18.289873Z`). verify
//! requires the two strings to be equal, so the approval record fails that
//! check. The receipt chain and the approval chain are otherwise the ones
//! saved with the fixture.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../praetore-verify/tests/fixtures/praetore-mcp-homes")
        .join(name)
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn verify(home: &Path, receipts_head: &str, approval_head: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
        .args([
            "verify",
            "--dir",
            home.to_str().unwrap(),
            "--expected-head",
            receipts_head,
            "--expected-approval-head",
            approval_head,
        ])
        .output()
        .unwrap()
}

/// A 0.3.6 home: no receipt names an approval, and the forwarded call is
/// tied to its approval only by the execution record. The chains still
/// match the saved heads. The decision's `created_at` is the truncated
/// hold clock, so verify reports that one mismatch and exits 1.
#[test]
fn a_home_written_by_0_3_6_keeps_its_heads_and_fails_the_window_check() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    copy_dir(&fixture("0.3.6"), &home);
    let journal = fs::read_to_string(home.join("receipts/2026-11-17.jsonl")).unwrap();
    assert!(!journal.contains("praetore.approval_id"));
    assert_eq!(journal.matches("praetore-mcp/0.3.6").count(), 4);
    let out = verify(
        &home,
        "8bb82a68865e714262fef57ce0f506834e2b6e1e0968f39f96fb07f7bd015446",
        "ee7b4d244ad58a58367dc40c96731264c7b92fa7131e7a6baeb7d0cbddbb7005",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("4 receipts: 4 verified, 1 failed"),
        "{stdout}"
    );
    assert!(
        stdout.contains("created_at does not match the signed timestamp of the retained receipt"),
        "{stdout}"
    );
    assert!(
        stdout.contains("head 8bb82a68865e714262fef57ce0f506834e2b6e1e0968f39f96fb07f7bd015446"),
        "{stdout}"
    );
    assert!(
        stdout.contains("head ee7b4d244ad58a58367dc40c96731264c7b92fa7131e7a6baeb7d0cbddbb7005"),
        "{stdout}"
    );
}

/// The home written after 0.3.6 has the same truncated `created_at`.
/// Deleting its approval journal then fails `verify` because a receipt
/// names that approval. Deleting the 0.3.6 journal does not: no receipt
/// names an approval.
#[test]
fn a_deleted_approval_journal_fails_only_the_home_whose_receipts_name_it() {
    let temp = tempfile::tempdir().unwrap();
    let new = temp.path().join("new");
    copy_dir(&fixture("approval-id"), &new);
    let out = verify(
        &new,
        "97176c3c5aac8471ec5fa87ed01aecc27aca233559477f5b2b7f9e8a7b1df8cf",
        "f871c9b0b5783891c6d4c92719f022919ea19d80d4a491aae565716f1e65ae3b",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("created_at does not match the signed timestamp of the retained receipt"),
        "{stdout}"
    );

    let plain = |home: &Path| {
        Command::new(env!("CARGO_BIN_EXE_praetore-mcp"))
            .args(["verify", "--dir", home.to_str().unwrap()])
            .output()
            .unwrap()
    };
    fs::remove_file(new.join("approvals/journal.jsonl")).unwrap();
    let out = plain(&new);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("which has no signed decision"), "{stdout}");

    let old = temp.path().join("old");
    copy_dir(&fixture("0.3.6"), &old);
    fs::remove_file(old.join("approvals/journal.jsonl")).unwrap();
    let out = plain(&old);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
