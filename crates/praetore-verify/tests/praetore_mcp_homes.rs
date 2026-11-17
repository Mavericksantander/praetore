//! `praetore-verify` reads receipts written by praetore-mcp 0.3.6 and
//! receipts written after the format gained `praetore.approval_id`.
//! The homes are in `tests/fixtures/praetore-mcp-homes/` (see its README).

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const APPROVAL_KEY: &str = "praetore.approval_id";

struct Home {
    dir: PathBuf,
    receipts_head: &'static str,
}

fn home(name: &str, receipts_head: &'static str) -> Home {
    Home {
        dir: Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/praetore-mcp-homes")
            .join(name),
        receipts_head,
    }
}

fn v036() -> Home {
    home(
        "0.3.6",
        "8bb82a68865e714262fef57ce0f506834e2b6e1e0968f39f96fb07f7bd015446",
    )
}

fn approval_id() -> Home {
    home(
        "approval-id",
        "97176c3c5aac8471ec5fa87ed01aecc27aca233559477f5b2b7f9e8a7b1df8cf",
    )
}

impl Home {
    fn path(&self, name: &str) -> String {
        self.dir.join(name).to_str().unwrap().to_owned()
    }

    fn journal(&self) -> String {
        self.path("receipts/2026-11-17.jsonl")
    }

    /// The `evidence` member of each journal line, byte for byte.
    fn receipts(&self) -> Vec<String> {
        fs::read_to_string(self.journal())
            .unwrap()
            .lines()
            .map(|line| {
                let start = line.find("\"evidence\":").unwrap() + "\"evidence\":".len();
                line[start..line.len() - 1].to_owned()
            })
            .collect()
    }
}

fn verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .output()
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn verify_evidence(home: &Home, evidence: &str) -> Output {
    let temp = tempfile_path();
    fs::write(&temp, evidence).unwrap();
    let out = verify(&[
        "evidence",
        "--evidence",
        temp.to_str().unwrap(),
        "--attester-pin",
        &home.path("attester-public-key.hex"),
        "--issuer-pins",
        &home.path("issuer-pins.jsonl"),
        "--policy",
        &home.path("policy.json"),
        "--strict",
    ]);
    let _ = fs::remove_file(&temp);
    out
}

fn tempfile_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "praetore-verify-mcp-home-{}-{}.json",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

fn approval_ids(receipts: &[String]) -> Vec<Option<String>> {
    receipts
        .iter()
        .map(|receipt| {
            let value: Value = serde_json::from_str(receipt).unwrap();
            value["context"][APPROVAL_KEY].as_str().map(str::to_owned)
        })
        .collect()
}

fn check_home(home: &Home) {
    for (index, receipt) in home.receipts().iter().enumerate() {
        let out = verify_evidence(home, receipt);
        assert!(out.status.success(), "receipt {index}: {}", text(&out));
        assert!(text(&out).starts_with("OK evidence OK"), "{}", text(&out));
    }
    let out = verify(&[
        "journal",
        "--journal",
        &home.journal(),
        "--attester-pin",
        &home.path("attester-public-key.hex"),
        "--policy",
        &home.path("policy.json"),
        "--expected-head",
        home.receipts_head,
        "--require-anchored",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).starts_with("OK journal OK"), "{}", text(&out));
}

#[test]
fn receipts_written_by_praetore_mcp_0_3_6_still_verify() {
    let home = v036();
    let receipts = home.receipts();
    assert_eq!(receipts.len(), 4);
    assert!(
        approval_ids(&receipts).iter().all(Option::is_none),
        "0.3.6 receipts name no approval"
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.contains("\"praetore.proxy\":\"praetore-mcp/0.3.6\"")),
        "written by 0.3.6"
    );
    check_home(&home);
}

#[test]
fn receipts_that_name_their_approval_verify_and_the_id_is_signed() {
    let home = approval_id();
    let receipts = home.receipts();
    let ids = approval_ids(&receipts);
    assert_eq!(ids.iter().filter(|id| id.is_some()).count(), 1, "{ids:?}");
    assert!(ids[3].is_some(), "the forwarded call names its approval");
    check_home(&home);

    let id = ids[3].as_deref().unwrap();
    let edited = receipts[3].replace(id, &"0".repeat(64));
    let out = verify_evidence(&home, &edited);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}
