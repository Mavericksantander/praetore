//! `praetore policy classify --policy PATH` (G7): proposes the
//! `action_classes` table that policy format 2 requires, for a policy
//! document, and prints it. It reads the file and never writes or rewrites
//! any file.

use praetore_core::{ActionClassProposal, RecordedPolicy};
use std::{fs, io::Read, path::Path};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;

pub fn parse(mut args: impl Iterator<Item = String>) -> Result<String, Box<dyn std::error::Error>> {
    let mut path = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--policy" if path.is_none() => {
                path = Some(args.next().ok_or("missing --policy value")?);
            }
            _ => return Err(format!("unexpected argument: {flag}").into()),
        }
    }
    Ok(path.ok_or("praetore policy classify needs --policy <path>")?)
}

/// What `run` prints: the JSON proposal on stdout, notes on stderr.
pub struct Report {
    pub stdout: String,
    pub stderr: Vec<String>,
    pub problems: usize,
}

pub fn report(text: &str) -> Result<Report, Box<dyn std::error::Error>> {
    let recorded = RecordedPolicy::from_json(text)?;
    let ActionClassProposal {
        action_classes,
        problems,
    } = recorded.propose_action_classes();
    let stdout = serde_json::to_string_pretty(&serde_json::json!({
        "format_version": praetore_core::policy::POLICY_FORMAT_VERSION,
        "action_classes": action_classes,
    }))? + "\n";
    let mut stderr = vec![format!(
        "policy {} v{} is format {} (digest {})",
        recorded.id(),
        recorded.version(),
        recorded.format_version(),
        recorded.digest()
    )];
    if recorded.format_version() == 1 {
        stderr.push(
            "proposal: add the two fields above to the document. Its digest changes; receipts that recorded the format 1 digest keep verifying against the format 1 document (praetore-verify --policy <old document>).".into(),
        );
    }
    stderr.push(
        "review every Mission entry: an action the executor runs without waiting for PRÆTORE must be renamed `safety:<name>`, declared Safety and have no rule.".into(),
    );
    for problem in &problems {
        stderr.push(format!("problem: {problem}"));
    }
    Ok(Report {
        stdout,
        stderr,
        problems: problems.len(),
    })
}

pub fn run(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
        return Err("the policy must be a regular file no larger than 1 MiB".into());
    }
    let mut text = String::new();
    fs::File::open(path)?
        .take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut text)?;
    let report = report(&text)?;
    print!("{}", report.stdout);
    for line in &report.stderr {
        eprintln!("{line}");
    }
    if report.problems > 0 {
        return Err(format!(
            "{} problem(s) prevent this policy from loading as format 2; fix them before adding the table",
            report.problems
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = r#"{"id":"p","version":3,"canonical_version":1,"rules":[
        {"id":"w","action_type":"fs:write_file","effect":"Allow","required_capability":"fs:write",
         "target":null,"parameter_conditions":[],"context_conditions":[]},
        {"id":"c","action_type":"mcp.tools/call","effect":"Deny","required_capability":null,
         "target":null,"parameter_conditions":[],"context_conditions":[]}]}"#;

    #[test]
    fn proposes_mission_classes_for_a_format_1_policy() {
        let report = report(V1).unwrap();
        let proposal: serde_json::Value = serde_json::from_str(&report.stdout).unwrap();
        assert_eq!(
            proposal,
            serde_json::json!({
                "format_version": 2,
                "action_classes": {"fs:write_file": "Mission", "mcp.tools/call": "Mission"}
            })
        );
        assert_eq!(report.problems, 0);
        assert!(report.stderr[0].contains("is format 1"));

        // Adding the proposed fields gives a valid format 2 policy.
        let mut migrated: serde_json::Value = serde_json::from_str(V1).unwrap();
        migrated["format_version"] = proposal["format_version"].clone();
        migrated["action_classes"] = proposal["action_classes"].clone();
        assert!(praetore_core::Policy::from_json(&migrated.to_string()).is_ok());
    }

    #[test]
    fn reports_rules_on_safety_actions_and_ambiguous_names() {
        let text = V1
            .replace("fs:write_file", "safety:halt")
            .replace("mcp.tools/call", "ops:skip_safety");
        let report = report(&text).unwrap();
        assert_eq!(report.problems, 2);
        assert!(
            report
                .stderr
                .iter()
                .any(|line| line.contains("targets safety action 'safety:halt'"))
        );
        assert!(
            report
                .stderr
                .iter()
                .any(|line| line.contains("'ops:skip_safety' contains \"safety\""))
        );
    }

    #[test]
    fn never_writes_the_policy_file() {
        let directory =
            std::env::temp_dir().join(format!("praetore-classify-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("policy.json");
        fs::write(&path, V1).unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        run(path.to_str().unwrap()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), V1);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
}
