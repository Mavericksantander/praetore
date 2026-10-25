# PRÆTORE Engineering Command Center

Open `index.html` directly in a modern browser. The dashboard is static and
works offline; it has no build step, CDN, server, or connection to live CI,
databases, or running services.

## Refresh repository facts

From the repository root, run:

```sh
python3 engineering-command-center/refresh_dashboard.py
```

The standard-library-only script refreshes `dashboard-data.json` with the
current Git revision, branch, worktree cleanliness, workspace packages,
manifests, direct dependencies, Rust test annotations, test-file paths and
workflow names. It also generates `dashboard-data.js`, which lets the page load
the same structured data when opened with `file://` (browsers restrict
`fetch()` of a sibling JSON file in that mode). It does not run tests, contact
GitHub, or read environment-variable values, credentials, or private keys.

Edit `dashboard-data.json` to maintain component purpose/status, assessments,
known limitations, priorities, development signals, acceptance criteria and
milestones. Rerun the refresh script after editing so the generated JavaScript
bundle stays in sync. For an assessment, update its evidence, status,
`verifiedOn` and `lastVerifiedRevision` only after reviewing that repository
state. This refresh script updates the assessment revision when it still
contains the `discovered.revision` placeholder; it does not claim that
refreshing facts revalidates engineering judgments.

Record test outcomes explicitly in the `verification` section of
`dashboard-data.json`. Use `passed` or `failed` only for a command actually run
against the stated current worktree; include its command, timestamp and
result. Keep hosted CI, database-backed tests, fuzzing and live-cluster
validation as unavailable/not run unless there is evidence for that exact
candidate. The refresh script deliberately preserves verification entries
instead of reusing a previous run as current.

## Assessment methodology

Statuses are scoped claims, not a numeric security rating:

| Status | Meaning |
| --- | --- |
| **Verified** | A named property has relevant test or concrete validation evidence. This does not verify its whole subsystem. |
| **Implemented · needs validation** | Code and focused evidence exist; important integration, adversarial or environmental evidence is missing. |
| **Partial** | Useful implementation exists, but an essential part of the capability is absent. |
| **Missing** | No implementation was found for the stated product capability. |
| **Blocked** | Progress needs an unresolved prerequisite or owner. |
| **Unknown / unavailable** | Available repository evidence cannot support a reliable conclusion, or the required environment is not available. |

Repository facts discovered by the script are shown separately from manually
maintained assessments. Test annotation counts and the presence of CI commands
are inventory signals only; they are not coverage or passing results. A dirty
worktree is shown explicitly, and no local snapshot implies a hosted CI result.
The development-focus label says **inferred** when it is based on uncommitted
file activity rather than a declared project status.

Product readiness is tracked in its own checklist. Neither that checklist nor
the count of verified properties is an overall security score. Sandbox,
gateway bypass resistance, tenant separation, database recovery and release
provenance require target-environment evidence before deployment claims can
be made.
