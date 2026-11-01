//! Test-only evaluation counters (feature `test-probe`).
//!
//! The G7 runtime tests use them to show that an entry point never calls the
//! engine for a safety action. Counters are kept per policy id so tests that
//! run in parallel in one process do not see each other's calls. The feature
//! is off by default and the workspace enables it only from
//! `[dev-dependencies]`, so release builds do not contain this module.

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

#[derive(Default)]
struct Counters {
    engine: BTreeMap<String, usize>,
    policy: BTreeMap<String, usize>,
}

static COUNTERS: Mutex<Option<Counters>> = Mutex::new(None);

fn counters() -> MutexGuard<'static, Option<Counters>> {
    COUNTERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Calls into `AuthorizationEngine::evaluate` /
/// `evaluate_with_atomic_commit` with an engine whose policy has `policy_id`,
/// counted on entry, before any check.
pub fn engine_calls(policy_id: &str) -> usize {
    counters()
        .as_ref()
        .and_then(|counters| counters.engine.get(policy_id).copied())
        .unwrap_or(0)
}

/// Calls into `Policy::evaluate` / `evaluate_with_context` for `policy_id`.
pub fn policy_evaluations(policy_id: &str) -> usize {
    counters()
        .as_ref()
        .and_then(|counters| counters.policy.get(policy_id).copied())
        .unwrap_or(0)
}

pub(crate) fn record_engine_call(policy_id: &str) {
    *counters()
        .get_or_insert_with(Counters::default)
        .engine
        .entry(policy_id.to_owned())
        .or_default() += 1;
}

pub(crate) fn record_policy_evaluation(policy_id: &str) {
    *counters()
        .get_or_insert_with(Counters::default)
        .policy
        .entry(policy_id.to_owned())
        .or_default() += 1;
}
