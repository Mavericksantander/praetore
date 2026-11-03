//! Rate limits of the ingester and the counts of what they suppress (G1).

use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

use super::{LossReason, Suppressed};

/// Rates are in messages per second; a burst is the most messages accepted
/// at once after a quiet period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodLimits {
    /// Verified events recorded per second for one source.
    pub source_rate: u64,
    pub source_burst: u64,
    /// Individual `rejected` records per second, all inputs together.
    pub rejected_rate: u64,
    pub rejected_burst: u64,
}

/// Defaults: 100 events per second per source (bursts of 1000), and 10
/// `rejected` records per second (bursts of 100).
pub const DEFAULT_FLOOD_LIMITS: FloodLimits = FloodLimits {
    source_rate: 100,
    source_burst: 1000,
    rejected_rate: 10,
    rejected_burst: 100,
};

impl Default for FloodLimits {
    fn default() -> Self {
        DEFAULT_FLOOD_LIMITS
    }
}

/// The largest rate or burst accepted.
pub const MAX_FLOOD_LIMIT: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("safety ingest rate limits must be between 1 and {MAX_FLOOD_LIMIT}")]
pub struct InvalidFloodLimits;

/// A token bucket, in millitokens so that refills are exact integers.
#[derive(Debug, Clone)]
struct Bucket {
    millitokens: u64,
    last: Duration,
}

impl Bucket {
    fn full(burst: u64, now: Duration) -> Self {
        Self {
            millitokens: burst * 1000,
            last: now,
        }
    }

    fn take(&mut self, rate: u64, burst: u64, now: Duration) -> bool {
        // A clock that goes back refills nothing. `last` advances only by the
        // time converted into whole millitokens, so frequent calls lose no
        // refill to rounding.
        let elapsed = now.saturating_sub(self.last).as_nanos();
        let refill = elapsed.saturating_mul(u128::from(rate)) / 1_000_000;
        let capacity = burst * 1000;
        let filled = u128::from(self.millitokens).saturating_add(refill);
        if filled >= u128::from(capacity) {
            self.millitokens = capacity;
            self.last = self.last.max(now);
        } else {
            self.millitokens = filled as u64;
            let used = refill * 1_000_000 / u128::from(rate);
            self.last += Duration::from_nanos(used.min(u128::from(u64::MAX)) as u64);
        }
        if self.millitokens >= 1000 {
            self.millitokens -= 1000;
            true
        } else {
            false
        }
    }
}

/// Per-source and rejected-input rate limits, and the pending counts of
/// suppressed messages to record (with
/// [`super::SafetyIngestor::prepare_count`]) as signed records on the
/// unattributed chain.
///
/// Memory is bounded: one bucket per verified source (sources are pinned)
/// and one count per reason and source.
#[derive(Debug, Clone)]
pub struct FloodControl {
    limits: FloodLimits,
    sources: HashMap<String, Bucket>,
    rejected: Option<Bucket>,
    pending: BTreeMap<LossReason, (u64, BTreeMap<String, u64>)>,
}

impl FloodControl {
    pub fn new(limits: FloodLimits) -> Result<Self, InvalidFloodLimits> {
        let valid = |value: u64| (1..=MAX_FLOOD_LIMIT).contains(&value);
        if !(valid(limits.source_rate)
            && valid(limits.source_burst)
            && valid(limits.rejected_rate)
            && valid(limits.rejected_burst))
        {
            return Err(InvalidFloodLimits);
        }
        Ok(Self {
            limits,
            sources: HashMap::new(),
            rejected: None,
            pending: BTreeMap::new(),
        })
    }

    pub fn limits(&self) -> FloodLimits {
        self.limits
    }

    /// Whether one more verified event of `source_id` may be recorded now.
    pub fn admit_event(&mut self, source_id: &str, now: Duration) -> bool {
        let limits = self.limits;
        self.sources
            .entry(source_id.to_owned())
            .or_insert_with(|| Bucket::full(limits.source_burst, now))
            .take(limits.source_rate, limits.source_burst, now)
    }

    /// Whether one more individual `rejected` record may be written now.
    pub fn admit_rejected(&mut self, now: Duration) -> bool {
        let limits = self.limits;
        self.rejected
            .get_or_insert_with(|| Bucket::full(limits.rejected_burst, now))
            .take(limits.rejected_rate, limits.rejected_burst, now)
    }

    /// Counts one suppressed message.
    pub fn count(&mut self, suppressed: &Suppressed) {
        self.add(suppressed.reason, suppressed.source_id.as_deref(), 1);
    }

    /// Counts `count` messages for `reason` (for example datagrams refused
    /// before they were read).
    pub fn add(&mut self, reason: LossReason, source_id: Option<&str>, count: u64) {
        if count == 0 {
            return;
        }
        let (total, sources) = self.pending.entry(reason).or_default();
        *total = total.saturating_add(count);
        if let Some(source) = source_id {
            let per_source = sources.entry(source.to_owned()).or_default();
            *per_source = per_source.saturating_add(count);
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Takes the pending counts: per reason, the total and a detail naming
    /// the sources (`executor-1=12, executor-2=3`), if any.
    pub fn take_pending(&mut self) -> Vec<PendingCount> {
        std::mem::take(&mut self.pending)
            .into_iter()
            .map(|(reason, (count, sources))| PendingCount {
                reason,
                count,
                detail: (!sources.is_empty()).then(|| {
                    sources
                        .iter()
                        .map(|(source, count)| format!("{source}={count}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
                sources,
            })
            .collect()
    }

    /// Puts back a count that could not be recorded (taken with
    /// [`Self::take_pending`]), so the next flush records it.
    ///
    /// Public because the ingester binary (`praetore-cli`) puts a count back
    /// when its database write fails. It can only add to the pending counts
    /// of this process's own `FloodControl` (as [`Self::add`] does): it
    /// never removes a count and touches no signed record.
    pub fn restore(&mut self, pending: PendingCount) {
        if pending.sources.is_empty() {
            self.add(pending.reason, None, pending.count);
        } else {
            let attributed = pending
                .sources
                .values()
                .fold(0u64, |sum, count| sum.saturating_add(*count));
            for (source, count) in &pending.sources {
                self.add(pending.reason, Some(source), *count);
            }
            self.add(
                pending.reason,
                None,
                pending.count.saturating_sub(attributed),
            );
        }
    }
}

/// One pending count from [`FloodControl::take_pending`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCount {
    pub reason: LossReason,
    pub count: u64,
    pub detail: Option<String>,
    sources: BTreeMap<String, u64>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn frequent_takes_lose_no_refill_to_rounding() {
        // 10 per second, asked every 50 µs: one token every 100 ms.
        let mut bucket = super::Bucket::full(1, super::Duration::ZERO);
        let mut now = super::Duration::ZERO;
        let mut taken = 0;
        for _ in 0..20_000 {
            if bucket.take(10, 1, now) {
                taken += 1;
            }
            now += super::Duration::from_micros(50);
        }
        // One second: the initial token and 10 refills (±1).
        assert!((10..=11).contains(&taken), "{taken}");
    }

    use super::*;

    const LIMITS: FloodLimits = FloodLimits {
        source_rate: 10,
        source_burst: 5,
        rejected_rate: 1,
        rejected_burst: 2,
    };

    #[test]
    fn a_bucket_allows_its_burst_then_its_rate() {
        let mut flood = FloodControl::new(LIMITS).unwrap();
        let start = Duration::from_secs(100);
        let admitted = (0..20)
            .filter(|_| flood.admit_event("executor-1", start))
            .count();
        assert_eq!(admitted, 5);
        // Another source has its own bucket.
        assert!(flood.admit_event("executor-2", start));
        // 10 per second: one more every 100 ms.
        assert!(!flood.admit_event("executor-1", start + Duration::from_millis(99)));
        assert!(flood.admit_event("executor-1", start + Duration::from_millis(100)));
        // A long pause refills up to the burst, not more.
        let later = start + Duration::from_secs(3600);
        assert_eq!(
            (0..20)
                .filter(|_| flood.admit_event("executor-1", later))
                .count(),
            5
        );
        // A clock that goes back refills nothing.
        assert!(!flood.admit_event("executor-1", start));
        assert_eq!((0..10).filter(|_| flood.admit_rejected(start)).count(), 2);
    }

    #[test]
    fn counts_are_aggregated_per_reason_and_restored_when_not_recorded() {
        let mut flood = FloodControl::new(LIMITS).unwrap();
        for _ in 0..3 {
            flood.count(&Suppressed {
                reason: LossReason::RateLimited,
                source_id: Some("executor-1".into()),
            });
        }
        flood.add(LossReason::RateLimited, Some("executor-2"), 2);
        flood.add(LossReason::PeerRefused, None, 7);
        let pending = flood.take_pending();
        assert!(!flood.has_pending());
        assert_eq!(pending.len(), 2);
        assert_eq!(
            (
                pending[0].reason,
                pending[0].count,
                pending[0].detail.as_deref()
            ),
            (
                LossReason::RateLimited,
                5,
                Some("executor-1=3, executor-2=2")
            )
        );
        assert_eq!((pending[1].count, pending[1].detail.as_deref()), (7, None));
        for count in pending.clone() {
            flood.restore(count);
        }
        assert_eq!(flood.take_pending(), pending);
    }

    #[test]
    fn limits_are_bounded() {
        for limits in [
            FloodLimits {
                source_rate: 0,
                ..LIMITS
            },
            FloodLimits {
                rejected_burst: MAX_FLOOD_LIMIT + 1,
                ..LIMITS
            },
        ] {
            assert!(FloodControl::new(limits).is_err());
        }
    }
}
