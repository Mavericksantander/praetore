use praetore_core::engine::{TrustedClock, TrustedClockError};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, RwLock, Weak},
    thread,
    time::{Duration, Instant},
};
use time::OffsetDateTime;

const MAX_TRACKING_OUTPUT_BYTES: usize = 8 * 1024;
const CHRONYC_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
struct TrackingStatus {
    synchronized: bool,
    estimated_error: Duration,
}

struct HealthSample {
    status: TrackingStatus,
    observed_at: Instant,
}

struct ClockState {
    sample: Option<HealthSample>,
    failed: bool,
    last_returned: Option<OffsetDateTime>,
}

/// The wall clock that `now` reads: `OffsetDateTime::now_utc` in
/// production, a controlled one in tests.
type WallClock = Box<dyn Fn() -> OffsetDateTime + Send + Sync>;

struct ClockInner {
    chronyc_path: PathBuf,
    wall: WallClock,
    poll_interval: Duration,
    max_sample_age: Duration,
    max_error: Duration,
    state: RwLock<ClockState>,
}

#[derive(Clone)]
pub struct ChronyClock {
    inner: Arc<ClockInner>,
}

impl ChronyClock {
    pub fn new(
        chronyc_path: impl AsRef<Path>,
        poll_interval: Duration,
        max_sample_age: Duration,
        max_error: Duration,
    ) -> Result<Self, String> {
        let chronyc_path = chronyc_path.as_ref();
        if !chronyc_path.is_absolute()
            || !chronyc_path.is_file()
            || !is_executable(chronyc_path)
            || poll_interval.is_zero()
            || max_sample_age <= poll_interval
            || max_error.is_zero()
        {
            return Err(
                "chrony clock requires an absolute executable, a positive polling interval, a larger sample age, and a positive error bound"
                    .into(),
            );
        }

        let status = query_tracking(chronyc_path)?;
        if !status.synchronized || status.estimated_error > max_error {
            return Err("chrony is not synchronized within the configured error bound".into());
        }

        let inner = Arc::new(ClockInner {
            chronyc_path: chronyc_path.to_owned(),
            wall: Box::new(OffsetDateTime::now_utc),
            poll_interval,
            max_sample_age,
            max_error,
            state: RwLock::new(ClockState {
                sample: Some(HealthSample {
                    status,
                    observed_at: Instant::now(),
                }),
                failed: false,
                last_returned: None,
            }),
        });
        spawn_health_monitor(Arc::downgrade(&inner))?;
        Ok(Self { inner })
    }
}

impl TrustedClock for ChronyClock {
    fn now(&self) -> Result<OffsetDateTime, TrustedClockError> {
        let mut state = self
            .inner
            .state
            .write()
            .map_err(|_| TrustedClockError::Unavailable)?;
        let sample = state
            .sample
            .as_ref()
            .ok_or(TrustedClockError::Unavailable)?;
        if state.failed || sample.observed_at.elapsed() > self.inner.max_sample_age {
            return Err(TrustedClockError::Unavailable);
        }
        if !sample.status.synchronized || sample.status.estimated_error > self.inner.max_error {
            return Err(TrustedClockError::Untrusted);
        }

        let now = (self.inner.wall)();
        if state.last_returned.is_some_and(|last| now < last) {
            state.failed = true;
            return Err(TrustedClockError::Regressed);
        }
        state.last_returned = Some(now);
        Ok(now)
    }
}

fn spawn_health_monitor(inner: Weak<ClockInner>) -> Result<(), String> {
    thread::Builder::new()
        .name("praetore-chrony-health".into())
        .spawn(move || {
            loop {
                let Some(clock) = inner.upgrade() else {
                    return;
                };
                if !record_health(&clock, query_tracking(&clock.chronyc_path)) {
                    return;
                }
                let poll_interval = clock.poll_interval;
                drop(clock);
                thread::sleep(poll_interval);
            }
        })
        .map(|_| ())
        .map_err(|error| format!("failed to start chrony health monitor thread: {error}"))
}

/// Applies one health query result to the clock's state, as the monitor
/// thread does after each poll. `false` when the state lock is poisoned
/// (the monitor stops).
fn record_health(clock: &ClockInner, result: Result<TrackingStatus, String>) -> bool {
    let Ok(mut state) = clock.state.write() else {
        return false;
    };
    match result {
        Ok(status) if status.synchronized && status.estimated_error <= clock.max_error => {
            if state.failed {
                tracing::info!("chrony clock health recovered");
            }
            state.sample = Some(HealthSample {
                status,
                observed_at: Instant::now(),
            });
            state.failed = false;
        }
        Ok(_) => {
            if !state.failed {
                tracing::warn!(
                    "chrony clock is unsynchronized or exceeds the configured error bound; authorization will fail closed"
                );
            }
            state.failed = true;
        }
        Err(error) => {
            if !state.failed {
                tracing::warn!(
                    error = %error,
                    "chrony clock health query failed; authorization will fail closed"
                );
            }
            state.failed = true;
        }
    }
    true
}

fn query_tracking(path: &Path) -> Result<TrackingStatus, String> {
    let mut child = Command::new(path)
        .args(["-n", "tracking"])
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to query chrony tracking status: {error}"))?;
    let started_at = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started_at.elapsed() < CHRONYC_TIMEOUT => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("chrony tracking query timed out".into());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed waiting for chrony tracking query: {error}"));
            }
        }
    };
    let mut stdout = child
        .stdout
        .take()
        .ok_or("chrony tracking query output was unavailable")?;
    let mut bytes = Vec::new();
    stdout
        .by_ref()
        .take((MAX_TRACKING_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed reading chrony tracking output: {error}"))?;
    if !status.success() || bytes.len() > MAX_TRACKING_OUTPUT_BYTES {
        return Err("chrony tracking query failed or exceeded its output limit".into());
    }
    parse_tracking(
        &String::from_utf8(bytes).map_err(|_| "chrony tracking output was not valid UTF-8")?,
    )
}

fn parse_tracking(output: &str) -> Result<TrackingStatus, String> {
    if output.len() > MAX_TRACKING_OUTPUT_BYTES {
        return Err("chrony tracking output exceeded its size limit".into());
    }
    let mut reference_id = None;
    let mut stratum = None;
    let mut system_offset_seconds = None;
    let mut root_delay_seconds = None;
    let mut root_dispersion_seconds = None;
    let mut leap_status = None;

    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match label.trim() {
            "Reference ID" => {
                reference_id = Some(
                    value
                        .split_whitespace()
                        .next()
                        .ok_or("chrony tracking output contains an empty reference id")?
                        .to_ascii_uppercase(),
                );
            }
            "Stratum" => {
                let raw = value
                    .split_whitespace()
                    .next()
                    .ok_or("chrony tracking output contains an empty stratum")?;
                stratum = Some(
                    raw.parse::<u8>()
                        .map_err(|_| "chrony tracking output contains an invalid stratum")?,
                );
            }
            "System time" => {
                system_offset_seconds = Some(parse_number(value)?.abs());
            }
            "Root delay" => root_delay_seconds = Some(parse_number(value)?),
            "Root dispersion" => root_dispersion_seconds = Some(parse_number(value)?),
            "Leap status" => leap_status = Some(value.to_owned()),
            _ => {}
        }
    }

    let reference_id = reference_id.ok_or("chrony tracking output is missing Reference ID")?;
    let stratum = stratum.ok_or("chrony tracking output is missing Stratum")?;
    let system_offset_seconds =
        system_offset_seconds.ok_or("chrony tracking output is missing System time")?;
    let root_delay_seconds =
        root_delay_seconds.ok_or("chrony tracking output is missing Root delay")?;
    let root_dispersion_seconds =
        root_dispersion_seconds.ok_or("chrony tracking output is missing Root dispersion")?;
    let leap_status = leap_status.ok_or("chrony tracking output is missing Leap status")?;

    if root_delay_seconds < 0.0 || root_dispersion_seconds < 0.0 {
        return Err("chrony tracking output contains a negative delay or dispersion".into());
    }
    let estimated_error_seconds =
        system_offset_seconds + root_dispersion_seconds + (root_delay_seconds / 2.0);
    if !estimated_error_seconds.is_finite() || estimated_error_seconds > 1_000_000.0 {
        return Err("chrony tracking error bound is invalid".into());
    }
    let synchronized =
        stratum > 0 && stratum < 16 && reference_id != "7F7F0101" && leap_status == "Normal";

    Ok(TrackingStatus {
        synchronized,
        estimated_error: Duration::from_secs_f64(estimated_error_seconds),
    })
}

fn parse_number(value: &str) -> Result<f64, String> {
    let number = value
        .split_whitespace()
        .next()
        .ok_or("chrony tracking output contains an empty numeric field")?
        .parse::<f64>()
        .map_err(|_| "chrony tracking output contains an invalid numeric field")?;
    if !number.is_finite() {
        return Err("chrony tracking output contains an invalid numeric field".into());
    }
    Ok(number)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|metadata| {
        let mode = metadata.permissions().mode();
        mode & 0o111 != 0 && mode & 0o022 == 0
    })
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEALTHY_TRACKING: &str = "\
Reference ID    : C0A80101 (ntp.example.net)\n\
Stratum         : 3\n\
System time     : 0.000006523 seconds slow of NTP time\n\
Root delay      : 0.013639022 seconds\n\
Root dispersion : 0.001100737 seconds\n\
Leap status     : Normal\n";

    #[test]
    fn parses_chrony_error_bound_from_tracking_fields() {
        let status = parse_tracking(HEALTHY_TRACKING).unwrap();
        assert!(status.synchronized);
        assert_eq!(
            status.estimated_error,
            Duration::from_secs_f64(0.000006523 + 0.001100737 + 0.013639022 / 2.0)
        );
    }

    #[test]
    fn rejects_unsynchronized_and_invalid_tracking_status() {
        let unsynchronized = HEALTHY_TRACKING.replace(
            "Leap status     : Normal",
            "Leap status     : Not synchronised",
        );
        assert!(!parse_tracking(&unsynchronized).unwrap().synchronized);

        assert!(
            parse_tracking(
                &HEALTHY_TRACKING.replace("Stratum         : 3", "Stratum         : 3.5")
            )
            .is_err()
        );
        assert!(
            parse_tracking(&HEALTHY_TRACKING.replace(
                "Root dispersion : 0.001100737 seconds",
                "Root dispersion : -1 seconds"
            ))
            .is_err()
        );
    }

    /// A ChronyClock whose wall clock the test sets, with one healthy
    /// sample and no monitor thread: the test applies each health poll
    /// with `record_health`.
    fn controlled_clock(start: OffsetDateTime) -> (ChronyClock, Arc<RwLock<OffsetDateTime>>) {
        let wall = Arc::new(RwLock::new(start));
        let read = wall.clone();
        let inner = Arc::new(ClockInner {
            chronyc_path: PathBuf::from("/nonexistent/chronyc"),
            wall: Box::new(move || *read.read().unwrap()),
            poll_interval: Duration::from_secs(1),
            max_sample_age: Duration::from_secs(3600),
            max_error: Duration::from_millis(100),
            state: RwLock::new(ClockState {
                sample: Some(HealthSample {
                    status: parse_tracking(HEALTHY_TRACKING).unwrap(),
                    observed_at: Instant::now(),
                }),
                failed: false,
                last_returned: None,
            }),
        });
        (ChronyClock { inner }, wall)
    }

    struct NoReplay;

    impl praetore_core::ReplayGuard for NoReplay {
        fn claim_once(
            &self,
            _tenant_id: uuid::Uuid,
            _agent_id: uuid::Uuid,
            _request_id: uuid::Uuid,
        ) -> Result<(), praetore_core::ReplayGuardError> {
            Ok(())
        }
    }

    struct NoFreshness;

    impl praetore_core::FreshnessProvider for NoFreshness {
        fn check(
            &self,
            _agent: &praetore_core::AgentKeyFingerprint,
            _authority_id: &praetore_core::AuthorityId,
            _policy_digest: &str,
            _now: OffsetDateTime,
        ) -> Result<praetore_core::FreshnessLease, praetore_core::FreshnessError> {
            Err(praetore_core::FreshnessError::Unavailable)
        }
    }

    /// The gateway's composition (`main.rs`): a HighAssurance engine over
    /// a ChronyClock.
    fn engine_over(clock: ChronyClock) -> praetore_core::engine::AuthorizationEngine {
        let policy = praetore_core::Policy::new_v2("chrony-latch", 1, vec![]);
        let issuer = praetore_core::AgentKeyPair::generate();
        let pin = praetore_core::TrustedAuthorityIssuer::new("praetore-root", issuer.public_key())
            .unwrap()
            .with_validity(praetore_core::authority::Validity {
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2027-01-01T00:00:00Z".into()),
            })
            .unwrap();
        let config = praetore_core::HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![pin],
            praetore_core::EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_audience("chrony-latch-test")
        .with_replay_guard(Arc::new(NoReplay))
        .with_freshness_provider(Arc::new(NoFreshness));
        praetore_core::engine::AuthorizationEngine::production_with_trusted_clock(
            policy, config, clock,
        )
        .unwrap()
    }

    /// P-50-2: a backward step of the wall clock latches the engine for
    /// good, even after the next healthy chrony poll and after the wall
    /// clock passes the last time it returned.
    #[test]
    fn a_wall_clock_regression_stays_latched_after_a_healthy_poll() {
        let start = OffsetDateTime::from_unix_timestamp(1_780_315_200).unwrap();
        let (clock, wall) = controlled_clock(start);
        let inner = clock.inner.clone();
        let engine = engine_over(clock);
        assert_eq!(engine.trusted_now().unwrap(), start);

        *wall.write().unwrap() = start - time::Duration::seconds(30);
        assert!(engine.trusted_now().is_err(), "a backward read is refused");

        // The monitor thread's next poll: chrony is healthy.
        assert!(record_health(
            &inner,
            Ok(parse_tracking(HEALTHY_TRACKING).unwrap())
        ));
        *wall.write().unwrap() = start + time::Duration::seconds(60);
        assert!(
            engine.trusted_now().is_err(),
            "after a regression the engine must stay latched, even after a healthy poll \
             and once the wall clock passes the last returned time"
        );
    }

    #[test]
    fn rejects_local_reference_clock_as_unsynchronized() {
        let status = parse_tracking(&HEALTHY_TRACKING.replace("C0A80101", "7F7F0101")).unwrap();
        assert!(!status.synchronized);
    }

    #[cfg(unix)]
    #[test]
    fn clock_fails_closed_after_chrony_loses_synchronization() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let directory = std::env::temp_dir().join(format!(
            "praetore-chrony-clock-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let status_path = directory.join("tracking.txt");
        fs::write(&status_path, HEALTHY_TRACKING).unwrap();
        let executable_path = directory.join("chronyc");
        fs::write(
            &executable_path,
            format!("#!/bin/sh\ncat '{}'\n", status_path.display()),
        )
        .unwrap();
        let mut permissions = fs::metadata(&executable_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable_path, permissions).unwrap();

        let clock = ChronyClock::new(
            &executable_path,
            Duration::from_millis(10),
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(clock.now().is_ok());

        fs::write(
            &status_path,
            HEALTHY_TRACKING.replace(
                "Leap status     : Normal",
                "Leap status     : Not synchronised",
            ),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && clock.now() != Err(TrustedClockError::Unavailable) {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(clock.now(), Err(TrustedClockError::Unavailable));
        drop(clock);
        thread::sleep(Duration::from_millis(30));
        fs::remove_dir_all(directory).unwrap();
    }
}
