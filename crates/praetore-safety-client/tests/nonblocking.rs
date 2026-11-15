//! The client never blocks: with no ingester, a dead one, or one that is
//! alive but stalled (never reads), every send returns within a bound, and
//! the event is dropped and counted.

use std::{
    collections::BTreeMap,
    os::unix::net::UnixDatagram,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use praetore_core::{SafetyEvent, SafetyEventDraft, SafetySourceKey, safety_ingest::ParamValue};
use praetore_safety_client::{SafetyClient, SendError};

/// The bound on one send. A non-blocking `sendto` takes microseconds (the
/// measured values are printed). A send that blocked on a stalled ingester
/// would not return at all.
const SEND_BOUND: Duration = Duration::from_millis(50);
/// The 99th percentile bound.
const P99_BOUND: Duration = Duration::from_millis(2);
/// The most the bounds can grow with load, whatever the probes measure.
const MAX_CAP: Duration = Duration::from_millis(100);
const P99_CAP: Duration = Duration::from_millis(10);
/// The probes show load when their max reaches `LOAD_PROBE_MAX` or their
/// p99 reaches `LOAD_PROBE_P99`. An idle machine measures probes of tens of
/// microseconds; a probe of 5 ms, or 1% of probes over 1 ms, means the
/// thread was descheduled.
const LOAD_PROBE_MAX: Duration = Duration::from_millis(5);
const LOAD_PROBE_P99: Duration = Duration::from_millis(1);
/// How many runs a measurement gets when the machine is loaded.
///
/// On a loaded machine the thread can be descheduled in the middle of a
/// send, for longer than the bound: that is the machine, not the client.
/// After each send the same thread times a probe: one encoding of the
/// event, the CPU part of a send, with no system call and nothing that can
/// block. Being descheduled lengthens the probes as much as the sends; a
/// sleep, a retry or a blocking call in `send` lengthens only the sends.
///
/// - Each bound is the fixed bound plus what the probes measured in the
///   same run (p99 for p99, max for max), capped at `MAX_CAP` and
///   `P99_CAP`.
/// - A run over a bound is run again, from a fresh client and socket, only
///   if its probes show load (see `LOAD_PROBE_MAX`), up to this many runs.
///   A run over a bound with idle probes fails the test at once.
const RUNS: usize = 3;
/// Sends per run in the single-thread tests. A send that is slow once
/// every 2000 sends lands in every run.
const SENDS: u64 = 2000;

/// The timing tests run one at a time, so they do not compete for the CPU.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A short directory for socket paths (`sun_path` holds about 104 bytes).
struct SocketDir(PathBuf);

impl SocketDir {
    fn new(name: &str) -> Self {
        let dir = PathBuf::from("/tmp").join(format!("psc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("s")
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event(seq: u64, padding: usize) -> SafetyEvent {
    let key = SafetySourceKey::from_secret_bytes(&[4; 32]);
    let mut params = BTreeMap::new();
    for index in 0..padding {
        params.insert(format!("p{index}"), ParamValue::String("x".repeat(250)));
    }
    key.sign_event(SafetyEventDraft {
        source_id: "executor-1".into(),
        source_epoch: 1,
        source_seq: seq,
        action: "safety:halt".into(),
        occurred_at: time::OffsetDateTime::now_utc(),
        params,
    })
    .unwrap()
}

/// The time of each send, and of the CPU-only probe timed right after it.
#[derive(Default)]
struct Timings {
    sends: Vec<Duration>,
    probes: Vec<Duration>,
}

fn quantile(values: &mut [Duration], q: f64) -> Duration {
    values.sort();
    values[((values.len() - 1) as f64 * q) as usize]
}

/// A run over a bound: why, and whether its probes showed load.
struct Over {
    message: String,
    loaded: bool,
}

impl Timings {
    /// Prints both distributions; `Err` names the bound that was passed.
    fn check(&mut self, label: &str) -> Result<(), Over> {
        let (p50, p99, max) = (
            quantile(&mut self.sends, 0.5),
            quantile(&mut self.sends, 0.99),
            quantile(&mut self.sends, 1.0),
        );
        let (probe_p99, probe_max) = (
            quantile(&mut self.probes, 0.99),
            quantile(&mut self.probes, 1.0),
        );
        let max_bound = (SEND_BOUND + probe_max).min(MAX_CAP);
        let p99_bound = (P99_BOUND + probe_p99).min(P99_CAP);
        let loaded = probe_max >= LOAD_PROBE_MAX || probe_p99 >= LOAD_PROBE_P99;
        println!(
            "{label}: {} sends, p50 {p50:?}, p99 {p99:?} (bound {p99_bound:?}), max {max:?} (bound {max_bound:?}); probe p99 {probe_p99:?}, max {probe_max:?}{}",
            self.sends.len(),
            if loaded { ", load" } else { "" },
        );
        let message = if max >= max_bound {
            format!("{label}: a send took {max:?}, bound {max_bound:?}")
        } else if p99 >= p99_bound {
            format!("{label}: p99 {p99:?}, bound {p99_bound:?}")
        } else {
            return Ok(());
        };
        Err(Over { message, loaded })
    }
}

/// Runs `measure` (one run: a fresh client, its sends and their checks).
/// Passes on the first run whose timings are all within the bounds. A run
/// over a bound is run again only if every timing over a bound showed load,
/// up to [`RUNS`] runs; otherwise the test fails at once.
fn within_bounds(label: &str, mut measure: impl FnMut() -> Vec<(String, Timings)>) {
    let mut failures = Vec::new();
    for run in 1..=RUNS {
        let mut timings = measure();
        let over: Vec<Over> = timings
            .iter_mut()
            .filter_map(|(name, times)| times.check(&format!("{label}, {name}, run {run}")).err())
            .collect();
        if over.is_empty() {
            println!("{label}: within the bounds on run {run} of {RUNS}");
            return;
        }
        if let Some(idle) = over.iter().find(|o| !o.loaded) {
            panic!(
                "{label}: over a bound on run {run} with no sign of load in the probes: {}",
                idle.message
            );
        }
        failures.extend(over.into_iter().map(|o| o.message));
        // Let a burst of load pass before the next run.
        thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "{label}: over a bound in all {RUNS} runs, each under load:\n{}",
        failures.join("\n")
    );
}

fn timed(client: &SafetyClient, event: &SafetyEvent, times: &mut Timings) -> Result<(), SendError> {
    let start = Instant::now();
    let result = client.send(event);
    times.sends.push(start.elapsed());
    // The probe: one encoding of the event, the CPU part of a send, with no
    // system call, so nothing in it can sleep or block.
    let start = Instant::now();
    std::hint::black_box(std::hint::black_box(event).to_wire().ok());
    times.probes.push(start.elapsed());
    result
}

#[test]
fn no_ingester_returns_at_once_and_counts_the_drop() {
    let _serial = serial();
    within_bounds("no socket file", || {
        let dir = SocketDir::new("none");
        let client = SafetyClient::new(dir.socket()).unwrap();
        let mut times = Timings::default();
        for seq in 1..=SENDS {
            assert_eq!(
                timed(&client, &event(seq, 0), &mut times),
                Err(SendError::NoListener)
            );
        }
        assert_eq!((client.sent(), client.dropped()), (0, SENDS));
        vec![("sends".into(), times)]
    });
}

#[test]
fn a_dead_ingester_returns_at_once() {
    let _serial = serial();
    within_bounds("dead ingester (stale socket file)", || {
        let dir = SocketDir::new("dead");
        // The socket file stays after the ingester is gone (killed, crashed).
        drop(UnixDatagram::bind(dir.socket()).unwrap());
        assert!(dir.socket().exists());
        let client = SafetyClient::new(dir.socket()).unwrap();
        let mut times = Timings::default();
        for seq in 1..=SENDS {
            assert_eq!(
                timed(&client, &event(seq, 0), &mut times),
                Err(SendError::NoListener)
            );
        }
        vec![("sends".into(), times)]
    });
    // A regular file at the path is no listener either.
    let file_dir = SocketDir::new("file");
    std::fs::write(file_dir.socket(), b"not a socket").unwrap();
    let client = SafetyClient::new(file_dir.socket()).unwrap();
    assert_eq!(client.send(&event(1, 0)), Err(SendError::NoListener));
}

#[test]
fn a_stalled_ingester_with_a_full_queue_never_blocks_the_sender() {
    let _serial = serial();
    within_bounds("stalled ingester (queue full)", || {
        let dir = SocketDir::new("stalled");
        // Bound and alive, but it never reads: its queue fills up.
        let ingester = UnixDatagram::bind(dir.socket()).unwrap();
        let client = SafetyClient::new(dir.socket()).unwrap();
        let mut times = Timings::default();
        let mut full = 0;
        let started = Instant::now();
        for seq in 1..=5_000 {
            match timed(&client, &event(seq, 4), &mut times) {
                Ok(()) => {}
                Err(SendError::QueueFull) => full += 1,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        let total = started.elapsed();
        println!(
            "stalled ingester: {} accepted by the kernel, {full} dropped as QueueFull, total {total:?}",
            client.sent()
        );
        assert!(full > 0, "the queue never filled");
        assert_eq!(client.dropped(), full);
        // Once it reads again, later sends succeed: nothing was stuck.
        let mut buffer = vec![0; 64 * 1024];
        ingester.set_nonblocking(true).unwrap();
        while ingester.recv(&mut buffer).is_ok() {}
        client.send(&event(5_001, 0)).unwrap();
        drop(ingester);
        vec![("sends".into(), times)]
    });
}

#[test]
fn concurrent_senders_against_a_stalled_ingester_stay_within_the_bound() {
    let _serial = serial();
    within_bounds("concurrent senders", || {
        let dir = SocketDir::new("concurrent");
        let _ingester = UnixDatagram::bind(dir.socket()).unwrap();
        let client = Arc::new(SafetyClient::new(dir.socket()).unwrap());
        let handles: Vec<_> = (0..4)
            .map(|thread_index| {
                let client = Arc::clone(&client);
                thread::spawn(move || {
                    let mut times = Timings::default();
                    for seq in 1..=2_000 {
                        let _ = timed(&client, &event(thread_index * 10_000 + seq, 1), &mut times);
                    }
                    times
                })
            })
            .collect();
        let timings = handles
            .into_iter()
            .enumerate()
            .map(|(index, handle)| (format!("sender {index}"), handle.join().unwrap()))
            .collect();
        assert_eq!(client.sent() + client.dropped(), 8_000);
        timings
    });
}

#[test]
fn a_listening_ingester_receives_the_event_exactly() {
    let _serial = serial();
    let dir = SocketDir::new("live");
    let ingester = UnixDatagram::bind(dir.socket()).unwrap();
    // As praetore-safety-ingest does: room for large datagrams (macOS
    // refuses a datagram larger than the receiver's free buffer).
    rustix::net::sockopt::set_socket_recv_buffer_size(&ingester, 1 << 20).unwrap();
    let client = SafetyClient::new(dir.socket()).unwrap();
    // The largest events (close to the 8 KiB limit) fit in one datagram,
    // also on macOS, whose default datagram limit is 2048 bytes.
    for padding in [0, 16] {
        let event = event(1, padding);
        let wire = event.to_wire().unwrap();
        assert!(padding == 0 || wire.len() > 4000, "{}", wire.len());
        client.send(&event).unwrap();
        let mut buffer = vec![0; 64 * 1024];
        let read = ingester.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..read], wire.as_slice());
        assert_eq!(SafetyEvent::parse(&buffer[..read]).unwrap(), event);
    }
    assert_eq!(
        client.send_bytes(&vec![b' '; 9000]),
        Err(SendError::TooLarge)
    );
}
