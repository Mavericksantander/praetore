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

/// The hard bound on one send asserted here. A non-blocking `sendto`
/// takes microseconds (the measured values are printed); the bound leaves
/// room for the thread being descheduled on a loaded CI machine. A send that
/// blocked on a stalled ingester would not return at all.
const SEND_BOUND: Duration = Duration::from_millis(50);
/// The 99th percentile bound.
const P99_BOUND: Duration = Duration::from_millis(2);

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
        source_seq: seq,
        action: "safety:halt".into(),
        occurred_at: time::OffsetDateTime::now_utc(),
        params,
    })
    .unwrap()
}

struct Timings(Vec<Duration>);

impl Timings {
    fn report(&mut self, label: &str) -> Duration {
        self.0.sort();
        let at = |q: f64| self.0[((self.0.len() - 1) as f64 * q) as usize];
        let max = *self.0.last().unwrap();
        println!(
            "{label}: {} sends, p50 {:?}, p99 {:?}, max {:?} (bound {SEND_BOUND:?})",
            self.0.len(),
            at(0.5),
            at(0.99),
            max
        );
        assert!(max < SEND_BOUND, "{label}: a send took {max:?}");
        assert!(at(0.99) < P99_BOUND, "{label}: p99 {:?}", at(0.99));
        max
    }
}

fn timed(client: &SafetyClient, event: &SafetyEvent, times: &mut Timings) -> Result<(), SendError> {
    let start = Instant::now();
    let result = client.send(event);
    times.0.push(start.elapsed());
    result
}

#[test]
fn no_ingester_returns_at_once_and_counts_the_drop() {
    let _serial = serial();
    let dir = SocketDir::new("none");
    let client = SafetyClient::new(dir.socket()).unwrap();
    let mut times = Timings(Vec::new());
    for seq in 1..=1000 {
        assert_eq!(
            timed(&client, &event(seq, 0), &mut times),
            Err(SendError::NoListener)
        );
    }
    times.report("no socket file");
    assert_eq!((client.sent(), client.dropped()), (0, 1000));
}

#[test]
fn a_dead_ingester_returns_at_once() {
    let _serial = serial();
    let dir = SocketDir::new("dead");
    // The socket file stays after the ingester is gone (killed, crashed).
    drop(UnixDatagram::bind(dir.socket()).unwrap());
    assert!(dir.socket().exists());
    let client = SafetyClient::new(dir.socket()).unwrap();
    let mut times = Timings(Vec::new());
    for seq in 1..=1000 {
        assert_eq!(
            timed(&client, &event(seq, 0), &mut times),
            Err(SendError::NoListener)
        );
    }
    times.report("dead ingester (stale socket file)");
    // A regular file at the path is no listener either.
    let file_dir = SocketDir::new("file");
    std::fs::write(file_dir.socket(), b"not a socket").unwrap();
    let client = SafetyClient::new(file_dir.socket()).unwrap();
    assert_eq!(client.send(&event(1, 0)), Err(SendError::NoListener));
}

#[test]
fn a_stalled_ingester_with_a_full_queue_never_blocks_the_sender() {
    let _serial = serial();
    let dir = SocketDir::new("stalled");
    // Bound and alive, but it never reads: its queue fills up.
    let ingester = UnixDatagram::bind(dir.socket()).unwrap();
    let client = SafetyClient::new(dir.socket()).unwrap();
    let mut times = Timings(Vec::new());
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
    times.report("stalled ingester (queue full)");
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
}

#[test]
fn concurrent_senders_against_a_stalled_ingester_stay_within_the_bound() {
    let _serial = serial();
    let dir = SocketDir::new("concurrent");
    let _ingester = UnixDatagram::bind(dir.socket()).unwrap();
    let client = Arc::new(SafetyClient::new(dir.socket()).unwrap());
    let handles: Vec<_> = (0..4)
        .map(|thread_index| {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                let mut times = Timings(Vec::new());
                for seq in 1..=2_000 {
                    let _ = timed(&client, &event(thread_index * 10_000 + seq, 1), &mut times);
                }
                times
            })
        })
        .collect();
    for (index, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap()
            .report(&format!("concurrent sender {index}"));
    }
    assert_eq!(client.sent() + client.dropped(), 8_000);
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
