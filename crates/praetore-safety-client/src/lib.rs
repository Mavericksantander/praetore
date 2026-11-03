//! Non-blocking client for `praetore-safety-ingest` (G1, SAF-09.5).
//!
//! An executor of an AI-enabled system runs a safety action (for example
//! `safety:halt`) first and reports it afterwards. Reporting must never
//! delay or condition the action or the executor's failsafe, so this
//! client:
//!
//! * sends each event as one Unix datagram on a non-blocking socket. The
//!   call is one `sendto` that returns at once: it never waits for the
//!   ingester, never sleeps and never retries;
//! * on any failure (no ingester bound, its queue full, no kernel buffer,
//!   an event too large) drops the event, counts it in [`SafetyClient::dropped`]
//!   and returns an error the executor may ignore;
//! * holds no lock and allocates only to encode the event.
//!
//! A dropped event is not lost silently on the ingester side either: the
//! next event the ingester receives from the same source shows a gap in
//! `source_seq`, which it records as a signed loss record.
//!
//! Every run of the source has its own `source_epoch`, persisted by
//! [`EpochFile::start`] before the first event: `source_seq` starts at 1 in
//! each epoch, and a source that cannot persist its epoch must not report
//! (the call fails; it never falls back to epoch 1).
//!
//! The transport is local only (v1). Reporting over the network (HTTP with
//! mutual TLS) is future work.
//!
//! ```no_run
//! use praetore_core::{SafetyEventDraft, SafetySourceKey};
//! use praetore_safety_client::{EpochFile, SafetyClient};
//!
//! let key = SafetySourceKey::generate();
//! // Once per start of the source, before the first event.
//! let epoch = EpochFile::new("/var/lib/executor-1/safety-epoch").start().unwrap();
//! let client = SafetyClient::new("/run/praetore-safety/ingest.sock").unwrap();
//! let event = key
//!     .sign_event(SafetyEventDraft {
//!         source_id: "executor-1".into(),
//!         source_epoch: epoch,
//!         source_seq: 1,
//!         action: "safety:halt".into(),
//!         occurred_at: time::OffsetDateTime::now_utc(),
//!         params: Default::default(),
//!     })
//!     .unwrap();
//! // The action already ran; the result of reporting it does not matter to it.
//! let _ = client.send(&event);
//! ```

#![cfg(unix)]

mod epoch;

pub use epoch::EpochFile;

use std::{
    io,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use praetore_core::safety_ingest::{MAX_SAFETY_EVENT_BYTES, SafetyEvent};

/// Send buffer of the client socket. On macOS a Unix datagram larger than
/// the socket's send buffer is refused, and the default is 2048 bytes; an
/// event may be up to [`MAX_SAFETY_EVENT_BYTES`].
pub const SEND_BUFFER_BYTES: usize = 4 * MAX_SAFETY_EVENT_BYTES;

/// Why an event was dropped. The event is never queued or retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// No ingester is bound at the path: no socket file, or a socket file
    /// nobody listens on (the ingester is not running).
    NoListener,
    /// The ingester's receive queue is full, or the kernel has no buffer
    /// for the datagram (the ingester is slow or stalled).
    QueueFull,
    /// The encoded event is larger than [`MAX_SAFETY_EVENT_BYTES`].
    TooLarge,
    /// The event could not be encoded.
    Encoding,
    /// Another socket error.
    Io(io::ErrorKind),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoListener => f.write_str("no safety ingester is listening; event dropped"),
            Self::QueueFull => f.write_str("the safety ingester queue is full; event dropped"),
            Self::TooLarge => write!(f, "event exceeds {MAX_SAFETY_EVENT_BYTES} bytes; dropped"),
            Self::Encoding => f.write_str("event cannot be encoded; dropped"),
            Self::Io(kind) => write!(f, "socket error ({kind}); event dropped"),
        }
    }
}

impl std::error::Error for SendError {}

/// A reporting socket for one ingester path. `Send + Sync`: one client can
/// be shared by every thread of an executor.
#[derive(Debug)]
pub struct SafetyClient {
    socket: UnixDatagram,
    path: PathBuf,
    sent: AtomicU64,
    dropped: AtomicU64,
}

impl SafetyClient {
    /// An unbound, non-blocking datagram socket that sends to `path`.
    /// Nothing is checked about `path` here: an ingester that starts later
    /// is reached by later sends.
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        // Best effort: a smaller buffer only makes large events fail with
        // `TooLarge` on macOS.
        let _ = rustix::net::sockopt::set_socket_send_buffer_size(&socket, SEND_BUFFER_BYTES);
        Ok(Self {
            socket,
            path: path.into(),
            sent: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    }

    /// The ingester socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encodes and sends `event`; see [`Self::send_bytes`].
    pub fn send(&self, event: &SafetyEvent) -> Result<(), SendError> {
        match event.to_wire() {
            Ok(bytes) => self.send_bytes(&bytes),
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Err(SendError::Encoding)
            }
        }
    }

    /// One non-blocking `sendto`. Returns at once; on failure the event is
    /// dropped and counted, never retried.
    pub fn send_bytes(&self, bytes: &[u8]) -> Result<(), SendError> {
        let result = if bytes.len() > MAX_SAFETY_EVENT_BYTES {
            Err(SendError::TooLarge)
        } else {
            match self.socket.send_to(bytes, &self.path) {
                Ok(written) if written == bytes.len() => Ok(()),
                Ok(_) => Err(SendError::Io(io::ErrorKind::WriteZero)),
                Err(error) => Err(classify(&error)),
            }
        };
        match result {
            Ok(()) => self.sent.fetch_add(1, Ordering::Relaxed),
            Err(_) => self.dropped.fetch_add(1, Ordering::Relaxed),
        };
        result
    }

    /// Events sent (accepted by the kernel; not necessarily stored).
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Events dropped locally. Saturates at `u64::MAX`, far beyond any run.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn classify(error: &io::Error) -> SendError {
    use rustix::io::Errno;
    match error.kind() {
        io::ErrorKind::WouldBlock => return SendError::QueueFull,
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            return SendError::NoListener;
        }
        _ => {}
    }
    match error.raw_os_error().map(Errno::from_raw_os_error) {
        Some(Errno::NOBUFS) => SendError::QueueFull,
        Some(Errno::MSGSIZE) => SendError::TooLarge,
        Some(Errno::NOENT | Errno::CONNREFUSED | Errno::NOTSOCK | Errno::PROTOTYPE) => {
            SendError::NoListener
        }
        _ => SendError::Io(error.kind()),
    }
}
