//! Approval expiry times as people read them: local time with UTC beside
//! it, and how long is left.
//!
//! The local offset comes from the C library (`localtime_r`, which follows
//! `TZ` and the system zone) on Linux and macOS. Elsewhere, or when it
//! fails, only UTC is shown.

use time::{OffsetDateTime, UtcOffset};

/// `2026-11-15 20:34:40`.
fn date_time(at: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// `20:34`.
fn clock(at: OffsetDateTime) -> String {
    format!("{:02}:{:02}", at.hour(), at.minute())
}

/// The local UTC offset at `at`, if the system can say.
pub fn local_offset(at: OffsetDateTime) -> Option<UtcOffset> {
    let seconds = system_offset_seconds(at.unix_timestamp())?;
    UtcOffset::from_whole_seconds(seconds).ok()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn system_offset_seconds(unix: i64) -> Option<i32> {
    unsafe extern "C" {
        fn tzset();
    }
    // time_t is i64 here, but i32 on some 32-bit targets.
    #[allow(clippy::useless_conversion)]
    let at: libc::time_t = unix.try_into().ok()?;
    // SAFETY: tzset only reads TZ and the zone files; localtime_r writes
    // only into `tm`, which is a plain C struct owned here.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { tzset() };
    let result = unsafe { libc::localtime_r(&at, &mut tm) };
    if result.is_null() {
        return None;
    }
    i32::try_from(tm.tm_gmtoff).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn system_offset_seconds(_unix: i64) -> Option<i32> {
    None
}

/// `9 min 40 s`, `1 h 5 min`, `40 s`, for a non-negative number of seconds.
pub fn duration_text(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let (hours, minutes, rest) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    match (hours, minutes) {
        (0, 0) => format!("{rest} s"),
        (0, _) => format!("{minutes} min {rest} s"),
        _ => format!("{hours} h {minutes} min"),
    }
}

/// `UTC-03:00`, `UTC+05:30`, `UTC`.
fn offset_label(offset: UtcOffset) -> String {
    if offset.is_utc() {
        return "UTC".into();
    }
    let (h, m, _) = offset.as_hms();
    let sign = if offset.is_negative() { '-' } else { '+' };
    format!("UTC{sign}{:02}:{:02}", h.unsigned_abs(), m.unsigned_abs())
}

/// `2026-11-15 20:34:40 local time (UTC-03:00) / 2026-11-15 23:34:40 UTC
/// (in 9 min 40 s)`, or `(expired 3 min 5 s ago)`. With no local offset,
/// only the UTC part.
pub fn expiry_text(
    expires: OffsetDateTime,
    now: OffsetDateTime,
    local: Option<UtcOffset>,
) -> String {
    let utc = expires.to_offset(UtcOffset::UTC);
    let utc_text = date_time(utc);
    let left = (expires - now).whole_seconds();
    let remaining = if left > 0 {
        format!("in {}", duration_text(left))
    } else {
        format!("expired {} ago", duration_text(-left))
    };
    match local {
        Some(offset) => format!(
            "{} local time ({}) / {utc_text} UTC ({remaining})",
            date_time(expires.to_offset(offset)),
            offset_label(offset),
        ),
        None => format!("{utc_text} UTC ({remaining})"),
    }
}

/// `20:34 (local time) / 23:34 UTC`, or `23:34 UTC` with no local offset.
pub fn clock_text(at: OffsetDateTime, local: Option<UtcOffset>) -> String {
    let utc = clock(at.to_offset(UtcOffset::UTC));
    match local {
        Some(offset) => format!("{} (local time) / {utc} UTC", clock(at.to_offset(offset))),
        None => format!("{utc} UTC"),
    }
}

/// [`expiry_text`] with the system's local offset and the current time.
pub fn expiry_now(expires: OffsetDateTime) -> String {
    let now = OffsetDateTime::now_utc();
    expiry_text(expires, now, local_offset(expires))
}

/// [`clock_text`] with the system's local offset.
pub fn clock_local(at: OffsetDateTime) -> String {
    clock_text(at, local_offset(at))
}

/// Parses an RFC 3339 time as written in the approval files.
pub fn parse(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> OffsetDateTime {
        parse(text).unwrap()
    }

    fn hours(h: i8, m: i8) -> UtcOffset {
        UtcOffset::from_hms(h, m, 0).unwrap()
    }

    #[test]
    fn expiry_in_a_fixed_zone_shows_local_utc_and_what_is_left() {
        let expires = at("2026-11-15T23:34:40Z");
        let now = at("2026-11-15T23:25:00Z");
        assert_eq!(
            expiry_text(expires, now, Some(hours(-3, 0))),
            "2026-11-15 20:34:40 local time (UTC-03:00) / 2026-11-15 23:34:40 UTC (in 9 min 40 s)"
        );
        assert_eq!(
            expiry_text(expires, now, Some(hours(5, 30))),
            "2026-11-16 05:04:40 local time (UTC+05:30) / 2026-11-15 23:34:40 UTC (in 9 min 40 s)"
        );
        assert_eq!(
            expiry_text(expires, now, None),
            "2026-11-15 23:34:40 UTC (in 9 min 40 s)"
        );
        let later = at("2026-11-15T23:37:45Z");
        assert_eq!(
            expiry_text(expires, later, Some(UtcOffset::UTC)),
            "2026-11-15 23:34:40 local time (UTC) / 2026-11-15 23:34:40 UTC (expired 3 min 5 s ago)"
        );
        assert_eq!(
            clock_text(expires, Some(hours(-3, 0))),
            "20:34 (local time) / 23:34 UTC"
        );
        assert_eq!(clock_text(expires, None), "23:34 UTC");
    }

    #[test]
    fn durations_read_as_hours_minutes_and_seconds() {
        assert_eq!(duration_text(0), "0 s");
        assert_eq!(duration_text(40), "40 s");
        assert_eq!(duration_text(580), "9 min 40 s");
        assert_eq!(duration_text(3600 + 5 * 60 + 9), "1 h 5 min");
        assert_eq!(duration_text(-5), "0 s");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_system_offset_is_a_whole_number_of_minutes() {
        let offset = local_offset(OffsetDateTime::now_utc()).expect("localtime_r");
        assert_eq!(offset.whole_seconds() % 60, 0);
    }
}
