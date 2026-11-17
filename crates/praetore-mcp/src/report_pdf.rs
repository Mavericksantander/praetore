//! The session report as a PDF ([`crate::report`] builds the data).
//!
//! Written with `pdf-writer`: no network, no external process, no font
//! file. Text uses the standard Helvetica and Courier fonts every PDF
//! reader has, so only printable ASCII is drawn; anything else is written
//! escaped. Content streams are not compressed, which keeps the text of the
//! report searchable in the file itself.
//!
//! All coordinates below are in points from the top-left corner of an A4
//! page; [`Canvas`] converts them to PDF space.

use crate::report::{ApprovalRow, ApprovalStatus, Label, Report, Row, STATEMENT};
use crate::when::local_offset;
use pdf_writer::{Content, Filter, Finish, Name, Pdf, Rect, Ref, Str, TextStr};
use time::{OffsetDateTime, UtcOffset};

/// PRÆTOR TECHNOLOGIES wordmark, white on black, 8-bit gray JPEG. Used as
/// the alpha of a one-pixel image, so it can be drawn in any color.
const LOGO_JPEG: &[u8] = include_bytes!("../assets/praetor-technologies-logo.jpg");
const LOGO_WIDTH: i32 = 760;
const LOGO_HEIGHT: i32 = 240;

const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const LEFT: f32 = 56.0;
const RIGHT: f32 = 539.0;
const BODY_BOTTOM: f32 = 780.0;
/// A table row: local time on the first line, UTC under it.
const ROW_H: f32 = 22.0;
/// Where a row's second line (UTC) and its rule go, below its first line.
const ROW_SECOND: f32 = 8.5;
const ROW_RULE: f32 = 12.0;

type Rgb = (f32, f32, f32);
const INK: Rgb = (0.07, 0.07, 0.08);
const MUTED: Rgb = (0.45, 0.46, 0.48);
const HAIR: Rgb = (0.82, 0.83, 0.85);
const ACCENT: Rgb = (0.216, 0.541, 0.867);
const GREEN: Rgb = (0.114, 0.62, 0.459);
const RED: Rgb = (0.82, 0.2, 0.2);
const AMBER: Rgb = (0.86, 0.56, 0.1);
const GRAY: Rgb = (0.55, 0.55, 0.53);

#[derive(Clone, Copy, PartialEq)]
enum Font {
    Sans,
    SansBold,
    Mono,
    MonoBold,
}

impl Font {
    fn resource(self) -> Name<'static> {
        Name(match self {
            Self::Sans => b"F1",
            Self::SansBold => b"F2",
            Self::Mono => b"F3",
            Self::MonoBold => b"F4",
        })
    }

    fn base(self) -> Name<'static> {
        Name(match self {
            Self::Sans => b"Helvetica",
            Self::SansBold => b"Helvetica-Bold",
            Self::Mono => b"Courier",
            Self::MonoBold => b"Courier-Bold",
        })
    }

    const ALL: [Self; 4] = [Self::Sans, Self::SansBold, Self::Mono, Self::MonoBold];
}

/// Helvetica advance widths for ASCII 32..=126, in 1/1000 of the font size
/// (Adobe core font metrics).
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

/// Width of `text` (already ASCII) at `size` with `spacing` after each
/// glyph. Bold sans is a little wider than the regular table.
fn width(font: Font, size: f32, spacing: f32, text: &str) -> f32 {
    let units: f32 = text
        .bytes()
        .map(|b| match font {
            Font::Mono | Font::MonoBold => 600.0,
            Font::Sans | Font::SansBold => {
                let glyph = f32::from(HELVETICA[usize::from(b.clamp(32, 126) - 32)]);
                if font == Font::SansBold {
                    glyph * 1.06
                } else {
                    glyph
                }
            }
        })
        .sum();
    units / 1000.0 * size + spacing * text.len() as f32
}

/// Text as the report draws it: escaped like every other display of the
/// journal (control, zero-width and bidi characters become `\u{..}`), then
/// reduced to printable ASCII.
fn ascii(text: &str) -> String {
    crate::shown::bounded(text, 400)
        .chars()
        .map(|c| match c {
            ' '..='~' => c,
            '…' => '~',
            _ => '?',
        })
        .collect()
}

/// Text already made printable ([`ascii`], [`fit`] or text this module
/// writes) as the PDF draws it: anything outside printable ASCII becomes
/// `?`. It does not escape again, so a `\` written by [`ascii`] stays one.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if matches!(c, ' '..='~') { c } else { '?' })
        .collect()
}

/// `text` cut to fit `max` points, ending in `...` when it was cut.
fn fit(font: Font, size: f32, max: f32, text: &str) -> String {
    let text = ascii(text);
    if width(font, size, 0.0, &text) <= max {
        return text;
    }
    let mut out = String::new();
    for c in text.chars() {
        let mut candidate = out.clone();
        candidate.push(c);
        if width(font, size, 0.0, &candidate) + width(font, size, 0.0, "...") > max {
            break;
        }
        out = candidate;
    }
    out.push_str("...");
    out
}

/// Drawing on one page, in top-left coordinates.
struct Canvas {
    content: Content,
}

impl Canvas {
    fn new() -> Self {
        Self {
            content: Content::new(),
        }
    }

    /// Text at (`x`, `y`) with `spacing` points after each glyph. Text from
    /// the journal or the session goes through [`ascii`] or [`fit`] first.
    fn text_spaced(&mut self, face: (Font, f32, f32), color: Rgb, x: f32, y: f32, text: &str) {
        let (font, size, spacing) = face;
        let text = printable(text);
        self.content
            .begin_text()
            .set_font(font.resource(), size)
            .set_char_spacing(spacing)
            .set_fill_rgb(color.0, color.1, color.2)
            .next_line(x, PAGE_H - y)
            .show(Str(text.as_bytes()))
            .end_text();
    }

    fn text(&mut self, font: Font, size: f32, color: Rgb, x: f32, y: f32, text: &str) {
        self.text_spaced((font, size, 0.0), color, x, y, text);
    }

    fn text_right(&mut self, font: Font, size: f32, color: Rgb, right: f32, y: f32, text: &str) {
        let text = printable(text);
        let x = right - width(font, size, 0.0, &text);
        self.text(font, size, color, x, y, &text);
    }

    /// Small spaced capitals: the labels of the report.
    fn label(&mut self, color: Rgb, x: f32, y: f32, text: &str) {
        self.text_spaced((Font::Mono, 6.8, 1.1), color, x, y, text);
    }

    fn rect(&mut self, color: Rgb, x: f32, y: f32, w: f32, h: f32) {
        self.content
            .set_fill_rgb(color.0, color.1, color.2)
            .rect(x, PAGE_H - y - h, w, h)
            .fill_nonzero();
    }

    fn line(&mut self, color: Rgb, weight: f32, x1: f32, y1: f32, x2: f32, y2: f32) {
        self.content
            .set_stroke_rgb(color.0, color.1, color.2)
            .set_line_width(weight)
            .move_to(x1, PAGE_H - y1)
            .line_to(x2, PAGE_H - y2)
            .stroke();
    }

    /// A square standing on a corner, centered at (`x`, `y`).
    fn diamond(&mut self, color: Rgb, filled: bool, x: f32, y: f32, r: f32) {
        let y = PAGE_H - y;
        self.content
            .move_to(x, y + r)
            .line_to(x + r, y)
            .line_to(x, y - r)
            .line_to(x - r, y)
            .close_path();
        if filled {
            self.content
                .set_fill_rgb(color.0, color.1, color.2)
                .fill_nonzero();
        } else {
            self.content
                .set_stroke_rgb(color.0, color.1, color.2)
                .set_line_width(0.9)
                .stroke();
        }
    }

    /// An arc of the circle at (`cx`, `cy`), from `from` to `to` degrees
    /// clockwise from the top.
    #[allow(clippy::too_many_arguments)]
    fn arc(&mut self, color: Rgb, weight: f32, cx: f32, cy: f32, r: f32, from: f32, to: f32) {
        let cy = PAGE_H - cy;
        let point = |deg: f32| {
            let t = (90.0 - deg).to_radians();
            (cx + r * t.cos(), cy + r * t.sin(), -t.sin(), t.cos())
        };
        self.content
            .set_stroke_rgb(color.0, color.1, color.2)
            .set_line_width(weight);
        let pieces = (((to - from) / 90.0).ceil() as usize).max(1);
        let step = (to - from) / pieces as f32;
        for piece in 0..pieces {
            let a0 = from + step * piece as f32;
            let a1 = a0 + step;
            // Clockwise on the page is a negative turn in PDF space.
            let k = 4.0 / 3.0 * ((-step).to_radians() / 4.0).tan() * r;
            let (x0, y0, tx0, ty0) = point(a0);
            let (x1, y1, tx1, ty1) = point(a1);
            if piece == 0 {
                self.content.move_to(x0, y0);
            }
            self.content.cubic_to(
                x0 + k * tx0,
                y0 + k * ty0,
                x1 - k * tx1,
                y1 - k * ty1,
                x1,
                y1,
            );
        }
        self.content.stroke();
    }

    /// The wordmark in black or white, `h` points tall.
    fn logo(&mut self, white: bool, x: f32, y: f32, h: f32) {
        let w = h * LOGO_WIDTH as f32 / LOGO_HEIGHT as f32;
        self.content
            .save_state()
            .transform([w, 0.0, 0.0, h, x, PAGE_H - y - h])
            .x_object(Name(if white { b"LogoW" } else { b"LogoK" }))
            .restore_state();
    }
}

fn stamp(at: OffsetDateTime, offset: UtcOffset) -> (String, String, String) {
    let at = at.to_offset(offset);
    let date = format!(
        "{:04}-{:02}-{:02}",
        at.year(),
        u8::from(at.month()),
        at.day()
    );
    let clock = format!("{:02}:{:02}:{:02}", at.hour(), at.minute(), at.second());
    let zone = if offset == UtcOffset::UTC {
        "UTC".to_owned()
    } else {
        let (h, m, _) = offset.as_hms();
        format!(
            "{}{:02}:{:02}",
            if offset.is_negative() { '-' } else { '+' },
            h.abs(),
            m.abs()
        )
    };
    (date, clock, zone)
}

/// `2026-11-15 11:42:07 -03:00` in local time, and `14:42:07 UTC` next to
/// it. Where the local offset is unknown both are UTC and the second part
/// is empty.
fn local_and_utc(at: OffsetDateTime) -> (String, String) {
    let (utc_date, utc_clock, _) = stamp(at, UtcOffset::UTC);
    match local_offset(at) {
        Some(offset) if offset != UtcOffset::UTC => {
            let (date, clock, zone) = stamp(at, offset);
            let utc = if date == utc_date {
                format!("{utc_clock} UTC")
            } else {
                format!("{utc_date} {utc_clock} UTC")
            };
            (format!("{date} {clock} {zone}"), utc)
        }
        _ => (format!("{utc_date} {utc_clock} UTC"), String::new()),
    }
}

fn local_clock(at: Option<OffsetDateTime>) -> String {
    at.map_or_else(
        || "--:--:--".into(),
        |at| stamp(at, local_offset(at).unwrap_or(UtcOffset::UTC)).1,
    )
}

fn utc_clock(at: Option<OffsetDateTime>) -> String {
    at.map_or_else(String::new, |at| {
        format!("{} UTC", stamp(at, UtcOffset::UTC).1)
    })
}

/// A time cell: local time, and UTC under it in small type.
fn time_cell(c: &mut Canvas, x: f32, y: f32, at: Option<OffsetDateTime>) {
    c.text(Font::Mono, 7.8, INK, x, y, &local_clock(at));
    if at.is_some() {
        c.text(Font::Mono, 5.8, MUTED, x, y + ROW_SECOND, &utc_clock(at));
    }
}

fn label_color(label: Label) -> Rgb {
    match label {
        Label::Allow => GREEN,
        Label::Deny | Label::Unreadable => RED,
        Label::Held => AMBER,
        Label::Approved => ACCENT,
        Label::WouldAsk => GRAY,
    }
}

/// The integrity ring: one segment per session receipt, red where `verify`
/// did not count the receipt as verified.
fn ring(canvas: &mut Canvas, report: &Report, cx: f32, cy: f32) {
    let passed = report.verify.passed;
    let tone = if passed { ACCENT } else { RED };
    let mut tick = 0.0;
    while tick < 360.0 {
        canvas.arc(tone, 0.5, cx, cy, 58.0, tick, tick + 1.2);
        tick += 6.0;
    }
    let rows = &report.rows;
    // Above this many receipts, one segment stands for several of them and
    // is red if any of them failed.
    let segments = rows.len().clamp(1, 72);
    let sweep = 360.0 / segments as f32;
    let gap = if segments == 1 {
        0.0
    } else {
        (sweep * 0.12).min(2.5)
    };
    for segment in 0..segments {
        let from = rows.len() * segment / segments;
        let to = (rows.len() * (segment + 1) / segments).max(from + 1);
        let ok = rows
            .get(from..to.min(rows.len()))
            .is_some_and(|slice| !slice.is_empty() && slice.iter().all(|row| row.verified));
        let start = sweep * segment as f32 + gap / 2.0;
        // When verify fails, the receipts of this session that verified are
        // gray, not green: the ring is about this session only and the
        // journal as a whole did not verify.
        canvas.arc(
            if ok && passed {
                GREEN
            } else if ok {
                GRAY
            } else if rows.is_empty() {
                HAIR
            } else {
                RED
            },
            6.0,
            cx,
            cy,
            46.0,
            start,
            start + sweep - gap,
        );
    }
    let count = format!(
        "{}/{}",
        report.verify.session_verified, report.verify.session_receipts
    );
    let w = width(Font::Sans, 19.0, 0.0, &count);
    canvas.text(Font::Sans, 19.0, INK, cx - w / 2.0, cy + 3.0, &count);
    let word = if passed { "VERIFIED" } else { "FAILED" };
    let w = width(Font::Mono, 6.8, 1.1, word);
    canvas.label(
        if passed { GREEN } else { RED },
        cx - w / 2.0,
        cy + 16.0,
        word,
    );
    if !passed {
        let note = "THIS SESSION";
        let w = width(Font::Mono, 6.8, 1.1, note);
        canvas.label(MUTED, cx - w / 2.0, cy - 16.0, note);
    }
}

/// A labelled value with a short accent bar on its left.
fn block(canvas: &mut Canvas, y: f32, label: &str, value: &str) {
    canvas.rect(ACCENT, LEFT, y - 7.0, 1.6, 22.0);
    canvas.label(ACCENT, LEFT + 9.0, y, label);
    canvas.text(Font::Mono, 8.2, INK, LEFT + 9.0, y + 12.0, &ascii(value));
}

fn cover(report: &Report) -> Canvas {
    let mut c = Canvas::new();
    let failed = !report.verify.passed;

    c.rect(INK, 0.0, 0.0, PAGE_W, 96.0);
    c.logo(true, LEFT - 14.0, 20.0, 56.0);
    c.text_right(
        Font::Mono,
        7.5,
        (0.72, 0.74, 0.78),
        RIGHT,
        52.0,
        &format!("PRAETORE-MCP // {}", report.version),
    );
    if failed {
        c.rect(RED, 0.0, 96.0, PAGE_W, 5.0);
    }
    let tone = if failed { RED } else { ACCENT };
    c.line(tone, 0.6, 36.0, 128.0, 36.0, 790.0);
    c.line(tone, 1.2, 24.0, 116.0, 42.0, 116.0);
    c.line(tone, 1.2, 24.0, 116.0, 24.0, 134.0);
    c.line(tone, 1.2, 571.0, 818.0, 553.0, 818.0);
    c.line(tone, 1.2, 571.0, 818.0, 571.0, 800.0);

    if failed {
        c.label(RED, LEFT, 140.0, "INTEGRITY ALERT");
        c.text_spaced((Font::Sans, 30.0, 2.4), RED, LEFT, 178.0, "VERIFY FAILED");
        c.text_spaced((Font::Sans, 12.0, 2.0), INK, LEFT, 200.0, "SESSION REPORT");
    } else {
        c.label(ACCENT, LEFT, 140.0, "DOCUMENT TYPE");
        c.text_spaced((Font::Sans, 30.0, 2.4), INK, LEFT, 178.0, "SESSION REPORT");
    }
    let receipts = match report.rows.len() {
        1 => "1 RECEIPT".to_owned(),
        count => format!("{count} RECEIPTS"),
    };
    let seq = report.seq.map_or_else(
        || format!("NO CHAINED RECEIPTS ({receipts})"),
        |(first, last)| {
            let chained = report.rows.iter().filter(|row| row.seq.is_some()).count();
            let contiguous = usize::try_from(last - first + 1).ok() == Some(chained);
            format!(
                "SEQ {first} -> {last} ({receipts}{})",
                if contiguous { "" } else { ", NOT CONTIGUOUS" }
            )
        },
    );
    c.text(
        Font::Mono,
        8.5,
        MUTED,
        LEFT,
        if failed { 218.0 } else { 200.0 },
        &format!("ID {}  /  {seq}", report.meta.id.to_uppercase()),
    );
    ring(&mut c, report, 472.0, 178.0);

    let mut y = 262.0;
    if failed {
        let verify = &report.verify;
        let headline = if verify.journal_receipts == 0 && verify.failures_total > 0 {
            "The journal could not be verified.".to_owned()
        } else {
            format!(
                "{} problem(s) found. {} of {} receipts in the journal verified; {} of {} in this session.",
                verify.failures_total + verify.missing.len(),
                verify.journal_verified,
                verify.journal_receipts,
                verify.session_verified,
                verify.session_receipts
            )
        };
        c.text(Font::SansBold, 9.5, RED, LEFT, y, &headline);
        y += 13.0;
        c.text(
            Font::Sans,
            8.5,
            INK,
            LEFT,
            y,
            "Do not rely on these records until the journal is checked against an external copy of the heads.",
        );
        y += 14.0;
        let mut shown: Vec<String> = verify.failures.iter().take(4).cloned().collect();
        if !verify.missing.is_empty() {
            shown.insert(
                0,
                format!(
                    "{} receipt(s) of this session are no longer in the journal",
                    verify.missing.len()
                ),
            );
            shown.truncate(4);
        }
        for failure in &shown {
            let failure = failure.strip_prefix("FAIL ").unwrap_or(failure);
            c.text(
                Font::Mono,
                7.0,
                INK,
                LEFT,
                y,
                &fit(Font::Mono, 7.0, RIGHT - LEFT, failure),
            );
            y += 10.0;
        }
        let total = verify.failures_total + usize::from(!verify.missing.is_empty());
        if total > shown.len() {
            c.text(
                Font::Mono,
                7.0,
                MUTED,
                LEFT,
                y,
                &format!("... {} more in the JSON file", total - shown.len()),
            );
            y += 10.0;
        }
        y += 16.0;
    }

    let (opened, opened_utc) = local_and_utc(report.meta.started_at);
    let (closed, closed_utc) = local_and_utc(report.meta.ended_at);
    let columns = [LEFT, LEFT + 250.0];
    c.label(ACCENT, columns[0], y, "AGENT");
    c.text(
        Font::Mono,
        8.2,
        INK,
        columns[0],
        y + 12.0,
        &fit(Font::Mono, 8.2, 240.0, &report.agent),
    );
    c.label(ACCENT, columns[1], y, "SERVER");
    c.text(
        Font::Sans,
        9.5,
        INK,
        columns[1],
        y + 12.0,
        &fit(Font::Sans, 9.5, 130.0, &report.meta.server),
    );
    c.label(ACCENT, columns[1] + 150.0, y, "MODE");
    c.text(
        Font::Sans,
        9.5,
        INK,
        columns[1] + 150.0,
        y + 12.0,
        &ascii(&report.meta.mode),
    );
    y += 34.0;
    c.label(ACCENT, columns[0], y, "OPENED");
    c.text(Font::Sans, 9.5, INK, columns[0], y + 12.0, &opened);
    c.text(Font::Sans, 8.0, MUTED, columns[0], y + 23.0, &opened_utc);
    c.label(ACCENT, columns[1], y, "CLOSED");
    c.text(Font::Sans, 9.5, INK, columns[1], y + 12.0, &closed);
    c.text(Font::Sans, 8.0, MUTED, columns[1], y + 23.0, &closed_utc);
    y += 46.0;

    let s = &report.summary;
    c.label(ACCENT, LEFT, y, "DECISION SPECTRUM");
    y += 8.0;
    let parts = [
        (s.allow, GREEN),
        (s.deny + s.unreadable, RED),
        (s.held, AMBER),
        (s.forwarded, ACCENT),
        (s.would_ask, GRAY),
    ];
    let total: usize = parts.iter().map(|(count, _)| count).sum();
    let mut x = LEFT;
    for (count, color) in parts {
        if count == 0 || total == 0 {
            continue;
        }
        let w = (RIGHT - LEFT) * count as f32 / total as f32;
        c.rect(color, x, y, (w - 1.5).max(1.0), 7.0);
        x += w;
    }
    y += 24.0;
    // Two fixed rows on the same columns, every tile shown even at 0. The
    // first counts receipts, one decision per call; the second counts the
    // approval records of the held calls, a status and not another event.
    let decisions = [
        ("ALLOW", s.allow, GREEN),
        ("DENY", s.deny, RED),
        ("HELD", s.held, AMBER),
        ("FORWARDED", s.forwarded, ACCENT),
        ("WOULD ASK", s.would_ask, GRAY),
    ];
    let statuses = [
        ("APPROVED", s.approved, ACCENT),
        ("REJECTED", s.rejected, RED),
        ("PENDING", s.pending, AMBER),
        ("EXPIRED", s.expired, MUTED),
    ];
    let step = (RIGHT - LEFT) / decisions.len() as f32;
    let tile_row =
        |c: &mut Canvas, y: f32, title: &str, note: &str, tiles: &[(&str, usize, Rgb)]| {
            c.label(ACCENT, LEFT, y, title);
            c.text(
                Font::Sans,
                7.5,
                MUTED,
                LEFT + width(Font::Mono, 6.8, 1.1, title) + 10.0,
                y,
                note,
            );
            let y = y + 16.0;
            for (index, (name, count, color)) in tiles.iter().enumerate() {
                let x = LEFT + step * index as f32;
                c.diamond(*color, true, x + 3.0, y - 2.5, 3.0);
                c.label(MUTED, x + 11.0, y, name);
                c.text(Font::Sans, 20.0, INK, x, y + 24.0, &count.to_string());
            }
        };
    tile_row(
        &mut c,
        y,
        "DECISIONS",
        "one per call, from the signed receipts",
        &decisions,
    );
    y += 64.0;
    c.line(HAIR, 0.6, LEFT, y - 14.0, RIGHT, y - 14.0);
    tile_row(
        &mut c,
        y,
        "APPROVAL STATUS",
        "of the held calls, from the approval journal; not more calls",
        &statuses,
    );
    y += 66.0;
    if report.meta.mode == "observe" {
        c.text(
            Font::Sans,
            8.5,
            MUTED,
            LEFT,
            y,
            "Observe mode: decisions were recorded and not enforced.",
        );
        y += 16.0;
    }

    let none = "none".to_owned();
    let (label, value) = match &report.close_heads.receipt {
        Some((next, head)) => (
            format!("RECEIPT JOURNAL HEAD AT CLOSE // NEXT SEQ {next}"),
            head,
        ),
        None => ("RECEIPT JOURNAL HEAD AT CLOSE".to_owned(), &none),
    };
    block(&mut c, y, &label, value);
    y += 34.0;
    block(
        &mut c,
        y,
        "APPROVAL JOURNAL HEAD AT CLOSE",
        report.close_heads.approval.as_ref().unwrap_or(&none),
    );
    y += 34.0;
    block(
        &mut c,
        y,
        &format!("SHA-256 OF {}", report.json_name.to_uppercase()),
        &report.json_sha256,
    );
    y += 38.0;

    let (checked, checked_utc) = local_and_utc(report.verify.checked_at);
    c.label(tone, LEFT, y, "VERIFY");
    y += 13.0;
    let verdict = if report.verify.passed {
        format!(
            "Verify passed: {} of {} receipts in the journal verified; approval journal: {} decision(s), {} execution(s).",
            report.verify.journal_verified,
            report.verify.journal_receipts,
            report.verify.approval_decisions,
            report.verify.approval_executions
        )
    } else {
        "Verify failed: see the problems listed above and in the JSON file.".to_owned()
    };
    c.text(
        if failed { Font::SansBold } else { Font::Sans },
        8.8,
        if failed { RED } else { INK },
        LEFT,
        y,
        &verdict,
    );
    y += 12.0;
    let mut when = format!("Checked {checked}");
    if !checked_utc.is_empty() {
        when.push_str(&format!(" ({checked_utc})"));
    }
    if report.regenerated {
        when.push_str(". Regenerated from the journal; heads above are those recorded at close.");
    }
    c.text(Font::Sans, 8.0, MUTED, LEFT, y, &when);
    if let Some(from) = &report.regenerated_from {
        y += 11.0;
        c.text(
            Font::Mono,
            7.0,
            MUTED,
            LEFT,
            y,
            &fit(
                Font::Mono,
                7.0,
                RIGHT - LEFT,
                &format!("report written at close (not replaced): {from}"),
            ),
        );
    }
    if report.regenerated && report.verify.heads != report.close_heads {
        y += 11.0;
        let now = report
            .verify
            .heads
            .receipt
            .as_ref()
            .map_or("none", |(_, head)| head.as_str());
        c.text(
            Font::Mono,
            7.0,
            MUTED,
            LEFT,
            y,
            &format!("receipt journal head now: {now}"),
        );
    }

    c.line(HAIR, 0.5, LEFT, 742.0, RIGHT, 742.0);
    c.text(Font::SansBold, 8.8, INK, LEFT, 757.0, STATEMENT);
    c.text(
        Font::Sans,
        8.0,
        MUTED,
        LEFT,
        769.0,
        "This report is a view of the journal. It signs nothing and changes nothing.",
    );
    c
}

/// The pages after the cover: call log, then approvals.
struct Flow<'a> {
    report: &'a Report,
    pages: Vec<Canvas>,
    y: f32,
}

const COL_TIME: f32 = LEFT + 14.0;
const COL_TOOL: f32 = LEFT + 66.0;
const COL_DECISION: f32 = LEFT + 192.0;
const COL_RULE: f32 = LEFT + 256.0;
const COL_REASON: f32 = LEFT + 352.0;

impl<'a> Flow<'a> {
    fn new(report: &'a Report) -> Self {
        let mut flow = Self {
            report,
            pages: Vec::new(),
            y: 0.0,
        };
        flow.new_page();
        flow
    }

    fn canvas(&mut self) -> &mut Canvas {
        self.pages.last_mut().expect("a flow always has a page")
    }

    fn new_page(&mut self) {
        let mut c = Canvas::new();
        c.logo(false, LEFT - 6.0, 30.0, 24.0);
        c.text_right(
            Font::Mono,
            7.5,
            MUTED,
            RIGHT,
            46.0,
            &format!("SESSION {}", self.report.meta.id.to_uppercase()),
        );
        c.line(HAIR, 0.5, LEFT, 62.0, RIGHT, 62.0);
        c.line(ACCENT, 0.6, 36.0, 62.0, 36.0, 790.0);
        self.pages.push(c);
        self.y = 88.0;
    }

    /// Starts a section, with its column names, on the current page if at
    /// least two rows still fit below it.
    fn section(&mut self, title: &str, columns: &[(f32, &str)]) {
        if self.y + 22.0 + 2.0 * ROW_H > BODY_BOTTOM {
            self.new_page();
        }
        let y = self.y;
        let c = self.canvas();
        c.label(ACCENT, LEFT, y, title);
        for (x, name) in columns {
            c.label(MUTED, *x, y + 16.0, name);
        }
        c.line(HAIR, 0.5, LEFT, y + 21.0, RIGHT, y + 21.0);
        self.y = y + 34.0;
    }

    fn row_start(&mut self, title: &str, columns: &[(f32, &str)]) -> f32 {
        if self.y > BODY_BOTTOM {
            self.new_page();
            self.section(&format!("{title} (CONTINUED)"), columns);
        }
        let y = self.y;
        self.y += ROW_H;
        y
    }
}

const CALL_COLUMNS: [(f32, &str); 5] = [
    (COL_TIME, "TIME"),
    (COL_TOOL, "TOOL"),
    (COL_DECISION, "DECISION"),
    (COL_RULE, "RULE"),
    (COL_REASON, "REASON"),
];
const APPROVAL_COLUMNS: [(f32, &str); 5] = [
    (COL_TIME, "TIME"),
    (COL_TOOL, "TOOL"),
    (COL_DECISION, "OUTCOME"),
    (COL_RULE, "APPROVER KEY"),
    (COL_REASON, "WHEN / USE"),
];

fn call_row(c: &mut Canvas, y: f32, row: &Row) {
    let color = label_color(row.label);
    c.diamond(color, row.verified, LEFT + 4.0, y - 2.6, 3.0);
    time_cell(c, COL_TIME, y, row.decided_at);
    c.text(
        Font::Mono,
        7.8,
        INK,
        COL_TOOL,
        y,
        &fit(Font::Mono, 7.8, COL_DECISION - COL_TOOL - 8.0, &row.tool),
    );
    c.text(
        Font::SansBold,
        7.6,
        color,
        COL_DECISION,
        y,
        row.label.text(),
    );
    c.text(
        Font::Mono,
        7.2,
        MUTED,
        COL_RULE,
        y,
        &fit(Font::Mono, 7.2, COL_REASON - COL_RULE - 8.0, &row.rule),
    );
    let reason = if row.verified {
        row.reason.clone()
    } else {
        format!("NOT VERIFIED. {}", row.reason)
    };
    c.text(
        Font::Sans,
        7.6,
        if row.verified { INK } else { RED },
        COL_REASON,
        y,
        &fit(Font::Sans, 7.6, RIGHT - COL_REASON, &reason),
    );
    c.line(HAIR, 0.3, LEFT, y + ROW_RULE, RIGHT, y + ROW_RULE);
}

fn approval_row(c: &mut Canvas, y: f32, row: &ApprovalRow) {
    let color = match row.status {
        ApprovalStatus::Approved => ACCENT,
        ApprovalStatus::Rejected => RED,
        ApprovalStatus::Pending => AMBER,
        ApprovalStatus::Expired => MUTED,
    };
    c.diamond(color, false, LEFT + 4.0, y - 2.6, 3.0);
    // The time of the decision; an undecided approval has none.
    let decided = row.approver.as_ref().and(row.at);
    time_cell(c, COL_TIME, y, decided);
    c.text(
        Font::Mono,
        7.8,
        INK,
        COL_TOOL,
        y,
        &fit(Font::Mono, 7.8, COL_DECISION - COL_TOOL - 8.0, &row.tool),
    );
    c.text(
        Font::SansBold,
        7.6,
        color,
        COL_DECISION,
        y,
        row.status.text(),
    );
    let approver = row.approver.as_deref().map_or_else(
        || "no approver".to_owned(),
        |key| {
            let key = ascii(key);
            if key.len() > 16 {
                format!("{}..{}", &key[..12], &key[key.len() - 4..])
            } else {
                key
            }
        },
    );
    c.text(Font::Mono, 7.2, MUTED, COL_RULE, y, &approver);
    // What happened next, in local time, with UTC under it. The decision
    // time is in the TIME column.
    let (detail, at) = match (row.status, row.used_at) {
        (ApprovalStatus::Approved, Some(used)) if row.used_here => {
            (format!("used {}", local_clock(Some(used))), Some(used))
        }
        (ApprovalStatus::Approved, Some(_)) => ("used in another session".to_owned(), None),
        (ApprovalStatus::Approved, None) => ("not used".to_owned(), None),
        (ApprovalStatus::Rejected, _) => ("rejected".to_owned(), None),
        (ApprovalStatus::Pending, _) => (format!("expires {}", local_clock(row.at)), row.at),
        (ApprovalStatus::Expired, _) => (format!("expired {}", local_clock(row.at)), row.at),
    };
    c.text(
        Font::Sans,
        7.6,
        INK,
        COL_REASON,
        y,
        &fit(Font::Sans, 7.6, RIGHT - COL_REASON, &detail),
    );
    if at.is_some() {
        c.text(
            Font::Mono,
            5.8,
            MUTED,
            COL_REASON,
            y + ROW_SECOND,
            &utc_clock(at),
        );
    }
    c.line(HAIR, 0.3, LEFT, y + ROW_RULE, RIGHT, y + ROW_RULE);
}

fn log_pages(report: &Report) -> Vec<Canvas> {
    let mut flow = Flow::new(report);
    let title = format!("CALL LOG // {} ENTRIES", report.rows.len());
    flow.section(&title, &CALL_COLUMNS);
    for row in &report.rows {
        let y = flow.row_start("CALL LOG", &CALL_COLUMNS);
        call_row(flow.canvas(), y, row);
    }
    if report.rows.is_empty() {
        let y = flow.row_start("CALL LOG", &CALL_COLUMNS);
        flow.canvas().text(
            Font::Sans,
            8.5,
            MUTED,
            COL_TIME,
            y,
            "No receipt of this session is in the journal.",
        );
    }
    flow.y += 18.0;
    let title = format!("HUMAN APPROVALS // {}", report.approvals.len());
    flow.section(&title, &APPROVAL_COLUMNS);
    if let Some(error) = &report.approval_journal_error {
        let y = flow.row_start("HUMAN APPROVALS", &APPROVAL_COLUMNS);
        flow.canvas().text(
            Font::SansBold,
            8.0,
            RED,
            COL_TIME,
            y,
            &fit(
                Font::SansBold,
                8.0,
                RIGHT - COL_TIME,
                &format!("The approval journal could not be read: {error}"),
            ),
        );
    }
    for row in &report.approvals {
        let y = flow.row_start("HUMAN APPROVALS", &APPROVAL_COLUMNS);
        approval_row(flow.canvas(), y, row);
    }
    if report.approvals.is_empty() && report.approval_journal_error.is_none() {
        let y = flow.row_start("HUMAN APPROVALS", &APPROVAL_COLUMNS);
        flow.canvas().text(
            Font::Sans,
            8.5,
            MUTED,
            COL_TIME,
            y,
            "No approval record for this session.",
        );
    }
    flow.y += 10.0;
    if flow.y + 24.0 <= BODY_BOTTOM {
        let y = flow.y;
        let c = flow.canvas();
        c.text(
            Font::Sans,
            7.4,
            MUTED,
            LEFT,
            y,
            "A filled marker is a receipt that verify counted as verified. The approver is the id of the local key that signed the decision,",
        );
        c.text(
            Font::Sans,
            7.4,
            MUTED,
            LEFT,
            y + 10.0,
            "not proof that a person reviewed the call.",
        );
    }
    flow.pages
}

fn footer(canvas: &mut Canvas, report: &Report, page: usize, pages: usize) {
    let (generated, generated_utc) = local_and_utc(report.generated_at);
    let mut left = format!("GENERATED {generated}");
    if !generated_utc.is_empty() {
        left.push_str(&format!(" ({generated_utc})"));
    }
    if page > 1 {
        let zone = local_offset(report.meta.started_at)
            .map_or_else(|| "UTC".to_owned(), |o| stamp(report.meta.started_at, o).2);
        left = format!("TIME COLUMN IN LOCAL TIME ({zone})");
    }
    canvas.text(Font::Mono, 6.8, MUTED, LEFT, 806.0, &left);
    canvas.text_right(
        Font::Mono,
        6.8,
        MUTED,
        RIGHT,
        806.0,
        &format!("{page:02} / {pages:02}"),
    );
}

/// The whole document.
pub fn render(report: &Report) -> Vec<u8> {
    let mut canvases = vec![cover(report)];
    canvases.extend(log_pages(report));
    let total = canvases.len();
    for (index, canvas) in canvases.iter_mut().enumerate() {
        footer(canvas, report, index + 1, total);
    }

    let mut next = 1;
    let mut alloc = || {
        let id = Ref::new(next);
        next += 1;
        id
    };
    let catalog = alloc();
    let tree = alloc();
    let info = alloc();
    let fonts = Font::ALL.map(|font| (font, alloc()));
    let mask = alloc();
    let logo_white = alloc();
    let logo_black = alloc();
    let pages: Vec<(Ref, Ref)> = canvases.iter().map(|_| (alloc(), alloc())).collect();

    let mut pdf = Pdf::new();
    pdf.catalog(catalog).pages(tree);
    pdf.pages(tree)
        .kids(pages.iter().map(|(page, _)| *page))
        .count(total as i32);
    pdf.document_info(info)
        .title(TextStr(&format!(
            "praetore-mcp session report {}",
            report.meta.id
        )))
        .producer(TextStr(&format!("praetore-mcp {}", report.version)));
    for (font, id) in fonts {
        pdf.type1_font(id)
            .base_font(font.base())
            .encoding_predefined(Name(b"WinAnsiEncoding"));
    }
    let mut image = pdf.image_xobject(mask, LOGO_JPEG);
    image.filter(Filter::DctDecode);
    image.width(LOGO_WIDTH).height(LOGO_HEIGHT);
    image.color_space().device_gray();
    image.bits_per_component(8);
    image.finish();
    for (id, pixel) in [(logo_white, [255u8]), (logo_black, [18u8])] {
        let mut image = pdf.image_xobject(id, &pixel);
        image.width(1).height(1);
        image.color_space().device_gray();
        image.bits_per_component(8);
        image.s_mask(mask);
        image.finish();
    }
    for ((page_id, content_id), canvas) in pages.iter().zip(canvases) {
        let mut page = pdf.page(*page_id);
        page.media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H));
        page.parent(tree);
        page.contents(*content_id);
        let mut resources = page.resources();
        let mut font_dict = resources.fonts();
        for (font, id) in fonts {
            font_dict.pair(font.resource(), id);
        }
        font_dict.finish();
        let mut x_objects = resources.x_objects();
        x_objects.pair(Name(b"LogoW"), logo_white);
        x_objects.pair(Name(b"LogoK"), logo_black);
        x_objects.finish();
        resources.finish();
        page.finish();
        pdf.stream(*content_id, &canvas.content.finish());
    }
    pdf.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_reduced_to_printable_ascii() {
        assert_eq!(ascii("read_file"), "read_file");
        assert_eq!(ascii("a\u{202e}b"), "a\\u{202e}b");
        assert!(ascii("PR\u{c6}TOR \u{1f600}").is_ascii());
    }

    #[test]
    fn fit_cuts_to_the_width_and_marks_the_cut() {
        let short = fit(Font::Mono, 8.0, 200.0, "echo");
        assert_eq!(short, "echo");
        let cut = fit(Font::Mono, 8.0, 48.0, "a_very_long_tool_name");
        assert!(cut.ends_with("..."), "{cut}");
        assert!(width(Font::Mono, 8.0, 0.0, &cut) <= 48.0);
    }

    fn sample(rows: usize, passed: bool) -> Report {
        use crate::report::{Heads, SessionMeta, Summary, VerifyOutcome};
        let at = OffsetDateTime::from_unix_timestamp(1_794_000_000).unwrap();
        Report {
            version: "0.0.0",
            meta: SessionMeta {
                id: "a41f9c2e".into(),
                server: "fake".into(),
                mode: "enforce".into(),
                started_at: at,
                ended_at: at,
            },
            agent: "agent".into(),
            generated_at: at,
            regenerated: false,
            regenerated_from: None,
            approval_journal_error: None,
            rows: (0..rows)
                .map(|index| Row {
                    seq: Some(index as u64),
                    evidence_id: format!("id-{index}"),
                    decided_at: Some(at),
                    tool: format!("tool_{index}"),
                    label: Label::Allow,
                    rule: "allow-all".into(),
                    reason: "Rule matched".into(),
                    verified: passed,
                })
                .collect(),
            approvals: Vec::new(),
            summary: Summary {
                allow: rows,
                ..Summary::default()
            },
            seq: None,
            close_heads: Heads::default(),
            verify: VerifyOutcome {
                passed,
                checked_at: at,
                journal_receipts: rows,
                journal_verified: if passed { rows } else { 0 },
                failures_total: usize::from(!passed),
                failures: Vec::new(),
                session_receipts: rows,
                session_verified: if passed { rows } else { 0 },
                missing: Vec::new(),
                heads: Heads::default(),
                approval_decisions: 0,
                approval_executions: 0,
            },
            json_name: "session-x.json".into(),
            json_sha256: "00".repeat(32),
        }
    }

    fn count(bytes: &[u8], needle: &[u8]) -> usize {
        bytes.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[test]
    fn a_long_session_continues_on_more_pages_and_keeps_every_row() {
        let pdf = render(&sample(200, true));
        assert!(pdf.starts_with(b"%PDF-"));
        assert!(count(&pdf, b"/Type /Page\n") + count(&pdf, b"/Type /Page ") >= 6);
        assert!(count(&pdf, b"CONTINUED") >= 4);
        for index in [0, 99, 199] {
            assert_eq!(count(&pdf, format!("(tool_{index})").as_bytes()), 1);
        }
        assert_eq!(count(&pdf, b"VERIFY FAILED"), 0);
    }

    #[test]
    fn an_empty_or_failed_report_still_renders() {
        let failed = render(&sample(0, false));
        assert_eq!(count(&failed, b"(VERIFY FAILED)"), 1);
        assert_eq!(count(&failed, STATEMENT.as_bytes()), 1);
    }

    #[test]
    fn a_backslash_in_a_tool_name_is_escaped_once() {
        let mut report = sample(1, true);
        report.rows[0].tool = "a\\b".into();
        let pdf = render(&report);
        // ascii() writes the display escape `a\\b`; the PDF string escapes
        // each `\` once more, so the bytes hold four, never eight.
        assert!(count(&pdf, b"(a\\\\\\\\b)") >= 1);
        assert_eq!(count(&pdf, b"a\\\\\\\\\\\\\\\\b"), 0, "escaped twice");
        assert_eq!(printable("x\\y"), "x\\y");
        assert_eq!(printable("caf\u{e9}"), "caf?");
    }

    #[test]
    fn rows_show_local_time_with_utc_under_it() {
        let report = sample(1, true);
        let pdf = render(&report);
        let at = report.rows[0].decided_at.unwrap();
        let utc = format!("({})", utc_clock(Some(at)));
        assert!(count(&pdf, utc.as_bytes()) >= 1, "{utc}");
        assert!(count(&pdf, format!("({})", local_clock(Some(at))).as_bytes()) >= 1);
    }

    #[test]
    fn the_cover_counts_receipts_and_says_when_seq_is_not_contiguous() {
        let mut report = sample(3, true);
        report.seq = Some((0, 2));
        assert_eq!(count(&render(&report), b"SEQ 0 -> 2 (3 RECEIPTS)"), 1);
        report.rows[2].seq = Some(7);
        report.seq = Some((0, 7));
        assert_eq!(
            count(&render(&report), b"SEQ 0 -> 7 (3 RECEIPTS, NOT CONTIGUOUS)"),
            1
        );
        // One receipt is RECEIPT, with seq or without.
        let mut one = sample(1, true);
        one.seq = Some((4, 4));
        let pdf = render(&one);
        assert_eq!(count(&pdf, b"SEQ 4 -> 4 (1 RECEIPT)"), 1);
        assert_eq!(count(&pdf, b"1 RECEIPTS"), 0);
        one.seq = None;
        one.rows[0].seq = None;
        let pdf = render(&one);
        assert_eq!(count(&pdf, b"NO CHAINED RECEIPTS (1 RECEIPT)"), 1);
        assert_eq!(count(&pdf, b"1 RECEIPTS"), 0);
    }

    #[test]
    fn a_failed_verify_labels_the_ring_this_session_and_grays_good_receipts() {
        let passed = render(&sample(2, true));
        assert_eq!(count(&passed, b"(THIS SESSION)"), 0);
        let mut failed = sample(2, false);
        failed.rows.iter_mut().for_each(|row| row.verified = true);
        failed.verify.session_verified = 2;
        let pdf = render(&failed);
        assert_eq!(count(&pdf, b"(THIS SESSION)"), 1);
        // GRAY as the stroke color of the ring segments, never GREEN there.
        let gray = format!("{} {} {} RG", GRAY.0, GRAY.1, GRAY.2);
        assert!(count(&pdf, gray.as_bytes()) >= 2, "no gray segment");
    }

    #[test]
    fn decisions_and_approval_statuses_are_two_fixed_rows_with_zeros() {
        // Every tile at 0: all nine are drawn, in two labeled rows.
        let report = sample(0, true);
        let pdf = render(&report);
        for name in [
            "ALLOW",
            "DENY",
            "HELD",
            "FORWARDED",
            "WOULD ASK",
            "APPROVED",
            "REJECTED",
            "PENDING",
            "EXPIRED",
        ] {
            assert_eq!(count(&pdf, format!("({name})").as_bytes()), 1, "{name}");
        }
        assert_eq!(count(&pdf, b"(DECISIONS)"), 1);
        assert_eq!(count(&pdf, b"(APPROVAL STATUS)"), 1);
        assert_eq!(
            count(
                &pdf,
                b"(of the held calls, from the approval journal; not more calls)"
            ),
            1
        );
        // HELD is in the first row, PENDING in the second: PENDING is drawn
        // lower on the page (a smaller y in PDF space) at the same x as HELD.
        let at = |name: &str| -> (f32, f32) {
            let text = String::from_utf8_lossy(&pdf).into_owned();
            let end = text.find(&format!("({name}) Tj")).unwrap();
            let line = text[..end].rsplit(" Td").next().unwrap();
            let before = &text[..end - line.len() - 3];
            let numbers: Vec<f32> = before
                .rsplit('\n')
                .next()
                .unwrap()
                .split_whitespace()
                .filter_map(|n| n.parse().ok())
                .collect();
            (numbers[numbers.len() - 2], numbers[numbers.len() - 1])
        };
        let (held, pending) = (at("HELD"), at("PENDING"));
        assert!((held.0 - pending.0).abs() < 0.01, "{held:?} {pending:?}");
        assert!(pending.1 < held.1, "{held:?} {pending:?}");
    }

    #[test]
    fn an_unreadable_approval_journal_is_said_in_the_pdf() {
        let mut report = sample(1, true);
        report.approval_journal_error = Some("approvals/journal.jsonl:1: not JSON".into());
        let pdf = render(&report);
        assert_eq!(
            count(
                &pdf,
                b"The approval journal could not be read: approvals/journal.jsonl:1: not JSON"
            ),
            1
        );
        assert_eq!(count(&pdf, b"No approval record for this session."), 0);
    }

    #[test]
    fn the_wordmark_is_a_gray_jpeg_of_the_declared_size() {
        assert_eq!(&LOGO_JPEG[..3], &[0xff, 0xd8, 0xff]);
        // Baseline frame header: height, width, one component.
        let sof = LOGO_JPEG
            .windows(2)
            .position(|w| w == [0xff, 0xc0])
            .expect("baseline JPEG");
        let frame = &LOGO_JPEG[sof + 5..sof + 10];
        assert_eq!(
            i32::from(u16::from_be_bytes([frame[0], frame[1]])),
            LOGO_HEIGHT
        );
        assert_eq!(
            i32::from(u16::from_be_bytes([frame[2], frame[3]])),
            LOGO_WIDTH
        );
        assert_eq!(frame[4], 1, "one gray component");
    }
}
