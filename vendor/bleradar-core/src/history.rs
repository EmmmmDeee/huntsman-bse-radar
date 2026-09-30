//! Cross-session device history: when a device was first and last seen, and on
//! how many separate visits — the persistent "seen before?" memory BlueHydra
//! keeps, owned here so the app, its tests and every future caller share one
//! rule set.
//!
//! The store is a plain, versioned text document the app writes to its private
//! files directory and reads back on the next start, so the history survives a
//! process kill, a reboot and an app upgrade. Every rule is pure and total:
//!
//! * Only **stable** keys are remembered: [`is_history_key`] accepts a
//!   canonical lowercase public MAC (`aa:bb:cc:dd:ee:ff`). A randomized
//!   address rotates within minutes, so remembering it would only fill the
//!   store with one-time identifiers, and an advertisement-shape key is shared
//!   by every unit of a model, so remembering it would merge different devices.
//! * A sighting more than [`VISIT_GAP_MS`] after the previous one starts a new
//!   **visit**; sightings within the gap extend the current one. A clock that
//!   runs backwards never moves `last_seen` back and never counts a visit.
//! * The store is bounded ([`MAX_ENTRIES`]): past the bound the entries seen
//!   longest ago are evicted, oldest first (ties by key), so a long-running
//!   install cannot grow without limit.
//! * [`History::parse`] never fails: a document with a wrong header yields an
//!   empty history, and a malformed line is skipped (and counted in
//!   [`History::rejected_lines`]) instead of discarding the good lines around
//!   it — a torn or corrupted file costs only what is actually damaged.
//! * [`History::serialize`] is canonical (sorted by key), so
//!   `parse(serialize(h)) == h` and re-serializing is a fixed point.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// First line of every serialized history; the version gates the line format.
pub const HISTORY_HEADER: &str = "bleradar-history v1";

/// A sighting later than this after the previous one begins a new visit
/// (5 minutes: longer than a scan pause or a walk out of range and back,
/// shorter than leaving and returning).
pub const VISIT_GAP_MS: u64 = 5 * 60 * 1000;

/// The most devices the store remembers.
pub const MAX_ENTRIES: usize = 2048;

/// What the store remembers about one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryRecord {
    /// Wall-clock milliseconds of the first sighting ever recorded.
    pub first_seen_ms: u64,
    /// Wall-clock milliseconds of the most recent sighting.
    pub last_seen_ms: u64,
    /// Separate visits (sightings more than [`VISIT_GAP_MS`] apart), ≥ 1.
    pub visits: u32,
}

/// Whether `key` is one the history remembers: a canonical, lowercase,
/// colon-separated MAC whose first octet is not locally administered (a
/// public, followable address), and not the all-zero / broadcast placeholder.
#[must_use]
pub fn is_history_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        let ok = if i % 3 == 2 {
            b == b':'
        } else {
            b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
        };
        if !ok {
            return false;
        }
    }
    if key == "00:00:00:00:00:00" || key == "ff:ff:ff:ff:ff:ff" {
        return false;
    }
    // Second hex digit of the first octet carries the U/L bit (0x02).
    let first_octet = u8::from_str_radix(&key[0..2], 16).unwrap_or(0x02);
    first_octet & 0x02 == 0
}

/// The persistent device history. Two histories are equal when they remember
/// the same devices; the parse diagnostic [`History::rejected_lines`] is not
/// part of what is remembered.
#[derive(Debug, Clone, Default)]
pub struct History {
    entries: BTreeMap<String, HistoryRecord>,
    rejected_lines: usize,
}

impl PartialEq for History {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for History {}

impl History {
    /// An empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a serialized history. Never fails: a missing or unknown header
    /// yields an empty history; a malformed line is skipped and counted.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut history = Self::new();
        let mut lines = text.lines();
        if lines.next().map(str::trim_end) != Some(HISTORY_HEADER) {
            return history;
        }
        for line in lines {
            if line.is_empty() {
                continue;
            }
            match parse_line(line) {
                Some((key, record)) => {
                    // A duplicate key keeps the merged, widest view of both.
                    history
                        .entries
                        .entry(key)
                        .and_modify(|existing| *existing = merge_records(*existing, record))
                        .or_insert(record);
                }
                None => history.rejected_lines += 1,
            }
        }
        history.enforce_capacity();
        history
    }

    /// The canonical serialization: the header, then one
    /// `key\tfirst_seen_ms\tlast_seen_ms\tvisits` line per device, sorted by key.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = String::with_capacity(20 + self.entries.len() * 48);
        out.push_str(HISTORY_HEADER);
        out.push('\n');
        for (key, record) in &self.entries {
            let _ = writeln!(
                out,
                "{key}\t{}\t{}\t{}",
                record.first_seen_ms, record.last_seen_ms, record.visits
            );
        }
        out
    }

    /// Records a sighting of `key` at `now_ms`. Returns whether it was
    /// recorded (`false` for a key [`is_history_key`] rejects).
    pub fn observe(&mut self, key: &str, now_ms: u64) -> bool {
        if !is_history_key(key) {
            return false;
        }
        match self.entries.get_mut(key) {
            Some(record) => {
                if now_ms > record.last_seen_ms {
                    if now_ms - record.last_seen_ms > VISIT_GAP_MS {
                        record.visits = record.visits.saturating_add(1);
                    }
                    record.last_seen_ms = now_ms;
                }
                record.first_seen_ms = record.first_seen_ms.min(now_ms);
            }
            None => {
                self.entries.insert(
                    key.to_string(),
                    HistoryRecord {
                        first_seen_ms: now_ms,
                        last_seen_ms: now_ms,
                        visits: 1,
                    },
                );
                self.enforce_capacity();
            }
        }
        true
    }

    /// What the history remembers about `key`, if anything.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<HistoryRecord> {
        self.entries.get(key).copied()
    }

    /// How many devices are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no device is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lines [`History::parse`] skipped as malformed.
    #[must_use]
    pub fn rejected_lines(&self) -> usize {
        self.rejected_lines
    }

    /// Evicts the entries seen longest ago (ties by key) until the store is
    /// within [`MAX_ENTRIES`].
    fn enforce_capacity(&mut self) {
        let excess = self.entries.len().saturating_sub(MAX_ENTRIES);
        if excess == 0 {
            return;
        }
        let mut by_age: Vec<(u64, String)> = self
            .entries
            .iter()
            .map(|(key, record)| (record.last_seen_ms, key.clone()))
            .collect();
        by_age.sort_unstable();
        for (_, key) in by_age.into_iter().take(excess) {
            self.entries.remove(&key);
        }
    }
}

fn merge_records(a: HistoryRecord, b: HistoryRecord) -> HistoryRecord {
    HistoryRecord {
        first_seen_ms: a.first_seen_ms.min(b.first_seen_ms),
        last_seen_ms: a.last_seen_ms.max(b.last_seen_ms),
        visits: a.visits.max(b.visits),
    }
}

fn parse_line(line: &str) -> Option<(String, HistoryRecord)> {
    let mut fields = line.split('\t');
    let key = fields.next()?;
    let first_seen_ms = parse_decimal(fields.next()?)?;
    let last_seen_ms = parse_decimal(fields.next()?)?;
    let visits = u32::try_from(parse_decimal(fields.next()?)?).ok()?;
    if fields.next().is_some()
        || !is_history_key(key)
        || visits == 0
        || first_seen_ms > last_seen_ms
    {
        return None;
    }
    Some((
        key.to_string(),
        HistoryRecord {
            first_seen_ms,
            last_seen_ms,
            visits,
        },
    ))
}

/// Strict unsigned decimal: digits only, no sign, no whitespace, fits `u64`.
fn parse_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Records every newline-separated key in `keys` at `now_ms` into the history
/// serialized as `state` (anything unparseable starts empty) and returns the
/// new serialization — the single call the app makes per flush.
#[must_use]
pub fn history_merge(state: &str, keys: &str, now_ms: u64) -> String {
    let mut history = History::parse(state);
    for key in keys.lines() {
        history.observe(key.trim(), now_ms);
    }
    history.serialize()
}

/// For each newline-separated key in `keys`, in order, one line
/// `first_seen_ms\tvisits` when the history serialized as `state` remembers
/// it, or an empty line when it does not.
#[must_use]
pub fn history_lookup(state: &str, keys: &str) -> String {
    let history = History::parse(state);
    let mut out = String::new();
    for key in keys.lines() {
        if let Some(record) = history.get(key.trim()) {
            let _ = write!(out, "{}\t{}", record.first_seen_ms, record.visits);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "3c:5a:b4:11:22:01";
    const B: &str = "00:1a:7d:da:71:13";

    #[test]
    fn only_canonical_public_macs_are_history_keys() {
        assert!(is_history_key(A));
        assert!(is_history_key(B));
        for rejected in [
            "",
            "3C:5A:B4:11:22:01",           // not canonical lowercase
            "3c-5a-b4-11-22-01",           // wrong separator
            "3c:5a:b4:11:22",              // short
            "3c:5a:b4:11:22:01:00",        // long
            "3g:5a:b4:11:22:01",           // not hex
            "aa:bb:cc:dd:ee:02",           // locally administered (0xaa & 0x02)
            "02:00:00:00:00:01",           // locally administered
            "00:00:00:00:00:00",           // placeholder
            "ff:ff:ff:ff:ff:ff",           // broadcast
            "p[s:feaa/7]|s[feaa]",         // advertisement-shape key
            "3c:5a:b4:11:22:01\tinjected", // separator injection
        ] {
            assert!(!is_history_key(rejected), "{rejected:?}");
        }
    }

    #[test]
    fn visits_count_gaps_not_sightings() {
        let mut h = History::new();
        assert!(h.observe(A, 1_000));
        assert!(h.observe(A, 1_000 + VISIT_GAP_MS)); // exactly the gap: same visit
        assert_eq!(h.get(A).unwrap().visits, 1);
        assert!(h.observe(A, 1_001 + 2 * VISIT_GAP_MS)); // past the gap: new visit
        let r = h.get(A).unwrap();
        assert_eq!(
            (r.first_seen_ms, r.last_seen_ms, r.visits),
            (1_000, 1_001 + 2 * VISIT_GAP_MS, 2)
        );
    }

    #[test]
    fn a_backward_clock_never_rewinds_or_counts_a_visit() {
        let mut h = History::new();
        h.observe(A, 10 * VISIT_GAP_MS);
        h.observe(A, 1); // clock jumped back
        let r = h.get(A).unwrap();
        assert_eq!(r.last_seen_ms, 10 * VISIT_GAP_MS);
        assert_eq!(r.first_seen_ms, 1);
        assert_eq!(r.visits, 1);
    }

    #[test]
    fn rejected_keys_are_not_remembered() {
        let mut h = History::new();
        assert!(!h.observe("aa:bb:cc:dd:ee:02", 5));
        assert!(h.is_empty());
    }

    #[test]
    fn serialization_round_trips_and_is_canonical() {
        let mut h = History::new();
        h.observe(A, 7);
        h.observe(B, 3);
        h.observe(A, 7 + VISIT_GAP_MS + 1);
        let text = h.serialize();
        assert_eq!(
            text,
            format!(
                "{HISTORY_HEADER}\n{B}\t3\t3\t1\n{A}\t7\t{}\t2\n",
                7 + VISIT_GAP_MS + 1
            )
        );
        let back = History::parse(&text);
        assert_eq!(back, h);
        assert_eq!(back.serialize(), text);
    }

    #[test]
    fn corruption_costs_only_the_damaged_lines() {
        let text = format!(
            "{HISTORY_HEADER}\n{A}\t1\t2\t1\ngarbage\n{B}\t5\t4\t1\n{B}\t1\t2\t0\n\
             {B}\t-1\t2\t1\n{B}\t1\t2\t1\textra\n{B}\t1\t2\t99999999999\n{B}\t1\t9\t3"
        );
        let h = History::parse(&text);
        assert_eq!(h.len(), 2);
        assert_eq!(h.rejected_lines(), 6);
        assert_eq!(h.get(B).unwrap().visits, 3); // a torn final line without \n is kept
    }

    #[test]
    fn a_wrong_or_missing_header_yields_an_empty_history() {
        for text in [
            "",
            "bleradar-history v2\n3c:5a:b4:11:22:01\t1\t1\t1\n",
            "3c:5a:b4:11:22:01\t1\t1\t1\n",
        ] {
            assert!(History::parse(text).is_empty(), "{text:?}");
        }
    }

    #[test]
    fn duplicate_lines_merge_to_the_widest_view() {
        let text = format!("{HISTORY_HEADER}\n{A}\t5\t10\t2\n{A}\t3\t8\t4\n");
        let r = History::parse(&text).get(A).unwrap();
        assert_eq!((r.first_seen_ms, r.last_seen_ms, r.visits), (3, 10, 4));
    }

    #[test]
    fn capacity_evicts_the_longest_unseen_first() {
        let mut h = History::new();
        for i in 0..=MAX_ENTRIES {
            let key = format!("00:00:00:00:{:02x}:{:02x}", (i >> 8) & 0xff, i & 0xff);
            let key = if i == 0 {
                "00:00:00:01:00:00".to_string()
            } else {
                key
            };
            h.observe(&key, 1_000 + i as u64);
        }
        assert_eq!(h.len(), MAX_ENTRIES);
        assert!(
            h.get("00:00:00:01:00:00").is_none(),
            "the oldest is evicted"
        );
        assert!(h.get("00:00:00:00:08:00").is_some(), "the newest is kept");
    }

    #[test]
    fn merge_and_lookup_are_the_app_contract() {
        let state = history_merge("", &format!("{A}\n{B}\naa:bb:cc:dd:ee:02\n"), 100);
        let state = history_merge(&state, A, 100 + VISIT_GAP_MS + 1);
        assert_eq!(
            history_lookup(&state, &format!("{A}\naa:bb:cc:dd:ee:02\n{B}")),
            "100\t2\n\n100\t1\n"
        );
        // An unparseable state starts over instead of failing.
        assert_eq!(
            history_lookup(&history_merge("not a history", A, 9), A),
            "9\t1\n"
        );
    }
}
