//! Randomized differential campaign over the cross-session device history
//! (`bleradar_core::History`).
//!
//! A deterministic PRNG drives random sightings (valid and invalid keys, a
//! clock that mostly advances but sometimes jumps back, persist/reload cycles
//! through `serialize`/`parse`, and byte-level corruption of the persisted
//! text) against an independent reference model, and asserts after every step:
//!
//! * **agreement** — every remembered record equals the reference's, and the
//!   remembered key set equals the reference's (the key pool stays under
//!   capacity, so no eviction applies);
//! * **record invariants** — `visits ≥ 1` and `first_seen ≤ last_seen`;
//! * **round trip** — `parse(serialize(h)) == h`, and re-serializing is a
//!   fixed point;
//! * **corruption is contained** — parsing a damaged document never panics
//!   and never yields a record that violates the invariants. (The format has
//!   no checksum: a substituted hex digit is a different, valid public key,
//!   so the damaged key set is deliberately not compared with the original.)
//!
//! `BLERADAR_HISTORY_CAMPAIGN_STEPS` scales the run.

use std::collections::BTreeMap;

use bleradar_core::{HISTORY_VISIT_GAP_MS, History, HistoryRecord, is_history_key};

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
}

/// The reference: the documented rules restated independently.
fn reference_observe(model: &mut BTreeMap<String, HistoryRecord>, key: &str, now: u64) {
    let public = key.len() == 17
        && key.bytes().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                b == b':'
            } else {
                matches!(b, b'0'..=b'9' | b'a'..=b'f')
            }
        })
        && key != "00:00:00:00:00:00"
        && key != "ff:ff:ff:ff:ff:ff"
        && u8::from_str_radix(&key[..2], 16).is_ok_and(|o| o & 0x02 == 0);
    if !public {
        return;
    }
    let r = model.entry(key.to_string()).or_insert(HistoryRecord {
        first_seen_ms: now,
        last_seen_ms: now,
        visits: 0,
    });
    if r.visits == 0 {
        r.visits = 1;
        return;
    }
    if now > r.last_seen_ms {
        if now - r.last_seen_ms > HISTORY_VISIT_GAP_MS {
            r.visits += 1;
        }
        r.last_seen_ms = now;
    }
    if now < r.first_seen_ms {
        r.first_seen_ms = now;
    }
}

fn key_pool(rng: &mut Rng) -> Vec<String> {
    let mut pool = Vec::new();
    for _ in 0..40 {
        let octets: Vec<String> = (0..6).map(|_| format!("{:02x}", rng.below(256))).collect();
        pool.push(octets.join(":"));
    }
    pool.push("00:00:00:00:00:00".into());
    pool.push("ff:ff:ff:ff:ff:ff".into());
    pool.push("3C:5A:B4:11:22:01".into());
    pool.push("p[s:feaa/7]|s[feaa]".into());
    pool.push(String::new());
    pool
}

fn check_invariants(h: &History, context: &str) {
    let text = h.serialize();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "{context}: {line:?}");
        assert!(is_history_key(fields[0]), "{context}: {line:?}");
        let first: u64 = fields[1].parse().unwrap();
        let last: u64 = fields[2].parse().unwrap();
        let visits: u32 = fields[3].parse().unwrap();
        assert!(visits >= 1 && first <= last, "{context}: {line:?}");
    }
    let back = History::parse(&text);
    assert_eq!(&back, h, "{context}: round trip");
    assert_eq!(back.serialize(), text, "{context}: fixed point");
}

#[test]
fn history_agrees_with_the_reference_and_survives_corruption() {
    let steps: u64 = std::env::var("BLERADAR_HISTORY_CAMPAIGN_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let mut rng = Rng::new(0x5eed_4157_0e1d);
    let pool = key_pool(&mut rng);
    let mut history = History::new();
    let mut model: BTreeMap<String, HistoryRecord> = BTreeMap::new();
    let mut now: u64 = 1_700_000_000_000;
    let mut corruptions = 0u64;

    for step in 0..steps {
        match rng.below(100) {
            // Clock: mostly small advances, sometimes past the visit gap,
            // occasionally backwards.
            0..=69 => now = now.saturating_add(rng.below(90_000)),
            70..=84 => now = now.saturating_add(HISTORY_VISIT_GAP_MS + rng.below(600_000)),
            85..=89 => now = now.saturating_sub(rng.below(3_600_000)),
            _ => {}
        }
        let key = &pool[rng.below(pool.len() as u64) as usize];
        history.observe(key, now);
        reference_observe(&mut model, key, now);

        if rng.below(50) == 0 {
            // Persist and reload, as a process restart does.
            history = History::parse(&history.serialize());
        }
        if rng.below(200) == 0 {
            // Corrupt a persisted copy: flip, drop, or truncate bytes.
            let original = history.serialize();
            let mut bytes = original.clone().into_bytes();
            for _ in 0..=rng.below(4) {
                if bytes.is_empty() {
                    break;
                }
                let at = rng.below(bytes.len() as u64) as usize;
                match rng.below(3) {
                    0 => bytes[at] = rng.below(128) as u8,
                    1 => {
                        bytes.remove(at);
                    }
                    _ => bytes.truncate(at),
                }
            }
            let damaged = History::parse(&String::from_utf8_lossy(&bytes));
            check_invariants(&damaged, &format!("step {step} corrupted"));
            corruptions += 1;
        }

        if step % 97 == 0 || step + 1 == steps {
            let remembered: Vec<(String, HistoryRecord)> = pool
                .iter()
                .filter_map(|k| history.get(k).map(|r| (k.clone(), r)))
                .collect();
            let expected: Vec<(String, HistoryRecord)> = pool
                .iter()
                .filter_map(|k| model.get(k).map(|r| (k.clone(), *r)))
                .collect();
            assert_eq!(remembered, expected, "step {step}: disagreement");
            assert_eq!(history.len(), model.len(), "step {step}: key set");
            check_invariants(&history, &format!("step {step}"));
        }
    }
    assert!(corruptions > 0 && !model.is_empty());
}

/// The campaign's agreement check is sensitive: a history that counts every
/// sighting as a visit disagrees with the reference.
#[test]
fn the_reference_catches_a_visit_count_mutant() {
    let mut model = BTreeMap::new();
    let key = "3c:5a:b4:11:22:01";
    reference_observe(&mut model, key, 0);
    reference_observe(&mut model, key, 1);
    // One visit, where a mutant counting sightings would say two.
    assert_eq!(model[key].visits, 1);
    let mut h = History::new();
    h.observe(key, 0);
    h.observe(key, 1);
    assert_eq!(h.get(key).unwrap(), model[key]);
}
