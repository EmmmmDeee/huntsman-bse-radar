//! Bounds-checked, panic-free decoder for BLE advertising / scan-response
//! payloads — the capability nRF Connect, LightBlue and Beacon-Scanner-class
//! apps provide, owned here in safe Rust.
//!
//! The input is the raw GAP advertising data: a sequence of length-tagged AD
//! structures (Core Specification Supplement, "AD" = advertising data). Each
//! structure is `[length][type][payload…]` where `length` counts `type` plus
//! `payload`. Radio data is attacker-controllable and routinely malformed
//! (truncated payloads, lengths that run past the buffer, zero-length padding),
//! so every read is bounds-checked and the parser can never panic — proven by
//! the `adv_campaign` differential/robustness campaign, which throws millions
//! of random and mutated byte strings at it.
//!
//! What is decoded (assigned numbers, little-endian on the wire, rendered
//! big-endian canonical):
//! - Flags (`0x01`)
//! - 16/32/128-bit service UUID lists, complete and incomplete
//!   (`0x02`–`0x07`), de-duplicated
//! - shortened / complete local name (`0x08` / `0x09`), lossily UTF-8 decoded
//! - TX power level (`0x0A`, signed)
//! - appearance (`0x19`)
//! - service data, 16/32/128-bit UUID (`0x16` / `0x20` / `0x21`)
//! - manufacturer-specific data (`0xFF`): company identifier + bytes
//! - recognised beacons layered on the above: **iBeacon** (Apple manufacturer
//!   data `0x004C`, type `0x02` len `0x15`) and **Eddystone** (service data
//!   under UUID `0xFEAA`: UID / URL / TLM frames)
//!
//! A single-valued AD type (flags, a local name, TX power, appearance) that
//! appears more than once is last-wins: the later structure's value is kept.
//!
//! Everything the parser does not fully decode is still surfaced: an unmodelled
//! AD type is recorded in `unknown_types`; a modelled AD type whose payload is
//! too short for its format (so it produced no field) is recorded in
//! `malformed`; a length that overran the buffer sets `truncated`. Nothing is
//! silently dropped, and a decode never asserts more than the bytes support
//! (`Unknown` stays unknown; a beacon's "not supported" sentinels become
//! `None`, never a fabricated reading).

use core::fmt::Write as _;

/// The Bluetooth SIG 16-bit UUID that identifies Eddystone service data.
const EDDYSTONE_UUID16: u16 = 0xFEAA;
/// Apple's Bluetooth SIG company identifier, which carries iBeacon frames.
const APPLE_COMPANY_ID: u16 = 0x004C;

/// A parsed service or service-data UUID, kept at its wire width so a 16-bit
/// UUID is never silently widened to its 128-bit base form (which would lose
/// the "this advertiser used the short form" fact and inflate comparisons).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uuid {
    /// A 16-bit SIG-assigned UUID, rendered as four lowercase hex digits.
    U16(u16),
    /// A 32-bit UUID, rendered as eight lowercase hex digits.
    U32(u32),
    /// A full 128-bit UUID, rendered in canonical dashed lowercase form.
    U128([u8; 16]),
}

impl Uuid {
    /// Canonical lowercase text: `xxxx` (16-bit), `xxxxxxxx` (32-bit), or the
    /// dashed `8-4-4-4-12` form (128-bit).
    #[must_use]
    pub fn to_canonical(&self) -> String {
        match self {
            Self::U16(v) => format!("{v:04x}"),
            Self::U32(v) => format!("{v:08x}"),
            Self::U128(bytes) => {
                let mut s = String::with_capacity(36);
                for (i, b) in bytes.iter().enumerate() {
                    if matches!(i, 4 | 6 | 8 | 10) {
                        s.push('-');
                    }
                    let _ = write!(s, "{b:02x}");
                }
                s
            }
        }
    }
}

/// Manufacturer-specific data: the company identifier and the bytes after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManufacturerData {
    /// The 16-bit Bluetooth SIG company identifier (little-endian on the wire).
    pub company_id: u16,
    /// The bytes following the company identifier, verbatim.
    pub data: Vec<u8>,
}

/// Service data: the UUID the data is scoped to, and the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceData {
    /// The UUID this service data belongs to.
    pub uuid: Uuid,
    /// The service-data bytes after the UUID, verbatim.
    pub data: Vec<u8>,
}

/// A recognised beacon frame, layered on the raw AD structures. Recognition is
/// evidence, not identity: a frame that matches the shape is reported; a frame
/// that does not stays absent rather than being force-fit.
#[derive(Debug, Clone, PartialEq)]
pub enum Beacon {
    /// Apple iBeacon: proximity UUID, major, minor, and calibrated TX power at
    /// 1 m (signed dBm).
    IBeacon {
        /// 128-bit proximity UUID, canonical dashed form.
        uuid: String,
        /// Major value (big-endian on the wire).
        major: u16,
        /// Minor value (big-endian on the wire).
        minor: u16,
        /// Measured power: RSSI at 1 m, in dBm.
        tx_power: i8,
    },
    /// Eddystone-UID: 10-byte namespace + 6-byte instance, plus ranging TX power.
    EddystoneUid {
        /// 10-byte namespace, lowercase hex.
        namespace: String,
        /// 6-byte instance, lowercase hex.
        instance: String,
        /// Calibrated TX power at 0 m, in dBm.
        tx_power: i8,
    },
    /// Eddystone-URL: the compressed URL expanded to text, plus ranging TX power.
    EddystoneUrl {
        /// The decompressed URL.
        url: String,
        /// Calibrated TX power at 0 m, in dBm.
        tx_power: i8,
    },
    /// Eddystone-TLM (unencrypted, version 0): telemetry. An encrypted TLM
    /// (version 1) is a different, keyed layout, so it is never decoded here as
    /// if it were plaintext — it stays unrecognised.
    EddystoneTlm {
        /// Battery voltage, millivolts, or `None` when the beacon reports no
        /// battery (the spec's `0` sentinel), e.g. a USB-powered beacon.
        battery_mv: Option<u16>,
        /// Beacon temperature in °C (8.8 fixed-point on the wire), or `None`
        /// when the beacon has no temperature sensor (the spec's `0x8000`
        /// sentinel) — never reported as a real −128 °C reading.
        temperature_c: Option<f32>,
        /// Count of advertising frames since power-on.
        adv_count: u32,
        /// Time since power-on, in 0.1 s units.
        uptime_deciseconds: u32,
    },
}

impl Beacon {
    /// A stable short label for the beacon kind — used by the live summary
    /// surface. Every recognised beacon has one.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::IBeacon { .. } => "iBeacon",
            Self::EddystoneUid { .. } => "Eddystone-UID",
            Self::EddystoneUrl { .. } => "Eddystone-URL",
            Self::EddystoneTlm { .. } => "Eddystone-TLM",
        }
    }
}

/// The full structured decode of one advertising payload.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AdvReport {
    /// GAP flags byte, if present.
    pub flags: Option<u8>,
    /// Complete local name (`0x09`), if present.
    pub complete_local_name: Option<String>,
    /// Shortened local name (`0x08`), if present.
    pub shortened_local_name: Option<String>,
    /// TX power level (`0x0A`), signed dBm.
    pub tx_power_level: Option<i8>,
    /// Appearance (`0x19`), if present.
    pub appearance: Option<u16>,
    /// Advertised service UUIDs (complete and incomplete lists merged, order
    /// preserved, duplicates removed).
    pub service_uuids: Vec<Uuid>,
    /// Service data blocks.
    pub service_data: Vec<ServiceData>,
    /// Manufacturer-specific data blocks.
    pub manufacturer_data: Vec<ManufacturerData>,
    /// A recognised beacon frame, if the payload matched one.
    pub beacon: Option<Beacon>,
    /// AD types present in the payload that this decoder does not model, in
    /// order of appearance (provenance; never silently dropped).
    pub unknown_types: Vec<u8>,
    /// Modelled AD types whose payload was too short (or had a trailing partial
    /// element) to yield their format, so they produced no field — recorded
    /// here rather than dropped in silence, in order of appearance. A name
    /// (`0x08`/`0x09`) has no minimum length and never appears here.
    pub malformed: Vec<u8>,
    /// True when an AD structure declared a length that ran past the buffer, so
    /// the tail could not be parsed. The structures before it are still valid.
    pub truncated: bool,
}

/// The decoder version, bumped when the output for a fixed input changes, so a
/// stored decode records which ruleset produced it (provenance).
pub const DECODER_VERSION: u32 = 1;

/// Decode a raw advertising payload. Never panics for any input.
#[must_use]
pub fn decode(data: &[u8]) -> AdvReport {
    let mut report = AdvReport::default();
    let mut pos = 0usize;

    while pos < data.len() {
        let len = data[pos] as usize;
        // A zero length is the padding terminator: the rest of the buffer is
        // zero-fill, not more structures.
        if len == 0 {
            break;
        }
        // `len` counts the type byte plus the payload. The structure occupies
        // bytes `pos+1 ..= pos+len`; if that runs past the buffer the payload
        // was truncated and nothing after it can be trusted.
        let type_pos = pos + 1;
        let end = match type_pos.checked_add(len) {
            Some(e) if e <= data.len() => e,
            _ => {
                report.truncated = true;
                break;
            }
        };
        let ad_type = data[type_pos];
        let payload = &data[type_pos + 1..end];
        decode_structure(&mut report, ad_type, payload);
        pos = end;
    }

    recognise_beacon(&mut report);
    report
}

/// Decode `data` given as a hex string (as the Android layer hands it across
/// the JNI bridge). Odd length or a non-hex digit yields an empty report with
/// no structures — a malformed hand-off is not a decode.
#[must_use]
pub fn decode_hex(hex: &str) -> AdvReport {
    match hex_decode(hex) {
        Some(bytes) => decode(&bytes),
        None => AdvReport::default(),
    }
}

fn decode_structure(report: &mut AdvReport, ad_type: u8, payload: &[u8]) {
    // A modelled AD type whose payload is too short to carry its minimum format
    // yields nothing; recording the type in `malformed` keeps the "nothing is
    // silently dropped" invariant true (an empty local name is still a name, so
    // 0x08/0x09 have no minimum and never land here).
    let mut malformed = || report.malformed.push(ad_type);
    match ad_type {
        0x01 => match payload.first() {
            Some(&b) => report.flags = Some(b),
            None => malformed(),
        },
        0x02 | 0x03 => {
            if !push_uuids16(&mut report.service_uuids, payload) {
                malformed();
            }
        }
        0x04 | 0x05 => {
            if !push_uuids32(&mut report.service_uuids, payload) {
                malformed();
            }
        }
        0x06 | 0x07 => {
            if !push_uuids128(&mut report.service_uuids, payload) {
                malformed();
            }
        }
        0x08 => report.shortened_local_name = Some(String::from_utf8_lossy(payload).into_owned()),
        0x09 => report.complete_local_name = Some(String::from_utf8_lossy(payload).into_owned()),
        0x0A => match payload.first() {
            Some(&b) => report.tx_power_level = Some(b as i8),
            None => malformed(),
        },
        0x19 => match le_u16(payload) {
            Some(v) => report.appearance = Some(v),
            None => malformed(),
        },
        0x16 => match payload.get(..2).and_then(le_u16_at) {
            Some(uuid) => report.service_data.push(ServiceData {
                uuid: Uuid::U16(uuid),
                data: payload.get(2..).unwrap_or(&[]).to_vec(),
            }),
            None => malformed(),
        },
        0x20 => match payload.get(..4).and_then(le_u32_at) {
            Some(uuid) => report.service_data.push(ServiceData {
                uuid: Uuid::U32(uuid),
                data: payload.get(4..).unwrap_or(&[]).to_vec(),
            }),
            None => malformed(),
        },
        0x21 => match payload.get(..16).and_then(le_u128_at) {
            Some(uuid) => report.service_data.push(ServiceData {
                uuid: Uuid::U128(uuid),
                data: payload.get(16..).unwrap_or(&[]).to_vec(),
            }),
            None => malformed(),
        },
        0xFF => match payload.get(..2).and_then(le_u16_at) {
            Some(company_id) => report.manufacturer_data.push(ManufacturerData {
                company_id,
                data: payload.get(2..).unwrap_or(&[]).to_vec(),
            }),
            None => malformed(),
        },
        other => report.unknown_types.push(other),
    }
}

/// True when the whole payload was a positive multiple of the UUID width, so
/// every byte was surfaced as a UUID; false for an empty payload or a trailing
/// partial UUID (bytes that could not form a whole UUID), which the caller
/// records as malformed rather than dropping in silence.
fn push_uuids16(out: &mut Vec<Uuid>, payload: &[u8]) -> bool {
    for chunk in payload.as_chunks::<2>().0 {
        let u = Uuid::U16(u16::from_le_bytes(*chunk));
        if !out.contains(&u) {
            out.push(u);
        }
    }
    !payload.is_empty() && payload.len().is_multiple_of(2)
}

fn push_uuids32(out: &mut Vec<Uuid>, payload: &[u8]) -> bool {
    for chunk in payload.as_chunks::<4>().0 {
        let u = Uuid::U32(u32::from_le_bytes(*chunk));
        if !out.contains(&u) {
            out.push(u);
        }
    }
    !payload.is_empty() && payload.len().is_multiple_of(4)
}

fn push_uuids128(out: &mut Vec<Uuid>, payload: &[u8]) -> bool {
    for chunk in payload.as_chunks::<16>().0 {
        let mut be = [0u8; 16];
        // 128-bit UUIDs are little-endian on the wire; store big-endian.
        for (i, &b) in chunk.iter().enumerate() {
            be[15 - i] = b;
        }
        let u = Uuid::U128(be);
        if !out.contains(&u) {
            out.push(u);
        }
    }
    !payload.is_empty() && payload.len().is_multiple_of(16)
}

fn recognise_beacon(report: &mut AdvReport) {
    // iBeacon: Apple manufacturer data, type 0x02, length 0x15 (21), then a
    // 16-byte UUID, 2-byte big-endian major, 2-byte big-endian minor, and a
    // signed measured-power byte — 23 bytes after the company id.
    for m in &report.manufacturer_data {
        if m.company_id == APPLE_COMPANY_ID
            && m.data.len() >= 23
            && m.data[0] == 0x02
            && m.data[1] == 0x15
        {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&m.data[2..18]);
            let major = u16::from_be_bytes([m.data[18], m.data[19]]);
            let minor = u16::from_be_bytes([m.data[20], m.data[21]]);
            let tx_power = m.data[22] as i8;
            report.beacon = Some(Beacon::IBeacon {
                uuid: Uuid::U128(uuid).to_canonical(),
                major,
                minor,
                tx_power,
            });
            return;
        }
    }
    // Eddystone: service data under 0xFEAA, first byte is the frame type.
    for s in &report.service_data {
        if s.uuid != Uuid::U16(EDDYSTONE_UUID16) {
            continue;
        }
        if let Some(beacon) = eddystone_frame(&s.data) {
            report.beacon = Some(beacon);
            return;
        }
    }
}

fn eddystone_frame(d: &[u8]) -> Option<Beacon> {
    match d.first()? {
        0x00 if d.len() >= 18 => Some(Beacon::EddystoneUid {
            tx_power: d[1] as i8,
            namespace: hex_of(&d[2..12]),
            instance: hex_of(&d[12..18]),
        }),
        0x10 if d.len() >= 3 => {
            let tx_power = d[1] as i8;
            eddystone_url(d[2], &d[3..]).map(|url| Beacon::EddystoneUrl { url, tx_power })
        }
        // Only unencrypted TLM (version byte 0x00) has this plaintext layout;
        // an encrypted TLM (0x01) or an unknown version is not decoded as if it
        // were, so its telemetry is never a fabricated reading.
        0x20 if d.len() >= 14 && d[1] == 0x00 => Some(Beacon::EddystoneTlm {
            battery_mv: match u16::from_be_bytes([d[2], d[3]]) {
                0 => None,
                mv => Some(mv),
            },
            temperature_c: eddystone_temp(d[4], d[5]),
            adv_count: u32::from_be_bytes([d[6], d[7], d[8], d[9]]),
            uptime_deciseconds: u32::from_be_bytes([d[10], d[11], d[12], d[13]]),
        }),
        _ => None,
    }
}

/// Eddystone temperature: 8.8 fixed-point signed, big-endian, or `None` for the
/// `0x8000` "no temperature sensor" sentinel the spec reserves.
fn eddystone_temp(hi: u8, lo: u8) -> Option<f32> {
    match i16::from_be_bytes([hi, lo]) {
        -32768 => None,
        raw => Some(f32::from(raw) / 256.0),
    }
}

/// Expand an Eddystone-URL scheme prefix + encoded body to a URL string.
fn eddystone_url(scheme: u8, body: &[u8]) -> Option<String> {
    let prefix = match scheme {
        0x00 => "http://www.",
        0x01 => "https://www.",
        0x02 => "http://",
        0x03 => "https://",
        _ => return None,
    };
    let mut url = String::from(prefix);
    for &b in body {
        match b {
            0x00 => url.push_str(".com/"),
            0x01 => url.push_str(".org/"),
            0x02 => url.push_str(".edu/"),
            0x03 => url.push_str(".net/"),
            0x04 => url.push_str(".info/"),
            0x05 => url.push_str(".biz/"),
            0x06 => url.push_str(".gov/"),
            0x07 => url.push_str(".com"),
            0x08 => url.push_str(".org"),
            0x09 => url.push_str(".edu"),
            0x0a => url.push_str(".net"),
            0x0b => url.push_str(".info"),
            0x0c => url.push_str(".biz"),
            0x0d => url.push_str(".gov"),
            // Bytes 0x0e..=0x20 and 0x7f..=0xff are reserved/unprintable in the
            // Eddystone-URL encoding; render them as their raw code so a decode
            // is never a silent lie about the URL.
            0x21..=0x7e => url.push(b as char),
            _ => {
                let _ = write!(url, "\\x{b:02x}");
            }
        }
    }
    Some(url)
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn le_u16(payload: &[u8]) -> Option<u16> {
    le_u16_at(payload.get(..2)?)
}

fn le_u16_at(b: &[u8]) -> Option<u16> {
    let a = b.get(..2)?;
    Some(u16::from_le_bytes([a[0], a[1]]))
}

fn le_u32_at(b: &[u8]) -> Option<u32> {
    let a = b.get(..4)?;
    Some(u32::from_le_bytes([a[0], a[1], a[2], a[3]]))
}

fn le_u128_at(b: &[u8]) -> Option<[u8; 16]> {
    let a = b.get(..16)?;
    let mut be = [0u8; 16];
    for (i, &byte) in a.iter().enumerate() {
        be[15 - i] = byte;
    }
    Some(be)
}

/// Decode a hex string to bytes; `None` for odd length or a non-hex digit.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for [hi, lo] in bytes.as_chunks::<2>().0 {
        out.push((nibble(*hi)? << 4) | nibble(*lo)?);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The first manufacturer company identifier as four lowercase hex digits, or
/// `None`. The live summary the Android layer shows for "who made this device".
#[must_use]
pub fn summary_company_id(report: &AdvReport) -> Option<String> {
    report
        .manufacturer_data
        .first()
        .map(|m| format!("{:04x}", m.company_id))
}

/// The recognised beacon's label, or `None`. The live summary the Android layer
/// shows for "is this a beacon, and which kind".
#[must_use]
pub fn summary_beacon(report: &AdvReport) -> Option<&'static str> {
    report.beacon.as_ref().map(Beacon::label)
}

/// The version of the bundled company-identifier table, bumped whenever the
/// bundled snapshot of the SIG registry (`data/company_identifiers.yaml`, see
/// `data/SOURCE.md`) is refreshed, so a stored name records which ruleset
/// produced it. Version 3 is the complete registry; versions 1 and 2 were
/// curated subsets (of 38 names, 30 of them shortened from the SIG's).
pub const COMPANY_TABLE_VERSION: u32 = 3;

// The registry's flat lookup tables, generated by `build.rs` from the SIG's
// own file: `COMPANY_IDS` strictly ascending, `COMPANY_NAME_ENDS[i]` the end
// offset of entry i's name in `COMPANY_NAMES` (its start is entry i-1's end).
include!(concat!(env!("OUT_DIR"), "/company_tables.rs"));
static COMPANY_NAMES: &str = include_str!(concat!(env!("OUT_DIR"), "/company_names.txt"));

/// The Bluetooth SIG assignee name for a 16-bit company identifier, exactly as
/// the SIG's Assigned Numbers spell it, or `None` — an identifier the SIG has
/// not assigned (or assigned after the bundled snapshot) stays unknown and the
/// caller shows the raw hex id. The table is the SIG's own
/// `company_identifiers.yaml`, bundled so identification works offline and
/// turned into a binary-searched lookup by `build.rs`.
#[must_use]
pub fn company_name(company_id: u16) -> Option<&'static str> {
    let index = COMPANY_IDS.binary_search(&company_id).ok()?;
    let start = match index {
        0 => 0,
        _ => COMPANY_NAME_ENDS[index - 1] as usize,
    };
    COMPANY_NAMES.get(start..COMPANY_NAME_ENDS[index] as usize)
}

/// The Bluetooth SIG assignee name for the first manufacturer block's company
/// identifier, or `None` when there is no manufacturer data or the identifier is
/// not in the bundled table. The live "who made this device" name behind the raw
/// [`summary_company_id`].
#[must_use]
pub fn summary_manufacturer_name(report: &AdvReport) -> Option<&'static str> {
    report
        .manufacturer_data
        .first()
        .and_then(|m| company_name(m.company_id))
}

/// The name of a well-known 16-bit Bluetooth SIG service (GATT service or member
/// service) UUID, or `None` — the caller then shows the raw hex. A curated,
/// versioned ([`SERVICE_TABLE_VERSION`]) subset of the public SIG Assigned
/// Numbers: the GATT services a scan actually meets, plus a few widely-seen
/// member-service UUIDs. 32/128-bit UUIDs are vendor-specific and unnamed here.
/// Sorted by id for a binary-search lookup that a test keeps strictly ascending.
#[must_use]
pub fn service_uuid_name(uuid: &Uuid) -> Option<&'static str> {
    let Uuid::U16(id) = uuid else {
        return None;
    };
    SERVICES
        .binary_search_by_key(id, |&(id, _)| id)
        .ok()
        .map(|i| SERVICES[i].1)
}

/// The version of the bundled service-UUID table, bumped when an entry changes.
pub const SERVICE_TABLE_VERSION: u32 = 2;

/// (id, name), strictly ascending by id — a test asserts the ordering and that
/// every row is reachable through [`service_uuid_name`].
const SERVICES: &[(u16, &str)] = &[
    (0x1800, "Generic Access"),
    (0x1801, "Generic Attribute"),
    (0x1802, "Immediate Alert"),
    (0x1803, "Link Loss"),
    (0x1804, "Tx Power"),
    (0x1805, "Current Time"),
    (0x1808, "Glucose"),
    (0x1809, "Health Thermometer"),
    (0x180A, "Device Information"),
    (0x180D, "Heart Rate"),
    (0x180F, "Battery"),
    (0x1810, "Blood Pressure"),
    (0x1811, "Alert Notification"),
    (0x1812, "Human Interface Device"),
    (0x1813, "Scan Parameters"),
    (0x1814, "Running Speed and Cadence"),
    (0x1816, "Cycling Speed and Cadence"),
    (0x1818, "Cycling Power"),
    (0x1819, "Location and Navigation"),
    (0x181A, "Environmental Sensing"),
    (0x181B, "Body Composition"),
    (0x181D, "Weight Scale"),
    (0x181F, "Continuous Glucose Monitoring"),
    (0x1826, "Fitness Machine"),
    (0x1827, "Mesh Provisioning"),
    (0x1828, "Mesh Proxy"),
    (0x183A, "Insulin Delivery"),
    (0xFD5A, "Samsung Electronics"),
    (0xFD6F, "Exposure Notification"),
    (0xFE9F, "Google"),
    (0xFEAA, "Eddystone"),
    (0xFEED, "Tile"),
    (0xFEF3, "Google"),
];

/// The names of the advertisement's well-known services, in the order the UUIDs
/// appear, without duplicates — the live "what does this device do" summary. An
/// unnamed UUID is skipped (the raw ids remain in [`AdvReport::service_uuids`]).
#[must_use]
pub fn summary_service_names(report: &AdvReport) -> Vec<&'static str> {
    let mut names = Vec::new();
    for uuid in &report.service_uuids {
        if let Some(name) = service_uuid_name(uuid)
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_decodes_to_empty_report() {
        assert_eq!(decode(&[]), AdvReport::default());
        assert_eq!(decode_hex(""), AdvReport::default());
    }

    #[test]
    fn zero_length_is_the_padding_terminator() {
        // Flags, then zero padding: the trailing zeros are not structures.
        let r = decode(&[0x02, 0x01, 0x06, 0x00, 0x00, 0x00]);
        assert_eq!(r.flags, Some(0x06));
        assert!(!r.truncated);
        assert!(r.unknown_types.is_empty());
    }

    #[test]
    fn a_length_past_the_buffer_is_truncated_not_a_panic() {
        // Declares a 5-byte structure with only 2 bytes present.
        let r = decode(&[0x05, 0x09, b'H', b'i']);
        assert!(r.truncated);
        assert_eq!(r.complete_local_name, None);
    }

    #[test]
    fn flags_name_txpower_and_appearance() {
        let r = decode(&[
            0x02, 0x01, 0x06, // flags
            0x05, 0x09, b'T', b'a', b'g', b'!', // complete local name "Tag!"
            0x02, 0x0A, 0xF6, // tx power -10 dBm
            0x03, 0x19, 0xC1, 0x03, // appearance 0x03C1 (LE)
        ]);
        assert_eq!(r.flags, Some(0x06));
        assert_eq!(r.complete_local_name.as_deref(), Some("Tag!"));
        assert_eq!(r.tx_power_level, Some(-10));
        assert_eq!(r.appearance, Some(0x03C1));
    }

    #[test]
    fn service_uuids_all_widths_dedup_and_canonical() {
        let mut data = vec![
            0x05, 0x03, 0x0D, 0x18, 0x0F, 0x18, // complete 16-bit: 180D, 180F
            0x03, 0x02, 0x0D, 0x18, // incomplete 16-bit: 180D again (dup)
            0x05, 0x05, 0x78, 0x56, 0x34, 0x12, // complete 32-bit: 12345678
        ];
        // complete 128-bit UUID 0102...10 (little-endian on the wire)
        data.push(0x11);
        data.push(0x07);
        for b in 1u8..=16 {
            data.push(b);
        }
        let r = decode(&data);
        let got: Vec<String> = r.service_uuids.iter().map(Uuid::to_canonical).collect();
        assert_eq!(
            got,
            vec![
                "180d".to_string(),
                "180f".to_string(),
                "12345678".to_string(),
                "100f0e0d-0c0b-0a09-0807-060504030201".to_string(),
            ]
        );
    }

    #[test]
    fn manufacturer_data_company_id_is_little_endian() {
        let r = decode(&[0x05, 0xFF, 0x4C, 0x00, 0xAA, 0xBB]);
        assert_eq!(r.manufacturer_data.len(), 1);
        assert_eq!(r.manufacturer_data[0].company_id, 0x004C);
        assert_eq!(r.manufacturer_data[0].data, vec![0xAA, 0xBB]);
        assert_eq!(summary_company_id(&r).as_deref(), Some("004c"));
    }

    #[test]
    fn ibeacon_is_recognised() {
        // Apple manufacturer data, iBeacon prefix, 16-byte UUID, major 1, minor 2, power -59.
        let mut data = vec![0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15];
        for b in 1u8..=16 {
            data.push(b);
        }
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xC5]);
        let r = decode(&data);
        match r.beacon.as_ref().expect("iBeacon recognised") {
            Beacon::IBeacon {
                uuid,
                major,
                minor,
                tx_power,
            } => {
                assert_eq!(uuid, "01020304-0506-0708-090a-0b0c0d0e0f10");
                assert_eq!(*major, 1);
                assert_eq!(*minor, 2);
                assert_eq!(*tx_power, -59);
            }
            other => panic!("expected iBeacon, got {other:?}"),
        }
        assert_eq!(summary_beacon(&r), Some("iBeacon"));
    }

    /// One AD structure with its length computed from the payload, so a test
    /// fixture can never carry a hand-miscounted length.
    fn ad(ad_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![u8::try_from(payload.len() + 1).expect("AD fits"), ad_type];
        v.extend_from_slice(payload);
        v
    }

    /// Service data under the Eddystone UUID (0xFEAA, little-endian on the wire).
    fn eddystone(frame: &[u8]) -> Vec<u8> {
        let mut payload = vec![0xAA, 0xFE];
        payload.extend_from_slice(frame);
        ad(0x16, &payload)
    }

    #[test]
    fn eddystone_url_expands() {
        // URL frame, tx -18, scheme https://, "example" + ".com/".
        let mut frame = vec![0x10u8, 0xEE, 0x03];
        frame.extend_from_slice(b"example");
        frame.push(0x00);
        let mut data = ad(0x03, &[0xAA, 0xFE]);
        data.extend(eddystone(&frame));
        let r = decode(&data);
        assert!(!r.truncated);
        match r.beacon.as_ref().expect("Eddystone-URL recognised") {
            Beacon::EddystoneUrl { url, tx_power } => {
                assert_eq!(url, "https://example.com/");
                assert_eq!(*tx_power, -18);
            }
            other => panic!("expected Eddystone-URL, got {other:?}"),
        }
        assert_eq!(summary_beacon(&r), Some("Eddystone-URL"));
    }

    #[test]
    fn eddystone_url_escapes_reserved_bytes_instead_of_lying() {
        // 0x20 (space) and 0x7f are reserved in Eddystone-URL: rendered as \xNN.
        let r = decode(&eddystone(&[0x10, 0x00, 0x02, b'a', 0x20, 0x7f]));
        match r.beacon.expect("URL frame") {
            Beacon::EddystoneUrl { url, .. } => assert_eq!(url, "http://a\\x20\\x7f"),
            other => panic!("expected Eddystone-URL, got {other:?}"),
        }
    }

    #[test]
    fn eddystone_uid_and_tlm() {
        // UID frame: tx -18, 10-byte namespace 00..09, 6-byte instance 0a..0f.
        let mut uid = vec![0x00u8, 0xEE];
        uid.extend(0u8..16);
        match decode(&eddystone(&uid)).beacon.expect("UID") {
            Beacon::EddystoneUid {
                namespace,
                instance,
                tx_power,
            } => {
                assert_eq!(namespace, "00010203040506070809");
                assert_eq!(instance, "0a0b0c0d0e0f");
                assert_eq!(tx_power, -18);
            }
            other => panic!("expected UID, got {other:?}"),
        }

        // TLM frame: version 0, 3300 mV, 25.5 °C, 42 adv, 1000 ds.
        let mut tlm = vec![0x20u8, 0x00];
        tlm.extend_from_slice(&3300u16.to_be_bytes());
        tlm.extend_from_slice(&0x1980i16.to_be_bytes()); // 25.5 °C in 8.8 fixed point
        tlm.extend_from_slice(&42u32.to_be_bytes());
        tlm.extend_from_slice(&1000u32.to_be_bytes());
        match decode(&eddystone(&tlm)).beacon.expect("TLM") {
            Beacon::EddystoneTlm {
                battery_mv,
                temperature_c,
                adv_count,
                uptime_deciseconds,
            } => {
                assert_eq!(battery_mv, Some(3300));
                assert!((temperature_c.expect("temp") - 25.5).abs() < f32::EPSILON);
                assert_eq!(adv_count, 42);
                assert_eq!(uptime_deciseconds, 1000);
            }
            other => panic!("expected TLM, got {other:?}"),
        }
    }

    #[test]
    fn tlm_not_supported_sentinels_are_none_and_negative_temps_decode() {
        // Battery 0 and temperature 0x8000 are "not supported", not readings.
        let mut tlm = vec![0x20u8, 0x00];
        tlm.extend_from_slice(&0u16.to_be_bytes()); // battery not supported
        tlm.extend_from_slice(&(-32768i16).to_be_bytes()); // temp not supported
        tlm.extend_from_slice(&1u32.to_be_bytes());
        tlm.extend_from_slice(&2u32.to_be_bytes());
        match decode(&eddystone(&tlm)).beacon.expect("TLM") {
            Beacon::EddystoneTlm {
                battery_mv,
                temperature_c,
                ..
            } => {
                assert_eq!(battery_mv, None);
                assert_eq!(temperature_c, None);
            }
            other => panic!("expected TLM, got {other:?}"),
        }
        // A genuine sub-zero temperature (−20.25 °C = 0xEBC0) is a real reading.
        let mut cold = vec![0x20u8, 0x00];
        cold.extend_from_slice(&3000u16.to_be_bytes());
        cold.extend_from_slice(&0xEBC0u16.to_be_bytes());
        cold.extend_from_slice(&0u32.to_be_bytes());
        cold.extend_from_slice(&0u32.to_be_bytes());
        match decode(&eddystone(&cold)).beacon.expect("TLM") {
            Beacon::EddystoneTlm { temperature_c, .. } => {
                assert!((temperature_c.expect("temp") + 20.25).abs() < f32::EPSILON);
            }
            other => panic!("expected TLM, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_or_unknown_tlm_version_is_not_decoded_as_plaintext() {
        // Version 0x01 is encrypted TLM (a different, keyed layout): it must not
        // be reported as plaintext telemetry.
        let mut etlm = vec![0x20u8, 0x01];
        etlm.extend(std::iter::repeat_n(0xAB, 12));
        assert_eq!(decode(&eddystone(&etlm)).beacon, None);
    }

    #[test]
    fn short_beacon_frames_are_not_force_fit() {
        // An iBeacon prefix one byte short, and Eddystone frames below their
        // minimum lengths, are reported as raw data, never as a beacon.
        let mut ib = vec![0x4C, 0x00, 0x02, 0x15];
        ib.extend(0u8..18); // 22 bytes after the company id; iBeacon needs 23
        assert_eq!(decode(&ad(0xFF, &ib)).beacon, None);
        assert_eq!(decode(&eddystone(&[0x00, 0xEE, 1, 2, 3])).beacon, None);
        assert_eq!(decode(&eddystone(&[0x20, 0x00, 1])).beacon, None);
        assert_eq!(decode(&eddystone(&[0x10, 0x00])).beacon, None);
        // An unknown URL scheme byte is not a URL.
        assert_eq!(decode(&eddystone(&[0x10, 0x00, 0x09, b'x'])).beacon, None);
    }

    #[test]
    fn unknown_types_are_recorded_not_dropped() {
        let r = decode(&[0x02, 0x3D, 0x01]); // 0x3D unmodelled
        assert_eq!(r.unknown_types, vec![0x3D]);
    }

    #[test]
    fn modelled_but_too_short_structures_are_recorded_not_dropped() {
        // Manufacturer data with one byte (needs 2 for the company id), a
        // 16-bit service-data structure with one byte, an appearance with one
        // byte, and a 16-bit UUID list with a trailing partial UUID — each
        // yields no field but is recorded, so nothing vanishes silently.
        let r = decode(&[
            0x02, 0xFF, 0x4C, // manufacturer, too short
            0x02, 0x16, 0xAA, // service data 16-bit, too short
            0x02, 0x19, 0x01, // appearance, too short
            0x04, 0x03, 0x0D, 0x18, 0x0F, // 16-bit UUID list: one UUID + a stray byte
        ]);
        assert_eq!(r.malformed, vec![0xFF, 0x16, 0x19, 0x03]);
        assert!(r.manufacturer_data.is_empty());
        assert!(r.service_data.is_empty());
        assert_eq!(r.appearance, None);
        // The one whole UUID before the stray byte is still surfaced.
        assert_eq!(r.service_uuids, vec![Uuid::U16(0x180D)]);
    }

    #[test]
    fn hex_handoff_is_validated() {
        // Odd length and non-hex both yield an empty report, not a wrong one.
        assert_eq!(decode_hex("020106f"), AdvReport::default());
        assert_eq!(decode_hex("0201zz"), AdvReport::default());
        assert_eq!(decode_hex("020106").flags, Some(0x06));
        // Uppercase and mixed-case hex decode identically (the JNI doc promises
        // ScanRecord.getBytes() hex "as lowercase or uppercase").
        let mixed = decode_hex("05FF4c00AAbb");
        assert_eq!(decode_hex("05ff4c00aabb"), mixed);
        assert_eq!(mixed.manufacturer_data[0].company_id, 0x004C);
        assert_eq!(mixed.manufacturer_data[0].data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn eddystone_url_table_matches_the_spec_code_for_code() {
        // Every scheme prefix (0x00–0x03) and expansion code (0x00–0x0d), each
        // asserted against the literal the Eddystone-URL spec defines — an
        // independent check on the decoder's table, not a copy of it.
        let schemes = [
            (0x00u8, "http://www."),
            (0x01, "https://www."),
            (0x02, "http://"),
            (0x03, "https://"),
        ];
        let codes = [
            (0x00u8, ".com/"),
            (0x01, ".org/"),
            (0x02, ".edu/"),
            (0x03, ".net/"),
            (0x04, ".info/"),
            (0x05, ".biz/"),
            (0x06, ".gov/"),
            (0x07, ".com"),
            (0x08, ".org"),
            (0x09, ".edu"),
            (0x0a, ".net"),
            (0x0b, ".info"),
            (0x0c, ".biz"),
            (0x0d, ".gov"),
        ];
        for (scheme, prefix) in schemes {
            for (code, suffix) in codes {
                // len 0x08 = service-data type + [AA FE] uuid + [10 tx scheme x code].
                let r = decode(&[0x08, 0x16, 0xAA, 0xFE, 0x10, 0x00, scheme, b'x', code]);
                match r.beacon {
                    Some(Beacon::EddystoneUrl { url, .. }) => {
                        assert_eq!(
                            url,
                            format!("{prefix}x{suffix}"),
                            "scheme {scheme:#x} code {code:#x}"
                        );
                    }
                    other => {
                        panic!("scheme {scheme:#x} code {code:#x}: expected URL, got {other:?}")
                    }
                }
            }
        }
    }

    /// Every `(id, name)` of the bundled SIG file, read by a second scanner
    /// that shares nothing with `build.rs`'s parser (no unescaping: no name in
    /// the registry needs it) — the oracle the generated tables are held to.
    fn registry_oracle() -> Vec<(u16, &'static str)> {
        let mut lines = include_str!("../data/company_identifiers.yaml").lines();
        let mut pairs = Vec::new();
        while let Some(line) = lines.next() {
            let Some(hex) = line.trim().strip_prefix("- value: 0x") else {
                continue;
            };
            let name = lines
                .next()
                .and_then(|line| line.trim().strip_prefix("name: "))
                .expect("a name follows every value");
            // Exactly one quote per side: a name may itself end in a quote.
            let name = ['\'', '"']
                .into_iter()
                .find_map(|quote| name.strip_prefix(quote)?.strip_suffix(quote))
                .expect("a quoted name");
            pairs.push((
                u16::from_str_radix(hex, 16).expect("a four-digit hex id"),
                name,
            ));
        }
        pairs
    }

    #[test]
    fn company_table_is_the_whole_sig_registry_and_nothing_else() {
        let oracle = registry_oracle();
        assert_eq!(
            oracle.len(),
            COMPANY_IDS.len(),
            "an entry was dropped or invented"
        );
        let by_id: std::collections::HashMap<u16, &str> = oracle.iter().copied().collect();
        assert_eq!(by_id.len(), oracle.len(), "the registry repeats an id");
        // Extensional: for every one of the 65,536 identifiers the lookup gives
        // exactly what the file says — the file's name for an assigned one,
        // `None` for the rest.
        for id in 0..=u16::MAX {
            assert_eq!(company_name(id), by_id.get(&id).copied(), "{id:#06x}");
        }
        assert!(
            COMPANY_IDS.windows(2).all(|pair| pair[0] < pair[1]),
            "the binary search needs strictly ascending ids"
        );
    }

    #[test]
    fn company_names_are_the_sigs_spelling_including_the_awkward_lines() {
        // Pinned from the SIG's file by reading it, independently of both
        // parsers: the well-known assignees, the first and last rows, the two
        // double-quoted names (they hold an apostrophe), a name that ends in a
        // quote character and a non-ASCII one.
        for (id, name) in [
            (0x0000, "Ericsson AB"),
            (0x0006, "Microsoft"),
            (0x004C, "Apple, Inc."),
            (0x0059, "Nordic Semiconductor ASA"),
            (0x0075, "Samsung Electronics Co. Ltd."),
            (0x00E0, "Google"),
            (0x0A9C, "Xi'an Fengyu Information Technology Co., Ltd."),
            (0x0380, "LLC \"MEGA-F service\""),
            (0x1101, "Nearfaces UG (haftungsbeschränkt)"),
            (0x112A, "Flowil International Lighting (Holding) B.V."),
        ] {
            assert_eq!(company_name(id), Some(name), "{id:#06x}");
        }
        // 0xFFFF is the SIG's testing identifier: it is never assigned.
        assert_eq!(company_name(0xFFFF), None);
    }

    #[test]
    fn service_table_is_sorted_and_names_known_services() {
        assert!(
            SERVICES.windows(2).all(|w| w[0].0 < w[1].0),
            "service table not strictly ascending"
        );
        for &(id, name) in SERVICES {
            assert!(!name.is_empty());
            assert_eq!(
                service_uuid_name(&Uuid::U16(id)),
                Some(name),
                "{id:#06x} unreachable"
            );
        }
        assert_eq!(
            service_uuid_name(&Uuid::U16(0xFD6F)),
            Some("Exposure Notification")
        );
        assert_eq!(
            service_uuid_name(&Uuid::U16(0xFD5A)),
            Some("Samsung Electronics")
        );
        assert_eq!(service_uuid_name(&Uuid::U16(0xFEF3)), Some("Google"));
        assert_eq!(service_uuid_name(&Uuid::U16(0x180D)), Some("Heart Rate"));
        assert_eq!(service_uuid_name(&Uuid::U16(0x180F)), Some("Battery"));
        assert_eq!(service_uuid_name(&Uuid::U16(0xFEAA)), Some("Eddystone"));
        assert_eq!(service_uuid_name(&Uuid::U16(0xABCD)), None);
        // 32/128-bit UUIDs are not named here.
        assert_eq!(service_uuid_name(&Uuid::U32(0x180D)), None);
        assert_eq!(service_uuid_name(&Uuid::U128([0; 16])), None);
    }

    #[test]
    fn repeated_singleton_ad_type_is_last_wins() {
        let r = decode(&[0x02, 0x01, 0x06, 0x02, 0x01, 0x1A]);
        assert_eq!(r.flags, Some(0x1A));
    }

    #[test]
    fn service_names_summarise_named_services_and_dedup() {
        // Complete 16-bit list: Heart Rate (180D), Battery (180F), plus an
        // unnamed 0x1234 which is skipped; a duplicate 180D is not repeated.
        let r = decode(&[
            0x0B, 0x03, 0x0D, 0x18, 0x0F, 0x18, 0x34, 0x12, 0x0D, 0x18, 0xAA, 0xFE,
        ]);
        assert_eq!(
            summary_service_names(&r),
            vec!["Heart Rate", "Battery", "Eddystone"]
        );
        // The raw ids are still all present (including the unnamed one).
        assert!(r.service_uuids.contains(&Uuid::U16(0x1234)));
        // No services → empty.
        assert!(summary_service_names(&decode(&[0x02, 0x01, 0x06])).is_empty());
    }

    #[test]
    fn manufacturer_name_resolves_from_the_advertisement() {
        // Apple iBeacon manufacturer block → "Apple, Inc."; its raw id is still 004c.
        let ib = decode_hex("1aff4c0002150102030405060708090a0b0c0d0e0f1000010002c5");
        assert_eq!(summary_manufacturer_name(&ib), Some("Apple, Inc."));
        assert_eq!(summary_company_id(&ib).as_deref(), Some("004c"));
        // A testing id (0xFFFF) has a raw id but no name.
        let test = decode_hex("05ffffff0102");
        assert_eq!(summary_company_id(&test).as_deref(), Some("ffff"));
        assert_eq!(summary_manufacturer_name(&test), None);
        // No manufacturer data → neither.
        let none = decode_hex("020106");
        assert_eq!(summary_manufacturer_name(&none), None);
    }

    #[test]
    fn summaries_absent_when_nothing_matches() {
        let r = decode(&[0x02, 0x01, 0x06]);
        assert_eq!(summary_company_id(&r), None);
        assert_eq!(summary_beacon(&r), None);
    }
}
