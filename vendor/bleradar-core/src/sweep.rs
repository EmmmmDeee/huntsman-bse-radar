//! Multi-sensor radar sweep domain, imported from the Huntsman Search Engine
//! (HSE) `signal_radar` module so the radar's sensor rules have one authority.
//!
//! HSE's radar sweeps Wi-Fi APs, Bluetooth devices and cell towers in one pass.
//! Its transport (Termux subprocesses, `serde_json`, async I/O) is platform glue
//! and stays in HSE; the *rules* it applies to each reading are pure domain
//! logic and live here, dependency-free, next to the signal primitives they
//! already used (`wifi_frequency_to_channel`, `proximity_label`).
//!
//! Invariants carried over from HSE (each regression-locked below):
//! - a reading the platform omitted stays `None`; it is never defaulted to `0`;
//! - a positive Wi-Fi RSSI is corrupt input and scores the *worst* tier;
//! - placeholder addresses are not devices;
//! - a locally administered MAC is randomized, never a trackable device;
//! - a cell's identity is read from the key its radio actually emits
//!   (`cid` GSM/WCDMA, `ci` LTE, `nci` NR), with `Integer.MAX_VALUE` and `0`
//!   treated as unavailable.

use crate::{
    ProximityBand, WifiSecurity, canonical_mac, is_locally_administered, proximity_label,
    wifi_frequency_to_channel, wifi_is_enterprise, wifi_security,
};

/// Android's `Integer.MAX_VALUE` "value unavailable" sentinel.
pub const ANDROID_UNAVAILABLE: i64 = i32::MAX as i64;

/// Addresses that stand for "no device": the all-zero MAC and the fixed MAC
/// Android reports when the caller lacks permission to see the real one.
const PLACEHOLDER_MACS: [&str; 2] = ["00:00:00:00:00:00", "02:00:00:00:00:00"];

/// Whether `mac` names a real device: a canonicalisable address that is not a
/// placeholder sentinel. Canonicalising first means the two sentinels are
/// rejected regardless of separator formatting (`00-00-…` as well as `00:00:…`),
/// and a string that is not a MAC at all is not a device.
#[must_use]
pub fn is_real_device_address(mac: &str) -> bool {
    canonical_device_mac(mac).is_some()
}

/// The canonical (lowercase, colon-separated) form of a real device MAC, or
/// `None` when `mac` is not a canonicalisable address or is a placeholder
/// sentinel. The single gate both [`is_real_device_address`] and
/// [`sighting_key`] apply, so a placeholder can never slip through one spelling.
fn canonical_device_mac(mac: &str) -> Option<String> {
    canonical_mac(mac).filter(|c| !PLACEHOLDER_MACS.contains(&c.as_str()))
}

/// How a MAC-addressed radio entity may be tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressTrackability {
    /// A globally administered (real hardware) address — a followable device.
    Trackable,
    /// A locally administered (rotating/privacy) address — a throwaway, never
    /// plotted as a followable device.
    Randomized,
    /// Not a canonicalisable MAC, so trackability is unknown.
    Unknown,
}

/// Classify how a MAC may be tracked, from its U/L bit — the rule for Wi-Fi,
/// whose MAC randomization sets the locally-administered bit. Mirrors the
/// exact distinction HSE's `signal_radar` and WiGLE paths partition on. A BLE
/// address is classified by [`ble_address_trackability`] instead: the U/L bit
/// means nothing in a BLE random address.
#[must_use]
pub fn address_trackability(mac: &str) -> AddressTrackability {
    match is_locally_administered(mac) {
        Some(false) => AddressTrackability::Trackable,
        Some(true) => AddressTrackability::Randomized,
        None => AddressTrackability::Unknown,
    }
}

/// The type of a BLE device address as the platform reports it (Android
/// `BluetoothDevice.getAddressType()`, API 35+): the one fact the address
/// bytes alone cannot give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleAddressType {
    /// A public (IEEE-assigned) device address.
    Public,
    /// A random address; its subtype is in its two most significant bits.
    Random,
    /// Not reported (an older platform, or `ADDRESS_TYPE_UNKNOWN` /
    /// `ADDRESS_TYPE_ANONYMOUS`).
    Unknown,
}

impl BleAddressType {
    /// From Android's `BluetoothDevice.ADDRESS_TYPE_*` code: `0` public,
    /// `1` random, anything else (`0xFFFF` unknown, `0xFF` anonymous, a code
    /// this build does not know) unknown.
    #[must_use]
    pub fn from_android(code: i32) -> Self {
        match code {
            0 => Self::Public,
            1 => Self::Random,
            _ => Self::Unknown,
        }
    }
}

/// Classify how a BLE address may be tracked, from the platform-reported
/// address type and the address itself (Bluetooth Core Spec, Vol 6, Part B,
/// §1.3):
///
/// * public → [`AddressTrackability::Trackable`];
/// * random static (top two bits `11`: fixed at least until a power cycle) →
///   [`AddressTrackability::Trackable`];
/// * resolvable private (`01`) or non-resolvable private (`00`) — the
///   rotating privacy addresses → [`AddressTrackability::Randomized`];
/// * the reserved subtype (`10`) → [`AddressTrackability::Unknown`].
///
/// The U/L bit that [`address_trackability`] reads is meaningless here: about
/// half of all resolvable private addresses have it clear, so reading it would
/// file a rotating phone as followable hardware and remember it. Only when
/// the platform reports no type does this fall back to that rule, unchanged
/// (an older Android). A non-canonicalisable MAC is always `Unknown`.
#[must_use]
pub fn ble_address_trackability(mac: &str, address_type: BleAddressType) -> AddressTrackability {
    let Some(canonical) = canonical_mac(mac) else {
        return AddressTrackability::Unknown;
    };
    match address_type {
        BleAddressType::Public => AddressTrackability::Trackable,
        BleAddressType::Unknown => address_trackability(&canonical),
        BleAddressType::Random => {
            let msb = u8::from_str_radix(&canonical[..2], 16).unwrap_or(0);
            match msb >> 6 {
                0b11 => AddressTrackability::Trackable,
                0b01 | 0b00 => AddressTrackability::Randomized,
                _ => AddressTrackability::Unknown,
            }
        }
    }
}

/// Coarse Wi-Fi RSSI reliability tiers, from HSE `wifi::rssi_confidence`. A
/// positive dBm reading is unphysical (0 dBm is already a theoretical ceiling),
/// so it is corrupt input and degrades to the worst tier — never the best.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RssiReliability {
    /// dBm ≥ -50 — the strongest, most reliable tier. A corrupt (positive)
    /// reading never reaches this tier; it falls to [`Self::LowMedium`].
    VeryHighPlus,
    /// -71 ≤ dBm < -50.
    VeryHigh,
    /// -86 ≤ dBm < -71.
    MediumPlus,
    /// dBm < -86, absent, or corrupt (positive) — the worst tier.
    LowMedium,
}

/// Reliability tier for a Wi-Fi RSSI reading in dBm. `None` and a positive
/// reading both fall to [`RssiReliability::LowMedium`].
#[must_use]
pub fn wifi_rssi_reliability(rssi_dbm: Option<i64>) -> RssiReliability {
    match rssi_dbm {
        Some(r) if r > 0 => RssiReliability::LowMedium,
        Some(r) if r >= -50 => RssiReliability::VeryHighPlus,
        Some(r) if r >= -71 => RssiReliability::VeryHigh,
        Some(r) if r >= -86 => RssiReliability::MediumPlus,
        _ => RssiReliability::LowMedium,
    }
}

/// The specific 802.11 channel for an AP centre frequency in MHz, via the
/// radar's verified frequency↔channel map. `None` for an out-of-plan frequency.
#[must_use]
pub fn wifi_channel(frequency_mhz: Option<i64>) -> Option<u16> {
    frequency_mhz
        .and_then(|f| u16::try_from(f).ok())
        .and_then(wifi_frequency_to_channel)
}

/// The coarse RSSI proximity band for a Wi-Fi reading — an honest signal-strength
/// bucket, never a fabricated distance. `None` when no RSSI was reported or the
/// reading is not a received power at all (positive, e.g. Android's
/// [`ANDROID_UNAVAILABLE`] sentinel), rather than banding it as the closest.
#[must_use]
pub fn wifi_proximity(rssi_dbm: Option<i64>) -> Option<ProximityBand> {
    rssi_dbm
        .filter(|&r| r <= 0)
        .and_then(|r| proximity_label(r as f64))
}

/// Everything the radar's rules say about one Wi-Fi scan result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiObservation {
    /// Whether the BSSID is followable hardware or a randomized address (the
    /// U/L rule, which is the Wi-Fi authority).
    pub trackability: AddressTrackability,
    /// How far the RSSI reading can be trusted.
    pub reliability: RssiReliability,
    /// The 802.11 channel, when the frequency is in the plan.
    pub channel: Option<u16>,
    /// The coarse signal-strength band, never a distance.
    pub proximity: Option<ProximityBand>,
    /// The advertised security, by the oracle-locked [`wifi_security`] (the one
    /// authority; this layer only decides when there is nothing to classify).
    pub security: WifiSecurity,
    /// Whether the AP uses 802.1X/EAP authentication ([`wifi_is_enterprise`]).
    pub enterprise: bool,
}

/// Apply every Wi-Fi reading rule to one scan result. `None` when `bssid` is not
/// a real device address (all-zero, Android's permission-masked
/// `02:00:00:00:00:00`, or not a MAC at all): such a result names no access
/// point and must not be surveyed or counted as one.
///
/// An absent or blank `capabilities` string is passed on as absent, so the
/// security is [`WifiSecurity::Unknown`], never [`WifiSecurity::Open`]: the
/// oracle-locked [`wifi_security`] reads a string with no security token as
/// open, which is right for a real capabilities string (`[ESS]`) and wrong for
/// silence.
#[must_use]
pub fn wifi_observation(
    bssid: &str,
    capabilities: Option<&str>,
    rssi_dbm: Option<i64>,
    frequency_mhz: Option<i64>,
) -> Option<WifiObservation> {
    if !is_real_device_address(bssid) {
        return None;
    }
    let capabilities = capabilities.filter(|c| !c.trim().is_empty());
    Some(WifiObservation {
        trackability: address_trackability(bssid),
        reliability: wifi_rssi_reliability(rssi_dbm),
        channel: wifi_channel(frequency_mhz),
        proximity: wifi_proximity(rssi_dbm),
        security: wifi_security(capabilities),
        enterprise: wifi_is_enterprise(capabilities),
    })
}

/// The radio a cell record was seen on, which decides the key its identity lives
/// under and the name of its area code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellRadio {
    /// GSM — `cid` / `lac`.
    Gsm,
    /// WCDMA/UMTS — `cid` / `lac`.
    Wcdma,
    /// LTE — `ci` / `tac`.
    Lte,
    /// NR / 5G — `nci` / `tac`.
    Nr,
    /// An unrecognised or absent type string.
    Unknown,
}

impl CellRadio {
    /// Classify from `termux-telephony-cellinfo`'s `type` string.
    #[must_use]
    pub fn from_type(cell_type: Option<&str>) -> Self {
        match cell_type.map(str::to_ascii_lowercase).as_deref() {
            Some("lte") => Self::Lte,
            Some("nr" | "5g") => Self::Nr,
            Some("umts" | "wcdma") => Self::Wcdma,
            Some("gsm") => Self::Gsm,
            _ => Self::Unknown,
        }
    }

    /// Stable lowercase technology tag.
    #[must_use]
    pub fn tech_tag(self) -> &'static str {
        match self {
            Self::Gsm => "gsm",
            Self::Wcdma => "umts",
            Self::Lte => "lte",
            Self::Nr => "nr",
            Self::Unknown => "unknown",
        }
    }
}

/// A cell identity component (`cid`/`ci`/`nci` or `lac`/`tac`) that survives the
/// unavailable-sentinel and zero filters, or `None` when the platform omitted it
/// or reported it unavailable.
#[must_use]
pub fn usable_cell_identity(raw: Option<i64>) -> Option<i64> {
    raw.filter(|&v| v != 0 && v != ANDROID_UNAVAILABLE)
}

/// A signal reading in dBm that is a real measurement, or `None` when it is the
/// unconditionally written `Integer.MAX_VALUE` sentinel. HSE `Cell::usable_dbm`.
#[must_use]
pub fn usable_dbm(raw: Option<i64>) -> Option<i64> {
    raw.filter(|&v| v != ANDROID_UNAVAILABLE)
}

/// The canonical `mcc-mnc-lac-cid` tower id — one authority so a coerced-string
/// caller and a typed-int caller yield the same id for the same tower.
#[must_use]
pub fn tower_id(mcc: &str, mnc: &str, area_code: i64, cid: i64) -> String {
    format!("{mcc}-{mnc}-{area_code}-{cid}")
}

/// True when `s` is a non-empty run of ASCII digits — the shape every segment of
/// a cell tower id must have to be a valid, re-feedable device id.
#[must_use]
pub fn is_numeric_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The canonical (lowercase, colon-separated) device MAC for a sighting — the
/// stable key it is tracked under — or `None` when `mac` is not a
/// canonicalisable address or is a placeholder sentinel. A non-MAC string never
/// becomes a key: an unstable, verbatim key would let the same device split
/// across formatting differences.
#[must_use]
pub fn sighting_key(mac: &str) -> Option<String> {
    canonical_device_mac(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_about_security_is_unknown_never_open() {
        for caps in [None, Some(""), Some("   ")] {
            let seen = wifi_observation("3c:5a:b4:11:22:01", caps, Some(-60), Some(2412)).unwrap();
            assert_eq!(seen.security, WifiSecurity::Unknown, "{caps:?}");
            assert!(!seen.enterprise);
        }
        // A real capabilities string with no security token is open, by the oracle.
        let open = wifi_observation("3c:5a:b4:11:22:01", Some("[ESS]"), None, None).unwrap();
        assert_eq!(open.security, WifiSecurity::Open);
    }

    #[test]
    fn an_observation_reads_security_and_enterprise_from_the_one_classifier() {
        for caps in [
            "[WPA2-EAP-CCMP][ESS]",
            "[RSN-SAE-CCMP][ESS]",
            "[WEP][ESS]",
            "[OWE][ESS]",
        ] {
            let seen = wifi_observation("3c:5a:b4:11:22:01", Some(caps), None, None).unwrap();
            assert_eq!(seen.security, wifi_security(Some(caps)), "{caps}");
            assert_eq!(seen.enterprise, wifi_is_enterprise(Some(caps)), "{caps}");
        }
    }

    #[test]
    fn a_wifi_observation_applies_every_reading_rule() {
        let seen = wifi_observation(
            "3c:5a:b4:11:22:01",
            Some("[WPA2-PSK-CCMP][ESS]"),
            Some(-48),
            Some(2437),
        )
        .expect("a real BSSID is an access point");
        assert_eq!(seen.trackability, AddressTrackability::Trackable);
        assert_eq!(seen.reliability, RssiReliability::VeryHighPlus);
        assert_eq!(seen.channel, Some(6));
        assert!(seen.proximity.is_some());
        assert_eq!(seen.security, WifiSecurity::Wpa2);

        let random = wifi_observation("aa:bb:cc:dd:ee:01", None, None, None).unwrap();
        assert_eq!(random.trackability, AddressTrackability::Randomized);
        assert_eq!(random.channel, None);
        assert_eq!(random.proximity, None);
        assert_eq!(random.reliability, RssiReliability::LowMedium);
        assert_eq!(random.security, WifiSecurity::Unknown);
    }

    #[test]
    fn a_placeholder_or_malformed_bssid_is_not_an_access_point() {
        for bssid in [
            "",
            "00:00:00:00:00:00",
            "02:00:00:00:00:00",
            "02-00-00-00-00-00",
            "nope",
        ] {
            assert_eq!(
                wifi_observation(bssid, Some("[ESS]"), Some(-40), Some(2412)),
                None,
                "{bssid}"
            );
        }
    }

    #[test]
    fn a_corrupt_positive_rssi_never_bands_as_close() {
        let seen = wifi_observation("3c:5a:b4:11:22:01", None, Some(5), Some(2412)).unwrap();
        assert_eq!(seen.reliability, RssiReliability::LowMedium);
        assert_eq!(seen.proximity, None);
    }

    #[test]
    fn placeholder_and_empty_addresses_are_not_devices() {
        assert!(!is_real_device_address(""));
        assert!(!is_real_device_address("00:00:00:00:00:00"));
        assert!(!is_real_device_address("02:00:00:00:00:00"));
        // Placeholders are rejected regardless of separator formatting.
        assert!(!is_real_device_address("00-00-00-00-00-00"));
        assert!(!is_real_device_address("02-00-00-00-00-00"));
        // A string that is not a MAC at all is not a real device address.
        assert!(!is_real_device_address("not-a-mac"));
        assert!(is_real_device_address("a4:c1:38:00:11:22"));
    }

    #[test]
    fn locally_administered_mac_is_randomized_never_trackable() {
        // U/L bit set in the first octet (0x02).
        assert_eq!(
            address_trackability("02:11:22:33:44:55"),
            AddressTrackability::Randomized
        );
        // Globally administered.
        assert_eq!(
            address_trackability("a4:c1:38:00:11:22"),
            AddressTrackability::Trackable
        );
        assert_eq!(
            address_trackability("not-a-mac"),
            AddressTrackability::Unknown
        );
    }

    #[test]
    fn ble_address_type_decides_trackability_not_the_ul_bit() {
        use AddressTrackability::{Randomized, Trackable, Unknown};
        use BleAddressType::{Public, Random};
        // A resolvable private address whose U/L bit is clear (0x4c): the
        // U/L rule calls it hardware; its type and subtype say it rotates.
        assert_eq!(address_trackability("4c:11:22:33:44:55"), Trackable);
        assert_eq!(
            ble_address_trackability("4c:11:22:33:44:55", Random),
            Randomized
        );
        // Random static (11), non-resolvable private (00), reserved (10).
        assert_eq!(
            ble_address_trackability("c0:de:be:ac:0d:01", Random),
            Trackable
        );
        assert_eq!(
            ble_address_trackability("0a:11:22:33:44:55", Random),
            Randomized
        );
        assert_eq!(
            ble_address_trackability("80:11:22:33:44:55", Random),
            Unknown
        );
        // Public is hardware whatever its bits look like.
        assert_eq!(
            ble_address_trackability("02:11:22:33:44:55", Public),
            Trackable
        );
        // No platform type: the U/L rule, unchanged.
        for mac in [
            "02:11:22:33:44:55",
            "a4:c1:38:00:11:22",
            "4c:11:22:33:44:55",
        ] {
            assert_eq!(
                ble_address_trackability(mac, BleAddressType::Unknown),
                address_trackability(mac)
            );
        }
        // Not a MAC: unknown under every type.
        for t in [Public, Random, BleAddressType::Unknown] {
            assert_eq!(ble_address_trackability("not-a-mac", t), Unknown);
        }
        assert_eq!(BleAddressType::from_android(0), Public);
        assert_eq!(BleAddressType::from_android(1), Random);
        assert_eq!(
            BleAddressType::from_android(0xFFFF),
            BleAddressType::Unknown
        );
        assert_eq!(BleAddressType::from_android(0xFF), BleAddressType::Unknown);
    }

    #[test]
    fn positive_wifi_rssi_is_corrupt_and_scores_worst() {
        assert_eq!(wifi_rssi_reliability(Some(10)), RssiReliability::LowMedium);
        assert_eq!(wifi_rssi_reliability(None), RssiReliability::LowMedium);
        assert_eq!(
            wifi_rssi_reliability(Some(-40)),
            RssiReliability::VeryHighPlus
        );
        assert_eq!(wifi_rssi_reliability(Some(-60)), RssiReliability::VeryHigh);
        assert_eq!(
            wifi_rssi_reliability(Some(-80)),
            RssiReliability::MediumPlus
        );
        assert_eq!(wifi_rssi_reliability(Some(-99)), RssiReliability::LowMedium);
    }

    #[test]
    fn wifi_channel_derives_from_centre_frequency() {
        assert_eq!(wifi_channel(Some(2412)), Some(1));
        assert_eq!(wifi_channel(Some(5180)), Some(36));
        assert_eq!(wifi_channel(None), None);
        assert_eq!(wifi_channel(Some(-1)), None);
    }

    #[test]
    fn wifi_proximity_absent_without_rssi() {
        assert!(wifi_proximity(None).is_none());
        assert!(wifi_proximity(Some(-40)).is_some());
        assert_eq!(wifi_proximity(Some(10)), None);
        assert_eq!(wifi_proximity(Some(ANDROID_UNAVAILABLE)), None);
        assert_eq!(wifi_proximity(Some(0)), Some(ProximityBand::Immediate));
    }

    #[test]
    fn cell_radio_maps_type_string() {
        assert_eq!(CellRadio::from_type(Some("lte")), CellRadio::Lte);
        assert_eq!(CellRadio::from_type(Some("5G")), CellRadio::Nr);
        assert_eq!(CellRadio::from_type(Some("WCDMA")), CellRadio::Wcdma);
        assert_eq!(CellRadio::from_type(None), CellRadio::Unknown);
        assert_eq!(CellRadio::Lte.tech_tag(), "lte");
    }

    #[test]
    fn cell_identity_rejects_zero_and_unavailable() {
        assert_eq!(usable_cell_identity(Some(222)), Some(222));
        assert_eq!(usable_cell_identity(Some(0)), None);
        assert_eq!(usable_cell_identity(Some(ANDROID_UNAVAILABLE)), None);
        assert_eq!(usable_cell_identity(None), None);
    }

    #[test]
    fn usable_dbm_rejects_the_written_sentinel() {
        assert_eq!(usable_dbm(Some(-80)), Some(-80));
        assert_eq!(usable_dbm(Some(ANDROID_UNAVAILABLE)), None);
        assert_eq!(usable_dbm(None), None);
    }

    #[test]
    fn tower_id_is_stable_and_segments_validated() {
        assert_eq!(tower_id("505", "1", 12345, 67890), "505-1-12345-67890");
        assert!(is_numeric_segment("505"));
        assert!(!is_numeric_segment(""));
        assert!(!is_numeric_segment("5a"));
        assert!(!is_numeric_segment("-1"));
    }

    #[test]
    fn sighting_key_canonicalises_and_rejects_placeholders() {
        assert_eq!(
            sighting_key("A4-C1-38-00-11-22").as_deref(),
            Some("a4:c1:38:00:11:22")
        );
        assert!(sighting_key("00:00:00:00:00:00").is_none());
        assert!(sighting_key("00-00-00-00-00-00").is_none());
        // A non-canonicalisable string never becomes an (unstable) key.
        assert!(sighting_key("not-a-mac").is_none());
    }
}
