//! Canonical entity tag string constants, ported from the Huntsman Search
//! Engine (HSE) `hse-core::tags` module (see `docs/HSE_IMPORT.md`). One
//! definition per tag so a tag one module emits and another matches on can't
//! drift in spelling.
//!
//! A tag records **how a value was learned, or what it is** — never a
//! conclusion. What a tag *causes* lives in the pass or rule that reads it.
//!
//! In this crate the tags label [`crate::HseEntity`] values (see
//! [`crate::entity`]); several also map directly onto the radar domain
//! (`WIFI_AP`/`CELL_TOWER` presence corroboration without a GPS fix,
//! `GEOLOCATION_LEAD` for an address worth geolocating that is not itself a
//! location, `HOSTING`/`COARSE`/`REGISTRANT` for keeping infrastructure and
//! imprecise places out of a subject's physical footprint).

// Provenance / collection channel
/// The value came out of a **breach corpus** — a compromised-credential dump or
/// a breach-search provider's index.
pub const BREACH: &str = "breach";
/// The value came from an **infostealer log** specifically — malware exfil from
/// an infected device, not a service-side database breach.
///
/// Narrower and more serious than [`BREACH`]: it implies a compromised *device*.
pub const STEALER_LOG: &str = "stealer-log";
/// Observed over HTTP(S) by a module that fetched the host itself.
pub const WEB: &str = "web";
/// Reached by this scan's own crawler, as opposed to being reported by a
/// third-party index. Always accompanies [`WEB`] on crawled output.
pub const CRAWLED: &str = "crawled";
/// A domain that is a **subdomain of the target**, not an independent one.
pub const SUBDOMAIN: &str = "subdomain";
/// Points **away from the target** — an off-site link, an MX host in someone
/// else's zone, a third-party reference. Marks the value as related-to but not
/// owned-by the subject.
pub const EXTERNAL: &str = "external";
/// Lifted from **rendered page text** rather than a structured API field.
/// Text-mined values carry the extractor's false-positive risk, which a typed
/// API field does not.
pub const WEB_SCRAPED: &str = "web-scraped";
/// Recovered from a **Certificate Transparency log** — a SAN or issuer field in
/// a publicly logged certificate.
pub const CT_LOG: &str = "ct-log";
/// A domain derived from an IP's **reverse-DNS (PTR) record**. The operator of
/// the address chose this name, so it evidences hosting rather than ownership.
pub const PTR: &str = "ptr";
/// The identifier appears across an unusually **large number of breaches**, as
/// judged by the emitting provider's own count.
pub const HIGH_EXPOSURE: &str = "high-exposure";
/// The value was published in a **paste** (Pastebin and similar), rather than in
/// a breach dump.
pub const PASTE_EXPOSED: &str = "paste-exposed";
/// A **password or credential** for this identity is present in the source
/// corpus — not merely the identity's existence in a breach.
pub const PASSWORD_AT_RISK: &str = "password-at-risk";
/// The identity appears on **more than one compromised device** in stealer-log
/// data, which distinguishes a reused personal account from a one-off infection.
pub const MULTI_DEVICE: &str = "multi-device";
/// The crawled host is **missing security response headers**. A property of the
/// server's configuration, recorded as exposure context.
pub const MISSING_SECURITY_HEADERS: &str = "missing-security-headers";

// Geolocation
/// The location came from a **geospatial source** — a gazetteer/OSM lookup, a
/// mail-header trace, an externally-published address — rather than being
/// inferred from the entity's own text.
pub const GEOINT: &str = "geoint";
/// An IP worth geolocating, but **not itself a location**. Carried by addresses
/// that breach and stealer-log records attach to an identity.
///
/// It is a no-fabrication device: the module states "here is where to look"
/// instead of emitting coordinates it cannot stand behind.
pub const GEOLOCATION_LEAD: &str = "geolocation-lead";
/// The place is **an area, not a point** — a postcode, suburb or city centroid
/// standing in for a precise address.
///
/// A coarse place is still admissible as evidence, but must not be cross-scan
/// bridged, must not link a household, and must not be pivoted for recursive
/// expansion.
pub const COARSE: &str = "coarse";
/// Datacenter / CDN / cloud-host location, not a residence. Carried by
/// coordinates that geolocate a hosting IP (e.g. a Cloudflare edge), so
/// area-of-operation rules can exclude them from a person's footprint.
pub const HOSTING: &str = "hosting";
/// Shared / third-party **platform infrastructure** — cloud-storage buckets,
/// datacenter/CDN hosting endpoints, and third-party analytics IDs. Not
/// subject-owned, so default reports suppress it and location rules keep it
/// out of the subject's physical footprint.
pub const PLATFORM_INFRA: &str = "platform-infra";
/// A WHOIS/RDAP **registrant** location — the domain owner's filing or privacy
/// address (often a registrar's privacy service), not the scan subject's home.
pub const REGISTRANT: &str = "registrant";

// Device / local
/// A **Wi-Fi access point** — observed by the on-device radio scan, or looked up
/// in a wardriving database by BSSID. Counts as a LAN-adjacency signal and as
/// passive corroboration of physical presence, independent of any GPS fix.
pub const WIFI_AP: &str = "wifi-ap";
/// A **cellular tower** the device observed, or one resolved from a
/// `MCC/MNC/LAC/CID` against a tower database. Like [`WIFI_AP`], it corroborates
/// presence in the geo profile without depending on a satellite fix.
pub const CELL_TOWER: &str = "cell-tower";
/// Seen in the device's own **ARP table** — a host on the same layer-2 segment.
pub const LOCAL_ARP: &str = "local-arp";
/// An address **belonging to a local network interface** of the device running
/// the scan, rather than to a discovered peer.
pub const LOCAL_INTERFACE: &str = "local-interface";

// Reputation / threat
/// A **threat-intelligence provider reported on this entity** — the neutral
/// fact of a reputation lookup having returned something, which is not the same
/// as a bad verdict. [`MALICIOUS`] is the verdict.
pub const THREAT_INTEL: &str = "threat-intel";
/// A reputation source **judged this entity malicious**. One opinion is not
/// acted on: escalation requires the entity to be non-benign infrastructure
/// *and* corroborated by at least two sources.
pub const MALICIOUS: &str = "malicious";
/// The address is a **Tor exit node**. An attribution caveat: it says traffic
/// was relayed, not that the subject was at that address.
pub const TOR_EXIT: &str = "tor-exit";
/// The address is a **proxy**. Like [`TOR_EXIT`], an attribution caveat: it
/// breaks the link between the address and a physical location.
pub const PROXY: &str = "proxy";
/// The address belongs to a **VPN** provider — the same attribution caveat as
/// [`PROXY`] and [`TOR_EXIT`].
pub const VPN: &str = "vpn";
/// The host or resource is **exposed or misconfigured** — an AXFR-open zone, a
/// world-readable storage bucket, a service a scanner flagged. Defensive by
/// construction: it records that an exposure exists, not how to use it.
pub const VULNERABLE: &str = "vulnerable";

// Sanctions / regulatory risk
/// Listed on a sanctions list (OFAC SDN, UN, EU, DFAT, …).
pub const SANCTIONED: &str = "sanctioned";
/// Politically Exposed Person — an official/political role that elevates
/// corruption/bribery risk under AML/CTF due-diligence conventions.
pub const PEP: &str = "pep";
/// Debarred from public contracting (World Bank, IDB, and similar
/// multilateral debarment lists).
pub const DEBARRED: &str = "debarred";

// Identity
/// The entity is a **social-media or community profile** — a platform account
/// page, or a URL that resolves to one.
pub const SOCIAL_PROFILE: &str = "social-profile";
/// **Quarantine.** The value is plausible but unconfirmed — a same-name breach
/// record that may be a namesake, a geocode that resolved off-region, a
/// generated username variant never verified to exist.
///
/// The most consequential tag in this module, and the only one with a
/// lifecycle: a quarantined entity is held out of shareable exports, timelines,
/// cross-scan bridging, exposure scoring, and correlation inputs. Clearing it
/// requires evidence rather than time — merging with a non-candidate
/// observation of the same value, or a geo-corroboration pass resolving the
/// namesake doubt. Its absence is therefore load bearing — never add it to
/// something already confirmed, and never strip it without that evidence.
pub const CANDIDATE: &str = "candidate";

// Discovery method
/// Found via a **search engine or web archive** result, rather than by querying
/// a source that holds the data itself.
pub const SEARCH_DISCOVERED: &str = "search-discovered";
/// **Derived from** a breach record rather than published in one — a domain
/// split out of a breached email address, for example.
pub const BREACH_DERIVED: &str = "breach-derived";
/// Entity injected from the persistent store at scan start — prior-scan
/// knowledge recalled so the local database acts as a source, not just a sink.
pub const RECALLED: &str = "recalled";

// Lifecycle gates — the spelling of each of the three below silently gates a
// grounding/expansion decision in `HseEntity`, so a reader typo would disable
// a gate with no compiler error. They are constants for the same anti-drift
// reason every other tag here is.
/// A **deterministic transform** of data already in the graph (a parse,
/// canonicalisation, permutation), carrying no independent observation. Gates
/// the source-count grounding rule: a derivation's own evidence must not count
/// as an independent corroborating source.
pub const DERIVED: &str = "derived";
/// A value **recycled** from a prior scan / the store rather than freshly
/// observed this scan. Read alongside `source_count` to gate expansion of a
/// still-uncorroborated recalled value.
pub const RECYCLED: &str = "recycled";
/// A username/handle **derived from a name permutation** rather than observed
/// on a platform. Gates expansion so an unconfirmed name-permutation guess does
/// not fan out as though it were a sighting.
pub const NAME_DERIVED: &str = "name-derived";

// Document references
/// A **document in a public corpus** the subject was searched in — a court
/// judgment, an archived newspaper article, a search hit on a court-record
/// host — surfaced as a URL the operator can open and read.
///
/// A document's text names third parties by its nature (the judge, counsel,
/// witnesses and the opposing party; a newspaper page's other subjects), and
/// the engine cannot tell which of the names, addresses and phone numbers mined
/// from it relate to the subject. So it is **never pivoted on**: the URL is
/// delivered as evidence to read rather than a seed to mine, the same
/// discipline [`COARSE`] applies to an imprecise place.
pub const SOURCE_DOCUMENT: &str = "source-document";
