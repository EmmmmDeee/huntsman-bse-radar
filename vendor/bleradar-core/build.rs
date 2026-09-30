//! Turns the Bluetooth SIG's `company_identifiers.yaml` — checked in verbatim
//! under `data/`, the one source of every manufacturer name the radar shows —
//! into the sorted lookup tables `adv::company_name` searches.
//!
//! The file is parsed strictly: a line the parser does not recognise fails the
//! build with its line number rather than dropping an entry, so a refreshed
//! file can never silently lose (or misread) a company. The generated tables
//! are three flat statics (ids, name end offsets, one concatenated name
//! string) instead of a `&[(u16, &str)]`, because a shared library must
//! relocate every pointer in the latter at load time and a flat layout has
//! exactly one.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

const SOURCE: &str = "data/company_identifiers.yaml";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(manifest.join(SOURCE))
        .unwrap_or_else(|error| panic!("reading {SOURCE}: {error}"));
    let companies = parse(&source);

    let mut ids = String::new();
    let mut ends = String::new();
    let mut names = String::new();
    for (id, name) in &companies {
        write!(ids, "{id:#06x},").expect("writing to a String");
        names.push_str(name);
        write!(ends, "{},", names.len()).expect("writing to a String");
    }
    let count = companies.len();
    let tables = format!(
        "static COMPANY_IDS: [u16; {count}] = [{ids}];\n\
         static COMPANY_NAME_ENDS: [u32; {count}] = [{ends}];\n"
    );

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out.join("company_tables.rs"), tables).expect("writing company_tables.rs");
    fs::write(out.join("company_names.txt"), names).expect("writing company_names.txt");
}

/// Every `(id, name)` of the file, ascending by id. Panics, naming the line,
/// on anything the SIG's format does not use.
fn parse(source: &str) -> Vec<(u16, String)> {
    let mut lines = source
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line));
    match lines.next() {
        Some((_, "company_identifiers:")) => {}
        other => panic!("{SOURCE}: expected `company_identifiers:` first, found {other:?}"),
    }

    let mut companies: Vec<(u16, String)> = Vec::new();
    while let Some((number, line)) = lines.next() {
        if line.is_empty() {
            continue;
        }
        let id = line
            .strip_prefix("  - value: 0x")
            .filter(|hex| hex.len() == 4)
            .and_then(|hex| u16::from_str_radix(hex, 16).ok())
            .unwrap_or_else(|| {
                panic!("{SOURCE}:{number}: expected `  - value: 0xHHHH`, found {line:?}")
            });
        let (name_number, name_line) = lines
            .next()
            .unwrap_or_else(|| panic!("{SOURCE}:{number}: the file ends after a value"));
        let scalar = name_line.strip_prefix("    name: ").unwrap_or_else(|| {
            panic!("{SOURCE}:{name_number}: expected `    name: ...`, found {name_line:?}")
        });
        let name = unquote(scalar)
            .unwrap_or_else(|reason| panic!("{SOURCE}:{name_number}: {reason} in {scalar:?}"));
        assert!(!name.is_empty(), "{SOURCE}:{name_number}: empty name");
        companies.push((id, name));
    }

    companies.sort_by_key(|&(id, _)| id);
    if let Some(pair) = companies.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        panic!("{SOURCE}: id {:#06x} is assigned twice", pair[0].0);
    }
    assert!(!companies.is_empty(), "{SOURCE}: no company at all");
    companies
}

/// The text of a YAML single- (`''` is a quote) or double-quoted (`\\` and
/// `\"` only) scalar; anything else is refused.
fn unquote(scalar: &str) -> Result<String, String> {
    if let Some(inner) = scalar.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' && chars.next() != Some('\'') {
                return Err("a lone quote inside a single-quoted scalar".to_string());
            }
            out.push(c);
        }
        return Ok(out);
    }
    if let Some(inner) = scalar.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Err("an unescaped quote inside a double-quoted scalar".to_string()),
                '\\' => match chars.next() {
                    Some(escaped @ ('\\' | '"')) => out.push(escaped),
                    other => return Err(format!("the unsupported escape \\{other:?}")),
                },
                other => out.push(other),
            }
        }
        return Ok(out);
    }
    Err("a scalar that is not quoted".to_string())
}
