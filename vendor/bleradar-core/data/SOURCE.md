# Bluetooth SIG company identifiers

`company_identifiers.yaml` is the Bluetooth SIG's own Assigned Numbers file, checked in
verbatim. `../build.rs` turns it into the tables behind `bleradar_core::adv::company_name`,
and nothing else names a manufacturer.

| | |
|---|---|
| Upstream | https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml |
| Retrieved | 2026-09-29 |
| Entries | 4041 (0x0000 to 0x112a) |
| SHA-256 | 2cde011f0c16603b456eec01d086be5ddf2abc28fba062ee1a9bcf2c5baaba43 |

Refresh with `cargo xtask sync-company-ids`: it downloads the file, checks it, runs the
core's registry tests against it and restores the previous file if they fail, then
rewrites this record. `cargo xtask`'s own tests hold this record to the data file.
