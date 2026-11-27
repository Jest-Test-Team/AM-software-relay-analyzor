//! Network sensors: sources that see *every* device's traffic, not just this
//! host's. A switched / Wi-Fi LAN only delivers this Mac its own unicast
//! traffic, so rating other devices needs the gateway (FortiGate) or a mirror
//! port (Zeek) to tell us what they talk to.
//!
//! Every sensor yields a [`Batch`]: flows (with `origin`, `src_mac`,
//! `outcome`) plus identity observations (MAC ↔ IP ↔ hostname) so devices the
//! sensor knows get a name even if mDNS never announced one.

pub mod fortigate;
pub mod fortigate_api;
pub mod zeek;

use relay_core::{Flow, Observation};

#[derive(Debug, Default, Clone)]
pub struct Batch {
    pub flows: Vec<Flow>,
    pub observations: Vec<Observation>,
    /// Lines/records that were not traffic or could not be parsed.
    pub skipped: usize,
}

impl Batch {
    pub fn extend(&mut self, other: Batch) {
        self.flows.extend(other.flows);
        self.observations.extend(other.observations);
        self.skipped += other.skipped;
    }
}

/// Split FortiOS-style `key=value key="quoted value"` text. Tokens without
/// `=` (e.g. a syslog `<189>` prefix or hostname) are ignored.
pub fn kv_pairs(line: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b' ' || b[i] == b',' || b[i] == b'\t') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && b[i] != b'=' && b[i] != b' ' && b[i] != b',' {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            continue; // bare token
        }
        let key = &line[ks..i];
        i += 1;
        let val = if i < b.len() && b[i] == b'"' {
            let vs = i + 1;
            let mut j = vs;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            i = (j + 1).min(b.len());
            &line[vs..j.min(b.len())]
        } else {
            let vs = i;
            while i < b.len() && b[i] != b' ' && b[i] != b',' {
                i += 1;
            }
            &line[vs..i]
        };
        if !key.is_empty() {
            out.push((key, val));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::kv_pairs;

    #[test]
    fn tokenizes_quoted_and_prefix() {
        let kv = kv_pairs(r#"<189>date=2026-11-27 srcname="Mu-so Qb 我的辦公室" proto=6 x"#);
        assert_eq!(
            kv,
            vec![
                ("<189>date", "2026-11-27"),
                ("srcname", "Mu-so Qb 我的辦公室"),
                ("proto", "6")
            ]
        );
    }
}
