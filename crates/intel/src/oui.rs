//! IEEE MA-L (OUI) registry. Load `data/oui.csv` (see `scripts/fetch-oui.sh`).

use anyhow::{Context, Result};
use relay_core::Mac;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct OuiDb {
    map: HashMap<String, String>,
}

impl OuiDb {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading {}", path.as_ref().display()))?;
        Ok(Self::parse(&text))
    }

    /// Parse `Registry,Assignment,Organization Name,Organization Address`.
    pub fn parse(csv: &str) -> Self {
        let map = csv
            .lines()
            .skip(1)
            .filter_map(|line| {
                let f = split_csv(line);
                let (assign, org) = (f.get(1)?, f.get(2)?);
                (assign.len() == 6).then(|| (assign.to_ascii_uppercase(), org.trim().to_string()))
            })
            .collect();
        Self { map }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Vendor for a MAC. Randomized MACs never resolve (their OUI is fake).
    pub fn lookup(&self, mac: &Mac) -> Option<&str> {
        if mac.is_randomized() {
            return None;
        }
        self.map.get(&mac.oui()).map(String::as_str)
    }
}

/// Minimal RFC 4180 field splitter (quoted fields, doubled quotes).
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = r#"Registry,Assignment,Organization Name,Organization Address
MA-L,BCD074,"Apple, Inc.",1 Infinite Loop Cupertino CA US 95014
MA-L,00090F,"Fortinet, Inc.",1090 Kifer Road Sunnyvale CA US 94086
MA-L,1A9DD1,Bogus,should never match a randomized mac
MA-L,ABCDEF,"Quote ""Co""",x
"#;

    #[test]
    fn lookup() {
        let db = OuiDb::parse(CSV);
        assert_eq!(db.len(), 4);
        let gw: Mac = "0:9:f:aa:0:1a".parse().unwrap();
        assert_eq!(db.lookup(&gw), Some("Fortinet, Inc."));
        let rnd: Mac = "1a:9d:d1:46:63:73".parse().unwrap();
        assert_eq!(db.lookup(&rnd), None);
        assert_eq!(split_csv(r#"a,"Quote ""Co""",b"#)[1], r#"Quote "Co""#);
    }
}
