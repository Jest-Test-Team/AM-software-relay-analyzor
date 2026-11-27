use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A 48-bit MAC address, normalised to lowercase, zero-padded hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Locally administered bit set: almost always a randomized / private MAC
    /// (iOS/Android/Windows privacy addresses). OUI lookup is meaningless.
    pub fn is_randomized(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    /// First three octets, as used for IEEE OUI lookup (e.g. `BCD074`).
    pub fn oui(&self) -> String {
        format!("{:02X}{:02X}{:02X}", self.0[0], self.0[1], self.0[2])
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mac({self})")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid MAC address: {0}")]
pub struct MacParseError(String);

impl FromStr for Mac {
    type Err = MacParseError;

    /// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-…`, and macOS's unpadded `2:7a:4a:2d:b5:9a`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(MacParseError(s.to_string()));
        }
        let mut out = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() || p.len() > 2 {
                return Err(MacParseError(s.to_string()));
            }
            out[i] = u8::from_str_radix(p, 16).map_err(|_| MacParseError(s.to_string()))?;
        }
        Ok(Mac(out))
    }
}

impl From<Mac> for String {
    fn from(m: Mac) -> String {
        m.to_string()
    }
}

impl TryFrom<String> for Mac {
    type Error = MacParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unpadded_macos_format() {
        let m: Mac = "2:7a:4a:2d:b5:9a".parse().unwrap();
        assert_eq!(m.to_string(), "02:7a:4a:2d:b5:9a");
        let m: Mac = "92:ef:1f:12:e:0".parse().unwrap();
        assert_eq!(m.to_string(), "92:ef:1f:12:0e:00");
    }

    #[test]
    fn randomized_detection_matches_screenshots() {
        // Android_OUJZGW45 and an "Unknown Device" from Kaspersky Smart Home Monitor.
        assert!("1a:9d:d1:46:63:73".parse::<Mac>().unwrap().is_randomized());
        assert!("5a:26:5d:31:3f:18".parse::<Mac>().unwrap().is_randomized());
        // Fortinet gateway: real burned-in OUI.
        let gw: Mac = "bc:d0:74:1e:5b:f1".parse().unwrap();
        assert!(!gw.is_randomized());
        assert_eq!(gw.oui(), "BCD074");
    }

    #[test]
    fn rejects_garbage() {
        assert!("(incomplete)".parse::<Mac>().is_err());
        assert!("aa:bb:cc".parse::<Mac>().is_err());
        assert!("aa:bb:cc:dd:ee:fff".parse::<Mac>().is_err());
    }
}
