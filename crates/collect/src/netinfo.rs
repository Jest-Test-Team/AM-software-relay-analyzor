//! Local interface facts: own IPv4/subnet/MAC and the default gateway.

use anyhow::{anyhow, Result};
use relay_core::Mac;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInfo {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<Mac>,
    pub gateway: Option<Ipv4Addr>,
}

impl NetInfo {
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) & mask(self.prefix))
    }

    /// Usable host addresses in the subnet, excluding network/broadcast and self.
    /// Refuses anything larger than a /22 (1022 hosts) to keep sweeps "light".
    pub fn sweep_targets(&self) -> Result<Vec<Ipv4Addr>> {
        if self.prefix < 22 {
            return Err(anyhow!(
                "/{} is too large for a light sweep (max /22); pass a narrower --cidr",
                self.prefix
            ));
        }
        Ok(hosts(self.network(), self.prefix)
            .filter(|ip| *ip != self.ip)
            .collect())
    }
}

pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

pub fn hosts(network: Ipv4Addr, prefix: u8) -> impl Iterator<Item = Ipv4Addr> {
    let base = u32::from(network) & mask(prefix);
    let size = 1u64 << (32 - prefix as u32);
    let (lo, hi) = if prefix >= 31 {
        (0, size)
    } else {
        (1, size - 1)
    };
    (lo..hi).map(move |i| Ipv4Addr::from(base + i as u32))
}

/// Parse `a.b.c.d/nn`.
pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, p) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("expected a.b.c.d/nn"))?;
    let prefix: u8 = p.parse()?;
    if prefix > 32 {
        return Err(anyhow!("prefix > 32"));
    }
    Ok((ip.parse()?, prefix))
}

/// Parse `ifconfig <iface>` output (macOS: hex netmask).
pub fn parse_ifconfig(iface: &str, text: &str) -> Option<NetInfo> {
    let mut ip = None;
    let mut prefix = None;
    let mut mac = None;
    for line in text.lines().map(str::trim) {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("ether") => mac = it.next().and_then(|m| m.parse().ok()),
            Some("inet") if ip.is_none() => {
                ip = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok());
                while let Some(tok) = it.next() {
                    if tok == "netmask" {
                        prefix = it.next().and_then(parse_netmask);
                    }
                }
            }
            _ => {}
        }
    }
    Some(NetInfo {
        iface: iface.to_string(),
        ip: ip?,
        prefix: prefix?,
        mac,
        gateway: None,
    })
}

fn parse_netmask(s: &str) -> Option<u8> {
    let bits = if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        u32::from(s.parse::<Ipv4Addr>().ok()?)
    };
    Some(bits.count_ones() as u8)
}

/// Parse `route -n get default` → (gateway, interface).
pub fn parse_route(text: &str) -> (Option<Ipv4Addr>, Option<String>) {
    let mut gw = None;
    let mut iface = None;
    for line in text.lines() {
        if let Some((k, v)) = line.trim().split_once(':') {
            match k.trim() {
                "gateway" => gw = v.trim().parse().ok(),
                "interface" => iface = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    (gw, iface)
}

/// Detect the interface (default route's unless given) and its addressing.
pub fn detect(iface: Option<&str>) -> Result<NetInfo> {
    let (gw, default_iface) = crate::run("route", &["-n", "get", "default"])
        .map(|t| parse_route(&t))
        .unwrap_or((None, None));
    let iface = iface
        .map(str::to_string)
        .or(default_iface)
        .ok_or_else(|| anyhow!("no default route; pass --iface"))?;
    let text = crate::run("ifconfig", &[&iface])?;
    let mut info =
        parse_ifconfig(&iface, &text).ok_or_else(|| anyhow!("{iface} has no IPv4 address"))?;
    // Only trust the gateway if it is on this interface's subnet.
    info.gateway = gw.filter(|g| u32::from(*g) & mask(info.prefix) == u32::from(info.network()));
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFCONFIG: &str = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
\tether 92:ef:1f:12:0e:00
\tinet6 fe80::1c2d:1a0f:4f3a:1b2c%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.50.2 netmask 0xffffff00 broadcast 192.168.50.255
\tstatus: active
";

    const ROUTE: &str = "   route to: default
destination: default
       mask: default
    gateway: 192.168.50.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";

    #[test]
    fn ifconfig_and_route() {
        let mut n = parse_ifconfig("en0", IFCONFIG).unwrap();
        assert_eq!(n.ip, Ipv4Addr::new(192, 168, 50, 2));
        assert_eq!(n.prefix, 24);
        assert!(n.mac.unwrap().is_randomized());
        let (gw, iface) = parse_route(ROUTE);
        assert_eq!(iface.as_deref(), Some("en0"));
        n.gateway = gw;
        assert_eq!(n.network(), Ipv4Addr::new(192, 168, 50, 0));
        let t = n.sweep_targets().unwrap();
        assert_eq!(t.len(), 253);
        assert!(!t.contains(&n.ip));
        assert_eq!(t[0], Ipv4Addr::new(192, 168, 50, 1));
        assert_eq!(*t.last().unwrap(), Ipv4Addr::new(192, 168, 50, 254));
    }

    #[test]
    fn refuses_big_subnets_and_parses_cidr() {
        let n = NetInfo {
            iface: "en0".into(),
            ip: Ipv4Addr::new(10, 0, 0, 5),
            prefix: 16,
            mac: None,
            gateway: None,
        };
        assert!(n.sweep_targets().is_err());
        assert_eq!(parse_cidr("10.0.0.0/30").unwrap().1, 30);
        assert_eq!(hosts(Ipv4Addr::new(10, 0, 0, 0), 30).count(), 2);
        assert_eq!(parse_netmask("255.255.252.0"), Some(22));
    }
}
