use crate::Mac;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Reachability only — NOT a security verdict (Kaspersky's green/gray dot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Online,
    Offline,
}

/// Security verdict, independent of connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Not enough information to judge.
    Gray,
    /// Known / trusted, low risk.
    Green,
    /// Suspicious, needs investigation.
    Yellow,
    /// High-risk connection or anomalous behaviour.
    Orange,
    /// Matches a known-malicious IOC.
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Router,
    Computer,
    Phone,
    Tablet,
    Tv,
    Speaker,
    Camera,
    Printer,
    Iot,
    Unknown,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Computer => "computer",
            Self::Phone => "phone",
            Self::Tablet => "tablet",
            Self::Tv => "tv",
            Self::Speaker => "speaker",
            Self::Camera => "camera",
            Self::Printer => "printer",
            Self::Iot => "iot",
            Self::Unknown => "unknown",
        }
    }

    /// Fallback display label (Kaspersky-style) when no name is known.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Router => "Router",
            Self::Computer => "Computer",
            Self::Phone => "Mobile Phone",
            Self::Tablet => "Tablet",
            Self::Tv => "TV",
            Self::Speaker => "Speaker",
            Self::Camera => "Camera",
            Self::Printer => "Printer",
            Self::Iot => "Smart Device",
            Self::Unknown => "Unknown Device",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "router" => Self::Router,
            "computer" => Self::Computer,
            "phone" => Self::Phone,
            "tablet" => Self::Tablet,
            "tv" => Self::Tv,
            "speaker" => Self::Speaker,
            "camera" => Self::Camera,
            "printer" => Self::Printer,
            "iot" => Self::Iot,
            _ => Self::Unknown,
        }
    }
}

/// Where an observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Arp,
    Ndp,
    Mdns,
    Ssdp,
    ReverseDns,
    Kaspersky,
    /// FortiGate traffic log / syslog / REST API (session or DHCP table).
    Fortigate,
    /// Zeek conn.log.
    Zeek,
}

/// One raw sighting produced by a collector. Collectors never write devices
/// directly; the store merges observations into `Device` rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub source: Source,
    pub seen_at: DateTime<Utc>,
    pub ip: Option<IpAddr>,
    pub mac: Option<Mac>,
    pub hostname: Option<String>,
    /// mDNS service types or SSDP server/ST strings, used for type inference.
    pub services: Vec<String>,
    pub interface: Option<String>,
}

impl Observation {
    pub fn new(source: Source, seen_at: DateTime<Utc>) -> Self {
        Self {
            source,
            seen_at,
            ip: None,
            mac: None,
            hostname: None,
            services: Vec::new(),
            interface: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub id: i64,
    pub mac: Mac,
    pub mac_randomized: bool,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub mdns_name: Option<String>,
    pub device_type: DeviceType,
    pub ips: Vec<IpAddr>,
    pub services: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub connection_status: ConnectionStatus,
    /// User has acknowledged the device (clears the "NEW" badge).
    pub acknowledged: bool,
    /// User marks the device as known-good.
    pub trusted: bool,
}

impl Device {
    /// Best human-readable name, mirroring what Kaspersky shows: a real name if
    /// known, otherwise a label derived from the inferred type.
    pub fn display_name(&self) -> String {
        self.hostname
            .clone()
            .or_else(|| self.mdns_name.clone())
            .unwrap_or_else(|| self.device_type.label().to_string())
    }

    /// Vendor line; randomized MACs have no meaningful OUI.
    pub fn vendor_label(&self) -> String {
        match (&self.vendor, self.mac_randomized) {
            (Some(v), _) => v.clone(),
            (None, true) => "Randomized MAC".to_string(),
            (None, false) => "Unknown vendor".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpBinding {
    pub mac: Mac,
    pub ip: IpAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Where a flow record came from. Only `Nettop` is local to this host; the
/// others are network sensors that see every device's traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum FlowOrigin {
    #[default]
    Nettop,
    Fortigate,
    Zeek,
}

impl FlowOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nettop => "nettop",
            Self::Fortigate => "fortigate",
            Self::Zeek => "zeek",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "fortigate" => Self::Fortigate,
            "zeek" => Self::Zeek,
            _ => Self::Nettop,
        }
    }
    /// Sensors see traffic of other devices; nettop only this host.
    pub fn is_sensor(&self) -> bool {
        !matches!(self, Self::Nettop)
    }
}

/// How a connection ended up, normalised across sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum FlowOutcome {
    /// Established / still running.
    #[default]
    Active,
    /// Finished normally.
    Closed,
    /// Never established or reset (SYN without answer, RST, timeout).
    Failed,
    /// Blocked by the firewall.
    Denied,
}

impl FlowOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Closed => "closed",
            Self::Failed => "failed",
            Self::Denied => "denied",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "closed" => Self::Closed,
            "failed" => Self::Failed,
            "denied" => Self::Denied,
            _ => Self::Active,
        }
    }
    /// Map a TCP state as printed by nettop/netstat.
    pub fn from_tcp_state(state: &str) -> Self {
        match state.to_ascii_lowercase().replace(['_', ' '], "").as_str() {
            "established" | "" => Self::Active,
            "closed" | "timewait" | "finwait1" | "finwait2" | "closing" => Self::Closed,
            "synsent" | "synreceived" | "closewait" | "lastack" => Self::Failed,
            _ => Self::Active,
        }
    }
}

/// Per-device connection tally: active / closed / other (failed, denied,
/// stale = "active" record that stopped being updated).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConnCounts {
    pub active: usize,
    pub closed: usize,
    pub failed: usize,
    pub denied: usize,
    pub stale: usize,
    pub last_closed: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub origins: Vec<FlowOrigin>,
}

impl ConnCounts {
    /// Minutes after which a still-"active" sensor record counts as stale. A
    /// nettop connection that vanished from the socket table is closed.
    pub const STALE_MINUTES: i64 = 15;

    pub fn tally<'a>(flows: impl IntoIterator<Item = &'a Flow>, now: DateTime<Utc>) -> Self {
        let mut c = Self::default();
        let stale = now - chrono::Duration::minutes(Self::STALE_MINUTES);
        let gone = now - chrono::Duration::minutes(5);
        for f in flows {
            if !c.origins.contains(&f.origin) {
                c.origins.push(f.origin);
            }
            c.last_seen = c.last_seen.max(Some(f.last_seen));
            let mut closed = || {
                c.closed += 1;
                c.last_closed = c.last_closed.max(Some(f.last_seen));
            };
            match f.outcome {
                FlowOutcome::Active if f.origin == FlowOrigin::Nettop && f.last_seen < gone => {
                    closed()
                }
                FlowOutcome::Active if f.origin.is_sensor() && f.last_seen < stale => {
                    c.stale += 1
                }
                FlowOutcome::Active => c.active += 1,
                FlowOutcome::Closed => closed(),
                FlowOutcome::Failed => c.failed += 1,
                FlowOutcome::Denied => c.denied += 1,
            }
        }
        c
    }
    pub fn other(&self) -> usize {
        self.failed + self.denied + self.stale
    }
    pub fn total(&self) -> usize {
        self.active + self.closed + self.other()
    }
}

/// A network connection observed on this host. `dst_mac` is only set when the
/// peer is on-link: a MAC can never be learned across a router, so we never
/// substitute the gateway's MAC for a remote server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    /// When this connection (5-tuple + pid) was first observed.
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub proto: Proto,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub dst_mac: Option<Mac>,
    pub state: Option<String>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    #[serde(default)]
    pub origin: FlowOrigin,
    /// Sender's MAC when the source reports it (FortiGate `srcmac`, Zeek
    /// `orig_l2_addr`); used to attribute the flow to a device.
    #[serde(default)]
    pub src_mac: Option<Mac>,
    #[serde(default)]
    pub outcome: FlowOutcome,
}

/// One threat-intelligence answer about an indicator (IP for now).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub indicator: IpAddr,
    pub source: String,
    /// High-confidence known-bad (IOC hit), as opposed to merely reported.
    pub malicious: bool,
    /// Number of independent reporters, where the source exposes it.
    pub reporters: Option<u32>,
    /// 0.0–1.0, the source's own confidence.
    pub confidence: f32,
    /// e.g. `botnet_cc`, `drop`, `abuse-reports`.
    pub category: String,
    pub detail: String,
    pub fetched_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn f(origin: FlowOrigin, outcome: FlowOutcome, age_min: i64, now: DateTime<Utc>) -> Flow {
        let t = now - Duration::minutes(age_min);
        Flow {
            first_seen: t,
            last_seen: t,
            pid: None,
            process: None,
            proto: Proto::Tcp,
            src_ip: "192.168.50.7".parse().unwrap(),
            src_port: 40000,
            dst_ip: "198.51.100.1".parse().unwrap(),
            dst_port: 443,
            dst_mac: None,
            state: None,
            bytes_in: None,
            bytes_out: None,
            origin,
            src_mac: None,
            outcome,
        }
    }

    #[test]
    fn tcp_state_mapping() {
        assert_eq!(FlowOutcome::from_tcp_state("Established"), FlowOutcome::Active);
        assert_eq!(FlowOutcome::from_tcp_state("TimeWait"), FlowOutcome::Closed);
        assert_eq!(FlowOutcome::from_tcp_state("SynSent"), FlowOutcome::Failed);
        assert_eq!(FlowOutcome::from_tcp_state(""), FlowOutcome::Active);
    }

    #[test]
    fn conn_counts_split_active_closed_other() {
        use FlowOrigin::*;
        use FlowOutcome::*;
        let now = Utc::now();
        let flows = [
            f(Fortigate, Active, 1, now),
            f(Fortigate, Active, 30, now), // stale
            f(Fortigate, Closed, 3, now),
            f(Fortigate, Denied, 2, now),
            f(Zeek, Failed, 2, now),
            f(Nettop, Active, 1, now),
            f(Nettop, Active, 10, now), // vanished from socket table → closed
        ];
        let c = ConnCounts::tally(&flows, now);
        assert_eq!((c.active, c.closed, c.other()), (2, 2, 3));
        assert_eq!((c.failed, c.denied, c.stale), (1, 1, 1));
        assert_eq!(c.total(), 7);
        assert_eq!(c.last_closed, Some(now - Duration::minutes(3)));
        assert_eq!(c.origins, vec![Fortigate, Zeek, Nettop]);
    }
}
