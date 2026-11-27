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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    /// Best human-readable name, mirroring what Kaspersky shows.
    pub fn display_name(&self) -> String {
        self.hostname
            .clone()
            .or_else(|| self.mdns_name.clone())
            .unwrap_or_else(|| "Unknown Device".to_string())
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

/// A network connection observed on this host. `dst_mac` is only set when the
/// peer is on-link: a MAC can never be learned across a router, so we never
/// substitute the gateway's MAC for a remote server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub ts: DateTime<Utc>,
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
}
