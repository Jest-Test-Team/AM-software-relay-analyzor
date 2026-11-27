//! SSDP / UPnP discovery (TVs, speakers, media renderers, cameras, routers).

use chrono::Utc;
use relay_core::{Observation, Source};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SsdpReply {
    pub server: Option<String>,
    pub st: Option<String>,
    pub location: Option<String>,
}

pub fn parse_reply(text: &str) -> SsdpReply {
    let mut r = SsdpReply::default();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = Some(v.trim().to_string());
            match k.trim().to_ascii_uppercase().as_str() {
                "SERVER" => r.server = v,
                "ST" => r.st = v,
                "LOCATION" => r.location = v,
                _ => {}
            }
        }
    }
    r
}

/// Extract `<friendlyName>` (and `<modelName>`) from a UPnP device description.
pub fn parse_description(xml: &str) -> (Option<String>, Option<String>) {
    let tag = |t: &str| {
        let open = format!("<{t}>");
        let s = xml.find(&open)? + open.len();
        let e = xml[s..].find(&format!("</{t}>"))? + s;
        Some(xml[s..e].trim().to_string()).filter(|v| !v.is_empty())
    };
    (tag("friendlyName"), tag("modelName"))
}

/// Fetch a description URL, but only from the responding LAN host itself.
fn fetch_description(location: &str, from: IpAddr) -> Option<String> {
    let rest = location.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
    let addr: SocketAddr = if hostport.contains(':') {
        hostport.parse().ok()?
    } else {
        SocketAddr::new(hostport.parse().ok()?, 80)
    };
    if addr.ip() != from {
        return None;
    }
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    write!(s, "GET /{path} HTTP/1.0\r\nHost: {hostport}\r\n\r\n").ok()?;
    let mut buf = Vec::new();
    let _ = s.take(256 * 1024).read_to_end(&mut buf);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn collect(wait: Duration) -> std::io::Result<Vec<Observation>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    sock.send_to(MSEARCH.as_bytes(), "239.255.255.250:1900")?;
    let deadline = Instant::now() + wait;
    let mut by_ip: HashMap<IpAddr, (Vec<String>, Option<String>)> = HashMap::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let reply = parse_reply(&String::from_utf8_lossy(&buf[..n]));
        let entry = by_ip.entry(from.ip()).or_default();
        for v in [reply.server, reply.st].into_iter().flatten() {
            if !entry.0.contains(&v) {
                entry.0.push(v);
            }
        }
        if entry.1.is_none() {
            entry.1 = reply.location;
        }
    }
    let now = Utc::now();
    Ok(by_ip
        .into_iter()
        .map(|(ip, (mut services, loc))| {
            let (name, model) = loc
                .and_then(|l| fetch_description(&l, ip))
                .map(|x| parse_description(&x))
                .unwrap_or((None, None));
            services.extend(model);
            Observation {
                ip: Some(ip),
                hostname: name,
                services,
                ..Observation::new(Source::Ssdp, now)
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reply_and_description() {
        let r = parse_reply("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.50.21:1880/desc.xml\r\nSERVER: WebOS/4.1.0 UPnP/1.0\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n");
        assert_eq!(r.server.as_deref(), Some("WebOS/4.1.0 UPnP/1.0"));
        assert_eq!(
            r.location.as_deref(),
            Some("http://192.168.50.21:1880/desc.xml")
        );
        let (n, m) = parse_description("<root><device><friendlyName>LGwebOSTV</friendlyName><modelName>OLED55</modelName></device></root>");
        assert_eq!(n.as_deref(), Some("LGwebOSTV"));
        assert_eq!(m.as_deref(), Some("OLED55"));
    }

    #[test]
    fn refuses_description_from_other_host() {
        assert!(
            fetch_description("http://8.8.8.8/x.xml", "192.168.50.21".parse().unwrap()).is_none()
        );
    }
}
