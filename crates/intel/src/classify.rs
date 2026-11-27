//! Rule-based device-type inference from vendor, hostname and advertised
//! services — mirroring the icons Kaspersky Smart Home Monitor shows.

use relay_core::{Device, DeviceType};
use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct Context {
    pub gateway: Option<IpAddr>,
    pub self_ip: Option<IpAddr>,
}

pub fn classify(d: &Device, ctx: &Context) -> DeviceType {
    if ctx.gateway.is_some_and(|g| d.ips.contains(&g)) {
        return DeviceType::Router;
    }
    let name = d
        .hostname
        .iter()
        .chain(d.mdns_name.iter())
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let vendor = d.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
    let svc = d.services.join(" ").to_ascii_lowercase();
    let has = |hay: &str, needles: &[&str]| needles.iter().any(|n| hay.contains(n));

    // 1. Hostname patterns are the strongest hint (and work for randomized MACs).
    if has(&name, &["dcs-", "ipcam", "camera", "cam-"]) {
        return DeviceType::Camera;
    }
    if has(&name, &["ipad", "tablet", "galaxy-tab"]) {
        return DeviceType::Tablet;
    }
    if has(
        &name,
        &[
            "android", "iphone", "pixel", "galaxy", "redmi", "oppo", "mobile",
        ],
    ) {
        return DeviceType::Phone;
    }
    if has(
        &name,
        &[
            "webos",
            "lgtv",
            "bravia",
            "roku",
            "chromecast",
            "-tv",
            "tv-",
            "appletv",
            "apple-tv",
        ],
    ) {
        return DeviceType::Tv;
    }
    if has(&name, &["mu-so", "sonos", "homepod", "speaker", "echo"]) {
        return DeviceType::Speaker;
    }
    if has(
        &name,
        &[
            "printer",
            "epson",
            "brother",
            "laserjet",
            "officejet",
            "canon",
        ],
    ) {
        return DeviceType::Printer;
    }
    if has(
        &name,
        &[
            "macbook",
            "imac",
            "mac-mini",
            "desktop-",
            "laptop-",
            "-pc",
            "thinkpad",
            "raspberrypi",
        ],
    ) {
        return DeviceType::Computer;
    }
    if has(
        &name,
        &["esp32", "esp-", "esp_", "tasmota", "shelly", "tuya"],
    ) {
        return DeviceType::Iot;
    }

    // 2. Advertised services (mDNS / SSDP).
    if has(&svc, &["_ipp.", "_printer.", "_pdl-datastream"]) {
        return DeviceType::Printer;
    }
    if has(&svc, &["_googlecast", "mediarenderer", "dial", "webos"]) {
        return DeviceType::Tv;
    }
    if has(&svc, &["_raop", "_spotify-connect", "_sonos"]) {
        return DeviceType::Speaker;
    }
    if has(&svc, &["_rtsp", "_onvif", "networkvideotransmitter"]) {
        return DeviceType::Camera;
    }
    if has(&svc, &["_hap.", "_matter", "_hue"]) {
        return DeviceType::Iot;
    }
    if has(
        &svc,
        &["_smb.", "_ssh.", "_sftp-ssh", "_rfb.", "_workstation"],
    ) {
        return DeviceType::Computer;
    }

    // 3. Vendor.
    if has(
        &vendor,
        &["espressif", "tuya", "shelly", "sonoff", "itead", "xiaomi"],
    ) {
        return DeviceType::Iot;
    }
    if has(
        &vendor,
        &[
            "hikvision",
            "dahua",
            "axis comm",
            "d-link",
            "reolink",
            "wyze",
        ],
    ) {
        return DeviceType::Camera;
    }
    if has(&vendor, &["raspberry pi"]) {
        return DeviceType::Computer;
    }
    if has(
        &vendor,
        &[
            "fortinet", "cisco", "ubiquiti", "mikrotik", "juniper", "aruba",
        ],
    ) {
        return DeviceType::Router;
    }
    DeviceType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use relay_core::ConnectionStatus;

    fn dev(host: Option<&str>, vendor: Option<&str>, services: &[&str], ip: &str) -> Device {
        let mac = "bc:d0:74:11:22:33".parse().unwrap();
        Device {
            id: 1,
            mac,
            mac_randomized: false,
            vendor: vendor.map(Into::into),
            hostname: host.map(Into::into),
            mdns_name: None,
            device_type: DeviceType::Unknown,
            ips: vec![ip.parse().unwrap()],
            services: services.iter().map(|s| s.to_string()).collect(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            connection_status: ConnectionStatus::Online,
            acknowledged: false,
            trusted: false,
        }
    }

    #[test]
    fn kaspersky_screenshot_devices() {
        let ctx = Context {
            gateway: Some("192.168.50.254".parse().unwrap()),
            self_ip: None,
        };
        let cases = [
            (
                dev(None, Some("Fortinet, Inc."), &[], "192.168.50.254"),
                DeviceType::Router,
            ),
            (
                dev(
                    Some("someones-MacBook-Pro"),
                    Some("Apple, Inc."),
                    &[],
                    "192.168.50.2",
                ),
                DeviceType::Computer,
            ),
            (
                dev(Some("Android_OUJZGW45"), None, &[], "192.168.50.112"),
                DeviceType::Phone,
            ),
            (
                dev(Some("Mo-IPAD-8"), Some("Apple, Inc."), &[], "192.168.50.20"),
                DeviceType::Tablet,
            ),
            (
                dev(Some("LGwebOSTV"), None, &[], "192.168.50.21"),
                DeviceType::Tv,
            ),
            (
                dev(
                    Some("Mu-so Qb-office"),
                    Some("Liteon Technology"),
                    &[],
                    "192.168.50.22",
                ),
                DeviceType::Speaker,
            ),
            (
                dev(
                    Some("DCS-8525LH-B0C554520"),
                    Some("D-Link International"),
                    &[],
                    "192.168.50.23",
                ),
                DeviceType::Camera,
            ),
            (
                dev(None, None, &["_googlecast._tcp"], "192.168.50.24"),
                DeviceType::Tv,
            ),
            (
                dev(None, Some("Espressif Inc."), &[], "192.168.50.25"),
                DeviceType::Iot,
            ),
            (dev(None, None, &[], "192.168.50.26"), DeviceType::Unknown),
        ];
        for (d, want) in cases {
            assert_eq!(classify(&d, &ctx), want, "{:?}", d.hostname);
        }
    }
}
