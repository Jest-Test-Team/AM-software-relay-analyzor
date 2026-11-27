use relay_core::{ConnectionStatus, Device};

pub fn print_devices(devs: &[Device]) {
    println!(
        "{:<2} {:<3} {:<15} {:<17} {:<9} {:<28} {:<26}",
        "", "", "IP", "MAC", "TYPE", "VENDOR", "NAME"
    );
    for d in devs {
        let dot = match d.connection_status {
            ConnectionStatus::Online => "●",
            ConnectionStatus::Offline => "○",
        };
        let flags = format!(
            "{}{}",
            if d.acknowledged { "" } else { "N" },
            if d.trusted { "T" } else { "" }
        );
        println!(
            "{:<2} {:<3} {:<15} {:<17} {:<9} {:<28} {:<26}",
            dot,
            flags,
            d.ips
                .iter()
                .find(|i| i.is_ipv4())
                .or(d.ips.first())
                .map(|i| i.to_string())
                .unwrap_or_default(),
            d.mac.to_string(),
            d.device_type.as_str(),
            trunc(&d.vendor_label(), 28),
            trunc(&d.display_name(), 26),
        );
    }
    println!(
        "{} devices  (● online ○ offline, N = new/unacknowledged, T = trusted)",
        devs.len()
    );
}

pub fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
