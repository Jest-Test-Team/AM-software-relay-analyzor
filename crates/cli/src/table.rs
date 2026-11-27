use relay_core::{i18n, tr, ConnectionStatus, Device, Lang};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn print_devices(l: Lang, devs: &[Device]) {
    println!(
        "{:<2} {:<3} {} {} {} {} {}",
        "",
        "",
        pad("IP", 15),
        pad("MAC", 17),
        pad(&tr!(l, "TYPE", "類型"), 12),
        pad(&tr!(l, "VENDOR", "廠商"), 28),
        tr!(l, "NAME", "名稱"),
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
            "{:<2} {:<3} {} {} {} {} {}",
            dot,
            flags,
            pad(
                &d.ips
                    .iter()
                    .find(|i| i.is_ipv4())
                    .or(d.ips.first())
                    .map(|i| i.to_string())
                    .unwrap_or_default(),
                15
            ),
            pad(&d.mac.to_string(), 17),
            pad(&i18n::device_type(l, d.device_type), 12),
            pad(&i18n::vendor_label(l, d), 28),
            trunc(&i18n::display_name(l, d), 32),
        );
    }
    let n = devs.len();
    println!(
        "{}",
        tr!(
            l,
            "{n} devices  (● online ○ offline, N = new/unacknowledged, T = trusted)",
            "{n} 台裝置（● 在線 ○ 離線，N = 新裝置／未確認，T = 已信任）"
        )
    );
}

/// Display width in terminal cells (CJK characters take two).
pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Truncate to at most `n` terminal cells, adding "…" when cut.
pub fn trunc(s: &str, n: usize) -> String {
    if width(s) <= n {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(0);
        if w + cw + 1 > n {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// Truncate and left-align to exactly `n` cells (format!'s `{:<n}` counts
/// chars, which misaligns CJK text).
pub fn pad(s: &str, n: usize) -> String {
    let t = trunc(s, n);
    let w = width(&t);
    format!("{t}{}", " ".repeat(n.saturating_sub(w)))
}

pub fn pad_left(s: &str, n: usize) -> String {
    let t = trunc(s, n);
    format!("{}{t}", " ".repeat(n.saturating_sub(width(&t))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cjk_width_aware() {
        assert_eq!(width("Mu-so Qb-我的辦公室"), 19);
        assert_eq!(width(&pad("我的辦公室", 12)), 12);
        assert_eq!(width(&trunc("Mu-so Qb-我的辦公室", 12)), 12);
        assert_eq!(trunc("Mu-so Qb-我的辦公室", 12), "Mu-so Qb-我…");
        assert_eq!(pad("abc", 5), "abc  ");
    }
}
