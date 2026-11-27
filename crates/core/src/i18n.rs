//! English / Traditional Chinese (zh-TW). Every user-facing string is written
//! with both languages side by side via [`tr!`], so a missing translation is a
//! compile error rather than a silent English fallback.

use crate::model::{ConnectionStatus, Device, DeviceType, RiskLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Lang {
    #[default]
    En,
    ZhTw,
}

/// `tr!(lang, "english {x}", "中文 {x}", args...)` → `String`.
#[macro_export]
macro_rules! tr {
    ($lang:expr, $en:literal, $zh:literal $(, $arg:expr)* $(,)?) => {
        match $lang {
            $crate::i18n::Lang::En => format!($en $(, $arg)*),
            $crate::i18n::Lang::ZhTw => format!($zh $(, $arg)*),
        }
    };
}

impl Lang {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        if s.starts_with("zh-tw")
            || s.starts_with("zh-hant")
            || s.starts_with("zh-hk")
            || s == "zh"
            || s == "tw"
        {
            Some(Self::ZhTw)
        } else if s.starts_with("en") || s == "c" || s == "posix" {
            Some(Self::En)
        } else {
            None
        }
    }

    /// `--lang` flag → `RELAYSCAN_LANG` → `LC_ALL` / `LC_MESSAGES` / `LANG` →
    /// macOS `AppleLanguages` → English.
    pub fn detect(flag: Option<&str>, env: &dyn Fn(&str) -> Option<String>) -> Self {
        if let Some(l) = flag.and_then(Self::parse) {
            return l;
        }
        for var in ["RELAYSCAN_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Some(v) = env(var).filter(|v| !v.is_empty()) {
                // "C"/"en_US.UTF-8" are explicit choices; unknown values fall through.
                if let Some(l) = Self::parse(&v) {
                    return l;
                }
            }
        }
        #[cfg(target_os = "macos")]
        if let Ok(out) = std::process::Command::new("defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(first) = s
                .split(['"', '(', ',', '\n'])
                .map(str::trim)
                .find(|t| !t.is_empty())
            {
                if let Some(l) = Self::parse(first) {
                    return l;
                }
            }
        }
        Self::En
    }

    pub fn toggle(self) -> Self {
        match self {
            Self::En => Self::ZhTw,
            Self::ZhTw => Self::En,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhTw => "zh-TW",
        }
    }
}

pub fn level(l: Lang, lv: RiskLevel) -> String {
    match lv {
        RiskLevel::Green => tr!(l, "Green", "綠色·低風險"),
        RiskLevel::Yellow => tr!(l, "Yellow", "黃色·可疑"),
        RiskLevel::Orange => tr!(l, "Orange", "橙色·高風險"),
        RiskLevel::Red => tr!(l, "Red", "紅色·危急"),
        RiskLevel::Gray => tr!(l, "Gray", "灰色·無法判定"),
    }
}

/// Short form for list badges.
pub fn level_short(l: Lang, lv: RiskLevel) -> String {
    match lv {
        RiskLevel::Green => tr!(l, "Green", "綠"),
        RiskLevel::Yellow => tr!(l, "Yellow", "黃"),
        RiskLevel::Orange => tr!(l, "Orange", "橙"),
        RiskLevel::Red => tr!(l, "Red", "紅"),
        RiskLevel::Gray => tr!(l, "Gray", "灰"),
    }
}

pub fn status(l: Lang, s: ConnectionStatus) -> String {
    match s {
        ConnectionStatus::Online => tr!(l, "Online", "在線"),
        ConnectionStatus::Offline => tr!(l, "Offline", "離線"),
    }
}

pub fn device_type(l: Lang, t: DeviceType) -> String {
    match t {
        DeviceType::Router => tr!(l, "Router", "路由器"),
        DeviceType::Computer => tr!(l, "Computer", "電腦"),
        DeviceType::Phone => tr!(l, "Mobile Phone", "手機"),
        DeviceType::Tablet => tr!(l, "Tablet", "平板"),
        DeviceType::Tv => tr!(l, "TV", "電視"),
        DeviceType::Camera => tr!(l, "Camera", "攝影機"),
        DeviceType::Printer => tr!(l, "Printer", "印表機"),
        DeviceType::Speaker => tr!(l, "Speaker", "音響"),
        DeviceType::Iot => tr!(l, "Smart Device", "智慧裝置"),
        DeviceType::Unknown => tr!(l, "Unknown Device", "未知裝置"),
    }
}

/// Like `Device::display_name`, with the type fallback translated.
pub fn display_name(l: Lang, d: &Device) -> String {
    d.hostname
        .clone()
        .or_else(|| d.mdns_name.clone())
        .unwrap_or_else(|| device_type(l, d.device_type))
}

pub fn vendor_label(l: Lang, d: &Device) -> String {
    match (&d.vendor, d.mac_randomized) {
        (Some(v), _) => v.clone(),
        (None, true) => tr!(l, "Randomized MAC", "隨機化 MAC"),
        (None, false) => tr!(l, "Unknown vendor", "未知廠商"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_precedence() {
        let env = |k: &str| match k {
            "LANG" => Some("zh_TW.UTF-8".to_string()),
            _ => None,
        };
        assert_eq!(Lang::detect(Some("en"), &env), Lang::En, "flag wins");
        assert_eq!(Lang::detect(None, &env), Lang::ZhTw, "LANG");
        let env2 = |k: &str| match k {
            "RELAYSCAN_LANG" => Some("en".to_string()),
            "LANG" => Some("zh_TW.UTF-8".to_string()),
            _ => None,
        };
        assert_eq!(
            Lang::detect(None, &env2),
            Lang::En,
            "RELAYSCAN_LANG beats LANG"
        );
        assert_eq!(Lang::detect(Some("zh-Hant"), &env2), Lang::ZhTw);
        assert_eq!(Lang::parse("zh_TW.UTF-8"), Some(Lang::ZhTw));
        assert_eq!(Lang::parse("fr_FR"), None);
    }

    #[test]
    fn tr_macro_formats_both() {
        let n = 3;
        assert_eq!(tr!(Lang::En, "{n} devices", "{n} 台裝置"), "3 devices");
        assert_eq!(tr!(Lang::ZhTw, "{n} devices", "{n} 台裝置"), "3 台裝置");
    }
}
