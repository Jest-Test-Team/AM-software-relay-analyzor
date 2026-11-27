//! Kaspersky-style two-pane TUI: device list (status dot, name, vendor, NEW,
//! risk badge, connection counts) on the left; details, reasons, confidence,
//! next steps and timestamped connections on the right. `L` switches
//! English / 繁體中文.

use crate::assess::{assess_all, counts_line, Opts};
use crate::table::pad;
use anyhow::Result;
use chrono::{Duration, Local, Utc};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use relay_collect::netinfo::{self, NetInfo};
use relay_core::risk::{Assessment, RiskConfig};
use relay_core::store::Flag;
use relay_core::{i18n, tr};
use relay_core::{ConnectionStatus, Device, Flow, FlowOutcome, Lang, Mac, RiskLevel, Store};
use relay_intel::ti::Intel;
use relay_intel::OuiDb;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    #[arg(long)]
    iface: Option<String>,
    #[arg(long, default_value = "data/feeds")]
    feeds: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    /// Seconds between automatic reloads from the store (pair with `watch`).
    #[arg(long, default_value_t = 5)]
    reload: u64,
}

pub struct App {
    pub rows: Vec<(Device, Assessment)>,
    /// Attributed flows per device, newest first.
    pub flows: HashMap<Mac, Vec<Flow>>,
    pub state: ListState,
    pub show_offline: bool,
    pub status: String,
    pub detail_scroll: u16,
    pub lang: Lang,
}

impl App {
    fn visible(&self) -> Vec<&(Device, Assessment)> {
        self.rows
            .iter()
            .filter(|(d, _)| self.show_offline || d.connection_status == ConnectionStatus::Online)
            .collect()
    }

    fn selected(&self) -> Option<&(Device, Assessment)> {
        self.visible().get(self.state.selected()?).copied()
    }

    fn move_by(&mut self, delta: i64) {
        let n = self.visible().len() as i64;
        if n == 0 {
            self.state.select(None);
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as i64;
        self.state
            .select(Some((cur + delta).clamp(0, n - 1) as usize));
    }
}

fn level_color(l: RiskLevel) -> Color {
    match l {
        RiskLevel::Green => Color::Green,
        RiskLevel::Yellow => Color::Yellow,
        RiskLevel::Orange => Color::Rgb(255, 140, 0),
        RiskLevel::Red => Color::Red,
        RiskLevel::Gray => Color::DarkGray,
    }
}

fn outcome_color(o: FlowOutcome) -> Color {
    match o {
        FlowOutcome::Active => Color::Green,
        FlowOutcome::Closed => Color::Gray,
        FlowOutcome::Failed => Color::Yellow,
        FlowOutcome::Denied => Color::Red,
    }
}

fn outcome_label(l: Lang, o: FlowOutcome) -> String {
    match o {
        FlowOutcome::Active => tr!(l, "connecting", "連線中"),
        FlowOutcome::Closed => tr!(l, "disconnected", "已中斷"),
        FlowOutcome::Failed => tr!(l, "failed", "失敗"),
        FlowOutcome::Denied => tr!(l, "denied", "被阻擋"),
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let l = app.lang;
    let [main, footer] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(1)]).areas(f.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(main);
    draw_list(f, app, left);
    draw_detail(f, app, right);
    let key = |k: &str, v: String| vec![Span::raw(format!(" {k} ")).bold(), Span::raw(v)];
    let mut spans = Vec::new();
    for (k, v) in [
        ("↑↓/jk", tr!(l, "move", "移動")),
        ("J/K", tr!(l, "scroll details", "捲動詳細資訊")),
        ("a", tr!(l, "ack", "確認")),
        ("t", tr!(l, "trust", "信任")),
        ("o", tr!(l, "offline", "離線裝置")),
        ("r", tr!(l, "rescan", "重新掃描")),
        ("L", tr!(l, "中文", "English")),
        ("q", tr!(l, "quit", "離開")),
    ] {
        spans.extend(key(k, v));
    }
    spans.push(Span::raw(format!("  {}", app.status)).dim());
    f.render_widget(Paragraph::new(Line::from(spans)), footer);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let l = app.lang;
    let vis = app.visible();
    let online = vis
        .iter()
        .filter(|(d, _)| d.connection_status == ConnectionStatus::Online)
        .count();
    let items: Vec<ListItem> = vis
        .iter()
        .map(|(d, a)| {
            let dot = match d.connection_status {
                ConnectionStatus::Online => "●".fg(Color::Green),
                ConnectionStatus::Offline => "●".fg(Color::DarkGray),
            };
            let new = if d.acknowledged {
                Span::raw(pad("", 6))
            } else {
                Span::raw(pad(&tr!(l, "NEW", "新裝置"), 6))
                    .fg(Color::Rgb(255, 140, 0))
                    .bold()
            };
            let badge = Span::raw(format!(" {}", i18n::level_short(l, a.level)))
                .fg(level_color(a.level))
                .bold();
            let conns = match &a.counts {
                Some(c) => vec![
                    Span::raw(format!("  ▲{}", c.active)).fg(Color::Green),
                    Span::raw(format!(" ●{}", c.closed)).fg(Color::Gray),
                    Span::raw(format!(" ✕{}", c.other())).fg(if c.other() > 0 {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }),
                ],
                None => vec![Span::raw(format!("  {}", tr!(l, "conn n/a", "連線 不適用"))).dim()],
            };
            let ip = d
                .ips
                .iter()
                .find(|i| i.is_ipv4())
                .map(|i| i.to_string())
                .unwrap_or_default();
            let mut row2 = vec![
                "  ".into(),
                Span::raw(format!(
                    "{} {}",
                    pad(&ip, 15),
                    pad(&i18n::vendor_label(l, d), 22)
                ))
                .dim(),
            ];
            row2.extend(conns);
            ListItem::new(vec![
                Line::from(vec![
                    dot,
                    " ".into(),
                    Span::raw(pad(&i18n::display_name(l, d), 28)).bold(),
                    new,
                    badge,
                ]),
                Line::from(row2),
            ])
        })
        .collect();
    let n = vis.len();
    let title = tr!(
        l,
        " Devices — {online} online / {n} shown ",
        " 裝置 — {online} 台在線／顯示 {n} 台 "
    );
    let list = List::new(items)
        .block(Block::bordered().title(title))
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 90, 200))
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut app.state);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let l = app.lang;
    let block = Block::bordered().title(tr!(l, " Details ", " 詳細資訊 "));
    let Some((d, a)) = app.selected() else {
        f.render_widget(
            Paragraph::new(tr!(
                l,
                "No devices yet — run `relayscan discover --active`.",
                "尚無裝置 — 請執行 `relayscan discover --active`。"
            ))
            .block(block),
            area,
        );
        return;
    };
    let kv =
        |k: String, v: String| Line::from(vec![Span::raw(pad(&k, 14)).dim(), Span::raw(v).bold()]);
    let mut lines = vec![
        Line::from(vec![
            if d.acknowledged {
                "".into()
            } else {
                Span::raw(tr!(l, " NEW DEVICE ", " 新裝置 "))
                    .bg(Color::Rgb(255, 140, 0))
                    .fg(Color::White)
                    .bold()
            },
            " ".into(),
            Span::raw(i18n::display_name(l, d)).bold(),
        ]),
        Line::from(""),
        kv(
            tr!(l, "Last seen:", "最後上線："),
            d.last_seen
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        ),
        kv(
            tr!(l, "Status:", "狀態："),
            i18n::status(l, d.connection_status),
        ),
        kv(
            tr!(l, "IP address:", "IP 位址："),
            d.ips
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        kv(
            tr!(l, "MAC address:", "MAC 位址："),
            format!(
                "{}{}",
                d.mac,
                if d.mac_randomized {
                    tr!(l, "  (randomized)", "（隨機化）")
                } else {
                    String::new()
                }
            ),
        ),
        kv(tr!(l, "Vendor:", "廠商："), i18n::vendor_label(l, d)),
        kv(
            tr!(l, "Type:", "類型："),
            i18n::device_type(l, d.device_type),
        ),
        kv(
            tr!(l, "Trusted:", "信任："),
            if d.trusted {
                tr!(l, "yes", "是")
            } else {
                tr!(l, "no", "否")
            },
        ),
        Line::from(""),
        Line::from(vec![
            Span::raw(pad(&tr!(l, "Risk:", "風險："), 14)).dim(),
            Span::raw(format!(" {} ", i18n::level(l, a.level)))
                .bg(level_color(a.level))
                .fg(Color::Black)
                .bold(),
            Span::raw(format!(
                "  {} {}  {} {:.0}%",
                tr!(l, "score", "分數"),
                a.score,
                tr!(l, "confidence", "信心度"),
                a.confidence * 100.0
            )),
        ]),
    ];
    lines.push(Line::from(Span::raw(format!("  {}", a.summary)).italic()));
    lines.push(Line::from(""));
    lines.push(Line::from(
        tr!(l, "Connections (last 60 min)", "連線數（最近 60 分鐘）").dim(),
    ));
    lines.push(Line::from(format!(
        "  {}",
        counts_line(l, a.counts.as_ref())
    )));
    if !a.reasons.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(
            tr!(l, "Why this score", "為什麼是這個分數").dim(),
        ));
    }
    for r in &a.reasons {
        lines.push(Line::from(vec![
            Span::raw(format!("  {:+4} ", r.delta)).fg(if r.delta > 0 {
                Color::Red
            } else {
                Color::Green
            }),
            Span::raw(r.detail.clone()),
        ]));
    }
    if !a.evidence.is_empty() {
        lines.push(Line::from(""));
        let pct = a.confidence * 100.0;
        lines.push(Line::from(
            tr!(
                l,
                "Confidence {pct:.0}% — built from",
                "信心度 {pct:.0}% — 構成如下"
            )
            .dim(),
        ));
        for e in &a.evidence {
            let (mark, col) = if e.present {
                ("✔", Color::Green)
            } else {
                ("✘", Color::DarkGray)
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {mark} ")).fg(col),
                Span::raw(pad(&e.factor, 20)).bold(),
                Span::raw(format!("{:>4}  ", format!("+{:.0}", e.weight * 100.0))).fg(col),
                Span::raw(e.note.clone()).dim(),
            ]));
        }
    }
    if !a.actions.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(tr!(l, "Next steps", "下一步").dim()));
        for (i, act) in a.actions.iter().enumerate() {
            lines.push(Line::from(format!("  {}. {act}", i + 1)));
        }
    }
    if let Some(fl) = app.flows.get(&d.mac).filter(|v| !v.is_empty()) {
        lines.push(Line::from(""));
        lines.push(Line::from(
            tr!(
                l,
                "Recent connections — last seen · since · app/process → destination · state",
                "最近連線 — 最後出現 · 開始於 · 應用/程序 → 目的地 · 狀態"
            )
            .dim(),
        ));
        for fl in fl.iter().take(15) {
            lines.push(Line::from(vec![
                Span::raw(format!(
                    "  {} ",
                    fl.last_seen.with_timezone(&Local).format("%H:%M:%S")
                ))
                .fg(Color::Cyan),
                Span::raw(format!(
                    "({} {}) ",
                    tr!(l, "since", "自"),
                    fl.first_seen.with_timezone(&Local).format("%m-%d %H:%M")
                ))
                .dim(),
                Span::raw(format!(
                    "{} → {}:{} ",
                    pad(fl.process.as_deref().unwrap_or("?"), 16),
                    fl.dst_ip,
                    fl.dst_port,
                )),
                Span::raw(outcome_label(l, fl.outcome)).fg(outcome_color(fl.outcome)),
                Span::raw(format!(" [{}]", fl.origin.as_str())).dim(),
            ]));
        }
        if fl.len() > 15 {
            let more = fl.len() - 15;
            lines.push(Line::from(
                tr!(
                    l,
                    "  … {more} more (relayscan flows)",
                    "  … 另有 {more} 條（relayscan flows）"
                )
                .dim(),
            ));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        area,
    );
}

struct Ctx<'a> {
    store: &'a mut Store,
    oui: &'a OuiDb,
    intel: Intel,
    cfg: RiskConfig,
    net: Option<NetInfo>,
    iface: Option<String>,
}

fn reload(ctx: &mut Ctx, app: &mut App) -> Result<()> {
    let keep = app.selected().map(|(d, _)| d.mac);
    if let Some(net) = &ctx.net {
        let res = assess_all(
            ctx.store,
            net,
            &ctx.intel,
            &Opts {
                cfg: &ctx.cfg,
                window: Duration::minutes(60),
                baseline: Duration::days(7),
                offline: true,
                lang: app.lang,
            },
            Utc::now(),
        )?;
        app.rows = res.rows;
        app.flows = res.flows;
        for v in app.flows.values_mut() {
            v.sort_by_key(|f| std::cmp::Reverse(f.last_seen));
        }
    }
    let vis = app.visible();
    let idx = keep
        .and_then(|m| vis.iter().position(|(d, _)| d.mac == m))
        .or(if vis.is_empty() { None } else { Some(0) });
    app.state.select(idx);
    Ok(())
}

pub fn run(store: &mut Store, oui: &OuiDb, args: &Args, lang: Lang) -> Result<()> {
    let mut ctx = Ctx {
        store,
        oui,
        intel: crate::intel::load(&args.feeds, false),
        cfg: crate::assess::load_config(args.config.as_deref())?,
        net: netinfo::detect(args.iface.as_deref()).ok(),
        iface: args.iface.clone(),
    };
    let mut app = App {
        rows: vec![],
        flows: HashMap::new(),
        state: ListState::default(),
        show_offline: false,
        status: String::new(),
        detail_scroll: 0,
        lang,
    };
    // Capture this host's connections up front (local nettop; no network
    // calls), so the self device is rated instead of showing Gray.
    app.status = rescan(&mut ctx).unwrap_or_else(|e| format!("initial scan failed: {e:#}"));
    reload(&mut ctx, &mut app)?;
    let mut terminal = ratatui::init();
    let res = event_loop(&mut terminal, &mut ctx, &mut app, args.reload);
    ratatui::restore();
    res
}

fn event_loop(
    term: &mut DefaultTerminal,
    ctx: &mut Ctx,
    app: &mut App,
    reload_s: u64,
) -> Result<()> {
    let mut last = std::time::Instant::now();
    loop {
        term.draw(|f| draw(f, app))?;
        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.move_by(1);
                        app.detail_scroll = 0;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.move_by(-1);
                        app.detail_scroll = 0;
                    }
                    KeyCode::Char('J') => app.detail_scroll = app.detail_scroll.saturating_add(3),
                    KeyCode::Char('K') => app.detail_scroll = app.detail_scroll.saturating_sub(3),
                    KeyCode::PageDown => app.move_by(10),
                    KeyCode::PageUp => app.move_by(-10),
                    KeyCode::Char('o') => {
                        app.show_offline = !app.show_offline;
                        app.move_by(0);
                    }
                    KeyCode::Char('L') | KeyCode::Char('l') => {
                        app.lang = app.lang.toggle();
                        reload(ctx, app)?;
                    }
                    KeyCode::Char('a') => {
                        if let Some((d, _)) = app.selected() {
                            ctx.store.set_flag(d.mac, Flag::Acknowledged, true)?;
                            reload(ctx, app)?;
                        }
                    }
                    KeyCode::Char('t') => {
                        if let Some((d, _)) = app.selected() {
                            let v = !d.trusted;
                            ctx.store.set_flag(d.mac, Flag::Trusted, v)?;
                            reload(ctx, app)?;
                        }
                    }
                    KeyCode::Char('r') => {
                        app.status = tr!(app.lang, "scanning…", "掃描中…");
                        term.draw(|f| draw(f, app))?;
                        app.status =
                            rescan(ctx).unwrap_or_else(|e| format!("rescan failed: {e:#}"));
                        reload(ctx, app)?;
                    }
                    _ => {}
                }
            }
        }
        if last.elapsed().as_secs() >= reload_s {
            reload(ctx, app)?;
            last = std::time::Instant::now();
        }
    }
}

/// Passive pass (ARP/NDP + flows) without printing to the terminal.
fn rescan(ctx: &mut Ctx) -> Result<String> {
    let net = netinfo::detect(ctx.iface.as_deref())?;
    let ictx = relay_intel::Context {
        gateway: net.gateway.map(IpAddr::V4),
        self_ip: Some(IpAddr::V4(net.ip)),
    };
    let enrich = relay_intel::enricher(ctx.oui, &ictx);
    let obs = relay_collect::arp::collect(Some(&net.iface))?;
    let r = ctx.store.ingest(&obs, &enrich)?;
    let (seen, _) = crate::flows::snapshot(ctx.store, &net)?;
    ctx.net = Some(net);
    Ok(format!(
        "rescanned {}: {} neighbours, {} new, {seen} connections",
        Local::now().format("%H:%M:%S"),
        r.observations,
        r.new_devices.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use relay_core::risk::{Reason, Signal};
    use relay_core::DeviceType;

    fn row(name: &str, mac: &str, level: RiskLevel, ack: bool) -> (Device, Assessment) {
        let now = Utc::now();
        let mac = mac.parse().unwrap();
        (
            Device {
                id: 1,
                mac,
                mac_randomized: false,
                vendor: Some("D-Link International".into()),
                hostname: Some(name.into()),
                mdns_name: None,
                device_type: DeviceType::Camera,
                ips: vec!["192.168.50.184".parse().unwrap()],
                services: vec![],
                first_seen: now,
                last_seen: now,
                connection_status: ConnectionStatus::Online,
                acknowledged: ack,
                trusted: false,
            },
            Assessment {
                mac,
                at: now,
                score: 100,
                level,
                confidence: 0.6,
                summary: "act now".into(),
                counts: None,
                lang: Lang::En,
                evidence: vec![relay_core::risk::Evidence {
                    key: "Traffic visible".into(),
                    factor: "Traffic visible".into(),
                    weight: 0.3,
                    present: false,
                    note: "not through this Mac".into(),
                }],
                actions: vec!["Isolate the device".into()],
                reasons: vec![Reason {
                    signal: Signal::IocHit,
                    delta: 100,
                    detail: "destination matches malicious IOC".into(),
                }],
            },
        )
    }

    #[test]
    fn renders_list_and_detail() {
        let mut app = App {
            rows: vec![row(
                "DCS-8525LH",
                "b0:c5:54:00:00:01",
                RiskLevel::Red,
                false,
            )],
            flows: HashMap::new(),
            state: ListState::default().with_selected(Some(0)),
            show_offline: false,
            status: String::new(),
            detail_scroll: 0,
            lang: Lang::En,
        };
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        for needle in [
            "Devices — 1 online",
            "DCS-8525LH",
            "NEW",
            "Red",
            "MAC address:",
            "b0:c5:54:00:00:01",
            "D-Link International",
            "+100",
            "malicious IOC",
        ] {
            assert!(text.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn navigation_clamps() {
        let mut app = App {
            rows: vec![
                row("a", "b0:c5:54:00:00:01", RiskLevel::Red, true),
                row("b", "b0:c5:54:00:00:02", RiskLevel::Gray, true),
            ],
            flows: HashMap::new(),
            state: ListState::default().with_selected(Some(0)),
            show_offline: false,
            status: String::new(),
            detail_scroll: 0,
            lang: Lang::En,
        };
        app.move_by(5);
        assert_eq!(app.state.selected(), Some(1));
        app.move_by(-9);
        assert_eq!(app.state.selected(), Some(0));
    }

    #[test]
    fn renders_traditional_chinese_with_counts_and_timestamps() {
        let (d, mut a) = row("DCS-8525LH", "b0:c5:54:00:00:01", RiskLevel::Red, false);
        a.evidence[0].factor = "流量可見".into();
        a.counts = Some(relay_core::ConnCounts {
            active: 2,
            closed: 5,
            failed: 1,
            ..Default::default()
        });
        let t = Utc::now();
        let flow = Flow {
            first_seen: t,
            last_seen: t,
            pid: None,
            process: Some("HTTPS".into()),
            proto: relay_core::Proto::Tcp,
            src_ip: "192.168.50.184".parse().unwrap(),
            src_port: 1,
            dst_ip: "198.51.100.7".parse().unwrap(),
            dst_port: 443,
            dst_mac: None,
            state: None,
            bytes_in: None,
            bytes_out: None,
            origin: relay_core::FlowOrigin::Fortigate,
            src_mac: None,
            outcome: FlowOutcome::Closed,
        };
        let mut app = App {
            flows: HashMap::from([(d.mac, vec![flow])]),
            rows: vec![(d, a)],
            state: ListState::default().with_selected(Some(0)),
            show_offline: false,
            status: String::new(),
            detail_scroll: 0,
            lang: Lang::ZhTw,
        };
        let mut term = Terminal::new(TestBackend::new(170, 60)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen_text(&term);
        let hhmmss = t.with_timezone(&Local).format("%H:%M:%S").to_string();
        for needle in [
            "裝置 — 1 台在線",
            "新裝置",
            "信心度",
            "下一步",
            "▲2",
            "●5",
            "✕1",
            "最近連線",
            "已中斷",
            "198.51.100.7:443",
            hhmmss.as_str(),
        ] {
            assert!(text.contains(needle), "missing {needle:?}");
        }
    }

    /// Wide (CJK) glyphs occupy two cells and the second cell holds a blank,
    /// so skip it to read the buffer as text.
    fn screen_text(term: &Terminal<TestBackend>) -> String {
        let mut text = String::new();
        let mut skip = 0;
        for c in term.backend().buffer().content() {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            text.push_str(c.symbol());
            skip = crate::table::width(c.symbol()).saturating_sub(1);
        }
        text
    }
}
