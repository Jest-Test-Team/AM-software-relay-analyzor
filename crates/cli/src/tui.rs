//! Kaspersky-style two-pane TUI: device list (status dot, name, vendor, NEW,
//! risk badge) on the left, details + reasons + flows on the right.

use crate::assess::{assess_all, Opts};
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
use relay_core::{ConnectionStatus, Device, Flow, RiskLevel, Store};
use relay_intel::ti::Intel;
use relay_intel::OuiDb;
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
    pub flows: Vec<Flow>,
    pub self_ip: Option<IpAddr>,
    pub state: ListState,
    pub show_offline: bool,
    pub status: String,
    pub detail_scroll: u16,
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

pub fn draw(f: &mut Frame, app: &mut App) {
    let [main, footer] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(1)]).areas(f.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(main);
    draw_list(f, app, left);
    draw_detail(f, app, right);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            " ↑↓/jk ".bold(),
            "move  ".into(),
            "J/K ".bold(),
            "scroll details  ".into(),
            "a ".bold(),
            "ack  ".into(),
            "t ".bold(),
            "trust  ".into(),
            "o ".bold(),
            "offline  ".into(),
            "r ".bold(),
            "rescan  ".into(),
            "q ".bold(),
            "quit   ".into(),
            Span::raw(app.status.clone()).dim(),
        ])),
        footer,
    );
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
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
                "   ".into()
            } else {
                "NEW".fg(Color::Rgb(255, 140, 0)).bold()
            };
            let badge = format!(" {:<6}", format!("{:?}", a.level))
                .fg(level_color(a.level))
                .bold();
            ListItem::new(vec![
                Line::from(vec![
                    dot,
                    " ".into(),
                    Span::raw(format!(
                        "{:<28}",
                        crate::table::trunc(&d.display_name(), 28)
                    ))
                    .bold(),
                    new,
                    badge,
                ]),
                Line::from(vec![
                    "  ".into(),
                    Span::raw(format!(
                        "{:<15} {}",
                        d.ips
                            .iter()
                            .find(|i| i.is_ipv4())
                            .map(|i| i.to_string())
                            .unwrap_or_default(),
                        d.vendor_label()
                    ))
                    .dim(),
                ]),
            ])
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::bordered().title(format!(" Devices — {online} online / {} shown ", vis.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 90, 200))
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut app.state);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered().title(" Details ");
    let Some((d, a)) = app.selected() else {
        f.render_widget(
            Paragraph::new("No devices yet — run `relayscan discover --active`.").block(block),
            area,
        );
        return;
    };
    let kv = |k: &str, v: String| {
        Line::from(vec![
            Span::raw(format!("{k:<13}")).dim(),
            Span::raw(v).bold(),
        ])
    };
    let mut lines = vec![
        Line::from(vec![
            if d.acknowledged {
                "".into()
            } else {
                " NEW DEVICE "
                    .bg(Color::Rgb(255, 140, 0))
                    .fg(Color::White)
                    .bold()
            },
            " ".into(),
            Span::raw(d.display_name()).bold(),
        ]),
        Line::from(""),
        kv(
            "Last seen:",
            d.last_seen
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        ),
        kv("Status:", format!("{:?}", d.connection_status)),
        kv(
            "IP address:",
            d.ips
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        kv(
            "MAC address:",
            format!(
                "{}{}",
                d.mac,
                if d.mac_randomized {
                    "  (randomized)"
                } else {
                    ""
                }
            ),
        ),
        kv("Vendor:", d.vendor_label()),
        kv("Type:", d.device_type.as_str().to_string()),
        kv(
            "Trusted:",
            if d.trusted { "yes".into() } else { "no".into() },
        ),
        Line::from(""),
        Line::from(vec![
            Span::raw(format!("{:<13}", "Risk:")).dim(),
            Span::raw(format!(" {:?} ", a.level))
                .bg(level_color(a.level))
                .fg(Color::Black)
                .bold(),
            Span::raw(format!(
                "  score {}  confidence {:.0}%",
                a.score,
                a.confidence * 100.0
            )),
        ]),
    ];
    lines.push(Line::from(Span::raw(format!("  {}", a.summary)).italic()));
    if !a.reasons.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Why this score".dim()));
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
        lines.push(Line::from(
            format!("Confidence {:.0}% — built from", a.confidence * 100.0).dim(),
        ));
        for e in &a.evidence {
            let (mark, col) = if e.present {
                ("✔", Color::Green)
            } else {
                ("✘", Color::DarkGray)
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {mark} ")).fg(col),
                Span::raw(format!("{:<20}", e.factor)).bold(),
                Span::raw(format!("{:>4}  ", format!("+{:.0}", e.weight * 100.0))).fg(col),
                Span::raw(e.note.clone()).dim(),
            ]));
        }
    }
    if !a.actions.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Next steps".dim()));
        for (i, act) in a.actions.iter().enumerate() {
            lines.push(Line::from(format!("  {}. {act}", i + 1)));
        }
    }
    if app.self_ip.is_some_and(|ip| d.ips.contains(&ip)) && !app.flows.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Recent connections (this host)".dim()));
        for fl in app.flows.iter().take(12) {
            lines.push(Line::from(format!(
                "  {:<16} → {}:{} {}",
                crate::table::trunc(fl.process.as_deref().unwrap_or("?"), 16),
                fl.dst_ip,
                fl.dst_port,
                fl.state.as_deref().unwrap_or("")
            )));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
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
        app.rows = assess_all(
            ctx.store,
            net,
            &ctx.intel,
            &Opts {
                cfg: &ctx.cfg,
                window: Duration::minutes(60),
                baseline: Duration::days(7),
                offline: true,
            },
            Utc::now(),
        )?;
        app.self_ip = Some(IpAddr::V4(net.ip));
    }
    app.flows = ctx.store.flows_since(Utc::now() - Duration::minutes(10))?;
    let vis = app.visible();
    let idx = keep
        .and_then(|m| vis.iter().position(|(d, _)| d.mac == m))
        .or(if vis.is_empty() { None } else { Some(0) });
    app.state.select(idx);
    Ok(())
}

pub fn run(store: &mut Store, oui: &OuiDb, args: &Args) -> Result<()> {
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
        flows: vec![],
        self_ip: None,
        state: ListState::default(),
        show_offline: false,
        status: String::new(),
        detail_scroll: 0,
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
                        app.status = "scanning…".into();
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
                evidence: vec![relay_core::risk::Evidence {
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
            flows: vec![],
            self_ip: None,
            state: ListState::default().with_selected(Some(0)),
            show_offline: false,
            status: String::new(),
            detail_scroll: 0,
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
            flows: vec![],
            self_ip: None,
            state: ListState::default().with_selected(Some(0)),
            show_offline: false,
            status: String::new(),
            detail_scroll: 0,
        };
        app.move_by(5);
        assert_eq!(app.state.selected(), Some(1));
        app.move_by(-9);
        assert_eq!(app.state.selected(), Some(0));
    }
}
