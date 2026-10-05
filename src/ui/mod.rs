//! Rendering. Pure functions of [`App`] state.

pub mod modals;
pub mod pages;
pub mod theme;
pub mod widgets;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::app::modal::Level;
use crate::app::{App, Page};
use widgets::*;

pub fn render(app: &App, f: &mut Frame) {
    let t = &app.theme;
    let area = f.area();
    f.render_widget(Block::default().style(t.base()), area);

    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);
    render_header(app, f, header);

    let narrow = area.width < 90;
    let side_w = if narrow { 5 } else { 24 };
    let [side, content] =
        Layout::horizontal([Constraint::Length(side_w), Constraint::Min(30)]).areas(body);
    render_sidebar(app, f, side, narrow);
    pages::render_page(app, f, content);
    render_footer(app, f, footer);

    if app.reset.is_some() {
        modals::render_reset(app, f, area);
    }
    if let Some(m) = &app.modal {
        modals::render_modal(app, m, f, area);
    }
    if let Some(b) = &app.busy {
        modals::render_busy(app, b, f, area);
    }
}

fn render_header(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let mut left = vec![
        Span::styled(" ◆ fido2-tui ", t.badge(t.accent)),
        Span::raw(" "),
    ];
    match app.device() {
        Some(d) => {
            left.push(Span::styled(d.display_name(), t.bold()));
            left.push(Span::styled(format!("  {}", d.short_path()), t.dim()));
            if app.devices.len() > 1 {
                left.push(Span::styled(
                    format!(
                        "  [{}/{}]  [ ] switch",
                        app.selected_device + 1,
                        app.devices.len()
                    ),
                    t.dim(),
                ));
            }
        }
        None if !app.scanned_once => {
            left.push(Span::styled("Looking for security keys...", t.dim()))
        }
        None => left.push(Span::styled("No security key connected", t.fg(t.warning))),
    }

    let mut right: Vec<Span> = Vec::new();
    if app.is_scanning() {
        right.push(Span::styled(
            format!("{} scanning ", spinner(app.tick)),
            t.dim(),
        ));
    }
    if let Some(d) = app.device() {
        if d.has_pin_set() {
            if app.is_unlocked() {
                right.push(badge(t, "UNLOCKED", t.success));
            } else {
                right.push(badge(t, "LOCKED", t.overlay));
            }
        } else if d.supports_pin() {
            right.push(badge(t, "NO PIN", t.warning));
        }
        right.push(Span::raw(" "));
    }
    right.push(Span::styled("? help ", t.dim()));

    let rw: u16 = right.iter().map(|s| s.width() as u16).sum();
    let [l, r] = Layout::horizontal([Constraint::Min(10), Constraint::Length(rw)]).areas(area);
    f.render_widget(
        Paragraph::new(Line::from(left)).style(Style::default().bg(t.surface)),
        l,
    );
    f.render_widget(
        Paragraph::new(Line::from(right)).style(Style::default().bg(t.surface)),
        r,
    );
}

fn page_badge(app: &App, p: Page) -> Option<String> {
    let s = app.session();
    match p {
        Page::Passkeys => s
            .and_then(|s| s.creds.as_ref())
            .map(|c| c.len().to_string()),
        Page::Fingerprints => s.and_then(|s| s.bio.as_ref()).map(|b| b.len().to_string()),
        Page::Ssh => {
            let n = app.ssh_keys.len();
            (n > 0).then(|| n.to_string())
        }
        Page::Disk => app.luks.as_ref().map(|l| l.devices.len().to_string()),
        Page::Audit => app.audit().map(|a| a.grade),
        _ => None,
    }
}

fn page_available(app: &App, p: Page) -> bool {
    let Some(d) = app.device() else {
        return matches!(p, Page::Overview | Page::Disk | Page::Ssh);
    };
    match p {
        Page::Passkeys => d.supports_cred_mgmt(),
        Page::Fingerprints => d.supports_bio(),
        Page::LargeBlobs => d.supports_large_blobs(),
        _ => true,
    }
}

fn render_sidebar(app: &App, f: &mut Frame, area: Rect, narrow: bool) {
    let t = &app.theme;
    let mut lines = vec![Line::raw("")];
    for (i, p) in Page::ALL.iter().enumerate() {
        let active = *p == app.page;
        let avail = page_available(app, *p);
        let marker = if active { "▌" } else { " " };
        let num_style = if active { t.key() } else { t.dim() };
        let label_style = match (active, avail) {
            (true, _) => t.bold(),
            (false, true) => t.text(),
            (false, false) => t.dim().add_modifier(Modifier::DIM),
        };
        let mut spans = vec![
            Span::styled(marker, Style::default().fg(t.accent)),
            Span::styled(format!("{} ", i + 1), num_style),
        ];
        if !narrow {
            let label = p.title();
            let badge = page_badge(app, *p).unwrap_or_default();
            let width = area.width.saturating_sub(5) as usize;
            let pad = width.saturating_sub(label.chars().count() + badge.chars().count());
            spans.push(Span::styled(label, label_style));
            spans.push(Span::raw(" ".repeat(pad)));
            spans.push(Span::styled(badge, t.dim()));
        }
        let line = Line::from(spans);
        lines.push(if active {
            line.style(Style::default().bg(t.selection))
        } else {
            line
        });
    }

    if !narrow && !app.devices.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            " KEYS",
            t.dim().add_modifier(Modifier::BOLD),
        )));
        for (i, d) in app.devices.iter().enumerate() {
            let sel = i == app.selected_device;
            let dot = if sel { "●" } else { "○" };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {dot} "),
                    if sel { t.fg(t.success) } else { t.dim() },
                ),
                Span::styled(
                    truncate(&d.display_name(), area.width.saturating_sub(5) as usize),
                    if sel { t.text() } else { t.dim() },
                ),
            ]));
        }
    }
    let block = Block::default()
        .borders(ratatui::widgets::Borders::RIGHT)
        .border_style(t.border(false))
        .style(Style::default().bg(t.bg));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_footer(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let line = if let Some(toast) = &app.toast {
        let (icon, color) = match toast.level {
            Level::Info => ("ℹ", t.info),
            Level::Success => ("✓", t.success),
            Level::Warn => ("!", t.warning),
            Level::Error => ("✗", t.danger),
        };
        Line::from(vec![
            Span::styled(format!(" {icon} "), t.badge(color)),
            Span::styled(format!(" {}", toast.message), Style::default().fg(color)),
        ])
    } else {
        let mut l = hints(t, &pages::page_hints(app));
        l.spans.insert(0, Span::raw(" "));
        l
    };
    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(t.surface)),
        area,
    );
}
