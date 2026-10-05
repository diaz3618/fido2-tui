use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use crate::app::App;
use crate::model::LuksDevice;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(scan) = &app.luks else {
        empty_state(
            f,
            area,
            t,
            spinner(app.tick),
            "Scanning encrypted volumes...",
            &[],
        );
        return;
    };
    let banner_h = if scan.needs_root || !scan.errors.is_empty() {
        3
    } else {
        0
    };
    let [banner, list, detail] = Layout::vertical([
        Constraint::Length(banner_h),
        Constraint::Length(scan.devices.len().max(1) as u16 + 3),
        Constraint::Min(6),
    ])
    .areas(area);

    if banner_h > 0 {
        let line = if scan.needs_root {
            Line::from(vec![
                Span::styled("! ", t.fg(t.warning)),
                Span::styled(
                    "Reading LUKS headers of system disks needs root.  ",
                    t.text(),
                ),
                Span::styled("a", t.key()),
                Span::styled(" authenticate with sudo", t.dim()),
            ])
        } else {
            Line::styled(scan.errors.join("; "), t.fg(t.danger))
        };
        f.render_widget(Paragraph::new(line).block(panel(t, "Notice")), banner);
    }

    if scan.devices.is_empty() {
        empty_state(
            f,
            list.union(detail),
            t,
            "",
            "No LUKS-encrypted volumes found",
            &[
                Line::styled(
                    "You can still practise enrolling a key on a throw-away volume:",
                    t.dim(),
                ),
                Line::raw(""),
                hints(
                    t,
                    &[("n", "create a 32 MB practice volume (no root needed)")],
                ),
            ],
        );
        return;
    }

    let rows: Vec<Row> = scan
        .devices
        .iter()
        .map(|d| {
            let fido = match &d.header {
                None => Span::styled("?", t.dim()),
                Some(_) if d.has_fido2_token() => {
                    Span::styled(format!("✓ {}", d.fido2_tokens().len()), t.fg(t.success))
                }
                Some(_) => Span::styled("-", t.dim()),
            };
            let name = if d.is_practice {
                "practice volume".to_string()
            } else {
                d.path.clone()
            };
            let usage = if d.is_practice {
                "test file".to_string()
            } else if d.mountpoints.is_empty() {
                if d.mapped_name.is_some() {
                    "open".into()
                } else {
                    "closed".into()
                }
            } else {
                d.mountpoints.join(", ")
            };
            Row::new(vec![
                Cell::from(Span::styled(name, t.bold())),
                Cell::from(Span::styled(d.size.clone(), t.text())),
                Cell::from(Span::styled(
                    truncate(&usage, 24),
                    if d.is_system_volume {
                        t.fg(t.accent2)
                    } else {
                        t.dim()
                    },
                )),
                Cell::from(fido),
                Cell::from(Span::styled(
                    d.header
                        .as_ref()
                        .map_or("?".into(), |h| h.keyslots.len().to_string()),
                    t.text(),
                )),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Min(22),
            Constraint::Length(8),
            Constraint::Min(16),
            Constraint::Length(7),
            Constraint::Length(6),
        ],
    )
    .header(Row::new(["Volume", "Size", "Used as", "FIDO2", "Slots"]).style(t.dim()))
    .row_highlight_style(t.selected())
    .highlight_symbol("› ")
    .block(panel(t, "Encrypted volumes"));
    let mut state = TableState::default().with_selected(Some(app.disk_list.selected));
    f.render_stateful_widget(table, list, &mut state);

    if let Some(d) = scan.devices.get(app.disk_list.selected) {
        render_detail(app, d, scan.initramfs_fido2, f, detail);
    }
}

fn render_detail(app: &App, d: &LuksDevice, initramfs: Option<bool>, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let [slots, boot] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area);
    let mut lines = Vec::new();
    match &d.header {
        None => lines.push(Line::styled(
            "Header not readable yet - press a to authenticate.",
            t.dim(),
        )),
        Some(h) if h.version == 1 => lines.push(Line::styled(
            "LUKS1 volume - FIDO2 enrollment requires LUKS2 (cryptsetup convert).",
            t.fg(t.warning),
        )),
        Some(h) => {
            for k in &h.keyslots {
                let tok = h.tokens.iter().find(|tk| tk.keyslots.contains(&k.id));
                let (kind, color) = match tok {
                    Some(tk) if tk.is_fido2() => ("FIDO2 security key", t.success),
                    Some(tk) => (tk.token_type.as_str(), t.info),
                    None => ("passphrase / recovery", t.fg),
                };
                let mut spans = vec![
                    Span::styled(format!("slot {:<3}", k.id), t.dim()),
                    Span::styled(
                        format!("{kind:<24}"),
                        ratatui::style::Style::default().fg(color),
                    ),
                    Span::styled(k.kdf.clone(), t.dim()),
                ];
                if let Some(tk) = tok.filter(|tk| tk.is_fido2()) {
                    let flag = |name: &str, v: Option<bool>| {
                        Span::styled(
                            format!("  {name}{}", if v == Some(true) { "✓" } else { "✗" }),
                            t.dim(),
                        )
                    };
                    spans.push(flag("PIN", tk.fido2_pin_required));
                    spans.push(flag("touch", tk.fido2_up_required));
                    spans.push(flag("UV", tk.fido2_uv_required));
                }
                lines.push(Line::from(spans));
            }
            if d.passphrase_slots().is_empty() {
                lines.push(Line::styled(
                    "! No passphrase slot: losing the key means losing the data!",
                    t.fg(t.danger),
                ));
            }
        }
    }
    lines.push(Line::raw(""));
    lines.push(hints(
        t,
        &[
            ("e", "enroll key"),
            ("t", "test key unlock"),
            ("w", "test passphrase"),
            ("x", "remove FIDO2"),
        ],
    ));
    f.render_widget(
        Paragraph::new(lines)
            .block(panel(t, "Key slots"))
            .wrap(Wrap { trim: true }),
        slots,
    );

    let mut b = Vec::new();
    if d.is_practice {
        b.push(Line::styled(
            "Practice volume: experiment freely.",
            t.text(),
        ));
        b.push(Line::styled(
            "It is a plain file and never used at boot.",
            t.dim(),
        ));
        b.push(Line::raw(""));
        b.push(hints(t, &[("D", "delete practice volume")]));
    } else {
        let ct = match &d.crypttab {
            Some(e) if e.has_fido2_device() => Span::styled("fido2-device=auto ✓", t.fg(t.success)),
            Some(_) => Span::styled("entry without fido2-device", t.fg(t.warning)),
            None => Span::styled("no entry", t.dim()),
        };
        b.push(Line::from(vec![
            Span::styled(format!("{:<11}", "crypttab"), t.dim()),
            ct,
        ]));
        b.push(kv_styled(
            t,
            "initramfs",
            match initramfs {
                Some(true) => "FIDO2 module available ✓",
                Some(false) => "FIDO2 module missing",
                None => "unknown",
            },
            t.fg(if initramfs == Some(false) {
                t.warning
            } else {
                t.text().fg.unwrap_or(t.fg)
            }),
            11,
        ));
        b.push(Line::raw(""));
        b.push(hints(
            t,
            &[("c", "boot setup guide"), ("b", "back up header")],
        ));
    }
    f.render_widget(
        Paragraph::new(b)
            .block(panel(t, "Boot unlock"))
            .wrap(Wrap { trim: true }),
        boot,
    );
}
