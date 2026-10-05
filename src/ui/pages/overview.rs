use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::model::CheckStatus;
use crate::ui::widgets::*;

pub fn no_device(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    if !app.scanned_once {
        empty_state(
            f,
            area,
            t,
            spinner(app.tick),
            "Looking for security keys...",
            &[],
        );
        return;
    }
    let mut lines = vec![
        Line::styled(
            "Plug in a FIDO2 security key - it is detected automatically.",
            t.text(),
        ),
        Line::raw(""),
    ];
    if !app.inaccessible.is_empty() {
        lines.push(Line::styled(
            "Found keys this user is not allowed to open:",
            t.fg(t.warning),
        ));
        for k in &app.inaccessible {
            lines.push(Line::styled(
                format!("  {}  ({})", k.name, k.node),
                t.fg(t.warning),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Fix: run ./install.sh (installs a udev rule), then re-plug the key.",
            t.text(),
        ));
        lines.push(Line::raw(""));
    }
    for e in &app.enum_errors {
        lines.push(Line::styled(format!("✗ {e}"), t.fg(t.danger)));
    }
    lines.push(Line::styled(
        "Disk Unlock and SSH Keys pages still work without a key.",
        t.dim(),
    ));
    let pulse = ["○", "◔", "◑", "◕", "●", "◕", "◑", "◔"][(app.tick as usize / 2) % 8];
    empty_state(f, area, t, pulse, "No security key connected", &lines);
}

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(d) = app.device() else {
        no_device(app, f, area);
        return;
    };
    let multi = app.devices.len() > 1;
    let [list_area, top, bottom, log_area] = Layout::vertical([
        Constraint::Length(if multi {
            app.devices.len() as u16 + 2
        } else {
            0
        }),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Min(3),
    ])
    .areas(area);

    if multi {
        let lines: Vec<Line> = app
            .devices
            .iter()
            .enumerate()
            .map(|(i, dev)| {
                let sel = i == app.selected_device;
                let l = Line::from(vec![
                    Span::styled(
                        if sel { " ● " } else { " ○ " },
                        if sel { t.fg(t.success) } else { t.dim() },
                    ),
                    Span::styled(
                        format!("{:<34}", truncate(&dev.display_name(), 34)),
                        t.text(),
                    ),
                    Span::styled(format!("{:<14}", dev.short_path()), t.dim()),
                    Span::styled(
                        if dev.has_pin_set() {
                            "PIN set"
                        } else {
                            "no PIN"
                        },
                        if dev.has_pin_set() {
                            t.fg(t.success)
                        } else {
                            t.fg(t.warning)
                        },
                    ),
                ]);
                if sel { l.style(t.selected()) } else { l }
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines).block(panel(t, "Connected keys  (j/k to select)")),
            list_area,
        );
    }

    let [card, status] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(top);

    // Identity card
    let w = 13;
    let mut id = vec![
        Line::from(Span::styled(
            d.display_name(),
            Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
        )),
        Line::styled(format!("{} · {}", d.manufacturer, d.product), t.dim()),
        Line::raw(""),
        kv(t, "Device", d.path.clone(), w),
        kv(
            t,
            "USB ID",
            format!("{:04x}:{:04x}", d.vendor_id, d.product_id),
            w,
        ),
        kv(
            t,
            "Firmware",
            d.fw_version_string().unwrap_or_else(|| "-".into()),
            w,
        ),
        kv(t, "Protocols", d.versions.join(" "), w),
    ];
    if let Some(a) = &d.aaguid {
        id.push(kv(t, "AAGUID", a.clone(), w));
    }
    if !d.is_fido2 {
        id.push(Line::styled(
            "U2F-only key: management features are unavailable.",
            t.fg(t.warning),
        ));
    }
    f.render_widget(
        Paragraph::new(id)
            .block(panel(t, "Security key"))
            .wrap(Wrap { trim: true }),
        card,
    );

    // Status
    let w = 15;
    let mut st = Vec::new();
    if d.supports_pin() {
        if d.has_pin_set() {
            let mut s = vec![
                Span::styled(format!("{:<w$}", "PIN"), t.dim()),
                Span::styled("set  ", t.fg(t.success)),
            ];
            if let Some(r) = d.pin_retries {
                s.extend(dots(t, r, 8.max(r)));
                s.push(Span::styled(format!(" {r} tries"), t.dim()));
            }
            st.push(Line::from(s));
        } else {
            st.push(kv_styled(t, "PIN", "not set - press p", t.fg(t.warning), w));
        }
    } else {
        st.push(kv_styled(t, "PIN", "unsupported", t.dim(), w));
    }
    st.push(kv(
        t,
        "Min PIN length",
        d.min_pin_len.map_or("-".into(), |n| n.to_string()),
        w,
    ));
    if d.supports_always_uv() {
        st.push(kv(
            t,
            "Always UV",
            if d.is_always_uv() { "on" } else { "off" },
            w,
        ));
    }
    let storage = app.session().and_then(|s| s.stats);
    match (storage, d.rk_remaining) {
        (Some(s), _) => {
            let r = s.usage_ratio();
            let mut sp = vec![Span::styled(format!("{:<w$}", "Passkeys"), t.dim())];
            sp.extend(bar(t, r, 14, usage_color(t, r)));
            sp.push(Span::styled(
                format!(" {}/{}", s.existing, s.total()),
                t.text(),
            ));
            st.push(Line::from(sp));
        }
        (None, Some(rem)) => st.push(kv(t, "Passkeys", format!("{rem} slots free"), w)),
        (None, None) if d.supports_cred_mgmt() && d.has_pin_set() => {
            st.push(kv_styled(t, "Passkeys", "unlock to count (u)", t.dim(), w))
        }
        _ => {}
    }
    if let Some(report) = app.audit() {
        let color = match report.grade.as_str() {
            "A" => t.success,
            "B" => t.info,
            "C" => t.warning,
            _ => t.danger,
        };
        st.push(Line::raw(""));
        st.push(Line::from(vec![
            Span::styled(format!("{:<w$}", "Security grade"), t.dim()),
            badge(t, &report.grade, color),
            Span::styled(format!("  {}/100", report.score), t.dim()),
        ]));
        if let Some(top) = report
            .checks
            .iter()
            .find(|c| matches!(c.status, CheckStatus::Fail | CheckStatus::Warn))
        {
            st.push(Line::styled(
                format!(
                    "{} {}",
                    if top.status == CheckStatus::Fail {
                        "✗"
                    } else {
                        "!"
                    },
                    top.fix.clone().unwrap_or(top.detail.clone())
                ),
                t.fg(if top.status == CheckStatus::Fail {
                    t.danger
                } else {
                    t.warning
                }),
            ));
        }
    }
    if let Some(s) = app.session().and_then(|s| s.self_test.as_ref()) {
        st.push(kv_styled(
            t,
            "Self-test",
            if s.assertion_verified {
                "passed ✓"
            } else {
                "failed ✗"
            },
            t.fg(if s.assertion_verified {
                t.success
            } else {
                t.danger
            }),
            w,
        ));
    }
    f.render_widget(
        Paragraph::new(st)
            .block(panel(t, "Status"))
            .wrap(Wrap { trim: true }),
        status,
    );

    // Capabilities + actions
    let [caps, actions] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(bottom);
    let features: [(&str, bool); 10] = [
        ("Passkey management", d.supports_cred_mgmt()),
        ("Discoverable creds", d.supports_rk()),
        ("Fingerprints", d.supports_bio()),
        ("Large blobs", d.supports_large_blobs()),
        ("hmac-secret", d.has_extension("hmac-secret")),
        ("credProtect", d.has_extension("credProtect")),
        ("Min PIN length", d.supports_min_pin()),
        ("Config commands", d.supports_config()),
        ("Enterprise attest.", d.option("ep").is_some()),
        ("credBlob", d.has_extension("credBlob")),
    ];
    let mut cl = Vec::new();
    for pair in features.chunks(2) {
        let mut spans = Vec::new();
        for (name, on) in pair {
            let mut c = chip(t, &format!("{name:<20}"), *on);
            spans.append(&mut c);
        }
        cl.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(cl).block(panel(t, "Capabilities")), caps);

    let has_pin = d.has_pin_set();
    let mut al = vec![
        Line::from(vec![
            Span::styled(" t ", t.badge(t.accent)),
            Span::styled("  Self-test (register + sign)", t.text()),
        ]),
        Line::from(vec![
            Span::styled(" i ", t.badge(t.accent)),
            Span::styled("  Identify - touch to select", t.text()),
        ]),
        Line::from(vec![
            Span::styled(" p ", t.badge(t.accent)),
            Span::styled(if has_pin { "  Change PIN" } else { "  Set PIN" }, t.text()),
        ]),
    ];
    if has_pin {
        al.push(Line::from(vec![
            Span::styled(
                if app.is_unlocked() { " L " } else { " u " },
                t.badge(t.accent),
            ),
            Span::styled(
                if app.is_unlocked() {
                    "  Lock session"
                } else {
                    "  Unlock with PIN"
                },
                t.text(),
            ),
        ]));
    }
    f.render_widget(Paragraph::new(al).block(panel(t, "Quick actions")), actions);

    render_activity(app, f, log_area);
}

fn render_activity(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let rows = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = if app.activity.is_empty() {
        vec![Line::styled(
            "Nothing yet - actions and plug/unplug events appear here.",
            t.dim(),
        )]
    } else {
        app.activity
            .iter()
            .rev()
            .take(rows)
            .map(|e| {
                let (icon, color) = match e.level {
                    crate::app::modal::Level::Info => ("·", t.muted),
                    crate::app::modal::Level::Success => ("✓", t.success),
                    crate::app::modal::Level::Warn => ("!", t.warning),
                    crate::app::modal::Level::Error => ("✗", t.danger),
                };
                Line::from(vec![
                    Span::styled(e.time.format("%H:%M:%S  ").to_string(), t.dim()),
                    Span::styled(format!("{icon} "), Style::default().fg(color)),
                    Span::styled(e.message.clone(), t.text()),
                ])
            })
            .collect()
    };
    f.render_widget(Paragraph::new(lines).block(panel(t, "Activity")), area);
}
