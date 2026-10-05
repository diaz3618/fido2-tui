use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap};

use super::theme::Theme;
use super::widgets::*;
use crate::app::modal::*;
use crate::app::{App, Busy, ResetStage};

fn modal_block<'a>(t: &Theme, title: &'a str, color: ratatui::style::Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
        .padding(Padding::new(2, 2, 1, 0))
        .style(Style::default().bg(t.surface).fg(t.fg))
}

fn show(
    f: &mut Frame,
    area: Rect,
    width: u16,
    lines: Vec<Line<'static>>,
    block: Block,
    scroll: u16,
) {
    let inner_w = width.saturating_sub(6).max(10) as usize;
    // Estimate wrapped height.
    let h: usize = lines
        .iter()
        .map(|l| (l.width().max(1)).div_ceil(inner_w))
        .sum::<usize>()
        + 4;
    let r = centered(area, width, h.min(area.height as usize) as u16);
    f.render_widget(Clear, r);
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        r,
    );
}

pub fn render_modal(app: &App, m: &Modal, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    match m {
        Modal::Help { scroll } => {
            let lines = help_lines(t);
            let r = centered(area, 84, area.height.saturating_sub(4));
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(lines)
                    .block(modal_block(t, "Keyboard shortcuts", t.accent))
                    .scroll((*scroll, 0)),
                r,
            );
        }
        Modal::Message { title, body, level } => {
            let color = level_color(t, *level);
            let mut lines: Vec<Line> = body
                .iter()
                .map(|l| Line::styled(l.clone(), t.text()))
                .collect();
            lines.push(Line::raw(""));
            lines.push(hints(t, &[("enter", "close")]).alignment(Alignment::Right));
            show(f, area, 72, lines, modal_block(t, title, color), 0);
        }
        Modal::Text {
            title,
            lines,
            scroll,
        } => {
            let mut out: Vec<Line> = lines
                .iter()
                .map(|l| Line::styled(l.clone(), t.text()))
                .collect();
            out.push(Line::raw(""));
            out.push(hints(t, &[("j/k", "scroll"), ("esc", "close")]).alignment(Alignment::Right));
            let r = centered(
                area,
                92,
                (out.len() as u16 + 4).min(area.height.saturating_sub(2)),
            );
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(out)
                    .block(modal_block(t, title, t.accent))
                    .scroll((*scroll, 0)),
                r,
            );
        }
        Modal::Confirm(c) => {
            let color = if c.danger { t.danger } else { t.accent };
            let mut lines: Vec<Line> = c
                .body
                .iter()
                .map(|l| Line::styled(l.clone(), t.text()))
                .collect();
            lines.push(Line::raw(""));
            if let Some(word) = &c.type_to_confirm {
                lines.push(Line::from(vec![
                    Span::styled("Type ", t.dim()),
                    Span::styled(
                        word.clone(),
                        Style::default().fg(t.danger).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" to continue: ", t.dim()),
                ]));
                let ok = c.can_confirm();
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" {} ", c.typed),
                        Style::default().bg(t.overlay).fg(t.fg),
                    ),
                    Span::styled("▏", t.fg(t.accent)),
                    Span::raw("  "),
                    if ok {
                        Span::styled("✓", t.fg(t.success))
                    } else {
                        Span::raw("")
                    },
                ]));
                lines.push(Line::raw(""));
                lines.push(
                    hints(
                        t,
                        &[
                            (
                                "enter",
                                if ok {
                                    c.yes_label.as_str()
                                } else {
                                    "(type to enable)"
                                },
                            ),
                            ("esc", "cancel"),
                        ],
                    )
                    .alignment(Alignment::Right),
                );
            } else {
                let btn = |label: &str, sel: bool, col| {
                    if sel {
                        Span::styled(format!("  {label}  "), t.badge(col))
                    } else {
                        Span::styled(
                            format!("  {label}  "),
                            Style::default().fg(t.muted).bg(t.overlay),
                        )
                    }
                };
                lines.push(
                    Line::from(vec![
                        btn("Cancel", !c.yes_selected, t.accent),
                        Span::raw("   "),
                        btn(&c.yes_label, c.yes_selected, color),
                    ])
                    .alignment(Alignment::Center),
                );
                lines.push(Line::raw(""));
                lines.push(
                    hints(t, &[("←/→", "choose"), ("y", "yes"), ("esc", "cancel")])
                        .alignment(Alignment::Right),
                );
            }
            show(f, area, 76, lines, modal_block(t, &c.title, color), 0);
        }
        Modal::Pin(p) => {
            let mut lines = vec![Line::styled(p.reason.clone(), t.text()), Line::raw("")];
            let shown = if p.reveal {
                p.input.to_string()
            } else {
                "•".repeat(p.input.chars().count())
            };
            lines.push(Line::from(vec![
                Span::styled("PIN  ", t.dim()),
                Span::styled(
                    format!(" {shown:<30}"),
                    Style::default().bg(t.overlay).fg(t.fg),
                ),
                Span::styled("▏", t.fg(t.accent)),
            ]));
            if let Some(r) = p.retries {
                let mut s = vec![Span::styled("     ", t.dim())];
                s.extend(dots(t, r, 8.max(r)));
                s.push(Span::styled(format!("  {r} attempts left"), t.dim()));
                lines.push(Line::from(s));
            }
            if let Some(e) = &p.error {
                lines.push(Line::styled(format!("✗ {e}"), t.fg(t.danger)));
            }
            lines.push(Line::raw(""));
            lines.push(
                hints(
                    t,
                    &[("enter", "unlock"), ("ctrl+r", "show"), ("esc", "cancel")],
                )
                .alignment(Alignment::Right),
            );
            show(f, area, 62, lines, modal_block(t, &p.title, t.accent), 0);
        }
        Modal::Form(form) => render_form(t, form, f, area),
    }
}

fn render_form(t: &Theme, form: &Form, f: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = form
        .description
        .iter()
        .map(|d| Line::styled(d.clone(), t.dim()))
        .collect();
    if !lines.is_empty() {
        lines.push(Line::raw(""));
    }
    let lw = form
        .fields
        .iter()
        .map(|f| f.label.chars().count())
        .max()
        .unwrap_or(10)
        + 2;
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let label_style = if focused { t.key() } else { t.dim() };
        let marker = if focused { "›" } else { " " };
        let mut spans = vec![
            Span::styled(format!("{marker} "), t.fg(t.accent)),
            Span::styled(format!("{:<lw$}", field.label), label_style),
        ];
        let input_style = Style::default()
            .bg(if focused { t.overlay } else { t.surface })
            .fg(t.fg);
        match &field.kind {
            FieldKind::Text | FieldKind::Number { .. } => {
                spans.push(Span::styled(
                    format!(" {:<28}", truncate(&field.value, 40)),
                    input_style,
                ));
                if focused {
                    spans.push(Span::styled("▏", t.fg(t.accent)));
                }
            }
            FieldKind::Secret => {
                spans.push(Span::styled(
                    format!(" {:<28}", "•".repeat(field.value.chars().count())),
                    input_style,
                ));
                if focused {
                    spans.push(Span::styled("▏", t.fg(t.accent)));
                }
            }
            FieldKind::Toggle => {
                let (mark, col) = if field.checked {
                    ("[✓]", t.success)
                } else {
                    ("[ ]", t.muted)
                };
                spans.push(Span::styled(
                    mark,
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ));
                spans.push(Span::styled(
                    if field.checked { " on" } else { " off" },
                    t.dim(),
                ));
            }
            FieldKind::Choice(opts) => {
                for (j, o) in opts.iter().enumerate() {
                    if j == field.choice {
                        spans.push(Span::styled(format!(" {o} "), t.badge(t.accent)));
                    } else {
                        spans.push(Span::styled(format!(" {o} "), t.dim()));
                    }
                }
            }
        }
        lines.push(Line::from(spans));
        if let Some(h) = &field.hint
            && !h.is_empty()
        {
            lines.push(Line::styled(format!("  {:<lw$} {h}", ""), t.dim()));
        }
    }
    if let Some(e) = &form.error {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("✗ {e}"), t.fg(t.danger)));
    }
    lines.push(Line::raw(""));
    let has_toggles = form
        .fields
        .iter()
        .any(|f| matches!(f.kind, FieldKind::Toggle | FieldKind::Choice(_)));
    let mut h = vec![("tab", "next")];
    if has_toggles {
        h.push(("space/←→", "toggle"));
    }
    h.extend([("enter", form.submit_label.as_str()), ("esc", "cancel")]);
    lines.push(hints(t, &h).alignment(Alignment::Right));
    show(f, area, 80, lines, modal_block(t, &form.title, t.accent), 0);
}

pub fn render_busy(app: &App, b: &Busy, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let secs = b.started.elapsed().as_secs();
    let mut lines = Vec::new();
    if b.touch {
        // Pulsing key indicator.
        let pulse = ["◯", "◎", "◉", "●", "◉", "◎"][(app.tick as usize / 2) % 6];
        lines.push(
            Line::styled(
                pulse.to_string(),
                Style::default().fg(t.warning).add_modifier(Modifier::BOLD),
            )
            .alignment(Alignment::Center),
        );
        lines.push(Line::raw(""));
    }
    lines.push(
        Line::from(vec![
            Span::styled(format!("{} ", spinner(app.tick)), t.fg(t.accent)),
            Span::styled(b.title.clone(), t.bold()),
        ])
        .alignment(Alignment::Center),
    );
    if !b.detail.is_empty() {
        lines.push(Line::styled(b.detail.clone(), t.text()).alignment(Alignment::Center));
    }
    if let (Some(rem), Some(total)) = (b.bio_remaining, b.bio_total) {
        let done = total.saturating_sub(rem);
        let mut s = bar(t, done as f64 / total.max(1) as f64, 30, t.success);
        s.push(Span::styled(format!("  {done}/{total} samples"), t.dim()));
        lines.push(Line::raw(""));
        lines.push(Line::from(s).alignment(Alignment::Center));
    }
    lines.push(Line::raw(""));
    let footer = if b.touch {
        format!("Touch the blinking key · times out after ~30 s · {secs}s")
    } else {
        format!("{secs}s")
    };
    lines.push(Line::styled(footer, t.dim()).alignment(Alignment::Center));
    let color = if b.touch { t.warning } else { t.accent };
    show(
        f,
        area,
        64,
        lines,
        modal_block(t, if b.touch { "Action needed" } else { "Working" }, color),
        0,
    );
}

pub fn render_reset(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(w) = &app.reset else { return };
    let step = |n: u8, label: &str, state: i8| -> Line<'static> {
        let (mark, style) = match state {
            1 => ("✓", t.fg(t.success)),
            0 => (
                "▶",
                Style::default().fg(t.warning).add_modifier(Modifier::BOLD),
            ),
            _ => ("·", t.dim()),
        };
        Line::from(vec![
            Span::styled(format!("  {mark} {n}. "), style),
            Span::styled(
                label.to_string(),
                if state == 0 { t.bold() } else { t.dim() },
            ),
        ])
    };
    let (s1, s2, s3) = match w.stage {
        ResetStage::Unplug => (0, -1, -1),
        ResetStage::Replug { .. } => (1, 0, -1),
        ResetStage::Running => (1, 1, 0),
    };
    let mut lines = vec![
        Line::styled(
            "Most keys only accept a reset right after being plugged in.",
            t.text(),
        ),
        Line::raw(""),
        step(1, "Unplug the security key", s1),
        step(2, "Plug it back in", s2),
        step(3, "Touch it when it blinks", s3),
        Line::raw(""),
    ];
    match w.stage {
        ResetStage::Unplug => lines.push(hints(
            t,
            &[
                ("enter", "reset now without re-plugging"),
                ("esc", "cancel"),
            ],
        )),
        ResetStage::Replug { since } => {
            lines.push(Line::styled(
                format!(
                    "{} waiting for the key... {}s",
                    spinner(app.tick),
                    since.elapsed().as_secs()
                ),
                t.dim(),
            ));
            lines.push(hints(t, &[("esc", "cancel")]));
        }
        ResetStage::Running => {}
    }
    show(
        f,
        area,
        66,
        lines,
        modal_block(t, "Factory reset", t.danger),
        0,
    );
}

fn level_color(t: &Theme, l: Level) -> ratatui::style::Color {
    match l {
        Level::Info => t.info,
        Level::Success => t.success,
        Level::Warn => t.warning,
        Level::Error => t.danger,
    }
}

fn help_lines(t: &Theme) -> Vec<Line<'static>> {
    let sections: &[(&str, &[(&str, &str)])] = &[
        (
            "Global",
            &[
                ("1-9 / tab", "switch page"),
                ("[ ]", "previous / next security key"),
                ("r", "refresh"),
                ("i", "identify key (touch to blink/select)"),
                ("L", "lock: forget PIN and loaded data"),
                ("T", "cycle color theme"),
                ("?", "this help"),
                ("q / ctrl+c", "quit"),
            ],
        ),
        (
            "Overview",
            &[
                ("t", "self-test (register + sign, nothing stored)"),
                ("u", "unlock with PIN"),
                ("p", "set / change PIN"),
            ],
        ),
        (
            "Passkeys",
            &[
                ("j/k ↑/↓", "move"),
                ("/", "search (esc clears)"),
                ("enter", "details"),
                ("e", "edit user name / display name"),
                ("d", "delete"),
                ("x", "export metadata as JSON"),
            ],
        ),
        (
            "PIN & Security",
            &[
                ("enter", "run action"),
                ("p", "set/change PIN"),
                ("v", "verify PIN"),
                ("m", "min PIN length"),
                ("a", "toggle Always-UV"),
                ("R", "factory reset"),
            ],
        ),
        (
            "Fingerprints",
            &[("n", "enroll"), ("e", "rename"), ("d", "delete")],
        ),
        (
            "Large Blobs",
            &[
                ("enter", "view"),
                ("e", "write (text or file)"),
                ("s", "save to file"),
                ("d", "delete"),
            ],
        ),
        (
            "SSH Keys",
            &[
                ("n", "generate key on the security key"),
                ("l", "download resident keys"),
                ("enter", "show public key"),
            ],
        ),
        (
            "Disk Unlock",
            &[
                ("a", "authenticate with sudo"),
                ("e", "enroll key into LUKS2 volume"),
                ("t / w", "test unlock with key / passphrase"),
                ("x", "remove FIDO2 slots (passphrases kept)"),
                ("b", "back up LUKS header"),
                ("c", "boot (crypttab) setup help"),
                ("n / D", "create / delete practice volume"),
            ],
        ),
        (
            "Audit",
            &[
                ("x / c", "export JSON / CSV"),
                ("u", "unlock for a deeper audit"),
            ],
        ),
        (
            "Dialogs",
            &[
                ("tab", "next field"),
                ("space", "toggle"),
                ("ctrl+u", "clear field"),
                ("ctrl+r", "reveal PIN"),
            ],
        ),
    ];
    let mut lines = Vec::new();
    for (name, keys) in sections {
        lines.push(Line::styled(name.to_string(), t.title()));
        for (k, d) in keys.iter() {
            lines.push(Line::from(vec![
                Span::styled(format!("  {k:<14}"), t.key()),
                Span::styled(d.to_string(), t.text()),
            ]));
        }
        lines.push(Line::raw(""));
    }
    lines
}
