use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let on_key_rows = app
        .credentials()
        .map_or(2, |c| c.iter().filter(|c| c.is_ssh()).count().max(1)) as u16;
    let file_rows = app.ssh_keys.len().max(1) as u16;
    let [on_key, files, about, _] = Layout::vertical([
        Constraint::Length(on_key_rows + 2),
        Constraint::Length(file_rows + 2),
        Constraint::Length(4),
        Constraint::Min(0),
    ])
    .areas(area);

    // Resident SSH credentials stored on the key (rp id "ssh:*").
    match (app.device(), app.credentials()) {
        (None, _) => f.render_widget(
            Paragraph::new(Line::styled(
                "Connect a security key to see SSH keys stored on it.",
                t.dim(),
            ))
            .block(panel(t, "On the security key")),
            on_key,
        ),
        (Some(_), None) => f.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "Unlock to list resident SSH keys stored on the key.",
                    t.dim(),
                ),
                hints(t, &[("u", "unlock")]),
            ])
            .block(panel(t, "On the security key")),
            on_key,
        ),
        (Some(_), Some(creds)) => {
            let ssh: Vec<_> = creds.iter().filter(|c| c.is_ssh()).collect();
            let lines: Vec<Line> = if ssh.is_empty() {
                vec![Line::styled(
                    "No resident SSH keys on this key. Press n to create one.",
                    t.dim(),
                )]
            } else {
                ssh.iter()
                    .map(|c| {
                        Line::from(vec![
                            Span::styled(format!("  {:<22}", c.rp_id), t.bold()),
                            Span::styled(format!("{:<12}", c.algorithm), t.text()),
                            Span::styled(c.user_name.clone(), t.dim()),
                        ])
                    })
                    .collect()
            };
            f.render_widget(
                Paragraph::new(lines)
                    .block(panel(t, &format!("On the security key ({})", ssh.len()))),
                on_key,
            );
        }
    }

    let lines: Vec<Line> = if app.ssh_keys.is_empty() {
        vec![Line::styled(
            "No security-key backed (sk-*) public keys in ~/.ssh",
            t.dim(),
        )]
    } else {
        app.ssh_keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let sel = i == app.ssh_list.selected;
                let name = k
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let l = Line::from(vec![
                    Span::styled(if sel { "› " } else { "  " }, t.fg(t.accent)),
                    Span::styled(format!("{name:<28}"), t.text()),
                    Span::styled(format!("{:<38}", k.key_type), t.dim()),
                    Span::styled(truncate(&k.comment, 30), t.dim()),
                ]);
                if sel {
                    l.style(Style::default().bg(t.selection))
                } else {
                    l
                }
            })
            .collect()
    };
    f.render_widget(
        Paragraph::new(lines).block(panel(t, "Key files in ~/.ssh")),
        files,
    );

    let info = vec![
        Line::styled(
            "ed25519-sk / ecdsa-sk keys keep the private key on the security key; the file in ~/.ssh is only a handle.",
            t.dim(),
        ),
        Line::styled(
            "Resident keys can be restored on any machine with \"l\" (ssh-keygen -K).",
            t.dim(),
        ),
    ];
    f.render_widget(
        Paragraph::new(info)
            .wrap(Wrap { trim: true })
            .block(panel(t, "About")),
        about,
    );
}
