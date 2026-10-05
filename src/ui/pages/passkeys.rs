use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use crate::app::App;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(d) = app.device() else { return };
    if !d.supports_cred_mgmt() {
        empty_state(
            f,
            area,
            t,
            "",
            "Passkey management is not supported",
            &[Line::styled(
                "This key does not implement CTAP 2.1 credential management.",
                t.dim(),
            )],
        );
        return;
    }
    let Some(all) = app.credentials() else {
        super::locked(app, f, area, "passkeys");
        return;
    };

    let [top, body] = Layout::vertical([Constraint::Length(3), Constraint::Min(5)]).areas(area);

    // Storage + search bar
    let stats = app.session().and_then(|s| s.stats);
    let mut spans = vec![Span::styled("Storage ", t.dim())];
    if let Some(s) = stats {
        let r = s.usage_ratio();
        spans.extend(bar(t, r, 20, usage_color(t, r)));
        spans.push(Span::styled(
            format!(" {} used · {} free    ", s.existing, s.remaining),
            t.text(),
        ));
    }
    spans.push(Span::styled("Search ", t.dim()));
    if app.searching || !app.search.is_empty() {
        spans.push(Span::styled(
            format!(" {} ", app.search),
            Style::default().bg(t.overlay).fg(t.fg),
        ));
        if app.searching {
            spans.push(Span::styled("▏", t.fg(t.accent)));
        }
    } else {
        spans.push(Span::styled("press /", t.dim()));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(panel(t, "Passkeys")),
        top,
    );

    let creds = app.filtered_credentials();
    if all.is_empty() {
        empty_state(
            f,
            body,
            t,
            "∅",
            "No passkeys stored on this key",
            &[Line::styled(
                "Passkeys you create on websites with this key will appear here.",
                t.dim(),
            )],
        );
        return;
    }
    if creds.is_empty() {
        empty_state(
            f,
            body,
            t,
            "∅",
            "No passkeys match your search",
            &[hints(t, &[("esc", "clear search")])],
        );
        return;
    }

    let wide = body.width >= 110;
    let [table_area, detail_area] = if wide {
        Layout::horizontal([Constraint::Min(60), Constraint::Length(44)]).areas(body)
    } else {
        [body, Rect::default()]
    };

    let mut prev_rp = "";
    let rows: Vec<Row> = creds
        .iter()
        .map(|c| {
            let rp = if c.rp_id == prev_rp {
                String::new()
            } else {
                c.rp_id.clone()
            };
            prev_rp = &c.rp_id;
            let prot = match c.cred_protect {
                3 => Span::styled("UV", t.fg(t.success)),
                2 => Span::styled("UV/ID", t.fg(t.info)),
                _ => Span::styled("-", t.dim()),
            };
            Row::new(vec![
                Cell::from(Span::styled(rp, t.bold())),
                Cell::from(Span::styled(c.user_name.clone(), t.text())),
                Cell::from(Span::styled(c.user_display_name.clone(), t.dim())),
                Cell::from(prot),
                Cell::from(Span::styled(
                    if c.large_blob_key.is_some() {
                        "◆"
                    } else {
                        ""
                    },
                    t.fg(t.accent2),
                )),
            ])
        })
        .collect();
    let title = format!("{} of {}", creds.len(), all.len());
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(32),
            Constraint::Percentage(32),
            Constraint::Percentage(26),
            Constraint::Length(6),
            Constraint::Length(2),
        ],
    )
    .header(
        Row::new(["Site", "User", "Display name", "Prot.", ""])
            .style(t.dim())
            .bottom_margin(0),
    )
    .row_highlight_style(t.selected())
    .highlight_symbol("› ")
    .block(panel(t, &title));
    let mut state = TableState::default().with_selected(Some(app.passkeys.selected));
    f.render_stateful_widget(table, table_area, &mut state);

    if wide && let Some(c) = creds.get(app.passkeys.selected) {
        let w = 10;
        let lines = vec![
            Line::styled(
                c.rp_name.clone().unwrap_or_else(|| c.rp_id.clone()),
                t.title(),
            ),
            Line::styled(c.rp_id.clone(), t.dim()),
            Line::raw(""),
            kv(t, "User", c.user_name.clone(), w),
            kv(t, "Display", c.user_display_name.clone(), w),
            kv(t, "Algorithm", c.algorithm.clone(), w),
            kv(t, "Protect", c.cred_protect_label(), w),
            kv(
                t,
                "Blob key",
                if c.large_blob_key.is_some() {
                    "yes"
                } else {
                    "no"
                },
                w,
            ),
            kv(
                t,
                "Kind",
                if c.is_ssh() {
                    "SSH key"
                } else {
                    "WebAuthn passkey"
                },
                w,
            ),
            Line::raw(""),
            Line::styled("Credential ID", t.dim()),
            Line::styled(truncate(&c.cred_id_hex(), 120), t.text()),
            Line::raw(""),
            hints(t, &[("enter", "full details")]),
        ];
        f.render_widget(
            Paragraph::new(lines)
                .block(panel(t, "Details"))
                .wrap(Wrap { trim: true }),
            detail_area,
        );
    }
}
