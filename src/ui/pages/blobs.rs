use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};

use crate::app::App;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(d) = app.device() else { return };
    if !d.supports_large_blobs() {
        empty_state(
            f,
            area,
            t,
            "",
            "Large blobs are not supported",
            &[Line::styled(
                "This key cannot store per-passkey data (CTAP 2.1 largeBlobs).",
                t.dim(),
            )],
        );
        return;
    }
    let [top, body] = Layout::vertical([Constraint::Length(4), Constraint::Min(4)]).areas(area);
    let session = app.session();
    let max = d.max_large_blob.max(1);
    let mut lines = vec![];
    match session.and_then(|s| s.blob_array_size) {
        Some(used) => {
            let r = used as f64 / max as f64;
            let mut s = vec![Span::styled("Storage  ", t.dim())];
            s.extend(bar(t, r, 30, usage_color(t, r)));
            s.push(Span::styled(format!("  {used} / {max} bytes"), t.text()));
            lines.push(Line::from(s));
        }
        None => lines.push(Line::styled(
            format!("Capacity: {max} bytes shared by all passkeys"),
            t.text(),
        )),
    }
    lines.push(Line::styled(
        "Small pieces of data (certificates, notes, keys) bound to a passkey. Readable without PIN.",
        t.dim(),
    ));
    f.render_widget(
        Paragraph::new(lines).block(panel(t, "Large blob storage")),
        top,
    );

    if app.credentials().is_none() {
        super::locked(app, f, body, "large blobs");
        return;
    }
    let capable = app.blob_capable();
    if capable.is_empty() {
        empty_state(
            f,
            body,
            t,
            "∅",
            "No passkeys with a large-blob key",
            &[Line::styled(
                "A site must request the largeBlob extension when creating the passkey.",
                t.dim(),
            )],
        );
        return;
    }
    let rows: Vec<Row> = capable
        .iter()
        .map(|c| {
            let entry = app.blob_for(&c.cred_id);
            let (size, preview) = match entry.and_then(|e| e.data.as_ref()) {
                Some(data) => (
                    format!("{} B", data.len()),
                    String::from_utf8(data.clone())
                        .map(|s| truncate(&s.replace('\n', " "), 40))
                        .unwrap_or_else(|_| "(binary)".into()),
                ),
                None if session.and_then(|s| s.blobs.as_ref()).is_some() => {
                    ("-".into(), String::new())
                }
                None => ("?".into(), "press u to load".into()),
            };
            Row::new(vec![
                Cell::from(Span::styled(c.rp_id.clone(), t.bold())),
                Cell::from(Span::styled(c.user_name.clone(), t.text())),
                Cell::from(Span::styled(size, t.text())),
                Cell::from(Span::styled(preview, t.dim())),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(28),
            Constraint::Percentage(24),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(Row::new(["Site", "User", "Size", "Preview"]).style(t.dim()))
    .row_highlight_style(t.selected())
    .highlight_symbol("› ")
    .block(panel(t, "Passkeys with blob storage"));
    let mut state = TableState::default().with_selected(Some(app.blob_list.selected));
    f.render_stateful_widget(table, body, &mut state);
}
