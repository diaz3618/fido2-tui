use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::App;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(d) = app.device() else { return };
    if !d.supports_bio() {
        empty_state(
            f,
            area,
            t,
            "",
            "No fingerprint sensor",
            &[
                Line::styled(
                    format!("{} verifies you with its PIN only.", d.display_name()),
                    t.dim(),
                ),
                Line::styled(
                    "Biometric keys (e.g. YubiKey Bio, Token2 Bio) are managed here.",
                    t.dim(),
                ),
            ],
        );
        return;
    }
    let Some(list) = app.session().and_then(|s| s.bio.as_ref()) else {
        super::locked(app, f, area, "fingerprints");
        return;
    };
    let [info, body] = Layout::vertical([Constraint::Length(3), Constraint::Min(4)]).areas(area);
    let sensor = app.session().and_then(|s| s.bio_sensor);
    let text = match sensor {
        Some(s) => format!(
            "{} sensor · {} samples per enrollment · {} enrolled",
            s.sensor_label(),
            s.max_samples,
            list.len()
        ),
        None => format!("{} enrolled", list.len()),
    };
    f.render_widget(
        Paragraph::new(Line::styled(text, t.text())).block(panel(t, "Sensor")),
        info,
    );

    if list.is_empty() {
        empty_state(
            f,
            body,
            t,
            "",
            "No fingerprints enrolled",
            &[hints(t, &[("n", "add a fingerprint")])],
        );
        return;
    }
    let lines: Vec<Line> = list
        .iter()
        .enumerate()
        .map(|(i, tpl)| {
            let sel = i == app.bio_list.selected;
            let l = Line::from(vec![
                Span::styled(if sel { "› " } else { "  " }, t.fg(t.accent)),
                Span::styled(format!("{:<24}", tpl.display_name()), t.text()),
                Span::styled(format!("id {}", tpl.id_hex()), t.dim()),
            ]);
            if sel {
                l.style(Style::default().bg(t.selection))
            } else {
                l
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(panel(t, "Fingerprints")), body);
}
