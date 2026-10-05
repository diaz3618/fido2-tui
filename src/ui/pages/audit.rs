use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::model::CheckStatus;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(r) = app.audit() else { return };
    let [head, body] = Layout::vertical([Constraint::Length(5), Constraint::Min(5)]).areas(area);
    let color = match r.grade.as_str() {
        "A" => t.success,
        "B" => t.info,
        "C" => t.warning,
        _ => t.danger,
    };
    let mut gauge = vec![Span::styled("Score  ", t.dim())];
    gauge.extend(bar(t, r.score as f64 / 100.0, 30, color));
    gauge.push(Span::styled(format!("  {}/100", r.score), t.text()));
    let depth = if app.credentials().is_some() {
        Line::styled("Full audit (passkeys loaded)", t.dim())
    } else {
        Line::from(vec![
            Span::styled("Basic audit - ", t.dim()),
            Span::styled("u", t.key()),
            Span::styled(" unlock to include passkeys", t.dim()),
        ])
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("Grade  ", t.dim()),
            Span::styled(
                format!(" {} ", r.grade),
                t.badge(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   {} · {}", r.device_name, r.device_path),
                t.text(),
            ),
        ]),
        Line::from(gauge),
        depth,
    ];
    f.render_widget(
        Paragraph::new(lines).block(panel(t, "Security posture")),
        head,
    );

    let mut out = Vec::new();
    for c in &r.checks {
        let (icon, col) = match c.status {
            CheckStatus::Pass => ("✓", t.success),
            CheckStatus::Info => ("ℹ", t.info),
            CheckStatus::Warn => ("!", t.warning),
            CheckStatus::Fail => ("✗", t.danger),
        };
        out.push(Line::from(vec![
            Span::styled(
                format!(" {icon} "),
                Style::default().fg(col).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:<22}", c.title), t.bold()),
            Span::styled(c.detail.clone(), t.text()),
        ]));
        if let Some(fix) = &c.fix {
            out.push(Line::styled(
                format!("   {:<22}→ {fix}", ""),
                t.fg(t.accent),
            ));
        }
    }
    f.render_widget(
        Paragraph::new(out)
            .block(panel(t, "Checks"))
            .wrap(Wrap { trim: false })
            .scroll((app.audit_scroll, 0)),
        body,
    );
}
