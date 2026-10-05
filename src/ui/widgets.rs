//! Small reusable rendering helpers.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap};

use super::theme::Theme;

pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn spinner(tick: u64) -> &'static str {
    SPINNER[(tick as usize) % SPINNER.len()]
}

pub fn panel<'a>(t: &Theme, title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(t.border(false))
        .title(Span::styled(format!(" {title} "), t.title()))
        .padding(Padding::horizontal(1))
}

pub fn panel_focused<'a>(t: &Theme, title: &'a str) -> Block<'a> {
    panel(t, title).border_style(t.border(true))
}

pub fn kv<'a>(t: &Theme, key: &'a str, value: impl Into<String>, width: usize) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<width$}"), t.dim()),
        Span::styled(value.into(), t.text()),
    ])
}

pub fn kv_styled<'a>(
    t: &Theme,
    key: &'a str,
    value: impl Into<String>,
    style: Style,
    width: usize,
) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<width$}"), t.dim()),
        Span::styled(value.into(), style),
    ])
}

/// Text gauge like `━━━━━━────  12 / 25`.
pub fn bar(t: &Theme, ratio: f64, width: usize, color: Color) -> Vec<Span<'static>> {
    let ratio = ratio.clamp(0.0, 1.0);
    let filled = ((ratio * width as f64).round() as usize).min(width);
    vec![
        Span::styled("━".repeat(filled), Style::default().fg(color)),
        Span::styled("─".repeat(width - filled), t.fg(t.border)),
    ]
}

pub fn usage_color(t: &Theme, ratio: f64) -> Color {
    if ratio >= 0.9 {
        t.danger
    } else if ratio >= 0.75 {
        t.warning
    } else {
        t.success
    }
}

/// `●●●●●○○○` style counter (e.g. PIN retries).
pub fn dots(t: &Theme, filled: u32, total: u32) -> Vec<Span<'static>> {
    let color = if filled <= 2 {
        t.danger
    } else if filled * 2 <= total {
        t.warning
    } else {
        t.success
    };
    vec![
        Span::styled("●".repeat(filled as usize), Style::default().fg(color)),
        Span::styled(
            "○".repeat(total.saturating_sub(filled) as usize),
            t.fg(t.border),
        ),
    ]
}

pub fn chip(t: &Theme, label: &str, on: bool) -> Vec<Span<'static>> {
    let (mark, style) = if on {
        ("✓ ", Style::default().fg(t.success))
    } else {
        ("· ", t.dim())
    };
    vec![
        Span::styled(mark.to_string(), style),
        Span::styled(format!("{label}   "), if on { t.text() } else { t.dim() }),
    ]
}

pub fn badge(t: &Theme, text: &str, color: Color) -> Span<'static> {
    Span::styled(format!(" {text} "), t.badge(color))
}

pub fn hints(t: &Theme, items: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, (k, d)) in items.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", t.dim()));
        }
        spans.push(Span::styled(k.to_string(), t.key()));
        spans.push(Span::styled(format!(" {d}"), t.dim()));
    }
    Line::from(spans)
}

pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(2));
    let h = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// A centered empty-state message inside `area`.
pub fn empty_state(
    f: &mut Frame,
    area: Rect,
    t: &Theme,
    icon: &str,
    title: &str,
    lines: &[Line<'static>],
) {
    let mut text = Vec::new();
    if !icon.is_empty() {
        text.push(
            Line::from(Span::styled(icon.to_string(), t.title())).alignment(Alignment::Center),
        );
        text.push(Line::raw(""));
    }
    text.extend([
        Line::from(Span::styled(title.to_string(), t.bold())).alignment(Alignment::Center),
        Line::raw(""),
    ]);
    text.extend(
        lines
            .iter()
            .cloned()
            .map(|l| l.alignment(Alignment::Center)),
    );
    let h = text.len() as u16 + 2;
    let box_area = centered(area, area.width.min(76), h);
    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), box_area);
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max <= 1 {
        "…".into()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

pub fn bold(style: Style) -> Style {
    style.add_modifier(Modifier::BOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
    }

    #[test]
    fn centered_fits() {
        let r = centered(Rect::new(0, 0, 100, 40), 50, 10);
        assert_eq!(r, Rect::new(25, 15, 50, 10));
        let small = centered(Rect::new(0, 0, 20, 5), 50, 10);
        assert!(small.width <= 18 && small.height <= 3);
    }
}
