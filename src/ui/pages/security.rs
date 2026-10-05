use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::ui::widgets::*;

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(d) = app.device() else { return };
    let [cols, _] = Layout::vertical([Constraint::Length(14), Constraint::Min(0)]).areas(area);
    let [left, right] =
        Layout::horizontal([Constraint::Length(42), Constraint::Min(40)]).areas(cols);

    let w = 18;
    let mut st = Vec::new();
    if !d.supports_pin() {
        st.push(Line::styled("This key does not support a PIN.", t.dim()));
    } else {
        st.push(kv_styled(
            t,
            "PIN",
            if d.has_pin_set() { "set" } else { "not set" },
            t.fg(if d.has_pin_set() {
                t.success
            } else {
                t.warning
            }),
            w,
        ));
        if let Some(r) = d.pin_retries {
            let mut s = vec![Span::styled(format!("{:<w$}", "PIN retries"), t.dim())];
            s.extend(dots(t, r, 8.max(r)));
            s.push(Span::styled(format!(" {r}"), t.text()));
            st.push(Line::from(s));
        }
        if let Some(r) = d.uv_retries {
            st.push(kv(t, "UV retries", r.to_string(), w));
        }
        st.push(kv(
            t,
            "Min PIN length",
            d.min_pin_len.map_or("-".into(), |n| n.to_string()),
            w,
        ));
        if d.pin_change_required {
            st.push(kv_styled(t, "PIN change", "required", t.fg(t.warning), w));
        }
    }
    if d.supports_always_uv() {
        st.push(kv(
            t,
            "Always-UV",
            if d.is_always_uv() { "on" } else { "off" },
            w,
        ));
    }
    st.push(kv(
        t,
        "PIN protocols",
        d.pin_protocols
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        w,
    ));
    if !d.uv_modalities().is_empty() {
        st.push(kv(t, "UV methods", d.uv_modalities().join(", "), w));
    }
    st.push(Line::raw(""));
    st.push(kv_styled(
        t,
        "Session",
        if app.is_unlocked() {
            "unlocked (PIN in memory)"
        } else {
            "locked"
        },
        if app.is_unlocked() {
            t.fg(t.success)
        } else {
            t.dim()
        },
        w,
    ));
    f.render_widget(
        Paragraph::new(st)
            .block(panel(t, "Status"))
            .wrap(Wrap { trim: true }),
        left,
    );

    let items = app.security_items();
    let mut lines = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let sel = i == app.security.selected;
        let ok = item.available.is_ok();
        let base = if item.danger {
            Style::default().fg(t.danger)
        } else {
            t.text()
        };
        let style = if !ok {
            t.dim()
        } else if sel {
            base.add_modifier(Modifier::BOLD)
        } else {
            base
        };
        let mut l = Line::from(vec![
            Span::styled(if sel { "› " } else { "  " }, t.fg(t.accent)),
            Span::styled(item.label.clone(), style),
        ]);
        if sel {
            l = l.style(Style::default().bg(t.selection));
        }
        lines.push(l);
        if sel {
            lines.push(Line::styled(format!("    {}", item.description), t.dim()));
            if let Err(why) = &item.available {
                lines.push(Line::styled(format!("    ! {why}"), t.fg(t.warning)));
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(panel(t, "Actions"))
            .wrap(Wrap { trim: false }),
        right,
    );
}
