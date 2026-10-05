mod audit;
mod bio;
mod blobs;
mod disk;
mod info;
mod overview;
mod passkeys;
mod security;
mod ssh;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Padding;

use super::widgets::*;
use crate::app::{App, Page};

pub fn render_page(app: &App, f: &mut Frame, area: Rect) {
    let inner = ratatui::widgets::Block::default()
        .padding(Padding::new(1, 1, 0, 0))
        .inner(area);
    let needs_device = !matches!(app.page, Page::Disk | Page::Ssh | Page::Overview);
    if needs_device && app.device().is_none() {
        overview::no_device(app, f, inner);
        return;
    }
    match app.page {
        Page::Overview => overview::render(app, f, inner),
        Page::Passkeys => passkeys::render(app, f, inner),
        Page::Security => security::render(app, f, inner),
        Page::Fingerprints => bio::render(app, f, inner),
        Page::LargeBlobs => blobs::render(app, f, inner),
        Page::Ssh => ssh::render(app, f, inner),
        Page::Disk => disk::render(app, f, inner),
        Page::Audit => audit::render(app, f, inner),
        Page::Info => info::render(app, f, inner),
    }
}

/// Context-sensitive key hints for the footer.
pub fn page_hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let no_pin = app
        .device()
        .is_some_and(|d| d.supports_pin() && !d.has_pin_set());
    let needs_pin = matches!(
        app.page,
        Page::Passkeys | Page::LargeBlobs | Page::Fingerprints
    );
    let mut h: Vec<(&str, &str)> = match app.page {
        _ if no_pin && needs_pin => vec![("p", "set PIN")],
        Page::Fingerprints if app.device().is_some_and(|d| !d.supports_bio()) => vec![],
        Page::LargeBlobs if app.device().is_some_and(|d| !d.supports_large_blobs()) => vec![],
        Page::Overview if app.device().is_some() => {
            let mut v = vec![("t", "self-test"), ("i", "identify")];
            if app.device().is_some_and(|d| d.has_pin_set()) {
                v.push(if app.is_unlocked() {
                    ("L", "lock")
                } else {
                    ("u", "unlock")
                });
                v.push(("p", "change PIN"));
            } else {
                v.push(("p", "set PIN"));
            }
            v
        }
        Page::Passkeys if app.searching => vec![
            ("type", "filter"),
            ("enter/esc", "done"),
            ("ctrl+u", "clear"),
        ],
        Page::Passkeys if app.credentials().is_some() => vec![
            ("j/k", "move"),
            ("/", "search"),
            ("enter", "details"),
            ("e", "edit"),
            ("d", "delete"),
            ("x", "export"),
        ],
        Page::Passkeys => vec![("u", "unlock")],
        Page::Security => vec![
            ("j/k", "move"),
            ("enter", "run"),
            ("p", "PIN"),
            ("v", "verify"),
            ("R", "reset"),
        ],
        Page::Fingerprints => vec![
            ("n", "add"),
            ("e", "rename"),
            ("d", "delete"),
            ("u", "unlock"),
        ],
        Page::LargeBlobs => vec![
            ("enter", "view"),
            ("e", "write"),
            ("s", "save"),
            ("d", "delete"),
            ("u", "load"),
        ],
        Page::Ssh => vec![
            ("n", "new key"),
            ("l", "load from key"),
            ("enter", "public key"),
            ("u", "unlock"),
        ],
        Page::Disk => vec![
            ("e", "enroll"),
            ("t", "test"),
            ("x", "remove"),
            ("b", "backup"),
            ("c", "boot"),
            ("n", "practice"),
        ],
        Page::Audit => vec![("j/k", "scroll"), ("x", "JSON"), ("c", "CSV")],
        Page::Info => vec![("j/k", "scroll")],
        _ => vec![],
    };
    h.extend([("tab", "page"), ("?", "help"), ("q", "quit")]);
    h
}

/// "Unlock with your PIN" placeholder.
pub(super) fn locked(app: &App, f: &mut Frame, area: Rect, what: &str) {
    let t = &app.theme;
    let d = app.device();
    if d.is_some_and(|d| !d.has_pin_set()) {
        empty_state(
            f,
            area,
            t,
            "",
            "This key has no PIN",
            &[
                Line::styled(format!("A PIN is required to manage {what}."), t.text()),
                Line::raw(""),
                hints(t, &[("p", "set a PIN now")]),
            ],
        );
    } else {
        let retries = d
            .and_then(|d| d.pin_retries)
            .map(|r| format!("{r} PIN attempts remaining"))
            .unwrap_or_default();
        empty_state(
            f,
            area,
            t,
            "",
            &format!("{} are protected by your PIN", capitalize(what)),
            &[
                Line::styled(retries, t.dim()),
                Line::raw(""),
                hints(t, &[("u", "unlock")]),
            ],
        );
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}
