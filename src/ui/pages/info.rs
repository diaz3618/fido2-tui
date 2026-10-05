use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::App;
use crate::ui::widgets::*;

fn option_meaning(name: &str) -> &'static str {
    match name {
        "plat" => "platform authenticator (built into a device)",
        "rk" => "can store discoverable credentials (passkeys)",
        "up" => "can test user presence (touch)",
        "uv" => "built-in user verification configured",
        "clientPin" => "PIN set (true) / supported but unset (false)",
        "pinUvAuthToken" => "supports CTAP 2.1 permission tokens",
        "credMgmt" => "credential management",
        "credentialMgmtPreview" => "credential management (pre-2.1)",
        "bioEnroll" => "fingerprints enrolled (true) / sensor unused (false)",
        "userVerificationMgmtPreview" => "fingerprint management (pre-2.1)",
        "largeBlobs" => "large blob storage",
        "authnrCfg" => "authenticator configuration commands",
        "alwaysUv" => "always require user verification",
        "setMinPINLength" => "minimum PIN length can be raised",
        "makeCredUvNotRqd" => "non-discoverable creds without UV",
        "noMcGaPermissionsWithClientPin" => "legacy PIN token disabled",
        "ep" => "enterprise attestation",
        "perCredMgmtRO" => "read-only credential management token",
        "uvAcfg" => "UV can authorize config",
        "uvBioEnroll" => "UV can authorize fingerprint enrollment",
        _ => "",
    }
}

pub fn render(app: &App, f: &mut Frame, area: Rect) {
    let t = &app.theme;
    let Some(d) = app.device() else { return };
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
    let w = 20;
    let opt = |v: u64| {
        if v == 0 {
            "-".to_string()
        } else {
            v.to_string()
        }
    };
    let mut l = vec![
        Line::styled("Identity", t.title()),
        kv(t, "Product", d.product.clone(), w),
        kv(t, "Manufacturer", d.manufacturer.clone(), w),
        kv(
            t,
            "Model (AAGUID)",
            d.aaguid_name.clone().unwrap_or_else(|| "unknown".into()),
            w,
        ),
        kv(
            t,
            "AAGUID",
            d.aaguid.clone().unwrap_or_else(|| "-".into()),
            w,
        ),
        kv(
            t,
            "USB VID:PID",
            format!("{:04x}:{:04x}", d.vendor_id, d.product_id),
            w,
        ),
        kv(
            t,
            "Firmware",
            d.fw_version_string().unwrap_or_else(|| "-".into()),
            w,
        ),
        kv(t, "CTAPHID version", d.ctaphid_version.clone(), w),
        kv(t, "Path", d.path.clone(), w),
        Line::raw(""),
        Line::styled("Limits", t.title()),
        kv(t, "Max message size", opt(d.max_msg_size), w),
        kv(t, "Creds per request", opt(d.max_creds_in_list), w),
        kv(t, "Max credential ID", opt(d.max_cred_id_len), w),
        kv(t, "Max credBlob", opt(d.max_cred_blob_len), w),
        kv(t, "Large blob storage", opt(d.max_large_blob), w),
        kv(
            t,
            "Min PIN length",
            d.min_pin_len.map_or("-".into(), |n| n.to_string()),
            w,
        ),
        kv(t, "minPinLength RPs", opt(d.max_rpids_min_pin), w),
        kv(
            t,
            "Free passkey slots",
            d.rk_remaining
                .map_or("not reported".into(), |n| n.to_string()),
            w,
        ),
        Line::raw(""),
        Line::styled("Protocols", t.title()),
        kv(t, "Versions", d.versions.join(", "), w),
        kv(t, "Algorithms", d.algorithms.join(", "), w),
        kv(
            t,
            "Transports",
            if d.transports.is_empty() {
                "usb (not reported)".into()
            } else {
                d.transports.join(", ")
            },
            w,
        ),
    ];
    l.push(Line::styled(format!("{:<w$}", "Extensions"), t.dim()));
    for e in &d.extensions {
        l.push(Line::styled(format!("  • {e}"), t.text()));
    }
    f.render_widget(
        Paragraph::new(l)
            .block(panel(t, "authenticatorGetInfo"))
            .wrap(Wrap { trim: false })
            .scroll((app.info_scroll, 0)),
        left,
    );

    let mut r = Vec::new();
    for (name, val) in &d.options {
        r.push(Line::from(vec![
            Span::styled(
                if *val { " ✓ " } else { " ✗ " },
                t.fg(if *val { t.success } else { t.muted }),
            ),
            Span::styled(format!("{name:<30}"), t.bold()),
        ]));
        let m = option_meaning(name);
        if !m.is_empty() {
            r.push(Line::styled(format!("     {m}"), t.dim()));
        }
    }
    f.render_widget(
        Paragraph::new(r)
            .block(panel(t, "Options"))
            .scroll((app.info_scroll, 0)),
        right,
    );
}
