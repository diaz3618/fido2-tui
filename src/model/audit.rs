use serde::{Deserialize, Serialize};

use crate::model::{FidoDevice, PasskeyCredential, StorageStats};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckStatus {
    Fail,
    Warn,
    Info,
    Pass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditCheck {
    pub title: String,
    pub status: CheckStatus,
    pub detail: String,
    /// What the user can do about it (and where in the app).
    pub fix: Option<String>,
    /// Points this check is worth towards the score.
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub timestamp: String,
    pub device_name: String,
    pub device_path: String,
    pub aaguid: Option<String>,
    pub firmware: Option<String>,
    pub score: u32,
    pub grade: String,
    pub checks: Vec<AuditCheck>,
    pub passkey_count: Option<usize>,
    pub storage: Option<StorageStats>,
}

/// Extra context that improves the audit when available.
#[derive(Debug, Default, Clone)]
pub struct AuditContext<'a> {
    pub credentials: Option<&'a [PasskeyCredential]>,
    pub storage: Option<StorageStats>,
    pub fingerprints: Option<usize>,
    pub luks_fido2_enrolled: Option<bool>,
}

impl AuditReport {
    pub fn build(dev: &FidoDevice, ctx: &AuditContext) -> Self {
        let mut checks = Vec::new();
        let mut add = |title: &str, status, detail: String, fix: Option<&str>, weight| {
            checks.push(AuditCheck {
                title: title.to_string(),
                status,
                detail,
                fix: fix.map(String::from),
                weight,
            })
        };

        // PIN
        if !dev.supports_pin() {
            add(
                "Client PIN",
                CheckStatus::Warn,
                "This key does not support a PIN".into(),
                None,
                30,
            );
        } else if dev.is_pin_blocked() {
            add(
                "Client PIN",
                CheckStatus::Fail,
                "PIN is blocked (0 retries left)".into(),
                Some("Factory reset is the only recovery (PIN & Security → Reset)"),
                30,
            );
        } else if dev.has_pin_set() {
            add(
                "Client PIN",
                CheckStatus::Pass,
                "A PIN protects this key".into(),
                None,
                30,
            );
        } else {
            add(
                "Client PIN",
                CheckStatus::Fail,
                "No PIN set - anyone holding the key can use its passkeys and you cannot manage them".into(),
                Some("Set a PIN in PIN & Security (press p)"),
                30,
            );
        }

        if let Some(r) = dev.pin_retries.filter(|_| dev.has_pin_set()) {
            let status = if r >= 5 {
                CheckStatus::Pass
            } else if r > 0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            };
            add(
                "PIN retries",
                status,
                format!("{r} attempts remaining before lock-out"),
                None,
                5,
            );
        }

        if dev.pin_change_required {
            add(
                "PIN change",
                CheckStatus::Warn,
                "The key requires a new PIN before it can be used".into(),
                Some("Change the PIN in PIN & Security"),
                5,
            );
        }

        // Minimum PIN length
        match dev.min_pin_len {
            Some(n) if n >= 6 => add(
                "Minimum PIN length",
                CheckStatus::Pass,
                format!("Enforced at {n} characters"),
                None,
                10,
            ),
            Some(n) => add(
                "Minimum PIN length",
                CheckStatus::Warn,
                format!("Only {n} characters required"),
                dev.supports_min_pin()
                    .then_some("Raise it to 6+ in PIN & Security (press m)"),
                10,
            ),
            None => add(
                "Minimum PIN length",
                CheckStatus::Info,
                "Not reported by this key".into(),
                None,
                0,
            ),
        }

        // Always UV
        if dev.supports_always_uv() {
            if dev.is_always_uv() {
                add(
                    "Always require UV",
                    CheckStatus::Pass,
                    "PIN/biometric required for every use".into(),
                    None,
                    10,
                );
            } else {
                add(
                    "Always require UV",
                    CheckStatus::Info,
                    "Some sites can sign in with touch only (U2F-style)".into(),
                    dev.supports_config()
                        .then_some("Enable Always-UV in PIN & Security (press u)"),
                    5,
                );
            }
        }

        // Firmware / protocol
        let v21 = dev.versions.iter().any(|v| {
            v.starts_with("FIDO_2_1") || v.starts_with("FIDO_2_2") || v.starts_with("FIDO_2_3")
        });
        add(
            "CTAP version",
            if v21 {
                CheckStatus::Pass
            } else {
                CheckStatus::Info
            },
            if v21 {
                "Supports CTAP 2.1+ (credential management, config commands)".into()
            } else {
                "CTAP 2.0 only - fewer management features".into()
            },
            None,
            5,
        );

        if dev.has_extension("credProtect") {
            add(
                "credProtect",
                CheckStatus::Pass,
                "Credentials can require UV to be discovered".into(),
                None,
                5,
            );
        }

        // Biometrics
        if dev.supports_bio() {
            match ctx.fingerprints {
                Some(0) => add(
                    "Fingerprints",
                    CheckStatus::Info,
                    "Sensor present but no fingerprints enrolled".into(),
                    Some("Enroll one in Fingerprints"),
                    0,
                ),
                Some(n) => add(
                    "Fingerprints",
                    CheckStatus::Pass,
                    format!("{n} fingerprint(s) enrolled"),
                    None,
                    0,
                ),
                None => {}
            }
        }

        // Storage
        let storage = ctx.storage.or_else(|| {
            dev.rk_remaining.map(|r| StorageStats {
                existing: ctx.credentials.map_or(0, |c| c.len() as u64),
                remaining: r as u64,
            })
        });
        if let Some(s) = storage {
            let status = if s.remaining == 0 {
                CheckStatus::Fail
            } else if s.usage_ratio() >= 0.8 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            };
            add(
                "Passkey storage",
                status,
                format!("{} used, {} free", s.existing, s.remaining),
                (status != CheckStatus::Pass)
                    .then_some("Remove unused passkeys in Passkeys (press d)"),
                5,
            );
        }

        if let Some(creds) = ctx.credentials {
            let weak = creds.iter().filter(|c| c.cred_protect <= 1).count();
            if weak > 0 {
                add(
                    "Passkey protection",
                    CheckStatus::Info,
                    format!("{weak} passkey(s) can be discovered without UV (credProtect level 1)"),
                    None,
                    0,
                );
            }
        }

        if let Some(enrolled) = ctx.luks_fido2_enrolled {
            add(
                "Disk encryption",
                CheckStatus::Info,
                if enrolled {
                    "A LUKS2 volume can be unlocked with a FIDO2 key".into()
                } else {
                    "No LUKS2 volume uses a FIDO2 token".into()
                },
                None,
                0,
            );
        }

        let total: u32 = checks.iter().map(|c| c.weight).sum();
        let earned: u32 = checks
            .iter()
            .map(|c| match c.status {
                CheckStatus::Pass => c.weight,
                CheckStatus::Info => c.weight / 2,
                CheckStatus::Warn => c.weight / 3,
                CheckStatus::Fail => 0,
            })
            .sum();
        let score = (earned * 100).checked_div(total).unwrap_or(0);
        let grade = match score {
            90.. => "A",
            75..=89 => "B",
            60..=74 => "C",
            40..=59 => "D",
            _ => "F",
        }
        .to_string();

        checks.sort_by_key(|c| c.status);
        AuditReport {
            timestamp: chrono::Local::now().to_rfc3339(),
            device_name: dev.display_name(),
            device_path: dev.path.clone(),
            aaguid: dev.aaguid.clone(),
            firmware: dev.fw_version_string(),
            score,
            grade,
            checks,
            passkey_count: ctx.credentials.map(|c| c.len()),
            storage,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_csv(&self) -> String {
        let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        let mut out = String::from("check,status,detail,fix\n");
        for c in &self.checks {
            out.push_str(&format!(
                "{},{:?},{},{}\n",
                esc(&c.title),
                c.status,
                esc(&c.detail),
                esc(c.fix.as_deref().unwrap_or(""))
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(opts: &[(&str, bool)]) -> FidoDevice {
        FidoDevice {
            path: "/dev/hidraw0".into(),
            options: opts.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            versions: vec!["FIDO_2_1".into()],
            min_pin_len: Some(4),
            ..Default::default()
        }
    }

    #[test]
    fn missing_pin_fails_and_lowers_grade() {
        let r = AuditReport::build(
            &dev(&[("clientPin", false), ("alwaysUv", false)]),
            &AuditContext::default(),
        );
        assert_eq!(r.checks[0].status, CheckStatus::Fail);
        assert_eq!(r.checks[0].title, "Client PIN");
        assert!(r.score < 60, "score {}", r.score);
    }

    #[test]
    fn hardened_key_scores_high() {
        let mut d = dev(&[
            ("clientPin", true),
            ("alwaysUv", true),
            ("setMinPINLength", true),
        ]);
        d.min_pin_len = Some(8);
        d.pin_retries = Some(8);
        d.extensions = vec!["credProtect".into()];
        let r = AuditReport::build(&d, &AuditContext::default());
        assert_eq!(r.grade, "A");
        assert!(r.checks.iter().all(|c| c.status != CheckStatus::Fail));
    }

    #[test]
    fn csv_escapes_quotes() {
        let r = AuditReport::build(&dev(&[("clientPin", false)]), &AuditContext::default());
        let csv = r.to_csv();
        assert!(csv.starts_with("check,status,detail,fix\n"));
        assert!(csv.contains("\"Client PIN\",Fail"));
    }
}
