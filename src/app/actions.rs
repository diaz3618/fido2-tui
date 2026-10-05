//! User-triggered operations. Each validates preconditions, asks for input or
//! confirmation when needed, and dispatches work to the job runner.

use std::time::Instant;

use zeroize::Zeroizing;

use super::jobs::{BlobEntry, Outcome, Reload};
use super::modal::*;
use super::{App, Page, ResetStage, ResetWizard};
use crate::model::*;
use crate::sys::{self, ExternalCommand};

const MAX_PIN_BYTES: usize = 63;

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Validate a new PIN against CTAP rules and the key's minimum length.
pub fn validate_new_pin(pin: &str, confirm: &str, min_len: usize) -> Result<(), String> {
    let chars = pin.chars().count();
    if chars < min_len {
        return Err(format!("PIN must be at least {min_len} characters"));
    }
    if pin.len() > MAX_PIN_BYTES {
        return Err(format!("PIN must be at most {MAX_PIN_BYTES} bytes"));
    }
    if pin != confirm {
        return Err("PINs do not match".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAction {
    SetPin,
    ChangePin,
    VerifyPin,
    MinPinLength,
    MinPinRpIds,
    AlwaysUv,
    ForcePinChange,
    Lock,
    FactoryReset,
}

pub struct SecurityItem {
    pub action: SecurityAction,
    pub label: String,
    pub description: String,
    pub available: Result<(), String>,
    pub danger: bool,
}

impl App {
    fn need_device(&mut self) -> Option<FidoDevice> {
        let d = self.device().cloned();
        if d.is_none() {
            self.notify(Level::Warn, "No security key connected");
        }
        d
    }

    /// Run `f` with the device PIN: cached for the session, or prompted for.
    pub fn require_pin(
        &mut self,
        reason: &str,
        f: impl FnOnce(&mut App, Zeroizing<String>) + 'static,
    ) {
        let Some(dev) = self.need_device() else {
            return;
        };
        if !dev.supports_pin() {
            self.notify(Level::Error, "This key does not support a PIN");
            return;
        }
        if dev.is_pin_blocked() {
            self.message(
                Level::Error,
                "PIN blocked",
                &[
                    "All PIN attempts were used.",
                    "Only a factory reset (PIN & Security) can recover this key.",
                ],
            );
            return;
        }
        if !dev.has_pin_set() {
            self.modal = Some(Modal::Confirm(
                Confirm::new(
                    "No PIN set",
                    vec![
                        "This key has no PIN yet. Managing passkeys, fingerprints and".into(),
                        "settings requires one (it also protects your passkeys).".into(),
                        String::new(),
                        "Set a PIN now?".into(),
                    ],
                    Box::new(|app| app.open_set_pin_form()),
                )
                .yes_label("Set PIN"),
            ));
            return;
        }
        if let Some(pin) = self.session().and_then(|s| s.pin.clone()) {
            f(self, pin);
            return;
        }
        self.modal = Some(Modal::Pin(PinPrompt {
            title: "Enter PIN".into(),
            reason: reason.into(),
            input: Zeroizing::new(String::new()),
            reveal: false,
            retries: dev.pin_retries,
            min_len: dev.min_pin_len.unwrap_or(4) as usize,
            error: None,
            on_submit: Some(Box::new(f)),
        }));
    }

    fn with_pin_job<F>(&mut self, pin: Zeroizing<String>, title: &str, touch: bool, f: F)
    where
        F: FnOnce(
                &dyn crate::fido::FidoBackend,
                &str,
                &str,
                &dyn Fn(crate::fido::Progress),
            ) -> crate::fido::FidoResult<Outcome>
            + Send
            + 'static,
    {
        let Some(path) = self.device_path() else {
            return;
        };
        let p = pin.clone();
        let job_path = path.clone();
        self.run_with_pin(title, touch, Some((path, pin)), move |b, prog| {
            f(b, &job_path, &p, prog)
        });
    }

    // Passkeys

    pub fn unlock(&mut self) {
        self.load_credentials(true);
    }

    pub fn lock(&mut self) {
        if let Some(s) = self.session_mut() {
            *s = Default::default();
            self.notify(
                Level::Info,
                "Locked - PIN and loaded data cleared from memory",
            );
        }
    }

    pub fn load_credentials(&mut self, prompt: bool) {
        let Some(dev) = self.device().cloned() else {
            return;
        };
        if !dev.supports_cred_mgmt() {
            if prompt {
                self.notify(
                    Level::Error,
                    "This key does not support credential management (CTAP 2.1)",
                );
            }
            return;
        }
        if !prompt && !self.is_unlocked() {
            return;
        }
        self.require_pin(
            "Unlock to list the passkeys stored on this key",
            |app, pin| {
                app.with_pin_job(pin, "Reading passkeys...", false, |b, path, pin, _| {
                    let stats = b.storage_stats(path, pin)?;
                    let creds = b.list_credentials(path, pin)?;
                    Ok(Outcome::Credentials {
                        path: path.to_string(),
                        creds,
                        stats: Some(stats),
                    })
                });
            },
        );
    }

    pub fn delete_credential(&mut self) {
        let Some(c) = self.selected_credential() else {
            return;
        };
        let body = vec![
            format!("Site:  {}", c.rp_id),
            format!(
                "User:  {}",
                if c.user_name.is_empty() {
                    "(none)"
                } else {
                    &c.user_name
                }
            ),
            String::new(),
            "You will no longer be able to sign in to this site with this key.".into(),
            "Make sure you have another sign-in method before continuing.".into(),
        ];
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Delete passkey?",
                body,
                Box::new(move |app| {
                    let id = c.cred_id.clone();
                    app.require_pin("Authorize passkey deletion", move |app, pin| {
                        app.with_pin_job(
                            pin,
                            "Deleting passkey...",
                            false,
                            move |b, path, pin, _| {
                                b.delete_credential(path, pin, &id)?;
                                Ok(Outcome::Done {
                                    message: "Passkey deleted".into(),
                                    reload: Reload::CREDS,
                                })
                            },
                        );
                    });
                }),
            )
            .danger(None)
            .yes_label("Delete"),
        ));
    }

    pub fn edit_credential(&mut self) {
        let Some(c) = self.selected_credential() else {
            return;
        };
        if !self.device().is_some_and(|d| {
            d.versions
                .iter()
                .any(|v| v != "FIDO_2_0" && v.starts_with("FIDO_2"))
        }) {
            self.notify(Level::Error, "Editing passkeys requires a CTAP 2.1 key");
            return;
        }
        let form = Form::new(
            format!("Edit passkey · {}", c.rp_id),
            vec![
                Field::text("User name", &c.user_name),
                Field::text("Display name", &c.user_display_name),
            ],
            Box::new(move |app, fields| {
                let name = fields[0].value.trim().to_string();
                let display = fields[1].value.trim().to_string();
                if name.is_empty() {
                    return Err("User name cannot be empty".into());
                }
                let cred = c.clone();
                app.require_pin("Authorize passkey update", move |app, pin| {
                    app.with_pin_job(pin, "Updating passkey...", false, move |b, path, pin, _| {
                        b.update_user(path, pin, &cred, &name, &display)?;
                        Ok(Outcome::Done {
                            message: "Passkey updated".into(),
                            reload: Reload::CREDS,
                        })
                    });
                });
                Ok(())
            }),
        )
        .describe(&["Only the names stored on the key change; the site keeps its own copy."]);
        self.modal = Some(Modal::Form(form));
    }

    pub fn show_credential_details(&mut self) {
        let Some(c) = self.selected_credential() else {
            return;
        };
        let mut lines = vec![
            format!("Relying party : {}", c.rp_id),
            format!(
                "RP name       : {}",
                c.rp_name.clone().unwrap_or_else(|| "-".into())
            ),
            format!("User name     : {}", c.user_name),
            format!("Display name  : {}", c.user_display_name),
            format!("Algorithm     : {}", c.algorithm),
            format!(
                "Protection    : {} (credProtect {})",
                c.cred_protect_label(),
                c.cred_protect
            ),
            format!(
                "Large blob key: {}",
                if c.large_blob_key.is_some() {
                    "yes"
                } else {
                    "no"
                }
            ),
            String::new(),
            "User handle (hex):".into(),
        ];
        lines.extend(wrap_hex(&c.user_id_hex(), 64));
        lines.push(String::new());
        lines.push("Credential ID (hex):".into());
        lines.extend(wrap_hex(&c.cred_id_hex(), 64));
        self.modal = Some(Modal::Text {
            title: format!("Passkey · {}", c.rp_id),
            lines,
            scroll: 0,
        });
    }

    pub fn export_credentials(&mut self) {
        let (Some(dev), Some(creds)) = (
            self.device().cloned(),
            self.credentials().map(|c| c.to_vec()),
        ) else {
            self.notify(Level::Warn, "Unlock passkeys first (press u)");
            return;
        };
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let path = sys::home().join(format!("fido2-passkeys-{}-{stamp}.json", dev.short_path()));
        let doc = serde_json::json!({
            "device": dev.display_name(),
            "aaguid": dev.aaguid,
            "exported_at": chrono::Local::now().to_rfc3339(),
            "note": "Metadata only - private keys never leave the security key.",
            "passkeys": creds,
        });
        match std::fs::write(
            &path,
            serde_json::to_string_pretty(&doc).unwrap_or_default(),
        ) {
            Ok(()) => self.notify(
                Level::Success,
                format!("Exported {} passkeys to {}", creds.len(), path.display()),
            ),
            Err(e) => self.notify(Level::Error, format!("Export failed: {e}")),
        }
    }

    // Security

    pub fn security_items(&self) -> Vec<SecurityItem> {
        let Some(d) = self.device() else {
            return Vec::new();
        };
        let pin = d.has_pin_set();
        let need_pin = |ok: bool, why: &str| -> Result<(), String> {
            if !ok {
                Err(why.to_string())
            } else if !pin {
                Err("Set a PIN first".into())
            } else {
                Ok(())
            }
        };
        let mut items = Vec::new();
        if !pin {
            items.push(SecurityItem {
                action: SecurityAction::SetPin,
                label: "Set PIN".into(),
                description: "Protect the key with a PIN (required for passkey management)".into(),
                available: if d.supports_pin() {
                    Ok(())
                } else {
                    Err("Key has no PIN support".into())
                },
                danger: false,
            });
        } else {
            items.push(SecurityItem {
                action: SecurityAction::ChangePin,
                label: "Change PIN".into(),
                description: "Replace the current PIN".into(),
                available: Ok(()),
                danger: false,
            });
            items.push(SecurityItem {
                action: SecurityAction::VerifyPin,
                label: "Verify PIN".into(),
                description: "Check that you remember the PIN (uses a retry only if wrong)".into(),
                available: need_pin(d.supports_cred_mgmt(), "Requires credential management"),
                danger: false,
            });
        }
        items.push(SecurityItem {
            action: SecurityAction::MinPinLength,
            label: format!(
                "Minimum PIN length ({})",
                d.min_pin_len.map_or("?".into(), |n| n.to_string())
            ),
            description: "Raise the minimum PIN length (it can never be lowered without a reset)"
                .into(),
            available: need_pin(d.supports_min_pin(), "Not supported by this key"),
            danger: false,
        });
        items.push(SecurityItem {
            action: SecurityAction::MinPinRpIds,
            label: "Sites allowed to read min PIN length".into(),
            description: "Let specific relying parties (e.g. your IdP) see the PIN-length policy"
                .into(),
            available: need_pin(
                d.supports_min_pin() && d.max_rpids_min_pin > 0,
                "Not supported by this key",
            ),
            danger: false,
        });
        items.push(SecurityItem {
            action: SecurityAction::AlwaysUv,
            label: format!(
                "Always require PIN/UV ({})",
                if d.is_always_uv() { "on" } else { "off" }
            ),
            description: "Require user verification for every sign-in, including U2F".into(),
            available: need_pin(
                d.supports_config() && d.supports_always_uv(),
                "Not supported by this key",
            ),
            danger: false,
        });
        items.push(SecurityItem {
            action: SecurityAction::ForcePinChange,
            label: "Require PIN change".into(),
            description: "Force a new PIN to be chosen before the key can be used again".into(),
            available: need_pin(d.supports_min_pin(), "Not supported by this key"),
            danger: false,
        });
        items.push(SecurityItem {
            action: SecurityAction::Lock,
            label: "Lock session".into(),
            description: "Forget the PIN and loaded passkeys from this app's memory".into(),
            available: if self.is_unlocked() {
                Ok(())
            } else {
                Err("Not unlocked".into())
            },
            danger: false,
        });
        items.push(SecurityItem {
            action: SecurityAction::FactoryReset,
            label: "Factory reset".into(),
            description: "Erase ALL passkeys, fingerprints and the PIN".into(),
            available: if d.is_fido2 {
                Ok(())
            } else {
                Err("Not a FIDO2 key".into())
            },
            danger: true,
        });
        items
    }

    pub fn run_security_action(&mut self, action: SecurityAction) {
        match action {
            SecurityAction::SetPin => self.open_set_pin_form(),
            SecurityAction::ChangePin => self.open_change_pin_form(),
            SecurityAction::VerifyPin => self.verify_pin(),
            SecurityAction::MinPinLength => self.open_min_pin_form(),
            SecurityAction::MinPinRpIds => self.open_min_pin_rpids_form(),
            SecurityAction::AlwaysUv => self.toggle_always_uv(),
            SecurityAction::ForcePinChange => self.force_pin_change(),
            SecurityAction::Lock => self.lock(),
            SecurityAction::FactoryReset => self.start_factory_reset(),
        }
    }

    pub fn open_set_pin_form(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        let min = dev.min_pin_len.unwrap_or(4) as usize;
        let form = Form::new(
            "Set PIN",
            vec![
                Field::secret("New PIN").hint(&format!("{min}–63 characters; letters allowed")),
                Field::secret("Confirm PIN"),
            ],
            Box::new(move |app, f| {
                validate_new_pin(&f[0].value, &f[1].value, min)?;
                let new = Zeroizing::new(f[0].value.clone());
                let Some(path) = app.device_path() else {
                    return Err("Key disconnected".into());
                };
                let job_pin = new.clone();
                let job_path = path.clone();
                app.run_with_pin("Setting PIN...", false, Some((path, new)), move |b, _| {
                    b.set_pin(&job_path, &job_pin)?;
                    Ok(Outcome::Done {
                        message: "PIN set".into(),
                        reload: Reload::DEVICES,
                    })
                });
                Ok(())
            }),
        )
        .describe(&[
            "The PIN protects your passkeys. After 8 wrong attempts the key locks",
            "and must be factory reset, erasing everything on it.",
        ])
        .submit_label("Set PIN");
        self.modal = Some(Modal::Form(form));
    }

    pub fn open_change_pin_form(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        let min = dev.min_pin_len.unwrap_or(4) as usize;
        let retries = dev
            .pin_retries
            .map(|r| format!("{r} attempts left"))
            .unwrap_or_default();
        let form = Form::new(
            "Change PIN",
            vec![
                Field::secret("Current PIN").hint(&retries),
                Field::secret("New PIN").hint(&format!("at least {min} characters")),
                Field::secret("Confirm new PIN"),
            ],
            Box::new(move |app, f| {
                if f[0].value.is_empty() {
                    return Err("Enter the current PIN".into());
                }
                validate_new_pin(&f[1].value, &f[2].value, min)?;
                if f[0].value == f[1].value {
                    return Err("The new PIN must differ from the current one".into());
                }
                let old = Zeroizing::new(f[0].value.clone());
                let new = Zeroizing::new(f[1].value.clone());
                let Some(path) = app.device_path() else {
                    return Err("Key disconnected".into());
                };
                if let Some(s) = app.sessions.get_mut(&path) {
                    s.pin = None;
                }
                let job_path = path.clone();
                let job_new = new.clone();
                app.run_with_pin("Changing PIN...", false, Some((path, new)), move |b, _| {
                    b.change_pin(&job_path, &old, &job_new)?;
                    Ok(Outcome::Done {
                        message: "PIN changed".into(),
                        reload: Reload::DEVICES,
                    })
                });
                Ok(())
            }),
        )
        .submit_label("Change PIN");
        self.modal = Some(Modal::Form(form));
    }

    pub fn verify_pin(&mut self) {
        let Some(path) = self.device_path() else {
            return;
        };
        // Always prompt, even if cached: the point is to check what the user remembers.
        if let Some(s) = self.sessions.get_mut(&path) {
            s.pin = None;
        }
        self.require_pin("Check that you remember this key's PIN", |app, pin| {
            app.with_pin_job(pin, "Verifying PIN...", false, |b, path, pin, _| {
                b.verify_pin(path, pin)?;
                Ok(Outcome::Done {
                    message: "PIN is correct".into(),
                    reload: Reload::DEVICES,
                })
            });
        });
    }

    pub fn open_min_pin_form(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        let cur = dev.min_pin_len.unwrap_or(4) as i64;
        let form = Form::new(
            "Minimum PIN length",
            vec![Field::number("Minimum length", cur.max(6), cur, 63)],
            Box::new(move |app, f| {
                let n = f[0].number_value()? as usize;
                if n as i64 == cur {
                    return Err(format!("Already {cur}"));
                }
                app.require_pin("Authorize changing the PIN policy", move |app, pin| {
                    app.with_pin_job(
                        pin,
                        "Updating PIN policy...",
                        false,
                        move |b, path, pin, _| {
                            b.set_min_pin_length(path, pin, n)?;
                            Ok(Outcome::Done {
                                message: format!("Minimum PIN length is now {n}"),
                                reload: Reload::DEVICES,
                            })
                        },
                    );
                });
                Ok(())
            }),
        )
        .describe(&[
            "The length can only be increased. If your current PIN is shorter,",
            "the key will require you to change it before next use.",
        ])
        .submit_label("Apply");
        self.modal = Some(Modal::Form(form));
    }

    pub fn open_min_pin_rpids_form(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        let max = dev.max_rpids_min_pin;
        let form = Form::new(
            "minPinLength relying parties",
            vec![Field::text("RP IDs", "").hint("comma-separated, e.g. login.microsoft.com")],
            Box::new(move |app, f| {
                let rps: Vec<String> = f[0]
                    .value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if rps.is_empty() {
                    return Err("Enter at least one RP ID".into());
                }
                if rps.len() as u64 > max {
                    return Err(format!("This key accepts at most {max} RP IDs"));
                }
                app.require_pin("Authorize changing the PIN policy", move |app, pin| {
                    app.with_pin_job(
                        pin,
                        "Updating PIN policy...",
                        false,
                        move |b, path, pin, _| {
                            b.set_min_pin_rpids(path, pin, &rps)?;
                            Ok(Outcome::Done {
                                message: format!("{} RP ID(s) allowed", rps.len()),
                                reload: Reload::NONE,
                            })
                        },
                    );
                });
                Ok(())
            }),
        )
        .describe(&["These sites will receive the key's minimum PIN length during registration."])
        .submit_label("Apply");
        self.modal = Some(Modal::Form(form));
    }

    pub fn toggle_always_uv(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        let target = !dev.is_always_uv();
        let body = if target {
            vec![
                "Every sign-in will require the PIN (or fingerprint), including".into(),
                "older U2F-style logins that used to need only a touch.".into(),
            ]
        } else {
            vec!["Sites that only ask for user presence will work with a touch again.".into()]
        };
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                if target {
                    "Enable Always-UV?"
                } else {
                    "Disable Always-UV?"
                },
                body,
                Box::new(move |app| {
                    app.require_pin("Authorize the configuration change", move |app, pin| {
                        app.with_pin_job(
                            pin,
                            "Updating configuration...",
                            false,
                            move |b, path, pin, _| {
                                b.toggle_always_uv(path, pin)?;
                                Ok(Outcome::Done {
                                    message: format!(
                                        "Always-UV {}",
                                        if target { "enabled" } else { "disabled" }
                                    ),
                                    reload: Reload::DEVICES,
                                })
                            },
                        );
                    });
                }),
            )
            .yes_label(if target { "Enable" } else { "Disable" }),
        ));
    }

    pub fn force_pin_change(&mut self) {
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Require PIN change?",
                vec!["The key will refuse to work until a new PIN is set.".into()],
                Box::new(|app| {
                    app.require_pin("Authorize the configuration change", |app, pin| {
                        app.with_pin_job(
                            pin,
                            "Updating configuration...",
                            false,
                            |b, path, pin, _| {
                                b.force_pin_change(path, pin)?;
                                Ok(Outcome::Done {
                                    message: "PIN change is now required".into(),
                                    reload: Reload::DEVICES,
                                })
                            },
                        );
                    });
                }),
            )
            .yes_label("Require"),
        ));
    }

    pub fn start_factory_reset(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        let body = vec![
            format!("Key: {} ({})", dev.display_name(), dev.path),
            String::new(),
            "This permanently erases every passkey, fingerprint and the PIN.".into(),
            "Accounts that rely on these passkeys will lose this sign-in method.".into(),
            String::new(),
            "Most keys only accept a reset within a few seconds of being plugged in,".into(),
            "so you will be guided to re-insert the key and then touch it.".into(),
        ];
        let (vid, pid) = (dev.vendor_id, dev.product_id);
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Factory reset",
                body,
                Box::new(move |app| {
                    app.reset = Some(ResetWizard {
                        vendor_id: vid,
                        product_id: pid,
                        stage: ResetStage::Unplug,
                    });
                }),
            )
            .danger(Some("RESET"))
            .yes_label("Continue"),
        ));
    }

    /// Reset immediately without the unplug/replug step.
    pub fn reset_now(&mut self) {
        let Some(path) = self.device_path() else {
            return;
        };
        if let Some(w) = self.reset.as_mut() {
            w.stage = ResetStage::Running;
        }
        self.run(
            "Touch your key to confirm the factory reset",
            true,
            move |b, _| {
                b.factory_reset(&path)?;
                Ok(Outcome::Done {
                    message: "Key reset to factory defaults".into(),
                    reload: Reload::DEVICES,
                })
            },
        );
    }

    pub(super) fn advance_reset(&mut self, list: &[DeviceSummary]) {
        let Some(w) = self.reset.as_ref() else { return };
        let present = list
            .iter()
            .find(|d| d.vendor_id == w.vendor_id && d.product_id == w.product_id)
            .cloned();
        match (w.stage, present) {
            (ResetStage::Unplug, None) => {
                if let Some(w) = self.reset.as_mut() {
                    w.stage = ResetStage::Replug {
                        since: Instant::now(),
                    };
                }
            }
            (ResetStage::Replug { .. }, Some(d)) => {
                if let Some(w) = self.reset.as_mut() {
                    w.stage = ResetStage::Running;
                }
                let path = d.path.clone();
                self.run(
                    "Touch your key now to confirm the factory reset",
                    true,
                    move |b, _| {
                        b.factory_reset(&path)?;
                        Ok(Outcome::Done {
                            message: "Key reset to factory defaults".into(),
                            reload: Reload::DEVICES,
                        })
                    },
                );
            }
            _ => {}
        }
    }

    pub fn cancel_reset(&mut self) {
        if self
            .reset
            .as_ref()
            .is_some_and(|w| w.stage != ResetStage::Running)
        {
            self.reset = None;
            self.notify(Level::Info, "Factory reset cancelled");
            self.scan_devices();
        }
    }

    // Utilities

    pub fn identify(&mut self) {
        let Some(path) = self.device_path() else {
            return;
        };
        self.run("Touch the key to identify it", true, move |b, _| {
            let touched = b.identify(&path, 15_000)?;
            Ok(Outcome::Identified { path, touched })
        });
    }

    pub fn self_test(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        if !dev.is_fido2 {
            self.notify(Level::Error, "Self-test requires a FIDO2 key");
            return;
        }
        let intro = |app: &mut App, pin: Option<Zeroizing<String>>| {
            let Some(path) = app.device_path() else {
                return;
            };
            let pin_meta = pin.clone().map(|p| (path.clone(), p));
            app.run_with_pin(
                "Self-test: touch your key when it blinks",
                true,
                pin_meta,
                move |b, prog| {
                    b.self_test(&path, pin.as_deref().map(|s| s.as_str()), prog)
                        .map(Outcome::SelfTest)
                },
            );
        };
        if dev.has_pin_set() {
            self.require_pin(
                "The self-test signs in once with your PIN",
                move |app, pin| intro(app, Some(pin)),
            );
        } else {
            intro(self, None);
        }
    }

    // Fingerprints

    pub fn load_fingerprints(&mut self, prompt: bool) {
        let Some(dev) = self.device().cloned() else {
            return;
        };
        if !dev.supports_bio() || (!prompt && !self.is_unlocked()) {
            return;
        }
        self.require_pin("Unlock to manage fingerprints", |app, pin| {
            app.with_pin_job(pin, "Reading fingerprints...", false, |b, path, pin, _| {
                let sensor = b.bio_info(path)?;
                let templates = b.bio_list(path, pin)?;
                Ok(Outcome::Fingerprints {
                    path: path.to_string(),
                    sensor,
                    templates,
                })
            });
        });
    }

    pub fn enroll_fingerprint(&mut self) {
        if !self.device().is_some_and(|d| d.supports_bio()) {
            self.notify(Level::Warn, "This key has no fingerprint sensor");
            return;
        }
        let n = self
            .session()
            .and_then(|s| s.bio.as_ref())
            .map_or(0, |b| b.len());
        let form = Form::new(
            "Add fingerprint",
            vec![Field::text("Name", &format!("Finger {}", n + 1))],
            Box::new(|app, f| {
                let name = f[0].value.trim().to_string();
                if name.len() > 15 {
                    return Err("Names are limited to 15 bytes on most keys".into());
                }
                app.require_pin("Authorize fingerprint enrollment", move |app, pin| {
                    app.with_pin_job(
                        pin,
                        "Enrolling fingerprint",
                        true,
                        move |b, path, pin, prog| {
                            let t = b.bio_enroll(path, pin, &name, prog)?;
                            Ok(Outcome::Done {
                                message: format!("Enrolled {}", t.display_name()),
                                reload: Reload::BIO,
                            })
                        },
                    );
                });
                Ok(())
            }),
        )
        .describe(&[
            "You will be asked to touch the sensor several times. Vary your finger position.",
        ])
        .submit_label("Start");
        self.modal = Some(Modal::Form(form));
    }

    fn selected_template(&self) -> Option<BioTemplate> {
        self.session()?
            .bio
            .as_ref()?
            .get(self.bio_list.selected)
            .cloned()
    }

    pub fn rename_fingerprint(&mut self) {
        let Some(t) = self.selected_template() else {
            return;
        };
        let form = Form::new(
            "Rename fingerprint",
            vec![Field::text("Name", t.name.as_deref().unwrap_or(""))],
            Box::new(move |app, f| {
                let name = f[0].value.trim().to_string();
                if name.is_empty() || name.len() > 15 {
                    return Err("Name must be 1–15 bytes".into());
                }
                let id = t.id.clone();
                app.require_pin("Authorize renaming", move |app, pin| {
                    app.with_pin_job(
                        pin,
                        "Renaming fingerprint...",
                        false,
                        move |b, path, pin, _| {
                            b.bio_rename(path, pin, &id, &name)?;
                            Ok(Outcome::Done {
                                message: "Fingerprint renamed".into(),
                                reload: Reload::BIO,
                            })
                        },
                    );
                });
                Ok(())
            }),
        );
        self.modal = Some(Modal::Form(form));
    }

    pub fn delete_fingerprint(&mut self) {
        let Some(t) = self.selected_template() else {
            return;
        };
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Delete fingerprint?",
                vec![format!(
                    "{} will no longer unlock this key.",
                    t.display_name()
                )],
                Box::new(move |app| {
                    let id = t.id.clone();
                    app.require_pin("Authorize deletion", move |app, pin| {
                        app.with_pin_job(
                            pin,
                            "Deleting fingerprint...",
                            false,
                            move |b, path, pin, _| {
                                b.bio_delete(path, pin, &id)?;
                                Ok(Outcome::Done {
                                    message: "Fingerprint deleted".into(),
                                    reload: Reload::BIO,
                                })
                            },
                        );
                    });
                }),
            )
            .danger(None)
            .yes_label("Delete"),
        ));
    }

    // Large blobs

    /// Passkeys that can carry a large blob, in display order.
    pub fn blob_capable(&self) -> Vec<PasskeyCredential> {
        self.credentials()
            .map(|c| {
                c.iter()
                    .filter(|c| c.large_blob_key.is_some())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn blob_for(&self, cred_id: &[u8]) -> Option<&BlobEntry> {
        self.session()?
            .blobs
            .as_ref()?
            .iter()
            .find(|e| e.cred_id == cred_id)
    }

    pub fn load_blobs(&mut self) {
        let Some(dev) = self.device().cloned() else {
            return;
        };
        if !dev.supports_large_blobs() {
            return;
        }
        let Some(path) = self.device_path() else {
            return;
        };
        let keys: Vec<(Vec<u8>, Vec<u8>)> = self
            .blob_capable()
            .into_iter()
            .filter_map(|c| Some((c.cred_id, c.large_blob_key?)))
            .collect();
        self.run("Reading large blobs...", false, move |b, _| {
            let array_size = b.large_blob_array_size(&path)?;
            let mut entries = Vec::new();
            for (cred_id, key) in keys {
                let data = b.large_blob_get(&path, &key)?;
                entries.push(BlobEntry { cred_id, data });
            }
            Ok(Outcome::Blobs {
                path,
                array_size,
                entries,
            })
        });
    }

    fn selected_blob_cred(&mut self) -> Option<PasskeyCredential> {
        let c = self.blob_capable().get(self.blob_list.selected).cloned();
        if c.is_none() {
            self.notify(
                Level::Warn,
                "Select a passkey with a large-blob key (unlock passkeys first)",
            );
        }
        c
    }

    pub fn view_blob(&mut self) {
        let Some(c) = self.selected_blob_cred() else {
            return;
        };
        let Some(data) = self.blob_for(&c.cred_id).and_then(|e| e.data.clone()) else {
            self.notify(Level::Info, "No blob stored for this passkey");
            return;
        };
        let mut lines = vec![format!("{} bytes", data.len()), String::new()];
        if let Ok(text) = std::str::from_utf8(&data) {
            lines.push("UTF-8 text:".into());
            lines.extend(text.lines().map(String::from));
            lines.push(String::new());
        }
        lines.push("Hex dump:".into());
        lines.extend(hexdump(&data));
        self.modal = Some(Modal::Text {
            title: format!("Large blob · {}", c.rp_id),
            lines,
            scroll: 0,
        });
    }

    pub fn edit_blob(&mut self) {
        let Some(c) = self.selected_blob_cred() else {
            return;
        };
        let current = self
            .blob_for(&c.cred_id)
            .and_then(|e| e.data.as_ref())
            .and_then(|d| String::from_utf8(d.clone()).ok())
            .unwrap_or_default();
        let max = self.device().map_or(0, |d| d.max_large_blob);
        let form = Form::new(
            format!("Large blob · {}", c.rp_id),
            vec![
                Field::choice("Source", &["Text", "File"], 0),
                Field::text("Text / file path", &current).hint("text is stored as UTF-8"),
            ],
            Box::new(move |app, f| {
                let data = if f[0].choice == 0 {
                    f[1].value.clone().into_bytes()
                } else {
                    let p = expand_home(f[1].value.trim());
                    std::fs::read(&p).map_err(|e| format!("Cannot read {}: {e}", p))?
                };
                if data.is_empty() {
                    return Err("Nothing to write - use delete to remove a blob".into());
                }
                if max > 0 && data.len() as u64 > max {
                    return Err(format!("Too large: {} bytes (key total is {max})", data.len()));
                }
                let key = c.large_blob_key.clone().unwrap_or_default();
                app.require_pin("Authorize writing the large blob", move |app, pin| {
                    app.with_pin_job(pin, "Writing large blob...", false, move |b, path, pin, _| {
                        b.large_blob_set(path, pin, &key, &data)?;
                        Ok(Outcome::Done { message: format!("Stored {} bytes", data.len()), reload: Reload::BLOBS })
                    });
                });
                Ok(())
            }),
        )
        .describe(&["Large blobs are readable by anyone holding the key - don't store secrets in plain text."])
        .submit_label("Write");
        self.modal = Some(Modal::Form(form));
    }

    pub fn export_blob(&mut self) {
        let Some(c) = self.selected_blob_cred() else {
            return;
        };
        let Some(data) = self.blob_for(&c.cred_id).and_then(|e| e.data.clone()) else {
            self.notify(Level::Info, "No blob stored for this passkey");
            return;
        };
        let default = sys::home().join(format!(
            "largeblob-{}.bin",
            c.rp_id.replace(['/', ':'], "_")
        ));
        let form = Form::new(
            "Save large blob",
            vec![Field::text("File", &default.display().to_string())],
            Box::new(move |app, f| {
                let p = expand_home(f[0].value.trim());
                std::fs::write(&p, &data).map_err(|e| format!("Cannot write {p}: {e}"))?;
                app.notify(Level::Success, format!("Saved {} bytes to {p}", data.len()));
                Ok(())
            }),
        )
        .submit_label("Save");
        self.modal = Some(Modal::Form(form));
    }

    pub fn delete_blob(&mut self) {
        let Some(c) = self.selected_blob_cred() else {
            return;
        };
        if self
            .blob_for(&c.cred_id)
            .and_then(|e| e.data.as_ref())
            .is_none()
        {
            self.notify(Level::Info, "No blob stored for this passkey");
            return;
        }
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Delete large blob?",
                vec![format!(
                    "The data attached to the {} passkey will be erased.",
                    c.rp_id
                )],
                Box::new(move |app| {
                    let key = c.large_blob_key.clone().unwrap_or_default();
                    app.require_pin("Authorize deleting the large blob", move |app, pin| {
                        app.with_pin_job(
                            pin,
                            "Deleting large blob...",
                            false,
                            move |b, path, pin, _| {
                                b.large_blob_delete(path, pin, &key)?;
                                Ok(Outcome::Done {
                                    message: "Large blob deleted".into(),
                                    reload: Reload::BLOBS,
                                })
                            },
                        );
                    });
                }),
            )
            .danger(None)
            .yes_label("Delete"),
        ));
    }

    // SSH

    pub fn ssh_generate(&mut self) {
        let Some(dev) = self.need_device() else {
            return;
        };
        if sys::which("ssh-keygen").is_none() {
            self.notify(
                Level::Error,
                "ssh-keygen not found - install OpenSSH (see install.sh)",
            );
            return;
        }
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        let host = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        let path = dev.path.clone();
        let has_pin = dev.has_pin_set();
        let form = Form::new(
            "Generate SSH key",
            vec![
                Field::choice("Type", &["ed25519-sk", "ecdsa-sk"], 0),
                Field::toggle("Store on key (resident)", true)
                    .hint("lets you recover it with ssh-keygen -K"),
                Field::toggle("Require PIN (verify-required)", has_pin),
                Field::text("Application", "ssh:").hint("must start with ssh:"),
                Field::text("Comment", &format!("{user}@{host} fido2")),
                Field::text("Output file", "~/.ssh/id_ed25519_sk"),
            ],
            Box::new(move |app, f| {
                let ktype = f[0].choice_label().to_string();
                let app_id = f[3].value.trim().to_string();
                if !app_id.starts_with("ssh:") {
                    return Err("Application must start with \"ssh:\"".into());
                }
                let mut out = f[5].value.trim().to_string();
                if ktype == "ecdsa-sk" && out == "~/.ssh/id_ed25519_sk" {
                    out = "~/.ssh/id_ecdsa_sk".into();
                }
                let out = expand_home(&out);
                if std::path::Path::new(&out).exists() {
                    return Err(format!("{out} already exists - choose another file"));
                }
                let mut args: Vec<String> =
                    vec!["-t".into(), ktype, "-O".into(), format!("device={path}")];
                if f[1].checked {
                    args.extend(["-O".into(), "resident".into()]);
                }
                if f[2].checked {
                    args.extend(["-O".into(), "verify-required".into()]);
                }
                if app_id != "ssh:" {
                    args.extend(["-O".into(), format!("application={app_id}")]);
                }
                args.extend(["-C".into(), f[4].value.trim().to_string(), "-f".into(), out]);
                let _ = std::fs::create_dir_all(sys::home().join(".ssh"));
                let cmd = ExternalCommand {
                    title: "Generate SSH key - follow the prompts, touch the key when it blinks"
                        .into(),
                    program: "ssh-keygen".into(),
                    args,
                    cwd: Some(sys::home().join(".ssh")),
                };
                app.external = Some((cmd, Reload::CREDS));
                Ok(())
            }),
        )
        .describe(&["Runs ssh-keygen in the terminal; you'll be asked for the PIN and a touch."])
        .submit_label("Generate");
        self.modal = Some(Modal::Form(form));
    }

    pub fn ssh_download(&mut self) {
        if sys::which("ssh-keygen").is_none() {
            self.notify(Level::Error, "ssh-keygen not found - install OpenSSH");
            return;
        }
        let dir = sys::home().join(".ssh");
        let _ = std::fs::create_dir_all(&dir);
        let mut cmd = ExternalCommand::new(
            "Download resident SSH keys into ~/.ssh (enter the PIN when asked)",
            "ssh-keygen",
            &["-K"],
        );
        cmd.cwd = Some(dir);
        self.external = Some((cmd, Reload::NONE));
    }

    pub fn ssh_show_pubkey(&mut self) {
        let Some(k) = self.ssh_keys.get(self.ssh_list.selected).cloned() else {
            return;
        };
        let text = std::fs::read_to_string(&k.path).unwrap_or_default();
        self.modal = Some(Modal::Text {
            title: k.path.display().to_string(),
            lines: vec![
                "Add this line to ~/.ssh/authorized_keys on the server:".into(),
                String::new(),
                text.trim().to_string(),
                String::new(),
                format!(
                    "Copy it with: ssh-copy-id -i {} user@host",
                    k.path.display()
                ),
            ],
            scroll: 0,
        });
    }

    // LUKS

    pub fn load_luks(&mut self) {
        self.run_background(|_, _| Ok(Outcome::Luks(sys::scan_luks())));
    }

    pub fn selected_luks(&self) -> Option<LuksDevice> {
        self.luks
            .as_ref()?
            .devices
            .get(self.disk_list.selected)
            .cloned()
    }

    fn privileged(
        &self,
        dev: &LuksDevice,
        title: &str,
        program: &str,
        args: &[&str],
    ) -> ExternalCommand {
        if dev.is_practice {
            ExternalCommand::new(title, program, args)
        } else {
            ExternalCommand::root(title, program, args)
        }
    }

    pub fn sudo_auth(&mut self) {
        if sys::is_root() {
            self.load_luks();
            return;
        }
        self.external = Some((
            ExternalCommand::new(
                "Authenticate with sudo to read LUKS headers",
                "sudo",
                &["-v"],
            ),
            Reload::LUKS,
        ));
    }

    pub fn luks_enroll(&mut self) {
        let Some(disk) = self.selected_luks() else {
            return;
        };
        if let Err(e) = disk.can_safely_enroll() {
            self.notify(Level::Error, e);
            return;
        }
        let Some(key) = self.need_device() else {
            return;
        };
        let form = Form::new(
            format!("Enroll {} → {}", key.display_name(), disk.path),
            vec![
                Field::toggle("Require PIN at unlock", key.has_pin_set()),
                Field::toggle("Require touch at unlock", true),
                Field::toggle("Require built-in UV (fingerprint)", false),
                Field::toggle("Back up LUKS header first", !disk.is_practice),
            ],
            Box::new(move |app, f| {
                let yn = |b: bool| if b { "yes" } else { "no" };
                if f[0].checked && !key.has_pin_set() {
                    return Err("The key has no PIN - set one first or disable \"Require PIN\"".into());
                }
                if f[2].checked && !key.has_fingerprints() && key.option("uv") != Some(true) {
                    return Err("This key has no built-in user verification".into());
                }
                let sudo = if disk.is_practice || sys::is_root() { "" } else { "sudo " };
                let mut script = String::from("set -e\n");
                if f[3].checked {
                    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
                    let backup = sys::home().join(format!("luks-header-{}-{stamp}.img", disk.uuid));
                    let b = shell_quote(&backup.display().to_string());
                    script.push_str(&format!(
                        "echo 'Backing up LUKS header to {}'\n{sudo}cryptsetup luksHeaderBackup {} --header-backup-file {b}\n",
                        backup.display(),
                        shell_quote(&disk.path)
                    ));
                    if !sudo.is_empty() {
                        script.push_str(&format!("sudo chown \"$(id -u):$(id -g)\" {b}\n"));
                    }
                }
                script.push_str(&format!(
                    "{sudo}systemd-cryptenroll --fido2-device={} --fido2-with-client-pin={} --fido2-with-user-presence={} --fido2-with-user-verification={} {}\n",
                    shell_quote(&key.path),
                    yn(f[0].checked),
                    yn(f[1].checked),
                    yn(f[2].checked),
                    shell_quote(&disk.path)
                ));
                let title = "Enroll FIDO2 key: enter an existing passphrase, then the key PIN, then touch the key";
                app.external = Some((ExternalCommand::shell(title, &script), Reload::LUKS));
                Ok(())
            }),
        )
        .describe(&[
            "Adds a new key slot unlocked by this security key. Existing passphrases",
            "are kept, so you can always fall back to your recovery passphrase.",
        ])
        .submit_label("Enroll");
        self.modal = Some(Modal::Form(form));
    }

    pub fn luks_wipe_fido2(&mut self) {
        let Some(disk) = self.selected_luks() else {
            return;
        };
        if !disk.has_fido2_token() {
            self.notify(Level::Info, "No FIDO2 token is enrolled on this volume");
            return;
        }
        if disk.passphrase_slots().is_empty() {
            self.notify(
                Level::Error,
                "Refusing: no passphrase slot would remain (you would be locked out)",
            );
            return;
        }
        let n = disk.fido2_tokens().len();
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Remove FIDO2 unlock?",
                vec![
                    format!("Removes {n} FIDO2 key slot(s) from {}.", disk.path),
                    format!(
                        "Passphrase slot(s) {:?} stay untouched.",
                        disk.passphrase_slots()
                    ),
                ],
                Box::new(move |app| {
                    let cmd = app.privileged(
                        &disk,
                        "Remove FIDO2 key slots",
                        "systemd-cryptenroll",
                        &["--wipe-slot=fido2", &disk.path],
                    );
                    app.external = Some((cmd, Reload::LUKS));
                }),
            )
            .danger(None)
            .yes_label("Remove"),
        ));
    }

    pub fn luks_backup_header(&mut self) {
        let Some(disk) = self.selected_luks() else {
            return;
        };
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let backup = sys::home().join(format!(
            "luks-header-{}-{stamp}.img",
            if disk.uuid.is_empty() {
                "practice"
            } else {
                &disk.uuid
            }
        ));
        let b = shell_quote(&backup.display().to_string());
        let sudo = if disk.is_practice || sys::is_root() {
            ""
        } else {
            "sudo "
        };
        let mut script = format!(
            "set -e\n{sudo}cryptsetup luksHeaderBackup {} --header-backup-file {b}\n",
            shell_quote(&disk.path)
        );
        if !sudo.is_empty() {
            script.push_str(&format!("sudo chown \"$(id -u):$(id -g)\" {b}\n"));
        }
        script.push_str(&format!(
            "echo 'Header saved to {}. Keep it somewhere safe and offline.'\n",
            backup.display()
        ));
        self.external = Some((
            ExternalCommand::shell("Back up LUKS header", &script),
            Reload::NONE,
        ));
    }

    pub fn luks_test_unlock(&mut self, with_key: bool) {
        let Some(disk) = self.selected_luks() else {
            return;
        };
        if with_key && !disk.has_fido2_token() {
            self.notify(
                Level::Warn,
                "No FIDO2 token on this volume - enroll one first (e)",
            );
            return;
        }
        let args: Vec<&str> = if with_key {
            vec![
                "open",
                "--test-passphrase",
                "--token-only",
                "--token-type",
                "systemd-fido2",
                "-v",
                &disk.path,
            ]
        } else {
            vec!["open", "--test-passphrase", "-v", &disk.path]
        };
        let title = if with_key {
            "Test unlocking with the security key (PIN + touch); nothing is mounted"
        } else {
            "Test a passphrase; nothing is mounted"
        };
        let cmd = self.privileged(&disk, title, "cryptsetup", &args);
        self.external = Some((cmd, Reload::NONE));
    }

    pub fn luks_crypttab_help(&mut self) {
        let Some(disk) = self.selected_luks() else {
            return;
        };
        let mut lines = Vec::new();
        if disk.is_practice {
            lines.push("The practice volume is not used at boot - nothing to configure.".into());
        } else {
            match &disk.crypttab {
                Some(e) if e.has_fido2_device() => {
                    lines.push(format!(
                        "✓ /etc/crypttab entry '{}' already has fido2-device=auto.",
                        e.name
                    ));
                }
                Some(e) => {
                    lines.push(format!(
                        "Add fido2-device=auto to the options of entry '{}':",
                        e.name
                    ));
                    let mut opts = e.options.clone();
                    opts.retain(|o| o != "none" && !o.is_empty());
                    opts.push("fido2-device=auto".into());
                    lines.push(String::new());
                    lines.push(format!(
                        "  {} {} {} {}",
                        e.name,
                        e.source,
                        e.key_file,
                        opts.join(",")
                    ));
                }
                None => {
                    lines.push("No /etc/crypttab entry found. A typical line would be:".into());
                    lines.push(String::new());
                    lines.push(format!(
                        "  luks-{0} UUID={0} none fido2-device=auto",
                        disk.uuid
                    ));
                }
            }
            lines.push(String::new());
            lines.push("Then rebuild the initramfs so it can talk to the key at boot:".into());
            lines.push(match self.luks.as_ref().and_then(|l| l.initramfs_fido2) {
                Some(false) => {
                    "  ✗ dracut fido2 module not found - install it (e.g. dracut + libfido2)".into()
                }
                _ => {
                    "  sudo dracut -f        (Fedora/RHEL)   |   sudo mkinitcpio -P  (Arch)".into()
                }
            });
            lines.push(String::new());
            lines.push("Keep your recovery passphrase: it still works if the key is lost.".into());
        }
        self.modal = Some(Modal::Text {
            title: format!("Boot unlock · {}", disk.path),
            lines,
            scroll: 0,
        });
    }

    pub fn practice_create(&mut self) {
        let img = sys::practice_image();
        if img.exists() {
            self.notify(Level::Info, "Practice volume already exists");
            return;
        }
        let dir = shell_quote(&sys::data_dir().display().to_string());
        let i = shell_quote(&img.display().to_string());
        let script = format!(
            "set -e\nmkdir -p {dir}\ntruncate -s 32M {i}\n\
             echo 'Choose a passphrase for the practice volume (it is only a test file).'\n\
             cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --verify-passphrase {i} || {{ rm -f {i}; exit 1; }}\n\
             echo 'Created {}'\n",
            img.display()
        );
        self.external = Some((
            ExternalCommand::shell(
                "Create a practice LUKS2 volume (a 32 MB file - safe to experiment)",
                &script,
            ),
            Reload::LUKS,
        ));
    }

    pub fn practice_delete(&mut self) {
        let Some(disk) = self.selected_luks().filter(|d| d.is_practice) else {
            self.notify(Level::Warn, "Select the practice volume to delete it");
            return;
        };
        self.modal = Some(Modal::Confirm(
            Confirm::new(
                "Delete practice volume?",
                vec![format!("Deletes {}", disk.path)],
                Box::new(move |app| match std::fs::remove_file(&disk.path) {
                    Ok(()) => {
                        app.notify(Level::Success, "Practice volume deleted");
                        app.load_luks();
                    }
                    Err(e) => app.notify(Level::Error, format!("Delete failed: {e}")),
                }),
            )
            .yes_label("Delete"),
        ));
    }

    // Audit

    pub fn export_audit(&mut self, json: bool) {
        let Some(report) = self.audit() else {
            self.notify(Level::Warn, "No key connected");
            return;
        };
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let ext = if json { "json" } else { "csv" };
        let path = sys::home().join(format!("fido2-audit-{stamp}.{ext}"));
        let body = if json {
            report.to_json().unwrap_or_default()
        } else {
            report.to_csv()
        };
        match std::fs::write(&path, body) {
            Ok(()) => self.notify(Level::Success, format!("Audit saved to {}", path.display())),
            Err(e) => self.notify(Level::Error, format!("Export failed: {e}")),
        }
    }

    pub fn goto(&mut self, page: Page) {
        self.page = page;
        self.on_page_enter();
    }

    /// Lazy-load data the first time a page is shown.
    pub fn on_page_enter(&mut self) {
        match self.page {
            Page::Passkeys | Page::LargeBlobs | Page::Ssh => {
                let have = self.credentials().is_some();
                if !have && self.is_unlocked() {
                    self.load_credentials(false);
                }
                if self.page == Page::LargeBlobs
                    && have
                    && self.session().is_some_and(|s| s.blobs.is_none())
                {
                    self.load_blobs();
                }
                if self.page == Page::Ssh {
                    self.ssh_keys = sys::ssh_sk_keys();
                }
            }
            Page::Fingerprints => {
                if self.session().is_none_or(|s| s.bio.is_none()) {
                    self.load_fingerprints(false);
                }
            }
            Page::Disk | Page::Audit if self.luks.is_none() => {
                self.load_luks();
            }
            _ => {}
        }
    }
}

pub fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        sys::home().join(rest).display().to_string()
    } else {
        p.to_string()
    }
}

fn wrap_hex(h: &str, width: usize) -> Vec<String> {
    if h.is_empty() {
        return vec!["  (empty)".into()];
    }
    h.as_bytes()
        .chunks(width)
        .map(|c| format!("  {}", String::from_utf8_lossy(c)))
        .collect()
}

pub fn hexdump(data: &[u8]) -> Vec<String> {
    data.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:06x}  {:<47}  {}", i * 16, hex.join(" "), ascii)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_validation() {
        assert!(validate_new_pin("123", "123", 4).is_err());
        assert!(validate_new_pin("1234", "1235", 4).is_err());
        assert!(validate_new_pin("1234", "1234", 4).is_ok());
        assert!(validate_new_pin(&"x".repeat(64), &"x".repeat(64), 4).is_err());
        // length counts characters, not bytes
        assert!(validate_new_pin("ñññ", "ñññ", 4).is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/dev/sda2"), "/dev/sda2");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn hexdump_format() {
        let d = hexdump(b"hello");
        assert_eq!(d[0], format!("000000  {:<47}  hello", "68 65 6c 6c 6f"));
    }
}
