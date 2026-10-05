//! End-to-end app flows against an in-memory authenticator: key presses in,
//! device calls and rendered screens out.

use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tokio::sync::mpsc::UnboundedReceiver;

use fido2_tui::app::jobs::WorkerMsg;
use fido2_tui::app::modal::Modal;
use fido2_tui::app::{App, Page, ResetStage};
use fido2_tui::fido::{FidoBackend, FidoError, FidoResult, Progress, SelfTestReport, ffi};
use fido2_tui::model::*;

const PIN: &str = "482915";

#[derive(Default)]
struct State {
    present: bool,
    pin: Option<String>,
    retries: u32,
    creds: Vec<PasskeyCredential>,
    blobs: Vec<(Vec<u8>, Vec<u8>)>,
    resets: u32,
    calls: Vec<String>,
}

struct Fake(Mutex<State>);

impl Fake {
    fn new() -> Arc<Self> {
        let cred = |rp: &str, user: &str, id: u8, blob: bool| PasskeyCredential {
            rp_id: rp.into(),
            rp_name: None,
            user_id: vec![id],
            user_name: user.into(),
            user_display_name: user.to_uppercase(),
            cred_id: vec![id, id],
            algorithm: "ES256".into(),
            cred_protect: 2,
            large_blob_key: blob.then(|| vec![id; 32]),
        };
        Arc::new(Self(Mutex::new(State {
            present: true,
            pin: Some(PIN.into()),
            retries: 8,
            creds: vec![
                cred("github.com", "octocat", 1, true),
                cred("google.com", "alice", 2, false),
            ],
            ..Default::default()
        })))
    }

    fn s(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    fn check_pin(&self, pin: &str) -> FidoResult<()> {
        let mut s = self.s();
        s.calls.push("pin".into());
        match &s.pin {
            None => Err(FidoError::new(ffi::FIDO_ERR_PIN_NOT_SET, "no pin")),
            Some(p) if p == pin => {
                s.retries = 8;
                Ok(())
            }
            Some(_) => {
                s.retries -= 1;
                Err(FidoError::new(ffi::FIDO_ERR_PIN_INVALID, "Incorrect PIN"))
            }
        }
    }

    fn summary() -> DeviceSummary {
        DeviceSummary {
            path: "/dev/hidraw9".into(),
            vendor_id: 0x2e8a,
            product_id: 0x10fe,
            manufacturer: "Pol Henarejos".into(),
            product: "Pico Key".into(),
        }
    }
}

impl FidoBackend for Fake {
    fn enumerate(&self) -> FidoResult<Vec<DeviceSummary>> {
        Ok(if self.s().present {
            vec![Self::summary()]
        } else {
            vec![]
        })
    }
    fn device_info(&self, s: &DeviceSummary) -> FidoResult<FidoDevice> {
        let st = self.s();
        Ok(FidoDevice {
            path: s.path.clone(),
            vendor_id: s.vendor_id,
            product_id: s.product_id,
            product: s.product.clone(),
            manufacturer: s.manufacturer.clone(),
            is_fido2: true,
            versions: vec!["FIDO_2_0".into(), "FIDO_2_1".into()],
            extensions: vec!["credProtect".into(), "hmac-secret".into()],
            options: vec![
                ("rk".into(), true),
                ("clientPin".into(), st.pin.is_some()),
                ("credMgmt".into(), true),
                ("authnrCfg".into(), true),
                ("largeBlobs".into(), true),
                ("setMinPINLength".into(), true),
                ("alwaysUv".into(), false),
            ],
            algorithms: vec!["ES256".into()],
            aaguid_name: Some("Pico Key (Pico-FIDO)".into()),
            min_pin_len: Some(4),
            max_large_blob: 2048,
            max_rpids_min_pin: 8,
            pin_retries: Some(st.retries),
            ..Default::default()
        })
    }
    fn identify(&self, _: &str, _: u32) -> FidoResult<bool> {
        Ok(true)
    }
    fn self_test(
        &self,
        _: &str,
        _: Option<&str>,
        p: &dyn Fn(Progress),
    ) -> FidoResult<SelfTestReport> {
        p(Progress::TouchNeeded);
        Ok(SelfTestReport {
            algorithm: "ES256".into(),
            attestation_format: "packed".into(),
            attestation_verified: true,
            assertion_verified: true,
            user_verified: true,
        })
    }
    fn set_pin(&self, _: &str, new: &str) -> FidoResult<()> {
        self.s().pin = Some(new.into());
        Ok(())
    }
    fn change_pin(&self, _: &str, old: &str, new: &str) -> FidoResult<()> {
        self.check_pin(old)?;
        self.s().pin = Some(new.into());
        Ok(())
    }
    fn verify_pin(&self, _: &str, pin: &str) -> FidoResult<()> {
        self.check_pin(pin)
    }
    fn factory_reset(&self, _: &str) -> FidoResult<()> {
        let mut s = self.s();
        s.resets += 1;
        s.pin = None;
        s.creds.clear();
        Ok(())
    }
    fn toggle_always_uv(&self, _: &str, pin: &str) -> FidoResult<()> {
        self.check_pin(pin)
    }
    fn set_min_pin_length(&self, _: &str, pin: &str, _: usize) -> FidoResult<()> {
        self.check_pin(pin)
    }
    fn set_min_pin_rpids(&self, _: &str, pin: &str, _: &[String]) -> FidoResult<()> {
        self.check_pin(pin)
    }
    fn force_pin_change(&self, _: &str, pin: &str) -> FidoResult<()> {
        self.check_pin(pin)
    }
    fn storage_stats(&self, _: &str, pin: &str) -> FidoResult<StorageStats> {
        self.check_pin(pin)?;
        let n = self.s().creds.len() as u64;
        Ok(StorageStats {
            existing: n,
            remaining: 25 - n,
        })
    }
    fn list_credentials(&self, _: &str, pin: &str) -> FidoResult<Vec<PasskeyCredential>> {
        self.check_pin(pin)?;
        Ok(self.s().creds.clone())
    }
    fn delete_credential(&self, _: &str, pin: &str, id: &[u8]) -> FidoResult<()> {
        self.check_pin(pin)?;
        self.s().creds.retain(|c| c.cred_id != id);
        Ok(())
    }
    fn update_user(
        &self,
        _: &str,
        pin: &str,
        cred: &PasskeyCredential,
        name: &str,
        display: &str,
    ) -> FidoResult<()> {
        self.check_pin(pin)?;
        let mut s = self.s();
        let c = s
            .creds
            .iter_mut()
            .find(|c| c.cred_id == cred.cred_id)
            .unwrap();
        c.user_name = name.into();
        c.user_display_name = display.into();
        Ok(())
    }
    fn bio_info(&self, _: &str) -> FidoResult<BioSensorInfo> {
        Err(FidoError::new(ffi::FIDO_ERR_INVALID_COMMAND, "unsupported"))
    }
    fn bio_list(&self, _: &str, _: &str) -> FidoResult<Vec<BioTemplate>> {
        Ok(vec![])
    }
    fn bio_enroll(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &dyn Fn(Progress),
    ) -> FidoResult<BioTemplate> {
        unreachable!()
    }
    fn bio_rename(&self, _: &str, _: &str, _: &[u8], _: &str) -> FidoResult<()> {
        Ok(())
    }
    fn bio_delete(&self, _: &str, _: &str, _: &[u8]) -> FidoResult<()> {
        Ok(())
    }
    fn large_blob_array_size(&self, _: &str) -> FidoResult<usize> {
        Ok(1 + self
            .s()
            .blobs
            .iter()
            .map(|(_, d)| d.len() + 30)
            .sum::<usize>())
    }
    fn large_blob_get(&self, _: &str, key: &[u8]) -> FidoResult<Option<Vec<u8>>> {
        Ok(self
            .s()
            .blobs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, d)| d.clone()))
    }
    fn large_blob_set(&self, _: &str, pin: &str, key: &[u8], data: &[u8]) -> FidoResult<()> {
        self.check_pin(pin)?;
        let mut s = self.s();
        s.blobs.retain(|(k, _)| k != key);
        s.blobs.push((key.to_vec(), data.to_vec()));
        Ok(())
    }
    fn large_blob_delete(&self, _: &str, pin: &str, key: &[u8]) -> FidoResult<()> {
        self.check_pin(pin)?;
        self.s().blobs.retain(|(k, _)| k != key);
        Ok(())
    }
}

struct Harness {
    app: App,
    rx: UnboundedReceiver<WorkerMsg>,
    fake: Arc<Fake>,
}

impl Harness {
    fn new() -> Self {
        let fake = Fake::new();
        let (mut app, rx) = App::new(fake.clone());
        app.jobs.inline = true;
        let mut h = Self { app, rx, fake };
        h.app.start();
        h.pump();
        h
    }

    /// Deliver all pending worker messages (jobs run inline, so they're queued).
    fn pump(&mut self) {
        for _ in 0..10 {
            let mut any = false;
            while let Ok(msg) = self.rx.try_recv() {
                self.app.handle_worker(msg);
                any = true;
            }
            if !any {
                break;
            }
        }
    }

    fn key(&mut self, code: KeyCode) {
        self.app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        self.pump();
    }

    fn ch(&mut self, c: char) {
        self.key(KeyCode::Char(c));
    }

    fn typ(&mut self, s: &str) {
        for c in s.chars() {
            self.app
                .handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        self.pump();
    }

    fn unlock(&mut self, pin: &str) {
        self.app.goto(Page::Passkeys);
        self.ch('u');
        assert!(
            matches!(self.app.modal, Some(Modal::Pin(_))),
            "PIN prompt expected"
        );
        self.typ(pin);
        self.key(KeyCode::Enter);
    }

    fn screen(&self, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| fido2_tui::ui::render(&self.app, f)).unwrap();
        let buf = term.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[test]
fn detects_device_on_start() {
    let h = Harness::new();
    assert_eq!(h.app.devices.len(), 1);
    assert_eq!(
        h.app.device().unwrap().display_name(),
        "Pico Key (Pico-FIDO)"
    );
    assert!(h.screen(120, 36).contains("Pico Key (Pico-FIDO)"));
}

#[test]
fn unlock_lists_passkeys_and_caches_pin() {
    let mut h = Harness::new();
    h.unlock(PIN);
    assert!(h.app.is_unlocked());
    assert_eq!(h.app.credentials().unwrap().len(), 2);
    let screen = h.screen(120, 36);
    assert!(
        screen.contains("github.com") && screen.contains("octocat"),
        "{screen}"
    );
    // Cached PIN: no second prompt for the next operation.
    h.ch('d');
    h.ch('y');
    assert!(h.app.modal.is_none());
    assert_eq!(h.fake.s().creds.len(), 1);
}

#[test]
fn wrong_pin_is_not_cached_and_reports_retries() {
    let mut h = Harness::new();
    h.unlock("000000");
    assert!(!h.app.is_unlocked());
    assert!(h.app.credentials().is_none());
    assert_eq!(h.fake.s().retries, 7);
    assert_eq!(
        h.app.device().unwrap().pin_retries,
        Some(7),
        "retry counter refreshed"
    );
    assert!(
        h.app
            .toast
            .as_ref()
            .unwrap()
            .message
            .contains("Incorrect PIN")
    );
}

#[test]
fn search_filters_and_edit_updates_user() {
    let mut h = Harness::new();
    h.unlock(PIN);
    h.ch('/');
    h.typ("goo");
    h.key(KeyCode::Enter);
    assert_eq!(h.app.filtered_credentials().len(), 1);
    h.ch('e');
    let Some(Modal::Form(_)) = &h.app.modal else {
        panic!("edit form expected")
    };
    h.key(KeyCode::Tab);
    h.app
        .handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    h.typ("Alice A.");
    h.key(KeyCode::Enter);
    assert_eq!(
        h.fake
            .s()
            .creds
            .iter()
            .find(|c| c.rp_id == "google.com")
            .unwrap()
            .user_display_name,
        "Alice A."
    );
}

#[test]
fn set_pin_form_validates_before_calling_device() {
    let mut h = Harness::new();
    h.fake.s().pin = None;
    h.app.scan_devices();
    h.pump();
    h.ch('p');
    h.typ("12");
    h.key(KeyCode::Tab);
    h.typ("12");
    h.key(KeyCode::Enter);
    let Some(Modal::Form(f)) = &h.app.modal else {
        panic!("form should stay open")
    };
    assert!(f.error.as_deref().unwrap().contains("at least 4"));
    assert!(h.fake.s().pin.is_none());
    h.key(KeyCode::BackTab);
    h.typ("34");
    h.key(KeyCode::Tab);
    h.typ("34");
    h.key(KeyCode::Enter);
    assert_eq!(h.fake.s().pin.as_deref(), Some("1234"));
    assert!(h.app.is_unlocked(), "new PIN cached for the session");
}

#[test]
fn unplug_forgets_pin_and_data() {
    let mut h = Harness::new();
    h.unlock(PIN);
    assert!(h.app.is_unlocked());
    h.fake.s().present = false;
    h.app.scan_devices();
    h.pump();
    assert!(h.app.devices.is_empty());
    assert!(
        h.app.sessions.is_empty(),
        "PIN must be dropped when the key is removed"
    );
    assert!(h.screen(100, 30).contains("No security key connected"));
    h.fake.s().present = true;
    h.app.scan_devices();
    h.pump();
    assert!(!h.app.is_unlocked());
}

#[test]
fn factory_reset_requires_typed_confirmation_and_replug() {
    let mut h = Harness::new();
    h.app.goto(Page::Security);
    h.ch('R');
    h.key(KeyCode::Enter); // nothing typed yet: must not proceed
    assert!(h.app.reset.is_none());
    h.typ("RESET");
    h.key(KeyCode::Enter);
    assert_eq!(h.app.reset.as_ref().unwrap().stage, ResetStage::Unplug);

    // Unplug → replug drives the wizard; the reset runs only after re-insertion.
    h.fake.s().present = false;
    h.app
        .run_background(|b, _| b.enumerate().map(fido2_tui::app::jobs::Outcome::Summaries));
    h.pump();
    assert!(matches!(
        h.app.reset.as_ref().unwrap().stage,
        ResetStage::Replug { .. }
    ));
    assert_eq!(h.fake.s().resets, 0);
    h.fake.s().present = true;
    h.app
        .run_background(|b, _| b.enumerate().map(fido2_tui::app::jobs::Outcome::Summaries));
    h.pump();
    assert_eq!(h.fake.s().resets, 1);
    assert!(
        h.app.reset.is_none(),
        "wizard closes after the reset finished"
    );
}

#[test]
fn reset_can_be_cancelled() {
    let mut h = Harness::new();
    h.app.goto(Page::Security);
    h.ch('R');
    h.typ("RESET");
    h.key(KeyCode::Enter);
    h.key(KeyCode::Esc);
    assert!(h.app.reset.is_none());
    assert_eq!(h.fake.s().resets, 0);
}

#[test]
fn large_blob_write_read_delete() {
    let mut h = Harness::new();
    h.unlock(PIN);
    h.app.goto(Page::LargeBlobs);
    h.pump();
    assert_eq!(h.app.blob_capable().len(), 1);
    h.ch('e');
    h.key(KeyCode::Tab);
    h.typ("hello");
    h.key(KeyCode::Enter);
    let key = vec![1u8; 32];
    assert_eq!(h.fake.s().blobs, vec![(key.clone(), b"hello".to_vec())]);
    assert_eq!(
        h.app.blob_for(&[1, 1]).unwrap().data.as_deref(),
        Some(&b"hello"[..])
    );
    h.ch('d');
    h.ch('y');
    assert!(h.fake.s().blobs.is_empty());
}

#[test]
fn self_test_shows_result() {
    let mut h = Harness::new();
    h.unlock(PIN);
    h.app.goto(Page::Overview);
    h.ch('t');
    let Some(Modal::Message { title, .. }) = &h.app.modal else {
        panic!("result dialog expected")
    };
    assert_eq!(title, "Self-test passed");
}

#[test]
fn paste_goes_into_pin_prompt() {
    let mut h = Harness::new();
    h.app.goto(Page::Passkeys);
    h.ch('u');
    h.app.handle_paste("482915\n");
    h.key(KeyCode::Enter);
    assert!(h.app.is_unlocked());
}

#[test]
fn every_page_renders_at_common_sizes() {
    let mut h = Harness::new();
    for unlocked in [false, true] {
        if unlocked {
            h.unlock(PIN);
        }
        for page in Page::ALL {
            h.app.goto(page);
            h.pump();
            for (w, ht) in [(80, 24), (120, 36), (200, 60), (40, 12)] {
                let s = h.screen(w, ht);
                assert!(s.contains("fido2-tui"), "{page:?} at {w}x{ht}");
            }
        }
    }
    // Modals render too.
    h.ch('?');
    assert!(h.screen(100, 40).contains("Keyboard shortcuts"));
}

#[test]
fn no_device_screen_and_themes() {
    let mut h = Harness::new();
    h.fake.s().present = false;
    h.app.scan_devices();
    h.pump();
    for _ in 0..4 {
        h.ch('T');
        let s = h.screen(100, 30);
        assert!(s.contains("No security key connected"));
    }
}
