//! Application state and event handling (UI-independent, unit-testable).

pub mod actions;
pub mod jobs;
pub mod keys;
pub mod modal;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::UnboundedReceiver;
use zeroize::Zeroizing;

use crate::fido::{FidoBackend, FidoError, FidoResult, Progress, SelfTestReport};
use crate::model::*;
use crate::sys::{self, ExternalCommand, InaccessibleKey, LuksScan, SshKeyFile};
use crate::ui::theme::Theme;
use jobs::{BlobEntry, Jobs, Outcome, Reload, WorkerMsg};
use modal::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Passkeys,
    Security,
    Fingerprints,
    LargeBlobs,
    Ssh,
    Disk,
    Audit,
    Info,
}

impl Page {
    pub const ALL: [Page; 9] = [
        Page::Overview,
        Page::Passkeys,
        Page::Security,
        Page::Fingerprints,
        Page::LargeBlobs,
        Page::Ssh,
        Page::Disk,
        Page::Audit,
        Page::Info,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "Overview",
            Page::Passkeys => "Passkeys",
            Page::Security => "PIN & Security",
            Page::Fingerprints => "Fingerprints",
            Page::LargeBlobs => "Large Blobs",
            Page::Ssh => "SSH Keys",
            Page::Disk => "Disk Unlock",
            Page::Audit => "Security Audit",
            Page::Info => "Device Info",
        }
    }

    pub fn index(self) -> usize {
        Page::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// Per-device state that lives only while the key is plugged in.
#[derive(Default)]
pub struct DeviceSession {
    pub pin: Option<Zeroizing<String>>,
    pub creds: Option<Vec<PasskeyCredential>>,
    pub stats: Option<StorageStats>,
    pub bio_sensor: Option<BioSensorInfo>,
    pub bio: Option<Vec<BioTemplate>>,
    pub blob_array_size: Option<usize>,
    pub blobs: Option<Vec<BlobEntry>>,
    pub self_test: Option<SelfTestReport>,
}

pub struct Busy {
    pub id: u64,
    pub title: String,
    pub detail: String,
    pub touch: bool,
    pub bio_remaining: Option<u8>,
    pub bio_total: Option<u8>,
    pub started: Instant,
}

pub struct Toast {
    pub message: String,
    pub level: Level,
    pub at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetStage {
    Unplug,
    Replug { since: Instant },
    Running,
}

pub struct ResetWizard {
    pub vendor_id: u16,
    pub product_id: u16,
    pub stage: ResetStage,
}

#[derive(Default)]
pub struct ListState {
    pub selected: usize,
    pub scroll: u16,
}

impl ListState {
    pub fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn down(&mut self, len: usize) {
        if self.selected + 1 < len {
            self.selected += 1;
        }
    }

    pub fn clamp(&mut self, len: usize) {
        if self.selected >= len {
            self.selected = len.saturating_sub(1);
        }
    }
}

/// Context for each in-flight job.
struct JobMeta {
    foreground: bool,
    /// (device path, PIN) used by this job - cached on success, dropped if wrong.
    pin: Option<(String, Zeroizing<String>)>,
}

pub struct App {
    pub jobs: Jobs,
    pub theme: Theme,
    pub page: Page,
    pub devices: Vec<FidoDevice>,
    pub enum_errors: Vec<String>,
    pub inaccessible: Vec<InaccessibleKey>,
    pub selected_device: usize,
    pub sessions: HashMap<String, DeviceSession>,
    pub scanned_once: bool,

    pub passkeys: ListState,
    pub search: String,
    pub searching: bool,
    pub security: ListState,
    pub bio_list: ListState,
    pub blob_list: ListState,
    pub ssh_list: ListState,
    pub disk_list: ListState,
    pub audit_scroll: u16,
    pub info_scroll: u16,
    pub overview_list: ListState,

    pub luks: Option<LuksScan>,
    pub ssh_keys: Vec<SshKeyFile>,

    pub modal: Option<Modal>,
    pub busy: Option<Busy>,
    pub toast: Option<Toast>,
    pub external: Option<(ExternalCommand, Reload)>,
    pub reset: Option<ResetWizard>,
    pub should_quit: bool,
    pub tick: u64,

    meta: HashMap<u64, JobMeta>,
    scanning: bool,
    hidraw_sig: Vec<String>,
    last_scan: Instant,
}

impl App {
    pub fn new(backend: Arc<dyn FidoBackend>) -> (Self, UnboundedReceiver<WorkerMsg>) {
        let (jobs, rx) = Jobs::new(backend);
        let app = Self {
            jobs,
            theme: Theme::default(),
            page: Page::Overview,
            devices: Vec::new(),
            enum_errors: Vec::new(),
            inaccessible: Vec::new(),
            selected_device: 0,
            sessions: HashMap::new(),
            scanned_once: false,
            passkeys: ListState::default(),
            search: String::new(),
            searching: false,
            security: ListState::default(),
            bio_list: ListState::default(),
            blob_list: ListState::default(),
            ssh_list: ListState::default(),
            disk_list: ListState::default(),
            audit_scroll: 0,
            info_scroll: 0,
            overview_list: ListState::default(),
            luks: None,
            ssh_keys: Vec::new(),
            modal: None,
            busy: None,
            toast: None,
            external: None,
            reset: None,
            should_quit: false,
            tick: 0,
            meta: HashMap::new(),
            scanning: false,
            hidraw_sig: Vec::new(),
            last_scan: Instant::now(),
        };
        (app, rx)
    }

    /// Initial scan; call once after construction.
    pub fn start(&mut self) {
        self.hidraw_sig = sys::hidraw_signature();
        self.scan_devices();
        self.ssh_keys = sys::ssh_sk_keys();
    }

    // Accessors

    pub fn device(&self) -> Option<&FidoDevice> {
        self.devices.get(self.selected_device)
    }

    pub fn device_path(&self) -> Option<String> {
        self.device().map(|d| d.path.clone())
    }

    pub fn session(&self) -> Option<&DeviceSession> {
        self.device().and_then(|d| self.sessions.get(&d.path))
    }

    pub fn session_mut(&mut self) -> Option<&mut DeviceSession> {
        let path = self.device_path()?;
        Some(self.sessions.entry(path).or_default())
    }

    pub fn is_unlocked(&self) -> bool {
        self.session().is_some_and(|s| s.pin.is_some())
    }

    pub fn credentials(&self) -> Option<&[PasskeyCredential]> {
        self.session().and_then(|s| s.creds.as_deref())
    }

    pub fn filtered_credentials(&self) -> Vec<&PasskeyCredential> {
        self.credentials()
            .map(|c| c.iter().filter(|c| c.matches(&self.search)).collect())
            .unwrap_or_default()
    }

    pub fn selected_credential(&self) -> Option<PasskeyCredential> {
        self.filtered_credentials()
            .get(self.passkeys.selected)
            .map(|c| (*c).clone())
    }

    pub fn is_scanning(&self) -> bool {
        self.scanning
    }

    pub fn audit(&self) -> Option<AuditReport> {
        let dev = self.device()?;
        let s = self.session();
        let ctx = AuditContext {
            credentials: s.and_then(|s| s.creds.as_deref()),
            storage: s.and_then(|s| s.stats),
            fingerprints: s.and_then(|s| s.bio.as_ref().map(|b| b.len())),
            luks_fido2_enrolled: self
                .luks
                .as_ref()
                .filter(|l| !l.devices.iter().all(|d| d.is_practice))
                .map(|l| {
                    l.devices
                        .iter()
                        .any(|d| !d.is_practice && d.has_fido2_token())
                }),
        };
        Some(AuditReport::build(dev, &ctx))
    }

    // Toasts

    pub fn notify(&mut self, level: Level, message: impl Into<String>) {
        self.toast = Some(Toast {
            message: message.into(),
            level,
            at: Instant::now(),
        });
    }

    pub fn message(&mut self, level: Level, title: &str, body: &[&str]) {
        self.modal = Some(Modal::Message {
            title: title.into(),
            body: body.iter().map(|s| s.to_string()).collect(),
            level,
        });
    }

    // Jobs

    /// Run a device operation with a busy overlay.
    pub fn run<F>(&mut self, title: &str, touch: bool, f: F)
    where
        F: FnOnce(&dyn FidoBackend, &dyn Fn(Progress)) -> FidoResult<Outcome> + Send + 'static,
    {
        self.run_with_pin(title, touch, None, f)
    }

    pub fn run_with_pin<F>(
        &mut self,
        title: &str,
        touch: bool,
        pin: Option<(String, Zeroizing<String>)>,
        f: F,
    ) where
        F: FnOnce(&dyn FidoBackend, &dyn Fn(Progress)) -> FidoResult<Outcome> + Send + 'static,
    {
        let id = self.jobs.alloc_id();
        self.busy = Some(Busy {
            id,
            title: title.to_string(),
            detail: String::new(),
            touch,
            bio_remaining: None,
            bio_total: None,
            started: Instant::now(),
        });
        self.meta.insert(
            id,
            JobMeta {
                foreground: true,
                pin,
            },
        );
        self.jobs.spawn_with_id(id, f);
    }

    /// Run a device operation silently (no overlay).
    pub fn run_background<F>(&mut self, f: F)
    where
        F: FnOnce(&dyn FidoBackend, &dyn Fn(Progress)) -> FidoResult<Outcome> + Send + 'static,
    {
        let id = self.jobs.alloc_id();
        self.meta.insert(
            id,
            JobMeta {
                foreground: false,
                pin: None,
            },
        );
        self.jobs.spawn_with_id(id, f);
    }

    pub fn scan_devices(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.last_scan = Instant::now();
        self.inaccessible = sys::inaccessible_fido_nodes();
        self.run_background(|b, _| {
            let summaries = b.enumerate()?;
            let mut devices = Vec::new();
            let mut errors = Vec::new();
            for s in &summaries {
                match b.device_info(s) {
                    Ok(d) => devices.push(d),
                    Err(e) => errors.push(format!("{} ({}): {}", s.product, s.path, e)),
                }
            }
            Ok(Outcome::Devices { devices, errors })
        });
    }

    pub fn handle_worker(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Progress { id, progress } => {
                if let Some(b) = self.busy.as_mut().filter(|b| b.id == id) {
                    match progress {
                        Progress::TouchNeeded => b.touch = true,
                        Progress::Message(m) => b.detail = m,
                        Progress::BioSample {
                            remaining,
                            feedback,
                        } => {
                            if b.bio_total.is_none() {
                                b.bio_total = Some(remaining + 1);
                            }
                            b.bio_remaining = Some(remaining);
                            b.detail = feedback;
                        }
                    }
                }
            }
            WorkerMsg::Finished { id, result } => {
                let meta = self.meta.remove(&id);
                if self.busy.as_ref().is_some_and(|b| b.id == id) {
                    self.busy = None;
                    if self
                        .reset
                        .as_ref()
                        .is_some_and(|w| w.stage == ResetStage::Running)
                    {
                        self.reset = None;
                    }
                }
                let pin = meta.as_ref().and_then(|m| m.pin.clone());
                match result {
                    Ok(outcome) => {
                        if let Some((path, pin)) = pin {
                            self.sessions.entry(path).or_default().pin = Some(pin);
                        }
                        self.apply_outcome(outcome);
                    }
                    Err(e) => {
                        self.handle_error(e, pin.map(|p| p.0), meta.is_some_and(|m| m.foreground))
                    }
                }
            }
        }
    }

    fn handle_error(&mut self, e: FidoError, pin_path: Option<String>, foreground: bool) {
        if !foreground {
            // Background scans: keep quiet, but don't wedge the scanner.
            self.scanning = false;
            self.enum_errors = vec![e.to_string()];
            return;
        }
        if e.is_pin_invalid() || e.is_pin_blocked() {
            if let Some(path) = pin_path
                && let Some(s) = self.sessions.get_mut(&path)
            {
                s.pin = None;
            }
            self.scan_devices(); // refresh retry counter
        }
        if self.reset.is_some() {
            self.reset = None;
        }
        self.notify(Level::Error, e.to_string());
    }

    fn apply_outcome(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Devices { devices, errors } => {
                self.scanning = false;
                self.scanned_once = true;
                let previous = self.device_path();
                // Forget sessions (and cached PINs) of keys that were unplugged.
                self.sessions
                    .retain(|p, _| devices.iter().any(|d| &d.path == p));
                self.devices = devices;
                self.enum_errors = errors;
                self.selected_device = previous
                    .and_then(|p| self.devices.iter().position(|d| d.path == p))
                    .unwrap_or(0);
            }
            Outcome::Summaries(list) => self.advance_reset(&list),
            Outcome::Credentials { path, creds, stats } => {
                let s = self.sessions.entry(path).or_default();
                s.creds = Some(creds);
                s.stats = stats;
                let n = self.filtered_credentials().len();
                self.passkeys.clamp(n);
            }
            Outcome::Fingerprints {
                path,
                sensor,
                templates,
            } => {
                let n = templates.len();
                let s = self.sessions.entry(path).or_default();
                s.bio_sensor = Some(sensor);
                s.bio = Some(templates);
                self.bio_list.clamp(n);
            }
            Outcome::Blobs {
                path,
                array_size,
                entries,
            } => {
                let s = self.sessions.entry(path).or_default();
                s.blob_array_size = Some(array_size);
                s.blobs = Some(entries);
            }
            Outcome::SelfTest(report) => {
                let ok = report.assertion_verified;
                let lines = vec![
                    format!(
                        "Registration:  OK ({} attestation, {})",
                        report.attestation_format, report.algorithm
                    ),
                    format!(
                        "Attestation signature: {}",
                        if report.attestation_verified {
                            "verified"
                        } else {
                            "not verifiable (no x5c / none)"
                        }
                    ),
                    format!(
                        "Assertion signature:   {}",
                        if ok { "verified ✓" } else { "INVALID ✗" }
                    ),
                    format!(
                        "User verified (PIN/UV): {}",
                        if report.user_verified {
                            "yes"
                        } else {
                            "no (presence only)"
                        }
                    ),
                    String::new(),
                    "The test credential was not stored on the key.".into(),
                ];
                if let Some(s) = self.session_mut() {
                    s.self_test = Some(report);
                }
                self.modal = Some(Modal::Message {
                    title: if ok {
                        "Self-test passed".into()
                    } else {
                        "Self-test FAILED".into()
                    },
                    body: lines,
                    level: if ok { Level::Success } else { Level::Error },
                });
            }
            Outcome::Identified { path, touched } => {
                if touched {
                    if let Some(i) = self.devices.iter().position(|d| d.path == path) {
                        self.selected_device = i;
                    }
                    self.notify(Level::Success, format!("Touched: {}", path));
                } else {
                    self.notify(Level::Warn, "No touch detected");
                }
            }
            Outcome::Luks(scan) => {
                let n = scan.devices.len();
                self.luks = Some(scan);
                self.disk_list.clamp(n);
            }
            Outcome::Done { message, reload } => {
                self.notify(Level::Success, message);
                self.reload(reload);
            }
        }
    }

    pub fn reload(&mut self, r: Reload) {
        if r.devices {
            self.scan_devices();
        }
        if r.creds {
            self.load_credentials(false);
        }
        if r.bio {
            self.load_fingerprints(false);
        }
        if r.blobs {
            self.load_blobs();
        }
        if r.luks {
            self.load_luks();
        }
    }

    // Tick

    /// Called about four times per second: hot-plug detection, toast expiry, reset wizard.
    pub fn on_tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        if self
            .toast
            .as_ref()
            .is_some_and(|t| t.at.elapsed() > Duration::from_secs(6))
        {
            self.toast = None;
        }
        let sig = sys::hidraw_signature();
        let changed = sig != self.hidraw_sig;
        self.hidraw_sig = sig;

        if self.reset.is_some() {
            if changed {
                self.run_background(|b, _| b.enumerate().map(Outcome::Summaries));
            }
            if let Some(ResetWizard {
                stage: ResetStage::Replug { since },
                ..
            }) = &self.reset
                && since.elapsed() > Duration::from_secs(60)
            {
                self.reset = None;
                self.notify(Level::Warn, "Reset cancelled: key was not re-inserted");
            }
            return;
        }
        if changed || (!self.scanned_once && self.last_scan.elapsed() > Duration::from_secs(2)) {
            self.scan_devices();
        } else if self.devices.is_empty() && self.last_scan.elapsed() > Duration::from_secs(5) {
            // Permissions may change without a hidraw change (udev ACL applied late).
            self.scan_devices();
        }
    }

    pub fn take_external(&mut self) -> Option<(ExternalCommand, Reload)> {
        self.external.take()
    }

    pub fn after_external(&mut self, reload: Reload, success: bool) {
        if !success {
            self.notify(Level::Warn, "Command did not complete successfully");
        }
        self.ssh_keys = sys::ssh_sk_keys();
        self.reload(reload);
    }

    pub fn select_device(&mut self, idx: usize) {
        if idx < self.devices.len() && idx != self.selected_device {
            self.selected_device = idx;
            self.passkeys = ListState::default();
            self.bio_list = ListState::default();
            self.blob_list = ListState::default();
            let name = self.devices[idx].display_name();
            self.notify(Level::Info, format!("Selected {name}"));
        }
    }
}
