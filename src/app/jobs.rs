//! Background execution of device operations.
//!
//! Every authenticator call can block for seconds (touch prompts, fingerprint
//! capture), so it runs on a worker thread. Calls are serialized with a mutex
//! so two operations never talk to a key at the same time.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::fido::{FidoBackend, FidoError, FidoResult, Progress, SelfTestReport};
use crate::model::*;
use crate::sys::LuksScan;

/// What to reload after a successful mutation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Reload {
    pub devices: bool,
    pub creds: bool,
    pub bio: bool,
    pub blobs: bool,
    pub luks: bool,
}

impl Reload {
    pub const NONE: Reload = Reload {
        devices: false,
        creds: false,
        bio: false,
        blobs: false,
        luks: false,
    };
    pub const DEVICES: Reload = Reload {
        devices: true,
        ..Self::NONE
    };
    pub const CREDS: Reload = Reload {
        devices: true,
        creds: true,
        ..Self::NONE
    };
    pub const BIO: Reload = Reload {
        bio: true,
        ..Self::NONE
    };
    pub const BLOBS: Reload = Reload {
        blobs: true,
        ..Self::NONE
    };
    pub const LUKS: Reload = Reload {
        luks: true,
        ..Self::NONE
    };
}

#[derive(Debug, Clone)]
pub struct BlobEntry {
    pub cred_id: Vec<u8>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum Outcome {
    Devices {
        devices: Vec<FidoDevice>,
        errors: Vec<String>,
    },
    Summaries(Vec<DeviceSummary>),
    Credentials {
        path: String,
        creds: Vec<PasskeyCredential>,
        stats: Option<StorageStats>,
    },
    Fingerprints {
        path: String,
        sensor: BioSensorInfo,
        templates: Vec<BioTemplate>,
    },
    Blobs {
        path: String,
        array_size: usize,
        entries: Vec<BlobEntry>,
    },
    SelfTest(SelfTestReport),
    Identified {
        path: String,
        touched: bool,
    },
    Luks(LuksScan),
    Done {
        message: String,
        reload: Reload,
    },
}

#[derive(Debug)]
pub enum WorkerMsg {
    Progress {
        id: u64,
        progress: Progress,
    },
    Finished {
        id: u64,
        result: FidoResult<Outcome>,
    },
}

pub struct Jobs {
    backend: Arc<dyn FidoBackend>,
    tx: UnboundedSender<WorkerMsg>,
    device_lock: Arc<Mutex<()>>,
    next_id: u64,
    /// Run jobs inline on the calling thread (deterministic tests).
    pub inline: bool,
}

impl Jobs {
    pub fn new(backend: Arc<dyn FidoBackend>) -> (Self, UnboundedReceiver<WorkerMsg>) {
        let (tx, rx) = unbounded_channel();
        (
            Self {
                backend,
                tx,
                device_lock: Arc::new(Mutex::new(())),
                next_id: 1,
                inline: false,
            },
            rx,
        )
    }

    pub fn backend(&self) -> &Arc<dyn FidoBackend> {
        &self.backend
    }

    pub fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn spawn_with_id<F>(&mut self, id: u64, f: F)
    where
        F: FnOnce(&dyn FidoBackend, &dyn Fn(Progress)) -> FidoResult<Outcome> + Send + 'static,
    {
        let backend = self.backend.clone();
        let tx = self.tx.clone();
        let lock = self.device_lock.clone();
        let work = move || {
            let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let ptx = tx.clone();
            let progress = move |p: Progress| {
                let _ = ptx.send(WorkerMsg::Progress { id, progress: p });
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f(backend.as_ref(), &progress)
            }))
            .unwrap_or_else(|_| Err(FidoError::other("internal error (worker panicked)")));
            let _ = tx.send(WorkerMsg::Finished { id, result });
        };
        if self.inline {
            work();
        } else {
            std::thread::Builder::new()
                .name(format!("fido-job-{id}"))
                .spawn(work)
                .expect("spawn worker thread");
        }
    }
}
