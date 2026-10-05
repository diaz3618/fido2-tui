//! FIDO2 authenticator access.
//!
//! [`FidoBackend`] is the device-facing API used by the app; [`native::Libfido2`]
//! implements it on top of the system libfido2.

pub mod ffi;
pub mod native;

use std::fmt;

use crate::model::*;

/// A libfido2 / CTAP error with a human-readable explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidoError {
    pub code: i32,
    pub message: String,
}

impl FidoError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::new(ffi::FIDO_ERR_INTERNAL, message)
    }

    /// The PIN was wrong: the cached PIN must be discarded.
    pub fn is_pin_invalid(&self) -> bool {
        self.code == ffi::FIDO_ERR_PIN_INVALID
    }

    /// Too many wrong PINs in a row (or permanently blocked): stop retrying.
    pub fn is_pin_blocked(&self) -> bool {
        matches!(
            self.code,
            ffi::FIDO_ERR_PIN_BLOCKED | ffi::FIDO_ERR_PIN_AUTH_BLOCKED
        )
    }

    pub fn is_pin_required(&self) -> bool {
        matches!(
            self.code,
            ffi::FIDO_ERR_PIN_REQUIRED | ffi::FIDO_ERR_PIN_NOT_SET
        )
    }

    pub fn is_timeout(&self) -> bool {
        matches!(
            self.code,
            ffi::FIDO_ERR_USER_ACTION_TIMEOUT
                | ffi::FIDO_ERR_ACTION_TIMEOUT
                | ffi::FIDO_ERR_TIMEOUT
        )
    }
}

impl fmt::Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FidoError {}

pub type FidoResult<T> = Result<T, FidoError>;

/// Progress callback events for long-running, interactive operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The authenticator is waiting for the user to touch it.
    TouchNeeded,
    /// A fingerprint sample was captured; `remaining` more are needed.
    BioSample {
        remaining: u8,
        feedback: String,
    },
    Message(String),
}

/// Result of an end-to-end make-credential + get-assertion round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    pub algorithm: String,
    pub attestation_format: String,
    pub attestation_verified: bool,
    pub assertion_verified: bool,
    pub user_verified: bool,
}

pub trait FidoBackend: Send + Sync {
    fn enumerate(&self) -> FidoResult<Vec<DeviceSummary>>;
    fn device_info(&self, summary: &DeviceSummary) -> FidoResult<FidoDevice>;

    /// Blink / wait for a touch so the user can tell which key is which.
    fn identify(&self, path: &str, timeout_ms: u32) -> FidoResult<bool>;
    fn self_test(
        &self,
        path: &str,
        pin: Option<&str>,
        progress: &dyn Fn(Progress),
    ) -> FidoResult<SelfTestReport>;

    fn set_pin(&self, path: &str, new_pin: &str) -> FidoResult<()>;
    fn change_pin(&self, path: &str, old_pin: &str, new_pin: &str) -> FidoResult<()>;
    /// Checks a PIN without changing anything (uses credential-management metadata).
    fn verify_pin(&self, path: &str, pin: &str) -> FidoResult<()>;
    fn factory_reset(&self, path: &str) -> FidoResult<()>;

    fn toggle_always_uv(&self, path: &str, pin: &str) -> FidoResult<()>;
    fn set_min_pin_length(&self, path: &str, pin: &str, min_len: usize) -> FidoResult<()>;
    fn set_min_pin_rpids(&self, path: &str, pin: &str, rp_ids: &[String]) -> FidoResult<()>;
    fn force_pin_change(&self, path: &str, pin: &str) -> FidoResult<()>;

    fn storage_stats(&self, path: &str, pin: &str) -> FidoResult<StorageStats>;
    fn list_credentials(&self, path: &str, pin: &str) -> FidoResult<Vec<PasskeyCredential>>;
    fn delete_credential(&self, path: &str, pin: &str, cred_id: &[u8]) -> FidoResult<()>;
    fn update_user(
        &self,
        path: &str,
        pin: &str,
        cred: &PasskeyCredential,
        name: &str,
        display: &str,
    ) -> FidoResult<()>;

    fn bio_info(&self, path: &str) -> FidoResult<BioSensorInfo>;
    fn bio_list(&self, path: &str, pin: &str) -> FidoResult<Vec<BioTemplate>>;
    fn bio_enroll(
        &self,
        path: &str,
        pin: &str,
        name: &str,
        progress: &dyn Fn(Progress),
    ) -> FidoResult<BioTemplate>;
    fn bio_rename(&self, path: &str, pin: &str, id: &[u8], name: &str) -> FidoResult<()>;
    fn bio_delete(&self, path: &str, pin: &str, id: &[u8]) -> FidoResult<()>;

    /// Size in bytes of the serialized large-blob array.
    fn large_blob_array_size(&self, path: &str) -> FidoResult<usize>;
    fn large_blob_get(&self, path: &str, key: &[u8]) -> FidoResult<Option<Vec<u8>>>;
    fn large_blob_set(&self, path: &str, pin: &str, key: &[u8], data: &[u8]) -> FidoResult<()>;
    fn large_blob_delete(&self, path: &str, pin: &str, key: &[u8]) -> FidoResult<()>;
}

/// Plain-language explanation for common CTAP / libfido2 errors.
pub fn explain_error(code: i32, op: &str) -> String {
    use ffi::*;
    let what = match code {
        FIDO_ERR_PIN_INVALID => "Incorrect PIN".to_string(),
        FIDO_ERR_PIN_BLOCKED => {
            "PIN is permanently blocked - only a factory reset will recover the key".to_string()
        }
        FIDO_ERR_PIN_AUTH_BLOCKED => {
            "Too many wrong PINs in a row - unplug and re-insert the key, then try again"
                .to_string()
        }
        FIDO_ERR_PIN_NOT_SET => {
            "No PIN is set on this key - set one in PIN & Security first".to_string()
        }
        FIDO_ERR_PIN_REQUIRED => "This operation requires the key's PIN".to_string(),
        FIDO_ERR_PIN_POLICY_VIOLATION => {
            "PIN rejected by the key's policy (too short, too long or reused)".to_string()
        }
        FIDO_ERR_ACTION_TIMEOUT | FIDO_ERR_USER_ACTION_TIMEOUT | FIDO_ERR_TIMEOUT => {
            "Timed out waiting for you to touch the key".to_string()
        }
        FIDO_ERR_KEEPALIVE_CANCEL => "Operation cancelled".to_string(),
        FIDO_ERR_NOT_ALLOWED => {
            "Not allowed - for factory reset, re-insert the key and confirm within 10 seconds"
                .to_string()
        }
        FIDO_ERR_OPERATION_DENIED => {
            "Denied on the key (touch refused or user verification failed)".to_string()
        }
        FIDO_ERR_UV_BLOCKED => "Built-in user verification is blocked - use the PIN".to_string(),
        FIDO_ERR_NO_CREDENTIALS => "No matching credentials on the key".to_string(),
        FIDO_ERR_KEY_STORE_FULL => "The key's credential storage is full".to_string(),
        FIDO_ERR_LARGEBLOB_STORAGE_FULL => "Large-blob storage is full".to_string(),
        FIDO_ERR_FP_DATABASE_FULL => "No room for more fingerprints".to_string(),
        FIDO_ERR_CHANNEL_BUSY => "The key is busy with another application - try again".to_string(),
        FIDO_ERR_INVALID_COMMAND | FIDO_ERR_UNSUPPORTED_OPTION | FIDO_ERR_INVALID_OPTION => {
            "This key does not support the requested operation".to_string()
        }
        FIDO_ERR_TX | FIDO_ERR_RX => {
            "Communication with the key failed (was it unplugged?)".to_string()
        }
        _ => native::strerr(code),
    };
    if op.is_empty() {
        what
    } else {
        format!("{op}: {what}")
    }
}
