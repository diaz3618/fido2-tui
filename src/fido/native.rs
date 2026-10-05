//! [`FidoBackend`] implementation backed by the system libfido2.

use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::Once;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use super::ffi::*;
use super::{FidoBackend, FidoError, FidoResult, Progress, SelfTestReport, explain_error};
use crate::model::*;

static INIT: Once = Once::new();

/// Talks to authenticators through libfido2. Every call opens the device,
/// performs the operation and closes it again, so hot-plugging is harmless.
pub struct Libfido2 {
    /// Timeout for operations that wait on the user (touch / fingerprint).
    pub user_timeout: Duration,
}

impl Default for Libfido2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Libfido2 {
    pub fn new() -> Self {
        // Never silently downgrade a FIDO2 key to U2F when GetInfo fails during open.
        INIT.call_once(|| unsafe { fido_init(FIDO_DISABLE_U2F_FALLBACK) });
        Self {
            user_timeout: Duration::from_secs(30),
        }
    }
}

pub fn strerr(code: i32) -> String {
    unsafe { cstr(fido_strerr(code)) }.unwrap_or_else(|| format!("libfido2 error {code}"))
}

fn is_transport_error(e: &FidoError) -> bool {
    matches!(
        e.code,
        FIDO_ERR_TX | FIDO_ERR_RX | FIDO_ERR_CHANNEL_BUSY | FIDO_ERR_TIMEOUT
    )
}

fn check(rc: c_int, op: &str) -> FidoResult<()> {
    if rc == FIDO_OK {
        Ok(())
    } else {
        Err(FidoError::new(rc, explain_error(rc, op)))
    }
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

unsafe fn bytes(p: *const u8, len: usize) -> Vec<u8> {
    if p.is_null() || len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
    }
}

unsafe fn str_array(p: *mut *mut c_char, len: usize) -> Vec<String> {
    if p.is_null() {
        return Vec::new();
    }
    (0..len)
        .filter_map(|i| unsafe { cstr(*p.add(i)) })
        .collect()
}

fn c_string(s: &str, what: &str) -> FidoResult<CString> {
    CString::new(s).map_err(|_| {
        FidoError::new(
            FIDO_ERR_INVALID_ARGUMENT,
            format!("{what} contains a NUL byte"),
        )
    })
}

/// NUL-terminated secret that is wiped from memory when dropped.
struct SecretCStr(Vec<u8>);

impl SecretCStr {
    fn new(s: &str) -> FidoResult<Self> {
        if s.as_bytes().contains(&0) {
            return Err(FidoError::new(
                FIDO_ERR_INVALID_ARGUMENT,
                "PIN contains a NUL byte",
            ));
        }
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        Ok(Self(v))
    }

    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr() as *const c_char
    }
}

impl Drop for SecretCStr {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn opt_pin(pin: Option<&str>) -> FidoResult<Option<SecretCStr>> {
    pin.filter(|p| !p.is_empty())
        .map(SecretCStr::new)
        .transpose()
}

fn pin_ptr(p: &Option<SecretCStr>) -> *const c_char {
    p.as_ref().map_or(ptr::null(), |s| s.as_ptr())
}

/// Owning wrapper for libfido2 objects freed through `fido_*_free(T **)`.
struct Owned<T> {
    ptr: *mut T,
    free: unsafe extern "C" fn(*mut *mut T),
}

impl<T> Owned<T> {
    fn new(ptr: *mut T, free: unsafe extern "C" fn(*mut *mut T), what: &str) -> FidoResult<Self> {
        if ptr.is_null() {
            Err(FidoError::other(format!("out of memory allocating {what}")))
        } else {
            Ok(Self { ptr, free })
        }
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe { (self.free)(&mut self.ptr) }
    }
}

/// An open device handle; closed and freed on drop.
struct Dev(*mut fido_dev_t);

impl Dev {
    /// Open with one retry: keys occasionally miss the first CTAPHID exchange
    /// (e.g. while another application is talking to them).
    fn open(path: &str) -> FidoResult<Self> {
        match Self::open_once(path) {
            Err(e) if is_transport_error(&e) => {
                std::thread::sleep(Duration::from_millis(300));
                Self::open_once(path)
            }
            r => r,
        }
    }

    fn open_once(path: &str) -> FidoResult<Self> {
        let cpath = c_string(path, "device path")?;
        let dev = unsafe { fido_dev_new() };
        if dev.is_null() {
            return Err(FidoError::other("out of memory allocating device"));
        }
        let rc = unsafe { fido_dev_open(dev, cpath.as_ptr()) };
        if rc != FIDO_OK {
            let mut d = dev;
            unsafe { fido_dev_free(&mut d) };
            return Err(FidoError::new(
                rc,
                explain_error(rc, &format!("Opening {path}")),
            ));
        }
        Ok(Self(dev))
    }

    fn set_timeout(&self, t: Duration) {
        unsafe { fido_dev_set_timeout(self.0, t.as_millis().min(i32::MAX as u128) as c_int) };
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        unsafe {
            fido_dev_close(self.0);
            fido_dev_free(&mut self.0);
        }
    }
}

fn cose_name(alg: c_int) -> &'static str {
    match alg {
        COSE_ES256 => "ES256",
        COSE_EDDSA => "EdDSA",
        COSE_ES384 => "ES384",
        COSE_RS256 => "RS256",
        -47 => "ES256K",
        -36 => "ES512",
        _ => "other",
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    } else {
        let u = uuid::Uuid::new_v4();
        for (i, x) in b.iter_mut().enumerate() {
            *x = u.as_bytes()[i % 16];
        }
    }
    b
}

impl Libfido2 {
    fn device_info_once(&self, s: &DeviceSummary) -> FidoResult<FidoDevice> {
        let dev = Dev::open(&s.path)?;
        let mut d = FidoDevice {
            path: s.path.clone(),
            vendor_id: s.vendor_id,
            product_id: s.product_id,
            manufacturer: s.manufacturer.clone(),
            product: s.product.clone(),
            ..Default::default()
        };
        unsafe {
            d.ctaphid_version = format!(
                "{}.{}.{}",
                fido_dev_major(dev.0),
                fido_dev_minor(dev.0),
                fido_dev_build(dev.0)
            );
            d.is_fido2 = fido_dev_is_fido2(dev.0);
        }
        if !d.is_fido2 {
            d.versions = vec!["U2F_V2".into()];
            return Ok(d);
        }

        let ci = Owned::new(unsafe { fido_cbor_info_new() }, fido_cbor_info_free, "info")?;
        check(
            unsafe { fido_dev_get_cbor_info(dev.0, ci.ptr) },
            "Reading device info",
        )?;
        unsafe {
            let c = ci.ptr;
            d.versions = str_array(
                fido_cbor_info_versions_ptr(c),
                fido_cbor_info_versions_len(c),
            );
            d.extensions = str_array(
                fido_cbor_info_extensions_ptr(c),
                fido_cbor_info_extensions_len(c),
            );
            d.transports = str_array(
                fido_cbor_info_transports_ptr(c),
                fido_cbor_info_transports_len(c),
            );
            let names = str_array(
                fido_cbor_info_options_name_ptr(c),
                fido_cbor_info_options_len(c),
            );
            let vals = fido_cbor_info_options_value_ptr(c);
            d.options = names
                .into_iter()
                .enumerate()
                .map(|(i, n)| (n, !vals.is_null() && *vals.add(i)))
                .collect();
            d.algorithms = (0..fido_cbor_info_algorithm_count(c))
                .map(|i| cose_name(fido_cbor_info_algorithm_cose(c, i)).to_string())
                .collect();
            d.pin_protocols = bytes(
                fido_cbor_info_protocols_ptr(c),
                fido_cbor_info_protocols_len(c),
            );
            let aaguid = bytes(fido_cbor_info_aaguid_ptr(c), fido_cbor_info_aaguid_len(c));
            if !aaguid.is_empty() && aaguid.iter().any(|b| *b != 0) {
                let a = format_aaguid(&aaguid);
                d.aaguid_name = lookup_aaguid(&a).map(String::from);
                d.aaguid = Some(a);
            }
            let fw = fido_cbor_info_fwversion(c);
            d.fw_version = (fw != 0).then_some(fw);
            d.max_msg_size = fido_cbor_info_maxmsgsiz(c);
            d.max_creds_in_list = fido_cbor_info_maxcredcntlst(c);
            d.max_cred_id_len = fido_cbor_info_maxcredidlen(c);
            d.max_cred_blob_len = fido_cbor_info_maxcredbloblen(c);
            d.max_large_blob = fido_cbor_info_maxlargeblob(c);
            d.max_rpids_min_pin = fido_cbor_info_maxrpid_minpinlen(c);
            let mpl = fido_cbor_info_minpinlen(c);
            d.min_pin_len = (mpl != 0).then_some(mpl);
            let rk = fido_cbor_info_rk_remaining(c);
            d.rk_remaining = (rk >= 0).then_some(rk);
            d.uv_modality = fido_cbor_info_uv_modality(c);
            d.pin_change_required = fido_cbor_info_new_pin_required(c);
        }

        if d.supports_pin() {
            let mut n: c_int = 0;
            if unsafe { fido_dev_get_retry_count(dev.0, &mut n) } == FIDO_OK {
                d.pin_retries = Some(n.max(0) as u32);
            }
        }
        if d.option("uv").is_some() || d.supports_bio() {
            let mut n: c_int = 0;
            if unsafe { fido_dev_get_uv_retry_count(dev.0, &mut n) } == FIDO_OK {
                d.uv_retries = Some(n.max(0) as u32);
            }
        }
        Ok(d)
    }

    fn identify_static(path: &str, timeout_ms: u32) -> FidoResult<bool> {
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_get_touch_begin(dev.0) },
            "Requesting touch",
        )?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < deadline {
            let mut touched: c_int = 0;
            let rc = unsafe { fido_dev_get_touch_status(dev.0, &mut touched, 200) };
            if rc != FIDO_OK {
                unsafe { fido_dev_cancel(dev.0) };
                return Err(FidoError::new(rc, explain_error(rc, "Waiting for touch")));
            }
            if touched != 0 {
                return Ok(true);
            }
        }
        unsafe { fido_dev_cancel(dev.0) };
        Ok(false)
    }

    fn self_test_impl(
        &self,
        path: &str,
        pin: Option<&str>,
        progress: &dyn Fn(Progress),
    ) -> FidoResult<SelfTestReport> {
        let pin = opt_pin(pin)?;
        let dev = Dev::open(path)?;
        dev.set_timeout(self.user_timeout);
        let rp = c"fido2-tui.local";
        let rp_name = c"fido2-tui self-test";
        let user_name = c"self-test";

        // 1. Make a non-discoverable credential (consumes no storage on the key).
        let cred = Owned::new(unsafe { fido_cred_new() }, fido_cred_free, "credential")?;
        let cdh = random_bytes::<32>();
        let uid = random_bytes::<16>();
        unsafe {
            check(fido_cred_set_type(cred.ptr, COSE_ES256), "Self-test")?;
            check(
                fido_cred_set_clientdata_hash(cred.ptr, cdh.as_ptr(), cdh.len()),
                "Self-test",
            )?;
            check(
                fido_cred_set_rp(cred.ptr, rp.as_ptr(), rp_name.as_ptr()),
                "Self-test",
            )?;
            check(
                fido_cred_set_user(
                    cred.ptr,
                    uid.as_ptr(),
                    uid.len(),
                    user_name.as_ptr(),
                    user_name.as_ptr(),
                    ptr::null(),
                ),
                "Self-test",
            )?;
            check(fido_cred_set_rk(cred.ptr, FIDO_OPT_FALSE), "Self-test")?;
        }
        progress(Progress::Message(
            "Step 1/2: registering a temporary credential".into(),
        ));
        progress(Progress::TouchNeeded);
        check(
            unsafe { fido_dev_make_cred(dev.0, cred.ptr, pin_ptr(&pin)) },
            "Registering test credential",
        )?;

        let fmt = unsafe { cstr(fido_cred_fmt(cred.ptr)) }.unwrap_or_default();
        let attestation_verified = match fmt.as_str() {
            "none" => false,
            _ => unsafe {
                fido_cred_verify(cred.ptr) == FIDO_OK || fido_cred_verify_self(cred.ptr) == FIDO_OK
            },
        };
        let cred_id = unsafe { bytes(fido_cred_id_ptr(cred.ptr), fido_cred_id_len(cred.ptr)) };
        let pubkey = unsafe {
            bytes(
                fido_cred_pubkey_ptr(cred.ptr),
                fido_cred_pubkey_len(cred.ptr),
            )
        };

        // 2. Sign a fresh challenge with it and verify the signature.
        let a = Owned::new(unsafe { fido_assert_new() }, fido_assert_free, "assertion")?;
        let cdh2 = random_bytes::<32>();
        unsafe {
            check(
                fido_assert_set_clientdata_hash(a.ptr, cdh2.as_ptr(), cdh2.len()),
                "Self-test",
            )?;
            check(fido_assert_set_rp(a.ptr, rp.as_ptr()), "Self-test")?;
            check(
                fido_assert_allow_cred(a.ptr, cred_id.as_ptr(), cred_id.len()),
                "Self-test",
            )?;
            check(fido_assert_set_up(a.ptr, FIDO_OPT_TRUE), "Self-test")?;
        }
        progress(Progress::Message("Step 2/2: signing a challenge".into()));
        progress(Progress::TouchNeeded);
        check(
            unsafe { fido_dev_get_assert(dev.0, a.ptr, pin_ptr(&pin)) },
            "Signing test challenge",
        )?;

        let pk = Owned::new(unsafe { es256_pk_new() }, es256_pk_free, "public key")?;
        let assertion_verified = unsafe {
            fido_assert_count(a.ptr) == 1
                && es256_pk_from_ptr(pk.ptr, pubkey.as_ptr().cast(), pubkey.len()) == FIDO_OK
                && fido_assert_verify(a.ptr, 0, COSE_ES256, pk.ptr as *const _) == FIDO_OK
        };
        let flags = unsafe { fido_assert_flags(a.ptr, 0) };
        Ok(SelfTestReport {
            algorithm: "ES256".into(),
            attestation_format: fmt,
            attestation_verified,
            assertion_verified,
            user_verified: flags & 0x04 != 0,
        })
    }
}

impl FidoBackend for Libfido2 {
    fn enumerate(&self) -> FidoResult<Vec<DeviceSummary>> {
        const MAX: usize = 64;
        let mut di = unsafe { fido_dev_info_new(MAX) };
        if di.is_null() {
            return Err(FidoError::other("out of memory"));
        }
        let mut n = 0usize;
        let rc = unsafe { fido_dev_info_manifest(di, MAX, &mut n) };
        let result = check(rc, "Enumerating security keys").map(|_| {
            (0..n)
                .filter_map(|i| unsafe {
                    let e = fido_dev_info_ptr(di, i);
                    let path = cstr(fido_dev_info_path(e))?;
                    let product = cstr(fido_dev_info_product_string(e)).unwrap_or_default();
                    let vendor_id = fido_dev_info_vendor(e) as u16;
                    let manufacturer = cstr(fido_dev_info_manufacturer_string(e))
                        .filter(|m| !m.trim().is_empty())
                        .unwrap_or_else(|| detect_vendor(vendor_id, &product));
                    Some(DeviceSummary {
                        path,
                        vendor_id,
                        product_id: fido_dev_info_product(e) as u16,
                        manufacturer,
                        product,
                    })
                })
                .collect::<Vec<_>>()
        });
        unsafe { fido_dev_info_free(&mut di, MAX) };
        let mut list = result?;
        list.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(list)
    }

    fn device_info(&self, s: &DeviceSummary) -> FidoResult<FidoDevice> {
        // Some firmware (seen on Pico-FIDO) occasionally fumbles a fresh channel:
        // the reply is lost or lacks the CBOR capability bit. Retry, paced, since
        // this call sends no PIN and is safe to repeat.
        let mut last = None;
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(300));
            }
            match self.device_info_once(s) {
                Ok(d) if d.is_fido2 => return Ok(d),
                Ok(d) => last = Some(Ok(d)),
                Err(e) if is_transport_error(&e) => last = Some(Err(e)),
                Err(e) => return Err(e),
            }
        }
        last.unwrap_or_else(|| Err(FidoError::other("no response")))
    }

    fn identify(&self, path: &str, timeout_ms: u32) -> FidoResult<bool> {
        Self::identify_static(path, timeout_ms)
    }

    fn self_test(
        &self,
        path: &str,
        pin: Option<&str>,
        progress: &dyn Fn(Progress),
    ) -> FidoResult<SelfTestReport> {
        self.self_test_impl(path, pin, progress)
    }

    fn set_pin(&self, path: &str, new_pin: &str) -> FidoResult<()> {
        let p = SecretCStr::new(new_pin)?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_set_pin(dev.0, p.as_ptr(), ptr::null()) },
            "Setting PIN",
        )
    }

    fn change_pin(&self, path: &str, old_pin: &str, new_pin: &str) -> FidoResult<()> {
        let old = SecretCStr::new(old_pin)?;
        let new = SecretCStr::new(new_pin)?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_set_pin(dev.0, new.as_ptr(), old.as_ptr()) },
            "Changing PIN",
        )
    }

    fn verify_pin(&self, path: &str, pin: &str) -> FidoResult<()> {
        self.storage_stats(path, pin).map(|_| ())
    }

    fn factory_reset(&self, path: &str) -> FidoResult<()> {
        let dev = Dev::open(path)?;
        dev.set_timeout(self.user_timeout);
        check(unsafe { fido_dev_reset(dev.0) }, "Factory reset")
    }

    fn toggle_always_uv(&self, path: &str, pin: &str) -> FidoResult<()> {
        let p = opt_pin(Some(pin))?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_toggle_always_uv(dev.0, pin_ptr(&p)) },
            "Toggling Always-UV",
        )
    }

    fn set_min_pin_length(&self, path: &str, pin: &str, min_len: usize) -> FidoResult<()> {
        let p = opt_pin(Some(pin))?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_set_pin_minlen(dev.0, min_len, pin_ptr(&p)) },
            "Setting minimum PIN length",
        )
    }

    fn set_min_pin_rpids(&self, path: &str, pin: &str, rp_ids: &[String]) -> FidoResult<()> {
        let p = opt_pin(Some(pin))?;
        let owned: Vec<CString> = rp_ids
            .iter()
            .map(|r| c_string(r, "RP ID"))
            .collect::<FidoResult<_>>()?;
        let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_set_pin_minlen_rpid(dev.0, ptrs.as_ptr(), ptrs.len(), pin_ptr(&p)) },
            "Setting minPinLength relying parties",
        )
    }

    fn force_pin_change(&self, path: &str, pin: &str) -> FidoResult<()> {
        let p = opt_pin(Some(pin))?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_force_pin_change(dev.0, pin_ptr(&p)) },
            "Forcing PIN change",
        )
    }

    fn storage_stats(&self, path: &str, pin: &str) -> FidoResult<StorageStats> {
        let p = SecretCStr::new(pin)?;
        let dev = Dev::open(path)?;
        let md = Owned::new(
            unsafe { fido_credman_metadata_new() },
            fido_credman_metadata_free,
            "metadata",
        )?;
        check(
            unsafe { fido_credman_get_dev_metadata(dev.0, md.ptr, p.as_ptr()) },
            "Reading credential storage",
        )?;
        Ok(StorageStats {
            existing: unsafe { fido_credman_rk_existing(md.ptr) },
            remaining: unsafe { fido_credman_rk_remaining(md.ptr) },
        })
    }

    fn list_credentials(&self, path: &str, pin: &str) -> FidoResult<Vec<PasskeyCredential>> {
        let p = SecretCStr::new(pin)?;
        let dev = Dev::open(path)?;
        let rps = Owned::new(
            unsafe { fido_credman_rp_new() },
            fido_credman_rp_free,
            "RP list",
        )?;
        let rc = unsafe { fido_credman_get_dev_rp(dev.0, rps.ptr, p.as_ptr()) };
        if rc == FIDO_ERR_NO_CREDENTIALS {
            return Ok(Vec::new());
        }
        check(rc, "Listing relying parties")?;

        let mut out = Vec::new();
        for i in 0..unsafe { fido_credman_rp_count(rps.ptr) } {
            let rp_id_ptr = unsafe { fido_credman_rp_id(rps.ptr, i) };
            let Some(rp_id) = (unsafe { cstr(rp_id_ptr) }) else {
                continue;
            };
            let rp_name =
                unsafe { cstr(fido_credman_rp_name(rps.ptr, i)) }.filter(|n| !n.is_empty());
            let rks = Owned::new(
                unsafe { fido_credman_rk_new() },
                fido_credman_rk_free,
                "credential list",
            )?;
            let rc = unsafe { fido_credman_get_dev_rk(dev.0, rp_id_ptr, rks.ptr, p.as_ptr()) };
            if rc == FIDO_ERR_NO_CREDENTIALS {
                continue;
            }
            check(rc, &format!("Listing credentials for {rp_id}"))?;
            for j in 0..unsafe { fido_credman_rk_count(rks.ptr) } {
                let c = unsafe { fido_credman_rk(rks.ptr, j) };
                if c.is_null() {
                    continue;
                }
                let lbk = unsafe {
                    bytes(
                        fido_cred_largeblob_key_ptr(c),
                        fido_cred_largeblob_key_len(c),
                    )
                };
                out.push(PasskeyCredential {
                    rp_id: rp_id.clone(),
                    rp_name: rp_name.clone(),
                    user_id: unsafe { bytes(fido_cred_user_id_ptr(c), fido_cred_user_id_len(c)) },
                    user_name: unsafe { cstr(fido_cred_user_name(c)) }.unwrap_or_default(),
                    user_display_name: unsafe { cstr(fido_cred_display_name(c)) }
                        .unwrap_or_default(),
                    cred_id: unsafe { bytes(fido_cred_id_ptr(c), fido_cred_id_len(c)) },
                    algorithm: cose_name(unsafe { fido_cred_type(c) }).to_string(),
                    cred_protect: unsafe { fido_cred_prot(c) }.clamp(0, 255) as u8,
                    large_blob_key: (!lbk.is_empty()).then_some(lbk),
                });
            }
        }
        out.sort_by(|a, b| a.rp_id.cmp(&b.rp_id).then(a.user_name.cmp(&b.user_name)));
        Ok(out)
    }

    fn delete_credential(&self, path: &str, pin: &str, cred_id: &[u8]) -> FidoResult<()> {
        let p = SecretCStr::new(pin)?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_credman_del_dev_rk(dev.0, cred_id.as_ptr(), cred_id.len(), p.as_ptr()) },
            "Deleting passkey",
        )
    }

    fn update_user(
        &self,
        path: &str,
        pin: &str,
        cred: &PasskeyCredential,
        name: &str,
        display: &str,
    ) -> FidoResult<()> {
        let p = SecretCStr::new(pin)?;
        let cname = c_string(name, "user name")?;
        let cdisplay = c_string(display, "display name")?;
        let c = Owned::new(unsafe { fido_cred_new() }, fido_cred_free, "credential")?;
        unsafe {
            check(
                fido_cred_set_id(c.ptr, cred.cred_id.as_ptr(), cred.cred_id.len()),
                "Updating passkey",
            )?;
            check(
                fido_cred_set_user(
                    c.ptr,
                    cred.user_id.as_ptr(),
                    cred.user_id.len(),
                    cname.as_ptr(),
                    cdisplay.as_ptr(),
                    ptr::null(),
                ),
                "Updating passkey",
            )?;
        }
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_credman_set_dev_rk(dev.0, c.ptr, p.as_ptr()) },
            "Updating passkey",
        )
    }

    fn bio_info(&self, path: &str) -> FidoResult<BioSensorInfo> {
        let dev = Dev::open(path)?;
        let bi = Owned::new(
            unsafe { fido_bio_info_new() },
            fido_bio_info_free,
            "bio info",
        )?;
        check(
            unsafe { fido_bio_dev_get_info(dev.0, bi.ptr) },
            "Reading fingerprint sensor info",
        )?;
        Ok(BioSensorInfo {
            sensor_type: unsafe { fido_bio_info_type(bi.ptr) },
            max_samples: unsafe { fido_bio_info_max_samples(bi.ptr) },
        })
    }

    fn bio_list(&self, path: &str, pin: &str) -> FidoResult<Vec<BioTemplate>> {
        let p = SecretCStr::new(pin)?;
        let dev = Dev::open(path)?;
        let ta = Owned::new(
            unsafe { fido_bio_template_array_new() },
            fido_bio_template_array_free,
            "templates",
        )?;
        check(
            unsafe { fido_bio_dev_get_template_array(dev.0, ta.ptr, p.as_ptr()) },
            "Listing fingerprints",
        )?;
        Ok((0..unsafe { fido_bio_template_array_count(ta.ptr) })
            .filter_map(|i| {
                let t = unsafe { fido_bio_template(ta.ptr, i) };
                (!t.is_null()).then(|| BioTemplate {
                    id: unsafe { bytes(fido_bio_template_id_ptr(t), fido_bio_template_id_len(t)) },
                    name: unsafe { cstr(fido_bio_template_name(t)) },
                })
            })
            .collect())
    }

    fn bio_enroll(
        &self,
        path: &str,
        pin: &str,
        name: &str,
        progress: &dyn Fn(Progress),
    ) -> FidoResult<BioTemplate> {
        let p = SecretCStr::new(pin)?;
        let cname = c_string(name, "fingerprint name")?;
        let dev = Dev::open(path)?;
        let t = Owned::new(
            unsafe { fido_bio_template_new() },
            fido_bio_template_free,
            "template",
        )?;
        let e = Owned::new(
            unsafe { fido_bio_enroll_new() },
            fido_bio_enroll_free,
            "enrollment",
        )?;
        let timeout = self.user_timeout.as_millis() as u32;

        progress(Progress::Message("Place your finger on the sensor".into()));
        progress(Progress::TouchNeeded);
        check(
            unsafe { fido_bio_dev_enroll_begin(dev.0, t.ptr, e.ptr, timeout, p.as_ptr()) },
            "Fingerprint enrollment",
        )?;
        loop {
            let remaining = unsafe { fido_bio_enroll_remaining_samples(e.ptr) };
            let status = unsafe { fido_bio_enroll_last_status(e.ptr) };
            progress(Progress::BioSample {
                remaining,
                feedback: bio_sample_feedback(status).to_string(),
            });
            if remaining == 0 {
                break;
            }
            let rc = unsafe { fido_bio_dev_enroll_continue(dev.0, t.ptr, e.ptr, timeout) };
            if rc != FIDO_OK {
                unsafe { fido_bio_dev_enroll_cancel(dev.0) };
                return Err(FidoError::new(
                    rc,
                    explain_error(rc, "Fingerprint enrollment"),
                ));
            }
        }
        let id = unsafe {
            bytes(
                fido_bio_template_id_ptr(t.ptr),
                fido_bio_template_id_len(t.ptr),
            )
        };
        if !name.is_empty() {
            unsafe {
                check(
                    fido_bio_template_set_name(t.ptr, cname.as_ptr()),
                    "Naming fingerprint",
                )?;
                check(
                    fido_bio_dev_set_template_name(dev.0, t.ptr, p.as_ptr()),
                    "Naming fingerprint",
                )?;
            }
        }
        Ok(BioTemplate {
            id,
            name: (!name.is_empty()).then(|| name.to_string()),
        })
    }

    fn bio_rename(&self, path: &str, pin: &str, id: &[u8], name: &str) -> FidoResult<()> {
        let p = SecretCStr::new(pin)?;
        let cname = c_string(name, "fingerprint name")?;
        let t = Owned::new(
            unsafe { fido_bio_template_new() },
            fido_bio_template_free,
            "template",
        )?;
        unsafe {
            check(
                fido_bio_template_set_id(t.ptr, id.as_ptr(), id.len()),
                "Renaming fingerprint",
            )?;
            check(
                fido_bio_template_set_name(t.ptr, cname.as_ptr()),
                "Renaming fingerprint",
            )?;
        }
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_bio_dev_set_template_name(dev.0, t.ptr, p.as_ptr()) },
            "Renaming fingerprint",
        )
    }

    fn bio_delete(&self, path: &str, pin: &str, id: &[u8]) -> FidoResult<()> {
        let p = SecretCStr::new(pin)?;
        let t = Owned::new(
            unsafe { fido_bio_template_new() },
            fido_bio_template_free,
            "template",
        )?;
        check(
            unsafe { fido_bio_template_set_id(t.ptr, id.as_ptr(), id.len()) },
            "Deleting fingerprint",
        )?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_bio_dev_enroll_remove(dev.0, t.ptr, p.as_ptr()) },
            "Deleting fingerprint",
        )
    }

    fn large_blob_array_size(&self, path: &str) -> FidoResult<usize> {
        let dev = Dev::open(path)?;
        let mut buf: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        check(
            unsafe { fido_dev_largeblob_get_array(dev.0, &mut buf, &mut len) },
            "Reading large-blob array",
        )?;
        unsafe { free(buf.cast()) };
        Ok(len)
    }

    fn large_blob_get(&self, path: &str, key: &[u8]) -> FidoResult<Option<Vec<u8>>> {
        let dev = Dev::open(path)?;
        let mut buf: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        let rc =
            unsafe { fido_dev_largeblob_get(dev.0, key.as_ptr(), key.len(), &mut buf, &mut len) };
        if rc == FIDO_ERR_NOTFOUND {
            return Ok(None);
        }
        check(rc, "Reading large blob")?;
        let data = unsafe { bytes(buf, len) };
        unsafe { free(buf.cast()) };
        Ok(Some(data))
    }

    fn large_blob_set(&self, path: &str, pin: &str, key: &[u8], data: &[u8]) -> FidoResult<()> {
        let p = opt_pin(Some(pin))?;
        let dev = Dev::open(path)?;
        check(
            unsafe {
                fido_dev_largeblob_set(
                    dev.0,
                    key.as_ptr(),
                    key.len(),
                    data.as_ptr(),
                    data.len(),
                    pin_ptr(&p),
                )
            },
            "Writing large blob",
        )
    }

    fn large_blob_delete(&self, path: &str, pin: &str, key: &[u8]) -> FidoResult<()> {
        let p = opt_pin(Some(pin))?;
        let dev = Dev::open(path)?;
        check(
            unsafe { fido_dev_largeblob_remove(dev.0, key.as_ptr(), key.len(), pin_ptr(&p)) },
            "Deleting large blob",
        )
    }
}
