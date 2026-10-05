//! Raw bindings to the system libfido2 (>= 1.13). Only the subset used by
//! this application is declared. See `fido.h` and `fido/*.h` upstream.
#![allow(non_camel_case_types, dead_code)]

use std::os::raw::{c_char, c_int, c_uchar, c_void};

#[repr(C)]
pub struct fido_dev_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_dev_info_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_cbor_info_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_cred_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_assert_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_credman_metadata_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_credman_rp_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_credman_rk_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_bio_info_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_bio_template_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_bio_template_array_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct fido_bio_enroll_t {
    _p: [u8; 0],
}
#[repr(C)]
pub struct es256_pk_t {
    _p: [u8; 0],
}

pub const FIDO_OK: c_int = 0;
pub const FIDO_DISABLE_U2F_FALLBACK: c_int = 0x02;

pub const FIDO_OPT_OMIT: c_int = 0;
pub const FIDO_OPT_FALSE: c_int = 1;
pub const FIDO_OPT_TRUE: c_int = 2;

pub const COSE_ES256: c_int = -7;
pub const COSE_EDDSA: c_int = -8;
pub const COSE_ES384: c_int = -35;
pub const COSE_RS256: c_int = -257;

pub const FIDO_ERR_TIMEOUT: c_int = 0x05;
pub const FIDO_ERR_CHANNEL_BUSY: c_int = 0x06;
pub const FIDO_ERR_UNSUPPORTED_OPTION: c_int = 0x2b;
pub const FIDO_ERR_INVALID_OPTION: c_int = 0x2c;
pub const FIDO_ERR_KEEPALIVE_CANCEL: c_int = 0x2d;
pub const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
pub const FIDO_ERR_USER_ACTION_TIMEOUT: c_int = 0x2f;
pub const FIDO_ERR_NOT_ALLOWED: c_int = 0x30;
pub const FIDO_ERR_PIN_INVALID: c_int = 0x31;
pub const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
pub const FIDO_ERR_PIN_AUTH_INVALID: c_int = 0x33;
pub const FIDO_ERR_PIN_AUTH_BLOCKED: c_int = 0x34;
pub const FIDO_ERR_PIN_NOT_SET: c_int = 0x35;
pub const FIDO_ERR_PIN_REQUIRED: c_int = 0x36;
pub const FIDO_ERR_PIN_POLICY_VIOLATION: c_int = 0x37;
pub const FIDO_ERR_ACTION_TIMEOUT: c_int = 0x3a;
pub const FIDO_ERR_UP_REQUIRED: c_int = 0x3b;
pub const FIDO_ERR_UV_BLOCKED: c_int = 0x3c;
pub const FIDO_ERR_OPERATION_DENIED: c_int = 0x27;
pub const FIDO_ERR_KEY_STORE_FULL: c_int = 0x28;
pub const FIDO_ERR_LARGEBLOB_STORAGE_FULL: c_int = 0x18;
pub const FIDO_ERR_FP_DATABASE_FULL: c_int = 0x17;
pub const FIDO_ERR_INVALID_COMMAND: c_int = 0x01;
pub const FIDO_ERR_UNSUPPORTED_ALGORITHM: c_int = 0x26;
pub const FIDO_ERR_TX: c_int = -1;
pub const FIDO_ERR_RX: c_int = -2;
pub const FIDO_ERR_INVALID_ARGUMENT: c_int = -7;
pub const FIDO_ERR_NOTFOUND: c_int = -10;
pub const FIDO_ERR_INTERNAL: c_int = -9;

#[link(name = "fido2")]
unsafe extern "C" {
    pub fn fido_init(flags: c_int);
    pub fn fido_strerr(err: c_int) -> *const c_char;

    // Enumeration
    pub fn fido_dev_info_new(n: usize) -> *mut fido_dev_info_t;
    pub fn fido_dev_info_free(di: *mut *mut fido_dev_info_t, n: usize);
    pub fn fido_dev_info_manifest(di: *mut fido_dev_info_t, ilen: usize, olen: *mut usize)
    -> c_int;
    pub fn fido_dev_info_ptr(di: *const fido_dev_info_t, i: usize) -> *const fido_dev_info_t;
    pub fn fido_dev_info_path(di: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_product_string(di: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_manufacturer_string(di: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_vendor(di: *const fido_dev_info_t) -> i16;
    pub fn fido_dev_info_product(di: *const fido_dev_info_t) -> i16;

    // Device handle
    pub fn fido_dev_new() -> *mut fido_dev_t;
    pub fn fido_dev_free(dev: *mut *mut fido_dev_t);
    pub fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
    pub fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_cancel(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_set_timeout(dev: *mut fido_dev_t, ms: c_int) -> c_int;
    pub fn fido_dev_protocol(dev: *const fido_dev_t) -> u8;
    pub fn fido_dev_major(dev: *const fido_dev_t) -> u8;
    pub fn fido_dev_minor(dev: *const fido_dev_t) -> u8;
    pub fn fido_dev_build(dev: *const fido_dev_t) -> u8;
    pub fn fido_dev_flags(dev: *const fido_dev_t) -> u8;
    pub fn fido_dev_is_fido2(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_get_retry_count(dev: *mut fido_dev_t, retries: *mut c_int) -> c_int;
    pub fn fido_dev_get_uv_retry_count(dev: *mut fido_dev_t, retries: *mut c_int) -> c_int;
    pub fn fido_dev_get_touch_begin(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_get_touch_status(dev: *mut fido_dev_t, touched: *mut c_int, ms: c_int)
    -> c_int;
    pub fn fido_dev_set_pin(
        dev: *mut fido_dev_t,
        pin: *const c_char,
        oldpin: *const c_char,
    ) -> c_int;
    pub fn fido_dev_reset(dev: *mut fido_dev_t) -> c_int;

    // authenticatorConfig
    pub fn fido_dev_toggle_always_uv(dev: *mut fido_dev_t, pin: *const c_char) -> c_int;
    pub fn fido_dev_set_pin_minlen(dev: *mut fido_dev_t, len: usize, pin: *const c_char) -> c_int;
    pub fn fido_dev_force_pin_change(dev: *mut fido_dev_t, pin: *const c_char) -> c_int;
    pub fn fido_dev_set_pin_minlen_rpid(
        dev: *mut fido_dev_t,
        rpid: *const *const c_char,
        n: usize,
        pin: *const c_char,
    ) -> c_int;

    // authenticatorGetInfo
    pub fn fido_cbor_info_new() -> *mut fido_cbor_info_t;
    pub fn fido_cbor_info_free(ci: *mut *mut fido_cbor_info_t);
    pub fn fido_dev_get_cbor_info(dev: *mut fido_dev_t, ci: *mut fido_cbor_info_t) -> c_int;
    pub fn fido_cbor_info_versions_ptr(ci: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_versions_len(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_extensions_ptr(ci: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_extensions_len(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_transports_ptr(ci: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_transports_len(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_options_name_ptr(ci: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_options_value_ptr(ci: *const fido_cbor_info_t) -> *const bool;
    pub fn fido_cbor_info_options_len(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_aaguid_ptr(ci: *const fido_cbor_info_t) -> *const c_uchar;
    pub fn fido_cbor_info_aaguid_len(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_protocols_ptr(ci: *const fido_cbor_info_t) -> *const u8;
    pub fn fido_cbor_info_protocols_len(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_algorithm_count(ci: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_algorithm_cose(ci: *const fido_cbor_info_t, i: usize) -> c_int;
    pub fn fido_cbor_info_fwversion(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_maxmsgsiz(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_maxcredcntlst(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_maxcredidlen(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_maxcredbloblen(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_maxlargeblob(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_maxrpid_minpinlen(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_minpinlen(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_uv_attempts(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_uv_modality(ci: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_rk_remaining(ci: *const fido_cbor_info_t) -> i64;
    pub fn fido_cbor_info_new_pin_required(ci: *const fido_cbor_info_t) -> bool;

    // Credentials / assertions
    pub fn fido_cred_new() -> *mut fido_cred_t;
    pub fn fido_cred_free(cred: *mut *mut fido_cred_t);
    pub fn fido_cred_id_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_id_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_user_id_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_user_id_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_user_name(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_display_name(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_rp_id(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_rp_name(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_type(cred: *const fido_cred_t) -> c_int;
    pub fn fido_cred_prot(cred: *const fido_cred_t) -> c_int;
    pub fn fido_cred_fmt(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_flags(cred: *const fido_cred_t) -> u8;
    pub fn fido_cred_pubkey_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_pubkey_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_largeblob_key_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_largeblob_key_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_set_id(cred: *mut fido_cred_t, ptr: *const c_uchar, len: usize) -> c_int;
    pub fn fido_cred_set_user(
        cred: *mut fido_cred_t,
        user_id: *const c_uchar,
        user_id_len: usize,
        name: *const c_char,
        display_name: *const c_char,
        icon: *const c_char,
    ) -> c_int;
    pub fn fido_cred_set_rp(
        cred: *mut fido_cred_t,
        id: *const c_char,
        name: *const c_char,
    ) -> c_int;
    pub fn fido_cred_set_type(cred: *mut fido_cred_t, cose_alg: c_int) -> c_int;
    pub fn fido_cred_set_clientdata_hash(
        cred: *mut fido_cred_t,
        ptr: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_cred_set_rk(cred: *mut fido_cred_t, rk: c_int) -> c_int;
    pub fn fido_cred_verify(cred: *const fido_cred_t) -> c_int;
    pub fn fido_cred_verify_self(cred: *const fido_cred_t) -> c_int;
    pub fn fido_dev_make_cred(
        dev: *mut fido_dev_t,
        cred: *mut fido_cred_t,
        pin: *const c_char,
    ) -> c_int;

    pub fn fido_assert_new() -> *mut fido_assert_t;
    pub fn fido_assert_free(a: *mut *mut fido_assert_t);
    pub fn fido_assert_set_clientdata_hash(
        a: *mut fido_assert_t,
        ptr: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_set_rp(a: *mut fido_assert_t, id: *const c_char) -> c_int;
    pub fn fido_assert_allow_cred(a: *mut fido_assert_t, ptr: *const c_uchar, len: usize) -> c_int;
    pub fn fido_assert_set_up(a: *mut fido_assert_t, up: c_int) -> c_int;
    pub fn fido_assert_count(a: *const fido_assert_t) -> usize;
    pub fn fido_assert_flags(a: *const fido_assert_t, idx: usize) -> u8;
    pub fn fido_assert_verify(
        a: *const fido_assert_t,
        idx: usize,
        cose_alg: c_int,
        pk: *const c_void,
    ) -> c_int;
    pub fn fido_dev_get_assert(
        dev: *mut fido_dev_t,
        a: *mut fido_assert_t,
        pin: *const c_char,
    ) -> c_int;

    pub fn es256_pk_new() -> *mut es256_pk_t;
    pub fn es256_pk_free(pk: *mut *mut es256_pk_t);
    pub fn es256_pk_from_ptr(pk: *mut es256_pk_t, ptr: *const c_void, len: usize) -> c_int;

    // Credential management
    pub fn fido_credman_metadata_new() -> *mut fido_credman_metadata_t;
    pub fn fido_credman_metadata_free(md: *mut *mut fido_credman_metadata_t);
    pub fn fido_credman_get_dev_metadata(
        dev: *mut fido_dev_t,
        md: *mut fido_credman_metadata_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_rk_existing(md: *const fido_credman_metadata_t) -> u64;
    pub fn fido_credman_rk_remaining(md: *const fido_credman_metadata_t) -> u64;

    pub fn fido_credman_rp_new() -> *mut fido_credman_rp_t;
    pub fn fido_credman_rp_free(rp: *mut *mut fido_credman_rp_t);
    pub fn fido_credman_get_dev_rp(
        dev: *mut fido_dev_t,
        rp: *mut fido_credman_rp_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_rp_count(rp: *const fido_credman_rp_t) -> usize;
    pub fn fido_credman_rp_id(rp: *const fido_credman_rp_t, i: usize) -> *const c_char;
    pub fn fido_credman_rp_name(rp: *const fido_credman_rp_t, i: usize) -> *const c_char;

    pub fn fido_credman_rk_new() -> *mut fido_credman_rk_t;
    pub fn fido_credman_rk_free(rk: *mut *mut fido_credman_rk_t);
    pub fn fido_credman_get_dev_rk(
        dev: *mut fido_dev_t,
        rp_id: *const c_char,
        rk: *mut fido_credman_rk_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_rk_count(rk: *const fido_credman_rk_t) -> usize;
    pub fn fido_credman_rk(rk: *const fido_credman_rk_t, i: usize) -> *const fido_cred_t;
    pub fn fido_credman_del_dev_rk(
        dev: *mut fido_dev_t,
        cred_id: *const c_uchar,
        cred_id_len: usize,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_set_dev_rk(
        dev: *mut fido_dev_t,
        cred: *mut fido_cred_t,
        pin: *const c_char,
    ) -> c_int;

    // Biometrics
    pub fn fido_bio_info_new() -> *mut fido_bio_info_t;
    pub fn fido_bio_info_free(bi: *mut *mut fido_bio_info_t);
    pub fn fido_bio_dev_get_info(dev: *mut fido_dev_t, bi: *mut fido_bio_info_t) -> c_int;
    pub fn fido_bio_info_type(bi: *const fido_bio_info_t) -> u8;
    pub fn fido_bio_info_max_samples(bi: *const fido_bio_info_t) -> u8;

    pub fn fido_bio_template_array_new() -> *mut fido_bio_template_array_t;
    pub fn fido_bio_template_array_free(ta: *mut *mut fido_bio_template_array_t);
    pub fn fido_bio_dev_get_template_array(
        dev: *mut fido_dev_t,
        ta: *mut fido_bio_template_array_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_bio_template_array_count(ta: *const fido_bio_template_array_t) -> usize;
    pub fn fido_bio_template(
        ta: *const fido_bio_template_array_t,
        i: usize,
    ) -> *const fido_bio_template_t;

    pub fn fido_bio_template_new() -> *mut fido_bio_template_t;
    pub fn fido_bio_template_free(t: *mut *mut fido_bio_template_t);
    pub fn fido_bio_template_id_ptr(t: *const fido_bio_template_t) -> *const c_uchar;
    pub fn fido_bio_template_id_len(t: *const fido_bio_template_t) -> usize;
    pub fn fido_bio_template_name(t: *const fido_bio_template_t) -> *const c_char;
    pub fn fido_bio_template_set_id(
        t: *mut fido_bio_template_t,
        ptr: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_bio_template_set_name(t: *mut fido_bio_template_t, name: *const c_char) -> c_int;
    pub fn fido_bio_dev_set_template_name(
        dev: *mut fido_dev_t,
        t: *const fido_bio_template_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_bio_dev_enroll_remove(
        dev: *mut fido_dev_t,
        t: *const fido_bio_template_t,
        pin: *const c_char,
    ) -> c_int;

    pub fn fido_bio_enroll_new() -> *mut fido_bio_enroll_t;
    pub fn fido_bio_enroll_free(e: *mut *mut fido_bio_enroll_t);
    pub fn fido_bio_enroll_remaining_samples(e: *const fido_bio_enroll_t) -> u8;
    pub fn fido_bio_enroll_last_status(e: *const fido_bio_enroll_t) -> u8;
    pub fn fido_bio_dev_enroll_begin(
        dev: *mut fido_dev_t,
        t: *mut fido_bio_template_t,
        e: *mut fido_bio_enroll_t,
        timeout_ms: u32,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_bio_dev_enroll_continue(
        dev: *mut fido_dev_t,
        t: *const fido_bio_template_t,
        e: *mut fido_bio_enroll_t,
        timeout_ms: u32,
    ) -> c_int;
    pub fn fido_bio_dev_enroll_cancel(dev: *mut fido_dev_t) -> c_int;

    // Large blobs
    pub fn fido_dev_largeblob_get_array(
        dev: *mut fido_dev_t,
        cbor: *mut *mut c_uchar,
        len: *mut usize,
    ) -> c_int;
    pub fn fido_dev_largeblob_get(
        dev: *mut fido_dev_t,
        key: *const c_uchar,
        key_len: usize,
        blob: *mut *mut c_uchar,
        blob_len: *mut usize,
    ) -> c_int;
    pub fn fido_dev_largeblob_set(
        dev: *mut fido_dev_t,
        key: *const c_uchar,
        key_len: usize,
        blob: *const c_uchar,
        blob_len: usize,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_dev_largeblob_remove(
        dev: *mut fido_dev_t,
        key: *const c_uchar,
        key_len: usize,
        pin: *const c_char,
    ) -> c_int;
}

unsafe extern "C" {
    pub fn free(p: *mut c_void);
}
