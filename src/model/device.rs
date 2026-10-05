use serde::{Deserialize, Serialize};

/// A FIDO HID device as reported by enumeration (no device I/O needed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceSummary {
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
}

/// A FIDO2 / CTAP2 authenticator together with its authenticatorGetInfo data.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FidoDevice {
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
    pub is_fido2: bool,
    pub ctaphid_version: String,
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub transports: Vec<String>,
    /// Options in the order reported by the authenticator.
    pub options: Vec<(String, bool)>,
    pub algorithms: Vec<String>,
    pub pin_protocols: Vec<u8>,
    pub aaguid: Option<String>,
    pub aaguid_name: Option<String>,
    pub fw_version: Option<u64>,
    pub max_msg_size: u64,
    pub max_creds_in_list: u64,
    pub max_cred_id_len: u64,
    pub max_cred_blob_len: u64,
    pub max_large_blob: u64,
    pub max_rpids_min_pin: u64,
    pub min_pin_len: Option<u64>,
    pub rk_remaining: Option<i64>,
    pub uv_modality: u64,
    pub pin_change_required: bool,
    pub pin_retries: Option<u32>,
    pub uv_retries: Option<u32>,
}

impl FidoDevice {
    /// Option lookup: `Some(true/false)` when reported, `None` when unsupported.
    pub fn option(&self, name: &str) -> Option<bool> {
        self.options
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| *v)
    }

    pub fn has_pin_set(&self) -> bool {
        self.option("clientPin") == Some(true)
    }

    pub fn supports_pin(&self) -> bool {
        self.option("clientPin").is_some()
    }

    pub fn supports_cred_mgmt(&self) -> bool {
        self.option("credMgmt") == Some(true) || self.option("credentialMgmtPreview") == Some(true)
    }

    pub fn supports_bio(&self) -> bool {
        self.option("bioEnroll").is_some() || self.option("userVerificationMgmtPreview").is_some()
    }

    pub fn has_fingerprints(&self) -> bool {
        self.option("bioEnroll") == Some(true)
            || self.option("userVerificationMgmtPreview") == Some(true)
    }

    pub fn supports_config(&self) -> bool {
        self.option("authnrCfg") == Some(true)
    }

    pub fn supports_large_blobs(&self) -> bool {
        self.option("largeBlobs") == Some(true)
    }

    pub fn supports_min_pin(&self) -> bool {
        self.option("setMinPINLength") == Some(true)
    }

    pub fn supports_always_uv(&self) -> bool {
        self.option("alwaysUv").is_some()
    }

    pub fn is_always_uv(&self) -> bool {
        self.option("alwaysUv") == Some(true)
    }

    pub fn supports_rk(&self) -> bool {
        self.option("rk") == Some(true)
    }

    pub fn has_extension(&self, ext: &str) -> bool {
        self.extensions.iter().any(|e| e == ext)
    }

    pub fn is_pin_blocked(&self) -> bool {
        self.pin_retries == Some(0)
    }

    pub fn fw_version_string(&self) -> Option<String> {
        self.fw_version
            .map(|v| format_fw_version(v, self.vendor_id))
    }

    pub fn display_name(&self) -> String {
        self.aaguid_name.clone().unwrap_or_else(|| {
            if self.product.is_empty() {
                "FIDO2 Security Key".to_string()
            } else {
                self.product.clone()
            }
        })
    }

    pub fn short_path(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn uv_modalities(&self) -> Vec<&'static str> {
        uv_modality_names(self.uv_modality)
    }
}

/// Firmware versions are vendor-encoded. Yubico uses 0xMMmmpp; Pico-FIDO uses 0xMMmm.
pub fn format_fw_version(v: u64, vendor_id: u16) -> String {
    match vendor_id {
        0x1050 => format!("{}.{}.{}", (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff),
        0x2e8a | 0x20a0 if v <= 0xffff => format!("{}.{}", (v >> 8) & 0xff, v & 0xff),
        _ => format!("0x{v:x}"),
    }
}

pub fn uv_modality_names(m: u64) -> Vec<&'static str> {
    const NAMES: [(u64, &str); 13] = [
        (0x0001, "presence"),
        (0x0002, "fingerprint"),
        (0x0004, "PIN"),
        (0x0008, "voice"),
        (0x0010, "face"),
        (0x0020, "location"),
        (0x0040, "eyeprint"),
        (0x0080, "pattern"),
        (0x0100, "handprint"),
        (0x0200, "none"),
        (0x0400, "all"),
        (0x0800, "external PIN"),
        (0x1000, "external pattern"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| m & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

pub fn detect_vendor(vendor_id: u16, name: &str) -> String {
    let by_vid = match vendor_id {
        0x1050 => Some("Yubico"),
        0x20a0 => Some("Nitrokey"),
        0x0483 | 0x1209 if name.to_lowercase().contains("solo") => Some("SoloKeys"),
        0x349e => Some("Token2"),
        0x18d1 => Some("Google"),
        0x096e => Some("Feitian"),
        0x1ea8 => Some("Thetis"),
        0x2e8a => Some("Pico Keys"),
        0x1d50 => Some("OpenMoko / OnlyKey"),
        _ => None,
    };
    if let Some(v) = by_vid {
        return v.to_string();
    }
    let lower = name.to_lowercase();
    for (needle, vendor) in [
        ("yubi", "Yubico"),
        ("nitrokey", "Nitrokey"),
        ("solo", "SoloKeys"),
        ("token2", "Token2"),
        ("titan", "Google"),
        ("feitian", "Feitian"),
        ("thetis", "Thetis"),
        ("pico", "Pico Keys"),
    ] {
        if lower.contains(needle) {
            return vendor.to_string();
        }
    }
    "Unknown vendor".to_string()
}

/// Resolve well-known AAGUIDs to marketing names.
pub fn lookup_aaguid(aaguid_hex: &str) -> Option<&'static str> {
    let normalized = aaguid_hex.replace('-', "").to_lowercase();
    Some(match normalized.as_str() {
        "ee882879721c491397753dfcce97072a" => "YubiKey 5 Series",
        "fa2b99dc9e3942578f924a30d23c4118" => "YubiKey 5 Series (NFC)",
        "cb69481e8ff7403993ec0a2729a154a8" => "YubiKey 5 Series (FW 5.1)",
        "2fc0579f811347eab116bb5a8db9202a" => "YubiKey 5 NFC (FW 5.2/5.4)",
        "d8522d9f575b486688a9ba99fa02f35b" => "YubiKey Bio Series",
        "149a20218ef6413396b881f8d5b7f1f5" => "Security Key NFC by Yubico",
        "6d44ba9bf6ec2e49b9300c8fe920cb73" => "Security Key by Yubico (Blue)",
        "b92c3f9ac0144056887f140a2501163b" => "Security Key by Yubico",
        "8876631bd4a0427f57730ec71c9e0279" => "SoloKeys Solo (secp256r1)",
        "89fb94b706c936739b7e30526d968145" => "Pico Key (Pico-FIDO)",
        "833b721aff5f4d00bb2ebdda3ec01e29" => "Feitian ePass FIDO2",
        _ => return None,
    })
}

pub fn format_aaguid(bytes: &[u8]) -> String {
    let h: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    if h.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
    } else {
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_detection() {
        assert_eq!(detect_vendor(0x1050, ""), "Yubico");
        assert_eq!(detect_vendor(0x2e8a, "Pol Henarejos Pico Key"), "Pico Keys");
        assert_eq!(detect_vendor(0xdead, "Some YubiKey"), "Yubico");
        assert_eq!(detect_vendor(0xdead, "Random"), "Unknown vendor");
    }

    #[test]
    fn aaguid_lookup_and_format() {
        assert_eq!(
            lookup_aaguid("89fb94b7-06c9-3673-9b7e-30526d968145"),
            Some("Pico Key (Pico-FIDO)")
        );
        let bytes = [
            0x89u8, 0xfb, 0x94, 0xb7, 0x06, 0xc9, 0x36, 0x73, 0x9b, 0x7e, 0x30, 0x52, 0x6d, 0x96,
            0x81, 0x45,
        ];
        assert_eq!(
            format_aaguid(&bytes),
            "89fb94b7-06c9-3673-9b7e-30526d968145"
        );
    }

    #[test]
    fn fw_version_formats() {
        assert_eq!(format_fw_version(0x050704, 0x1050), "5.7.4");
        assert_eq!(format_fw_version(0x800, 0x2e8a), "8.0");
        assert_eq!(format_fw_version(0x42, 0x1234), "0x42");
    }

    #[test]
    fn options_lookup() {
        let d = FidoDevice {
            options: vec![("clientPin".into(), false), ("credMgmt".into(), true)],
            ..Default::default()
        };
        assert!(d.supports_pin());
        assert!(!d.has_pin_set());
        assert!(d.supports_cred_mgmt());
        assert!(!d.supports_bio());
        assert_eq!(d.option("alwaysUv"), None);
    }
}
