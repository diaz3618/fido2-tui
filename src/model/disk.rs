use serde::{Deserialize, Serialize};

/// An encrypted (LUKS) block device.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LuksDevice {
    pub path: String,
    pub uuid: String,
    pub label: Option<String>,
    pub size: String,
    /// Mount points of the unlocked mapping (if open).
    pub mountpoints: Vec<String>,
    /// Name of the dm-crypt mapping when the volume is open.
    pub mapped_name: Option<String>,
    pub is_system_volume: bool,
    pub is_practice: bool,
    /// `None` when the header could not be read (usually needs root).
    pub header: Option<LuksHeader>,
    pub crypttab: Option<CrypttabEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LuksHeader {
    pub version: u32,
    pub keyslots: Vec<LuksKeyslot>,
    pub tokens: Vec<LuksToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LuksKeyslot {
    pub id: u32,
    pub kdf: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LuksToken {
    pub id: u32,
    pub token_type: String,
    pub keyslots: Vec<u32>,
    pub fido2_rp: Option<String>,
    pub fido2_pin_required: Option<bool>,
    pub fido2_up_required: Option<bool>,
    pub fido2_uv_required: Option<bool>,
}

impl LuksToken {
    pub fn is_fido2(&self) -> bool {
        self.token_type == "systemd-fido2"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrypttabEntry {
    pub name: String,
    pub source: String,
    pub key_file: String,
    pub options: Vec<String>,
}

impl CrypttabEntry {
    pub fn has_fido2_device(&self) -> bool {
        self.options.iter().any(|o| o.starts_with("fido2-device="))
    }

    pub fn parse_line(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        Some(Self {
            name: parts[0].to_string(),
            source: parts[1].to_string(),
            key_file: parts.get(2).unwrap_or(&"none").to_string(),
            options: parts
                .get(3)
                .map(|o| o.split(',').map(String::from).collect())
                .unwrap_or_default(),
        })
    }

    /// Does this entry refer to the given device (by UUID or path)?
    pub fn refers_to(&self, uuid: &str, path: &str) -> bool {
        let src = self
            .source
            .trim_start_matches("UUID=")
            .trim_start_matches("/dev/disk/by-uuid/");
        (!uuid.is_empty() && src.eq_ignore_ascii_case(uuid)) || self.source == path
    }
}

impl LuksDevice {
    pub fn fido2_tokens(&self) -> Vec<&LuksToken> {
        self.header
            .iter()
            .flat_map(|h| h.tokens.iter().filter(|t| t.is_fido2()))
            .collect()
    }

    pub fn has_fido2_token(&self) -> bool {
        !self.fido2_tokens().is_empty()
    }

    /// Key slots not bound to any token - i.e. passphrase / recovery slots.
    pub fn passphrase_slots(&self) -> Vec<u32> {
        let Some(h) = &self.header else {
            return Vec::new();
        };
        let bound: Vec<u32> = h
            .tokens
            .iter()
            .flat_map(|t| t.keyslots.iter().copied())
            .collect();
        h.keyslots
            .iter()
            .map(|k| k.id)
            .filter(|id| !bound.contains(id))
            .collect()
    }

    /// Safety gate: enrolling needs LUKS2 and an existing passphrase slot,
    /// so there is always a fallback if the key is lost.
    pub fn can_safely_enroll(&self) -> Result<(), String> {
        let Some(h) = &self.header else {
            return Err(
                "LUKS header not readable yet - authenticate with sudo first (press a)".into(),
            );
        };
        if h.version != 2 {
            return Err("systemd-cryptenroll requires LUKS2 (this is LUKS1)".into());
        }
        if self.passphrase_slots().is_empty() {
            return Err(
                "No passphrase key slot found - refusing to enroll without a recovery passphrase"
                    .into(),
            );
        }
        if h.keyslots.len() >= 32 {
            return Err("All 32 LUKS2 key slots are in use".into());
        }
        Ok(())
    }
}

/// Parse `cryptsetup luksDump --dump-json-metadata` output.
pub fn parse_luks_json(json: &str) -> Result<LuksHeader, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid LUKS JSON: {e}"))?;
    let mut keyslots: Vec<LuksKeyslot> = v["keyslots"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, s)| {
                    Some(LuksKeyslot {
                        id: k.parse().ok()?,
                        kdf: s["kdf"]["type"].as_str().unwrap_or("?").to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    keyslots.sort_by_key(|k| k.id);
    let mut tokens: Vec<LuksToken> = v["tokens"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, t)| {
                    Some(LuksToken {
                        id: k.parse().ok()?,
                        token_type: t["type"].as_str().unwrap_or("?").to_string(),
                        keyslots: t["keyslots"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|s| s.as_str()?.parse().ok()).collect())
                            .unwrap_or_default(),
                        fido2_rp: t["fido2-rp"].as_str().map(String::from),
                        fido2_pin_required: t["fido2-clientPin-required"].as_bool(),
                        fido2_up_required: t["fido2-up-required"].as_bool(),
                        fido2_uv_required: t["fido2-uv-required"].as_bool(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    tokens.sort_by_key(|t| t.id);
    Ok(LuksHeader {
        version: 2,
        keyslots,
        tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = r#"{
      "keyslots": {
        "0": {"type": "luks2", "kdf": {"type": "argon2id"}},
        "1": {"type": "luks2", "kdf": {"type": "pbkdf2"}}
      },
      "tokens": {
        "0": {"type": "systemd-fido2", "keyslots": ["1"], "fido2-rp": "io.systemd.cryptsetup",
              "fido2-clientPin-required": true, "fido2-up-required": true, "fido2-uv-required": false}
      },
      "segments": {}, "digests": {}, "config": {}
    }"#;

    #[test]
    fn parses_json_dump() {
        let h = parse_luks_json(DUMP).unwrap();
        assert_eq!(h.keyslots.len(), 2);
        assert_eq!(h.keyslots[0].kdf, "argon2id");
        assert_eq!(h.tokens[0].keyslots, vec![1]);
        assert_eq!(h.tokens[0].fido2_pin_required, Some(true));
        let d = LuksDevice {
            header: Some(h),
            ..Default::default()
        };
        assert!(d.has_fido2_token());
        assert_eq!(d.passphrase_slots(), vec![0]);
        assert!(d.can_safely_enroll().is_ok());
    }

    #[test]
    fn refuses_enroll_without_passphrase_slot() {
        let mut h = parse_luks_json(DUMP).unwrap();
        h.keyslots.retain(|k| k.id == 1);
        let d = LuksDevice {
            header: Some(h),
            ..Default::default()
        };
        assert!(d.can_safely_enroll().is_err());
    }

    #[test]
    fn crypttab_parsing() {
        let e =
            CrypttabEntry::parse_line("luks-abc UUID=abc none discard,fido2-device=auto").unwrap();
        assert!(e.has_fido2_device());
        assert!(e.refers_to("ABC", "/dev/sda2"));
        assert!(CrypttabEntry::parse_line("# comment").is_none());
    }
}
