use serde::{Deserialize, Serialize};

/// A discoverable (resident) credential stored on the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyCredential {
    pub rp_id: String,
    pub rp_name: Option<String>,
    #[serde(with = "hex_bytes")]
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    #[serde(with = "hex_bytes")]
    pub cred_id: Vec<u8>,
    pub algorithm: String,
    /// credProtect level (1 = UV optional, 2 = UV optional with ID list, 3 = UV required)
    pub cred_protect: u8,
    #[serde(skip)]
    pub large_blob_key: Option<Vec<u8>>,
}

impl PasskeyCredential {
    pub fn cred_id_hex(&self) -> String {
        to_hex(&self.cred_id)
    }

    pub fn user_id_hex(&self) -> String {
        to_hex(&self.user_id)
    }

    pub fn is_ssh(&self) -> bool {
        self.rp_id.starts_with("ssh:")
    }

    pub fn cred_protect_label(&self) -> &'static str {
        match self.cred_protect {
            1 => "UV optional",
            2 => "UV optional w/ ID",
            3 => "UV required",
            _ => "unspecified",
        }
    }

    /// Lower-cased haystack used by the search filter.
    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        [
            self.rp_id.as_str(),
            self.rp_name.as_deref().unwrap_or(""),
            self.user_name.as_str(),
            self.user_display_name.as_str(),
        ]
        .iter()
        .any(|s| s.to_lowercase().contains(&q))
    }
}

/// Credential storage usage reported by credential management.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageStats {
    pub existing: u64,
    pub remaining: u64,
}

impl StorageStats {
    pub fn total(&self) -> u64 {
        self.existing + self.remaining
    }

    pub fn usage_ratio(&self) -> f64 {
        if self.total() == 0 {
            0.0
        } else {
            self.existing as f64 / self.total() as f64
        }
    }
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::to_hex(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> PasskeyCredential {
        PasskeyCredential {
            rp_id: "github.com".into(),
            rp_name: Some("GitHub".into()),
            user_id: vec![1, 2],
            user_name: "octocat".into(),
            user_display_name: "The Octocat".into(),
            cred_id: vec![0xde, 0xad],
            algorithm: "ES256".into(),
            cred_protect: 2,
            large_blob_key: None,
        }
    }

    #[test]
    fn search_matches_any_field() {
        let c = cred();
        assert!(c.matches("GIT"));
        assert!(c.matches("octo"));
        assert!(!c.matches("google"));
    }

    #[test]
    fn hex_roundtrip_and_json() {
        assert_eq!(from_hex("dead"), Some(vec![0xde, 0xad]));
        assert_eq!(from_hex("abc"), None);
        let json = serde_json::to_string(&cred()).unwrap();
        assert!(json.contains("\"cred_id\":\"dead\""));
        let back: PasskeyCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cred_id, vec![0xde, 0xad]);
    }

    #[test]
    fn storage_ratio() {
        let s = StorageStats {
            existing: 5,
            remaining: 15,
        };
        assert_eq!(s.total(), 20);
        assert!((s.usage_ratio() - 0.25).abs() < f64::EPSILON);
    }
}
