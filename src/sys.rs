//! System integration: LUKS volumes, privilege escalation, udev diagnostics, SSH keys.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::model::*;

/// An interactive command run with the TUI suspended, so tools like `sudo`,
/// `systemd-cryptenroll` and `ssh-keygen` can prompt on the real terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCommand {
    pub title: String,
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
}

impl ExternalCommand {
    pub fn new(title: impl Into<String>, program: &str, args: &[&str]) -> Self {
        Self {
            title: title.into(),
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: None,
        }
    }

    /// `sudo <program> args...` unless we already are root.
    pub fn root(title: impl Into<String>, program: &str, args: &[&str]) -> Self {
        if is_root() {
            Self::new(title, program, args)
        } else {
            let mut all = vec![program];
            all.extend_from_slice(args);
            Self::new(title, "sudo", &all)
        }
    }

    pub fn shell(title: impl Into<String>, script: &str) -> Self {
        Self::new(title, "sh", &["-c", script])
    }

    pub fn display(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.args {
            if a.contains(' ') || a.is_empty() {
                s.push_str(&format!(" '{a}'"));
            } else {
                s.push(' ');
                s.push_str(a);
            }
        }
        s
    }
}

pub fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn data_dir() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local/share"))
        .join("fido2-tui")
}

pub fn which(prog: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
        .map(|d| Path::new(d).join(prog))
        .find(|p| p.is_file())
}

/// Run a read-only command, retrying through passwordless `sudo -n` when the
/// direct call fails (e.g. reading LUKS headers of system disks).
pub fn run_maybe_root(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let direct = Command::new(program).args(args).output();
    match &direct {
        Ok(o) if o.status.success() => return direct,
        _ if is_root() => return direct,
        _ => {}
    }
    let sudo = Command::new("sudo")
        .arg("-n")
        .arg(program)
        .args(args)
        .output();
    match sudo {
        Ok(o) if o.status.success() => Ok(o),
        _ => direct,
    }
}

/// Is there a cached sudo credential (or are we root)?
pub fn sudo_ready() -> bool {
    is_root()
        || Command::new("sudo")
            .args(["-n", "true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

pub fn practice_image() -> PathBuf {
    data_dir().join("practice-luks.img")
}

#[derive(Debug, Clone, Default)]
pub struct LuksScan {
    pub devices: Vec<LuksDevice>,
    /// Some headers could not be read without root.
    pub needs_root: bool,
    pub initramfs_fido2: Option<bool>,
    pub errors: Vec<String>,
}

pub fn scan_luks() -> LuksScan {
    let mut scan = LuksScan::default();
    let crypttab: Vec<CrypttabEntry> = std::fs::read_to_string("/etc/crypttab")
        .unwrap_or_default()
        .lines()
        .filter_map(CrypttabEntry::parse_line)
        .collect();

    match Command::new("lsblk")
        .args([
            "-J",
            "-p",
            "-o",
            "NAME,PATH,FSTYPE,FSVER,UUID,LABEL,SIZE,MOUNTPOINTS,TYPE",
        ])
        .output()
    {
        Ok(o) if o.status.success() => {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&o.stdout) {
                for node in v["blockdevices"].as_array().into_iter().flatten() {
                    collect_luks(node, &mut scan.devices);
                }
            }
        }
        Ok(o) => scan.errors.push(format!(
            "lsblk failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => scan.errors.push(format!("lsblk unavailable: {e}")),
    }

    let practice = practice_image();
    if practice.exists() {
        scan.devices.push(LuksDevice {
            path: practice.display().to_string(),
            label: Some("practice volume".into()),
            size: std::fs::metadata(&practice)
                .map(|m| format!("{}M", m.len() / (1024 * 1024)))
                .unwrap_or_default(),
            is_practice: true,
            ..Default::default()
        });
    }

    for dev in &mut scan.devices {
        dev.crypttab = crypttab
            .iter()
            .find(|c| c.refers_to(&dev.uuid, &dev.path))
            .cloned();
        let luks1 = dev.header.as_ref().is_some_and(|h| h.version == 1);
        if luks1 {
            continue;
        }
        match run_maybe_root(
            "cryptsetup",
            &["luksDump", "--dump-json-metadata", &dev.path],
        ) {
            Ok(o) if o.status.success() => {
                match parse_luks_json(&String::from_utf8_lossy(&o.stdout)) {
                    Ok(h) => dev.header = Some(h),
                    Err(e) => scan.errors.push(format!("{}: {e}", dev.path)),
                }
            }
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                if err.contains("ermission")
                    || err.contains("root")
                    || err.contains("Cannot use device")
                {
                    scan.needs_root = true;
                } else if !err.trim().is_empty() {
                    scan.errors.push(format!("{}: {}", dev.path, err.trim()));
                } else {
                    scan.needs_root = true;
                }
                dev.header = None;
            }
            Err(e) => {
                scan.errors.push(format!("cryptsetup unavailable: {e}"));
                break;
            }
        }
    }
    scan.initramfs_fido2 = initramfs_fido2_support();
    scan
}

fn collect_luks(node: &serde_json::Value, out: &mut Vec<LuksDevice>) {
    let s = |k: &str| node[k].as_str().map(String::from);
    if s("fstype").as_deref() == Some("crypto_LUKS") {
        let mut dev = LuksDevice {
            path: s("path").unwrap_or_default(),
            uuid: s("uuid").unwrap_or_default(),
            label: s("label"),
            size: s("size").unwrap_or_default(),
            ..Default::default()
        };
        if s("fsver").as_deref() == Some("1") {
            dev.header = Some(LuksHeader {
                version: 1,
                ..Default::default()
            });
        }
        for child in node["children"].as_array().into_iter().flatten() {
            if child["type"].as_str() == Some("crypt") {
                dev.mapped_name = child["name"]
                    .as_str()
                    .map(|n| n.trim_start_matches("/dev/mapper/").to_string());
            }
            gather_mounts(child, &mut dev.mountpoints);
        }
        dev.is_system_volume = dev.mountpoints.iter().any(|m| {
            matches!(
                m.as_str(),
                "/" | "/home" | "/usr" | "/var" | "/boot" | "[SWAP]"
            )
        });
        out.push(dev);
    }
    for child in node["children"].as_array().into_iter().flatten() {
        collect_luks(child, out);
    }
}

fn gather_mounts(node: &serde_json::Value, out: &mut Vec<String>) {
    for m in node["mountpoints"].as_array().into_iter().flatten() {
        if let Some(m) = m.as_str() {
            out.push(m.to_string());
        }
    }
    for child in node["children"].as_array().into_iter().flatten() {
        gather_mounts(child, out);
    }
}

/// Can the initramfs unlock with a FIDO2 token at boot?
pub fn initramfs_fido2_support() -> Option<bool> {
    if Path::new("/usr/lib/dracut/modules.d").exists() {
        let found = std::fs::read_dir("/usr/lib/dracut/modules.d")
            .map(|rd| {
                rd.flatten()
                    .any(|e| e.file_name().to_string_lossy().contains("fido2"))
            })
            .unwrap_or(false);
        return Some(found);
    }
    if Path::new("/etc/mkinitcpio.conf").exists() {
        let conf = std::fs::read_to_string("/etc/mkinitcpio.conf").unwrap_or_default();
        return Some(
            conf.lines()
                .any(|l| l.trim_start().starts_with("HOOKS") && l.contains("sd-encrypt")),
        );
    }
    None
}

/// FIDO HID nodes the current user cannot open (wrong udev permissions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InaccessibleKey {
    pub node: String,
    pub name: String,
}

pub fn inaccessible_fido_nodes() -> Vec<InaccessibleKey> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/class/hidraw") else {
        return out;
    };
    for e in rd.flatten() {
        let sys = e.path();
        let Ok(desc) = std::fs::read(sys.join("device/report_descriptor")) else {
            continue;
        };
        // Usage Page (FIDO Alliance) = 0x06 0xD0 0xF1
        if !desc.windows(3).any(|w| w == [0x06, 0xd0, 0xf1]) {
            continue;
        }
        let node = format!("/dev/{}", e.file_name().to_string_lossy());
        if std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&node)
            .is_err()
        {
            let name = std::fs::read_to_string(sys.join("device/uevent"))
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("HID_NAME=").map(String::from))
                .unwrap_or_else(|| "FIDO device".into());
            out.push(InaccessibleKey { node, name });
        }
    }
    out
}

/// Cheap fingerprint of the hidraw device set, used for hot-plug detection.
pub fn hidraw_signature() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/sys/class/hidraw")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyFile {
    pub path: PathBuf,
    pub key_type: String,
    pub comment: String,
    pub resident_handle: bool,
}

/// Security-key backed public keys in ~/.ssh (`sk-*` key types).
pub fn ssh_sk_keys() -> Vec<SshKeyFile> {
    let dir = home().join(".ssh");
    let mut out: Vec<SshKeyFile> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "pub"))
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path()).ok()?;
            let mut parts = text.split_whitespace();
            let key_type = parts.next()?.to_string();
            if !key_type.starts_with("sk-") {
                return None;
            }
            let _blob = parts.next();
            let comment = parts.collect::<Vec<_>>().join(" ");
            let name = e.file_name().to_string_lossy().into_owned();
            Some(SshKeyFile {
                path: e.path(),
                key_type,
                comment,
                resident_handle: name.contains("_rk"),
            })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_command_display_quotes() {
        let c = ExternalCommand::new("t", "ssh-keygen", &["-C", "my key", "-N", ""]);
        assert_eq!(c.display(), "ssh-keygen -C 'my key' -N ''");
    }

    #[test]
    fn lsblk_tree_collects_nested_luks() {
        let json = serde_json::json!({
            "blockdevices": [{
                "name": "/dev/nvme0n1", "path": "/dev/nvme0n1", "fstype": null, "type": "disk",
                "mountpoints": [null],
                "children": [{
                    "name": "/dev/nvme0n1p3", "path": "/dev/nvme0n1p3", "fstype": "crypto_LUKS", "fsver": "2",
                    "uuid": "abcd", "size": "100G", "type": "part", "mountpoints": [null],
                    "children": [{
                        "name": "/dev/mapper/luks-abcd", "type": "crypt", "fstype": "btrfs",
                        "mountpoints": ["/", "/home"]
                    }]
                }]
            }]
        });
        let mut out = Vec::new();
        for n in json["blockdevices"].as_array().unwrap() {
            collect_luks(n, &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "/dev/nvme0n1p3");
        assert_eq!(out[0].mapped_name.as_deref(), Some("luks-abcd"));
        assert!(out[0].is_system_volume);
        assert_eq!(out[0].mountpoints, vec!["/", "/home"]);
    }
}
