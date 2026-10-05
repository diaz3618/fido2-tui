//! Locate libfido2 for linking.
//!
//! Prefers pkg-config (libfido2-devel / libfido2-dev). When only the runtime
//! library (`libfido2.so.1`) is installed, a `libfido2.so` symlink is created
//! in OUT_DIR so `-lfido2` still resolves.
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FIDO2_LIB_DIR");

    if let Ok(dir) = std::env::var("FIDO2_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        return;
    }

    if let Ok(out) = Command::new("pkg-config")
        .args(["--libs-only-L", "libfido2"])
        .output()
        && out.status.success()
    {
        for flag in String::from_utf8_lossy(&out.stdout).split_whitespace() {
            if let Some(dir) = flag.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={dir}");
            }
        }
        return;
    }

    let candidates = [
        "/usr/lib64",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/local/lib",
        "/usr/local/lib64",
    ];
    if candidates
        .iter()
        .any(|d| Path::new(d).join("libfido2.so").exists())
    {
        return;
    }
    for dir in candidates {
        let runtime = Path::new(dir).join("libfido2.so.1");
        if runtime.exists() {
            let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
            let link = out_dir.join("libfido2.so");
            let _ = std::fs::remove_file(&link);
            #[cfg(unix)]
            std::os::unix::fs::symlink(&runtime, &link).expect("symlink libfido2.so");
            println!("cargo:rustc-link-search=native={}", out_dir.display());
            return;
        }
    }
    println!(
        "cargo:warning=libfido2 not found; install libfido2 (e.g. `sudo dnf install libfido2-devel`) or run ./install.sh"
    );
}
