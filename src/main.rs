use clap::Parser;
use color_eyre::Result;

use fido2_tui::fido::FidoBackend;
use fido2_tui::fido::native::Libfido2;
use fido2_tui::sys;

#[derive(Parser, Debug)]
#[command(name = "fido2-tui", version, about = "Manage FIDO2 security keys")]
struct Args {}

fn main() -> Result<()> {
    color_eyre::install()?;
    let _args = Args::parse();
    let backend = Libfido2::new();
    list_devices(&backend)
}

fn list_devices(backend: &dyn FidoBackend) -> Result<()> {
    let list = backend
        .enumerate()
        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
    if list.is_empty() {
        println!("No FIDO security keys found.");
    }
    for s in &list {
        match backend.device_info(s) {
            Ok(d) => {
                println!(
                    "{}  {}  ({:04x}:{:04x})",
                    d.path,
                    d.display_name(),
                    d.vendor_id,
                    d.product_id
                );
                println!(
                    "    firmware {}  ·  {}",
                    d.fw_version_string().unwrap_or_else(|| "?".into()),
                    d.versions.join(" ")
                );
            }
            Err(e) => println!("{}  {}  - error: {e}", s.path, s.product),
        }
    }
    for k in sys::inaccessible_fido_nodes() {
        println!(
            "{}  {}  - NOT ACCESSIBLE (permission denied; run ./install.sh to add a udev rule)",
            k.node, k.name
        );
    }
    Ok(())
}
