#!/usr/bin/env bash
# fido2-tui installer
#
# Installs build/runtime dependencies, verifies that FIDO2 security keys are
# accessible to the current user, builds the release binary and installs it.
#
#   ./install.sh                 # install to ~/.local/bin
#   ./install.sh --system        # install to /usr/local/bin
#   ./install.sh --deps-only     # only install dependencies
#   ./install.sh --no-optional   # skip optional tools (cryptsetup, ssh, ...)
#   ./install.sh --uninstall     # remove the installed binary
#
set -euo pipefail

BIN_NAME="fido2-tui"
MIN_RUST="1.88.0"   # edition 2024 + ratatui 0.30
PREFIX="${HOME}/.local"
DEPS_ONLY=0
OPTIONAL=1
UNINSTALL=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
    case "$arg" in
        --system) PREFIX="/usr/local" ;;
        --prefix=*) PREFIX="${arg#--prefix=}" ;;
        --deps-only) DEPS_ONLY=1 ;;
        --no-optional) OPTIONAL=0 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [ -t 1 ]; then
    C_B=$'\e[1m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_C=$'\e[36m'; C_0=$'\e[0m'
else
    C_B=""; C_G=""; C_Y=""; C_R=""; C_C=""; C_0=""
fi
step() { printf '%s==>%s %s%s%s\n' "$C_C" "$C_0" "$C_B" "$*" "$C_0"; }
ok()   { printf '  %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
die()  { printf '%serror:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && SUDO="sudo"
fi
need_root() {
    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
        die "root privileges are required for: $* (install sudo or run as root)"
    fi
}

install_target() { echo "${PREFIX}/bin/${BIN_NAME}"; }
as_prefix_owner() {
    # Write into PREFIX with sudo only when we cannot write there ourselves.
    local dir="${PREFIX}/bin"
    if mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then "$@"; else need_root "writing to $dir"; $SUDO "$@"; fi
}

if [ "$UNINSTALL" -eq 1 ]; then
    step "Removing $(install_target)"
    as_prefix_owner rm -f "$(install_target)"
    ok "Uninstalled"
    exit 0
fi

# Distro
. /etc/os-release 2>/dev/null || true
ID_ALL="${ID:-unknown} ${ID_LIKE:-}"
PM=""
case "$ID_ALL" in
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*) PM="dnf" ;;
    *debian*|*ubuntu*) PM="apt" ;;
    *arch*) PM="pacman" ;;
    *suse*) PM="zypper" ;;
esac
step "Detected ${PRETTY_NAME:-unknown OS} (package manager: ${PM:-none})"

REQUIRED=()
OPTIONAL_PKGS=()
DISTRO_RUST=()
case "$PM" in
    dnf)
        REQUIRED=(gcc pkgconf-pkg-config libfido2 libfido2-devel)
        DISTRO_RUST=(rust cargo)
        OPTIONAL_PKGS=(cryptsetup systemd-udev openssh-clients fido2-tools) ;;
    apt)
        REQUIRED=(build-essential pkg-config libfido2-1 libfido2-dev curl)
        DISTRO_RUST=()   # Debian/Ubuntu rustc is usually too old -> rustup
        OPTIONAL_PKGS=(cryptsetup udev openssh-client fido2-tools) ;;
    pacman)
        REQUIRED=(base-devel pkgconf libfido2)
        DISTRO_RUST=(rust)
        OPTIONAL_PKGS=(cryptsetup openssh) ;;
    zypper)
        REQUIRED=(gcc pkgconf libfido2-1 libfido2-devel curl)
        DISTRO_RUST=(rust cargo)
        OPTIONAL_PKGS=(cryptsetup openssh-clients fido2-tools) ;;
esac

pkg_install() {
    [ "$#" -eq 0 ] && return 0
    need_root "installing packages"
    case "$PM" in
        dnf)    $SUDO dnf install -y "$@" ;;
        apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$@" ;;
        pacman) $SUDO pacman -S --needed --noconfirm "$@" ;;
        zypper) $SUDO zypper --non-interactive install "$@" ;;
    esac
}

if [ -n "$PM" ]; then
    step "Installing required packages: ${REQUIRED[*]}"
    pkg_install "${REQUIRED[@]}"
    ok "Required packages installed"
    if [ "$OPTIONAL" -eq 1 ] && [ "${#OPTIONAL_PKGS[@]}" -gt 0 ]; then
        step "Installing optional tools (drive encryption, SSH): ${OPTIONAL_PKGS[*]}"
        pkg_install "${OPTIONAL_PKGS[@]}" || warn "Some optional packages failed to install; related tabs will be limited"
    fi
else
    warn "Unsupported distribution: install libfido2 (+ development headers), a C toolchain and pkg-config manually."
fi

# Rust
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
rust_ok() {
    command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1 || return 1
    local v; v="$(rustc --version | awk '{print $2}')"
    version_ge "$v" "$MIN_RUST"
}

[ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env"
step "Checking Rust toolchain (need >= ${MIN_RUST})"
if ! rust_ok && [ "${#DISTRO_RUST[@]}" -gt 0 ]; then
    pkg_install "${DISTRO_RUST[@]}" || true
fi
if ! rust_ok; then
    warn "Distribution Rust missing or too old; installing via rustup (user-local)"
    command -v curl >/dev/null 2>&1 || die "curl is required to install rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    . "${HOME}/.cargo/env"
fi
rust_ok || die "Rust >= ${MIN_RUST} is still not available"
ok "$(rustc --version)"

# -------------------------------------------------------- device access ---
step "Checking FIDO2 device access"
found=0
for dev in /sys/class/hidraw/hidraw*; do
    [ -e "$dev" ] || continue
    node="/dev/$(basename "$dev")"
    # FIDO HID usage page 0xF1D0 appears as bytes 06 d0 f1 in the report descriptor
    if od -An -tx1 -v "$dev/device/report_descriptor" 2>/dev/null | tr -d ' \n' | grep -q '06d0f1'; then
        found=1
        name="$(grep -m1 HID_NAME "$dev/device/uevent" 2>/dev/null | cut -d= -f2)"
        if [ -r "$node" ] && [ -w "$node" ]; then
            ok "$node  ${name:-FIDO device}  (accessible)"
        else
            warn "$node  ${name:-FIDO device}  is NOT accessible by $(id -un)"
            udev_missing=1
        fi
    fi
done
[ "$found" -eq 0 ] && warn "No FIDO2 key plugged in right now (that's fine - the TUI detects hot-plugged keys)."

has_uaccess_rule() {
    grep -qsE 'ID_FIDO_TOKEN|ID_SECURITY_TOKEN|f1d0|FIDO' \
        /usr/lib/udev/rules.d/*.rules /lib/udev/rules.d/*.rules /etc/udev/rules.d/*.rules 2>/dev/null
}
if [ "${udev_missing:-0}" -eq 1 ] || ! has_uaccess_rule; then
    step "Installing udev rule granting the logged-in user access to FIDO keys"
    need_root "installing udev rules"
    $SUDO tee /etc/udev/rules.d/70-fido2-tui.rules >/dev/null <<'EOF'
# fido2-tui: give the active seat user access to FIDO2/U2F HID authenticators
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ENV{ID_FIDO_TOKEN}=="1", TAG+="uaccess"
EOF
    $SUDO udevadm control --reload-rules && $SUDO udevadm trigger --subsystem-match=hidraw
    ok "udev rules reloaded (re-plug your key if it is still not accessible)"
else
    ok "udev rules for FIDO tokens present"
fi

[ "$DEPS_ONLY" -eq 1 ] && { ok "Dependencies installed"; exit 0; }

# Build
step "Building ${BIN_NAME} (release)"
( cd "$SRC_DIR" && cargo build --release --locked )
ok "Built ${SRC_DIR}/target/release/${BIN_NAME}"

step "Installing to $(install_target)"
as_prefix_owner install -Dm755 "${SRC_DIR}/target/release/${BIN_NAME}" "$(install_target)"
ok "Installed"

case ":$PATH:" in
    *":${PREFIX}/bin:"*) ;;
    *) warn "${PREFIX}/bin is not on your PATH - add: export PATH=\"${PREFIX}/bin:\$PATH\"" ;;
esac
printf '\n%sDone.%s Run %s%s%s to start.\n' "$C_G" "$C_0" "$C_B" "$BIN_NAME" "$C_0"
