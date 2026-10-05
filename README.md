# fido2-tui

Terminal UI for managing FIDO2 security keys on Linux: passkeys, PIN and
security policy, fingerprints, large blobs, SSH keys and LUKS2 disk unlock.

The app talks to keys through the system libfido2 library, notices keys being
plugged in or removed, and runs device operations on a worker thread so the
interface stays responsive while a key waits for a touch.

Developed against a Waveshare RP2350-USB board running the
[Pico-FIDO](https://github.com/polhenarejos/pico-fido) firmware. Any CTAP2
authenticator should work: YubiKey, Nitrokey, SoloKeys, Token2, Feitian,
Google Titan and others.

## Installation

```bash
./install.sh              # dependencies, build, install to ~/.local/bin
./install.sh --system     # install to /usr/local/bin
./install.sh --deps-only  # dependencies only
./install.sh --uninstall
```

The script supports Fedora/RHEL, Debian/Ubuntu, Arch and openSUSE. It installs
libfido2 with its headers, a C toolchain and Rust (the distribution package, or
rustup when that is too old), plus OpenSSH and cryptsetup for the SSH and disk
pages. It also checks that the current user can open the key and adds a
`uaccess` udev rule when needed.

To build by hand: `cargo build --release`. libfido2 1.13 or newer is required;
set `FIDO2_LIB_DIR` if it is installed in a non-standard location.

## Usage

```bash
fido2-tui                 # start the interface
fido2-tui --list          # print detected keys and exit
fido2-tui --theme mocha   # nord (default), mocha, gruvbox, terminal
```

Press `?` inside the app for the full list of shortcuts. The global ones are
`1`-`9` or `Tab` to change page, `[` and `]` to switch between keys, `r` to
refresh, `i` to identify a key, `p` for the PIN, `L` to lock, `T` to change
theme and `q` to quit.

## Pages

1. **Overview**: model (from the AAGUID), firmware, USB IDs, PIN state and
   retries, storage, security grade, capabilities and an activity log. Also
   runs a self-test (registers a temporary credential and verifies a signed
   challenge; nothing is stored) and identify (touch the key to select it).
2. **Passkeys**: discoverable credentials grouped by site, with search,
   details, renaming of user and display names, deletion and JSON export of
   the metadata.
3. **PIN & Security**: set, change and verify the PIN, raise the minimum PIN
   length, choose which relying parties may read it, toggle Always-UV, force a
   PIN change, lock the session and run a guided factory reset.
4. **Fingerprints**: enrollment with feedback for each sample, renaming and
   deletion on biometric keys.
5. **Large Blobs**: per-passkey data storage. View as text and hex, write from
   text or a file, save to a file, delete.
6. **SSH Keys**: generate `ecdsa-sk` and `ed25519-sk` keys (resident,
   verify-required, custom application string), restore resident keys with
   `ssh-keygen -K` and show public keys.
7. **Disk Unlock**: LUKS2 volumes with their key slots and tokens. Enroll the
   key with `systemd-cryptenroll`, test unlocking with the key or a passphrase,
   remove FIDO2 slots and get crypttab/initramfs instructions. A 32 MB practice
   volume (a regular file, no root needed) can be created to try this safely.
8. **Security Audit**: scored checklist with suggested fixes, exportable as
   JSON or CSV.
9. **Device Info**: the full authenticatorGetInfo response, including every
   option with a short explanation.

## Safety notes

- There is no default PIN. The PIN is requested once per session, kept only in
  memory, wiped when dropped, and forgotten on `L`, after a wrong attempt, or
  when the key is unplugged. Remaining retries are shown before entry.
- Operations that send a PIN are never retried automatically, so a lost reply
  cannot cost extra attempts.
- Destructive actions ask for confirmation. Factory reset requires typing
  `RESET`.
- Disk enrollment is refused unless a passphrase slot exists, and removal uses
  `--wipe-slot=fido2`, which leaves passphrase slots alone. A header backup is
  offered before enrolling.
- `sudo`, `systemd-cryptenroll`, `ssh-keygen` and `cryptsetup` run on the real
  terminal while the interface is suspended, and the exact command line is
  printed first.

## Troubleshooting

- Key not detected: run `fido2-tui --list`. If a key is reported as not
  accessible, run `./install.sh` to add the udev rule and re-plug the key.
- Passkeys page asks for a PIN: CTAP requires a PIN for credential management.
  Keys without one get a prompt to set it.
- [Pico-FIDO](https://github.com/polhenarejos/pico-fido) reports Always-UV as enabled whenever a PIN is set, whatever the
  stored setting is; the app points this out after toggling. Its user-presence
  button can be disabled in the firmware configuration, in which case touch
  prompts finish without a press. Some firmware versions occasionally miss the
  first message on a new channel, so reads that do not involve the PIN are
  retried.

## Development

```
src/fido/     libfido2 bindings and the FidoBackend implementation
src/app/      application state, background jobs, actions, key handling
src/ui/       rendering: layout, pages, dialogs, themes
src/model/    device, credential, LUKS and audit types
src/sys.rs    LUKS scanning, udev checks, SSH key files
tests/        application flows against an in-memory authenticator
```

```bash
cargo test
cargo clippy --all-targets
```

The repository ships git hooks: `pre-commit` (rustfmt, clippy, ShellCheck,
and Semgrep secret scanning when installed), `commit-msg` (subject line rules)
and `pre-push` (tests, and release tags must match `Cargo.toml` and
`CHANGELOG.md`). Enable them once per clone:

```bash
git config core.hooksPath .githooks
```

GitHub Actions run formatting, clippy, tests on x86_64 and aarch64, a minimum
Rust version check, ShellCheck, actionlint, Semgrep and a RustSec audit.
Dependabot keeps crates and pinned actions up to date.

The interface takes ideas from Yubico Authenticator, Token2 fido2-manage,
keyroost, lazygit and k9s.

## Acknowledgements

- [Pico-FIDO](https://github.com/polhenarejos/pico-fido) by Pol Henarejos:
  the open-source FIDO2 firmware used on the development and test key.
- [libfido2](https://github.com/Yubico/libfido2) by Yubico: the library this
  application uses to talk to authenticators.

## License

GPL-3.0. See [LICENSE](LICENSE).
