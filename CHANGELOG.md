# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-06

First stable release.

### Added

- Native libfido2 backend: enumeration, authenticatorGetInfo, PIN management,
  credential management, fingerprints, large blobs, authenticator config,
  factory reset and an end-to-end self-test.
- Terminal interface with nine pages: overview, passkeys, PIN and security,
  fingerprints, large blobs, SSH keys, disk unlock, security audit and device
  info. Includes hot-plug detection, an activity log and four color themes.
- Passkey search, details, renaming, deletion and JSON export of metadata.
- Guided factory reset (typed confirmation, re-plug, touch).
- SSH key generation and restore through `ssh-keygen`.
- LUKS2 enrollment, test unlock and FIDO2 slot removal through
  `systemd-cryptenroll` and `cryptsetup`, plus a practice volume.
- Security audit with a score and JSON/CSV export.
- `--list` mode for diagnosing detection and permission problems.
- `install.sh` for Fedora/RHEL, Debian/Ubuntu, Arch and openSUSE.
- CI (format, clippy, tests on x86_64 and aarch64, minimum Rust version),
  Semgrep and RustSec scanning, Dependabot, git hooks and release builds.

### Fixed

- Keys were reported as U2F-only when a terminal signal interrupted libfido2.
- Pico-FIDO keys that miss the first message on a new channel are retried.
- The program exited after returning from an external command.

[1.0.0]: https://github.com/diaz3618/fido2-tui/releases/tag/v1.0.0
