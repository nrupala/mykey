# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 1: Vault v2
- Envelope encryption (Vault v2): random 256-bit vault key, AES-256-GCM,
  header stores format version + KDF parameters + wrapped-key slots.
  Master-password and recovery slots wrap the same vault key; rotating
  an unlock method re-wraps, never re-encrypts the vault.
- Migration: v1 vaults (original and Phase 0 verifier variants) open
  normally and migrate to v2 on first save; the pre-migration file is
  kept as the rolling backup.
- Entries are records (service, username, password, url, notes,
  totp_secret, tags, created/updated, favourite) with full CRUD + search
  in the engine and CLI; the GUI gains manual add of an existing
  password, edit, delete and a searchable vault list.
- Real BIP-39 recovery: full 2048-word list with checksum, 128-bit
  minimum entropy, the phrase unwraps the vault key and actually
  unlocks; rotation and master-password change supported; a verify-back
  step at setup (CLI and GUI).
- Importers with preview/dedupe/conflict policies: Chromium browsers
  (Chrome/Edge/Brave/Opera/Vivaldi/Arc), Firefox, Safari/iCloud,
  Google Password Manager, Bitwarden (CSV + JSON), 1Password CSV,
  LastPass, Dashlane, KeePass/KeePassXC (CSV + XML), NordPass,
  Proton Pass, and a generic CSV mapper — each covered by fixture tests.
- TOTP code generation (RFC 6238) for entries with a TOTP secret.
- Brand neutrality: all brand strings live in `brand.py`; a test proves
  a vault created under one brand configuration opens under another.
- Licence headers aligned to the Apache 2.0 + Proprietary split
  (see LICENSING.md, including the patent section).

### Fixed — Phase 0 safety hardening
- **Vault wipe on wrong-password save (critical):** saving with a wrong
  master password silently reset the vault to a single entry, destroying
  every stored credential. Root cause: `_read_physical_vault()` returned
  the string `"Access Denied"` on failure and `save_password()` treated a
  string as corruption and reset it to `{}`. Errors are now typed
  exceptions (`WrongPassword`, `VaultCorrupt`, `VaultMissing`) and a save
  **refuses** when an existing vault cannot be decrypted. A regression
  test reproduces the original audit scenario and fails on the old code.
- `_derive_key` no longer swallows exceptions and returns `None`; it raises.
- Vault writes are atomic (temp file + fsync + rename) with `0600`
  permissions, and the previous vault is kept as a rolling backup
  (`vault.mykey.bak`, `0600`).
- A verifier (HMAC-SHA256 under the derived key) is stored with new
  vaults, so a wrong password is distinguishable from a corrupted vault.
  Legacy v1 vaults without a verifier still load.

### Added
- Minimums enforced: master passwords must be at least 12 characters;
  generated passwords at least 16 characters (CLI and engine).
- `pyproject.toml` packaging, pytest suite (`tests/`) covering round-trip,
  wrong password, corruption, legacy v1 vaults, PBKDF2, permissions and
  the wrong-password-save regression.
- CLI returns proper exit codes and prints typed errors to stderr
  instead of embedding them in password output.

### Security
- `vault.json` (a committed test vault) removed from the tree and added
  to `.gitignore`, along with `*.mykey`, backups and export files.
  Note: the file remains in git history; any credential ever stored in
  it should be treated as compromised and rotated.
- `requirements.txt` pinned to compatible version ranges.

### Notes
- No vault-format change in this PR: the v1 envelope is unchanged apart
  from the added `verifier` field, which older readers ignore.
