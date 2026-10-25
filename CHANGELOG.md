# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] \u2014 2026-10-24

### Changed \u2014 licensing (supersedes v2.2.0 on licence terms)
- Split licensing is now in force in the repository structure: pointer
  `LICENSE`, `LICENSES/Apache-2.0.txt` (interface layer) and
  `LICENSES/Proprietary.txt` (core, \u00a9 2351485 ALBERTA INC., all rights
  reserved, no patent licence granted). `LICENSING.md` is the
  controlling map. The MIT licence file is retired and the package
  metadata no longer declares MIT.
- Copies of v2.2.0 and earlier distributed under MIT remain governed
  by MIT for those copies. This release and future distributions are
  governed by the split licence.
- Source release: no binaries are attached. The v2.2.0 binaries remain
  available under their original terms; rebuilt binaries ship with the
  next built release.

## [Unreleased]

### Fixed — Stripe issuer idempotency + dispute handling (release-gate F-MK-1/F-MK-2)
- `tools/stripe_issuer.py` now dedupes by checkout session id
  (F-MK-1): before minting, the registry is checked for a
  record already carrying the order's session; if one exists
  the order is marked issued with the existing licence id and
  nothing is minted or emailed again. Together with the
  write-once order recorder in the usemykey-site Worker, one
  payment can no longer mint two licences via Stripe's
  at-least-once delivery or an issuer crash mid-run.
- The issuer now applies recorded Stripe disputes (F-MK-2):
  `charge.dispute.created` flags the licence in the registry,
  `charge.dispute.closed` lost revokes it with reason
  "stripe chargeback (dispute lost)", and closed won clears
  the flag. New tests: `tests/test_stripe_issuer.py`.

### Fixed — `_prompt_secret` is Windows-gated (packaging follow-up)
- The piped-stdin secret path introduced with the desktop
  packaging wave is now taken **only on Windows**, the platform
  with the getpass redirected-stdin hang. The first version took
  it on every platform when stdin was not a terminal, bypassing
  the `getpass` monkeypatch the test suite relies on and failing
  `test_cli_rotation_flow` under pytest (OSError on captured
  stdin). Non-Windows behaviour is identical to the original
  getpass flow; Windows behaviour is unchanged from the shipped
  v2.2.0 binaries (interactive → getpass, piped → stdin line).
  Full suite after the fix: 241 passed, 1 skipped.

### Added — desktop downloads (packaging wave, 2026-10-13)
- Ready-made desktop builds published on the Releases page as
  **v2.2.0**: Windows app + CLI `.exe` (built and smoke-tested on a
  real Windows 11 machine), Linux bundle (app + CLI +
  `mykey.desktop` launcher + docs). Builds are **unsigned** for
  now — the release notes say so in plain words and publish
  SHA-256 checksums.
- `packaging/build_desktop.py`: one PyInstaller build script for
  Windows/Linux/macOS (runs on the target platform; macOS yields
  `MyKey.app` — script-only until a signing certificate exists,
  no `.dmg` is published). Build notes and the smoke-test
  checklist live in `packaging/README.md`.

### Fixed — Windows CLI in pipes and legacy consoles
- Secret prompts (master password, recovery phrase, entry
  password) no longer go through `getpass` when stdin is piped:
  on Windows (CPython 3.14) getpass's redirected-stdin path
  leaves the interpreter hanging at exit (`_enter_buffered_busy`
  on `<stdin>`) — reproduced with `getpass` alone during the
  packaging smoke test. New `_prompt_secret` helper in the CLI:
  interactive terminal → `getpass` as before; piped stdin → one
  line read from stdin. This is the scripted/agent (MACHINE)
  path, so piped use on Windows now exits cleanly.
- CLI output is forced to UTF-8 at startup: Windows legacy code
  pages cannot encode the CLI's status glyphs (🔑/✅/❌) and
  crashed commands mid-print (e.g. `agent-get` on a cp1252 pipe).
### Added — Licensing: free tier + signed licence keys
- **Free tier, counted fairly.** The free version holds up to 50
  passwords per vault and 4 connections (enrolled devices +
  authorized agents + paired browsers, one shared pool per vault).
  Only the counts are limited — encryption, sync, two-factor
  backups, pairing, rotation and export are never gated.
- **Signed licence keys.** A one-time licence (`MKLIC1.` token,
  Ed25519-signed by the MyKey Licence Authority GPG key) verifies
  fully offline and unlocks unlimited passwords + the connection
  pool stated in the key (20 standard). Stored inside the vault's
  encrypted settings (travels with the vault) and in a device
  slot (new vaults on the device start licensed). Each licence
  carries a recovery passcode; lost keys are re-issued by email
  after an identity check (see `LICENCE.md`).
- **Grandfather rule.** A vault already over a limit opens, reads,
  edits, syncs and exports fully — only adding pauses until a
  licence is entered or room is made. Imports fill to the limit
  and report exactly how many were held back; agent inserts over
  the cap stay queued with a licence-denied audit record.
- CLI `licence` / `licence-activate`; GUI About menu gains
  "Enter licence key…", "Buy a licence" and "Tip jar". Issuer
  tooling (admin only): `tools/issue_licence.py`.


### Fixed — expiry validation for agents and pairings (issue #12)
- `agent-enroll --expires-days 0` no longer silently creates a
  never-expiring token: 0 came through a falsy check as "unset".
  Expiry must now be a whole number of days ≥ 1, at both the API
  (`enroll_agent`) and CLI level; 0 and negatives are refused with
  a plain error ("expiry must be at least 1 day — omit the flag
  for no expiry"). Omitting the flag remains the only way to
  create a non-expiring agent, and the enroll output now echoes
  the effective grant (agent id, scopes, "Expires: <date>" or
  "Expires: never").
- Same hardening at the sibling parse site, `enroll_pairing`:
  its `is not None` check already failed closed on 0 (a
  silently-dead pairing), and it now refuses 0/negatives with the
  same plain error; `pair-enroll` output echoes the expiry too.
  Regression suite: `tests/test_expires_days.py`.


### Changed — clipboard self-clear rule (owner directive, 2026-10-13)
- Copied passwords now clear through one guarded path
  (`clipboard_guard.py`): 60 seconds by default, user-settable
  between 60 and 300 seconds (Settings → Clipboard clear delay,
  persisted in `~/.mykey/preferences.json`, clamped at a single
  validation point). The clipboard is cleared only if it still
  holds exactly what MyKey put there, closing the window clears a
  pending copied secret immediately, and a re-copy restarts the
  timer. The CLI and MCP surfaces never touch the clipboard.
### Added — Passkey wave: WebAuthn passkey storage (desktop role)
- **Passkey entries in Vault v3.** A new entry kind `"passkey"`
  stores a WebAuthn record (rp_id, user info, credential id,
  public key, credential **private key**, sign_count) in its own
  blob under a new per-entry key class (DEK_passkey), sealed by a
  hash in the core's new `passkey_hashes` map. `_entry_hash` is
  unchanged, so existing vaults verify byte-for-byte. Format
  contract and limits: `PASSKEYS.md`.
- **Agents can never touch passkeys.** DEK_passkey is never in a
  bundle; passkey entries are excluded from bundle targets and
  service maps. Agent passkey use is a later, separately gated
  design (not built).
- **Desktop is read + delete in v1:** CLI `passkeys` lists them,
  `get` prints a public summary only, the GUI marks them
  "use the phone app". Creation/use live in the mobile client
  (authenticator + Android Credential Manager provider).
- CSV export skips passkeys; CSV import never overwrites one.
  Passkeys count toward the entry total like logins (the
  free-tier cap seam is noted at `add_passkey`).

### Added — Blob wave: two-factor backup packages + key-value pairing
- **MKBAK v2 — two-factor recovery.** New backup packages wrap
  the recovery slot twice: sealed to the recovery-phrase key as
  before, then encrypted under a key derived from a **backup
  code** (8 words, 88 bits, Argon2id-hardened) that is generated
  at export, shown once, and never stored anywhere. Opening a v2
  package outside the app needs the phrase AND the code; either
  alone fails, a wrong code fails closed. Legacy v1 packages
  still import with the phrase alone and are labelled LEGACY at
  inspect and import time. CLI `backup-export` prints the code
  once; `backup-import` prompts for it on the recovery path; the
  GUI shows it in a one-time dialog and offers package import
  from the Sync & Backup menu.
- **Key-value pairing for cloud storage and export targets.** A
  pairing registry inside the encrypted vault (target id →
  type, X25519 public key, scopes `push`/`pull`/`export`,
  expiry, enabled) decides which outside targets receive blobs.
  Targets present a pairing payload (public key + fingerprint);
  a human compares the fingerprint and enrolls it. Backup exports
  seal a content-key copy to every active pairing holding the
  `export` scope — unpaired, disabled, expired or revoked
  targets get no slot. A sync folder can be bound to a pairing
  target (`sync-configure --target`); pushes and pulls then
  require the pairing to be active with the matching scope,
  checked against pins refreshed from the registry at human
  unlock (the device-signer pin pattern). CLI: `pairing-keygen`,
  `pairing-payload`, `pair-enroll`, `pairings`, `pair-revoke`,
  `pair-disable`, `pair-enable`. Design and limits:
  `SYNC_BACKUP.md` §9–§10.
- Repaired `SYNC_BACKUP.md`: the file on main had been truncated
  mid-§3.4 in the Phase 3A push (a literal truncation marker was
  committed as its last line, and no intact copy survived in any
  working tree). The missing sections are rewritten from the
  shipped code and re-verified against it.

### Added — Password age + rotation
- **Every password gets an age clock.** The vault records when
  each password was set — at creation and whenever the password
  itself changes (including generate-and-save). Editing notes,
  tags, URL or other details never moves the clock. A "mark as
  changed today" action (CLI `mark-changed`, GUI button) covers
  passwords rotated on the website itself.
- **Rotation dates, your choice.** The vault default is 180 days
  and is editable (`rotation --set-default-days N`, or
  `--set-default-never`). A per-entry override (`edit
  --rotate-days N`, `0` = never, `--rotate-days-clear` back to the
  default) wins over the vault default.
- **Calm surfacing, no nagging.** Entry views show "Password set
  13 Oct 2026 · change by 11 Apr 2027" / "change date off" /
  "date not recorded"; lists badge due-soon and overdue entries;
  unlock shows a due count; the `rotation` CLI command and the
  GUI's Vault → Password rotation view list what needs attention.
  Due soon means within 14 days. No notifications are sent —
  noted as future work.
- **Private by construction.** The set date and per-entry period
  are stored inside the entry's encrypted secret blob; the vault
  default lives in the encrypted core. Nothing is written to a
  plaintext sidecar, and agent metadata never carries the fields.
  Vaults written before this feature open unchanged: the set date
  falls back to the entry's creation time, or shows "date not
  recorded" when no creation time exists.

### Added — In-app help, FAQ and About
- **Built-in help, fully offline.** `HELP.md` ("How MyKey works")
  and `FAQ.md` ("Common questions") are the canonical help text in
  plain words — vault, master password, recovery words, fingerprint
  unlock, sign-in codes, password dates, clipboard clearing, sync,
  two-factor backup packages, pairing, agents, skins. The GUI
  shows both from a new **Help** menu; the phone / web app mirrors
  the same files byte-for-byte, enforced in its CI. The old
  three-step `HELP.md` stub is replaced.
- **About dialog.** Name, version, seller (2351485 ALBERTA INC.),
  support address, the linked attribution line with the Muse
  referral code, a licence summary pointing at `LICENSING.md`,
  and a changelog pointer. A marked slot waits for the licence /
  tip block if the free-tier ruling lands.


### Added — Phase 3A: user-cloud sync + device-key backup packages
- **Sync through your own cloud folder.** A provider-neutral sync
  layer (folder provider shipped; no OAuth cloud APIs) moves the
  vault as an encrypted bundle — vault + audit log + anchor — with
  a signed, hash-chained manifest. Conflicts refuse on both sides
  and preserve both copies; rollback to a replaced history is
  refused; snapshots (last 10) and a human-gated restore path are
  included. CLI: `sync-configure/status/push/pull/snapshots/
  restore/pin`; basic controls in the GUI. Design, security model
  and exact limitations: `SYNC_BACKUP.md`.
- **Device keys.** Each device gets an X25519 + Ed25519 identity
  (private keys in a local 0600 file — no keystore claim). Public
  keys and fingerprints form a registry inside the encrypted
  vault; enrollment/revocation are human-gated.
- **Encrypted backup packages.** One portable file, content key
  wrapped to every enrolled device plus a recovery recipient
  re-derivable from the BIP-39 phrase (Argon2id-hardened), signed
  by the source device and strictly verified on import: tampered,
  malformed, wrong-recipient, revoked-source and downgrade
  packages are refused. Revoked devices are excluded from new
  packages; the inherent limit for already-exported packages is
  documented in `SYNC_BACKUP.md` §6. A hosted backup service is
  specified as a future contract only — not built, not claimed.

### Changed — Phase 2B: Vault v3, cryptographic agent partitioning
- **Vault format v3.** Per-entry key partitioning replaces the
  single-payload design: the core (registry, metadata key,
  per-entry keys, audit seal) sits under the vault key; each
  entry's metadata, secret fields and TOTP secret are encrypted
  under separate keys with domain-bound AAD. Agent slots now wrap
  per-agent *bundle keys*, never the vault key — scope is enforced
  **cryptographically**: an agent bundle contains only the keys of
  in-scope entries (plus the metadata key when `list` is held),
  so a token + vault file + modified client cannot decrypt
  out-of-scope entries. TOTP keys are in no bundle, ever.
- **Rotation on every privilege change.** Revoke, disable and
  scope narrowing re-encrypt the affected entries under fresh
  keys; expired enrollments are retired with rotation at the next
  human unlock. Agent writes go through an authenticated pending
  path (inbox public key + author MAC) and are processed — never
  overwritten — at human unlock. Committed ciphertexts are
  hash-pinned in the core. Design adversarially reviewed by the
  fleet before build; dispositions are in the PR description.
- **Audit anchoring.** Per-author MACs on authenticated records,
  a human-keyed HMAC anchor file checkpointed at human unlocks,
  and a seal-prefix rule: a log rolled back behind its sealed
  head is refused at unlock, never re-sealed over. Recovery is
  the documented `agent-audit-reset` quarantine flow.
- **Progressive backoff** replaces the hard 5-failure lockout:
  doubling no-retry windows (5s → 15 min cap) that refusals do
  not extend, audit-visible failure events without log-spam, and
  instant clear on human unlock.
- **Migration.** The first human unlock of a v2 vault migrates
  it in place: backup kept with agent slots stripped, vault key
  rotated, agent enrollments retired for re-enrollment, and a
  master-path migration retires the recovery phrase for re-setup
  (a recovery-path migration preserves it).
- `rotate-vault-key` is now a full re-key (new vault key,
  metadata key, per-entry keys, fresh vault identity) that also
  clears the audit anchor and pending queue.

### Added — Phase 2A: authorized-agent access
- Second principal: an authorized agent, next to the human. Agent
  authorization is a key-value pair on the app — agent id →
  {token hash (SHA-256; the 256-bit token is shown once at
  enrollment), scopes, created/expiry, enabled, last used} — stored
  inside the encrypted vault payload, with a matching wrapped-key
  slot (`agent:<id>`) in the Vault v2 header.
- Only a human session (master/recovery unlock) can enroll, scope,
  disable, enable or revoke an agent. Revocation deletes the pair
  and the slot; access dies immediately. An agent never sees the
  master password and can never export, delete, import, manage
  recovery, or manage agents.
- Scopes enforced on every call: `list` (metadata only — never
  passwords, notes or TOTP secrets), `get:<service>`,
  `get:tag:<tag>`, `get:*`, and `write` (add entries) only when
  explicitly granted. TOTP secrets are never returned to agents.
- Every authentication and access (allow and deny) is appended to a
  hash-chained audit log (`<vault>.audit.jsonl`, 0600); the chain
  head is sealed inside the encrypted payload so truncation is
  detectable. Bad-token attempts are rate-limited with a persistent
  lockout (5 failures → 5 minutes).
- Agent surfaces: CLI `agent-get` / `agent-list` (token only from
  the `MYKEY_AGENT_KEY` environment variable, never a flag) and a
  stdio MCP server (`mykey_mcp.py`) exposing `mykey_list` /
  `mykey_get`. Human management: `agent-enroll`, `agent-revoke`,
  `agent-disable`, `agent-enable`, `agents`, `agent-audit`.
- Fleet review round (three-builder rule): Claude drafted the MCP
  server (adopted: uniform auth errors, strict validation; rejected:
  cached session — revocation must apply per call). OpenAI's
  adversarial review produced 8 findings; all credible ones are
  fixed in this PR: audit chains are never re-sealed after a
  mismatch (`agent-audit-reset` archives the suspect log instead),
  `rotate-vault-key` re-keys the vault for suspected compromise,
  revocation/disable sync the rolling backup, the CLI no longer
  leaks entry existence, `list` metadata sanitizes URLs, agent
  writes are insert-only, and vault mutations take a cross-process
  lock. DeepSeek contributed adversarial test cases. 89 tests pass
  in a fresh venv (56 Phase 1 + 33 Phase 2A / review round). No
  mechanism here is judged novel (see LICENSING.md).

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

### Added — Browser extension host (native messaging)
- **Native messaging host** (`native_host.py`): a small,
  single-purpose broker the browser starts on demand. It serves
  ONE paired browser extension: unlock state, origin-matched entry
  queries, fills, TOTP codes, and save-capture commits. The vault
  never leaves this process unencrypted; the extension holds no
  vault copy. Design + protocol: `EXTENSION_HOST.md`.
- **Encryption in transit, not just at rest.** The local pipe is
  treated as untrusted: pairings are X25519 key-value records
  (extension id → public key + scopes `fill`/`save` + expiry +
  enabled, human-approved with a fingerprint ceremony), session
  keys come from the pairing keys per connection (HKDF-SHA256),
  every message is AES-256-GCM sealed with strict replay
  counters. A frame recording shows only ciphertext — proven by
  the leak test suite (`tests/test_native_host.py` greps raw wire
  bytes for fixture secrets; the extension repo carries the other
  half of the suite).
- **Pairing store** (`extpair.py`): `~/.mykey/extension-host.json`
  (0600), separate from the sync/export pairing registry —
  different trust domain, same key-value pattern. Revoked ids can
  never re-enroll. Per-entry "also fill on subdomains" prefs and
  host settings (vault path, auto-lock 300s default, clipboard
  clear 60–300s) live in this store, not in the vault.
- **Origin authority stays here.** Scheme + host + port must match
  exactly; subdomains fill only with the per-entry toggle;
  lookalike hosts never match. CLI: `ext-host-payload`,
  `ext-enroll`, `ext-pairings`, `ext-revoke`/`ext-disable`/
  `ext-enable`, `ext-set-vault`, `ext-set`, `ext-host-install`
  (Chromium family + Firefox manifests; Windows uses HKCU).
- Unlock lives in the host process memory only; wrong-password
  backoff; locking (or auto-lock) ends extension fills at once.
