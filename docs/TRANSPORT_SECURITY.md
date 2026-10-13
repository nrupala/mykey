# Transport security — MyKey

How vault data and secrets are protected **in transit**, not just at
rest. Every path by which vault data or a secret can move — between
folders, devices, apps, surfaces, or people — is named below, with
the encryption and authentication that protect it while it moves,
what protects its integrity, and what honestly remains exposed.

The short version: **MyKey has no servers and no network code.**
Nothing in either client can open a socket. Everything that moves,
moves as ciphertext the sender encrypted before the move, through
channels the user chose (their own cloud folder, a file they carry,
a share sheet they invoke) — and the receiving side verifies before
it trusts.

Enforcement: the properties below are encoded as tests that run in
CI — `tests/test_transport_gates.py` (desktop) and
`tests/transport.test.ts` (mobile/web). A change that weakens a row
of this table fails the build until the change is deliberate and
this document is updated in the same commit.

## Inventory

### 1. Folder / cloud sync (desktop, Phase 3A)

- **What moves:** a sync *bundle* (`MKBND`): the vault file bytes,
  the audit-log bytes, and the audit-anchor bytes, each base64'd
  with its SHA-256, plus a signed manifest (`MKMFT`) of commits.
- **Encryption in transit:** the bundle carries the vault file
  **byte-for-byte as it sits encrypted on disk** — envelope
  encryption (AES-256-GCM under per-entry keys, Vault v3) is never
  peeled for sync. The sync code holds no master password and
  decrypts nothing; it reads only the vault's plaintext header
  (format, version, vault id). The audit and anchor components are
  the on-disk artifacts themselves: an append-only, hash-chained,
  MAC'd log and its HMAC anchor.
- **Authentication + integrity:** every manifest commit is
  **Ed25519-signed** by the pushing device's key. A pull verifies,
  in order: the chain links (generation sequence, parent hashes),
  each commit's signature against the device key pinned from the
  vault's registry (trust-on-first-use before first pin, conflicts
  alarmed), revocation cut-off (a commit signed after its device
  was revoked is refused), ancestry (a head that does not descend
  from the last accepted bundle is refused as rollback/fork), and
  every bundle component's hash against the manifest before a
  single local byte is touched.
- **Proven by:** `tests/test_phase3a.py` (round trip, divergent
  conflict with both copies preserved, corrupted bundle refused,
  rollback + forgery refused, artifacts carry no plaintext) and
  `tests/test_transport_gates.py` (bundle components are the
  ciphertext files verbatim and contain no password, TOTP secret,
  or username; a one-bit tamper of a component in transit is
  refused; a one-bit tamper of a commit signature — or swapping
  the bundle hash under a valid signature — is refused).
- **Honest residual:** the folder's owner (the user's cloud
  provider) sees ciphertext plus metadata — that a vault exists,
  how many devices sync it, bundle sizes, and when it changed
  (SYNC_BACKUP.md §2.7). Audit lines are authenticated, not
  encrypted, so action metadata (not secrets) is inside the bundle.
  Metadata privacy is the user's folder choice; content secrecy
  does not depend on it.

### 2. File sync (mobile / web client)

- **What moves:** the vault file itself (`vault.mykey`) plus
  timestamped snapshots — via a user-picked folder (File System
  Access API, desktop Chromium) or explicit save/open file flows
  (Android share sheet and file pickers). There is no background
  sync and no server.
- **Encryption in transit:** the file that moves **is** the
  encrypted container (`MKVLT` v3) — the same bytes the export
  path produces. The client never writes a decrypted copy anywhere.
- **Authentication + integrity:** the container is self-verifying:
  its HMAC verifier and AES-256-GCM tags are checked at open; a
  corrupted or tampered file refuses to open rather than opening
  partially. The sync folder path re-checks the user's folder
  permission on every use.
- **Proven by:** `tests/transport.test.ts` (serialized bytes are
  the `MKVLT` container and contain no password, TOTP secret, or
  username) and `tests/filesync.test.ts` (platform flows are as
  labelled; folder sync is offered only where the platform
  genuinely supports it).
- **Honest residual:** same metadata exposure as row 1, on the
  user's chosen storage. On Android the flow is deliberately
  manual (the WebView has no directory picker) and the app says so
  instead of pretending to background-sync.

### 3. Backup blob (MKBAK, desktop + mobile restore)

- **What moves:** one JSON package: the vault bytes encrypted
  under a random content key, the content key sealed separately to
  each recipient — every enrolled device's X25519 key, every
  active key-value pairing target, and a recovery recipient
  derived from the user's BIP-39 phrase.
- **Encryption in transit:** ciphertext + recipient-wrapped by
  construction, before the file exists. In **v2** (the default)
  the recovery slot is wrapped a second time under a key derived
  from the export-time **backup code** (8 words, 88 bits, shown
  once, never stored): opening a v2 package outside the app needs
  the phrase **and** the code — two factors, either alone fails.
  Legacy v1 packages open with the phrase alone and are labelled
  LEGACY wherever inspected or imported.
- **Authentication + integrity:** each package is **Ed25519-signed
  by the exporting device**. Import fails closed on: bad signature,
  tampering, malformed/duplicate-key JSON, non-v3 bundled vault
  (downgrade), wrong recipient, revoked source (for imports over
  an existing vault), a fresh-device source fingerprint that does
  not match the one the human supplies independently, and older-
  than-newest-seen packages without an explicit human override.
  A signature proves device-key provenance, not human approval of
  that specific package — stated here, not smoothed over (see
  backup_pkg.py's module notes).
- **Proven by:** `tests/test_phase3a.py` (recovery round trip
  after total device loss, second-device import, tamper + wrong
  recipient refused, revoked device excluded from new packages),
  `tests/test_blob_wave.py` (v2 two-factor recovery: phrase-only
  and code-only both fail, wrong code fails closed; pairing
  targets receive wraps only while enrolled, scoped, and
  unexpired), and `tests/test_transport_gates.py` (exported
  package bytes carry no plaintext secret).
- **Honest residual:** a revoked device's retained private key can
  still open packages exported **before** its revocation — true of
  every offline file system; revocation cuts off the future, it
  cannot rewrite copies already carried away.

### 4. Network providers (WebDAV and friends) — policy, enforced

- **Status:** no network sync provider exists in either client.
  The desktop provider interface anticipates one; nothing is
  implemented, and no documentation may claim otherwise (the
  mobile feature matrix was corrected in this wave — it had
  wrongly implied the desktop ships WebDAV).
- **The rule, gated in tests:** any future network provider must
  be **HTTPS-only** (plain `http://` refused except explicit
  localhost), with **TLS certificate verification always on** —
  no `verify=False`, no unverified SSL contexts, no
  `rejectUnauthorized: false`, in any code path, option, or
  "advanced setting". There is no legitimate user setting that
  turns verification off.
- **Today's enforcement:** neither repo contains an HTTP client,
  a socket, or a TLS stack in product code at all; the desktop
  gate test fails if any of those (or any TLS-weakening pattern,
  or any URL beyond the licence-text allowlist) appears, and the
  mobile gate fails if any network-call primitive appears in the
  client source. Adding a provider means updating those gates
  deliberately, in the open, with this document.

### 5. Browser extension ↔ desktop (companion wave)

- **Status:** the extension is built by a parallel wave. Its
  channel answers to this standard, recorded here so both waves
  build to one rule.
- **Required design:** the extension talks to the desktop **only**
  over a paired local channel: pairing is a human-confirmed
  key-value exchange (the same registry pattern as agents,
  devices, and cloud targets) that establishes X25519 device keys
  for both ends; the session runs AES-256-GCM with per-session
  keys derived from those, with sequence numbers / nonces giving
  **replay protection**; frames carry ciphertext only, so a
  capture of the channel (pipe, socket, or log) shows no
  plaintext secret, ever. The desktop side binds loopback only if
  it binds at all, and refuses unpaired callers. Unlock authority
  never crosses the channel: the extension can request a fill for
  an entry the human's scopes allow; it never receives the master
  password or the vault key.
- **Acceptance evidence the extension wave must produce:** a
  frame-capture test showing no plaintext in transit, a replayed
  frame refused, and an unpaired caller refused.

### 6. Agent access surfaces (all five modes)

- **What moves:** nothing leaves the machine. The five access
  modes (HUMAN GUI, MACHINE CLI, AGENT MCP/agents library,
  SOFTWARE library embedding, API local contracts) are all
  **local-only by design** — AGENT_ACCESS.md states it and the
  code enforces it: there is no listener to turn on.
- **The MCP server** (`mykey_mcp.py`) speaks newline-delimited
  JSON-RPC on **stdio** — it imports no socket or HTTP module and
  binds nothing. The agent token comes from the environment; the
  agent never receives a master password; authorization is the
  key-value registry (hashed token, scopes, expiry, enabled) with
  revocation effective on the next call (no session caching).
- **Proven by:** `tests/test_transport_gates.py` — a repo-wide
  gate (no sockets, no listeners, no HTTP) plus a live stdio
  round trip of the MCP server — and `tests/test_agents.py` /
  `tests/test_agents_review.py` for scope, expiry, and audit
  behaviour.
- **Honest residual:** a local process running as the same user
  with the agent token in its environment is inside the trust
  boundary the human created when enrolling that agent. Scopes
  and per-entry keys bound what that trust can reach; TOTP
  secrets are in no agent bundle, ever.

### 7. App distribution + updates

- **PWA / service worker:** precache only. The service worker
  caches the app shell (the client itself) with **no runtime
  caching** (`runtimeCaching: []`, gated in the mobile tests) and
  the page's CSP is `connect-src 'none'` — the running app cannot
  make a network call, to us or anyone. The one network moment in
  a PWA's life is the browser fetching an updated shell from
  wherever the user installed it from; that channel's integrity
  is the host's HTTPS, and the shell contains no user data.
- **Android:** the app ships as a signed APK/AAB; its manifest
  requests **no permissions at all** — no INTERNET — and disables
  Android cloud backup of app data (`allowBackup="false"`, gated
  in the mobile tests). Web content is packaged in the app, not
  fetched.
- **Desktop:** no updater, no phone-home. New versions are new
  files the user obtains and can verify against the repository.

### 8. Clipboard + share sheets

- **Share sheets (Android):** the only file the export path hands
  to the share sheet is the encrypted vault container or an MKBAK
  package (rows 2–3) — asserted by the mobile transport gate
  (serialized bytes are the `MKVLT` container with no plaintext).
- **Clipboard:** copying is a deliberate human act inside an
  unlocked session. Copied secrets are marked sensitive on
  Android, and the clipboard auto-clears after a short user-set
  delay and immediately on lock. The honest limit is documented
  in the help text: the app cannot reach into every keyboard's
  own history on every phone brand; the timed clear plus the
  sensitive flag is the real control.

### 9. Plaintext CSV export — the one deliberate exception

- Exporting a readable CSV is sometimes the user's actual goal
  (leaving for another manager). It exists on both clients and is
  fenced identically: **human-only** (the engine refuses agent
  principals — `tests/test_transport_gates.py` proves an agent
  principal cannot export and no file is written), an explicit
  warning + confirm step in every UI before the button enables,
  0600 file permissions on desktop, and help text that says to
  delete the file when done. Import is the mirror: a foreign CSV
  is read locally, lands only inside the encrypted vault, and the
  UI tells the user to delete the source file.

### 10. Telemetry, analytics, licence, help

- **There is none.** No telemetry, no analytics endpoints, no
  crash reporting, no update checks in either client — gated by
  the URL allowlists in both test suites: the only external
  references in product code are the Apache licence text in file
  headers (desktop + mobile), and in the mobile UI the
  user-invoked attribution links (`nrupalakolkar.com`,
  `muse.ai/join`) and the support address
  (`info@aimlds.org`, a `mailto:` the user taps). Licence
  verification is fully offline against an embedded public key,
  and any buy/tip entry is a user-invoked browser open —
  the app itself fetches nothing, ever.

## Residuals, collected

1. Cloud/folder providers see ciphertext + metadata (existence,
   device count, sizes, timing). Content secrecy never depends on
   the provider; metadata privacy is the user's storage choice.
2. Audit lines inside sync bundles are authenticated, not
   encrypted — action metadata travels with the vault so other
   devices can verify the chain.
3. Revocation cannot reach backup copies already exported; it
   cuts off future packages and future sync commits.
4. MKBAK signatures prove device-key provenance, not per-package
   human approval.
5. Fresh-device trust starts at TOFU/fingerprint comparison: the
   human comparing the fingerprint over an independent channel is
   the authentication. The clients make the comparison mandatory
   where the design requires it; they cannot make the human look.
6. Clipboard contents are visible to the OS and the active
   keyboard during the short clear window (user-set delay).

Owned by 2351485 ALBERTA INC. · Questions: info@aimlds.org
