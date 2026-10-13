# Sync & Backup — Phase 3A

How MyKey 2.1 moves a vault between your devices without ever
exposing it: **sync through your own cloud folder**, and
**portable encrypted backup packages** addressed to your devices
and your recovery phrase.

Everything in this document is written to match the shipped code.
Where a protection has a hard limit, the limit is stated here in
plain terms — a backup system that oversells itself is worse than
none.

© 2026 2351485 ALBERTA INC. The modules described here
(`vaultsync.py`, `devices.py`, `backup_pkg.py`) are proprietary
core; see `LICENSING.md`.

---

## 1. The model in one paragraph

Your vault is ciphertext everywhere it travels. Sync copies an
encrypted **bundle** (vault file + audit log + audit anchor) into a
folder *you* choose — a Google Drive, iCloud Drive, OneDrive,
Dropbox, Syncthing or NAS folder all work, because to MyKey it is
just a folder. Backup packages are a second, independent path: one
portable encrypted file you can store or send anywhere, openable
only by your enrolled devices or your recovery phrase. There is no
MyKey server. There are no cloud accounts, OAuth grants, or API
keys in this product.

## 2. Sync

### 2.1 Provider

Sync talks to storage through a small provider interface
(`read` / `write_atomic` / `delete` / `list_names`). The only
provider shipped in this version is the **folder provider**. A
WebDAV provider is anticipated by the interface but is **not
implemented and not claimed**.

### 2.2 What is stored in the folder

```
<folder>/
  manifest.json            signed commit chain (see 2.3)
  bundles/<hash>.json      one content-addressed bundle per state
```

A **bundle** is one immutable JSON object holding the vault file
and its two sidecars (audit log, audit anchor), each
base64-wrapped with its SHA-256 recorded. The bundle hash covers
all three components *including their absence*, so a sidecar can
never be silently swapped or dropped without changing the bundle's
identity. The last 10 committed bundles are kept in the folder;
older unreferenced ones are pruned.

### 2.3 The manifest: signed commits, pinned signers

The manifest is an append-only chain of commits
`{generation, bundle_hash, parent, device_id, signer key,
timestamp, kind, Ed25519 signature}`. Generations are sequential
and each commit names its parent bundle hash, so the chain is a
verifiable ancestry of states.

Each device keeps private **sync state** beside its vault
(`<vault>.sync.json`, mode 0600): the last generation and bundle
hash it accepted, and the signer keys it trusts. Trust works like
this:

- **Registry pins are authoritative.** When you unlock, signer
  keys can be pinned from the vault's device registry
  (`sync-pin`, and automatically after device enroll/revoke).
  A commit whose signer key does not match its pin, or whose
  signature fails, is rejected outright.
- **First contact is TOFU** (trust on first use), like SSH: with
  no accepted state, a device accepts a self-consistent signed
  chain and pins the signers it saw. Once a device *has* accepted
  state, a commit from an **unpinned** device is refused, with
  instructions to unlock and run `sync-pin` — so a new device
  cannot silently join your sync history by writing to the folder.
- **Rollback is refused.** If the folder's chain no longer
  contains the bundle this device last accepted (history replaced
  by an older or forked chain), sync stops with a conflict error.
  Nothing is overwritten.
- **Post-revocation commits are refused** where revocation state
  is known locally (the revocations record, §3.4, or a registry
  pin carrying the revocation time).

*Honest limit:* a brand-new device with no trusted checkpoint
cannot distinguish "the authentic latest state" from "an authentic
older state" — both are validly signed history. This is inherent
to offline sync without a trusted witness. Restoring an old state
is always an explicit, human-gated act (§2.5).

### 2.4 Conflicts: never a silent overwrite

Push publishes only when the folder's head is exactly the state
this device last accepted (or this device's own new state). Pull
installs the head only when the local vault file is byte-identical
to the last synced one, or absent. Otherwise **both operations
refuse with a conflict** and both copies survive untouched:

- If the local vault diverged, pull refuses; a forced pull first
  snapshots the local bundle (kept beside the vault, last 10) and
  quarantines diverged audit/anchor sidecars to `.suspect-*`
  files rather than deleting them.
- One narrow merge exists: if the local *vault file* is untouched
  but the local audit log strictly extends the incoming one (this
  device recorded agent activity since the last sync), pull keeps
  the local audit log and takes the incoming vault + anchor. If
  the incoming bundle has no anchor while the local one does, pull
  refuses and asks you to unlock once on the other device first —
  the anchor is never silently dropped. *Forked audit logs are
  never merged automatically*: the chain-verify at unlock is the
  cryptographic gate, and fork resolution is a human decision.

Sync validates structure and provenance of what it moves. The
cryptographic verification of the audit chain and anchor still
happens at the next human unlock, exactly as before Phase 3A.

### 2.5 Snapshots and restore

Every bundle ever committed stays addressable in the folder
(last 10), and every forced overwrite keeps a local snapshot
(last 10). `sync-restore <bundle-hash>` (human unlock required)
installs a chosen bundle, snapshotting the current state first.
A restored state is deliberately *not* marked as synced: to
publish it you must `sync-push --force` (human unlock required),
so a rollback can never masquerade as routine sync.

### 2.6 Commands

```
mykey sync-configure --folder <path>     mykey sync-status
mykey sync-push [--force]                mykey sync-pull [--force]
mykey sync-snapshots                     mykey sync-restore --snapshot <hash>
mykey sync-pin
```

Routine push/pull/status need no master password — they move
ciphertext only. `--force` and restore require a human unlock.
The GUI exposes status/push/pull under **Sync & Backup**
(non-forced operations only).

### 2.7 What the folder reveals

The sync folder is not a black box to its host: the manifest
exposes stable vault and device ids, commit times, and history
length; the audit log is authenticated but **not encrypted**, and
its lines can name agent ids, actions and service names (never
entry secrets, never passwords). Anyone with read access to the
folder sees: that a vault exists, how many devices sync it, and
when it changed. If that metadata matters to you, keep the sync
folder somewhere you trust.

Two structural guards are enforced: the device key file may not
live inside the sync root, and the sync root may not be the
vault's own directory (either would eventually ship private keys
or raw state somewhere unintended).

Racing writers (two devices pushing at the same moment) surface as
a fork — bundle objects are content-addressed and preserved;
nothing resolves the fork silently. Providers without atomic
rename semantics are out of scope for the folder provider.

## 3. Device keys

### 3.1 Identity

`mykey device-init` generates a device identity: an **X25519**
key pair (encryption) and an **Ed25519** key pair (signing) —
the modern GPG arrangement. The identity's fingerprint is a
SHA-256 over both public keys, shown grouped for out-of-band
comparison. Private keys live in one local file
(`~/.mykey/device-keys.json`, or `$MYKEY_DEVICE_KEYS`), mode
**0600**, and the loader refuses group/other-readable key files.

State the limit plainly: in this version the private keys are
stored as a plain (permission-protected) file. **OS keystore
storage (Keychain / TPM / Windows Hello) is not implemented and
is not claimed.** Protect the file like a private key — anything
that can read it can act as this device.

### 3.2 Registry

Public keys live in a **device registry inside the encrypted
vault core**. Only a human-unlocked session can enroll or revoke
a device (`device-enroll`, `device-revoke`, `devices`).
Enrollment takes a public **card** (`device-card`) — cards carry
no secrets. Enrolling another device prompts you to compare its
fingerprint with what that device itself shows. A revoked device
id can never be re-enrolled; a replacement device generates a
fresh identity.

### 3.3 What device keys do

- **Sign sync commits** (§2.3) — folder writers are accountable.
- **Receive backup packages** (§4) — each enrolled device is a
  package recipient.
- **Sign backup packages** — the exporting device signs every
  package it creates.

### 3.4 Revocation

Revoking a device (human unlock) marks it in the registry,
records it in a local revocations file beside
...[truncated 14842 chars]