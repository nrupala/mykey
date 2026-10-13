# Sync & Backup — Phase 3A + the blob wave

How MyKey moves a vault between your devices without ever
exposing it: **sync through your own cloud folder**, and
**portable encrypted backup packages** addressed to your devices
and your recovery phrase. Sections 1–8 describe the Phase 3A
design as shipped in 2.1; §9–§10 describe the blob wave (2.2):
two-factor backup packages and key-value pairing. (Sections 4–8
were lost to a truncation in the Phase 3A push and have been
rewritten from the shipped code.)

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

Revoking a device (human unlock) marks it in the registry and
records it in a local revocations file beside the vault
(`<vault>.revocations.json`), which import and sync consult even
when the vault core itself has been rolled back. A revoked device
id can never be re-enrolled — a device that lost trust generates
a fresh identity. Revocation excludes the device from NEW
packages and stops its sync commits being trusted wherever
revocation state is known. It cannot make packages exported
BEFORE the revocation undecryptable to a private key that device
retained — see §6.

---

## 4. Backup packages

A backup package (`.mykeybak`, format token `MKBAK`) is one
portable JSON file holding the whole vault bundle — vault bytes,
audit log, audit anchor — encrypted under a random content key.
The content key is wrapped separately for each recipient:

- every enrolled, non-revoked **device** (sealed to its X25519
  public key),
- in v2 packages, every active **paired target** holding the
  `export` scope (§10),
- a **recovery recipient** re-derived from the BIP-39 recovery
  phrase (Argon2id over the seed with a per-vault salt, so
  checking phrase guesses is memory-hard) — in v2 packages this
  slot is additionally wrapped under a backup code (§9).

The exporting device signs the package with its Ed25519 key.
The signature proves possession of that device's key file —
device-key provenance — not that a human approved this
particular package.

Import is strict and fails closed. It refuses: malformed or
duplicate-key JSON; an unknown format or version; a bundled
vault that is not Vault v3; a signature that does not verify;
on a fresh device, a source fingerprint that does not match the
one the human supplies from an independent channel (a package
cannot vouch for itself); over an existing vault, a source
device the unlocked registry does not show as enrolled and
unrevoked, or a pairing target that registry shows revoked; a
caller who is not a recipient; and a package older than the
newest one seen for this vault, unless the human explicitly
allows older (`--allow-older`). A successful import snapshots
the outgoing vault and quarantines — never deletes — sidecars
the package does not replace.

Commands: `backup-export`, `backup-import`, `backup-inspect`;
the GUI offers export and import under Sync & Backup.

---

## 5. Security model

- **Zero-knowledge transport.** Sync folders and backup packages
  only ever hold ciphertext. Keys never travel: device private
  keys live in a local 0600 file outside any synced folder, and
  sync refuses a configuration that would put them inside one.
- **Authenticated provenance.** Sync commits and backup packages
  are signed; sync signer keys are pinned from the vault's
  device registry at human unlock (first contact is
  trust-on-first-use, with conflicts alarmed — §2.3).
- **Fail closed.** Every integrity check in this document ends
  in refusal, never in a best-effort import or a silent
  overwrite. Diverged copies are preserved for a human to
  resolve.
- **Human gates.** Enrollment, revocation, pairing, forced sync
  operations and snapshot restores all require a human-unlocked
  session. Agents can do none of them.

---

## 6. Limits, stated plainly

- **Revocation does not reach copies already out the door.** A
  device or paired target that retained its private key can
  still open packages exported before its revocation. This is
  inherent to offline files, not a bug to be patched: rotate the
  vault key if you need old copies dead, and treat that as a
  full re-enrollment event.
- **The anti-rollback high-water mark is local and editable.**
  It is a policy gate that catches accidents and lazy rollback,
  not a proof against someone who can rewrite all local state.
- **`--allow-older` is policy, not proof.** Allowing an older
  package is a human decision to trust it; the package's age is
  not cryptographically disproven.
- **Device private keys are plaintext inside a 0600 file.** No
  OS-keystore storage is claimed. Anyone who reads that file is
  that device, as far as packages and signatures can tell.

---

## 7. Hosted backup (contract only — not built)

A future hosted backup service is specified, not implemented:
our servers would store only the same opaque ciphertext
packages described in §4, with keys held entirely by the
client; retention and deletion-on-cancel semantics are part of
that contract. No endpoint, account system or subscription
state exists today, and nothing in the product claims one does.

---

## 8. Residual limits

- **Metadata exposure.** A sync folder reveals device ids,
  commit timing, and vault/audit sizes (§2.7). Content stays
  sealed; existence and rhythm do not.
- **Consistent full rollback.** Rolling the vault, its audit
  log and its anchor back together to one consistent old
  snapshot is undetectable from those files alone; the anchors
  and seals catch partial rollbacks, not a time machine with
  all three parts.
- **First contact.** Before any registry pin exists, first sync
  contact is trust-on-first-use. Compare fingerprints out of
  band before you rely on a new folder or device.

---

## 9. Two-factor backup packages (MKBAK v2)

New exports are format **v2**. The change is in the recovery
slot: the content key is sealed to the recovery-phrase key as
before, and that sealed blob is then encrypted under a second
key derived from a **backup code** — 8 words from the BIP-39
list (88 bits), generated at export, run through Argon2id of its
own, and combined under an HKDF domain label. The code is shown
to the user **once**, at export, with one instruction: keep it
somewhere different from the recovery phrase. It is never
written into the package, the vault, or any file.

The rule, plainly: **decrypting a v2 backup outside the app
needs two factors — the recovery phrase AND the backup code.**
The phrase alone fails. The code alone fails (it unwraps one
layer of a slot it cannot unseal). A wrong code fails closed
with a plain error. Enrolled devices and paired targets keep
their own key paths — the two factors guard the outside-app
recovery path, which is the one that works from nothing but
paper.

**Legacy v1 packages** keep their original semantics: the
recovery slot opens with the phrase alone. They still import,
and they are labelled LEGACY by `backup-inspect` and at import
time, so the weaker guarantee is never mistaken for the v2 one.
Exporting v1 remains possible only as an explicit choice
(`export_package(..., version=1)`); the clients export v2.

---

## 10. Key-value pairing (cloud storage + export targets)

Pairing is how a vault says which **outside targets** may
receive its encrypted blobs. The registry lives inside the
encrypted vault core, keyed by target id — the key-value
pattern used by the agent and device registries:

    target id → { type: device | cloud-folder | export,
                  X25519 public key, fingerprint,
                  scopes: [push, pull, export],
                  expires_at, enabled, enrolled_at, revoked_at }

**Pairing flow.** The target generates its own X25519 keypair
(`pairing-keygen`) and presents a **pairing payload** — target
id + public key + fingerprint, as a QR string or paste code.
The human compares the fingerprint against what the target
itself shows and confirms (`pair-enroll`). Only a
human-unlocked session can enroll, enable, disable or revoke a
pairing; fingerprints are always recomputed, never trusted as
stated.

**What pairing enables.**

- *Backup exports* seal a content-key copy to every pairing
  that is enabled, unexpired and holds the `export` scope. An
  unpaired target — or one paired without `export` — gets no
  slot and cannot open the package.
- *Sync* folders can be bound to a target
  (`sync-configure --target <id>`). Push then requires the
  `push` scope, pull the `pull` scope. Sync never unlocks the
  vault, so it checks **pins**: copies of the pairing records
  refreshed into the local sync state at human unlock — the
  same pattern as device signer pins. A binding whose pin is
  missing, disabled, expired or revoked stops sync with a plain
  error.

**Revocation.** A pairing target holds no vault key material —
no entry keys, no unlock slot — so there is nothing of its
inside the vault to rotate. Revocation is total for the future:
package content keys are random per export, so the next package
simply has no slot for the revoked target, and sync stops at
the next pin refresh (the CLI refreshes pins in the same
session as the revoke). Packages already exported stay openable
by a key the target retained — the same inherent limit as §6.

The cloud stays the user's own cloud throughout: pairing
decides WHICH targets receive blobs. It adds no server, no
OAuth, and no network listener.
