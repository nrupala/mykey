# Passkeys in MyKey — desktop summary

Passkey wave (2026-10-13). The full design document lives in the
mobile client repository (`docs/PASSKEYS.md` in nrupala/mykey-mobile);
this file states the desktop engine's part and the shared format
contract both clients implement identically.

## Format contract (both engines, byte-compatible)

- An entry of kind `"passkey"` (metadata field `kind`, appended
  last in the metadata field list; default `"login"`).
- The WebAuthn record lives in the entry's `passkey` blob, sealed
  under its own per-entry key class (DEK_passkey, the `passkey`
  member of the core's per-entry key map), with AAD
  `passkey:v3:<entry-id>`.
- A SHA-256 hash of the blob (`passkeyhash:v3` ‖ nonce ‖
  ciphertext) is sealed in the core's `passkey_hashes` map. It is
  kept separate from `entry_hashes`, which is unchanged, so
  pre-passkey vaults verify byte-for-byte.
- Load fails closed: a non-null passkey blob with a missing or
  mismatching sealed hash, or without a DEK_passkey, is
  `VaultCorrupt`.
- Record fields (`PASSKEY_RECORD_FIELDS` in mykey.py): `rp_id`,
  `user_id`, `user_name`, `user_display_name`, `credential_id`,
  `alg` (-7 ES256; -8 EdDSA), `public_key` (raw uncompressed EC
  point for ES256, raw bytes for EdDSA), `private_key` (PKCS#8
  DER) — all binary fields base64 — plus `sign_count`,
  `transports`, `created_at`, `aaguid`, `backup_eligible`,
  `backed_up`.
- The entry presents as service = rp_id, username = user_name,
  password empty. Key rotation rotates DEK_passkey with the other
  per-entry keys; deleting the entry drops its sealed hash.

## Desktop role in v1

Read-only plus delete. The CLI `passkeys` command lists passkeys
(created date + sign-in count) and `get` on a passkey prints a
public summary only — never the private key. The GUI lists
passkeys with a "use the phone app" marker. Creation and use are
phone-first: the mobile client holds the WebAuthn authenticator
and the Android Credential Manager provider.

## Non-negotiables

- **Agent bundles never contain passkeys.** DEK_passkey is never
  bundled and passkey entries are excluded from bundle targets
  and service maps (agents.py sessions also cannot read them).
  Agent passkey use is a later, separately gated design — it is
  documented here as *not built*, on purpose.
- **CSV export skips passkey entries** (no CSV representation of
  a passkey exists, and a private key must never land in a
  plaintext file). **CSV import never overwrites or merges into
  a passkey entry** — collisions count as skipped conflicts.
- Passkeys are ordinary entries for the free-tier count: they
  count toward the 50-entry cap exactly like logins
  (`add_passkey` carries the seam comment for the licensing
  wave's admission gating).
- Unknown-field tolerance runs both ways: pre-passkey cores have
  no `passkey_hashes` (treated as empty) and login entries have
  no passkey blob. The reverse is NOT safe: a pre-passkey client
  re-saving a passkey vault drops the passkey blobs. Both
  current clients are required for passkey vaults.
