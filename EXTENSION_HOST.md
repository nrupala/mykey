# Browser extension host — design and protocol

The desktop side of the MyKey browser extension. The extension
lives in `nrupala/mykey-mobile` under `extension/`; this document
covers the host it talks to: `native_host.py` + `extpair.py`.

## Shape

```
Browser ── native messaging (stdio, length-prefixed JSON) ──► native_host.py
                                                              ├─ extpair.py store (~/.mykey/extension-host.json)
                                                              └─ MyKey (the vault, in this process only)
```

- The browser starts the host on demand and kills it with the
  pipe. No daemon, no listening socket, no network — ever.
- The vault is opened only inside this process. The extension
  holds no vault copy and no vault key; it receives single entries,
  per fill, after the user clicks.
- The host is the authority for everything security-shaped:
  pairing checks, origin matching, scopes, lock state.

## Pairing (house key-value pattern)

The registry maps **extension id → record**, the same pattern as
agent access and backup pairing, in its own store because the
trust domain differs (a browser profile, not a device or an
export target):

| Field | Meaning |
|---|---|
| `x25519_pub` | The extension's public key (base64). |
| `fingerprint` | SHA-256 of the key, grouped hex — recomputed at enroll, never trusted from the payload. |
| `label` | Human name ("Firefox on the laptop"). |
| `scopes` | Subset of `fill`, `save`. |
| `expires_at` | Optional ISO timestamp; expired pairings are refused at hello. |
| `enabled` | Human can pause without revoking. |
| `revoked_at` | Once set, the id can **never** re-enroll. The browser must reset its identity (new keypair) to pair again. |

Enrollment is a human act on the desktop (`ext-enroll`), with the
fingerprint shown on both sides for comparison. The extension
pins the host's public key the same way (options page, step 2):
the host payload's fingerprint is recomputed from its key and a
lying payload is refused.

The store also holds the host's own X25519 identity (created on
first use), settings (`vault_file`, `auto_lock_seconds` default
300, `clipboard_clear_seconds` default 60, hard bounds 60–300),
and per-entry prefs keyed by vault entry id — currently only
`fill_subdomains` (default off). Prefs live here, **not in the
vault**, so the vault format did not need a new field for a
browser concern.

## The channel (`mykey-ext-v1`)

Native messaging is a local pipe, but the design treats it as
untrusted wire: other software on the machine could read or
inject pipe bytes, so traffic is encrypted and authenticated end
to end (the owner's "encryption in transit everywhere" rule).

1. **Hello (plaintext, public data only).** Extension sends
   `{extension_id, ext_pub, client_nonce}`. The host refuses
   unknown, disabled, expired or revoked pairings and key
   mismatches with a plaintext `fatal` frame and exits. It replies
   `{host_pub, server_nonce, session, ack}` where `ack` is the
   first sealed frame (below).
2. **Session keys.** X25519 shared secret from the pairing keys;
   HKDF-SHA256, salt = client_nonce‖server_nonce, info strings
   `mykey-ext-v1 e2h` / `mykey-ext-v1 h2e`, 32-byte keys per
   direction. Session id = first 32 hex of
   SHA-256(client_nonce‖server_nonce).
3. **Sealed messages.** AES-256-GCM; nonce = direction bytes +
   NUL + 8-byte big-endian counter; AAD binds protocol, direction,
   session and counter; plaintext is canonical JSON (sorted keys,
   Python `ensure_ascii` escaping — the TypeScript side reproduces
   it byte-for-byte; known-answer vectors are shared between the
   repos and CI fails on drift). Counters are strict per
   direction: a gap, replay or forgery ends the session.
4. **Unlock ack.** The ack (host → extension, sequence 0) carries
   protocol, unlock state, scopes and vault-configured — the host
   proves itself before any password crosses.

Message kinds (all sealed): `ping`, `status`, `unlock`, `lock`,
`match` (metadata only), `fill`, `totp`, `save_check`,
`save_commit`, `set_entry_pref`. Errors are
`{kind: "error", code, message}` and never contain secrets.

## Rules the host enforces

- **Origin matching.** Only http/https; userinfo rejected; host
  lowercased, trailing dot stripped; default ports normalized.
  A fill matches when scheme + host + port are equal, or — only
  with that entry's `fill_subdomains` pref — the page host is a
  subdomain of the entry's host. Lookalikes
  (`example.com.evil.com`, `evil-example.com`) can never match.
  The entry's origin comes from its saved website; the extension's
  own match list is a convenience, the host re-validates every
  fill.
- **Unlock discipline.** The master password arrives only inside
  the sealed channel, is verified against the vault here, and is
  never stored or logged. After 3 wrong attempts, exponential
  backoff (2^(n−3)s, capped 60s). Auto-lock is checked on every
  message; locking drops the vault object, and the extension
  wipes its caches the moment it sees a `locked` refusal.
- **Save discipline.** `save_check` classifies against the vault
  first (new / same / different); `save_commit` re-validates the
  origin for updates. The extension only calls either after the
  human clicks Save.

## Leak gate

This host ships behind the same named suite as the extension
(`tests/test_native_host.py` here; `extension/tests/` there). Its
desktop half includes a subprocess test that records every raw
byte on the pipe during a full unlock → match → fill → TOTP flow
and greps for the fixture master password, entry passwords,
usernames, TOTP secret and live code: none may appear.

## Install surface

`mykey ext-host-install` writes a per-OS launcher under
`~/.mykey/` plus one native-messaging manifest per browser
(Chrome/Chromium/Edge/Brave/Firefox directories on Linux/macOS;
manifest + HKCU registry key on Windows). Chromium manifests
allow only enrolled, non-revoked extension ids whose ids are
well-formed; Firefox uses the extension's fixed gecko id.

## Not in v1

- Safari (no native-messaging path comparable for this design).
- A desktop GUI pairing screen — pairing is CLI, with the same
  fingerprint ceremony.
- Card/identity items — the host serves logins only.
