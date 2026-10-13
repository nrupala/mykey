# Licensing — Apache 2.0 + Proprietary (owner decision, 2026-10-12)

This note proposes the licence map for MyKey. The full restructuring
(pointer `LICENSE` + `LICENSES/` texts, retiring the MIT file, closing
the superseded AGPL draft PR #2) lands in a separate licensing PR;
this PR only aligns the per-file headers with the map below.

## The map

| Bucket | Files | Terms |
|---|---|---|
| **Interface layer — Apache 2.0** | `brand.py`, `mykey_gui.py`, `mykey_cli.py`, `first_run.py`, import *format definitions* (the documented column layouts each exporter emits, as listed in `importers.py` docstrings) | Apache License 2.0, including its §3 patent grant (below) |
| **Core — Proprietary** | `mykey.py` (vault engine + cryptography), `recovery.py`, `totp.py`, `importers.py` (parsing/dedupe/conflict engine) | © 2351485 ALBERTA INC., all rights reserved. No licence is granted to copy, modify or redistribute. |
| **Data file** | `bip39_english.txt` | The BIP-39 English wordlist, reproduced from the BIP-39 specification (bitcoin/bips). |

## Patents

* **Apache 2.0 layer:** Apache §3 applies in full — each contributor
  grants a royalty-free patent licence for claims necessarily
  infringed by their contributions, and the §3 retaliation clause
  terminates that licence for anyone who brings a patent suit over
  the work. This protects adopters of the interface layer and deters
  suits against it. It is deliberately scoped to the interface layer.
* **Proprietary core:** **no patent licence is granted, express or
  implied. All patent rights are expressly reserved** by
  2351485 ALBERTA INC., together with all copyright. Publishing this
  code for inspection is not a licence of any kind.
* Any mechanism judged a patent candidate must live in the
  proprietary bucket and must not be described in public docs beyond
  what the shipped code itself necessarily shows, until the owner
  makes a filing decision.

### Honest assessment: what here is — and is not — a patent candidate

Standard practice (compositions of published standards; in our
judgement **not** patent candidates, and we say so plainly rather
than dressing them up):

* Argon2id / PBKDF2 key derivation, AES-256-GCM encryption,
* envelope encryption with per-credential wrapped-key slots
  (the architecture used across the password-manager industry),
* BIP-39 mnemonics with checksum, RFC 6238 TOTP,
* atomic file writes, typed-error handling, CSV format importers.

Phase 1 contains **no mechanism we judge novel**. Phase 2 watch-list
(not built; keep proprietary and unpublicised until evaluated, and
expect heavy prior art — push-approval MFA is well-trodden ground):

* the phone-approval unlock protocol (desktop challenge approved on
  a companion device releasing a wrapped vault-key slot),
* cross-device wrapped-slot handoff between desktop and companion.

The realistic everyday protections for the core are copyright,
trademark and trade secrecy for anything not yet shipped — the
reserved-rights posture above is what preserves those options.

## Brand neutrality (rename-on-the-fly guarantee)

All brand strings live in `brand.py` and nowhere else in the code.
The vault format binds no brand into its cryptography: the format
token is a stable technical identifier, no brand appears in AAD or
KDF inputs, and readers accept legacy v1 vaults. A rename is a
one-file change and can never break an existing vault — this is
covered by `tests/test_brand_neutral.py`.
