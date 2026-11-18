# Codetopo Profile — MyKey (nrupala/mykey)

**What this is.** The agent-facing map of this repository, generated with
Codetopo 0.9.1 (local engine, `~/.cargo/bin/codetopo`) so an arriving agent
can see the machine — topology, trust boundaries, money surface — before it
submits or changes anything. Read this first; the graph snapshot beside it
(`snapshot.json`, `stats.json`) is the measured evidence.

- **Repo:** nrupala/mykey
- **Commit profiled:** `a2be67fb32e82a998fba13fe557b18c3b4e4d00c` (main)
- **Engine:** codetopo 0.9.1 · index run 2026-11-18
- **Graph:** 60 files walked · 0 failed · 2488 nodes · 10993 edges · audit chain valid (3 entries, head `445136f8…cbc03`)
- **Nodes by kind:** class 41 · doc 17 · external 1273 · file 60 · function 601 · method 253 · module 60 · package 1 · variable 182
- **Edges by kind:** calls 5127 · contains 1214 · defines 406 · imports 342 · inherits 18 · reads 3738 · writes 148

## Coverage honesty

Codetopo extracts Rust, TypeScript/JavaScript and Python, plus Markdown
as Doc nodes. This repo is Python-only code: the graph walks 60 files
(the top-level vault modules, `tests/`, `tools/`, `packaging/`) at
full symbol level — the largest graph in this batch (2,488 nodes,
10,993 edges). The 17 Markdown files are indexed as Doc nodes only.
**Not covered:** `bip39_english.txt` (the BIP-39 wordlist — data),
licence texts, brand assets (SVG/PNG/ICO) and packaging data are not
parsed as code. There is no other code language in this repo.

**Handling note for this repo:** MyKey is a password-vault product.
This profile was written from file names, symbol names and README /
docs prose only. **No credential material was read or copied** — no
vault contents, no keys, no secrets, and no account identifiers
appear in this pack; crypto and licence parameters are referred to
by module and constant NAME only.

## Topology

A local-first, zero-knowledge password generator and vault
(README): Argon2id key derivation + AES-256-GCM authenticated local
encryption; master password and secrets never leave the machine; no
cloud, no tracking, no recovery backdoor.

- `mykey.py` — vault core; `mykey_cli.py` — CLI; `mykey_gui.py` —
  desktop GUI (entry points per README).
- `totp.py`, `recovery.py` (BIP-39-style recovery), `importers.py`,
  `clipboard_guard.py` (copied secrets self-clear on a timer),
  `first_run.py`, `brand.py`.
- Sync/backup/pairing: `vaultsync.py`, `backup_pkg.py` (portable
  encrypted backup packages), `devices.py`, `pairings.py`,
  `extpair.py`, `native_host.py` (browser native-messaging host),
  `agents.py` + `mykey_mcp.py` (agent/MCP access surface — see
  `AGENT_ACCESS.md`, `EXTENSION_HOST.md`), `PASSKEYS.md` passkey
  entries handled per-entry.
- `licensing.py` — free-tier limits + signed licence-key verification
  (see Money surface). `tools/issue_licence.py` — manual licence
  issuance; `tools/stripe_issuer.py` — the order-to-licence issuer
  (see Money surface). `tests/` (21 modules) covers vault versions,
  recovery, licensing, passkeys, transport gates and the issuer.

## Trust boundaries

- **Zero-knowledge by construction (README/SECURITY.md):** the
  master password never leaves the device; vault data is encrypted
  locally (Argon2id + AES-256-GCM, named in README). There is no
  server component in this repo to trust — sync moves encrypted
  blobs through the user's OWN cloud folder, gated by device keys
  and key-value pairing (`SYNC_BACKUP.md` states the exact model
  and limitations).
- **Licence authority:** licence keys are signed statements verified
  against an embedded PUBLIC key in `licensing.py` (constants named
  `LICENCE_AUTHORITY_FINGERPRINT` / `LICENCE_PUBLIC_KEY_B64` —
  public material by design; values deliberately not reproduced
  here). The signing (private) side lives only in the issuer tools'
  custody environment, never in the app.
- **Agent surface is gated:** `agents.py` / `mykey_mcp.py` access is
  governed by the pairing + transport gates documented in
  `AGENT_ACCESS.md` and `docs/TRANSPORT_SECURITY.md` and covered by
  `tests/test_transport_gates.py`; passkeys are never included in
  agent bundles (README).
- **Blast radius:** `mykey.py` (vault format), `licensing.py`
  (entitlement verification) and `backup_pkg.py` / `vaultsync.py`
  (what leaves the machine, encrypted).

## Money surface

Exactly one money-adjacent path, and it is licence issuance — the
desktop app itself takes no payments:

- `tools/stripe_issuer.py` — polls paid orders recorded by the
  MyKey site Worker's webhook (orders KV, namespace referenced by
  the env NAME `MYKEY_ORDERS_KV_ID`), cross-checks each order
  against Stripe's API via the Stripe CLI (env NAME `STRIPE_CLI`;
  account referenced by the in-code constant NAME `STRIPE_ACCOUNT`
  — value deliberately not reproduced here), mints the buyer's
  signed MKLIC1 licence key, records it in the licence registry,
  handles revocations (`process_revoke`), and emails the key to the
  buyer (Gmail CLI, env NAME `GMAIL_CLI`). Covered by
  `tests/test_stripe_issuer.py`.
- `licensing.py` — the receiving side: free tier (50 passwords /
  4 connections) vs licensed (unlimited passwords / 20 connections);
  only the COUNT is capped — encryption, sync, backups and export
  are never gated (README, LICENCE.md).
- Checkout itself (Stripe-hosted Payment Links) lives in the
  separate `usemykey-site` repo, not here; this repo never sees or
  stores card details.

## How an agent should approach

1. Read `README.md`, `SECURITY.md`, `AGENT_ACCESS.md` and
   `SYNC_BACKUP.md`, then this profile, then the snapshot.
2. Treat every vault-adjacent change as security-critical: run the
   full `tests/` suite, and never log, print or commit secret
   material in the course of a change.
3. Names only, always: refer to keys, accounts and credentials by
   constant/env NAME in every artifact, exactly as this profile
   does. Regenerate this profile (below) at every material change.

## Regeneration

`docs/codetopo-profile/refresh.sh` (in this pack) re-downloads the repo
at a named ref, re-runs the index, and rewrites `snapshot.json`,
`stats.json` and the header block inputs of this profile. Regenerate at
every release / material change.
