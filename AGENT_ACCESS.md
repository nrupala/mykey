# Authorized-agent access (Phase 2B) — the reference implementation

MyKey is the **first product built to the universal access standard**:
every product exposes, as needed, five access modes — HUMAN,
MACHINE, AGENT, SOFTWARE and API — and wherever agent access exists,
authorization is the key-value pair pattern defined here. This page
is the reference other products copy: how authorization works, what
an agent can and cannot do, and the known limits, stated plainly.

Implementation: `agents.py` + the Vault v3 engine in `mykey.py`
(proprietary core); surfaces in `mykey_cli.py` and `mykey_mcp.py`
(Apache 2.0 interface layer). See `LICENSING.md` for the licence map.

## The five surfaces in MyKey

| Mode | Surface | Who uses it |
|---|---|---|
| HUMAN | Desktop app + human CLI commands (master password / recovery) | The owner |
| MACHINE | CLI automation surface: `agent-get` / `agent-list` with the token read only from the `MYKEY_AGENT_KEY` environment variable | Scripts, CI, scheduled jobs |
| AGENT | Stdio MCP server (`mykey_mcp.py`) exposing `mykey_list` / `mykey_get` | AI agents (MCP clients) |
| SOFTWARE | The importable Python package: `MyKey` engine + `agents` module (`open_agent_session`, `AgentSession`) for embedding in other software | Other programs |
| API | The documented local interface: this page + the CLI/MCP contracts above. Local only — MyKey is an offline product, so there is no network listener by design | Integrators |

## How authorization works

Agent authorization is a key-value pair on the app:

```
agents = {
  "<agent-id>": { token_hash, scopes, created_at, expires_at,
                  enabled, last_used_at, + key material },
  ...
}
```

Vault v3 is envelope encryption **with per-entry key partitioning**:

* The **core** (agent registry, metadata key, every entry's data
  keys, the audit seal) is encrypted under the vault key. Only the
  master-password and recovery slots wrap the vault key.
* Every entry is encrypted separately: metadata under the vault
  metadata key, the secret fields (password, notes) under a
  **per-entry key**, and the TOTP secret under its own per-entry
  key that is *never* placed in any agent bundle.
* An agent slot wraps only that agent's random **bundle key** —
  never the vault key. The **bundle** (re-issued by the human side
  on every save) carries exactly what the agent's scopes allow:
  the metadata key when it holds `list`, and the secret keys of
  in-scope entries only. **Scope is enforced cryptographically**:
  a token holder who also has the vault file and runs modified
  code cannot decrypt out-of-scope entries — the keys are not in
  the bundle. (Verified by tests that attack the file with raw
  crypto: `tests/test_vault_v3.py`.)
* Enrollment (human only, vault unlocked) generates a 256-bit
  token, shown **once**: `mkag1.<agent-id>.<secret>`. The vault
  stores only the token's SHA-256. Expiry and enablement are bound
  into the bundle at issue; sessions re-open the bundle from the
  live file on **every** operation, so revocation, disable and
  scope changes apply on the very next call — even inside a
  long-lived MCP process.
* **Revocation, disable and scope narrowing rotate keys.** The
  affected entries are re-encrypted under fresh keys (and the
  metadata key rotates when `list` is involved), so a previously
  issued bundle goes stale against the live vault. Disabling is
  therefore cryptographic on the live file, not just a flag;
  re-enabling re-issues a bundle under the same token.
* Expired tokens are refused immediately by the shipped clients,
  and the enrollment is **retired with key rotation at the next
  human unlock**, after which the token is cryptographically dead
  on the live file.
* Agent writes are **insert-only through a pending path**: the
  agent seals the new entry to the vault's inbox public key
  (which its bundle authenticates) with an author MAC binding the
  agent, the vault and the contents. The human's next unlock
  verifies and accepts it — a submission that would overwrite an
  existing entry, fails its MAC, or fails to decrypt is left
  unprocessed for the human to inspect, never silently trusted
  and never silently dropped. Vault, audit and guard updates are
  serialized across processes with a per-vault lockfile, and the
  core stores a hash of every committed entry's ciphertexts:
  changing a committed record outside a human session is detected
  at the next human unlock.

## Scopes

| Scope | Allows |
|---|---|
| `list` | Entry metadata (service, username, sanitized url, tags) — never passwords, notes or TOTP secrets. URL userinfo, query and fragment are stripped: a URL can carry secrets. |
| `get:<service>` | Read that one entry's password |
| `get:tag:<tag>` | Read passwords of entries carrying that tag |
| `get:*` | Read any entry (grant deliberately) |
| `write` | Add entries — insert-only, via the pending path; an agent can never overwrite an existing entry |

An agent can **never**: export, delete, import, change the master
password, manage recovery, or manage agents. TOTP secrets are
stripped from every agent response — there is no scope for them.
From the agent surfaces, a missing entry and an out-of-scope entry
are indistinguishable (without `list`, the agent holds no metadata
key, so this is a cryptographic property, not just presentation);
the audit log keeps the detailed reason for the human. A bundle
does carry the metadata of the entries it may read — an agent
authorized to read an entry's password can see that entry's
service name, username and tags.

## Audit

Every authentication and every access — allow and deny — appends
to a hash-chained log at `<vault>.audit.jsonl` (mode 0600).
Authenticated records are additionally **MAC'd with their author's
key** (per-agent keys live in the bundle and the core; the human's
key derives from the vault key), so a file editor who rewrites the
unkeyed chain still cannot forge authenticated history. Three
witnesses protect the chain:

* the **seal**: the chain head stored inside the encrypted core on
  every human save — at human unlock the sealed head must still be
  in the chain, so a rollback behind the seal is refused, never
  re-sealed over;
* the **anchor**: `<vault>.audit-anchor.json`, an HMAC checkpoint
  (key derived from the vault key) written at human unlocks and
  saves — editing or forging it needs the vault key, rolling the
  log back behind it is detected, and rolling log + anchor back
  together is caught by the seal whenever the vault file itself is
  current;
* the chain itself, verified before every agent session opens:
  a suspect chain is **never** appended to or re-sealed — it is
  preserved untouched for the human, who recovers with
  `agent-audit-reset` (the suspect files are quarantined beside
  the vault, never deleted).

Bad-token attempts are throttled with **progressive backoff**
(sidecar guard file): each failure doubles the no-retry window
(5s, 10s, 20s, … capped at 15 minutes). Attempts inside a window
are refused without extending it and without appending to the log
(they are counted and the count is flushed into the next
authenticated record). The legitimate agent is delayed, never
locked out; a successful human unlock clears the guard instantly.

## If something goes wrong (human procedures)

* **Audit chain / anchor failure at unlock:** inspect with
  `agent-audit`. To recover, `mykey agent-audit-reset` quarantines
  the suspect log and anchor beside the vault (never deletes
  them) and starts a fresh chain.
* **Token may have leaked, or a vault copy may be out:**
  revoke the agent (keys rotate on the live vault), or
  `mykey rotate-vault-key` to re-key *everything* — new vault
  key, new metadata key, new per-entry keys, every slot except
  the master retired, agents and recovery dropped for re-setup,
  rolling backup deleted. The master password does not change.
* **Migrating from Vault v2:** the first human unlock migrates
  the vault, keeps a pre-migration backup with the agent slots
  stripped (`<vault>.v2.bak`), rotates the vault key (v2 agent
  slots wrapped the vault key itself), retires all agent
  enrollments for re-enrollment, and — when migrating with the
  master password — retires the recovery phrase for re-setup
  (migrating with the recovery phrase preserves it).

## Known limits (stated plainly)

* **Revocation cannot claw back copies.** If someone saved an
  earlier vault file (or a bundle extracted from it), that copy
  still opens with its old key material — the same truth as a
  changed master password and an old backup. Key rotation
  protects the *live* vault. Protect vault files like the
  secrets they are. This is inherent to offline files, not a
  defect a future version can remove.
* **Pre-migration (v2) copies are v2-trusted.** A vault copy saved
  before the v3 migration still follows v2 rules: its agent
  tokens unwrap its vault key. Migration cannot retroactively
  change copies that already left; the stripped-slot migration
  backup is the only copy this product creates on purpose.
* **Post-seal audit tail freshness.** Records appended after the
  last human visit, then deleted before the next one, leave no
  trace the next unlock can detect: the chain and MACs make
  *forged or edited* history detectable, and everything up to the
  last seal/anchor is rollback-proof, but an offline file has no
  witness for events between human visits beyond the anchor.
  Keeping any newer anchor copy elsewhere (it is ~200 bytes and
  contains no secrets) detects a full rollback of vault + log +
  anchor to one consistent old snapshot, which is otherwise
  undetectable from those files alone.
* **Expiry is policy until retirement.** Between an agent's
  expiry time and the next human unlock, the shipped clients
  refuse the token, but a saved bundle + saved file copy can
  still decrypt what they could before expiry. At the next human
  unlock the enrollment is retired with key rotation.
* **The backoff guard is a sidecar file.** Deleting it resets
  the failure counters, and it only throttles attempts made
  through the shipped clients on this machine. Offline guessing
  against a copied slot is bounded by Argon2id and the token's
  256 bits — the guard is defence in depth, not the barrier.
* **Agent ids are visible** as slot ids and bundle keys in the
  vault header (the same class of metadata as the `master` /
  `recovery` slot ids); plaintext entry ids reveal the number of
  entries. Scopes, hashes and entry contents are not visible.
* **Agent-written entries appear at the next human unlock** (the
  pending path above); the writing agent can read its own
  submission back within the same session.
