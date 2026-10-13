# Authorized-agent access (Phase 2A) — the reference implementation

MyKey is the **first product built to the universal access standard**:
every product exposes, as needed, five access modes — HUMAN,
MACHINE, AGENT, SOFTWARE and API — and wherever agent access exists,
authorization is the key-value pair pattern defined here. This page
is the reference other products copy: how authorization works, what
an agent can and cannot do, and the known limits, stated plainly.

Implementation: `agents.py` (proprietary core); surfaces in
`mykey_cli.py` and `mykey_mcp.py` (Apache 2.0 interface layer). See
`LICENSING.md` for the licence map.

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
                  enabled, last_used_at },
  ...
}
```

* The registry lives **inside the encrypted vault payload** — scopes
  and token hashes cannot be read or edited on disk without the
  vault key. Only the slot id (`agent:<id>`) is header metadata.
* Enrollment (human only, vault unlocked) generates a 256-bit token,
  shown **once**: `mkag1.<agent-id>.<secret>`. The vault stores only
  the token's SHA-256, plus a wrapped-key slot: the token derives an
  Argon2id wrapping key that unwraps the vault key in-process, with
  the registry's hash, enabled flag and expiry re-checked after
  unwrap on every authentication.
* **Revocation deletes the pair and the slot, and syncs the rolling
  backup forward**, so the live vault (and its backup) refuse the
  token immediately. Disable and expiry are checked on every
  authentication; the MCP server re-authenticates on **every** tool
  call, so revocation applies on the next call even in a long-lived
  process.
* Vault, audit and guard updates are serialized across processes
  with a per-vault lockfile.

## Scopes

| Scope | Allows |
|---|---|
| `list` | Entry metadata (service, username, sanitized url, tags) — never passwords, notes or TOTP secrets. URL userinfo, query and fragment are stripped: a URL can carry secrets. |
| `get:<service>` | Read that one entry's password |
| `get:tag:<tag>` | Read passwords of entries carrying that tag |
| `get:*` | Read any entry (grant deliberately) |
| `write` | Add entries — insert-only; an agent can never overwrite an existing entry |

An agent can **never**: export, delete, import, change the master
password, manage recovery, or manage agents. TOTP secrets are
stripped from every agent response — there is no scope for them.
From the agent surfaces, a missing entry and an out-of-scope entry
are indistinguishable (no existence oracle); the audit log keeps the
detailed reason for the human.

## Audit

Every authentication and every access — allow and deny — appends to
a hash-chained log at `<vault>.audit.jsonl` (mode 0600). The chain
head is also sealed inside the encrypted vault payload, and is
verified before every agent session opens: truncating, editing or
reordering the log is detected, the session is refused, and the
suspect chain is **never** re-sealed — it is preserved untouched for
the human. `mykey agent-audit` prints the log and verifies the
chain.

Bad-token attempts are rate-limited: 5 failures for an agent id
locks that id for 5 minutes (persistent sidecar guard file).

## If something goes wrong (human procedures)

* **Audit chain broken:** inspect with `agent-audit`. To recover,
  `mykey agent-audit-reset` archives the suspect log beside the
  vault (never deletes it) and starts a fresh chain.
* **Token may have leaked, or a vault copy may be out:**
  `mykey rotate-vault-key` re-keys the vault — new data key, every
  slot except the master retired, agents and recovery dropped for
  re-setup, rolling backup deleted. The master password does not
  change.

## Known limits (stated plainly)

* **Scope is enforced in-process, not cryptographically.** A token
  unwraps the vault key; a token holder who also has the vault file
  and runs *modified* code can decrypt the whole payload — scopes
  bind honest agent software and the shipped surfaces, and the
  audit log + revocation are the controls around them.
  Cryptographic per-entry partitioning is future work.
* **Revocation cannot claw back copies.** If someone saved an
  earlier vault file, that copy still opens with its old token —
  the same truth as a changed master password and an old backup.
  `rotate-vault-key` protects the live vault; protect vault files
  like the secrets they are.
* **Rollback of vault + audit log together** (restoring both from
  the same backup) is not detectable locally; detecting it needs an
  external anchor, which an offline product does not have.
* **A session is a snapshot.** Code embedding `AgentSession`
  directly should re-open it per operation (the MCP server does).
* **The lockout guard is a sidecar file.** Deleting it resets the
  failure counter. The primary barrier is the 256-bit token.
  Agent ids are visible as slot ids in the vault header, so a local
  attacker who knows an id can lock that id out for 5 minutes at a
  time (a nuisance denial of service; the human can re-enroll under
  a new id).
* **Agent ids are visible** as slot ids in the vault header (the
  same class of metadata as the `master` / `recovery` slot ids).
  Scopes, hashes and entry data are not.
