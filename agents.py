# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Authorized-agent access (Phase 2A) — the second principal.

The product serves two principals: the human (master password /
biometric / recovery) and an *authorized agent*. Agent authorization
is a key-value pair on the app, exactly as the owner specified:

    agents = {
        "<agent-id>": {
            "token_hash":  sha256 hex of the token (never the token),
            "scopes":      ["list", "get:github", "get:tag:dev", ...],
            "created_at":  unix time,
            "expires_at":  unix time or null,
            "enabled":     bool,
            "last_used_at": unix time or null,
        },
        ...
    }

The registry lives inside the AES-256-GCM encrypted vault payload,
so scopes and token hashes cannot be read or edited on disk without
the vault key. Enrollment also adds a wrapped-key slot
(``agent:<id>``) to the Vault v2 header: the agent token derives an
Argon2id wrapping key that unwraps the vault key in-process, and
scope is enforced on every call. Revocation deletes both the pair
and the slot — access dies immediately and permanently, because the
slot (the only way the token can unwrap anything) is gone.

Rules enforced here:

* ONLY a human session (vault unlocked by master/recovery) can
  enroll, scope, disable, enable or revoke an agent.
* An agent never sees the master password, never exports, never
  deletes, never imports, never touches recovery or other agents.
* ``get`` returns a password only for entries the agent's scopes
  cover (``get:<service>`` exact, ``get:tag:<tag>``, or ``get:*``
  when the human explicitly granted it). ``list`` returns metadata
  only — never passwords, notes or TOTP secrets. TOTP secrets are
  never returned to agents at all.
* ``write`` (add/update entries) exists only when the human
  explicitly granted the ``write`` scope.
* Bad-token attempts are rate-limited with a persistent lockout
  (sidecar guard file). The token itself is 256-bit random, so this
  is defence in depth, not the primary barrier.
* Every authentication and every access (allow AND deny) appends to a
  hash-chained audit log (the house trust primitive: sha256 chain
  over canonical records). The chain head is also stored inside the
  encrypted payload, so truncating the log is detectable on the next
  successful unlock.
"""

import base64
import contextlib
import functools
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
import urllib.parse

from mykey import MyKey, MyKeyError, VaultCorrupt, VaultMissing, WrongPassword, make_entry

_TOKEN_PREFIX = "mkag1"
_AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_ARGON = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
_DEFAULT_MAX_FAILURES = 5
_DEFAULT_LOCKOUT_SECONDS = 300
_METADATA_FIELDS = ("service", "username", "url", "tags", "favourite",
                    "created", "updated")


class AgentAuthError(MyKeyError):
    """Agent authentication failed (bad, unknown, disabled, expired)."""


class AgentLockedError(AgentAuthError):
    """Too many bad attempts — this agent id is temporarily locked."""


class AgentScopeError(MyKeyError):
    """The agent is authenticated but its scopes do not allow this."""


# --------------------------------------------------------------------------
# per-vault cross-process lock + backup sync
# --------------------------------------------------------------------------

@contextlib.contextmanager
def vault_lock(vault_path, timeout=15.0, stale_after=60.0):
    """Serialize vault/audit/guard mutations across processes.

    Atomic-create lockfile with a stale timeout. This narrows (it
    cannot fully close, in a local-file design) the read-modify-write
    races the threat review flagged between concurrent agent
    processes and human operations.
    """
    lock_path = vault_path + ".lock"
    deadline = time.time() + timeout
    fd = None
    while fd is None:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if time.time() - os.stat(lock_path).st_mtime > stale_after:
                    os.unlink(lock_path)
                    continue
            except OSError:
                pass
            if time.time() > deadline:
                raise AgentAuthError("vault is busy — another process holds it")
            time.sleep(0.05)
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        fd = None
        yield
    finally:
        try:
            os.unlink(lock_path)
        except OSError:
            pass


def _locked(fn):
    """Run the function under the per-vault cross-process lock."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        target = args[0] if args else None
        path = (getattr(target, "vault_file", None)
                or getattr(getattr(target, "_vault", None), "vault_file", None)
                or (target if isinstance(target, str) else None))
        if path is None:
            return fn(*args, **kwargs)
        with vault_lock(path):
            return fn(*args, **kwargs)
    return wrapper


def _sync_backup(vault_path):
    """Make the rolling backup byte-identical to the current vault.

    Without this, the pre-change vault (with a just-revoked agent's
    slot, or a just-disabled agent still enabled) lingers in the
    .bak file, where a copied backup + token would still open it.
    Registry/security changes therefore sync the backup forward.
    """
    backup = vault_path + ".bak"
    if os.path.exists(backup) and os.path.exists(vault_path):
        with open(vault_path, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
        os.chmod(backup, 0o600)


# --------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _build_token(agent_id: str, raw: bytes) -> str:
    secret = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{_TOKEN_PREFIX}.{agent_id}.{secret}"


def parse_token(token):
    """Return (agent_id, raw_secret_bytes) or raise AgentAuthError."""
    if not isinstance(token, str) or not token:
        raise AgentAuthError("invalid agent token")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _TOKEN_PREFIX or not _AGENT_ID_RE.match(parts[1]):
        raise AgentAuthError("invalid agent token")
    try:
        raw = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except Exception as exc:
        raise AgentAuthError("invalid agent token") from exc
    if len(raw) != 32:
        raise AgentAuthError("invalid agent token")
    return parts[1], raw


def validate_scopes(scopes):
    scopes = list(scopes or [])
    for scope in scopes:
        if scope in ("list", "write", "get:*"):
            continue
        if scope.startswith("get:") and scope[4:]:
            continue
        raise ValueError(f"invalid agent scope: {scope!r}")
    return scopes


# --------------------------------------------------------------------------
# audit log — append-only JSONL, hash-chained
# --------------------------------------------------------------------------

def audit_path_for(vault_path: str) -> str:
    return vault_path + ".audit.jsonl"


def _chain_hash(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def _read_audit_records(path):
    if not os.path.exists(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def append_audit(vault_path, agent, action, service, result, reason=""):
    """Append one record; returns the new chain head hash."""
    path = audit_path_for(vault_path)
    records = _read_audit_records(path)
    prev = records[-1]["hash"] if records else ""
    record = {
        "ts": int(time.time()),
        "agent": agent,
        "action": action,
        "service": service or "",
        "result": result,
        "reason": reason or "",
        "prev": prev,
    }
    record["hash"] = _chain_hash(prev, {k: v for k, v in record.items() if k != "hash"})
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".audit-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for old in records:
                f.write(json.dumps(old, sort_keys=True) + "\n")
            f.write(json.dumps(record, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return record["hash"]


def verify_audit(vault_path, expected_head=None):
    """Recompute the chain. Returns dict(ok, count, head, error)."""
    path = audit_path_for(vault_path)
    try:
        records = _read_audit_records(path)
    except Exception as exc:
        return {"ok": False, "count": 0, "head": "", "error": f"unreadable: {exc}"}
    prev = ""
    for rec in records:
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("prev") != prev or rec.get("hash") != _chain_hash(prev, body):
            return {"ok": False, "count": len(records), "head": prev,
                    "error": "chain broken — a record was edited or removed"}
        prev = rec["hash"]
    if expected_head and prev != expected_head:
        return {"ok": False, "count": len(records), "head": prev,
                "error": "chain head does not match the head sealed in the vault "
                         "(log may have been truncated)"}
    return {"ok": True, "count": len(records), "head": prev, "error": ""}


def read_audit(vault_path):
    return _read_audit_records(audit_path_for(vault_path))


@_locked
def reset_audit(vault: MyKey):
    """Human recovery for a broken audit chain.

    Archives the suspect log next to the vault (never deletes it),
    clears the sealed head, and starts a fresh chain whose first
    record documents the reset. Returns the archive path or None.
    """
    _require_human_vault(vault)
    path = audit_path_for(vault.vault_file)
    archive = None
    if os.path.exists(path):
        archive = f"{path}.suspect-{int(time.time())}"
        os.replace(path, archive)
        os.chmod(archive, 0o600)
    vault._audit_head = ""
    vault._persist()
    head = append_audit(vault.vault_file, "human", "audit-reset", "",
                        "allow", f"previous log archived: {archive}")
    vault._audit_head = head
    vault._persist()
    return archive


# --------------------------------------------------------------------------
# rate-limit guard (persistent sidecar; defence in depth)
# --------------------------------------------------------------------------

class AgentGuard:
    def __init__(self, vault_path, max_failures=_DEFAULT_MAX_FAILURES,
                 lockout_seconds=_DEFAULT_LOCKOUT_SECONDS):
        self.path = vault_path + ".agentguard.json"
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, state):
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".guard-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def is_locked(self, agent_id):
        rec = self._load().get(agent_id) or {}
        return float(rec.get("locked_until") or 0) > time.time()

    def record_failure(self, agent_id):
        state = self._load()
        rec = state.get(agent_id) or {"failures": 0, "locked_until": 0}
        rec["failures"] = int(rec.get("failures") or 0) + 1
        if rec["failures"] >= self.max_failures:
            rec["locked_until"] = time.time() + self.lockout_seconds
            rec["failures"] = 0
        state[agent_id] = rec
        self._save(state)
        return float(rec.get("locked_until") or 0) > time.time()

    def reset(self, agent_id):
        state = self._load()
        if agent_id in state:
            del state[agent_id]
            self._save(state)


# --------------------------------------------------------------------------
# human-side registry management (human principal ONLY)
# --------------------------------------------------------------------------

def _require_human_vault(vault: MyKey):
    vault._require_unlocked()
    vault._require_human("manage agents")


@_locked
def enroll_agent(vault: MyKey, agent_id, scopes, expires_days=None):
    """Enroll an agent. Returns the token — shown ONCE, never stored."""
    _require_human_vault(vault)
    if not _AGENT_ID_RE.match(agent_id or ""):
        raise ValueError("agent id must be 1–32 chars: [a-z0-9-], starting alphanumeric")
    scopes = validate_scopes(scopes)
    if agent_id in vault._agents:
        raise ValueError(f"agent already enrolled: {agent_id}")
    raw = secrets.token_bytes(32)
    token = _build_token(agent_id, raw)
    salt = os.urandom(16)
    wrapping = MyKey._derive_with_secret(raw, salt, "argon2id", _ARGON)
    # add_wrapped_slot persists slots; the registry write below persists
    # again with the matching record — the two are a pair.
    vault.add_wrapped_slot(f"agent:{agent_id}", wrapping,
                           {"salt": base64.b64encode(salt).decode(), **_ARGON})
    now = int(time.time())
    vault._agents[agent_id] = {
        "token_hash": _token_hash(token),
        "scopes": scopes,
        "created_at": now,
        "expires_at": (now + int(expires_days) * 86400) if expires_days else None,
        "enabled": True,
        "last_used_at": None,
    }
    vault._persist()
    return token


@_locked
def revoke_agent(vault: MyKey, agent_id):
    """Delete the key-value pair AND the wrapped slot. Access dies now."""
    _require_human_vault(vault)
    if agent_id not in vault._agents:
        raise KeyError(f"no such agent: {agent_id}")
    del vault._agents[agent_id]
    vault._persist()
    vault.remove_wrapped_slot(f"agent:{agent_id}")
    _sync_backup(vault.vault_file)


@_locked
def set_agent_enabled(vault: MyKey, agent_id, enabled: bool):
    _require_human_vault(vault)
    if agent_id not in vault._agents:
        raise KeyError(f"no such agent: {agent_id}")
    vault._agents[agent_id]["enabled"] = bool(enabled)
    vault._persist()
    _sync_backup(vault.vault_file)


@_locked
def set_agent_scopes(vault: MyKey, agent_id, scopes):
    _require_human_vault(vault)
    if agent_id not in vault._agents:
        raise KeyError(f"no such agent: {agent_id}")
    vault._agents[agent_id]["scopes"] = validate_scopes(scopes)
    vault._persist()
    _sync_backup(vault.vault_file)


def list_agents(vault: MyKey):
    """Registry metadata for the human. Token hashes are never shown."""
    _require_human_vault(vault)
    out = []
    for agent_id, rec in sorted(vault._agents.items()):
        out.append({
            "agent_id": agent_id,
            "scopes": list(rec.get("scopes") or []),
            "created_at": rec.get("created_at"),
            "expires_at": rec.get("expires_at"),
            "enabled": bool(rec.get("enabled")),
            "last_used_at": rec.get("last_used_at"),
        })
    return out


# --------------------------------------------------------------------------
# agent-side session
# --------------------------------------------------------------------------

def _scope_covers(scopes, entry):
    for scope in scopes:
        if scope == "get:*":
            return True
        if scope.startswith("get:tag:"):
            if scope[len("get:tag:"):] in (entry.get("tags") or []):
                return True
        elif scope.startswith("get:"):
            if scope[4:] == entry.get("service"):
                return True
    return False


def _sanitize_url(url):
    """Strip anything secret-shaped from a URL for metadata listing:
    userinfo, query and fragment (fleet review, finding 8 — a URL
    can carry tokens or signed parameters)."""
    if not url:
        return url
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        netloc = host + (f":{parts.port}" if parts.port else "")
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return ""


class AgentSession:
    """An authenticated agent's scoped, audited view of a vault.

    A session is a snapshot taken at authentication time. Revocation,
    disable and scope changes are enforced at the next
    ``open_agent_session`` — long-lived embedders (the MCP server)
    therefore re-authenticate on every operation rather than holding
    a session open.
    """

    def __init__(self, vault: MyKey, agent_id, scopes):
        self._vault = vault
        self.agent_id = agent_id
        self.scopes = list(scopes)

    # internal ------------------------------------------------------------
    def _audit(self, action, service, result, reason=""):
        head = append_audit(self._vault.vault_file, self.agent_id,
                            action, service, result, reason)
        self._vault._audit_head = head
        self._vault._persist()

    def _visible(self, entry):
        return "list" in self.scopes or _scope_covers(self.scopes, entry)

    # public API ------------------------------------------------------------
    @_locked
    def list_metadata(self):
        out = []
        for e in self._vault.list_entries():
            if not self._visible(e):
                continue
            meta = {k: (list(e[k]) if k == "tags" else e[k])
                    for k in _METADATA_FIELDS}
            meta["url"] = _sanitize_url(meta.get("url") or "")
            out.append(meta)
        self._audit("list", "", "allow", f"{len(out)} entries visible")
        return out

    @_locked
    def get(self, service, username=None):
        try:
            entry = self._vault.get_entry(service, username)
        except KeyError:
            self._audit("get", service, "deny", "not found")
            raise
        if not _scope_covers(self.scopes, entry):
            self._audit("get", service, "deny", "scope")
            raise AgentScopeError(
                f"agent {self.agent_id} has no get scope for {service}")
        self._audit("get", service, "allow")
        result = dict(entry)
        result.pop("totp_secret", None)  # TOTP secrets never leave to agents
        return result

    @_locked
    def add_entry(self, entry):
        service = (entry or {}).get("service", "")
        if "write" not in self.scopes:
            self._audit("add", service, "deny", "no write scope")
            raise AgentScopeError("agent has no write scope")
        try:
            record = self._vault.add_entry(make_entry(**{
                k: entry[k] for k in
                ("service", "username", "password", "url", "notes", "tags",
                 "favourite") if k in entry
            }))
        except Exception:
            self._audit("add", service, "deny", "rejected by vault")
            raise
        self._audit("add", service, "allow")
        return record


def _blank_vault(vault_path):
    inst = MyKey.__new__(MyKey)
    inst.vault_file = vault_path
    inst.secret_input = ""
    inst.algo = "argon2id"
    inst._vault_key = None
    inst._entries = None
    inst._slots = None
    inst._legacy = False
    inst._agents = {}
    inst._audit_head = ""
    inst._principal = None
    return inst


@_locked
def open_agent_session(vault_path, token, guard=None):
    """Authenticate an agent token and return an AgentSession.

    The token unwraps the vault key via the agent's wrapped slot;
    registry checks (hash, enabled, expiry) run inside the decrypted
    payload. Every outcome — allow and deny — is audit-logged.
    """
    guard = guard or AgentGuard(vault_path)
    try:
        agent_id, raw = parse_token(token)
    except AgentAuthError:
        append_audit(vault_path, "unknown", "auth", "", "deny", "malformed token")
        raise
    if guard.is_locked(agent_id):
        append_audit(vault_path, agent_id, "auth", "", "deny", "locked out")
        raise AgentLockedError(f"agent {agent_id} is locked out — try later")

    def deny(reason, exc):
        guard.record_failure(agent_id)
        append_audit(vault_path, agent_id, "auth", "", "deny", reason)
        raise exc

    vault = _blank_vault(vault_path)
    try:
        slot = vault.get_slot(f"agent:{agent_id}")
    except VaultMissing:
        deny("vault missing", AgentAuthError("vault unavailable"))
    except VaultCorrupt:
        deny("vault corrupt", AgentAuthError("vault unavailable"))
    if slot is None:
        deny("unknown agent", AgentAuthError("unknown agent"))
    try:
        salt = base64.b64decode(slot["salt"])
        params = {k: slot[k] for k in ("time_cost", "memory_cost", "parallelism")
                  if k in slot}
        # Parameter floor (fleet-generated test idea): a header
        # edited down to trivial KDF parameters is rejected outright
        # rather than honoured.
        if (int(params.get("time_cost", 0)) < 2
                or int(params.get("memory_cost", 0)) < 32768
                or int(params.get("parallelism", 0)) < 1):
            raise ValueError("slot KDF parameters below floor")
        wrapping = MyKey._derive_with_secret(raw, salt, "argon2id", params)
    except Exception:
        deny("slot damaged", AgentAuthError("agent credential damaged"))
    try:
        vault.unlock_via_wrapped_key(f"agent:{agent_id}", wrapping,
                                     principal=f"agent:{agent_id}")
    except WrongPassword:
        deny("bad token", AgentAuthError("agent token does not match"))
    except VaultCorrupt:
        deny("vault corrupt", AgentAuthError("vault unavailable"))

    record = vault._agents.get(agent_id)
    if record is None:
        deny("slot without registry entry",
             AgentAuthError("agent is not enrolled"))
    if not hmac.compare_digest(record.get("token_hash", ""), _token_hash(token)):
        deny("token hash mismatch", AgentAuthError("agent token does not match"))
    if not record.get("enabled", False):
        deny("disabled", AgentAuthError(f"agent {agent_id} is disabled"))
    expires = record.get("expires_at")
    if expires and int(time.time()) > int(expires):
        deny("expired", AgentAuthError(f"agent {agent_id} token has expired"))

    sealed = vault._audit_head
    if sealed:
        check = verify_audit(vault_path, expected_head=sealed)
        if not check["ok"]:
            # NEVER append to or re-seal a suspect chain (fleet threat
            # review, finding 1): that would launder the tampered log
            # into the new trusted baseline. The suspect file is
            # preserved untouched for the human, who recovers with
            # reset_audit() (CLI: agent-audit-reset).
            raise AgentAuthError(
                "audit log integrity failure — a human must inspect this vault")

    guard.reset(agent_id)
    record["last_used_at"] = int(time.time())
    session = AgentSession(vault, agent_id, record.get("scopes") or [])
    head = append_audit(vault_path, agent_id, "auth", "", "allow")
    vault._audit_head = head
    vault._persist()
    return session
