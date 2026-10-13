# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Authorized-agent access (Phase 2B) — the second principal.

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
            + key material (bundle/MAC keys) — core-encrypted only,
        },
        ...
    }

The registry lives inside the AES-256-GCM encrypted vault **core**
(Vault v3), so scopes, token hashes and key material cannot be read
or edited on disk without the vault key. Enrollment adds a
wrapped-key slot (``agent:<id>``) to the header — but in v3 the slot
wraps only the agent's random **bundle key**, never the vault key.
The bundle (re-issued by the human side on every save) carries
exactly what the agent's scopes allow: the metadata key when it
holds `list`, and the per-entry secret keys (DEKs) of in-scope
entries only. Scope is therefore enforced *cryptographically*: a
token holder with the file and modified code cannot decrypt
out-of-scope entries, because those keys are not in the bundle.

Revocation, disable and scope narrowing are equally cryptographic
on the live file: they rotate the affected entry keys (and the
metadata key when `list` is involved), so a previously issued
bundle goes stale. Nothing can claw back a vault *copy* saved
earlier — the same inherent truth as a changed master password and
an old backup; `rotate-vault-key` re-keys everything.

Rules enforced here:

* ONLY a human session (vault unlocked by master/recovery) can
  enroll, scope, disable, enable or revoke an agent.
* An agent never sees the master password, never exports, never
  deletes, never imports, never touches recovery or other agents.
  TOTP secrets are never in any bundle — there is no scope for them.
* `get` returns a password only for entries the agent's bundle
  carries a key for. `list` returns metadata only. `write` is
  insert-only and goes through the human-validated pending path:
  the agent seals the new entry to the vault's inbox key with an
  author MAC; the human's next unlock accepts or leaves it.
* Bad-token attempts are throttled with **progressive backoff**
  (sidecar guard): each failure doubles the no-retry window up to a
  cap, attempts inside the window are refused without extending it,
  and a successful human unlock clears the guard instantly. The
  legitimate agent is delayed, never locked out; brute force
  through the shipped clients stays throttled. (Offline guessing
  against a copied file is bounded by Argon2id and the 256-bit
  token, not by this guard — see AGENT_ACCESS.md.)
* Every authentication and access appends to a hash-chained,
  MAC-authenticated audit log; the head is sealed in the core on
  human saves and checkpointed into a human-keyed anchor file.
"""

import base64
import contextlib
import functools
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import tempfile
import time
import urllib.parse
import uuid

from mykey import (
    MAX_PENDING_ENTRIES,
    MAX_SEALED_BLOB_BYTES,
    AuditAnchorError,
    MyKey,
    MyKeyError,
    VaultCorrupt,
    VaultMissing,
    WrongPassword,
    _aad,
    _b64d,
    _b64e,
    _dec,
    _enc,
    audit_chain_hash,
    audit_chain_state,
    make_entry,
    read_audit_records,
    seal_to_inbox,
)

_TOKEN_PREFIX = "mkag1"
_AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_ARGON = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
_DEFAULT_BACKOFF_BASE_SECONDS = 5.0
_DEFAULT_BACKOFF_CAP_SECONDS = 900.0
_METADATA_FIELDS = ("service", "username", "url", "tags", "favourite",
                    "created", "updated", "android_app")


class AgentAuthError(MyKeyError):
    """Agent authentication failed (bad, unknown, disabled, expired)."""


class AgentLockedError(AgentAuthError):
    """Progressive backoff is active for this agent id."""


class AgentScopeError(MyKeyError):
    """The agent is authenticated but its scopes do not allow this."""


# --------------------------------------------------------------------------
# per-vault cross-process lock + backup sync
# --------------------------------------------------------------------------

@contextlib.contextmanager
def vault_lock(vault_path, timeout=15.0, stale_after=60.0):
    """Serialize vault/audit/guard mutations across processes."""
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
                or getattr(target, "_vault_path", None)
                or (target if isinstance(target, str) else None))
        if path is None:
            return fn(*args, **kwargs)
        with vault_lock(path):
            return fn(*args, **kwargs)
    return wrapper


def _sync_backup(vault_path):
    """Make the rolling backup byte-identical to the current vault."""
    backup = vault_path + ".bak"
    if os.path.exists(backup) and os.path.exists(vault_path):
        with open(vault_path, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
        os.chmod(backup, 0o600)


def _write_vault_file(vault_path, data):
    """Atomic 0600 write of a vault JSON document (agent-side saves)."""
    directory = os.path.dirname(os.path.abspath(vault_path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        if os.path.exists(vault_path):
            backup = vault_path + ".bak"
            with open(vault_path, "rb") as src, open(backup, "wb") as dst:
                dst.write(src.read())
            os.chmod(backup, 0o600)
        os.replace(tmp, vault_path)
        os.chmod(vault_path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_vault_file(vault_path):
    if not os.path.exists(vault_path):
        raise VaultMissing(f"no vault file at {vault_path}")
    try:
        with open(vault_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        raise VaultCorrupt(f"vault file is not readable JSON: {exc}") from exc
    if data.get("format") != "MKVLT":
        raise VaultCorrupt("not a MyKey vault file")
    if data.get("version") != 3:
        raise AgentAuthError(
            "this vault predates Vault v3 — a human must unlock it once "
            "to migrate it before agents can use it")
    return data


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
# audit log — append-only JSONL, hash-chained, MAC-authenticated
# --------------------------------------------------------------------------

def audit_path_for(vault_path: str) -> str:
    return vault_path + ".audit.jsonl"


def _record_mac(mac_key: bytes, record_hash: str) -> str:
    return hmac.new(mac_key, record_hash.encode(), hashlib.sha256).hexdigest()


def append_audit(vault_path, agent, action, service, result, reason="",
                 mac_key=None):
    """Append one record; returns the new chain head hash.

    Records appended with a MAC key (authenticated agent sessions,
    human operations) are tamper-evident individually, not just via
    the chain. Auth-*denial* records are appended without a MAC by
    design: at that point no key has been established.
    """
    path = audit_path_for(vault_path)
    records = read_audit_records(path)
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
    record["hash"] = audit_chain_hash(prev, record)
    if mac_key is not None:
        record["mac"] = _record_mac(mac_key, record["hash"])
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


def _mac_exempt(record):
    """Records that legitimately carry no MAC: malformed-token noise
    and auth denials (no key exists before authentication)."""
    if record.get("agent") == "unknown":
        return True
    return record.get("action") == "auth" and record.get("result") == "deny"


def verify_audit(vault_path, expected_head=None, mac_keys=None, mac_since=0):
    """Recompute the chain (and MACs, when keys are supplied).

    Returns dict(ok, count, head, error). With mac_keys (a human-side
    call), every non-exempt record at index >= mac_since must carry a
    valid MAC under its author's key — a file editor who rewrites the
    unkeyed chain still cannot forge authenticated records.
    """
    path = audit_path_for(vault_path)
    try:
        records = read_audit_records(path)
    except Exception as exc:
        return {"ok": False, "count": 0, "head": "", "error": f"unreadable: {exc}"}
    prev = ""
    for i, rec in enumerate(records):
        if rec.get("prev") != prev or rec.get("hash") != audit_chain_hash(prev, rec):
            return {"ok": False, "count": len(records), "head": prev,
                    "error": "chain broken — a record was edited or removed"}
        if mac_keys is not None and i >= mac_since and not _mac_exempt(rec):
            key = mac_keys.get(rec.get("agent", ""))
            if key is None:
                return {"ok": False, "count": len(records), "head": prev,
                        "error": f"record {i} has an unknown author "
                                 f"({rec.get('agent')!r}) — cannot verify"}
            if not hmac.compare_digest(rec.get("mac", ""),
                                       _record_mac(key, rec["hash"])):
                return {"ok": False, "count": len(records), "head": prev,
                        "error": f"record {i} failed MAC verification — "
                                 "it was forged or edited"}
        prev = rec["hash"]
    if expected_head and prev != expected_head:
        return {"ok": False, "count": len(records), "head": prev,
                "error": "chain head does not match the head sealed in the vault "
                         "(log may have been truncated)"}
    return {"ok": True, "count": len(records), "head": prev, "error": ""}


def read_audit(vault_path):
    return read_audit_records(audit_path_for(vault_path))


def human_audit_mac_key(vault: MyKey) -> bytes:
    return hmac.new(vault._vault_key, b"audit-mac-human-v3",
                    hashlib.sha256).digest()


def audit_mac_keys(vault: MyKey):
    """All MAC keys a human verifier needs, incl. retired agents'."""
    keys = {"human": human_audit_mac_key(vault)}
    for agent_id, rec in vault._agents.items():
        keys[agent_id] = _b64d(rec["audit_mac_key"])
    for agent_id, raw in vault._retired_audit_keys.items():
        keys[agent_id] = _b64d(raw)
    for agent_id in list(vault._agents) + list(vault._retired_audit_keys):
        keys[f"agent:{agent_id}"] = keys[agent_id]
    return keys


@_locked
def reset_audit(vault: MyKey):
    """Human recovery for a broken audit chain or anchor.

    Archives the suspect log next to the vault (never deletes it),
    clears the seal and anchor, and starts a fresh MAC'd chain whose
    first record documents the reset. Returns the archive path.
    """
    _require_human_vault(vault)
    path = audit_path_for(vault.vault_file)
    archive = None
    if os.path.exists(path):
        archive = f"{path}.suspect-{int(time.time())}"
        os.replace(path, archive)
        os.chmod(archive, 0o600)
    try:
        os.unlink(vault._anchor_path())
    except OSError:
        pass
    vault._audit_head = ""
    vault._audit_mac_since = 0
    vault._anchor_seq = 0
    vault._anchored_head = ""
    vault._persist()
    head = append_audit(vault.vault_file, "human", "audit-reset", "",
                        "allow", f"previous log archived: {archive}",
                        mac_key=human_audit_mac_key(vault))
    vault._audit_head = head
    vault._persist()
    return archive


# --------------------------------------------------------------------------
# progressive-backoff guard (persistent sidecar; defence in depth)
# --------------------------------------------------------------------------

class AgentGuard:
    """Per-agent progressive backoff.

    Failure n opens a no-retry window of min(base * 2^(n-1), cap).
    Attempts inside the window are refused WITHOUT incrementing the
    counter (spam cannot extend the window) but are counted, and the
    count is flushed into the audit log on the next authenticated
    append. Success resets the record; a human unlock deletes the
    whole guard file. This throttles guessing *through the shipped
    clients*; it is not the barrier against offline attacks on a
    copied file (Argon2id + a 256-bit token are).
    """

    def __init__(self, vault_path, base_seconds=_DEFAULT_BACKOFF_BASE_SECONDS,
                 cap_seconds=_DEFAULT_BACKOFF_CAP_SECONDS):
        self.path = vault_path + ".agentguard.json"
        self.base_seconds = float(base_seconds)
        self.cap_seconds = float(cap_seconds)

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

    def backoff_remaining(self, agent_id):
        rec = self._load().get(agent_id) or {}
        return max(0.0, float(rec.get("not_before") or 0) - time.time())

    def is_locked(self, agent_id):
        return self.backoff_remaining(agent_id) > 0

    def record_failure(self, agent_id):
        state = self._load()
        rec = state.get(agent_id) or {"failures": 0, "not_before": 0, "refusals": 0}
        rec["failures"] = int(rec.get("failures") or 0) + 1
        delay = min(self.base_seconds * (2 ** (rec["failures"] - 1)),
                    self.cap_seconds)
        rec["not_before"] = time.time() + delay
        state[agent_id] = rec
        self._save(state)
        return delay

    def record_refusal(self, agent_id):
        state = self._load()
        rec = state.get(agent_id) or {"failures": 0, "not_before": 0, "refusals": 0}
        rec["refusals"] = int(rec.get("refusals") or 0) + 1
        state[agent_id] = rec
        self._save(state)

    def pop_refusals(self, agent_id):
        state = self._load()
        rec = state.get(agent_id)
        if not rec:
            return 0
        n = int(rec.get("refusals") or 0)
        if n:
            rec["refusals"] = 0
            state[agent_id] = rec
            self._save(state)
        return n

    def reset(self, agent_id):
        state = self._load()
        if agent_id in state:
            del state[agent_id]
            self._save(state)


# --------------------------------------------------------------------------
# human-side registry management (human principal ONLY)
# --------------------------------------------------------------------------

def _require_human_vault(vault: MyKey):
    if not isinstance(vault, MyKey):
        # An AgentSession is not a vault handle at all in v3 — it
        # holds no vault key and exposes no management surface.
        raise PermissionError("agent sessions cannot manage agents")
    vault._require_unlocked()
    vault._require_human("manage agents")


def _validate_expires_days(expires_days):
    """Normalize an agent expiry: None (no expiry) or a whole
    number of days >= 1.

    0 is refused outright (issue #12): it used to fall through a
    falsy check and silently mint a NEVER-expiring token for an
    operator who asked for the shortest lifetime on the menu. On
    an authorization surface a typo must fail loud, not permanent —
    omitting the value is the only way to ask for no expiry, and
    negatives are refused rather than kept as a backdoor
    "already expired" test path.
    """
    if expires_days is None:
        return None
    if isinstance(expires_days, bool) or not isinstance(expires_days, int):
        raise ValueError("expiry must be a whole number of days or unset")
    if expires_days < 1:
        raise ValueError(
            "expiry must be at least 1 day — omit the flag for no expiry")
    return expires_days


@_locked
def enroll_agent(vault: MyKey, agent_id, scopes, expires_days=None):
    """Enroll an agent. Returns the token — shown ONCE, never stored."""
    _require_human_vault(vault)
    if not _AGENT_ID_RE.match(agent_id or ""):
        raise ValueError("agent id must be 1–32 chars: [a-z0-9-], starting alphanumeric")
    scopes = validate_scopes(scopes)
    expires_days = _validate_expires_days(expires_days)
    if agent_id in vault._agents:
        raise ValueError(f"agent already enrolled: {agent_id}")
    raw = secrets.token_bytes(32)
    token = _build_token(agent_id, raw)
    salt = os.urandom(16)
    wrapping = MyKey._derive_with_secret(raw, salt, "argon2id", _ARGON)
    bundle_key = os.urandom(32)
    slot = MyKey._wrap_key_slot(f"agent:{agent_id}", wrapping, bundle_key,
                                {"salt": base64.b64encode(salt).decode(), **_ARGON})
    vault._slots = [s for s in vault._slots
                    if s.get("id") != f"agent:{agent_id}"] + [slot]
    now = int(time.time())
    vault._agents[agent_id] = {
        "token_hash": _token_hash(token),
        "scopes": scopes,
        "created_at": now,
        "expires_at": (now + expires_days * 86400)
                      if expires_days is not None else None,
        "enabled": True,
        "last_used_at": None,
        "bundle_key": _b64e(bundle_key),
        "pending_mac_key": _b64e(os.urandom(32)),
        "audit_mac_key": _b64e(os.urandom(32)),
    }
    vault._persist()
    _sync_backup(vault.vault_file)
    return token


@_locked
def revoke_agent(vault: MyKey, agent_id):
    """Delete the pair + slot AND rotate everything the agent could
    read or authored. Its old bundle is useless against the live
    vault from this save on."""
    _require_human_vault(vault)
    if agent_id not in vault._agents:
        raise KeyError(f"no such agent: {agent_id}")
    vault._retire_agent(agent_id)
    vault._persist()
    _sync_backup(vault.vault_file)


@_locked
def set_agent_enabled(vault: MyKey, agent_id, enabled: bool):
    """Disable is cryptographic on the live file: the bundle vanishes
    and the agent's target keys rotate, so a cached bundle goes
    stale. Re-enabling re-issues a bundle under the same token (the
    slot and bundle key are retained in the core while disabled)."""
    _require_human_vault(vault)
    rec = vault._agents.get(agent_id)
    if rec is None:
        raise KeyError(f"no such agent: {agent_id}")
    if bool(rec.get("enabled")) == bool(enabled):
        return
    if not enabled:
        scopes = list(rec.get("scopes") or [])
        affected = [e["id"] for e in vault.list_entries()
                    if MyKey._scope_covers_entry(scopes, e)
                    or vault._origins.get(e["id"]) == f"agent:{agent_id}"]
        vault._rotate_entry_keys(affected, rotate_kmeta=("list" in scopes))
    rec["enabled"] = bool(enabled)
    vault._persist()
    _sync_backup(vault.vault_file)


@_locked
def set_agent_scopes(vault: MyKey, agent_id, scopes):
    """Change scopes. Entries that fall OUT of scope get fresh keys,
    so a previously issued bundle cannot keep reading them."""
    _require_human_vault(vault)
    rec = vault._agents.get(agent_id)
    if rec is None:
        raise KeyError(f"no such agent: {agent_id}")
    new_scopes = validate_scopes(scopes)
    old_scopes = list(rec.get("scopes") or [])
    entries = vault.list_entries()
    removed = [e["id"] for e in entries
               if MyKey._scope_covers_entry(old_scopes, e)
               and not MyKey._scope_covers_entry(new_scopes, e)]
    rotate_kmeta = "list" in old_scopes and "list" not in new_scopes
    if removed or rotate_kmeta:
        vault._rotate_entry_keys(removed, rotate_kmeta=rotate_kmeta)
    rec["scopes"] = new_scopes
    vault._persist()
    _sync_backup(vault.vault_file)


def list_agents(vault: MyKey):
    """Registry metadata for the human. Secrets are never shown.
    last_used_at is refreshed from the audit log (agents cannot
    write the core, so the log is the accurate source)."""
    _require_human_vault(vault)
    last_used = {}
    for rec in read_audit(vault.vault_file):
        if rec.get("action") == "auth" and rec.get("result") == "allow":
            last_used[rec.get("agent", "")] = rec.get("ts")
    out = []
    for agent_id, rec in sorted(vault._agents.items()):
        out.append({
            "agent_id": agent_id,
            "scopes": list(rec.get("scopes") or []),
            "created_at": rec.get("created_at"),
            "expires_at": rec.get("expires_at"),
            "enabled": bool(rec.get("enabled")),
            "last_used_at": last_used.get(agent_id, rec.get("last_used_at")),
        })
    return out


# --------------------------------------------------------------------------
# agent-side session (bundle-based; no vault key anywhere)
# --------------------------------------------------------------------------

def _scope_covers(scopes, entry):
    return MyKey._scope_covers_entry(scopes, entry)


def _sanitize_url(url):
    """Strip anything secret-shaped from a URL for metadata listing:
    userinfo, query and fragment (a URL can carry tokens)."""
    if not url:
        return url
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        netloc = host + (f":{parts.port}" if parts.port else "")
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return ""


def _sanitized_meta(meta):
    out = {k: (list(meta[k]) if k == "tags" else meta[k])
           for k in _METADATA_FIELDS if k in meta}
    out["url"] = _sanitize_url(out.get("url") or "")
    return out


class AgentSession:
    """An authenticated agent's scoped, audited view of a vault.

    The session holds only the agent's bundle key and the bundle the
    human issued. Every operation re-reads the vault file and
    re-opens the bundle, so revocation, disable and scope changes
    apply on the very next call — even inside a long-lived process.
    """

    def __init__(self, vault_path, agent_id, bundle_key, bundle):
        self._vault_path = vault_path
        self.agent_id = agent_id
        self._bundle_key = bundle_key
        self._bundle = bundle
        self.scopes = list(bundle.get("scopes") or [])
        self._pending_cache = {}  # entry id -> (entry dict, dek_pw)

    @property
    def vault_file(self):
        return self._vault_path

    # internal ------------------------------------------------------------
    def _audit(self, action, service, result, reason=""):
        key = _b64d(self._bundle["audit_mac_key"])
        append_audit(self._vault_path, self.agent_id, action, service,
                     result, reason, mac_key=key)

    def _fresh_bundle(self):
        """Re-open the bundle from the live file (revocation check)."""
        data = _load_vault_file(self._vault_path)
        blob = (data.get("bundles") or {}).get(self.agent_id)
        slot = next((s for s in data.get("slots", [])
                     if s.get("id") == f"agent:{self.agent_id}"), None)
        if blob is None or slot is None:
            raise AgentAuthError(
                f"agent {self.agent_id} is no longer authorized "
                "(revoked, disabled or expired)")
        try:
            bundle = json.loads(_dec(
                self._bundle_key, blob, _aad("bundle", self.agent_id)))
        except Exception as exc:
            raise AgentAuthError("agent bundle cannot be opened") from exc
        if bundle.get("vault_id") != data.get("vault_id"):
            raise AgentAuthError("agent bundle does not belong to this vault")
        expires = bundle.get("expires_at")
        if expires and int(time.time()) > int(expires):
            raise AgentAuthError(f"agent {self.agent_id} token has expired")
        self._bundle = bundle
        self.scopes = list(bundle.get("scopes") or [])
        return data, bundle

    def _kmeta(self, bundle):
        raw = bundle.get("kmeta")
        return _b64d(raw) if raw else None

    def _committed_meta(self, data, bundle, obj):
        """Metadata for one committed entry object, or None."""
        kmeta = self._kmeta(bundle)
        if kmeta is None:
            target = (bundle.get("targets") or {}).get(obj.get("id", ""))
            return dict(target["meta"]) if target else None
        try:
            return json.loads(_dec(kmeta, obj["meta"], _aad("meta", obj["id"])))
        except Exception:
            return None

    def _visible(self, bundle, entry_id, meta):
        if "list" in (bundle.get("scopes") or []):
            return True
        return entry_id in (bundle.get("targets") or {})

    # public API ------------------------------------------------------------
    @_locked
    def list_metadata(self):
        data, bundle = self._fresh_bundle()
        out = []
        for obj in data.get("entries") or []:
            if obj.get("pending") is not None:
                continue
            meta = self._committed_meta(data, bundle, obj)
            if meta is None or not self._visible(bundle, obj["id"], meta):
                continue
            out.append(_sanitized_meta(meta))
        for entry, _dek in self._pending_cache.values():
            out.append(_sanitized_meta(
                {k: entry[k] for k in _METADATA_FIELDS}))
        self._audit("list", "", "allow", f"{len(out)} entries visible")
        return out

    @_locked
    def get(self, service, username=None):
        data, bundle = self._fresh_bundle()
        targets = bundle.get("targets") or {}
        # own unprocessed writes first (same-session read-back)
        for entry, dek_pw in self._pending_cache.values():
            if entry["service"] == service and (
                    username is None or entry["username"] == username):
                self._audit("get", service, "allow")
                result = dict(entry)
                result.pop("totp_secret", None)
                return result
        found = None
        for obj in data.get("entries") or []:
            if obj.get("pending") is not None:
                continue
            meta = self._committed_meta(data, bundle, obj)
            if meta is None:
                continue
            if meta.get("service") == service and (
                    username is None or meta.get("username") == username):
                found = (obj, meta)
                break
        if found is None and username is None:
            # resolution via the bundle's service map (no-KMETA path)
            eid = (bundle.get("services") or {}).get(service.lower())
            if eid and eid in targets:
                obj = next((o for o in data.get("entries") or []
                            if o.get("id") == eid), None)
                if obj is not None:
                    found = (obj, dict(targets[eid]["meta"]))
        if found is None:
            self._audit("get", service, "deny", "not found")
            raise KeyError(f"no entry for service: {service}")
        obj, meta = found
        target = targets.get(obj["id"])
        if target is None:
            self._audit("get", service, "deny", "scope")
            raise AgentScopeError(
                f"agent {self.agent_id} has no get scope for {service}")
        try:
            secret = json.loads(_dec(
                _b64d(target["dek_pw"]), obj["secret"], _aad("secret", obj["id"])))
        except Exception as exc:
            self._audit("get", service, "deny", "decrypt failed")
            raise AgentAuthError("entry cannot be decrypted") from exc
        self._audit("get", service, "allow")
        result = {**meta, **secret}
        result.pop("totp_secret", None)  # TOTP secrets never leave to agents
        return result

    @_locked
    def add_entry(self, entry):
        data, bundle = self._fresh_bundle()
        service = (entry or {}).get("service", "")
        if "write" not in self.scopes:
            self._audit("add", service, "deny", "no write scope")
            raise AgentScopeError("agent has no write scope")
        pending_count = sum(1 for o in data.get("entries") or []
                            if o.get("pending") is not None)
        if pending_count >= MAX_PENDING_ENTRIES:
            self._audit("add", service, "deny", "pending queue full")
            raise AgentAuthError(
                "too many unprocessed agent entries — a human must "
                "unlock the vault to process them")
        if data.get("inbox_pub") != bundle.get("inbox_pub"):
            self._audit("add", service, "deny", "inbox key mismatch")
            raise AgentAuthError(
                "vault inbox key does not match the bundle — refusing "
                "to seal to an unauthenticated key")
        record = make_entry(**{
            k: entry[k] for k in
            ("service", "username", "password", "url", "notes", "tags",
             "favourite") if k in entry
        })
        eid = record["id"]
        meta = {k: record[k] for k in _METADATA_FIELDS}
        dek_pw = os.urandom(32)
        inbox_pub = _b64d(bundle["inbox_pub"])
        sealed_meta = seal_to_inbox(inbox_pub, json.dumps(meta).encode(), eid)
        sealed_dek = seal_to_inbox(inbox_pub, dek_pw, eid)
        for blob in (sealed_meta, sealed_dek):
            if len(json.dumps(blob)) > MAX_SEALED_BLOB_BYTES:
                raise AgentAuthError("entry is too large to submit")
        secret_blob = _enc(dek_pw, json.dumps({
            "password": record["password"], "notes": record["notes"],
        }).encode(), _aad("secret", eid))
        obj = {"id": eid, "meta": None, "secret": secret_blob,
               "totp": None, "pending": None}
        mac_body = {"vault_id": bundle["vault_id"], "entry_id": eid,
                    "origin_agent": self.agent_id,
                    "meta": sealed_meta, "dek_pw": sealed_dek,
                    "dek_totp": None, "secret": secret_blob, "totp": None}
        mac = hmac.new(
            _b64d(bundle["pending_mac_key"]),
            json.dumps(mac_body, sort_keys=True,
                       separators=(",", ":")).encode(),
            hashlib.sha256).hexdigest()
        obj["pending"] = {"origin_agent": self.agent_id,
                          "meta": sealed_meta, "dek_pw": sealed_dek,
                          "dek_totp": None, "mac": mac}
        data.setdefault("entries", []).append(obj)
        _write_vault_file(self._vault_path, data)
        self._pending_cache[eid] = (record, dek_pw)
        self._audit("add", service, "allow")
        return dict(record)


@_locked
def open_agent_session(vault_path, token, guard=None):
    """Authenticate an agent token and return an AgentSession.

    The token unwraps the agent's bundle key (never the vault key);
    the bundle carries the scopes and entry keys. Registry checks
    (hash, enabled, expiry) were bound into the bundle by the human
    at issue time and are re-verified against the live file on every
    operation. Every outcome — allow and deny — is audit-logged.
    """
    guard = guard or AgentGuard(vault_path)
    try:
        agent_id, raw = parse_token(token)
    except AgentAuthError:
        append_audit(vault_path, "unknown", "auth", "", "deny", "malformed token")
        raise
    remaining = guard.backoff_remaining(agent_id)
    if remaining > 0:
        # Refused WITHOUT an audit append per attempt (an attacker
        # could otherwise grow the log without bound); the refusal
        # count is flushed into the next authenticated record.
        guard.record_refusal(agent_id)
        raise AgentLockedError(
            f"agent {agent_id} is in progressive backoff — "
            f"retry in {math.ceil(remaining)}s")

    def deny(reason, exc):
        guard.record_failure(agent_id)
        append_audit(vault_path, agent_id, "auth", "", "deny", reason)
        raise exc

    try:
        data = _load_vault_file(vault_path)
    except VaultMissing:
        deny("vault missing", AgentAuthError("vault unavailable"))
    except VaultCorrupt:
        deny("vault corrupt", AgentAuthError("vault unavailable"))
    slot = next((s for s in data.get("slots", [])
                 if s.get("id") == f"agent:{agent_id}"), None)
    if slot is None:
        deny("unknown agent", AgentAuthError("unknown agent"))
    try:
        salt = base64.b64decode(slot["salt"])
        params = {k: slot[k] for k in ("time_cost", "memory_cost", "parallelism")
                  if k in slot}
        # Parameter floor: a header edited down to trivial KDF
        # parameters is rejected outright rather than honoured.
        if (int(params.get("time_cost", 0)) < 2
                or int(params.get("memory_cost", 0)) < 32768
                or int(params.get("parallelism", 0)) < 1):
            raise ValueError("slot KDF parameters below floor")
        wrapping = MyKey._derive_with_secret(raw, salt, "argon2id", params)
    except Exception:
        deny("slot damaged", AgentAuthError("agent credential damaged"))
    bundle_key = MyKey._unwrap_slot(slot, wrapping)
    if bundle_key is None:
        deny("bad token", AgentAuthError("agent token does not match"))
    # From here the credential has PROVEN itself (it unwrapped the
    # bundle key). Inactive states — no bundle (disabled / not yet
    # retired-expired), expiry — are administrative, not guesses:
    # they are audit-logged but never counted as brute-force failures.
    blob = (data.get("bundles") or {}).get(agent_id)
    if blob is None:
        append_audit(vault_path, agent_id, "auth", "", "deny", "no bundle")
        raise AgentAuthError("agent is disabled, expired or revoked")
    try:
        bundle = json.loads(_dec(bundle_key, blob, _aad("bundle", agent_id)))
    except Exception:
        deny("bundle damaged", AgentAuthError("agent bundle cannot be opened"))
    if bundle.get("agent_id") != agent_id or \
            bundle.get("vault_id") != data.get("vault_id"):
        deny("bundle mismatch", AgentAuthError("agent bundle is not valid "
                                               "for this vault"))
    expires = bundle.get("expires_at")
    if expires and int(time.time()) > int(expires):
        append_audit(vault_path, agent_id, "auth", "", "deny", "expired")
        raise AgentAuthError(f"agent {agent_id} token has expired")

    ok, _head, _count, _err = audit_chain_state(audit_path_for(vault_path))
    if not ok:
        # NEVER append to a suspect chain: that would launder the
        # tampered log into the new trusted baseline. The suspect
        # file is preserved untouched for the human (reset_audit).
        raise AgentAuthError(
            "audit log integrity failure — a human must inspect this vault")
    issued_head = bundle.get("audit_head") or ""
    if issued_head:
        hashes = [r["hash"] for r in read_audit_records(audit_path_for(vault_path))]
        if issued_head not in hashes:
            raise AgentAuthError(
                "audit log no longer contains the head this agent was "
                "issued against — a human must inspect this vault")

    refusals = guard.pop_refusals(agent_id)
    guard.reset(agent_id)
    session = AgentSession(vault_path, agent_id, bundle_key, bundle)
    reason = f"{refusals} backoff refusal(s) since last success" if refusals else ""
    session._audit("auth", "", "allow", reason)
    return session


# Re-exported for callers that treated these as agents-level names.
__all__ = [
    "AgentAuthError", "AgentGuard", "AgentLockedError", "AgentScopeError",
    "AgentSession", "append_audit", "audit_mac_keys", "audit_path_for",
    "enroll_agent", "human_audit_mac_key", "list_agents", "open_agent_session",
    "parse_token", "read_audit", "reset_audit", "revoke_agent",
    "set_agent_enabled", "set_agent_scopes", "validate_scopes",
    "verify_audit", "vault_lock", "AuditAnchorError",
]
