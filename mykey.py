# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Vault engine — Vault v3 (Phase 2B) with Phase 0/1/2A semantics.

Vault v3 is envelope encryption with *per-entry key partitioning*:

* a random 256-bit vault key (VK) encrypts the vault **core**
  (AES-256-GCM): the agent registry, the metadata key, every
  entry's data keys, the audit seal and the vault's inbox private
  key,
* every entry lives outside the core as separately encrypted
  records: metadata under a vault metadata key (KMETA), the secret
  fields (password, notes) under a per-entry data key (DEK_pw), and
  the TOTP secret under its own per-entry key (DEK_totp),
* header slots wrap keys for each unlock method — the master
  password and BIP-39 recovery slots wrap VK; an agent slot wraps
  only that agent's *bundle key* (BK), never VK,
* an agent's **bundle** (encrypted under BK, re-issued by the human
  side on every save) carries exactly what its scopes allow: KMETA
  when it holds `list`, and the DEK_pw of in-scope entries only.
  A token holder with the vault file and modified code therefore
  cannot decrypt out-of-scope entries — the keys are not there.

Vault v2 files are migrated on first human unlock: a backup with
the agent slots stripped is kept (``<vault>.v2.bak``), entries are
re-encrypted per-entry, and agent enrollments are retired (a human
cannot re-wrap an agent slot without the agent's token — re-enroll
after migration). Legacy v1 vaults migrate the same way.

Brand neutrality: no brand string appears anywhere in this module,
the file format, the AAD, or any KDF input. The format token is a
stable technical identifier.

All earlier guarantees hold: typed errors (WrongPassword /
VaultCorrupt / VaultMissing), saves refuse when an existing vault
cannot be decrypted, atomic 0600 writes with a rolling backup,
enforced minimums, and key derivation that raises on failure.
"""

import base64
import csv
import hashlib
import hmac
import json
import os
import secrets
import shutil
import string
import tempfile
import time
import uuid

from argon2 import low_level
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

MIN_MASTER_PASSWORD_LENGTH = 12
MIN_GENERATED_PASSWORD_LENGTH = 16
_FORMAT_TOKEN = "MKVLT"  # stable technical token — never a brand string
_FORMAT_VERSION = 3
_VERIFIER_LABEL = b"vault-verifier-v3"
_LEGACY_VERIFIER_LABEL = b"mykey-verifier-v1"  # Phase 0 v1 vaults only
_ARGON = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
_PBKDF2_ITERATIONS = 600000

ENTRY_FIELDS = (
    "service", "username", "password", "url", "notes",
    "totp_secret", "tags", "favourite",
)
_METADATA_FIELDS = ("service", "username", "url", "tags", "favourite",
                    "created", "updated", "android_app")
# Hard caps (fleet design review, finding 9): agent-submitted pending
# material is bounded before any expensive parsing or decryption.
MAX_PENDING_ENTRIES = 64
MAX_SEALED_BLOB_BYTES = 65536


class MyKeyError(Exception):
    """Base class for all vault errors."""


class WrongPassword(MyKeyError):
    """The supplied credential does not unlock this vault."""


class VaultCorrupt(MyKeyError):
    """The vault file exists but is damaged or not a vault."""


class VaultMissing(MyKeyError):
    """No vault file exists at the expected path."""


class AuditAnchorError(VaultCorrupt):
    """The audit anchor check failed at human unlock.

    Raised when the audit log was rolled back behind its anchor,
    the anchor was edited, or the anchor vanished after being
    established. A human recovers with the audit-reset flow.
    """


MyKeyWrongPassword = WrongPassword
MyKeyVaultCorrupt = VaultCorrupt
MyKeyVaultMissing = VaultMissing


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _now() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# small crypto helpers (shared with agents.py)
# ---------------------------------------------------------------------------

def _enc(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"nonce": _b64e(nonce), "ciphertext": _b64e(ct)}


def _dec(key: bytes, blob: dict, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(_b64d(blob["nonce"]), _b64d(blob["ciphertext"]), aad)


def _aad(kind: str, ident: str) -> bytes:
    return f"{kind}:v3:{ident}".encode()


def seal_to_inbox(inbox_pub_raw: bytes, plaintext: bytes, entry_id: str) -> dict:
    """Seal bytes to the vault inbox X25519 public key (agent side).

    Ephemeral ECDH + HKDF + AES-256-GCM. Anyone can seal; only the
    vault key holder (who unwraps the inbox private key from the
    encrypted core) can open.
    """
    pub = X25519PublicKey.from_public_bytes(inbox_pub_raw)
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"mykey-inbox-v3").derive(shared)
    blob = _enc(key, plaintext, _aad("pending", entry_id))
    blob["ephemeral"] = _b64e(
        eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return blob


def _open_inbox(inbox_priv_raw: bytes, blob: dict, entry_id: str) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(inbox_priv_raw)
    eph_pub = X25519PublicKey.from_public_bytes(_b64d(blob["ephemeral"]))
    shared = priv.exchange(eph_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"mykey-inbox-v3").derive(shared)
    return _dec(key, blob, _aad("pending", entry_id))


def _entry_hash(entry_obj: dict) -> str:
    """Hash of one committed entry record's ciphertexts (core-bound)."""
    h = hashlib.sha256(b"entryhash:v3")
    for field in ("meta", "secret", "totp"):
        blob = entry_obj.get(field)
        if blob is None:
            h.update(b"\x00none\x00")
        else:
            h.update(_b64d(blob["nonce"]))
            h.update(_b64d(blob["ciphertext"]))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# audit chain primitives (the rich audit API lives in agents.py)
# ---------------------------------------------------------------------------

def audit_chain_hash(prev_hash: str, record: dict) -> str:
    body = json.dumps(
        {k: v for k, v in record.items() if k not in ("hash", "mac")},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def read_audit_records(path):
    if not os.path.exists(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def audit_chain_state(path):
    """Return (ok, head, count, error) for the hash chain at *path*."""
    try:
        records = read_audit_records(path)
    except Exception as exc:
        return False, "", 0, f"unreadable: {exc}"
    prev = ""
    for rec in records:
        if rec.get("prev") != prev or rec.get("hash") != audit_chain_hash(prev, rec):
            return False, prev, len(records), "chain broken"
        prev = rec["hash"]
    return True, prev, len(records), ""


_HEX_DIGITS = frozenset("0123456789abcdef")


def clean_android_app(value):
    """Validate an Android-app autofill binding, or return None.

    A binding links an entry to one Android app: its package name
    plus the SHA-256 of the app's signing certificate (lowercase
    hex). The Android app sets bindings (after the user confirms);
    every other client carries them verbatim so the binding
    survives round trips. Anything malformed is dropped to None —
    a bad binding must never silently match an app at fill time.
    """
    if not isinstance(value, dict):
        return None
    package = value.get("package")
    cert = value.get("cert_sha256")
    if not isinstance(package, str) or not package.strip():
        return None
    if not isinstance(cert, str):
        return None
    cert = cert.strip().lower().replace(":", "")
    if len(cert) != 64 or any(c not in _HEX_DIGITS for c in cert):
        return None
    out = {"package": package.strip(), "cert_sha256": cert}
    label = value.get("label")
    if isinstance(label, str) and label.strip():
        out["label"] = label.strip()
    return out


def make_entry(service, password="", username="", url="", notes="",
               totp_secret="", tags=None, favourite=False, android_app=None,
               **extra):
    ts = _now()
    entry = {
        "id": uuid.uuid4().hex,
        "service": service,
        "username": username,
        "password": password,
        "url": url,
        "notes": notes,
        "totp_secret": totp_secret,
        "tags": list(tags or []),
        "favourite": bool(favourite),
        "android_app": clean_android_app(android_app),
        "created": ts,
        "updated": ts,
    }
    for key, value in extra.items():
        if key not in entry:
            entry[key] = value
    return entry


def _normalize_entry(raw):
    entry = make_entry(
        service=raw.get("service", ""),
        password=raw.get("password", ""),
        username=raw.get("username", ""),
        url=raw.get("url", ""),
        notes=raw.get("notes", ""),
        totp_secret=raw.get("totp_secret", ""),
        tags=raw.get("tags", []),
        favourite=raw.get("favourite", False),
        android_app=raw.get("android_app"),
    )
    entry["id"] = raw.get("id", entry["id"])
    entry["created"] = raw.get("created", entry["created"])
    entry["updated"] = raw.get("updated", entry["updated"])
    return entry


class MyKey:
    def __init__(self, secret_input, algo="argon2id", vault_file="vault.mykey"):
        if not isinstance(secret_input, str) or not secret_input:
            raise ValueError("master password must be a non-empty string")
        if len(secret_input) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "master password must be at least "
                f"{MIN_MASTER_PASSWORD_LENGTH} characters"
            )
        if algo not in ("argon2id", "pbkdf2"):
            raise ValueError(f"unsupported KDF algorithm: {algo!r}")
        self.vault_file = vault_file
        self.secret_input = secret_input
        self.algo = algo
        self._vault_key = None
        self._entries = None
        self._slots = None
        self._legacy = False
        self._migrated_from = None
        # v3 key material and core state (all of it lives on disk only
        # inside the VK-encrypted core).
        self._agents = {}
        self._audit_head = ""
        self._kmeta = None
        self._deks = {}          # entry id -> {"pw": bytes, "totp": bytes|None}
        self._origins = {}       # entry id -> "human" | "agent:<id>"
        self._entry_hashes = {}  # entry id -> committed ciphertext hash
        self._inbox_priv = None
        self._inbox_pub = None
        self._vault_id = ""
        self._anchor_seq = 0
        self._anchored_head = ""
        self._retired_audit_keys = {}   # agent id -> b64 audit MAC key
        self._retired_pending_keys = {}  # agent id -> b64 pending MAC key
        self._audit_mac_since = 0       # chain index where MACs begin
        self._anchor_recovery = False   # set only by the reset flow
        self._raw_pending = {}          # entry id -> unprocessed entry object
        # Phase 3A: device registry (device id -> public identity
        # record) and the recovery backup recipient public key. Both
        # live only inside the encrypted core, like the agent registry.
        self._devices = {}
        self._backup_recovery_pub = None
        # Blob wave: pairing registry (target id -> public pairing
        # record) for cloud-storage / export targets. Same home as
        # the device registry: public material only, inside the core.
        self._pairings = {}
        # "human" once unlocked by master/recovery; "agent:<id>" for an
        # agent session. Human-only operations check this.
        self._principal = None

    # -- KDF ------------------------------------------------------------
    def _derive_key(self, salt, algo, params=None):
        """Derive a 32-byte key from the master password. Raises on failure."""
        params = params or {}
        try:
            if algo == "argon2id":
                return low_level.hash_secret_raw(
                    secret=self.secret_input.encode(),
                    salt=salt,
                    time_cost=params.get("time_cost", _ARGON["time_cost"]),
                    memory_cost=params.get("memory_cost", _ARGON["memory_cost"]),
                    parallelism=params.get("parallelism", _ARGON["parallelism"]),
                    hash_len=32,
                    type=low_level.Type.ID,
                )
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32, salt=salt,
                iterations=params.get("iterations", _PBKDF2_ITERATIONS),
            )
            return kdf.derive(self.secret_input.encode())
        except Exception as exc:
            raise MyKeyError(f"key derivation failed: {exc}") from exc

    @staticmethod
    def _derive_with_secret(secret_bytes, salt, algo, params=None):
        params = params or {}
        if algo == "argon2id":
            return low_level.hash_secret_raw(
                secret=secret_bytes, salt=salt,
                time_cost=params.get("time_cost", _ARGON["time_cost"]),
                memory_cost=params.get("memory_cost", _ARGON["memory_cost"]),
                parallelism=params.get("parallelism", _ARGON["parallelism"]),
                hash_len=32, type=low_level.Type.ID,
            )
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=params.get("iterations", _PBKDF2_ITERATIONS),
        )
        return kdf.derive(secret_bytes)

    # -- slot helpers ------------------------------------------------------
    @staticmethod
    def _wrap_key_slot(slot_id, wrapping_key, key_bytes, params=None):
        nonce = os.urandom(12)
        ct = AESGCM(wrapping_key).encrypt(
            nonce, key_bytes, f"slot:{slot_id}".encode()
        )
        slot = {
            "id": slot_id,
            "algo": "argon2id",
            "salt": "",
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct),
        }
        if params:
            slot.update(params)
        return slot

    def _make_slot(self, slot_id, wrapping_key, params=None):
        return self._wrap_key_slot(slot_id, wrapping_key, self._vault_key, params)

    def _master_slot(self):
        salt = os.urandom(16)
        if self.algo == "argon2id":
            params = {"salt": _b64e(salt), **_ARGON}
        else:
            params = {"salt": _b64e(salt), "iterations": _PBKDF2_ITERATIONS}
        key = self._derive_key(salt, self.algo, params)
        slot = self._make_slot("master", key, params)
        slot["algo"] = self.algo
        return slot

    @staticmethod
    def _unwrap_slot(slot, wrapping_key):
        try:
            return AESGCM(wrapping_key).decrypt(
                _b64d(slot["nonce"]), _b64d(slot["ciphertext"]),
                f"slot:{slot['id']}".encode(),
            )
        except InvalidTag:
            return None

    # -- file IO -----------------------------------------------------------
    def _read_raw_file(self):
        if not os.path.exists(self.vault_file):
            raise VaultMissing(f"no vault file at {self.vault_file}")
        try:
            with open(self.vault_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            raise VaultCorrupt(f"vault file is not readable JSON: {exc}") from exc

    def _atomic_write(self, payload: dict):
        directory = os.path.dirname(os.path.abspath(self.vault_file))
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            if os.path.exists(self.vault_file):
                backup = self.vault_file + ".bak"
                shutil.copyfile(self.vault_file, backup)
                os.chmod(backup, 0o600)
            os.replace(tmp_path, self.vault_file)
            os.chmod(self.vault_file, 0o600)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # -- v3 core / entries / bundles --------------------------------------
    def _core_dict(self):
        return {
            "agents": self._agents,
            "audit_head": self._audit_head,
            "kmeta": _b64e(self._kmeta),
            "deks": {
                eid: {"pw": _b64e(d["pw"]),
                      "totp": _b64e(d["totp"]) if d.get("totp") else None}
                for eid, d in self._deks.items()
            },
            "origins": self._origins,
            "entry_hashes": self._entry_hashes,
            "inbox_priv": _b64e(self._inbox_priv),
            "vault_id": self._vault_id,
            "anchor_seq": self._anchor_seq,
            "retired_audit_keys": self._retired_audit_keys,
            "retired_pending_keys": self._retired_pending_keys,
            "audit_mac_since": self._audit_mac_since,
            "devices": self._devices,
            "pairings": self._pairings,
            "backup_recovery_pub": (
                _b64e(self._backup_recovery_pub)
                if self._backup_recovery_pub else None),
        }

    def _entry_object(self, entry):
        """Encrypt one in-memory entry into its v3 on-disk record."""
        eid = entry["id"]
        deks = self._deks[eid]
        meta = {k: entry[k] for k in _METADATA_FIELDS}
        obj = {
            "id": eid,
            "meta": _enc(self._kmeta, json.dumps(meta).encode(), _aad("meta", eid)),
            "secret": _enc(deks["pw"], json.dumps({
                "password": entry["password"], "notes": entry["notes"],
            }).encode(), _aad("secret", eid)),
            "totp": None,
            "pending": None,
        }
        if entry.get("totp_secret"):
            obj["totp"] = _enc(deks["totp"], json.dumps({
                "totp_secret": entry["totp_secret"],
            }).encode(), _aad("totp", eid))
        self._entry_hashes[eid] = _entry_hash(obj)
        return obj

    @staticmethod
    def _scope_covers_entry(scopes, entry):
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

    def _build_bundles(self):
        """Re-issue every agent bundle from current scopes and keys.

        Called on every human save, so bundles always reflect the
        registry: disabled or expired agents get no bundle, revoked
        agents are gone entirely, and rotated keys flow through.
        """
        bundles = {}
        now = _now()
        for agent_id, rec in self._agents.items():
            if not rec.get("enabled", False) or not rec.get("bundle_key"):
                continue
            expires = rec.get("expires_at")
            if expires and now > int(expires):
                continue
            scopes = list(rec.get("scopes") or [])
            targets = {}
            services = {}
            for entry in self._entries or []:
                if self._scope_covers_entry(scopes, entry):
                    targets[entry["id"]] = {
                        "dek_pw": _b64e(self._deks[entry["id"]]["pw"]),
                        "meta": {k: entry[k] for k in _METADATA_FIELDS},
                    }
                    services.setdefault(entry["service"].lower(), entry["id"])
            bundle = {
                "agent_id": agent_id,
                "vault_id": self._vault_id,
                "scopes": scopes,
                "expires_at": expires,
                "kmeta": _b64e(self._kmeta) if "list" in scopes else None,
                "targets": targets,
                "services": services,
                "inbox_pub": _b64e(self._inbox_pub),
                "pending_mac_key": rec["pending_mac_key"],
                "audit_mac_key": rec["audit_mac_key"],
                "audit_head": self._audit_head,
                "issued_at": now,
            }
            bk = _b64d(rec["bundle_key"])
            bundles[agent_id] = _enc(
                bk, json.dumps(bundle).encode(), _aad("bundle", agent_id))
        return bundles

    def _persist(self):
        """Encrypt core + entries under the current keys; write v3."""
        entry_objs = [self._entry_object(e) for e in self._entries or []]
        entry_objs += list(self._raw_pending.values())
        core_blob = _enc(
            self._vault_key,
            json.dumps(self._core_dict()).encode(),
            _aad("core", self._vault_id),
        )
        payload = {
            "format": _FORMAT_TOKEN,
            "version": _FORMAT_VERSION,
            "vault_id": self._vault_id,
            "inbox_pub": _b64e(self._inbox_pub),
            "slots": self._slots,
            "verifier": _b64e(
                hmac.new(self._vault_key, _VERIFIER_LABEL, hashlib.sha256).digest()
            ),
            "core": core_blob,
            "entries": entry_objs,
            "bundles": self._build_bundles(),
        }
        self._atomic_write(payload)
        self._anchor_checkpoint()

    def _load_core(self, core):
        self._agents = core.get("agents") or {}
        self._audit_head = core.get("audit_head") or ""
        self._kmeta = _b64d(core["kmeta"])
        self._deks = {
            eid: {"pw": _b64d(d["pw"]),
                  "totp": _b64d(d["totp"]) if d.get("totp") else None}
            for eid, d in (core.get("deks") or {}).items()
        }
        self._origins = core.get("origins") or {}
        self._entry_hashes = core.get("entry_hashes") or {}
        self._inbox_priv = _b64d(core["inbox_priv"])
        self._vault_id = core.get("vault_id") or ""
        self._anchor_seq = int(core.get("anchor_seq") or 0)
        self._retired_audit_keys = core.get("retired_audit_keys") or {}
        self._retired_pending_keys = core.get("retired_pending_keys") or {}
        self._audit_mac_since = int(core.get("audit_mac_since") or 0)
        # Phase 3A fields; absent in cores written before 3A.
        self._devices = core.get("devices") or {}
        # Blob-wave field; absent in cores written before it.
        self._pairings = core.get("pairings") or {}
        raw_pub = core.get("backup_recovery_pub")
        self._backup_recovery_pub = _b64d(raw_pub) if raw_pub else None

    def _decrypt_v3_contents(self, data):
        try:
            core = json.loads(_dec(
                self._vault_key, data["core"],
                _aad("core", data.get("vault_id", ""))))
        except Exception as exc:
            raise VaultCorrupt("vault core failed to decrypt") from exc
        self._load_core(core)
        if data.get("vault_id") != self._vault_id:
            raise VaultCorrupt("vault id mismatch between header and core")
        # inbox binding: the header public key must be the private
        # key's pair (fleet design review, finding 3).
        derived_pub = X25519PrivateKey.from_private_bytes(self._inbox_priv) \
            .public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if not hmac.compare_digest(derived_pub, _b64d(data.get("inbox_pub", ""))):
            raise VaultCorrupt("vault inbox key does not match its core")
        self._inbox_pub = derived_pub
        entries = []
        self._raw_pending = {}
        for obj in data.get("entries") or []:
            eid = obj.get("id", "")
            if obj.get("pending") is not None:
                self._raw_pending[eid] = obj
                continue
            expected = self._entry_hashes.get(eid)
            if expected is None or not hmac.compare_digest(expected, _entry_hash(obj)):
                raise VaultCorrupt(
                    f"entry {eid} ciphertext does not match the hash sealed "
                    "in the vault core — it was changed outside a human session")
            try:
                meta = json.loads(_dec(self._kmeta, obj["meta"], _aad("meta", eid)))
                secret = json.loads(_dec(
                    self._deks[eid]["pw"], obj["secret"], _aad("secret", eid)))
                totp_secret = ""
                if obj.get("totp") is not None:
                    totp = json.loads(_dec(
                        self._deks[eid]["totp"], obj["totp"], _aad("totp", eid)))
                    totp_secret = totp.get("totp_secret", "")
            except Exception as exc:
                raise VaultCorrupt(f"entry {eid} failed to decrypt") from exc
            entry = _normalize_entry({**meta, **secret,
                                      "totp_secret": totp_secret, "id": eid})
            entries.append(entry)
        return entries

    # -- audit anchor --------------------------------------------------------
    def _anchor_path(self):
        return self.vault_file + ".audit-anchor.json"

    def _anchor_key(self):
        return hmac.new(self._vault_key, b"audit-anchor-key-v3",
                        hashlib.sha256).digest()

    def _anchor_mac(self, vault_id, seq, head, count):
        body = json.dumps({"vault_id": vault_id, "seq": seq, "head": head,
                           "count": count},
                          sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._anchor_key(), body, hashlib.sha256).hexdigest()

    def _verify_anchor(self):
        """Verify the audit anchor at human unlock. Raises AuditAnchorError.

        Detects: anchor edited/forged (HMAC, needs the vault key),
        log rolled back behind the anchored head (prefix check),
        anchor rolled back behind the core (sequence check). Agent
        appends after the anchor are normal: the anchored head only
        has to remain a prefix of the current chain.
        """
        path = self._anchor_path()
        audit_file = self.vault_file + ".audit.jsonl"
        ok, head, count, err = audit_chain_state(audit_file)
        if not ok:
            raise AuditAnchorError(f"audit chain integrity failure: {err}")
        if not os.path.exists(path):
            # The anchor protects the audit log AT THIS PATH. A vault
            # copy opened standalone (e.g. the rolling .bak) has no
            # log beside it and nothing to anchor — but at a path
            # where a sealed log exists (or the core carries a seal),
            # a vanished anchor is a tamper signal.
            if self._anchor_seq > 0 and (os.path.exists(audit_file)
                                          or self._audit_head):
                raise AuditAnchorError(
                    "audit anchor file is missing but this vault has "
                    "anchored before — the log may have been rolled "
                    "back; recover with agent-audit-reset")
            self._anchored_head = head
            return
        try:
            anchor = json.loads(open(path, encoding="utf-8").read())
        except Exception as exc:
            raise AuditAnchorError(f"audit anchor is unreadable: {exc}") from exc
        expected = self._anchor_mac(anchor.get("vault_id", ""),
                                     int(anchor.get("seq") or 0),
                                     anchor.get("head", ""),
                                     int(anchor.get("count") or 0))
        if anchor.get("vault_id") != self._vault_id or not hmac.compare_digest(
                expected, anchor.get("hmac", "")):
            raise AuditAnchorError(
                "audit anchor failed authentication — it was edited or "
                "belongs to another vault")
        if int(anchor.get("seq") or 0) < self._anchor_seq:
            raise AuditAnchorError(
                "audit anchor was rolled back behind the vault core")
        # prefix check: the anchored head must be the hash at the
        # anchored position in the current chain.
        records = read_audit_records(audit_file)
        acount = int(anchor.get("count") or 0)
        if acount > len(records):
            raise AuditAnchorError(
                "audit log is shorter than its anchor — it was rolled back")
        ahead = records[acount - 1]["hash"] if acount else ""
        if ahead != anchor.get("head", ""):
            raise AuditAnchorError(
                "audit log head does not match its anchor — the log was "
                "rolled back or rewritten behind the anchor")
        self._anchor_seq = int(anchor.get("seq") or 0)
        self._anchored_head = anchor.get("head", "")

    def _anchor_checkpoint(self):
        """Write/refresh the anchor. Human principal only; best effort
        is NOT acceptable for failures of the write itself at unlock,
        but _persist calls this after the vault write and lets errors
        propagate."""
        if self._principal != "human" or self._vault_key is None:
            return
        audit_file = self.vault_file + ".audit.jsonl"
        ok, head, count, _err = audit_chain_state(audit_file)
        if not ok:
            return  # a broken chain is handled at unlock/reset, not here
        if head == self._anchored_head and os.path.exists(self._anchor_path()):
            return
        self._anchor_seq += 1
        anchor = {
            "version": 1,
            "vault_id": self._vault_id,
            "seq": self._anchor_seq,
            "head": head,
            "count": count,
        }
        anchor["hmac"] = self._anchor_mac(
            anchor["vault_id"], anchor["seq"], anchor["head"], anchor["count"])
        directory = os.path.dirname(os.path.abspath(self._anchor_path()))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".anchor-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(anchor, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._anchor_path())
            os.chmod(self._anchor_path(), 0o600)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._anchored_head = head

    # -- key rotation helpers -------------------------------------------------
    def _rotate_entry_keys(self, entry_ids, rotate_kmeta=False):
        """Replace DEKs (and optionally KMETA) for the given entries.

        Because _persist re-encrypts from plaintext, swapping the key
        material is the rotation: ciphertexts on the live file change
        and previously issued bundles go stale. Caller persists.
        """
        for eid in entry_ids:
            if eid in self._deks:
                totp = self._deks[eid].get("totp")
                self._deks[eid] = {
                    "pw": os.urandom(32),
                    "totp": os.urandom(32) if totp else None,
                }
        if rotate_kmeta:
            self._kmeta = os.urandom(32)

    def _init_v3_material(self, entries):
        """Generate fresh v3 key material for a new/migrated vault."""
        self._kmeta = os.urandom(32)
        self._vault_id = uuid.uuid4().hex
        priv = X25519PrivateKey.generate()
        self._inbox_priv = priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self._inbox_pub = priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self._deks = {}
        self._origins = {}
        for e in entries:
            self._deks[e["id"]] = {
                "pw": os.urandom(32),
                "totp": os.urandom(32) if e.get("totp_secret") else None,
            }
            self._origins[e["id"]] = "human"

    # -- unlock (v3) -----------------------------------------------------------
    def _finish_human_unlock(self, entries):
        """Shared tail of every human unlock: audit verification
        FIRST (entries are not exposed if it fails), then pending
        processing, expired-agent retirement, seal + anchor."""
        audit_file = self.vault_file + ".audit.jsonl"
        ok, head, count, err = audit_chain_state(audit_file)
        recovered = False
        try:
            if not ok:
                raise AuditAnchorError(f"audit chain integrity failure: {err}")
            if self._audit_head:
                # The seal is a freshness witness: the head sealed in
                # the core must still be IN the chain. A log rolled
                # back behind its seal (with or without its anchor)
                # fails here, before anything can re-seal over it.
                hashes = [r["hash"] for r in read_audit_records(audit_file)]
                if self._audit_head not in hashes:
                    raise AuditAnchorError(
                        "audit log was rolled back behind the head "
                        "sealed in the vault — recover with "
                        "agent-audit-reset")
            if self._migrated_from:
                # Records that predate the migration carry no MACs; MAC
                # enforcement starts at the current chain head.
                self._audit_mac_since = count
            self._verify_anchor()
        except AuditAnchorError:
            if not self._anchor_recovery:
                raise
            # Human-directed recovery (agent-audit-reset): quarantine
            # the suspect log + anchor untouched, start fresh. The
            # quarantined files are the evidence; nothing is deleted.
            ts = int(time.time())
            for suspect in (audit_file, self._anchor_path()):
                if os.path.exists(suspect):
                    os.replace(suspect, f"{suspect}.suspect-{ts}")
            self._audit_head = ""
            self._audit_mac_since = 0
            self._anchor_seq = 0
            self._anchored_head = ""
            ok, head, count, err = True, "", 0, ""
            recovered = True
        self._entries = entries
        accepted = self._process_pending()
        retired = self._retire_expired_agents()
        # Advance the seal to the verified current head and persist if
        # anything changed (migration, pendings, retirements, seal).
        if (self._migrated_from or accepted or retired or self._legacy
                or recovered or head != self._audit_head):
            self._audit_head = head
            self._persist()
        else:
            self._anchor_checkpoint()
        self._clear_agent_guard()
        return self._entries

    def _unlock_v3(self, data):
        slots = data.get("slots") or []
        master = next((s for s in slots if s.get("id") == "master"), None)
        if master is None:
            raise VaultCorrupt("vault has no master slot")
        salt = _b64d(master["salt"])
        params = {k: master[k] for k in ("time_cost", "memory_cost", "parallelism", "iterations") if k in master}
        key = self._derive_key(salt, master.get("algo", "argon2id"), params)
        vault_key = self._unwrap_slot(master, key)
        if vault_key is None:
            raise WrongPassword("master password does not match this vault")
        self._vault_key = vault_key
        self._slots = slots
        entries = self._decrypt_v3_contents(data)
        self._legacy = False
        self._principal = "human"
        return self._finish_human_unlock(entries)

    # -- unlock (v2 -> v3 migration, legacy v1) --------------------------------
    def _decrypt_v2_contents(self, data):
        try:
            plaintext = AESGCM(self._vault_key).decrypt(
                _b64d(data["nonce"]), _b64d(data["ciphertext"]), _FORMAT_TOKEN.encode()
            )
            parsed = json.loads(plaintext)
            return [_normalize_entry(e) for e in parsed["entries"]]
        except Exception as exc:
            raise VaultCorrupt("vault contents failed to decrypt") from exc

    def _write_migration_backup(self, data):
        """Keep a pre-migration copy with agent slots STRIPPED.

        A v2 backup with its agent slots intact would let an old
        agent token unwrap the whole vault key from the backup —
        silently defeating v3 partitioning (fleet design review,
        finding 1). Master/recovery slots stay: human recovery from
        the backup remains possible with a v2-era client.
        """
        backup = self.vault_file + ".v2.bak"
        if os.path.exists(backup):
            return
        stripped = dict(data)
        stripped["slots"] = [
            s for s in data.get("slots", [])
            if not str(s.get("id", "")).startswith("agent:")
        ]
        directory = os.path.dirname(os.path.abspath(self.vault_file))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".v2bak-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(stripped, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, backup)
            os.chmod(backup, 0o600)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _migrate_to_v3(self, entries, from_version):
        self._init_v3_material(entries)
        self._agents = {}
        self._audit_head = ""
        self._audit_mac_since = 0
        self._anchor_seq = 0
        self._anchored_head = ""
        self._retired_audit_keys = {}
        self._retired_pending_keys = {}
        self._entry_hashes = {}
        self._devices = {}
        self._pairings = {}
        self._backup_recovery_pub = None
        self._migrated_from = from_version
        self._principal = "human"
        return self._finish_human_unlock(entries)

    def _rotate_vk_for_migration(self, data, old_vault_key,
                                 recovery_wrapping=None):
        """Replace VK during a v2 -> v3 migration.

        Non-negotiable: in v2 every agent slot wrapped VK itself, so
        anyone holding a pre-migration file copy plus an old agent
        token can unwrap the OLD vault key. Keeping that key would
        silently defeat v3 partitioning. Migration therefore rotates
        VK, rebuilds the master slot when this instance's password
        proves correct against the old slot, and rebuilds the
        recovery slot only when the caller actually holds the phrase
        (recovery_wrapping = (wrapping_key, salt_b64)). On the plain
        master-password path the recovery phrase is retired and the
        human sets it up again — stated in the docs.
        """
        new_vk = os.urandom(32)
        slots = []
        old_master = next((s for s in data.get("slots", [])
                           if s.get("id") == "master"), None)
        if old_master is not None:
            try:
                salt = _b64d(old_master["salt"])
                params = {k: old_master[k] for k in
                          ("time_cost", "memory_cost", "parallelism",
                           "iterations") if k in old_master}
                probe = self._derive_key(
                    salt, old_master.get("algo", "argon2id"), params)
                if self._unwrap_slot(old_master, probe) == old_vault_key:
                    self._vault_key = new_vk
                    slots.append(self._master_slot())
            except Exception:
                pass
        if recovery_wrapping is not None:
            wrapping, salt_b64 = recovery_wrapping
            self._vault_key = new_vk
            slots.append(self._wrap_key_slot(
                "recovery", wrapping, new_vk,
                {"salt": salt_b64, **_ARGON}))
        self._vault_key = new_vk
        self._slots = slots

    def _unlock_v2(self, data):
        slots = data.get("slots") or []
        master = next((s for s in slots if s.get("id") == "master"), None)
        if master is None:
            raise VaultCorrupt("vault has no master slot")
        salt = _b64d(master["salt"])
        params = {k: master[k] for k in ("time_cost", "memory_cost", "parallelism", "iterations") if k in master}
        key = self._derive_key(salt, master.get("algo", "argon2id"), params)
        vault_key = self._unwrap_slot(master, key)
        if vault_key is None:
            raise WrongPassword("master password does not match this vault")
        self._vault_key = vault_key
        entries = self._decrypt_v2_contents(data)
        self._write_migration_backup(data)
        self._rotate_vk_for_migration(data, vault_key)
        return self._migrate_to_v3(entries, from_version=2)

    def _unlock_legacy(self, data):
        """Read a v1 / Phase-0 vault. Entries migrate to v3 on unlock."""
        try:
            salt = _b64d(data["salt"])
            nonce = _b64d(data["nonce"])
            ct = _b64d(data["ciphertext"])
            algo = data.get("algo", "argon2id")
        except Exception as exc:
            raise VaultCorrupt("legacy vault is missing fields") from exc
        key = self._derive_key(salt, algo)
        verifier = data.get("verifier")
        if verifier is not None:
            expected = _b64e(hmac.new(key, _LEGACY_VERIFIER_LABEL, hashlib.sha256).digest())
            if not hmac.compare_digest(expected, verifier):
                raise WrongPassword("master password does not match this vault")
            try:
                plaintext = AESGCM(key).decrypt(nonce, ct, None)
            except InvalidTag as exc:
                raise VaultCorrupt("legacy vault failed to decrypt") from exc
        else:
            try:
                plaintext = AESGCM(key).decrypt(nonce, ct, None)
            except InvalidTag as exc:
                raise WrongPassword("master password does not match this vault") from exc
        try:
            raw = json.loads(plaintext)
        except Exception as exc:
            raise VaultCorrupt("legacy vault plaintext is not valid JSON") from exc
        self._vault_key = os.urandom(32)
        self._slots = [self._master_slot()]
        entries = [make_entry(service=name, password=pw) for name, pw in raw.items()]
        self._legacy = True
        return self._migrate_to_v3(entries, from_version=1)

    # -- pending (agent-submitted) processing ----------------------------------
    def _pending_mac_key_for(self, agent_id):
        rec = self._agents.get(agent_id)
        if rec is not None:
            return _b64d(rec["pending_mac_key"])
        raw = self._retired_pending_keys.get(agent_id)
        return _b64d(raw) if raw else None

    def _process_pending(self):
        """Accept agent-submitted entries whose MAC + seal verify.

        Anything else stays in _raw_pending, untouched, for the human
        to inspect — it is never silently dropped and never trusted.
        """
        if not self._raw_pending:
            return
        accepted = []
        for eid, obj in list(self._raw_pending.items())[:MAX_PENDING_ENTRIES]:
            pend = obj.get("pending") or {}
            agent_id = pend.get("origin_agent", "")
            key = self._pending_mac_key_for(agent_id)
            ok = False
            if key is not None:
                body = json.dumps(
                    {"vault_id": self._vault_id, "entry_id": eid,
                     "origin_agent": agent_id,
                     "meta": pend.get("meta"), "dek_pw": pend.get("dek_pw"),
                     "dek_totp": pend.get("dek_totp"),
                     "secret": obj.get("secret"), "totp": obj.get("totp")},
                    sort_keys=True, separators=(",", ":")).encode()
                expected = hmac.new(key, body, hashlib.sha256).hexdigest()
                ok = hmac.compare_digest(expected, pend.get("mac", ""))
            if not ok:
                continue
            try:
                meta = json.loads(_open_inbox(
                    self._inbox_priv, pend["meta"], eid))
                dek_pw = _open_inbox(self._inbox_priv, pend["dek_pw"], eid)
                dek_totp = None
                if pend.get("dek_totp") is not None:
                    dek_totp = _open_inbox(self._inbox_priv, pend["dek_totp"], eid)
                secret = json.loads(_dec(dek_pw, obj["secret"], _aad("secret", eid)))
                totp_secret = ""
                if obj.get("totp") is not None:
                    totp = json.loads(_dec(dek_totp, obj["totp"], _aad("totp", eid)))
                    totp_secret = totp.get("totp_secret", "")
            except Exception:
                continue
            entry = _normalize_entry({**meta, **secret,
                                      "totp_secret": totp_secret, "id": eid})
            if any(e["service"] == entry["service"]
                   and e["username"] == entry["username"]
                   for e in self._entries):
                continue  # insert-only: never overwrite a human entry
            self._deks[eid] = {"pw": dek_pw, "totp": dek_totp}
            self._origins[eid] = f"agent:{agent_id}"
            self._entries.append(entry)
            del self._raw_pending[eid]
            accepted.append(eid)
        return accepted

    def _retire_expired_agents(self):
        """Retire agents past expiry: rotate their keys, drop them.

        Runs at human unlock (the human-mediated rekey the design
        review required): from this save on, an expired token is
        cryptographically dead on the live file, not just refused.
        """
        now = _now()
        expired = [aid for aid, rec in self._agents.items()
                   if rec.get("expires_at") and now > int(rec["expires_at"])]
        changed = False
        for aid in expired:
            self._retire_agent(aid)
            changed = True
        return changed

    def _retire_agent(self, agent_id):
        """Remove an agent and rotate everything it could read or
        authored (shared by revoke / disable / expiry paths)."""
        rec = self._agents.get(agent_id)
        if rec is None:
            return
        scopes = list(rec.get("scopes") or [])
        affected = [e["id"] for e in self._entries or []
                    if self._scope_covers_entry(scopes, e)
                    or self._origins.get(e["id"]) == f"agent:{agent_id}"]
        self._retired_audit_keys[agent_id] = rec["audit_mac_key"]
        self._retired_pending_keys[agent_id] = rec["pending_mac_key"]
        del self._agents[agent_id]
        self._slots = [s for s in self._slots
                       if s.get("id") != f"agent:{agent_id}"]
        self._rotate_entry_keys(affected, rotate_kmeta=("list" in scopes))

    def _clear_agent_guard(self):
        """A successful human unlock clears agent backoff state."""
        try:
            os.unlink(self.vault_file + ".agentguard.json")
        except OSError:
            pass

    # -- unlock --------------------------------------------------------------
    def unlock(self):
        """Unlock and return the entry list.

        A missing vault returns []. WrongPassword / VaultCorrupt are
        raised for an existing vault that cannot be opened.
        """
        if self._entries is not None:
            return self._entries
        try:
            data = self._read_raw_file()
        except VaultMissing:
            self._vault_key = os.urandom(32)
            self._slots = [self._master_slot()]
            self._entries = []
            self._legacy = False
            self._agents = {}
            self._audit_head = ""
            self._init_v3_material([])
            self._principal = "human"
            self._persist()
            return self._entries
        if data.get("format") == _FORMAT_TOKEN:
            version = data.get("version")
            if version == 3:
                return self._unlock_v3(data)
            if version == 2:
                return self._unlock_v2(data)
            raise VaultCorrupt(f"unsupported vault version: {version!r}")
        return self._unlock_legacy(data)

    def _require_unlocked(self):
        if self._entries is None:
            self.unlock()
        return self._entries

    # -- generation ------------------------------------------------------------
    def generate_password(self, length=16):
        if length < MIN_GENERATED_PASSWORD_LENGTH:
            raise ValueError(
                "generated passwords must be at least "
                f"{MIN_GENERATED_PASSWORD_LENGTH} characters"
            )
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length))

    # -- record CRUD ---------------------------------------------------------
    def list_entries(self):
        return [dict(e) for e in self._require_unlocked()]

    def search_entries(self, query):
        q = (query or "").lower()
        return [
            dict(e) for e in self._require_unlocked()
            if q in e["service"].lower()
            or q in e["username"].lower()
            or q in e["url"].lower()
            or q in e["notes"].lower()
            or any(q in t.lower() for t in e["tags"])
        ]

    def _find_index(self, service, username=None):
        for i, e in enumerate(self._require_unlocked()):
            if e["service"] == service and (username is None or e["username"] == username):
                return i
        return -1

    def get_entry(self, service, username=None):
        idx = self._find_index(service, username)
        if idx < 0:
            raise KeyError(f"no entry for service: {service}")
        return dict(self._entries[idx])

    def _register_new_entry(self, record):
        self._deks[record["id"]] = {
            "pw": os.urandom(32),
            "totp": os.urandom(32) if record.get("totp_secret") else None,
        }
        self._origins[record["id"]] = (
            "human" if self._principal in (None, "human")
            else self._principal)

    def add_entry(self, entry):
        entries = self._require_unlocked()
        record = _normalize_entry(entry)
        if not record["service"]:
            raise ValueError("entry service must be non-empty")
        if self._find_index(record["service"], record["username"]) >= 0:
            raise ValueError(
                f"entry already exists: {record['service']} ({record['username']})"
            )
        self._register_new_entry(record)
        entries.append(record)
        self._persist()
        return dict(record)

    def update_entry(self, service, username=None, **fields):
        idx = self._find_index(service, username)
        if idx < 0:
            raise KeyError(f"no entry for service: {service}")
        record = self._entries[idx]
        for key, value in fields.items():
            if key in ENTRY_FIELDS:
                record[key] = list(value) if key == "tags" else value
        record["updated"] = _now()
        if record.get("totp_secret") and self._deks[record["id"]].get("totp") is None:
            self._deks[record["id"]]["totp"] = os.urandom(32)
        if not record.get("totp_secret"):
            self._deks[record["id"]]["totp"] = None
        self._persist()
        return dict(record)

    def delete_entry(self, service, username=None):
        self._require_human("delete entries")
        idx = self._find_index(service, username)
        if idx < 0:
            raise KeyError(f"no entry for service: {service}")
        removed = self._entries.pop(idx)
        self._deks.pop(removed["id"], None)
        self._origins.pop(removed["id"], None)
        self._entry_hashes.pop(removed["id"], None)
        self._persist()
        return dict(removed)

    # -- Phase 0 compatible API ------------------------------------------------
    def save_password(self, service, password, **fields):
        if not service:
            raise ValueError("service must be non-empty")
        self._require_unlocked()  # raises WrongPassword/VaultCorrupt — never wipes
        idx = self._find_index(service, fields.get("username"))
        if idx >= 0:
            self.update_entry(service, fields.get("username"), password=password, **{
                k: v for k, v in fields.items() if k != "username"
            })
        else:
            self.add_entry(make_entry(service=service, password=password, **fields))

    def get_password(self, service):
        return self.get_entry(service)["password"]

    # -- recovery slots -----------------------------------------------------------
    def setup_recovery(self, strength=128):
        """Create a BIP-39 recovery slot. Returns the phrase (show once)."""
        from recovery import (derive_recovery_key, generate_mnemonic,
                              recovery_backup_keypair)

        self._require_human("manage recovery")
        self._require_unlocked()
        phrase = generate_mnemonic(strength)
        # Phase 3A: the backup-package recovery recipient public key
        # for THIS vault, derived from the new phrase (the private
        # half is never stored — it is re-derived from the phrase).
        _raw, pub = recovery_backup_keypair(phrase, self._vault_id)
        self._backup_recovery_pub = pub
        self._set_recovery_slot(phrase, derive_recovery_key)
        return phrase

    def _set_recovery_slot(self, phrase, derive_fn):
        salt = os.urandom(16)
        wrapping = derive_fn(phrase, salt)
        slot = self._make_slot("recovery", wrapping, {"salt": _b64e(salt), **_ARGON})
        self._slots = [s for s in self._slots if s.get("id") != "recovery"] + [slot]
        self._persist()

    def rotate_recovery(self, strength=128):
        """Replace the recovery phrase. The old phrase stops working."""
        return self.setup_recovery(strength)

    def has_recovery(self):
        self._require_unlocked()
        return any(s.get("id") == "recovery" for s in self._slots)

    def unlock_via_recovery(self, phrase):
        """Unlock this vault using its recovery phrase instead of the password."""
        from recovery import derive_recovery_key, validate_mnemonic

        if not validate_mnemonic(phrase):
            raise WrongPassword("recovery phrase is not a valid BIP-39 phrase")
        data = self._read_raw_file()
        if data.get("format") != _FORMAT_TOKEN or data.get("version") not in (2, 3):
            raise VaultCorrupt("recovery unlock requires a Vault v2/v3 vault")
        slot = next((s for s in data.get("slots", []) if s.get("id") == "recovery"), None)
        if slot is None:
            raise WrongPassword("this vault has no recovery phrase set up")
        wrapping = derive_recovery_key(phrase, _b64d(slot["salt"]))
        vault_key = self._unwrap_slot(slot, wrapping)
        if vault_key is None:
            raise WrongPassword("recovery phrase does not match this vault")
        self._vault_key = vault_key
        self._slots = data["slots"]
        if data.get("version") == 2:
            entries = self._decrypt_v2_contents(data)
            self._write_migration_backup(data)
            self._rotate_vk_for_migration(
                data, vault_key,
                recovery_wrapping=(wrapping, slot["salt"]))
            result = self._migrate_to_v3(entries, from_version=2)
            self._backfill_backup_recovery_pub(phrase)
            return result
        entries = self._decrypt_v3_contents(data)
        self._legacy = False
        self._principal = "human"
        result = self._finish_human_unlock(entries)
        self._backfill_backup_recovery_pub(phrase)
        return result

    def _backfill_backup_recovery_pub(self, phrase):
        """Store the Phase 3A backup recovery public key for vaults
        whose recovery phrase predates 3A. Runs only on a successful
        recovery unlock (the one human path that holds the phrase)."""
        if self._backup_recovery_pub is not None:
            return
        from recovery import recovery_backup_keypair

        _raw, pub = recovery_backup_keypair(phrase, self._vault_id)
        self._backup_recovery_pub = pub
        self._persist()

    # -- principal + generic wrapped slots (Phase 2A/2B) -------------------------
    def _require_human(self, action="this operation"):
        if self._principal is not None and self._principal != "human":
            raise PermissionError(f"agent sessions cannot perform {action}")

    def get_slot(self, slot_id):
        """Return the header slot dict with this id, or None (no unlock)."""
        data = self._read_raw_file()
        return next((s for s in data.get("slots", []) if s.get("id") == slot_id), None)

    def unlock_via_wrapped_key(self, slot_id, wrapping_key, principal):
        """Unlock using any wrapped-key slot whose key unwraps VK.

        Master and recovery slots qualify. An *agent* slot wraps only
        a bundle key in v3, so this path fails closed (VaultCorrupt)
        for agent slots — exactly the partitioning guarantee.
        """
        data = self._read_raw_file()
        if data.get("format") != _FORMAT_TOKEN or data.get("version") != 3:
            raise VaultCorrupt("wrapped-key unlock requires a Vault v3 vault")
        slot = next((s for s in data.get("slots", []) if s.get("id") == slot_id), None)
        if slot is None:
            raise WrongPassword(f"no unlock slot: {slot_id}")
        vault_key = self._unwrap_slot(slot, wrapping_key)
        if vault_key is None:
            raise WrongPassword("credential does not match this vault")
        self._vault_key = vault_key
        self._slots = data["slots"]
        entries = self._decrypt_v3_contents(data)
        self._legacy = False
        self._principal = principal
        if principal == "human":
            return self._finish_human_unlock(entries)
        self._entries = entries
        return self._entries

    def add_wrapped_slot(self, slot_id, wrapping_key, params=None):
        """Add/replace a slot wrapping the vault key. Human only."""
        self._require_unlocked()
        self._require_human("manage unlock slots")
        slot = self._make_slot(slot_id, wrapping_key, params)
        slot["algo"] = "argon2id"
        self._slots = [s for s in self._slots if s.get("id") != slot_id] + [slot]
        self._persist()
        return slot

    def remove_wrapped_slot(self, slot_id):
        self._require_unlocked()
        self._require_human("manage unlock slots")
        self._slots = [s for s in self._slots if s.get("id") != slot_id]
        self._persist()

    @classmethod
    def recover(cls, vault_file, phrase, new_master_password):
        """Full recovery flow: unlock by phrase, then set a new master password."""
        inst = cls.__new__(cls)
        inst.vault_file = vault_file
        inst.secret_input = new_master_password
        inst.algo = "argon2id"
        inst._vault_key = None
        inst._entries = None
        inst._slots = None
        inst._legacy = False
        inst._migrated_from = None
        inst._agents = {}
        inst._audit_head = ""
        inst._kmeta = None
        inst._deks = {}
        inst._origins = {}
        inst._entry_hashes = {}
        inst._inbox_priv = None
        inst._inbox_pub = None
        inst._vault_id = ""
        inst._anchor_seq = 0
        inst._anchored_head = ""
        inst._retired_audit_keys = {}
        inst._retired_pending_keys = {}
        inst._audit_mac_since = 0
        inst._anchor_recovery = False
        inst._raw_pending = {}
        inst._devices = {}
        inst._pairings = {}
        inst._backup_recovery_pub = None
        inst._principal = None
        if len(new_master_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "master password must be at least "
                f"{MIN_MASTER_PASSWORD_LENGTH} characters"
            )
        inst.unlock_via_recovery(phrase)
        inst.change_master(new_master_password)
        return inst

    def change_master(self, new_master_password):
        self._require_human("change the master password")
        if len(new_master_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "master password must be at least "
                f"{MIN_MASTER_PASSWORD_LENGTH} characters"
            )
        self._require_unlocked()
        self.secret_input = new_master_password
        self._slots = [s for s in self._slots if s.get("id") != "master"] + [self._master_slot()]
        self._persist()

    def rotate_vault_key(self):
        """Re-key the vault completely: new VK, new KMETA, new DEKs.

        Every ciphertext on the live file is re-encrypted under fresh
        keys, so any previously copied bundle, slot or backup-era key
        material is useless against the live vault. Every slot except
        the master is retired — agents are dropped (re-enroll them),
        recovery is dropped (set it up again) — and the rolling
        backup is deleted. The master password itself does not change.
        """
        self._require_human("rotate the vault key")
        self._require_unlocked()
        agents_dropped = len(self._agents)
        recovery_dropped = self.get_slot("recovery") is not None
        for agent_id, rec in self._agents.items():
            self._retired_audit_keys[agent_id] = rec["audit_mac_key"]
            self._retired_pending_keys[agent_id] = rec["pending_mac_key"]
        self._agents = {}
        self._backup_recovery_pub = None  # recovery slot is retired below
        self._vault_key = os.urandom(32)
        self._slots = [self._master_slot()]
        self._raw_pending = {}  # unprocessed submissions are discarded
        self._init_v3_material(self._entries)
        # _init_v3_material resets origins to "human"; agent-authored
        # provenance is moot once every key has rotated. The audit
        # anchor binds the old vault id — start it fresh.
        try:
            os.unlink(self._anchor_path())
        except OSError:
            pass
        self._anchor_seq = 0
        self._anchored_head = ""
        self._persist()
        backup = self.vault_file + ".bak"
        if os.path.exists(backup):
            os.unlink(backup)
        return {"agents_dropped": agents_dropped,
                "recovery_dropped": recovery_dropped}

    # -- TOTP ---------------------------------------------------------------------
    def totp_for(self, service, username=None, at=None):
        from totp import totp_now

        entry = self.get_entry(service, username)
        if not entry["totp_secret"]:
            raise ValueError(f"entry has no TOTP secret: {service}")
        return totp_now(entry["totp_secret"], at=at)

    # -- import ----------------------------------------------------------------------
    def import_entries(self, records, on_conflict="skip"):
        self._require_human("import entries")
        from importers import resolve_import

        existing = [dict(e) for e in self._require_unlocked()]
        merged, stats = resolve_import(records, existing, on_conflict=on_conflict)
        if stats["added"] or stats["overwritten"] or stats["kept_both"]:
            merged = [_normalize_entry(e) for e in merged]
            existing_ids = {e["id"] for e in self._entries}
            for record in merged:
                if record["id"] not in existing_ids:
                    self._register_new_entry(record)
            self._entries = merged
            self._persist()
        return stats

    # -- export ---------------------------------------------------------------------
    def export_vault_to_csv(self, path="mykey_export.csv"):
        self._require_human("export the vault")
        try:
            entries = self._require_unlocked()
        except VaultMissing:
            return False, "Auth Failed"
        if not entries:
            return False, "Auth Failed"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Service", "Username", "Password", "URL", "Notes"])
            for e in entries:
                writer.writerow([e["service"], e["username"], e["password"], e["url"], e["notes"]])
        os.chmod(path, 0o600)
        return True, "Exported!"
