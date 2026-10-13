# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Key-value pairing for cloud storage and export targets.

A **pairing** is how this vault learns that some outside target —
another installation acting as a data target, a cloud folder, an
export destination — may receive encrypted blobs from it. The
registry lives inside the vault's encrypted core (``pairings``),
keyed by target id, next to the device registry and the agent
registry, and follows their rules:

* Only a human-unlocked session can enroll, enable, disable or
  revoke a pairing. Agents never can.
* A target is introduced with a **pairing payload** (JSON, format
  ``MKPAIR``): target id + X25519 public key + a fingerprint the
  human compares against what the target itself shows before
  confirming. Enrollment trusts the payload only as far as that
  comparison — the same trust model as device cards.
* Each pairing carries **scopes** — ``push`` and ``pull`` for sync
  folders, ``export`` for backup-package recipients — an optional
  expiry, and an enabled flag. Expired, disabled or revoked
  pairings receive nothing new.

What pairing DOES with those scopes, concretely:

* **Backup packages** (backup_pkg) seal a copy of the package
  content key to every enabled, unexpired pairing holding the
  ``export`` scope. A target that was never paired, or was paired
  without ``export``, gets no slot and cannot open the package.
* **Sync** (vaultsync) gates a folder bound to a target id: pushes
  need ``push``, pulls need ``pull``. Sync runs without an unlock,
  so it consults pins copied from this registry into the local sync
  state at human unlock — the same pattern as device signer pins.

Revocation, stated plainly: a pairing target holds NO vault key
material — no entry keys, no bundles, no unlock slot — so there is
nothing of its inside the vault to rotate. What revocation does is
total for the future: package content keys are random per export,
so the next package simply has no slot for a revoked target, and
sync stops at the next pin refresh (the CLI refreshes pins in the
same session as the revoke). Packages exported BEFORE revocation
stay openable by a private key the target retained — the same
inherent limit as device revocation, documented in SYNC_BACKUP.md.
"""

import hashlib
import json
import os
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from devices import _atomic_write_json
from mykey import MyKey, MyKeyError, _b64d, _b64e

PAIRING_TYPES = ("device", "cloud-folder", "export")
PAIRING_SCOPES = ("push", "pull", "export")
_PAYLOAD_FORMAT = "MKPAIR"
_KEYFILE_FORMAT = "MKPAIRKEYS"
_VERSION = 1


class PairingError(MyKeyError):
    """Pairing payload, target key, or registry operation failed."""


def _now() -> int:
    return int(time.time())


def pairing_fingerprint(x25519_pub: bytes) -> str:
    """Grouped-hex SHA-256 fingerprint over the target's public key."""
    digest = hashlib.sha256(x25519_pub).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def validate_scopes(scopes) -> list:
    out = []
    for scope in scopes or []:
        scope = str(scope).strip().lower()
        if scope not in PAIRING_SCOPES:
            raise PairingError(
                f"unknown pairing scope {scope!r} — allowed: "
                + ", ".join(PAIRING_SCOPES))
        if scope not in out:
            out.append(scope)
    if not out:
        raise PairingError("a pairing needs at least one scope")
    return sorted(out)


# ---------------------------------------------------------------------------
# target side: the keypair a target holds and the payload it presents
# ---------------------------------------------------------------------------

def _raw_pub(priv) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_priv(priv) -> bytes:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


class PairingTargetIdentity:
    """A pairing target's own identity: one X25519 keypair.

    The private key never leaves the target. What travels is the
    payload (public key + fingerprint) the human enrolls.
    """

    def __init__(self, target_id, label, target_type, created_at,
                 x_priv_raw):
        self.target_id = target_id
        self.label = label or ""
        self.target_type = target_type
        self.created_at = int(created_at)
        self._x_priv = X25519PrivateKey.from_private_bytes(x_priv_raw)
        self.x_pub = _raw_pub(self._x_priv)

    @property
    def x_priv_raw(self) -> bytes:
        return _raw_priv(self._x_priv)

    @property
    def fingerprint(self) -> str:
        return pairing_fingerprint(self.x_pub)

    def payload(self) -> dict:
        """The public pairing payload — safe to share, carries no secrets."""
        return {
            "format": _PAYLOAD_FORMAT,
            "version": _VERSION,
            "target_id": self.target_id,
            "label": self.label,
            "type": self.target_type,
            "x25519_pub": _b64e(self.x_pub),
            "fingerprint": self.fingerprint,
        }

    # -- persistence (0600 key file, same discipline as device keys)
    def save(self, path):
        payload = {
            "format": _KEYFILE_FORMAT,
            "version": _VERSION,
            "target_id": self.target_id,
            "label": self.label,
            "type": self.target_type,
            "created_at": self.created_at,
            "x25519_priv": _b64e(self.x_priv_raw),
            "x25519_pub": _b64e(self.x_pub),
            "fingerprint": self.fingerprint,
        }
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        _atomic_write_json(path, payload)
        return path

    @classmethod
    def generate(cls, target_type="export", label=""):
        if target_type not in PAIRING_TYPES:
            raise PairingError(
                f"unknown pairing type {target_type!r} — allowed: "
                + ", ".join(PAIRING_TYPES))
        return cls(uuid.uuid4().hex, label, target_type, _now(),
                   _raw_priv(X25519PrivateKey.generate()))

    @classmethod
    def load(cls, path):
        if not os.path.exists(path):
            raise PairingError(f"no pairing target key at {path}")
        if os.name == "posix":
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                raise PairingError(
                    f"pairing key file {path} is accessible by "
                    f"group/other (mode {mode:03o}) — refusing to use "
                    "it; chmod 600 it")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise PairingError(
                f"pairing key file is unreadable: {exc}") from exc
        if data.get("format") != _KEYFILE_FORMAT or \
                data.get("version") != _VERSION:
            raise PairingError("pairing key file has an unsupported format")
        try:
            ident = cls(data["target_id"], data.get("label", ""),
                        data.get("type", "export"),
                        data.get("created_at", 0),
                        _b64d(data["x25519_priv"]))
            if _b64d(data["x25519_pub"]) != ident.x_pub or \
                    data.get("fingerprint") != ident.fingerprint:
                raise PairingError(
                    "pairing key file is inconsistent: stored public "
                    "key or fingerprint does not match the private key")
        except PairingError:
            raise
        except Exception as exc:
            raise PairingError(
                f"pairing key file is malformed: {exc}") from exc
        return ident


def verify_payload(payload) -> dict:
    """Validate a pairing payload and return a normalized record.

    Fingerprints are always recomputed — a payload whose stated
    fingerprint does not match its key is refused, never trusted.
    """
    if not isinstance(payload, dict) \
            or payload.get("format") != _PAYLOAD_FORMAT \
            or payload.get("version") != _VERSION:
        raise PairingError(
            "not a pairing payload (format/version not recognized)")
    target_id = payload.get("target_id") or ""
    if len(target_id) != 32:
        raise PairingError("pairing payload has a malformed target id")
    target_type = payload.get("type")
    if target_type not in PAIRING_TYPES:
        raise PairingError(
            f"pairing payload has an unknown type {target_type!r}")
    try:
        int(target_id, 16)
        x_pub = _b64d(payload["x25519_pub"])
        X25519PublicKey.from_public_bytes(x_pub)  # validates encoding
    except Exception as exc:
        raise PairingError(f"pairing payload key is malformed: {exc}") from exc
    if len(x_pub) != 32:
        raise PairingError("pairing payload key has the wrong length")
    fingerprint = pairing_fingerprint(x_pub)
    if payload.get("fingerprint") != fingerprint:
        raise PairingError(
            "pairing payload fingerprint does not match its key — "
            "refuse it")
    return {
        "target_id": target_id,
        "label": str(payload.get("label") or ""),
        "type": target_type,
        "x25519_pub": _b64e(x_pub),
        "fingerprint": fingerprint,
    }


# ---------------------------------------------------------------------------
# registry (human-unlocked MyKey sessions only)
# ---------------------------------------------------------------------------

def _require_human_vault(vault: MyKey):
    if not isinstance(vault, MyKey):
        raise PermissionError("agent sessions cannot manage pairings")
    vault._require_unlocked()
    vault._require_human("manage pairings")


def pairing_active(rec, now=None) -> bool:
    """Enabled, unrevoked, unexpired — the only state that receives
    new wraps or sync access."""
    if not rec or not rec.get("enabled", False) or rec.get("revoked_at"):
        return False
    expires = rec.get("expires_at")
    if expires and (now if now is not None else _now()) > int(expires):
        return False
    return True


def enroll_pairing(vault: MyKey, payload, scopes, expires_days=None) -> dict:
    """Enroll a pairing target from its payload.

    The caller (CLI/GUI) is responsible for the human fingerprint
    confirmation BEFORE calling this — enrollment itself trusts the
    payload exactly as far as verify_payload + that confirmation.
    """
    _require_human_vault(vault)
    record = verify_payload(payload)
    record["scopes"] = validate_scopes(scopes)
    target_id = record["target_id"]
    existing = vault._pairings.get(target_id)
    if existing is not None:
        if existing.get("revoked_at"):
            raise PairingError(
                "this target id was revoked and can never be "
                "re-enrolled; the target must generate a fresh "
                "identity (pairing-keygen)")
        raise PairingError(f"target already paired: {target_id}")
    record["enrolled_at"] = _now()
    record["expires_at"] = (
        _now() + int(expires_days) * 86400
        if expires_days is not None else None)
    record["enabled"] = True
    record["revoked_at"] = None
    vault._pairings[target_id] = record
    vault._persist()
    return dict(record)


def revoke_pairing(vault: MyKey, target_id) -> dict:
    """Revoke a pairing: no new package slots, no sync access.

    See the module docstring for exactly what this does and does
    not reach (packages already exported stay openable — inherent).
    """
    _require_human_vault(vault)
    record = vault._pairings.get(target_id)
    if record is None:
        raise PairingError(f"no such pairing target: {target_id}")
    if record.get("revoked_at"):
        raise PairingError(f"pairing target already revoked: {target_id}")
    record["revoked_at"] = _now()
    record["enabled"] = False
    vault._persist()
    return dict(record)


def set_pairing_enabled(vault: MyKey, target_id, enabled: bool) -> dict:
    _require_human_vault(vault)
    record = vault._pairings.get(target_id)
    if record is None:
        raise PairingError(f"no such pairing target: {target_id}")
    if record.get("revoked_at"):
        raise PairingError("a revoked pairing cannot be re-enabled — "
                           "enroll a fresh target identity instead")
    record["enabled"] = bool(enabled)
    vault._persist()
    return dict(record)


def list_pairings(vault: MyKey):
    _require_human_vault(vault)
    out = []
    for target_id, rec in sorted(vault._pairings.items()):
        out.append({
            "target_id": target_id,
            "label": rec.get("label", ""),
            "type": rec.get("type", ""),
            "fingerprint": rec.get("fingerprint", ""),
            "scopes": list(rec.get("scopes") or []),
            "enrolled_at": rec.get("enrolled_at"),
            "expires_at": rec.get("expires_at"),
            "enabled": bool(rec.get("enabled", False)),
            "revoked_at": rec.get("revoked_at"),
            "active": pairing_active(rec),
        })
    return out


def active_pairings(vault: MyKey, scope=None):
    """Pairings that may receive new wraps right now (optionally
    filtered to one scope). No human gate here — callers like
    backup export already hold a human-unlocked session."""
    out = {}
    for target_id, rec in vault._pairings.items():
        if not pairing_active(rec):
            continue
        if scope and scope not in (rec.get("scopes") or []):
            continue
        out[target_id] = dict(rec)
    return out
