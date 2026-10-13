# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Device identity and the device registry (Phase 3A).

Every installation has a *device identity*: an X25519 keypair
(encryption) and an Ed25519 keypair (signing), generated locally
and never derived from the vault. Two things hold it:

* the **key file** — this device's private keys, in a per-user
  state directory (default ``~/.mykey/device-keys.json``, mode
  0600; override with ``MYKEY_DEVICE_KEYS`` or an explicit path).
  The default location is deliberately NOT beside the vault, so a
  synced folder never carries private keys. For this wave the
  private keys are plaintext inside that 0600 file — stated
  plainly; no OS-keystore storage is claimed.
* the **registry** — public identities only, stored inside the
  vault's encrypted core (``devices``), so enrollments and
  revocations travel with the vault (including over user-cloud
  sync). Only a human-unlocked session can enroll or revoke.

A device is introduced to a vault with its public **card** (JSON:
pubkeys + fingerprint). The fingerprint is SHA-256 over the two
public keys, shown grouped for out-of-band comparison — enrollment
trusts the card only as far as the human compared fingerprints.

Revocation is recorded twice: in the registry (authoritative when
the vault is unlocked) and in a local sidecar revocation record
(``<vault>.revocations.json``), which import/sync checks consult
even against a rolled-back vault core. A revoked device id can
never be re-enrolled — a device that lost trust generates a fresh
identity. Revocation cannot make already-exported backup packages
undecryptable to a private key the device retained; that limit is
inherent and documented in SYNC_BACKUP.md.
"""

import hashlib
import json
import os
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
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

from mykey import MyKey, MyKeyError, _b64d, _b64e

import licensing

DEVICE_KEYS_ENV = "MYKEY_DEVICE_KEYS"
_KEYFILE_FORMAT = "MKDEVKEYS"
_CARD_FORMAT = "MKDEV"
_KEYFILE_VERSION = 1


class DeviceError(MyKeyError):
    """Device identity or registry operation failed."""


def _now() -> int:
    return int(time.time())


def _raw_pub(priv) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_priv(priv) -> bytes:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def device_fingerprint(x25519_pub: bytes, ed25519_pub: bytes) -> str:
    """Grouped-hex SHA-256 fingerprint over both public keys."""
    digest = hashlib.sha256(x25519_pub + ed25519_pub).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def default_device_keys_path() -> str:
    override = os.environ.get(DEVICE_KEYS_ENV)
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".mykey", "device-keys.json")


def _atomic_write_json(path, payload):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


class DeviceIdentity:
    """This installation's device keypair set."""

    def __init__(self, device_id, label, created_at,
                 x_priv_raw, e_priv_raw):
        self.device_id = device_id
        self.label = label or ""
        self.created_at = int(created_at)
        self._x_priv = X25519PrivateKey.from_private_bytes(x_priv_raw)
        self._e_priv = Ed25519PrivateKey.from_private_bytes(e_priv_raw)
        self.x_pub = _raw_pub(self._x_priv)
        self.e_pub = _raw_pub(self._e_priv)

    # raw private bytes (never leave this module's callers' hands
    # except into key wrapping/unwrapping operations)
    @property
    def x_priv_raw(self) -> bytes:
        return _raw_priv(self._x_priv)

    @property
    def e_priv_raw(self) -> bytes:
        return _raw_priv(self._e_priv)

    @property
    def fingerprint(self) -> str:
        return device_fingerprint(self.x_pub, self.e_pub)

    def card(self) -> dict:
        """The public identity card — safe to share, carries no secrets."""
        return {
            "format": _CARD_FORMAT,
            "version": 1,
            "device_id": self.device_id,
            "label": self.label,
            "x25519_pub": _b64e(self.x_pub),
            "ed25519_pub": _b64e(self.e_pub),
            "fingerprint": self.fingerprint,
        }

    def sign(self, data: bytes) -> bytes:
        return self._e_priv.sign(data)

    # -- persistence ------------------------------------------------------
    def save(self, path=None):
        path = path or default_device_keys_path()
        payload = {
            "format": _KEYFILE_FORMAT,
            "version": _KEYFILE_VERSION,
            "device_id": self.device_id,
            "label": self.label,
            "created_at": self.created_at,
            "x25519_priv": _b64e(self.x_priv_raw),
            "x25519_pub": _b64e(self.x_pub),
            "ed25519_priv": _b64e(self.e_priv_raw),
            "ed25519_pub": _b64e(self.e_pub),
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
    def generate(cls, label=""):
        return cls(uuid.uuid4().hex, label, _now(),
                   _raw_priv(X25519PrivateKey.generate()),
                   _raw_priv(Ed25519PrivateKey.generate()))

    @classmethod
    def load(cls, path=None):
        path = path or default_device_keys_path()
        if not os.path.exists(path):
            raise DeviceError(
                f"no device identity at {path} — run device-init first")
        if os.name == "posix":
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                raise DeviceError(
                    f"device key file {path} is accessible by group/other "
                    f"(mode {mode:03o}) — refusing to use it; chmod 600 it")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise DeviceError(f"device key file is unreadable: {exc}") from exc
        if data.get("format") != _KEYFILE_FORMAT or \
                data.get("version") != _KEYFILE_VERSION:
            raise DeviceError("device key file has an unsupported format")
        try:
            ident = cls(data["device_id"], data.get("label", ""),
                        data.get("created_at", 0),
                        _b64d(data["x25519_priv"]), _b64d(data["ed25519_priv"]))
            if _b64d(data["x25519_pub"]) != ident.x_pub or \
                    _b64d(data["ed25519_pub"]) != ident.e_pub:
                raise DeviceError(
                    "device key file is inconsistent: stored public keys "
                    "do not match the private keys")
            if data.get("fingerprint") != ident.fingerprint:
                raise DeviceError(
                    "device key file fingerprint mismatch — file was edited")
        except DeviceError:
            raise
        except Exception as exc:
            raise DeviceError(f"device key file is malformed: {exc}") from exc
        return ident


def verify_card(card) -> dict:
    """Validate a public device card and return a normalized record.

    Fingerprints are always recomputed — a card whose stated
    fingerprint does not match its keys is refused, never trusted.
    """
    if not isinstance(card, dict) or card.get("format") != _CARD_FORMAT \
            or card.get("version") != 1:
        raise DeviceError("not a device card (format/version not recognized)")
    device_id = card.get("device_id") or ""
    if len(device_id) != 32:
        raise DeviceError("device card has a malformed device id")
    try:
        int(device_id, 16)
        x_pub = _b64d(card["x25519_pub"])
        e_pub = _b64d(card["ed25519_pub"])
        # Constructing the keys validates their encodings.
        X25519PublicKey.from_public_bytes(x_pub)
        Ed25519PublicKey.from_public_bytes(e_pub)
    except Exception as exc:
        raise DeviceError(f"device card keys are malformed: {exc}") from exc
    if len(x_pub) != 32 or len(e_pub) != 32:
        raise DeviceError("device card keys have the wrong length")
    fingerprint = device_fingerprint(x_pub, e_pub)
    if card.get("fingerprint") != fingerprint:
        raise DeviceError(
            "device card fingerprint does not match its keys — refuse it")
    return {
        "device_id": device_id,
        "label": str(card.get("label") or ""),
        "x25519_pub": _b64e(x_pub),
        "ed25519_pub": _b64e(e_pub),
        "fingerprint": fingerprint,
    }


# ---------------------------------------------------------------------------
# registry (human-unlocked MyKey sessions only)
# ---------------------------------------------------------------------------

def _require_human_vault(vault: MyKey):
    if not isinstance(vault, MyKey):
        raise PermissionError("agent sessions cannot manage devices")
    vault._require_unlocked()
    vault._require_human("manage devices")


def enroll_device(vault: MyKey, card) -> dict:
    """Enroll a device's public card into the vault registry."""
    _require_human_vault(vault)
    record = verify_card(card)
    device_id = record["device_id"]
    existing = vault._devices.get(device_id)
    if existing is not None:
        if existing.get("revoked_at"):
            raise DeviceError(
                "this device id was revoked and can never be re-enrolled; "
                "the device must generate a fresh identity (device-init)")
        raise DeviceError(f"device already enrolled: {device_id}")
    # Licensing wave: an enrolled device holds one place in the
    # vault's connections pool (devices + agents + paired
    # browsers). Enrollment is the only moment the pool is checked.
    licensing.require_connection_slot(vault, "device")
    record["enrolled_at"] = _now()
    record["revoked_at"] = None
    vault._devices[device_id] = record
    vault._persist()
    return dict(record)


def revoke_device(vault: MyKey, device_id) -> dict:
    """Revoke a device: excluded from new backup packages, and its
    signatures stop being trusted wherever revocation state is read."""
    _require_human_vault(vault)
    record = vault._devices.get(device_id)
    if record is None:
        raise DeviceError(f"no such device: {device_id}")
    if record.get("revoked_at"):
        raise DeviceError(f"device already revoked: {device_id}")
    record["revoked_at"] = _now()
    vault._persist()
    record_revocation(vault.vault_file, record)
    return dict(record)


def list_devices(vault: MyKey):
    _require_human_vault(vault)
    out = []
    for device_id, rec in sorted(vault._devices.items()):
        out.append({
            "device_id": device_id,
            "label": rec.get("label", ""),
            "fingerprint": rec.get("fingerprint", ""),
            "enrolled_at": rec.get("enrolled_at"),
            "revoked_at": rec.get("revoked_at"),
        })
    return out


def active_devices(vault: MyKey):
    """Non-revoked registry records (backup-package recipients)."""
    return {did: dict(rec) for did, rec in vault._devices.items()
            if not rec.get("revoked_at")}


# ---------------------------------------------------------------------------
# local revocation record (sidecar; consulted even without an unlock)
# ---------------------------------------------------------------------------

def revocation_record_path(vault_file: str) -> str:
    return vault_file + ".revocations.json"


def read_revocations(vault_file: str) -> dict:
    """device_id -> {fingerprint, revoked_at}. Best-effort: a missing
    or unreadable record reads as empty (the registry in the core is
    authoritative whenever an unlock is available)."""
    path = revocation_record_path(vault_file)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data.get("revoked") or {}
    except Exception:
        pass
    return {}


def record_revocation(vault_file: str, record: dict):
    path = revocation_record_path(vault_file)
    revoked = read_revocations(vault_file)
    revoked[record["device_id"]] = {
        "fingerprint": record.get("fingerprint", ""),
        "revoked_at": record.get("revoked_at") or _now(),
    }
    _atomic_write_json(path, {"format": "MKREV", "version": 1,
                              "revoked": revoked})


def is_revoked(vault_file: str, device_id: str, since_ok_before=None) -> bool:
    rec = read_revocations(vault_file).get(device_id)
    return rec is not None
