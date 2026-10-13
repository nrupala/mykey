# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Browser-extension pairing — the key-value pattern, applied to the
extension channel.

A **browser pairing** is how the desktop app learns that one specific
browser extension installation may talk to the native messaging host:
the pairing record is keyed by the extension's runtime id and carries
the extension's X25519 public key, the scopes it was granted
(``fill``, ``save``), an optional expiry, and an enabled flag. It is
the same key-value shape as the agent registry (agents.py), the device
registry (devices.py) and the blob pairings (pairings.py):

* The extension generates its own X25519 keypair; the private key
  never leaves the browser profile.
* The human approves the pairing HERE, on the desktop: the extension
  presents a pairing payload (``MKEXTPAIR``), the desktop shows the
  payload's fingerprint, the human compares it with the fingerprint
  the extension itself displays, and only then is the record stored.
* Revoked extension ids can never be re-enrolled — a revoked browser
  profile must generate a fresh identity, exactly like revoked
  devices and revoked blob pairings.
* Expired, disabled or revoked pairings are refused by the host
  before any session key exists.

Where the records live: this pairing is between two programs on ONE
machine (the desktop app and a browser profile), so the registry is
the desktop app's local store — ``~/.mykey/extension-host.json``
(0600, written atomically) — NOT inside the vault. The same file
holds the host's own X25519 identity (the key the extension pins at
pairing time), the host settings (vault path, idle auto-lock,
clipboard clear seconds) and per-entry fill preferences keyed by
vault entry id (currently the "also fill on subdomains" allowance —
a per-machine browser-surface preference, deliberately not vault data
in v1, so the vault format did not have to change for it).

Nothing in this store is a vault secret: public keys, fingerprints,
labels, scopes, timestamps, preferences. A reader of this file learns
that a browser was paired, never what is in the vault.
"""

import hashlib
import json
import os
import re
import time

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
from mykey import MyKeyError, _b64d, _b64e

EXTENSION_SCOPES = ("fill", "save")
_PAYLOAD_FORMAT = "MKEXTPAIR"
_HOST_FORMAT = "MKHOST"
_STORE_FORMAT = "MKEXTSTORE"
_VERSION = 1

# Browser extension ids: Chromium ids are 32 lowercase letters a–p;
# Firefox add-on ids are either an email-shaped string or a
# {uuid}. Accept the union, reject anything with separators or
# whitespace — the id becomes a dict key and part of file content,
# never a path, but strictness here is free.
_EXT_ID_RE = re.compile(r"^[A-Za-z0-9@._\-{}]{8,128}$")

DEFAULT_AUTO_LOCK_SECONDS = 300
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 60
MIN_CLIPBOARD_CLEAR_SECONDS = 60
MAX_CLIPBOARD_CLEAR_SECONDS = 300


class ExtensionPairingError(MyKeyError):
    """Pairing payload, store, or registry operation failed."""


def _now() -> int:
    return int(time.time())


def extension_fingerprint(x25519_pub: bytes) -> str:
    """Grouped-hex SHA-256 fingerprint over a public key.

    Same presentation as pairing_fingerprint in pairings.py, so a
    human comparing fingerprints sees one consistent format.
    """
    digest = hashlib.sha256(x25519_pub).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def validate_scopes(scopes) -> list:
    out = []
    for scope in scopes or []:
        scope = str(scope).strip().lower()
        if scope not in EXTENSION_SCOPES:
            raise ExtensionPairingError(
                f"unknown extension scope {scope!r} — allowed: "
                + ", ".join(EXTENSION_SCOPES))
        if scope not in out:
            out.append(scope)
    if not out:
        raise ExtensionPairingError("a pairing needs at least one scope")
    return sorted(out)


def validate_extension_id(extension_id) -> str:
    extension_id = str(extension_id or "")
    if not _EXT_ID_RE.match(extension_id):
        raise ExtensionPairingError(
            f"malformed extension id: {extension_id!r}")
    return extension_id


def verify_payload(payload) -> dict:
    """Validate an extension pairing payload; return a normalized
    record. Fingerprints are always recomputed — a payload whose
    stated fingerprint does not match its key is refused."""
    if not isinstance(payload, dict) \
            or payload.get("format") != _PAYLOAD_FORMAT \
            or payload.get("version") != _VERSION:
        raise ExtensionPairingError(
            "not an extension pairing payload (format/version "
            "not recognized)")
    extension_id = validate_extension_id(payload.get("extension_id"))
    try:
        x_pub = _b64d(payload["x25519_pub"])
        X25519PublicKey.from_public_bytes(x_pub)
    except Exception as exc:
        raise ExtensionPairingError(
            f"pairing payload key is malformed: {exc}") from exc
    if len(x_pub) != 32:
        raise ExtensionPairingError("pairing payload key has the wrong length")
    fingerprint = extension_fingerprint(x_pub)
    if payload.get("fingerprint") != fingerprint:
        raise ExtensionPairingError(
            "pairing payload fingerprint does not match its key — "
            "refuse it")
    return {
        "extension_id": extension_id,
        "label": str(payload.get("label") or ""),
        "x25519_pub": _b64e(x_pub),
        "fingerprint": fingerprint,
    }


def default_store_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".mykey",
                        "extension-host.json")


class ExtensionHostStore:
    """The desktop host's local store (see module docstring).

    One JSON file, 0600, atomically replaced on every mutation —
    the same discipline as the device key file.
    """

    def __init__(self, data: dict):
        self._data = data

    # -- persistence ------------------------------------------------------

    @classmethod
    def load(cls, path=None, create=True) -> "ExtensionHostStore":
        path = path or default_store_path()
        if not os.path.exists(path):
            if not create:
                raise ExtensionPairingError(
                    f"no extension host store at {path}")
            store = cls(cls._fresh())
            store.save(path)
            return store
        if os.name == "posix":
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                raise ExtensionPairingError(
                    f"extension host store {path} is accessible by "
                    f"group/other (mode {mode:03o}) — refusing to use "
                    "it; chmod 600 it")
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise ExtensionPairingError(
                f"extension host store is unreadable: {exc}") from exc
        if data.get("format") != _STORE_FORMAT \
                or data.get("version") != _VERSION:
            raise ExtensionPairingError(
                "extension host store has an unsupported format")
        store = cls(data)
        store.path = path
        return store

    @staticmethod
    def _fresh() -> dict:
        priv = X25519PrivateKey.generate()
        x_priv = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                    NoEncryption())
        x_pub = priv.public_key().public_bytes(Encoding.Raw,
                                               PublicFormat.Raw)
        return {
            "format": _STORE_FORMAT,
            "version": _VERSION,
            "host": {
                "x25519_priv": _b64e(x_priv),
                "x25519_pub": _b64e(x_pub),
                "fingerprint": extension_fingerprint(x_pub),
                "created_at": _now(),
            },
            "settings": {
                "vault_file": "",
                "auto_lock_seconds": DEFAULT_AUTO_LOCK_SECONDS,
                "clipboard_clear_seconds":
                    DEFAULT_CLIPBOARD_CLEAR_SECONDS,
            },
            "pairings": {},
            "entry_prefs": {},
        }

    def save(self, path=None):
        path = path or getattr(self, "path", None) or default_store_path()
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        _atomic_write_json(path, self._data)
        return path

    # -- host identity ------------------------------------------------------

    @property
    def host_public_key(self) -> bytes:
        return _b64d(self._data["host"]["x25519_pub"])

    @property
    def host_private_key(self) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(
            _b64d(self._data["host"]["x25519_priv"]))

    @property
    def host_fingerprint(self) -> str:
        return self._data["host"]["fingerprint"]

    def host_payload(self) -> dict:
        """What the human carries INTO the extension to pin this host."""
        return {
            "format": _HOST_FORMAT,
            "version": _VERSION,
            "x25519_pub": self._data["host"]["x25519_pub"],
            "fingerprint": self.host_fingerprint,
        }

    # -- settings -----------------------------------------------------------

    @property
    def settings(self) -> dict:
        return dict(self._data.get("settings") or {})

    def set_setting(self, key, value):
        settings = self._data.setdefault("settings", {})
        if key == "clipboard_clear_seconds":
            value = int(value)
            if not (MIN_CLIPBOARD_CLEAR_SECONDS <= value
                    <= MAX_CLIPBOARD_CLEAR_SECONDS):
                raise ExtensionPairingError(
                    "clipboard clear must be between "
                    f"{MIN_CLIPBOARD_CLEAR_SECONDS} and "
                    f"{MAX_CLIPBOARD_CLEAR_SECONDS} seconds (the "
                    "house clipboard rule)")
        elif key == "auto_lock_seconds":
            value = int(value)
            if value < 30 or value > 86400:
                raise ExtensionPairingError(
                    "auto-lock must be between 30 seconds and a day")
        elif key == "vault_file":
            value = str(value)
        else:
            raise ExtensionPairingError(f"unknown host setting {key!r}")
        settings[key] = value
        self.save()
        return value

    # -- pairings registry --------------------------------------------------

    def enroll(self, payload, scopes, expires_days=None,
               save=True) -> dict:
        """Enroll a browser pairing from its payload.

        The CALLER is responsible for the human fingerprint
        confirmation BEFORE calling this (the CLI prints the
        fingerprint and asks) — enrollment trusts the payload exactly
        as far as verify_payload + that confirmation.
        """
        record = verify_payload(payload)
        record["scopes"] = validate_scopes(scopes)
        extension_id = record["extension_id"]
        existing = self._data["pairings"].get(extension_id)
        if existing is not None:
            if existing.get("revoked_at"):
                raise ExtensionPairingError(
                    "this extension id was revoked and can never be "
                    "re-enrolled; the browser profile must generate "
                    "a fresh identity (reset the pairing in the "
                    "extension's options)")
            raise ExtensionPairingError(
                f"extension already paired: {extension_id}")
        record["enrolled_at"] = _now()
        record["expires_at"] = (
            _now() + int(expires_days) * 86400
            if expires_days is not None else None)
        record["enabled"] = True
        record["revoked_at"] = None
        self._data["pairings"][extension_id] = record
        if save:
            self.save()
        return dict(record)

    def revoke(self, extension_id) -> dict:
        record = self._record(extension_id)
        if record.get("revoked_at"):
            raise ExtensionPairingError(
                f"extension pairing already revoked: {extension_id}")
        record["revoked_at"] = _now()
        record["enabled"] = False
        self.save()
        return dict(record)

    def set_enabled(self, extension_id, enabled: bool) -> dict:
        record = self._record(extension_id)
        if record.get("revoked_at"):
            raise ExtensionPairingError(
                "a revoked pairing cannot be re-enabled — enroll a "
                "fresh extension identity instead")
        record["enabled"] = bool(enabled)
        self.save()
        return dict(record)

    def _record(self, extension_id) -> dict:
        record = self._data["pairings"].get(extension_id)
        if record is None:
            raise ExtensionPairingError(
                f"no such extension pairing: {extension_id}")
        return record

    def get(self, extension_id):
        record = self._data["pairings"].get(extension_id)
        return dict(record) if record else None

    def pairing_active(self, extension_id, now=None) -> bool:
        """Enabled, unrevoked, unexpired — the only state the host
        will open a channel for."""
        record = self._data["pairings"].get(extension_id)
        if not record or not record.get("enabled", False) \
                or record.get("revoked_at"):
            return False
        expires = record.get("expires_at")
        if expires and (now if now is not None else _now()) > int(expires):
            return False
        return True

    def list_pairings(self):
        out = []
        for extension_id, rec in sorted(self._data["pairings"].items()):
            out.append({
                "extension_id": extension_id,
                "label": rec.get("label", ""),
                "fingerprint": rec.get("fingerprint", ""),
                "scopes": list(rec.get("scopes") or []),
                "enrolled_at": rec.get("enrolled_at"),
                "expires_at": rec.get("expires_at"),
                "enabled": bool(rec.get("enabled", False)),
                "revoked_at": rec.get("revoked_at"),
                "active": self.pairing_active(extension_id),
            })
        return out

    # -- per-entry fill preferences ------------------------------------------

    def entry_pref(self, entry_id, key, default=None):
        prefs = (self._data.get("entry_prefs") or {}).get(entry_id) or {}
        return prefs.get(key, default)

    def set_entry_pref(self, entry_id, key, value):
        if key != "fill_subdomains":
            raise ExtensionPairingError(
                f"unknown entry preference {key!r}")
        prefs = self._data.setdefault("entry_prefs", {})
        record = prefs.setdefault(entry_id, {})
        record[key] = bool(value)
        self.save()
        return record[key]
