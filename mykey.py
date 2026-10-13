# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Vault engine — Vault v2 (Phase 1) with Phase 0 safety semantics.

Vault v2 is envelope encryption:

* a random 256-bit vault key encrypts the vault contents
  (AES-256-GCM),
* the header (format token ``MKVLT``, version 2) stores the KDF
  parameters and one *wrapped-key slot* per unlock method — today the
  master-password slot and the BIP-39 recovery slot,
* adding, removing or rotating an unlock method only re-wraps the
  vault key; the vault contents are never re-encrypted for that.

Brand neutrality: no brand string appears anywhere in this module,
the file format, the AAD, or any KDF input. The format token is a
stable technical identifier. Renaming the product (see brand.py)
cannot affect any vault. Legacy v1 vaults (with or without the
Phase 0 verifier) are read and migrated to v2 on first save.

Entries are records: service, username, password, url, notes,
totp_secret, tags, created, updated, favourite — with full CRUD and
search. The Phase 0 API (save_password / get_password) is kept as a
thin layer over records.

All Phase 0 guarantees hold: typed errors (WrongPassword /
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MIN_MASTER_PASSWORD_LENGTH = 12
MIN_GENERATED_PASSWORD_LENGTH = 16
_FORMAT_TOKEN = "MKVLT"  # stable technical token — never a brand string
_FORMAT_VERSION = 2
_VERIFIER_LABEL = b"vault-verifier-v2"
_LEGACY_VERIFIER_LABEL = b"mykey-verifier-v1"  # Phase 0 v1 vaults only
_ARGON = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
_PBKDF2_ITERATIONS = 600000

ENTRY_FIELDS = (
    "service", "username", "password", "url", "notes",
    "totp_secret", "tags", "favourite",
)


class MyKeyError(Exception):
    """Base class for all vault errors."""


class WrongPassword(MyKeyError):
    """The supplied credential does not unlock this vault."""


class VaultCorrupt(MyKeyError):
    """The vault file exists but is damaged or not a vault."""


class VaultMissing(MyKeyError):
    """No vault file exists at the expected path."""


MyKeyWrongPassword = WrongPassword
MyKeyVaultCorrupt = VaultCorrupt
MyKeyVaultMissing = VaultMissing


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _now() -> int:
    return int(time.time())


def make_entry(service, password="", username="", url="", notes="",
               totp_secret="", tags=None, favourite=False, **extra):
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
    def _make_slot(self, slot_id, wrapping_key, params=None):
        nonce = os.urandom(12)
        ct = AESGCM(wrapping_key).encrypt(
            nonce, self._vault_key, f"slot:{slot_id}".encode()
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

    def _persist(self):
        """Encrypt the in-memory entries under the vault key and write v2."""
        nonce = os.urandom(12)
        plaintext = json.dumps({"entries": self._entries}).encode()
        ct = AESGCM(self._vault_key).encrypt(nonce, plaintext, _FORMAT_TOKEN.encode())
        payload = {
            "format": _FORMAT_TOKEN,
            "version": _FORMAT_VERSION,
            "slots": self._slots,
            "verifier": _b64e(
                hmac.new(self._vault_key, _VERIFIER_LABEL, hashlib.sha256).digest()
            ),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct),
        }
        self._atomic_write(payload)

    def _decrypt_v2_contents(self, data):
        try:
            plaintext = AESGCM(self._vault_key).decrypt(
                _b64d(data["nonce"]), _b64d(data["ciphertext"]), _FORMAT_TOKEN.encode()
            )
            parsed = json.loads(plaintext)
            return [_normalize_entry(e) for e in parsed["entries"]]
        except Exception as exc:
            raise VaultCorrupt("vault contents failed to decrypt") from exc

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
        self._slots = slots
        self._entries = self._decrypt_v2_contents(data)
        self._legacy = False
        return self._entries

    def _unlock_legacy(self, data):
        """Read a v1 / Phase-0 vault. Entries migrate to v2 on save."""
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
        self._entries = [
            make_entry(service=name, password=pw) for name, pw in raw.items()
        ]
        self._legacy = True
        return self._entries

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
            return self._entries
        if data.get("format") == _FORMAT_TOKEN and data.get("version") == _FORMAT_VERSION:
            return self._unlock_v2(data)
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

    def add_entry(self, entry):
        entries = self._require_unlocked()
        record = _normalize_entry(entry)
        if not record["service"]:
            raise ValueError("entry service must be non-empty")
        if self._find_index(record["service"], record["username"]) >= 0:
            raise ValueError(
                f"entry already exists: {record['service']} ({record['username']})"
            )
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
        self._persist()
        return dict(record)

    def delete_entry(self, service, username=None):
        idx = self._find_index(service, username)
        if idx < 0:
            raise KeyError(f"no entry for service: {service}")
        removed = self._entries.pop(idx)
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
        from recovery import derive_recovery_key, generate_mnemonic

        self._require_unlocked()
        phrase = generate_mnemonic(strength)
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
        if data.get("format") != _FORMAT_TOKEN:
            raise VaultCorrupt("recovery unlock requires a Vault v2 vault")
        slot = next((s for s in data.get("slots", []) if s.get("id") == "recovery"), None)
        if slot is None:
            raise WrongPassword("this vault has no recovery phrase set up")
        wrapping = derive_recovery_key(phrase, _b64d(slot["salt"]))
        vault_key = self._unwrap_slot(slot, wrapping)
        if vault_key is None:
            raise WrongPassword("recovery phrase does not match this vault")
        self._vault_key = vault_key
        self._slots = data["slots"]
        self._entries = self._decrypt_v2_contents(data)
        self._legacy = False
        return self._entries

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
        if len(new_master_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "master password must be at least "
                f"{MIN_MASTER_PASSWORD_LENGTH} characters"
            )
        inst.unlock_via_recovery(phrase)
        inst.change_master(new_master_password)
        return inst

    def change_master(self, new_master_password):
        if len(new_master_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "master password must be at least "
                f"{MIN_MASTER_PASSWORD_LENGTH} characters"
            )
        self._require_unlocked()
        self.secret_input = new_master_password
        self._slots = [s for s in self._slots if s.get("id") != "master"] + [self._master_slot()]
        self._persist()

    # -- TOTP ---------------------------------------------------------------------
    def totp_for(self, service, username=None, at=None):
        from totp import totp_now

        entry = self.get_entry(service, username)
        if not entry["totp_secret"]:
            raise ValueError(f"entry has no TOTP secret: {service}")
        return totp_now(entry["totp_secret"], at=at)

    # -- import ----------------------------------------------------------------------
    def import_entries(self, records, on_conflict="skip"):
        from importers import resolve_import

        existing = [dict(e) for e in self._require_unlocked()]
        merged, stats = resolve_import(records, existing, on_conflict=on_conflict)
        if stats["added"] or stats["overwritten"] or stats["kept_both"]:
            self._entries = [_normalize_entry(e) for e in merged]
            self._persist()
        return stats

    # -- export ---------------------------------------------------------------------
    def export_vault_to_csv(self, path="mykey_export.csv"):
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
