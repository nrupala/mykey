# MIT License
#
# Copyright (c) 2026 Nrupal Akolkar
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

"""MyKey vault engine — Phase 0 (safety hardening of the v1 format).

Phase 0 keeps the v1 on-disk envelope (algo / salt / nonce / ciphertext)
and fixes the safety defects found in the 2026-10-12 audit:

* Typed errors: WrongPassword / VaultCorrupt / VaultMissing replace the
  old string sentinel ("Access Denied") that callers could — and did —
  mistake for data. ``save_password`` now REFUSES to write when an
  existing vault cannot be decrypted, instead of resetting it to {}
  (the behaviour-verified vault-wipe bug).
* A verifier (HMAC-SHA256 of a fixed label under the derived key) is
  stored with the vault so a wrong password is distinguishable from a
  corrupted vault. Legacy v1 vaults without a verifier still load:
  an AES-GCM failure on a legacy vault is reported as WrongPassword.
* Vault writes are atomic (temp file in the same directory, fsync,
  os.replace) with 0600 permissions, and the previous vault file is
  kept as a rolling backup (``<vault>.bak``, also 0600).
* ``_derive_key`` raises on failure — it never returns None.
* Minimums are enforced: a master password must be at least
  MIN_MASTER_PASSWORD_LENGTH characters, and generated passwords must
  be at least MIN_GENERATED_PASSWORD_LENGTH characters.
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

from argon2 import low_level
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MIN_MASTER_PASSWORD_LENGTH = 12
MIN_GENERATED_PASSWORD_LENGTH = 16
_VERIFIER_LABEL = b"mykey-verifier-v1"


class MyKeyError(Exception):
    """Base class for all MyKey vault errors."""


class WrongPassword(MyKeyError):
    """The supplied master password does not match this vault."""


class VaultCorrupt(MyKeyError):
    """The vault file exists but is damaged or not a MyKey vault."""


class VaultMissing(MyKeyError):
    """No vault file exists at the expected path."""


# Backwards-compatible aliases (Phase 0 introduces the canonical names).
MyKeyWrongPassword = WrongPassword
MyKeyVaultCorrupt = VaultCorrupt
MyKeyVaultMissing = VaultMissing


def _verifier_for(key: bytes) -> str:
    return base64.b64encode(
        hmac.new(key, _VERIFIER_LABEL, hashlib.sha256).digest()
    ).decode()


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

    # -- key derivation -------------------------------------------------
    def _derive_key(self, salt, algo):
        """Derive the 32-byte vault key. Raises on any failure."""
        try:
            if algo == "argon2id":
                return low_level.hash_secret_raw(
                    secret=self.secret_input.encode(),
                    salt=salt,
                    time_cost=3,
                    memory_cost=65536,
                    parallelism=4,
                    hash_len=32,
                    type=low_level.Type.ID,
                )
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000
            )
            return kdf.derive(self.secret_input.encode())
        except Exception as exc:  # never return None / a sentinel
            raise MyKeyError(f"key derivation failed: {exc}") from exc

    # -- password generation --------------------------------------------
    def generate_password(self, length=16):
        if length < MIN_GENERATED_PASSWORD_LENGTH:
            raise ValueError(
                "generated passwords must be at least "
                f"{MIN_GENERATED_PASSWORD_LENGTH} characters"
            )
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length))

    # -- vault IO ---------------------------------------------------------
    def _load_envelope(self):
        if not os.path.exists(self.vault_file):
            raise VaultMissing(f"no vault file at {self.vault_file}")
        try:
            with open(self.vault_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {
                "algo": data["algo"],
                "salt": base64.b64decode(data["salt"], validate=True),
                "nonce": base64.b64decode(data["nonce"], validate=True),
                "ciphertext": base64.b64decode(data["ciphertext"], validate=True),
                "verifier": data.get("verifier"),
            }
        except MyKeyError:
            raise
        except Exception as exc:
            raise VaultCorrupt(f"vault file is not a readable MyKey vault: {exc}") from exc

    def _read_physical_vault(self):
        """Return the decrypted vault dict.

        Raises VaultMissing, WrongPassword or VaultCorrupt — never
        returns an error string.
        """
        env = self._load_envelope()
        key = self._derive_key(env["salt"], env["algo"])
        if env["verifier"] is not None:
            if not hmac.compare_digest(_verifier_for(key), env["verifier"]):
                raise WrongPassword("master password does not match this vault")
            try:
                decrypted = AESGCM(key).decrypt(env["nonce"], env["ciphertext"], None)
            except InvalidTag as exc:
                raise VaultCorrupt(
                    "vault authenticated with this password but failed to decrypt"
                ) from exc
        else:
            # Legacy v1 vault (no verifier): GCM failure == wrong password.
            try:
                decrypted = AESGCM(key).decrypt(env["nonce"], env["ciphertext"], None)
            except InvalidTag as exc:
                raise WrongPassword(
                    "master password does not match this vault"
                ) from exc
        try:
            vault = json.loads(decrypted)
        except Exception as exc:
            raise VaultCorrupt("vault plaintext is not valid JSON") from exc
        if not isinstance(vault, dict):
            raise VaultCorrupt("vault plaintext is not an object")
        return vault

    def _write_physical_vault(self, vault_data):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt, self.algo)
        ciphertext = AESGCM(key).encrypt(
            nonce, json.dumps(vault_data).encode(), None
        )
        full_data = {
            "algo": self.algo,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "verifier": _verifier_for(key),
        }
        directory = os.path.dirname(os.path.abspath(self.vault_file))
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(full_data, f)
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

    # -- public API -------------------------------------------------------
    def unlock(self):
        """Verify the master password against the vault. Returns the vault.

        A missing vault is not an error here: it returns {} (a vault
        that has not been created yet). WrongPassword / VaultCorrupt
        are raised for an existing vault.
        """
        try:
            return self._read_physical_vault()
        except VaultMissing:
            return {}

    def save_password(self, service, password):
        if not service:
            raise ValueError("service must be non-empty")
        # CRITICAL (Phase 0 fix): if a vault exists and cannot be
        # decrypted with this password, REFUSE. Never reset it.
        vault_data = self.unlock()
        vault_data[service] = password
        self._write_physical_vault(vault_data)

    def get_password(self, service):
        vault = self.unlock()
        if service not in vault:
            raise KeyError(f"no entry for service: {service}")
        return vault[service]

    def export_vault_to_csv(self, path="mykey_export.csv"):
        try:
            vault = self._read_physical_vault()
        except VaultMissing:
            return False, "Auth Failed"
        if not vault:
            return False, "Auth Failed"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Service", "Password"])
            for k, v in vault.items():
                writer.writerow([k, v])
        os.chmod(path, 0o600)
        return True, "Exported!"
