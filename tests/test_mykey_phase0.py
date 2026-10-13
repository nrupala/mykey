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

"""Phase 0 safety tests.

The centrepiece is test_wrong_password_save_does_not_wipe_vault: it
encodes the behaviour verified in the 2026-10-12 audit, where saving
with a wrong master password silently reset the vault to a single
entry. This test FAILS on the pre-Phase-0 code (no WrongPassword is
raised, and the original entries are gone).
"""

import base64
import json
import os
import stat

import pytest
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mykey import (
    MyKey,
    VaultCorrupt,
    VaultMissing,
    WrongPassword,
)

CORRECT = "Correct-Horse-2026!"
WRONG = "wrong-password-99"


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


def test_round_trip(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    app.save_password("bank", "pw-bank-456")
    fresh = MyKey(CORRECT, vault_file=vault_path)
    assert fresh.get_password("github") == "pw-github-123"
    assert fresh.get_password("bank") == "pw-bank-456"


def test_vault_file_permissions_and_backup(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    assert stat.S_IMODE(os.stat(vault_path).st_mode) == 0o600
    app.save_password("bank", "pw-bank-456")
    backup = vault_path + ".bak"
    assert os.path.exists(backup)
    assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600
    # The backup holds the previous (single-entry) vault.
    backed_up = MyKey(CORRECT, vault_file=backup)
    assert backed_up.get_password("github") == "pw-github-123"


def test_wrong_password_get_raises_typed_error(vault_path):
    MyKey(CORRECT, vault_file=vault_path).save_password("github", "pw-github-123")
    with pytest.raises(WrongPassword):
        MyKey(WRONG, vault_file=vault_path).get_password("github")


def test_wrong_password_save_does_not_wipe_vault(vault_path):
    """REGRESSION (2026-10-12 audit): the old code wiped the vault here."""
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    app.save_password("bank", "pw-bank-456")

    with pytest.raises(WrongPassword):
        MyKey(WRONG, vault_file=vault_path).save_password("evil", "pw-evil")

    fresh = MyKey(CORRECT, vault_file=vault_path)
    assert fresh.get_password("github") == "pw-github-123"
    assert fresh.get_password("bank") == "pw-bank-456"
    with pytest.raises(KeyError):
        fresh.get_password("evil")


def test_missing_vault_is_empty_not_an_error_string(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    # Vault v2: unlock() returns the entry list (Phase 0 returned the raw dict).
    assert app.unlock() == []
    with pytest.raises(KeyError):
        app.get_password("nope")


def test_missing_service_raises_keyerror(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    with pytest.raises(KeyError):
        app.get_password("nope")


def test_corrupt_vault_raises_vaultcorrupt(vault_path):
    with open(vault_path, "w") as f:
        f.write("this is not a vault")
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).get_password("github")
    # And saving over a corrupt vault must refuse, not silently reset it.
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).save_password("x", "y")


def test_tampered_ciphertext_with_verifier_is_corrupt_not_wrong_password(vault_path):
    MyKey(CORRECT, vault_file=vault_path).save_password("github", "pw-github-123")
    data = json.load(open(vault_path))
    raw = bytearray(base64.b64decode(data["core"]["ciphertext"]))
    raw[0] ^= 0xFF
    data["core"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    json.dump(data, open(vault_path, "w"))
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).get_password("github")


def test_short_master_password_rejected():
    with pytest.raises(ValueError):
        MyKey("short")
    with pytest.raises(ValueError):
        MyKey("")


def test_short_generated_password_rejected(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    with pytest.raises(ValueError):
        app.generate_password(4)
    with pytest.raises(ValueError):
        app.generate_password(15)
    assert len(app.generate_password(16)) == 16
    assert len(app.generate_password(32)) == 32


def test_derive_key_raises_instead_of_returning_none(vault_path, monkeypatch):
    app = MyKey(CORRECT, vault_file=vault_path)
    monkeypatch.setattr(low_level, "hash_secret_raw", lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(Exception):
        app._derive_key(b"1234567812345678", "argon2id")


def _write_legacy_v1_vault(path, password, entries):
    """Write a vault exactly as the pre-Phase-0 code did (no verifier)."""
    salt, nonce = os.urandom(16), os.urandom(12)
    key = low_level.hash_secret_raw(
        secret=password.encode(), salt=salt, time_cost=3, memory_cost=65536,
        parallelism=4, hash_len=32, type=low_level.Type.ID,
    )
    ct = AESGCM(key).encrypt(nonce, json.dumps(entries).encode(), None)
    json.dump(
        {
            "algo": "argon2id",
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        },
        open(path, "w"),
    )


def test_legacy_v1_vault_still_loads(vault_path):
    _write_legacy_v1_vault(vault_path, CORRECT, {"github": "pw-github-123"})
    assert MyKey(CORRECT, vault_file=vault_path).get_password("github") == "pw-github-123"
    with pytest.raises(WrongPassword):
        MyKey(WRONG, vault_file=vault_path).get_password("github")


def test_legacy_v1_vault_wrong_password_save_does_not_wipe(vault_path):
    _write_legacy_v1_vault(vault_path, CORRECT, {"github": "pw-github-123"})
    with pytest.raises(WrongPassword):
        MyKey(WRONG, vault_file=vault_path).save_password("evil", "pw-evil")
    assert MyKey(CORRECT, vault_file=vault_path).get_password("github") == "pw-github-123"


def test_pbkdf2_round_trip(vault_path):
    app = MyKey(CORRECT, algo="pbkdf2", vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    assert MyKey(CORRECT, algo="pbkdf2", vault_file=vault_path).get_password("github") == "pw-github-123"
