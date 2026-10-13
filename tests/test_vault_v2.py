# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

import base64
import json
import os
import stat

import pytest
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mykey import MyKey, VaultCorrupt, WrongPassword, make_entry
from recovery import validate_mnemonic

CORRECT = "Correct-Horse-2026!"
WRONG = "wrong-password-99"


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


def test_v2_round_trip_records(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.add_entry(make_entry(service="github", username="octocat",
                             password="pw-1", url="https://github.com",
                             notes="work", tags=["dev"], favourite=True))
    fresh = MyKey(CORRECT, vault_file=vault_path)
    entry = fresh.get_entry("github")
    assert entry["password"] == "pw-1"
    assert entry["username"] == "octocat"
    assert entry["tags"] == ["dev"] and entry["favourite"] is True
    data = json.load(open(vault_path))
    assert data["format"] == "MKVLT" and data["version"] == 3
    assert any(s["id"] == "master" for s in data["slots"])
    assert stat.S_IMODE(os.stat(vault_path).st_mode) == 0o600


def test_v2_crud_and_search(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.add_entry(make_entry(service="github", username="a", password="pw-1"))
    app.add_entry(make_entry(service="bank", username="b", password="pw-2",
                             notes="joint account"))
    assert len(app.list_entries()) == 2
    assert [e["service"] for e in app.search_entries("joint")] == ["bank"]
    assert [e["service"] for e in app.search_entries("GIT")] == ["github"]
    app.update_entry("github", password="pw-1b")
    assert app.get_password("github") == "pw-1b"
    with pytest.raises(ValueError):
        app.add_entry(make_entry(service="github", username="a", password="dup"))
    app.delete_entry("bank")
    assert [e["service"] for e in app.list_entries()] == ["github"]
    with pytest.raises(KeyError):
        app.get_entry("bank")


def test_v2_wrong_password_and_no_wipe(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    app.save_password("bank", "pw-bank-456")
    with pytest.raises(WrongPassword):
        MyKey(WRONG, vault_file=vault_path).save_password("evil", "pw-evil")
    fresh = MyKey(CORRECT, vault_file=vault_path)
    assert fresh.get_password("github") == "pw-github-123"
    assert fresh.get_password("bank") == "pw-bank-456"


def test_v2_tampered_contents_are_corrupt(vault_path):
    MyKey(CORRECT, vault_file=vault_path).save_password("github", "pw-1")
    data = json.load(open(vault_path))
    raw = bytearray(base64.b64decode(data["core"]["ciphertext"]))
    raw[0] ^= 0xFF
    data["core"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    json.dump(data, open(vault_path, "w"))
    with pytest.raises(VaultCorrupt):
        MyKey(CORRECT, vault_file=vault_path).unlock()


def _write_v1(path, password, entries, verifier=False):
    import hashlib, hmac as hmac_mod
    salt, nonce = os.urandom(16), os.urandom(12)
    key = low_level.hash_secret_raw(
        secret=password.encode(), salt=salt, time_cost=3, memory_cost=65536,
        parallelism=4, hash_len=32, type=low_level.Type.ID)
    ct = AESGCM(key).encrypt(nonce, json.dumps(entries).encode(), None)
    payload = {"algo": "argon2id", "salt": base64.b64encode(salt).decode(),
               "nonce": base64.b64encode(nonce).decode(),
               "ciphertext": base64.b64encode(ct).decode()}
    if verifier:
        payload["verifier"] = base64.b64encode(
            hmac_mod.new(key, b"mykey-verifier-v1", hashlib.sha256).digest()).decode()
    json.dump(payload, open(path, "w"))


@pytest.mark.parametrize("verifier", [False, True])
def test_v1_vaults_migrate_to_v2_on_save(vault_path, verifier):
    _write_v1(vault_path, CORRECT, {"github": "pw-github-123"}, verifier=verifier)
    app = MyKey(CORRECT, vault_file=vault_path)
    assert app.get_password("github") == "pw-github-123"
    with pytest.raises(WrongPassword):
        MyKey(WRONG, vault_file=vault_path).get_password("github")
    app.save_password("bank", "pw-bank-456")
    data = json.load(open(vault_path))
    assert data["format"] == "MKVLT" and data["version"] == 3
    fresh = MyKey(CORRECT, vault_file=vault_path)
    assert fresh.get_password("github") == "pw-github-123"
    assert fresh.get_password("bank") == "pw-bank-456"
    # the pre-migration vault survives as the rolling backup
    assert os.path.exists(vault_path + ".bak")


def test_recovery_unlock_end_to_end(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    phrase = app.setup_recovery()
    assert validate_mnemonic(phrase)
    recovered = MyKey(CORRECT, vault_file=vault_path)
    entries = recovered.unlock_via_recovery(phrase)
    assert [e["service"] for e in entries] == ["github"]


def test_recovery_wrong_phrase_rejected(vault_path):
    from recovery import generate_mnemonic
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    app.setup_recovery()
    other = generate_mnemonic()
    with pytest.raises(WrongPassword):
        MyKey(CORRECT, vault_file=vault_path).unlock_via_recovery(other)
    with pytest.raises(WrongPassword):
        MyKey(CORRECT, vault_file=vault_path).unlock_via_recovery("abandon " * 12)


def test_recovery_rotation_invalidates_old_phrase(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    old = app.setup_recovery()
    new = app.rotate_recovery()
    assert old != new
    with pytest.raises(WrongPassword):
        MyKey(CORRECT, vault_file=vault_path).unlock_via_recovery(old)
    entries = MyKey(CORRECT, vault_file=vault_path).unlock_via_recovery(new)
    assert entries[0]["service"] == "github"


def test_recover_sets_new_master(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    phrase = app.setup_recovery()
    MyKey.recover(vault_path, phrase, "Brand-New-Master-2026!")
    with pytest.raises(WrongPassword):
        MyKey(CORRECT, vault_file=vault_path).get_password("github")
    assert MyKey("Brand-New-Master-2026!", vault_file=vault_path).get_password("github") == "pw-github-123"


def test_change_master(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.save_password("github", "pw-github-123")
    app.change_master("Another-Master-2026!")
    with pytest.raises(WrongPassword):
        MyKey(CORRECT, vault_file=vault_path).get_password("github")
    assert MyKey("Another-Master-2026!", vault_file=vault_path).get_password("github") == "pw-github-123"


def test_totp_rfc6238_vector(vault_path):
    # RFC 6238 SHA-1 test seed "12345678901234567890" (base32-encoded).
    secret_b32 = base64.b32encode(b"12345678901234567890").decode()
    app = MyKey(CORRECT, vault_file=vault_path)
    app.add_entry(make_entry(service="example", password="pw", totp_secret=secret_b32))
    # RFC 6238 8-digit values are 94287082 / 07081804; 6-digit truncations:
    assert app.totp_for("example", at=59) == "287082"
    assert app.totp_for("example", at=1111111109) == "081804"
