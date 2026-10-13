# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# Passkey storage tests (passkey wave): a WebAuthn passkey record —
# including its credential PRIVATE key — is a Vault v3 entry of
# kind "passkey", encrypted under its own per-entry key class
# (DEK_passkey), sealed by a core hash like the other blobs, and
# NEVER present in any agent bundle. Desktop is read + delete in
# v1; creation/use lives in the phone client (see PASSKEYS.md).

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import agents
from mykey import (
    MyKey,
    VaultCorrupt,
    WrongPassword,
    _b64d,
    _b64e,
    _dec,
    make_entry,
    validate_passkey_record,
)

PASSWORD = "Passkey-Test-Password-1"
FIXED_SCALAR = 0x5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED


def _test_keypair():
    priv = ec.derive_private_key(FIXED_SCALAR, ec.SECP256R1())
    pkcs8 = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    point = priv.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    return pkcs8, point


def _record(sign_count=3):
    pkcs8, point = _test_keypair()
    return {
        "rp_id": "example.com",
        "user_id": _b64e(b"fixture-user-01"),
        "user_name": "user@example.com",
        "user_display_name": "Fixture User",
        "credential_id": _b64e(bytes(range(16))),
        "alg": -7,
        "public_key": _b64e(point),
        "private_key": _b64e(pkcs8),
        "sign_count": sign_count,
        "transports": ["internal"],
        "created_at": 1700000000,
        "aaguid": _b64e(bytes(16)),
        "backup_eligible": True,
        "backed_up": True,
    }


def _vault(tmp_path, name="vault.mykey"):
    path = str(tmp_path / name)
    app = MyKey(PASSWORD, vault_file=path)
    app.unlock()  # creates a fresh Vault v3 vault
    return app, path


def _reopen(path, password=PASSWORD):
    app = MyKey(password, vault_file=path)
    app.unlock()
    return app


def test_add_and_reopen_round_trip(tmp_path):
    app, path = _vault(tmp_path)
    app.add_entry(make_entry(service="github", password="pw-1"))
    entry = app.add_passkey(_record())
    assert entry["kind"] == "passkey"
    assert entry["service"] == "example.com"
    assert entry["password"] == ""

    again = _reopen(path)
    keys = again.list_passkeys()
    assert len(keys) == 1
    rec = keys[0]["passkey"]
    assert rec == validate_passkey_record(_record())
    pkcs8, point = _test_keypair()
    assert _b64d(rec["private_key"]) == pkcs8
    assert _b64d(rec["public_key"]) == point
    # the login entry survived alongside
    assert again.get_entry("github")["password"] == "pw-1"


def test_private_key_never_in_plaintext_file(tmp_path):
    app, path = _vault(tmp_path)
    app.add_passkey(_record())
    raw = open(path, "rb").read()
    pkcs8, _point = _test_keypair()
    assert _b64e(pkcs8).encode() not in raw
    assert _b64e(bytes(range(16))).encode() not in raw  # credential id


def test_record_validation():
    with pytest.raises(ValueError):
        validate_passkey_record({"rp_id": "example.com"})
    bad = _record()
    bad["private_key"] = "not base64!!"
    with pytest.raises(ValueError):
        validate_passkey_record(bad)
    bad2 = _record()
    bad2["sign_count"] = -1
    with pytest.raises(ValueError):
        validate_passkey_record(bad2)


def test_agent_bundle_never_contains_passkey(tmp_path):
    app, path = _vault(tmp_path)
    app.add_entry(make_entry(service="github", password="pw-1"))
    entry = app.add_passkey(_record())
    token = agents.enroll_agent(app, "pk-agent", ["list", "get:*"])
    app.unlock()  # re-read from disk with the agent enrolled

    rec = app._agents["pk-agent"]
    bundles = app._build_bundles()
    bundle = json.loads(_dec(_b64d(rec["bundle_key"]),
                             bundles["pk-agent"], b"bundle:v3:pk-agent"))
    assert entry["id"] not in bundle["targets"]
    assert "example.com" not in bundle["services"]
    blob = json.dumps(bundle)
    assert "passkey" not in blob
    assert _record()["credential_id"] not in blob

    session = agents.open_agent_session(path, token)
    with pytest.raises((agents.AgentScopeError, agents.AgentAuthError)):
        session.get("example.com")
    # the in-scope login is still readable
    assert session.get("github")["password"] == "pw-1"


def test_tampered_passkey_blob_fails_closed(tmp_path):
    app, path = _vault(tmp_path)
    app.add_passkey(_record())
    data = json.load(open(path))
    obj = next(o for o in data["entries"] if o.get("passkey"))
    ct = obj["passkey"]["ciphertext"]
    obj["passkey"]["ciphertext"] = ("A" if ct[0] != "A" else "B") + ct[1:]
    json.dump(data, open(path, "w"))
    with pytest.raises(VaultCorrupt):
        _reopen(path)


def test_missing_sealed_hash_fails_closed(tmp_path):
    app, path = _vault(tmp_path)
    app.add_passkey(_record())
    # Tamper the sealed core directly: decrypt it with the vault key
    # this session holds, drop the passkey hash, re-seal. A file whose
    # passkey blob has no matching core hash must fail closed on open.
    # (Clearing the in-memory map then calling _persist() would not
    # test this — _persist recomputes the hash from the blob.)
    from mykey import _aad, _dec, _enc
    data = json.load(open(path))
    core = json.loads(_dec(app._vault_key, data["core"],
                           _aad("core", data["vault_id"])))
    core["passkey_hashes"] = {}
    data["core"] = _enc(app._vault_key, json.dumps(core).encode(),
                        _aad("core", data["vault_id"]))
    json.dump(data, open(path, "w"))
    with pytest.raises(VaultCorrupt):
        _reopen(path)


def test_sign_count_moves_forward_only(tmp_path):
    app, path = _vault(tmp_path)
    entry = app.add_passkey(_record(sign_count=3))
    app.set_passkey_sign_count(entry["id"], 4)
    with pytest.raises(ValueError):
        app.set_passkey_sign_count(entry["id"], 2)
    again = _reopen(path)
    assert again.list_passkeys()[0]["passkey"]["sign_count"] == 4


def test_delete_passkey(tmp_path):
    app, path = _vault(tmp_path)
    app.add_passkey(_record())
    app.delete_entry("example.com", "user@example.com")
    again = _reopen(path)
    assert again.list_passkeys() == []
    assert again.list_entries() == []


def test_rotate_vault_key_keeps_passkey(tmp_path):
    app, path = _vault(tmp_path)
    app.add_passkey(_record())
    app.rotate_vault_key()
    again = _reopen(path)
    keys = again.list_passkeys()
    assert len(keys) == 1
    pkcs8, _ = _test_keypair()
    assert _b64d(keys[0]["passkey"]["private_key"]) == pkcs8


def test_import_never_overwrites_passkey(tmp_path):
    app, _path = _vault(tmp_path)
    app.add_passkey(_record())
    stats = app.import_entries(
        [{"service": "example.com", "username": "user@example.com",
          "password": "csv-password", "url": "", "notes": "",
          "totp_secret": "", "tags": [], "favourite": False}],
        on_conflict="overwrite")
    assert stats["skipped_conflicts"] >= 1
    entry = app.get_entry("example.com", "user@example.com")
    assert entry["kind"] == "passkey"
    assert entry["password"] == ""


def test_csv_export_skips_passkeys(tmp_path):
    app, _path = _vault(tmp_path)
    app.add_entry(make_entry(service="github", password="pw-1"))
    app.add_passkey(_record())
    out = str(tmp_path / "export.csv")
    ok, _msg = app.export_vault_to_csv(out)
    assert ok
    text = open(out).read()
    assert "github" in text
    assert "example.com" not in text


def test_wrong_password_still_typed(tmp_path):
    app, path = _vault(tmp_path)
    app.add_passkey(_record())
    with pytest.raises(WrongPassword):
        _reopen(path, password="Wrong-Password-999")


def test_login_only_vault_unaffected(tmp_path):
    app, path = _vault(tmp_path)
    app.add_entry(make_entry(service="github", password="pw-1"))
    data = json.load(open(path))
    for obj in data["entries"]:
        assert obj.get("passkey") is None
    again = _reopen(path)
    assert again.list_passkeys() == []
    assert again.get_entry("github")["password"] == "pw-1"
    assert os.path.exists(path)
