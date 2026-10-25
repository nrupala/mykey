# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Licensing wave tests.

The free tier caps the entry COUNT (50) and the connections pool
(4) — and nothing else: every security feature stays free. A
signed licence token lifts the entry cap and carries its own
connection pool size. Grandfather rule: a vault already over a
limit opens and works fully; only ADDING pauses.

Shared-fixture contract with the mobile client: SHARED_TOKEN below
is minted ONCE from TEST_SEED with the Python implementation; the
TypeScript suite (mykey-mobile tests/licence.test.ts) carries the
identical string, verifies it, and mints a byte-identical token
from the same seed + payload with @noble/curves. If either side's
canonicalization drifts, both suites fail.
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import agents
import devices
import licensing
from agents import enroll_agent, open_agent_session, read_audit
from devices import DeviceIdentity
from mykey import MyKey, make_entry

MASTER = "licence-test-master-1"

TEST_SEED_HEX = (
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
TEST_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(TEST_SEED_HEX))
TEST_PUBLIC_B64 = base64.b64encode(
    TEST_PRIVATE.public_key().public_bytes_raw()).decode()
assert TEST_PUBLIC_B64 == "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="

TEST_DOB = "1990-05-17"
TEST_PAYLOAD = {
    "licence_id": "lic-test000000000001",
    "licensee": "test-buyer@example.com",
    "product": "mykey",
    "edition": "unlimited",
    "issued_at": "2026-10-13T00:00:00Z",
    "payment_date": "2026-10-01",
    "serial": "0123456789abcdeffedcba9876543210",
    "passcode": (
        "370B EF86 0C2C 5F40 B556 CAD0 239F B711 "
        "0E4E 612B B292 4C45 89E5 68D0 9FE2 8DE8"
    ),
    "max_connections": 20,
}
SHARED_TOKEN = "MKLIC1.eyJlZGl0aW9uIjoidW5saW1pdGVkIiwiaXNzdWVkX2F0IjoiMjAyNi0xMC0xM1QwMDowMDowMFoiLCJsaWNlbmNlX2lkIjoibGljLXRlc3QwMDAwMDAwMDAwMDEiLCJsaWNlbnNlZSI6InRlc3QtYnV5ZXJAZXhhbXBsZS5jb20iLCJtYXhfY29ubmVjdGlvbnMiOjIwLCJwYXNzY29kZSI6IjM3MEIgRUY4NiAwQzJDIDVGNDAgQjU1NiBDQUQwIDIzOUYgQjcxMSAwRTRFIDYxMkIgQjI5MiA0QzQ1IDg5RTUgNjhEMCA5RkUyIDhERTgiLCJwYXltZW50X2RhdGUiOiIyMDI2LTEwLTAxIiwicHJvZHVjdCI6Im15a2V5Iiwic2VyaWFsIjoiMDEyMzQ1Njc4OWFiY2RlZmZlZGNiYTk4NzY1NDMyMTAifQ.ENHUW7GNXGTHx5nUy1JK_cpCowiZrG16UNm8fXEXMRWgDNHIVOWL0z-YVqIpIXkD1N16NFbzSB69UeJg-EpmCg"


def mint(payload_overrides=None, key=TEST_PRIVATE):
    payload = dict(TEST_PAYLOAD)
    if payload_overrides:
        payload.update(payload_overrides)
    return licensing.make_token(payload, key)


def fresh_vault(tmp_path, name="vault.mykey"):
    """A new vault whose licence checks use the TEST authority and
    whose device-local licence slot is an isolated tmp file."""
    path = str(tmp_path / name)
    app = MyKey(MASTER, vault_file=path)
    app.licence_public_key_b64 = TEST_PUBLIC_B64
    return app


@pytest.fixture()
def device_slot(tmp_path, monkeypatch):
    slot = str(tmp_path / "device-licence.key")
    monkeypatch.setattr(licensing, "device_licence_path", lambda: slot)
    return slot


def reopen(path):
    app = MyKey(MASTER, vault_file=path)
    app.licence_public_key_b64 = TEST_PUBLIC_B64
    app.unlock()
    return app


def fill(app, n, prefix="svc"):
    for i in range(n):
        app.add_entry(make_entry(service=f"{prefix}-{i:03d}",
                                 username="user", password=f"pw-{i}"))


def activate_test_licence(app, **overrides):
    return licensing.activate_licence(app, mint(overrides))


# ---------------------------------------------------------------------------
# token verification (shared fixture)
# ---------------------------------------------------------------------------

def test_shared_token_verifies_in_python():
    payload = licensing.verify_token(SHARED_TOKEN,
                                     public_key_b64=TEST_PUBLIC_B64)
    assert payload == TEST_PAYLOAD


def test_shared_token_fails_against_production_key():
    # The fixture is a TEST licence: the production authority must
    # reject it (and a production licence fails the other way).
    with pytest.raises(licensing.LicenceInvalidError):
        licensing.verify_token(SHARED_TOKEN)


def test_tampered_tokens_fail_closed():
    good = SHARED_TOKEN
    mid = len(good) // 2
    flipped = good[:mid] + ("A" if good[mid] != "A" else "B") + good[mid + 1:]
    variants = [
        flipped,                      # payload byte flipped
        good[:-2] + "AA",             # signature byte flipped
        good.replace("MKLIC1", "MKLIC2"),
        "MKLIC1..", "", "not a licence", good + "extra",
        good.split(".")[0] + "." + good.split(".")[1],  # missing signature
    ]
    for bad in variants:
        with pytest.raises(licensing.LicenceInvalidError):
            licensing.verify_token(bad, public_key_b64=TEST_PUBLIC_B64)


def test_wrong_product_or_edition_fails():
    for overrides in ({"product": "other"}, {"edition": "pro"},
                      {"max_connections": -1}, {"max_connections": "20"}):
        with pytest.raises(licensing.LicenceInvalidError):
            licensing.verify_token(mint(overrides),
                                   public_key_b64=TEST_PUBLIC_B64)


def test_token_display_round_trip():
    grouped = licensing.format_token_for_display(SHARED_TOKEN)
    assert "\n" not in grouped and " " in grouped
    assert licensing.normalize_token("  " + grouped + "\n") == SHARED_TOKEN
    assert licensing.normalize_token(SHARED_TOKEN.lower()) != SHARED_TOKEN


# ---------------------------------------------------------------------------
# passcode + recovery hash (Owner Update #1)
# ---------------------------------------------------------------------------

def test_passcode_deterministic_and_input_sensitive():
    base = licensing.compute_passcode(
        "Test-Buyer@Example.com", "2026-10-01", TEST_DOB,
        TEST_PAYLOAD["serial"])
    assert base == TEST_PAYLOAD["passcode"]  # email is case-folded
    assert base == licensing.compute_passcode(
        "test-buyer@example.com", "2026-10-01", TEST_DOB,
        TEST_PAYLOAD["serial"])
    for changed in (
        ("other@example.com", "2026-10-01", TEST_DOB, TEST_PAYLOAD["serial"]),
        ("test-buyer@example.com", "2026-10-02", TEST_DOB,
         TEST_PAYLOAD["serial"]),
        ("test-buyer@example.com", "2026-10-01", "1990-05-18",
         TEST_PAYLOAD["serial"]),
        ("test-buyer@example.com", "2026-10-01", TEST_DOB, "ff" * 16),
    ):
        assert licensing.compute_passcode(*changed) != base


def test_recovery_hash_deterministic_salted_and_sensitive():
    salt = licensing.make_recovery_salt()
    h = licensing.recovery_hash("a@b.c", TEST_DOB, "2026-10-01", salt)
    assert h == licensing.recovery_hash("A@b.c", TEST_DOB, "2026-10-01", salt)
    assert h != licensing.recovery_hash("a@b.c", "1990-05-18", "2026-10-01",
                                        salt)
    other_salt = licensing.make_recovery_salt()
    assert h != licensing.recovery_hash("a@b.c", TEST_DOB, "2026-10-01",
                                        other_salt)


# ---------------------------------------------------------------------------
# entry cap
# ---------------------------------------------------------------------------

def test_cap_at_exactly_50(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    fill(app, 50)
    assert licensing.entry_count(app) == 50
    assert licensing.entry_allowance(app) == 0
    with pytest.raises(licensing.LicenceRequiredError) as exc:
        app.add_entry(make_entry(service="one-too-many", password="pw"))
    assert "50" in str(exc.value)  # plain message names the limit
    # Editing an existing entry is never blocked by the cap.
    app.update_entry("svc-000", password="rotated-pw")
    # Delete one -> exactly one slot -> add works -> full again.
    app.delete_entry("svc-000")
    app.add_entry(make_entry(service="backfill", password="pw"))
    assert licensing.entry_count(app) == 50
    with pytest.raises(licensing.LicenceRequiredError):
        app.add_entry(make_entry(service="nope", password="pw"))


def test_licence_activation_lifts_cap_and_travels(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    fill(app, 50)
    payload = activate_test_licence(app)
    assert payload["licence_id"] == TEST_PAYLOAD["licence_id"]
    assert licensing.is_licensed(app)
    fill(app, 10, prefix="extra")  # 60 total now — no cap when licensed
    assert licensing.entry_count(app) == 60
    # (a) the token inside the vault travels with the vault file.
    again = reopen(app.vault_file)
    assert licensing.is_licensed(again)
    assert again.get_setting("licence_key") is not None
    # (b) the device-local slot was written too (mode 0600).
    assert os.path.exists(device_slot)
    assert os.stat(device_slot).st_mode & 0o777 == 0o600
    # (c) a NEW vault on this device starts licensed from the slot.
    other = fresh_vault(tmp_path, "other.mykey")
    assert licensing.licence_payload(other) is not None
    assert licensing.is_licensed(other)


def test_bad_licence_key_rejected_plainly(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    with pytest.raises(licensing.LicenceInvalidError):
        licensing.activate_licence(app, "MKLIC1.garbage.garbage")
    assert not licensing.is_licensed(app)
    assert app.get_setting("licence_key") is None


def test_grandfathered_vault_over_cap(tmp_path, device_slot, tmp_path_factory):
    app = fresh_vault(tmp_path)
    activate_test_licence(app)
    fill(app, 60)
    # Licence goes away (fresh device, vault-only copy removed).
    app.set_setting("licence_key", None)
    app._persist()
    os.unlink(device_slot)
    human = reopen(app.vault_file)
    assert not licensing.is_licensed(human)
    assert licensing.entry_count(human) == 60
    # Everything except ADDING works: read, edit, export.
    entry = human.get_entry("svc-005")
    assert entry["password"] == "pw-5"
    human.update_entry("svc-005", password="new-pw-5")
    csv_path = str(tmp_path / "export.csv")
    ok, _msg = human.export_vault_to_csv(csv_path)
    assert ok
    with open(csv_path) as f:
        assert sum(1 for _ in f) == 61  # header + 60 rows
    with pytest.raises(licensing.LicenceRequiredError):
        human.add_entry(make_entry(service="blocked", password="pw"))
    # Trim to 49 -> one add fits -> cap bites again at 50.
    for i in range(49, 60):
        human.delete_entry(f"svc-{i:03d}")
    assert licensing.entry_count(human) == 49
    human.add_entry(make_entry(service="fits-now", password="pw"))
    with pytest.raises(licensing.LicenceRequiredError):
        human.add_entry(make_entry(service="blocked-2", password="pw"))


def test_csv_import_partial_fill_reports_held_back(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    fill(app, 48)
    records = [{"service": f"imp-{i}", "username": "u",
                "password": f"pw-{i}"} for i in range(5)]
    stats = app.import_entries(records)
    assert stats["added"] == 2
    assert stats["held_back"] == 3
    assert licensing.entry_count(app) == 50
    # Once licensed, the SAME import brings in exactly the held-back
    # three (the first two are now duplicates).
    activate_test_licence(app)
    stats = app.import_entries(records)
    assert stats["added"] == 3
    assert stats["held_back"] == 0
    assert licensing.entry_count(app) == 53


def test_agent_pending_insert_denied_at_cap_with_audit(
        tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    token = enroll_agent(app, "writer", ["write"])
    fill(app, 50)
    session = open_agent_session(app.vault_file, token)
    session.add_entry({"service": "agent-added", "username": "bot",
                       "password": "pw-agent"})
    # Human unlock: the insert is verified but the cap denies it.
    human = reopen(app.vault_file)
    assert licensing.entry_count(human) == 50
    with pytest.raises(KeyError):
        human.get_entry("agent-added")
    denies = [r for r in read_audit(app.vault_file)
              if r.get("action") == "add" and r.get("result") == "deny"
              and "licence" in (r.get("reason") or "")]
    assert len(denies) == 1
    assert denies[0]["agent"] == "writer"
    # A second unlicensed unlock does NOT spam a second denial.
    reopen(app.vault_file)
    denies = [r for r in read_audit(app.vault_file)
              if r.get("action") == "add" and r.get("result") == "deny"
              and "licence" in (r.get("reason") or "")]
    assert len(denies) == 1
    # The submission was never dropped: licence the vault and the
    # next unlock accepts it.
    licensed = reopen(app.vault_file)
    activate_test_licence(licensed)
    human2 = reopen(app.vault_file)
    assert licensing.entry_count(human2) == 51
    assert human2.get_entry("agent-added")["password"] == "pw-agent"



def test_status_line_plain_words(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    fill(app, 3)
    assert licensing.status_line(app) == (
        "Free · 3 of 50 passwords · 0 of 4 connections")
    activate_test_licence(app)
    assert licensing.status_line(app) == (
        "Licensed · unlimited passwords · 0 of 20 connections")


# ---------------------------------------------------------------------------
# connections pool (Owner Update #3 — ONE combined pool)
# ---------------------------------------------------------------------------

def _enroll_device(app, label):
    ident = DeviceIdentity.generate(label)
    return devices.enroll_device(app, ident.card())


def test_connections_pool_mixed_free(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    _enroll_device(app, "d1")
    _enroll_device(app, "d2")
    enroll_agent(app, "agent-1", ["list"])
    licensing.register_browser_pairing(app, {"id": "browser-1"})
    assert licensing.connections_used(app) == 4
    assert licensing.connections_breakdown(app) == {
        "devices": 2, "agents": 1, "browsers": 1, "total": 4}
    # The pool is full: a 5th connection of ANY kind is refused.
    with pytest.raises(licensing.LicenceRequiredError):
        _enroll_device(app, "d3")
    with pytest.raises(licensing.LicenceRequiredError):
        enroll_agent(app, "agent-2", ["list"])
    with pytest.raises(licensing.LicenceRequiredError):
        licensing.register_browser_pairing(app, {"id": "browser-2"})
    # Revoking a device frees a slot immediately.
    devices.revoke_device(app, devices.list_devices(app)[0]["device_id"])
    assert licensing.connections_used(app) == 3
    _enroll_device(app, "d3")
    assert licensing.connections_used(app) == 4
    # Unregistering the browser frees a slot too.
    licensing.unregister_browser_pairing(app, "browser-1")
    enroll_agent(app, "agent-2", ["list"])
    assert licensing.connections_used(app) == 4


def test_connections_pool_licensed_20_any_mix(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    activate_test_licence(app)  # max_connections: 20 from the statement
    assert licensing.connection_limit(app) == 20
    for i in range(12):
        _enroll_device(app, f"d{i}")
    for i in range(5):
        enroll_agent(app, f"agent-{i}", ["list"])
    for i in range(3):
        licensing.register_browser_pairing(app, {"id": f"b{i}"})
    assert licensing.connections_used(app) == 20
    with pytest.raises(licensing.LicenceRequiredError):
        _enroll_device(app, "one-too-many")


def test_connections_pool_size_read_from_licence(tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    activate_test_licence(app, max_connections=2)
    assert licensing.connection_limit(app) == 2
    _enroll_device(app, "d1")
    enroll_agent(app, "agent-1", ["list"])
    with pytest.raises(licensing.LicenceRequiredError):
        _enroll_device(app, "d2")


def test_connections_grandfathered_registries_keep_working(
        tmp_path, device_slot):
    app = fresh_vault(tmp_path)
    activate_test_licence(app)
    for i in range(5):
        _enroll_device(app, f"d{i}")
    token = enroll_agent(app, "keeper", ["list", "get:*"])
    app.add_entry(make_entry(service="github", username="octo",
                             password="pw-gh"))
    # Licence removed: 6 connections on a free pool of 4.
    app.set_setting("licence_key", None)
    app._persist()
    os.unlink(device_slot)
    human = reopen(app.vault_file)
    assert licensing.connections_used(human) == 6
    assert len(devices.list_devices(human)) == 5
    assert len(devices.active_devices(human)) == 5
    # Existing connections keep working fully…
    session = open_agent_session(app.vault_file, token)
    assert session.get("github")["password"] == "pw-gh"
    # …only NEW enrollments pause.
    with pytest.raises(licensing.LicenceRequiredError):
        _enroll_device(human, "d-new")
    with pytest.raises(licensing.LicenceRequiredError):
        enroll_agent(human, "another", ["list"])


# ---------------------------------------------------------------------------
# issuer tool + registry + recovery (test authority only)
# ---------------------------------------------------------------------------

import issue_licence as issuer  # noqa: E402


@pytest.fixture()
def test_authority(tmp_path, monkeypatch):
    """A throwaway GPG licence authority in tmp (never the real one)."""
    if shutil.which("gpg") is None:
        pytest.skip("gpg not available in this environment")
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    gen = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", "MyKey Test Authority <test@example.com>",
         "ed25519", "cert,sign", "never"],
        capture_output=True, env=env, text=True)
    assert gen.returncode == 0, gen.stderr
    secret_export = tmp_path / "secret.asc"
    exp = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--export-secret-keys"],
        capture_output=True, env=env)
    assert exp.returncode == 0
    secret_export.write_bytes(exp.stdout)
    pem = tmp_path / "signing.pem"
    issuer.cmd_derive_pem(argparse.Namespace(
        secret_export=str(secret_export), out=str(pem)))
    assert os.stat(pem).st_mode & 0o777 == 0o600
    monkeypatch.setenv("MYKEY_LICENCE_SIGNING_KEY", str(pem))
    monkeypatch.setenv("MYKEY_LICENCE_GPG_HOME", str(home))
    monkeypatch.setenv("MYKEY_LICENCE_REGISTRY",
                       str(tmp_path / "registry.jsonl"))
    monkeypatch.setenv("MYKEY_LICENCE_ALLOW_TEST_KEY", "1")
    export = subprocess.run(["gpg", "--batch", "--export"],
                            capture_output=True, env=env)
    pub_b64 = base64.b64encode(
        issuer.raw_public_from_gpg_export(export.stdout)).decode()
    return {"home": str(home), "pem": str(pem),
            "registry": str(tmp_path / "registry.jsonl"),
            "pub_b64": pub_b64, "tmp": tmp_path}


def _issue(authority, out_dir, **kw):
    args = argparse.Namespace(
        email=kw.get("email", "buyer@example.com"),
        payment_date=kw.get("payment_date", "2026-10-01"),
        identity_ref=kw.get("identity_ref", TEST_DOB),
        max_connections=20,
        out_dir=str(out_dir), registry=None)
    assert issuer.cmd_issue(args) == 0
    files = sorted(os.listdir(out_dir))
    licence_id = files[0].split(".")[0]
    return licence_id


def test_issuer_issue_recover_and_gpg_verify(test_authority, capsys):
    out_dir = test_authority["tmp"] / "artefacts"
    licence_id = _issue(test_authority, out_dir)
    capsys.readouterr()  # drain the issue summary before recover
    key_text = (out_dir / f"{licence_id}.licence-key.txt").read_text()
    token = licensing.normalize_token(key_text)
    # The issued key verifies against the ISSUING authority only.
    payload = licensing.verify_token(
        token, public_key_b64=test_authority["pub_b64"])
    assert payload["licensee"] == "buyer@example.com"
    assert payload["max_connections"] == 20
    with pytest.raises(licensing.LicenceInvalidError):
        licensing.verify_token(token)  # not the production authority
    # gpg --verify passes on the statement pair.
    check = subprocess.run(
        ["gpg", "--batch", "--homedir", test_authority["home"],
         "--verify", str(out_dir / f"{licence_id}.statement.json.asc"),
         str(out_dir / f"{licence_id}.statement.json")],
        capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    # Registry: 0600, has the recovery material, and NO raw DOB
    # anywhere — registry or buyer artefacts.
    registry = test_authority["registry"]
    assert os.stat(registry).st_mode & 0o777 == 0o600
    for path in [registry] + [str(out_dir / f) for f in os.listdir(out_dir)]:
        with open(path, "rb") as fh:
            assert TEST_DOB.encode() not in fh.read(), path
    # Recovery: the three inputs re-mint the IDENTICAL key.
    rc = issuer.cmd_recover(argparse.Namespace(
        email="buyer@example.com", payment_date="2026-10-01",
        identity_ref=TEST_DOB, registry=None))
    assert rc == 0
    recovered = licensing.normalize_token(capsys.readouterr().out)
    assert recovered == token
    # Wrong identity reference finds nothing.
    rc = issuer.cmd_recover(argparse.Namespace(
        email="buyer@example.com", payment_date="2026-10-01",
        identity_ref="1990-05-18", registry=None))
    assert rc == 1


def test_issuer_refuses_world_readable_key(test_authority):
    os.chmod(test_authority["pem"], 0o644)
    with pytest.raises(issuer.LicenceToolError):
        issuer.load_authority()


# ---------------------------------------------------------------------------
# cross-client fixture (written by the TS suite; skip until it exists)
# ---------------------------------------------------------------------------

def test_ts_written_licensed_vault_opens_licensed(device_slot):
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "ts-licensed.mykey")
    if not os.path.exists(fixture):
        pytest.skip("TS licensed-vault fixture not present yet "
                    "(written by mykey-mobile tests/licence.test.ts)")
    app = MyKey("cross-client fixture 1", vault_file=fixture)
    app.licence_public_key_b64 = TEST_PUBLIC_B64
    app.unlock()
    assert licensing.is_licensed(app)
    assert licensing.entry_count(app) >= 1
