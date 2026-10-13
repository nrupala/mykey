# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Phase 3A: device identity, user-cloud sync, backup packages.

Behaviour tests, written against the security claims: sync is
conflict-safe and rollback-resistant, bundles and packages never
carry plaintext, backup import fails closed (tamper, wrong
recipient, revoked signer, downgrade), and a revoked device is
excluded from NEW packages while old ones stay openable — the
inherent limit, asserted as behaviour so it can never be
"smoothed" away silently.
"""

import json
import os
import stat
import subprocess
import sys

import pytest

import backup_pkg
import devices
import vaultsync
from backup_pkg import BackupError, BackupRefused, export_package, \
    import_package, inspect_package
from devices import DeviceError, DeviceIdentity
from mykey import MyKey, make_entry
from vaultsync import SyncConflict, SyncCorrupt, SyncError, VaultSync

MASTER = "Correct-Horse-2026!"
PW1 = "pw-github-123"
PW2 = "pw-bank-456"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_vault(path, entries=(("github", PW1),)):
    app = MyKey(MASTER, vault_file=path)
    for service, pw in entries:
        app.add_entry(make_entry(service=service, password=pw,
                                 username="user1"))
    return app


def identity_at(path, label=""):
    ident = DeviceIdentity.generate(label)
    ident.save(str(path))
    return DeviceIdentity.load(str(path))


@pytest.fixture()
def two_devices(tmp_path):
    """Device A with a stocked vault; device B empty. Shared folder."""
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    folder = tmp_path / "syncfolder"
    folder.mkdir()
    a_vault = str(a_dir / "vault.mykey")
    b_vault = str(b_dir / "vault.mykey")
    app_a = make_vault(a_vault)
    id_a = identity_at(a_dir / "keys-a.json", "A")
    id_b = identity_at(b_dir / "keys-b.json", "B")
    sync_a = VaultSync(a_vault)
    sync_a.configure(str(folder), id_a,
                     device_keys_path=str(a_dir / "keys-a.json"))
    sync_b = VaultSync(b_vault)
    return {"a_vault": a_vault, "b_vault": b_vault, "app_a": app_a,
            "id_a": id_a, "id_b": id_b, "sync_a": sync_a,
            "sync_b": sync_b, "folder": str(folder),
            "a_dir": str(a_dir), "b_dir": str(b_dir)}


def enroll_self_and(app, *idents):
    for ident in idents:
        devices.enroll_device(app, ident.card())


# ---------------------------------------------------------------------------
# device identity + registry
# ---------------------------------------------------------------------------

def test_device_identity_roundtrip_and_perms(tmp_path):
    path = str(tmp_path / "keys.json")
    ident = identity_at(path, "laptop")
    assert ident.label == "laptop"
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    card = ident.card()
    assert card["fingerprint"] == ident.fingerprint
    assert "priv" not in json.dumps(card)


def test_device_card_tamper_refused(tmp_path):
    ident = identity_at(tmp_path / "keys.json")
    card = ident.card()
    other = identity_at(tmp_path / "keys2.json")
    card["ed25519_pub"] = other.card()["ed25519_pub"]
    with pytest.raises(DeviceError):
        devices.verify_card(card)


def test_registry_enroll_revoke(tmp_path):
    vault = str(tmp_path / "vault.mykey")
    app = make_vault(vault)
    id_a = identity_at(tmp_path / "a.json", "A")
    id_b = identity_at(tmp_path / "b.json", "B")
    enroll_self_and(app, id_a, id_b)
    assert set(devices.active_devices(app)) == {id_a.device_id, id_b.device_id}
    devices.revoke_device(app, id_b.device_id)
    assert set(devices.active_devices(app)) == {id_a.device_id}
    listed = {d["device_id"]: d for d in devices.list_devices(app)}
    assert listed[id_b.device_id]["revoked_at"] is not None
    # a revoked id can never come back under the same identity
    with pytest.raises(DeviceError):
        devices.enroll_device(app, id_b.card())
    # the sidecar revocation record exists for unlock-free checks
    assert id_b.device_id in devices.read_revocations(vault)


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

def test_sync_first_push_pull_roundtrip(two_devices):
    d = two_devices
    assert d["sync_a"].push(d["id_a"])["result"] == "pushed"
    d["sync_b"].configure(d["folder"], d["id_b"],
                          device_keys_path=os.path.join(d["b_dir"],
                                                        "keys-b.json"))
    assert d["sync_b"].pull()["result"] == "pulled"
    app_b = MyKey(MASTER, vault_file=d["b_vault"])
    assert app_b.get_password("github") == PW1
    assert d["sync_a"].status()["state"] == "in-sync"
    assert d["sync_b"].status()["state"] == "in-sync"


def test_sync_no_change(two_devices):
    d = two_devices
    d["sync_a"].push(d["id_a"])
    d["sync_b"].configure(d["folder"], d["id_b"],
                          device_keys_path=os.path.join(d["b_dir"],
                                                        "keys-b.json"))
    d["sync_b"].pull()
    assert d["sync_a"].push(d["id_a"])["result"] == "no-change"
    assert d["sync_b"].pull()["result"] == "no-change"


def test_sync_divergent_conflict_both_preserved(two_devices):
    d = two_devices
    d["sync_a"].push(d["id_a"])
    d["sync_b"].configure(d["folder"], d["id_b"],
                          device_keys_path=os.path.join(d["b_dir"],
                                                        "keys-b.json"))
    d["sync_b"].pull()
    # A moves forward and publishes.
    app_a = MyKey(MASTER, vault_file=d["a_vault"])
    app_a.add_entry(make_entry(service="bank", password=PW2))
    assert d["sync_a"].push(d["id_a"])["generation"] == 2
    # B edits locally from the old state: both directions refuse.
    app_b = MyKey(MASTER, vault_file=d["b_vault"])
    app_b.add_entry(make_entry(service="mail", password="pw-mail-789"))
    with pytest.raises(SyncConflict):
        d["sync_b"].push(d["id_b"])
    with pytest.raises(SyncConflict):
        d["sync_b"].pull()
    # Both copies are intact.
    assert MyKey(MASTER, vault_file=d["b_vault"]).get_password("mail") \
        == "pw-mail-789"
    assert MyKey(MASTER, vault_file=d["a_vault"]).get_password("bank") == PW2
    manifest = json.loads(
        open(os.path.join(d["folder"], "manifest.json")).read())
    assert len(manifest["commits"]) == 2  # remote head untouched by B


def test_sync_snapshot_restore(two_devices):
    d = two_devices
    d["sync_a"].push(d["id_a"])
    gen1 = json.loads(open(os.path.join(
        d["folder"], "manifest.json")).read())["commits"][0]["bundle_hash"]
    app_a = MyKey(MASTER, vault_file=d["a_vault"])
    app_a.add_entry(make_entry(service="bank", password=PW2))
    d["sync_a"].push(d["id_a"])
    result = d["sync_a"].restore(gen1, human_unlocked=True)
    assert result["result"] == "restored"
    restored = MyKey(MASTER, vault_file=d["a_vault"])
    assert restored.get_password("github") == PW1
    with pytest.raises(KeyError):
        restored.get_entry("bank")


def test_sync_corrupted_bundle_refused(two_devices, tmp_path):
    d = two_devices
    d["sync_a"].push(d["id_a"])
    bundles = os.listdir(os.path.join(d["folder"], "bundles"))
    target = os.path.join(d["folder"], "bundles", bundles[0])
    raw = open(target).read()
    open(target, "w").write(raw.replace("A", "B", 1)
                            if raw[10] != "B" else raw.replace("B", "A", 1))
    c_vault = str(tmp_path / "c" / "vault.mykey")
    os.makedirs(os.path.dirname(c_vault))
    sync_c = VaultSync(c_vault)
    sync_c.configure(d["folder"], d["id_b"],
                     device_keys_path=os.path.join(d["b_dir"],
                                                   "keys-b.json"))
    with pytest.raises(SyncError):
        sync_c.pull()
    assert not os.path.exists(c_vault)  # local state untouched


def test_sync_rollback_and_forgery_refused(two_devices, tmp_path):
    d = two_devices
    d["sync_a"].push(d["id_a"])
    manifest_path = os.path.join(d["folder"], "manifest.json")
    gen1_manifest = open(manifest_path).read()
    app_a = MyKey(MASTER, vault_file=d["a_vault"])
    app_a.add_entry(make_entry(service="bank", password=PW2))
    d["sync_a"].push(d["id_a"])
    d["sync_b"].configure(d["folder"], d["id_b"],
                          device_keys_path=os.path.join(d["b_dir"],
                                                        "keys-b.json"))
    assert d["sync_b"].pull()["result"] == "pulled"  # B accepts gen2

    # Rollback: the folder now claims gen1 is the whole history.
    open(manifest_path, "w").write(gen1_manifest)
    with pytest.raises(SyncError):
        d["sync_b"].pull()

    # Forgery: a stranger device signs a fresh chain over gen1.
    stranger = identity_at(tmp_path / "stranger.json", "X")
    bundle = vaultsync.build_bundle(d["a_vault"])  # any bundle object
    forged = {"format": "MKMFT", "version": 1,
              "vault_id": json.loads(gen1_manifest)["vault_id"],
              "commits": []}
    # point the forged chain at the GEN1 bundle, not the current one
    gen1_hash = json.loads(gen1_manifest)["commits"][0]["bundle_hash"]
    forged["commits"] = [vaultsync.sign_commit(stranger, 1, gen1_hash,
                                               "", "push")]
    open(manifest_path, "w").write(json.dumps(forged))
    with pytest.raises(SyncError):
        d["sync_b"].pull()


def test_sync_force_requires_human_gate(two_devices):
    d = two_devices
    with pytest.raises(SyncError):
        d["sync_a"].push(d["id_a"], force=True, human_unlocked=False)
    with pytest.raises(SyncError):
        d["sync_a"].pull(force=True, human_unlocked=False)
    with pytest.raises(SyncError):
        d["sync_a"].restore("ab" * 32, human_unlocked=False)


def test_sync_refuses_device_keys_inside_root(tmp_path):
    vault = str(tmp_path / "vault.mykey")
    make_vault(vault)
    ident = identity_at(tmp_path / "keys.json")
    sync = VaultSync(vault)
    keys_inside = str(tmp_path / "folder" / "keys.json")
    with pytest.raises(SyncError):
        sync.configure(str(tmp_path / "folder"), ident,
                       device_keys_path=keys_inside)


def test_sync_artifacts_carry_no_plaintext(two_devices):
    d = two_devices
    d["sync_a"].push(d["id_a"])
    for root, _dirs, files in os.walk(d["folder"]):
        for name in files:
            raw = open(os.path.join(root, name), "rb").read()
            assert PW1.encode() not in raw
            assert d["id_a"].x_priv_raw.hex().encode() not in raw


# ---------------------------------------------------------------------------
# backup packages
# ---------------------------------------------------------------------------

@pytest.fixture()
def stocked_with_recovery(tmp_path):
    vault = str(tmp_path / "vault.mykey")
    app = make_vault(vault, (("github", PW1), ("bank", PW2)))
    phrase = app.setup_recovery()
    id_a = identity_at(tmp_path / "a.json", "A")
    devices.enroll_device(app, id_a.card())
    return {"vault": vault, "app": app, "phrase": phrase, "id_a": id_a,
            "dir": str(tmp_path)}


def test_backup_recovery_roundtrip_total_loss(stocked_with_recovery,
                                                tmp_path):
    d = stocked_with_recovery
    pkg_path = str(tmp_path / "backup.mykeybak")
    package = export_package(d["app"], d["id_a"], out_path=pkg_path)
    info = inspect_package(pkg_path)
    assert info["signature_valid"] and info["fingerprint_matches_header"]
    assert {r["type"] for r in info["recipients"]} == {"device", "recovery"}

    target = str(tmp_path / "newdevice" / "vault.mykey")
    result = import_package(pkg_path, target,
                            recovery_phrase=d["phrase"],
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"] == "recovery"
    recovered = MyKey(MASTER, vault_file=target)
    assert recovered.get_password("github") == PW1
    assert recovered.get_password("bank") == PW2
    raw = open(pkg_path, "rb").read()
    assert PW1.encode() not in raw and PW2.encode() not in raw
    assert d["id_a"].x_priv_raw.hex().encode() not in raw


def test_backup_second_device_import(stocked_with_recovery, tmp_path):
    d = stocked_with_recovery
    id_b = identity_at(tmp_path / "b.json", "B")
    devices.enroll_device(d["app"], id_b.card())
    pkg_path = str(tmp_path / "backup.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg_path)
    target = str(tmp_path / "bdev" / "vault.mykey")
    result = import_package(pkg_path, target, identity=id_b,
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"].startswith("device:")
    assert MyKey(MASTER, vault_file=target).get_password("bank") == PW2


def test_backup_tamper_and_wrong_recipient_refused(stocked_with_recovery,
                                                   tmp_path):
    d = stocked_with_recovery
    pkg_path = str(tmp_path / "backup.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg_path)
    raw = open(pkg_path).read()
    target = str(tmp_path / "t" / "vault.mykey")

    # tampered content
    tampered = raw.replace(raw[len(raw) // 2], "A"
                           if raw[len(raw) // 2] != "A" else "B", 1)
    bad = str(tmp_path / "bad.mykeybak")
    open(bad, "w").write(tampered)
    with pytest.raises(BackupRefused):
        import_package(bad, target, identity=d["id_a"],
                       expect_fingerprint=d["id_a"].fingerprint)

    # malformed
    junk = str(tmp_path / "junk.mykeybak")
    open(junk, "w").write("{not json")
    with pytest.raises(BackupRefused):
        import_package(junk, target, identity=d["id_a"],
                       expect_fingerprint=d["id_a"].fingerprint)

    # wrong recipient (never enrolled) with the right fingerprint
    stranger = identity_at(tmp_path / "x.json", "X")
    with pytest.raises(BackupRefused):
        import_package(pkg_path, target, identity=stranger,
                       expect_fingerprint=d["id_a"].fingerprint)

    # fresh import without an independently supplied fingerprint
    with pytest.raises(BackupRefused):
        import_package(pkg_path, target, identity=d["id_a"])

    # wrong independent fingerprint
    with pytest.raises(BackupRefused):
        import_package(pkg_path, target, identity=d["id_a"],
                       expect_fingerprint=stranger.fingerprint)


def test_backup_revoked_device_excluded_but_old_packages_open(
        stocked_with_recovery, tmp_path):
    d = stocked_with_recovery
    id_b = identity_at(tmp_path / "b.json", "B")
    devices.enroll_device(d["app"], id_b.card())
    pkg1 = str(tmp_path / "p1.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg1)
    devices.revoke_device(d["app"], id_b.device_id)
    pkg2 = str(tmp_path / "p2.mykeybak")
    package2 = export_package(d["app"], d["id_a"], out_path=pkg2)
    recipients2 = {r.get("device_id") for r in package2["recipients"]}
    assert id_b.device_id not in recipients2

    # B cannot open the NEW package…
    with pytest.raises(BackupRefused):
        import_package(pkg2, str(tmp_path / "n" / "vault.mykey"),
                       identity=id_b,
                       expect_fingerprint=d["id_a"].fingerprint)
    # …but the package exported BEFORE revocation still opens with
    # the key B retained. Inherent limit — asserted, not hidden.
    result = import_package(pkg1, str(tmp_path / "o" / "vault.mykey"),
                            identity=id_b,
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"].startswith("device:")


def test_backup_older_package_needs_explicit_allow(
        stocked_with_recovery, tmp_path, monkeypatch):
    d = stocked_with_recovery
    clock = [1_700_000_000]
    monkeypatch.setattr(backup_pkg, "_now", lambda: clock[0])
    pkg_old = str(tmp_path / "old.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg_old)
    clock[0] += 3600
    pkg_new = str(tmp_path / "new.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg_new)

    target = str(tmp_path / "t" / "vault.mykey")
    import_package(pkg_new, target, identity=d["id_a"],
                   expect_fingerprint=d["id_a"].fingerprint)
    probe = MyKey(MASTER, vault_file=target)
    probe.unlock()
    registry = probe._devices
    with pytest.raises(BackupRefused):
        import_package(pkg_old, target, identity=d["id_a"],
                       registry=registry)
    result = import_package(pkg_old, target, identity=d["id_a"],
                            registry=registry, allow_older=True)
    assert result["result"] == "imported"


def test_backup_downgrade_vault_refused(stocked_with_recovery, tmp_path):
    """A package whose bundled vault is not v3 is refused, even
    when it is correctly wrapped and signed by an enrolled device."""
    import base64

    import backup_pkg as bp
    from mykey import _enc

    d = stocked_with_recovery
    vault_id = d["app"]._vault_id
    package_id = "ab" * 16
    content_key = os.urandom(32)
    fake_vault = json.dumps({"format": "MKVLT", "version": 2,
                             "vault_id": vault_id}).encode()
    content = {"vault_id": vault_id, "exported_at": 1,
               "vault": base64.b64encode(fake_vault).decode(),
               "audit": None, "anchor": None}
    blob = _enc(content_key, bp._canonical(content),
                f"mkbak:v1:{vault_id}".encode())
    package = {
        "format": "MKBAK", "version": 1, "package_id": package_id,
        "created_at": 1,
        "source": {"device_id": d["id_a"].device_id,
                   "fingerprint": d["id_a"].fingerprint,
                   "x25519_pub": bp._b64e(d["id_a"].x_pub),
                   "ed25519_pub": bp._b64e(d["id_a"].e_pub),
                   "vault_id": vault_id},
        "recipients": [{
            "type": "device", "device_id": d["id_a"].device_id,
            "fingerprint": d["id_a"].fingerprint,
            "wrapped_key": bp._seal_to_pub(
                d["id_a"].x_pub, content_key,
                bp._wrap_aad(package_id, vault_id, d["id_a"].device_id)),
        }],
        "content": blob,
    }
    package["signature"] = bp._b64e(d["id_a"].sign(
        bp._canonical({k: v for k, v in package.items()
                       if k != "signature"})))
    path = str(tmp_path / "downgrade.mykeybak")
    open(path, "w").write(json.dumps(package))
    with pytest.raises(BackupRefused):
        import_package(path, str(tmp_path / "t" / "vault.mykey"),
                       identity=d["id_a"],
                       expect_fingerprint=d["id_a"].fingerprint)


def test_recovery_backfill_for_pre3a_vault(tmp_path):
    """A vault whose recovery predates 3A has no backup recipient
    until a recovery unlock backfills the public key."""
    vault = str(tmp_path / "vault.mykey")
    app = make_vault(vault)
    phrase = app.setup_recovery()
    ident = identity_at(tmp_path / "a.json", "A")
    devices.enroll_device(app, ident.card())
    # simulate the pre-3A core: no stored backup recovery pub
    app._backup_recovery_pub = None
    app._persist()
    with pytest.raises(BackupError):
        export_package(app, ident)
    fresh = MyKey(MASTER, vault_file=vault)
    fresh.unlock_via_recovery(phrase)
    assert fresh._backup_recovery_pub is not None
    package = export_package(fresh, ident)
    assert any(r["type"] == "recovery" for r in package["recipients"])


# ---------------------------------------------------------------------------
# CLI smoke: device-init -> configure -> push / fresh dir -> pull
# ---------------------------------------------------------------------------

def test_cli_sync_flow(tmp_path):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cli = os.path.join(root, "mykey_cli.py")
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    folder = tmp_path / "folder"
    for p in (a_dir, b_dir, folder):
        p.mkdir()
    a_vault = str(a_dir / "vault.mykey")
    make_vault(a_vault)
    env_a = {**os.environ, "MYKEY_DEVICE_KEYS": str(a_dir / "k.json")}
    env_b = {**os.environ, "MYKEY_DEVICE_KEYS": str(b_dir / "k.json")}

    def run(env, *argv, cwd):
        proc = subprocess.run(
            [sys.executable, cli, *argv], env=env, cwd=cwd,
            capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    run(env_a, "device-init", "--label", "A", cwd=str(a_dir))
    run(env_a, "sync-configure", "--vault", a_vault,
        "--folder", str(folder), cwd=str(a_dir))
    out = run(env_a, "sync-push", "--vault", a_vault, cwd=str(a_dir))
    assert "pushed" in out
    run(env_b, "device-init", "--label", "B", cwd=str(b_dir))
    b_vault = str(b_dir / "vault.mykey")
    run(env_b, "sync-configure", "--vault", b_vault,
        "--folder", str(folder), cwd=str(b_dir))
    out = run(env_b, "sync-pull", "--vault", b_vault, cwd=str(b_dir))
    assert "pulled" in out
    assert MyKey(MASTER, vault_file=b_vault).get_password("github") == PW1
