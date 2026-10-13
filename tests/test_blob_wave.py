# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Blob wave: MKBAK v2 two-factor recovery + key-value pairing.

Behaviour tests written against the claims:

* a v2 backup opens outside the app only with BOTH the recovery
  phrase and the backup code — either alone fails, a wrong code
  fails closed;
* the backup code is never written anywhere (package, vault, or
  any produced artifact is grepped for it);
* v1 packages still import phrase-only and are labelled LEGACY;
* backup packages carry a slot for a paired target only while the
  pairing is enabled, unexpired, unrevoked and holds the export
  scope — never for an unpaired target;
* a sync folder bound to a pairing target pushes/pulls only while
  that pairing is active; revocation stops it at the next pin
  refresh.
"""

import json
import os

import pytest

import pairings
import vaultsync
from backup_pkg import BackupRefused, export_package, import_package, \
    inspect_package
from devices import enroll_device
from mykey import MyKey, make_entry
from pairings import PairingError, PairingTargetIdentity
from recovery import generate_backup_code
from vaultsync import SyncError, VaultSync

MASTER = "Correct-Horse-2026!"
PW1 = "pw-github-123"
PW2 = "pw-bank-456"


def make_vault(path, entries=(("github", PW1), ("bank", PW2))):
    app = MyKey(MASTER, vault_file=path)
    for service, pw in entries:
        app.add_entry(make_entry(service=service, password=pw,
                                 username="user1"))
    return app


def identity_at(path, label=""):
    from devices import DeviceIdentity
    ident = DeviceIdentity.generate(label)
    ident.save(str(path))
    return DeviceIdentity.load(str(path))


@pytest.fixture()
def stocked(tmp_path):
    """A vault with recovery set up and device A enrolled."""
    vault = str(tmp_path / "vault.mykey")
    app = make_vault(vault)
    phrase = app.setup_recovery()
    id_a = identity_at(tmp_path / "a.json", "A")
    enroll_device(app, id_a.card())
    return {"vault": vault, "app": app, "phrase": phrase,
            "id_a": id_a, "dir": str(tmp_path)}


def fresh_target(tmp_path, name="new"):
    return str(tmp_path / name / "vault.mykey")


# ---------------------------------------------------------------------------
# MKBAK v2: two-factor recovery
# ---------------------------------------------------------------------------

def test_v2_recovery_roundtrip_needs_phrase_and_code(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    package, code = export_package(d["app"], d["id_a"], out_path=pkg)
    assert package["version"] == 2 and code
    assert len(code.split()) == 8
    info = inspect_package(pkg)
    assert info["version"] == 2 and info["legacy"] is False
    assert info["recovery_two_factor"] is True

    target = fresh_target(tmp_path)
    result = import_package(pkg, target, recovery_phrase=d["phrase"],
                            backup_code=code,
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"] == "recovery" and result["legacy"] is False
    recovered = MyKey(MASTER, vault_file=target)
    assert recovered.get_password("github") == PW1
    assert recovered.get_password("bank") == PW2


def test_v2_phrase_alone_fails(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg)
    with pytest.raises(BackupRefused) as excinfo:
        import_package(pkg, fresh_target(tmp_path),
                       recovery_phrase=d["phrase"],
                       expect_fingerprint=d["id_a"].fingerprint)
    assert "backup code" in str(excinfo.value)


def test_v2_code_alone_fails(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    _package, code = export_package(d["app"], d["id_a"], out_path=pkg)
    # code but no phrase, no device key: not a recipient at all
    with pytest.raises(BackupRefused):
        import_package(pkg, fresh_target(tmp_path), backup_code=code,
                       expect_fingerprint=d["id_a"].fingerprint)
    # code + a DIFFERENT vault's phrase: phrase does not match
    other = make_vault(str(tmp_path / "other.mykey"))
    other_phrase = other.setup_recovery()
    with pytest.raises(BackupRefused):
        import_package(pkg, fresh_target(tmp_path, "n2"),
                       recovery_phrase=other_phrase, backup_code=code,
                       expect_fingerprint=d["id_a"].fingerprint)


def test_v2_wrong_code_fails_closed(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    _package, code = export_package(d["app"], d["id_a"], out_path=pkg)
    wrong = generate_backup_code()
    while wrong == code:
        wrong = generate_backup_code()
    with pytest.raises(BackupRefused):
        import_package(pkg, fresh_target(tmp_path),
                       recovery_phrase=d["phrase"], backup_code=wrong,
                       expect_fingerprint=d["id_a"].fingerprint)
    # a malformed code (not word-list words) also fails, plainly
    with pytest.raises(BackupRefused):
        import_package(pkg, fresh_target(tmp_path, "n2"),
                       recovery_phrase=d["phrase"],
                       backup_code="not a real backup code at all",
                       expect_fingerprint=d["id_a"].fingerprint)


def test_v2_code_input_is_normalized(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    _package, code = export_package(d["app"], d["id_a"], out_path=pkg)
    messy = "  " + code.upper().replace(" ", "   ") + " "
    result = import_package(pkg, fresh_target(tmp_path),
                            recovery_phrase=d["phrase"],
                            backup_code=messy,
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"] == "recovery"


def test_v2_tampered_package_fails(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    _package, code = export_package(d["app"], d["id_a"], out_path=pkg)
    raw = open(pkg).read()
    mid = len(raw) // 2
    bad = str(tmp_path / "bad.mykeybak")
    open(bad, "w").write(raw[:mid] + ("A" if raw[mid] != "A" else "B")
                         + raw[mid + 1:])
    with pytest.raises(BackupRefused):
        import_package(bad, fresh_target(tmp_path),
                       recovery_phrase=d["phrase"], backup_code=code,
                       expect_fingerprint=d["id_a"].fingerprint)


def test_backup_code_is_never_written_anywhere(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    supplied = generate_backup_code()
    _package, code = export_package(d["app"], d["id_a"], out_path=pkg,
                                    backup_code=supplied)
    assert code == supplied
    raw_pkg = open(pkg, "rb").read()
    raw_vault = open(d["vault"], "rb").read()
    # The code as a phrase (or any long run of its words) must
    # appear nowhere. Individual short words are NOT checked as
    # substrings: 3-letter wordlist words occur inside base64
    # ciphertext by chance, which proves nothing either way.
    words = supplied.split()
    for chunk in (supplied, " ".join(words[:4]), " ".join(words[-4:])):
        assert chunk.encode() not in raw_pkg
        assert chunk.encode() not in raw_vault
    # a generated code is likewise absent from the package bytes
    pkg2 = str(tmp_path / "b2.mykeybak")
    _package2, code2 = export_package(d["app"], d["id_a"], out_path=pkg2)
    raw_pkg2 = open(pkg2, "rb").read()
    assert code2.encode() not in raw_pkg2


def test_v1_package_is_legacy_and_phrase_only(stocked, tmp_path):
    d = stocked
    pkg = str(tmp_path / "legacy.mykeybak")
    package, code = export_package(d["app"], d["id_a"], out_path=pkg,
                                   version=1)
    assert package["version"] == 1 and code is None
    info = inspect_package(pkg)
    assert info["legacy"] is True and info["recovery_two_factor"] is False
    result = import_package(pkg, fresh_target(tmp_path),
                            recovery_phrase=d["phrase"],
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"] == "recovery" and result["legacy"] is True
    assert MyKey(MASTER, vault_file=fresh_target(tmp_path)) \
        .get_password("bank") == PW2


def test_v2_device_path_unchanged(stocked, tmp_path):
    """Inside the trust boundary, an enrolled device still opens a
    v2 package with its key alone — 2FA guards the OUTSIDE path."""
    d = stocked
    pkg = str(tmp_path / "b.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg)
    result = import_package(pkg, fresh_target(tmp_path),
                            identity=d["id_a"],
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"].startswith("device:")


# ---------------------------------------------------------------------------
# pairing registry
# ---------------------------------------------------------------------------

def target_at(path, target_type="export", label="T"):
    target = PairingTargetIdentity.generate(target_type, label)
    target.save(str(path))
    return PairingTargetIdentity.load(str(path))


def test_payload_fingerprint_tamper_refused(tmp_path):
    target = target_at(tmp_path / "t.json")
    payload = target.payload()
    payload["x25519_pub"] = target_at(tmp_path / "u.json").payload()[
        "x25519_pub"]
    with pytest.raises(PairingError):
        pairings.verify_payload(payload)
    payload = target.payload()
    payload["type"] = "spaceship"
    with pytest.raises(PairingError):
        pairings.verify_payload(payload)


def test_pairing_gates_are_human_only(stocked):
    class NotAVault:
        pass

    target = PairingTargetIdentity.generate("export", "x")
    with pytest.raises(PermissionError):
        pairings.enroll_pairing(NotAVault(), target.payload(), ["export"])
    with pytest.raises(PermissionError):
        pairings.list_pairings(NotAVault())


def test_pairing_export_slot_and_open(stocked, tmp_path):
    d = stocked
    target = target_at(tmp_path / "t.json", "export", "archive-box")
    pairings.enroll_pairing(d["app"], target.payload(), ["export"])
    pkg = str(tmp_path / "b.mykeybak")
    package, _code = export_package(d["app"], d["id_a"], out_path=pkg)
    pairing_slots = [r for r in package["recipients"]
                     if r["type"] == "pairing"]
    assert [r["target_id"] for r in pairing_slots] == [target.target_id]

    result = import_package(pkg, fresh_target(tmp_path),
                            pairing_priv=target.x_priv_raw,
                            expect_fingerprint=d["id_a"].fingerprint)
    assert result["via"] == f"pairing:{target.target_id}"
    assert MyKey(MASTER, vault_file=fresh_target(tmp_path)) \
        .get_password("github") == PW1


def test_pairing_without_export_scope_gets_no_slot(stocked, tmp_path):
    d = stocked
    target = target_at(tmp_path / "t.json", "cloud-folder", "folder")
    pairings.enroll_pairing(d["app"], target.payload(), ["push", "pull"])
    pkg = str(tmp_path / "b.mykeybak")
    package, _code = export_package(d["app"], d["id_a"], out_path=pkg)
    assert not [r for r in package["recipients"] if r["type"] == "pairing"]
    with pytest.raises(BackupRefused):
        import_package(pkg, fresh_target(tmp_path),
                       pairing_priv=target.x_priv_raw,
                       expect_fingerprint=d["id_a"].fingerprint)


def test_unpaired_target_cannot_open(stocked, tmp_path):
    d = stocked
    stranger = target_at(tmp_path / "s.json", "export", "stranger")
    pkg = str(tmp_path / "b.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg)
    with pytest.raises(BackupRefused):
        import_package(pkg, fresh_target(tmp_path),
                       pairing_priv=stranger.x_priv_raw,
                       expect_fingerprint=d["id_a"].fingerprint)


def test_pairing_disabled_and_expired_get_no_slot(stocked, tmp_path,
                                                  monkeypatch):
    d = stocked
    off = target_at(tmp_path / "off.json", "export", "off")
    pairings.enroll_pairing(d["app"], off.payload(), ["export"])
    pairings.set_pairing_enabled(d["app"], off.target_id, False)
    old = target_at(tmp_path / "old.json", "export", "old")
    t0 = 1_700_000_000
    monkeypatch.setattr(pairings, "_now", lambda: t0)
    pairings.enroll_pairing(d["app"], old.payload(), ["export"],
                            expires_days=1)
    monkeypatch.setattr(pairings, "_now", lambda: t0 + 2 * 86400)
    pkg = str(tmp_path / "b.mykeybak")
    package, _code = export_package(d["app"], d["id_a"], out_path=pkg)
    monkeypatch.undo()
    assert not [r for r in package["recipients"] if r["type"] == "pairing"]
    listed = {t["target_id"]: t
              for t in pairings.list_pairings(d["app"])}
    assert listed[off.target_id]["active"] is False
    assert listed[old.target_id]["active"] is False


def test_pairing_revoke_excludes_new_packages_and_registry_refuses(
        stocked, tmp_path):
    d = stocked
    target = target_at(tmp_path / "t.json", "export", "archive-box")
    pairings.enroll_pairing(d["app"], target.payload(), ["export"])
    pkg_old = str(tmp_path / "old.mykeybak")
    export_package(d["app"], d["id_a"], out_path=pkg_old)
    pairings.revoke_pairing(d["app"], target.target_id)

    # new packages carry no slot for the revoked target
    pkg_new = str(tmp_path / "new.mykeybak")
    package_new, _code = export_package(d["app"], d["id_a"],
                                        out_path=pkg_new)
    assert not [r for r in package_new["recipients"]
                if r.get("target_id") == target.target_id]
    with pytest.raises(BackupRefused):
        import_package(pkg_new, fresh_target(tmp_path),
                       pairing_priv=target.x_priv_raw,
                       expect_fingerprint=d["id_a"].fingerprint)

    # over the existing vault, a registry that shows the target
    # revoked refuses even the pre-revocation package
    existing = str(tmp_path / "existing" / "vault.mykey")
    os.makedirs(os.path.dirname(existing))
    import shutil
    shutil.copyfile(d["vault"], existing)
    probe = MyKey(MASTER, vault_file=existing)
    probe.unlock()
    with pytest.raises(BackupRefused):
        import_package(pkg_old, existing, pairing_priv=target.x_priv_raw,
                       registry=probe._devices,
                       pairing_registry=probe._pairings,
                       allow_older=True)

    # a revoked id can never be re-enrolled
    with pytest.raises(PairingError):
        pairings.enroll_pairing(d["app"], target.payload(), ["export"])


# ---------------------------------------------------------------------------
# sync pairing gate
# ---------------------------------------------------------------------------

def test_sync_folder_bound_to_pairing_target(tmp_path):
    a_dir = tmp_path / "a"
    a_dir.mkdir()
    folder = tmp_path / "syncfolder"
    folder.mkdir()
    a_vault = str(a_dir / "vault.mykey")
    app = make_vault(a_vault)
    id_a = identity_at(a_dir / "keys-a.json", "A")
    target = target_at(tmp_path / "folder-target.json", "cloud-folder",
                       "my cloud folder")
    sync = VaultSync(a_vault)
    sync.configure(str(folder), id_a,
                   device_keys_path=str(a_dir / "keys-a.json"),
                   target_id=target.target_id)

    # bound but never pinned from the registry: refused, plainly
    with pytest.raises(SyncError):
        sync.push(id_a)

    pairings.enroll_pairing(app, target.payload(), ["push", "pull"])
    state = vaultsync.load_state(a_vault)
    vaultsync.refresh_pairing_pins(app, state)
    vaultsync.save_state(a_vault, state)
    assert sync.push(id_a)["result"] in ("pushed", "no-change")
    status = sync.status()
    assert status["pairing_target"] == target.target_id
    assert status["pairing_state"] == "active"

    # revocation + pin refresh stops both directions
    pairings.revoke_pairing(app, target.target_id)
    state = vaultsync.load_state(a_vault)
    vaultsync.refresh_pairing_pins(app, state)
    vaultsync.save_state(a_vault, state)
    with pytest.raises(SyncError):
        sync.push(id_a)
    with pytest.raises(SyncError):
        sync.pull()


def test_sync_pairing_scope_enforced(tmp_path):
    a_dir = tmp_path / "a"
    a_dir.mkdir()
    folder = tmp_path / "syncfolder"
    folder.mkdir()
    a_vault = str(a_dir / "vault.mykey")
    app = make_vault(a_vault)
    id_a = identity_at(a_dir / "keys-a.json", "A")
    target = target_at(tmp_path / "t.json", "cloud-folder", "push-only")
    pairings.enroll_pairing(app, target.payload(), ["push"])
    sync = VaultSync(a_vault)
    sync.configure(str(folder), id_a,
                   device_keys_path=str(a_dir / "keys-a.json"),
                   target_id=target.target_id)
    state = vaultsync.load_state(a_vault)
    vaultsync.refresh_pairing_pins(app, state)
    vaultsync.save_state(a_vault, state)
    assert sync.push(id_a)["result"] in ("pushed", "no-change")
    with pytest.raises(SyncError):
        sync.pull()
