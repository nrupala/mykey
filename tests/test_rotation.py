# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Password age + rotation (owner directive, 2026-10-13).

Covers: the set-date clock (set on create, reset only when the
password itself changes), the 180-day vault default, per-entry
overrides and Never at both levels, due-soon/overdue boundaries,
settings persistence inside the encrypted core, pre-feature vaults
opening with the creation-time fallback, unknown fields tolerated,
and the dates never appearing outside the encrypted payload.
"""

import json
import os

import pytest

import mykey
from mykey import (DEFAULT_ROTATE_DAYS, MyKey, _aad, _b64d, _b64e, _dec,
                   _enc, _entry_hash, make_entry, rotation_line,
                   rotation_status)

CORRECT = "Correct-Horse-2026!"
DAY = 86400
T0 = 1_800_000_000  # a fixed "now" for deterministic clocks


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


@pytest.fixture()
def clock(monkeypatch):
    state = {"now": T0}
    monkeypatch.setattr(mykey, "_now", lambda: state["now"])
    return state


def _add(app, service="github", password="pw-one-123456", **kw):
    return app.add_entry(make_entry(service=service, password=password, **kw))


# -- the clock ---------------------------------------------------------------

def test_new_entry_records_set_date(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    entry = _add(app)
    assert entry["password_set_at"] == T0
    assert entry["rotate_days"] is None
    status = rotation_status(entry, DEFAULT_ROTATE_DAYS, now=T0)
    assert status["state"] == "ok"
    assert status["rotate_days"] == 180
    assert status["due_at"] == T0 + 180 * DAY


def test_password_change_resets_clock(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    clock["now"] = T0 + 90 * DAY
    updated = app.update_entry("github", password="pw-two-123456")
    assert updated["password_set_at"] == T0 + 90 * DAY
    # Re-saving the SAME password is not a change.
    clock["now"] = T0 + 100 * DAY
    updated = app.update_entry("github", password="pw-two-123456")
    assert updated["password_set_at"] == T0 + 90 * DAY


def test_non_secret_edits_keep_clock(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app, username="octocat")
    clock["now"] = T0 + 30 * DAY
    for fields in ({"notes": "rotated via the app"},
                   {"url": "https://example.com"},
                   {"tags": ["dev"]},
                   {"favourite": True},
                   {"totp_secret": "JBSWY3DPEHPK3PXP"}):
        updated = app.update_entry("github", "octocat", **fields)
        assert updated["password_set_at"] == T0, fields


def test_generate_and_save_resets_clock(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    clock["now"] = T0 + 200 * DAY
    app.save_password("github", "brand-new-pw-123")
    assert app.get_entry("github")["password_set_at"] == T0 + 200 * DAY


def test_mark_password_changed(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    clock["now"] = T0 + 45 * DAY
    entry = app.mark_password_changed("github")
    assert entry["password_set_at"] == T0 + 45 * DAY
    assert entry["password"] == "pw-one-123456"  # value untouched


# -- defaults, overrides, Never ------------------------------------------------

def test_default_180_and_vault_default_change(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    entry = _add(app)
    assert rotation_status(entry, app.vault_settings()["default_rotate_days"],
                           now=T0)["rotate_days"] == 180
    app.set_default_rotate_days(90)
    entry = app.get_entry("github")
    assert rotation_status(entry, 90, now=T0)["due_at"] == T0 + 90 * DAY


def test_per_entry_override_wins(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    app.update_entry("github", rotate_days=30)
    entry = app.get_entry("github")
    assert entry["rotate_days"] == 30
    assert rotation_status(entry, 180, now=T0)["due_at"] == T0 + 30 * DAY
    app.update_entry("github", rotate_days=None)  # clear -> default again
    assert app.get_entry("github")["rotate_days"] is None


def test_never_at_both_levels(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app, service="frozen")
    _add(app, service="normal")
    app.update_entry("frozen", rotate_days=0)
    frozen = app.get_entry("frozen")
    assert rotation_status(frozen, 180, now=T0 + 9999 * DAY)["state"] == "off"
    # Vault default Never: unset entries are off, an override still wins.
    app.set_default_rotate_days(0)
    normal = app.get_entry("normal")
    assert rotation_status(normal, 0, now=T0 + 9999 * DAY)["state"] == "off"
    app.update_entry("normal", rotate_days=45)
    normal = app.get_entry("normal")
    assert rotation_status(normal, 0, now=T0)["state"] == "ok"
    app.set_default_rotate_days(None)
    _add(app, service="third")
    third = app.get_entry("third")
    assert rotation_status(third, None, now=T0)["state"] == "off"


def test_rotate_days_validation(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    for bad in (-1, -180, 1.5, "30", True):
        with pytest.raises(ValueError):
            app.update_entry("github", rotate_days=bad)
        with pytest.raises(ValueError):
            app.set_default_rotate_days(bad)


def test_settings_persist_in_core(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    app.set_default_rotate_days(45)
    again = MyKey(CORRECT, vault_file=vault_path)
    again.unlock()
    assert again.vault_settings()["default_rotate_days"] == 45
    # Settings live inside the encrypted core, not a sidecar.
    raw = open(vault_path, "rb").read()
    assert b"default_rotate_days" not in raw


# -- due states ------------------------------------------------------------------

def test_due_boundaries():
    entry = {"password_set_at": T0, "rotate_days": 180}
    due = T0 + 180 * DAY
    assert rotation_status(entry, 180, now=due - 14 * DAY - 1)["state"] == "ok"
    assert rotation_status(entry, 180, now=due - 14 * DAY)["state"] == "due_soon"
    assert rotation_status(entry, 180, now=due - 1)["state"] == "due_soon"
    assert rotation_status(entry, 180, now=due)["state"] == "overdue"
    assert rotation_status(entry, 180, now=due + 30 * DAY)["state"] == "overdue"
    assert rotation_status(entry, 180, now=due)["days_left"] == 0
    assert rotation_status(entry, 180, now=due - 10 * DAY)["days_left"] == 10


def test_unknown_when_no_date():
    entry = {"password_set_at": None, "rotate_days": None}
    status = rotation_status(entry, 180, now=T0)
    assert status["state"] == "unknown"
    assert status["due_at"] is None
    assert rotation_line(entry, 180) == "Password date not recorded"


def test_rotation_line_words():
    entry = {"password_set_at": T0, "rotate_days": None}
    line = rotation_line(entry, 180, now=T0)
    assert line.startswith("Password set ")
    assert " · change by " in line
    off = rotation_line(entry, 0, now=T0)
    assert off.endswith(" · change date off")


def test_report_order_and_due_count(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app, service="overdue")
    _add(app, service="soon")
    _add(app, service="fine")
    _add(app, service="never")
    _add(app, service="nodate")
    for e in app._entries:  # in-memory crafting for deterministic states
        if e["service"] == "overdue":
            e["password_set_at"] = T0 - 200 * DAY
        elif e["service"] == "soon":
            e["password_set_at"] = T0 - 170 * DAY
        elif e["service"] == "never":
            e["rotate_days"] = 0
        elif e["service"] == "nodate":
            e["password_set_at"] = None
    report = app.rotation_report(now=T0)
    assert [r["service"] for r in report] == [
        "overdue", "soon", "nodate", "fine", "never"]
    assert [r["state"] for r in report] == [
        "overdue", "due_soon", "unknown", "ok", "off"]
    assert app.rotation_due_count(now=T0) == 2


# -- pre-feature vaults + field tolerance -----------------------------------------

def _rewrite_secret_blob(vault_path, probe, mutate):
    """Rewrite one entry's secret blob in the file (and its sealed
    hash in the core) — the surgery used to simulate vault files
    written by older or future clients."""
    data = json.load(open(vault_path))
    entry = data["entries"][0]
    eid = entry["id"]
    secret = json.loads(_dec(probe._deks[eid]["pw"], entry["secret"],
                             _aad("secret", eid)))
    mutate(secret)
    entry["secret"] = _enc(probe._deks[eid]["pw"],
                            json.dumps(secret).encode(), _aad("secret", eid))
    core = json.loads(_dec(probe._vault_key, data["core"],
                           _aad("core", data["vault_id"])))
    core["entry_hashes"][eid] = _entry_hash(entry)
    data["core"] = _enc(probe._vault_key, json.dumps(core).encode(),
                        _aad("core", data["vault_id"]))
    with open(vault_path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def test_old_vault_without_fields_opens(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    created = _add(app)
    assert created["created"] == T0
    probe = MyKey(CORRECT, vault_file=vault_path)
    probe.unlock()

    def strip(secret):
        secret.pop("password_set_at", None)
        secret.pop("rotate_days", None)

    _rewrite_secret_blob(vault_path, probe, strip)
    fresh = MyKey(CORRECT, vault_file=vault_path)
    entry = fresh.get_entry("github")
    # Fallback: the password's set date is the entry creation time.
    assert entry["password_set_at"] == T0
    assert entry["rotate_days"] is None
    # A save by the new client writes the fields back, intact.
    clock["now"] = T0 + DAY
    fresh.update_entry("github", notes="saved by the new client")
    probe2 = MyKey(CORRECT, vault_file=vault_path)
    probe2.unlock()
    data = json.load(open(vault_path))
    eid = data["entries"][0]["id"]
    secret = json.loads(_dec(probe2._deks[eid]["pw"],
                             data["entries"][0]["secret"],
                             _aad("secret", eid)))
    assert secret["password_set_at"] == T0  # notes edit never moves it
    assert secret["rotate_days"] is None


def test_unknown_secret_fields_tolerated(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    probe = MyKey(CORRECT, vault_file=vault_path)
    probe.unlock()

    def add_future_field(secret):
        secret["future_field"] = {"nested": [1, 2, 3]}

    _rewrite_secret_blob(vault_path, probe, add_future_field)
    fresh = MyKey(CORRECT, vault_file=vault_path)
    entry = fresh.get_entry("github")  # opens fine, no crash
    assert entry["password"] == "pw-one-123456"
    assert entry["password_set_at"] == T0


def test_dates_stay_inside_encrypted_payload(vault_path, clock, tmp_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    app.set_default_rotate_days(45)
    for name in os.listdir(tmp_path):
        blob = open(tmp_path / name, "rb").read()
        assert b"password_set_at" not in blob, name
        assert b"rotate_days" not in blob, name
        assert b"default_rotate_days" not in blob, name


def test_imported_entries_have_no_recorded_date(vault_path, clock):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.unlock()
    records = [{"service": "imported", "username": "u",
                "password": "pw-imported-1", "url": "", "notes": "",
                "totp_secret": "", "tags": [], "favourite": False}]
    app.import_entries(records)
    entry = app.get_entry("imported")
    assert entry["password_set_at"] is None
    assert rotation_status(entry, 180, now=T0)["state"] == "unknown"
    # An import OVERWRITE also clears the date: the replacement
    # password's age is unknown, so the old entry's date must not
    # survive onto it.
    _add(app, service="victim", password="original-pw-123")
    assert app.get_entry("victim")["password_set_at"] == T0
    overwrite = [{"service": "victim", "username": "",
                  "password": "imported-pw-999", "url": "", "notes": "",
                  "totp_secret": "", "tags": [], "favourite": False}]
    app.import_entries(overwrite, on_conflict="overwrite")
    entry = app.get_entry("victim")
    assert entry["password"] == "imported-pw-999"
    assert entry["password_set_at"] is None


# -- CLI surface -------------------------------------------------------------------

def _run_cli(monkeypatch, capsys, vault_path, *argv):
    import getpass
    import sys

    import mykey_cli

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": CORRECT)
    monkeypatch.setattr(sys, "argv",
                        ["mykey_cli.py", *argv, "--vault", vault_path])
    rc = mykey_cli.main()
    out = capsys.readouterr().out
    assert rc == 0, out
    return out


def test_cli_rotation_flow(vault_path, monkeypatch, capsys):
    import time

    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    app.mark_password_changed("github", at=int(time.time()) - 200 * DAY)
    out = _run_cli(monkeypatch, capsys, vault_path, "rotation")
    assert "github" in out and "overdue" in out
    assert "change every 180 days" in out
    out = _run_cli(monkeypatch, capsys, vault_path,
                   "list")
    assert "change overdue" in out
    out = _run_cli(monkeypatch, capsys, vault_path,
                   "rotation", "--set-default-days", "30")
    assert "every 30 days" in out
    out = _run_cli(monkeypatch, capsys, vault_path,
                   "edit", "--service", "github", "--rotate-days", "0")
    assert "Updated" in out
    out = _run_cli(monkeypatch, capsys, vault_path, "rotation")
    assert "Nothing needs changing" in out
    out = _run_cli(monkeypatch, capsys, vault_path,
                   "edit", "--service", "github", "--rotate-days-clear")
    assert "Updated" in out
    check = MyKey(CORRECT, vault_file=vault_path)
    check.unlock()
    assert check.get_entry("github")["rotate_days"] is None
    assert check.vault_settings()["default_rotate_days"] == 30
    out = _run_cli(monkeypatch, capsys, vault_path,
                   "mark-changed", "--service", "github")
    assert "changed today" in out
    check2 = MyKey(CORRECT, vault_file=vault_path)
    check2.unlock()
    status = rotation_status(check2.get_entry("github"), 30)
    assert status["state"] == "ok"


def test_agent_metadata_carries_no_rotation_fields(vault_path, clock):
    from agents import enroll_agent, open_agent_session

    app = MyKey(CORRECT, vault_file=vault_path)
    _add(app)
    app.unlock()
    token = enroll_agent(app, "reader", ["list"])
    session = open_agent_session(vault_path, token)
    for meta in session.list_metadata():
        assert "password_set_at" not in meta
        assert "rotate_days" not in meta
