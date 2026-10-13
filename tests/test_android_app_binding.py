# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Android-app autofill bindings: the `android_app` entry field.

A binding links an entry to one Android app (package name + the
SHA-256 of its signing certificate) so the Android autofill
service can offer the entry inside that app — and only that app.
The binding is created in the Android app; the desktop engine's
job is to carry it faithfully: it lives in the KMETA-encrypted
metadata, survives desktop saves, and is validated on the way in
so a malformed binding can never silently match at fill time.
"""

import pytest

from mykey import MyKey, clean_android_app, make_entry

CORRECT = "Correct-Horse-2026!"
CERT = "aa" * 32
BINDING = {"package": "com.example.shop", "cert_sha256": CERT,
           "label": "Shop App"}


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "vault.mykey")


def test_binding_round_trips_a_desktop_save(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.unlock()
    app.add_entry(make_entry(service="shopapp", password="pw-1",
                             username="shopper", android_app=BINDING))
    app.add_entry(make_entry(service="plain", password="pw-2"))
    # A desktop edit + save must not drop the binding.
    app.update_entry("plain", password="pw-2b")

    again = MyKey(CORRECT, vault_file=vault_path)
    again.unlock()
    entries = {e["service"]: e for e in again.list_entries()}
    assert entries["shopapp"]["android_app"] == BINDING
    assert entries["plain"]["android_app"] is None


def test_binding_is_inside_the_encrypted_metadata(vault_path):
    app = MyKey(CORRECT, vault_file=vault_path)
    app.unlock()
    app.add_entry(make_entry(service="shopapp", password="pw-1",
                             android_app=BINDING))
    raw = open(vault_path, "rb").read()
    # The package name is metadata: it must not appear in the clear.
    assert b"com.example.shop" not in raw


def test_malformed_bindings_are_dropped():
    assert clean_android_app(None) is None
    assert clean_android_app("com.example.shop") is None
    assert clean_android_app({"package": "com.example.shop"}) is None
    assert clean_android_app(
        {"package": "", "cert_sha256": CERT}) is None
    assert clean_android_app(
        {"package": "com.example.shop", "cert_sha256": "zz" * 32}) is None
    assert clean_android_app(
        {"package": "com.example.shop", "cert_sha256": "abcd"}) is None


def test_binding_normalizes_cert_case_and_colons():
    out = clean_android_app(
        {"package": " com.example.shop ",
         "cert_sha256": ":".join(["AA"] * 32)})
    assert out == {"package": "com.example.shop", "cert_sha256": CERT}


def test_agent_bundle_meta_carries_the_binding(vault_path):
    import agents
    app = MyKey(CORRECT, vault_file=vault_path)
    app.unlock()
    app.add_entry(make_entry(service="shopapp", password="pw-1",
                             username="shopper", android_app=BINDING))
    token = agents.enroll_agent(app, "binding-agent", ["list"])
    session = agents.open_agent_session(vault_path, token)
    listed = session.list_metadata()
    mine = [e for e in listed if e["service"] == "shopapp"]
    assert mine and mine[0]["android_app"] == BINDING
