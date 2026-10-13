# Licensed under the Apache License, Version 2.0.
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Rename-on-the-fly guarantee (owner directive, 2026-10-12).

Brand strings live only in brand.py. The vault format binds no brand
into its cryptography, so a vault created under brand configuration A
must open under brand configuration B.
"""

import importlib
import json
import os
import sys

import brand
from mykey import MyKey

CORRECT = "Correct-Horse-2026!"


def _reload_brand(monkeypatch, name, domain):
    monkeypatch.setenv("MYKEY_PRODUCT_NAME", name)
    monkeypatch.setenv("MYKEY_DOMAIN", domain)
    reloaded = importlib.reload(brand)
    return reloaded


def test_vault_opens_under_a_different_brand(tmp_path, monkeypatch):
    vault = str(tmp_path / "vault.mykey")
    brand_a = _reload_brand(monkeypatch, "MyKey", "usemykey.com")
    assert brand_a.PRODUCT_NAME == "MyKey"
    app = MyKey(CORRECT, vault_file=vault)
    app.save_password("github", "pw-github-123")

    # Rename the product: different name, different domain.
    brand_b = _reload_brand(monkeypatch, "TotallyDifferentName", "example.invalid")
    assert brand_b.PRODUCT_NAME == "TotallyDifferentName"

    fresh = MyKey(CORRECT, vault_file=vault)
    assert fresh.get_password("github") == "pw-github-123"

    # The raw file carries no brand strings anywhere (header or ciphertext).
    raw = open(vault, "rb").read()
    assert b"MyKey" not in raw
    assert b"usemykey" not in raw
    assert b"TotallyDifferentName" not in raw
    parsed = json.loads(raw)
    assert parsed["format"] == "MKVLT"  # stable technical token, not a brand


def test_cli_and_gui_source_have_no_brand_literals():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for fname in ("mykey_cli.py", "mykey_gui.py", "mykey.py"):
        source = open(os.path.join(root, fname), encoding="utf-8").read()
        # These files may reference brand.* but must not embed the literals.
        assert "usemykey.com" not in source, fname
        if fname != "mykey.py":  # engine header carries no product title either
            assert '"MyKey"' not in source and "'MyKey'" not in source, fname
    assert "brand" in open(os.path.join(root, "mykey_cli.py")).read()
    assert "brand" in open(os.path.join(root, "mykey_gui.py")).read()


def teardown_module(module):
    # Leave the brand module in its default state for other tests.
    for var in ("MYKEY_PRODUCT_NAME", "MYKEY_DOMAIN"):
        os.environ.pop(var, None)
    importlib.reload(brand)
    sys.modules["brand"] = brand
