# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
"""Transport gates: encryption + authentication IN TRANSIT.

These tests encode the transport-security properties claimed in
docs/TRANSPORT_SECURITY.md so they cannot silently regress:

* Every byte that leaves the app for sync or backup is ciphertext
  before it moves, and tampering with it in transit is refused.
* Sync manifest commits are Ed25519-signed; a forged or altered
  commit is refused by the chain check.
* The product contains no network client code at all — no sockets,
  no HTTP stack, no way to disable TLS verification — because there
  is no network provider. (If one is ever added, these gates fail
  until the provider is HTTPS-only with verification on, and this
  file is updated to say so deliberately.)
* The MCP/agent surface speaks stdio only; it binds nothing.
* Plaintext CSV export stays behind the human-only gate.
"""

import ast
import base64
import io
import json
import os
import re

import pytest

import vaultsync
from devices import DeviceIdentity
from mykey import MyKey, _b64d, _b64e, make_entry
from vaultsync import SyncCorrupt

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER = "Correct-Horse-2026!"
SECRET = "pw-transport-gate-123"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _product_py_files():
    for name in sorted(os.listdir(REPO_ROOT)):
        if name.endswith(".py") and os.path.isfile(
                os.path.join(REPO_ROOT, name)):
            yield name


def _read(name):
    with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# source gates: no network client, no TLS weakening, no stray URLs
# ---------------------------------------------------------------------------

_FORBIDDEN_PATTERNS = [
    (r"verify\s*=\s*False", "TLS verification disabled"),
    (r"CERT_NONE", "TLS verification disabled"),
    (r"_create_unverified_context", "unverified TLS context"),
    (r"check_hostname\s*=\s*False", "TLS hostname check disabled"),
    (r"rejectUnauthorized", "TLS verification disabled"),
    (r"import\s+socket", "raw sockets"),
    (r"import\s+requests", "HTTP client library"),
    (r"urllib\.request", "HTTP client (urllib.request)"),
    (r"urlopen", "HTTP client (urlopen)"),
    (r"http\.client", "HTTP client (http.client)"),
    (r"import\s+ssl", "TLS stack (no network provider exists)"),
    (r"\.listen\s*\(", "network listener"),
    # A socket bind takes an (address, port) tuple; Tkinter widget
    # .bind("<event>", ...) calls are not network surface and are
    # not matched by this pattern.
    (r"\.bind\s*\(\s*\(", "socket bind"),
]

# The only URLs permitted in product code: the Apache licence text
# in file headers. Brand contact points are an email address and a
# bare domain string in brand.py — never a fetched endpoint.
_ALLOWED_URL = "http://www.apache.org/licenses/LICENSE-2.0"


def test_no_network_or_tls_weakening_in_product_code():
    offenders = []
    for name in _product_py_files():
        src = _read(name)
        for pattern, why in _FORBIDDEN_PATTERNS:
            if re.search(pattern, src):
                offenders.append(f"{name}: {why} ({pattern})")
    assert not offenders, "transport gate violations:\n" + "\n".join(
        offenders)


def test_no_unapproved_urls_in_product_code():
    offenders = []
    for name in _product_py_files():
        for url in re.findall(r"https?://[^\s'\")]+", _read(name)):
            if url != _ALLOWED_URL:
                offenders.append(f"{name}: {url}")
    assert not offenders, (
        "unapproved URL(s) in product code (telemetry/endpoint "
        "gate):\n" + "\n".join(offenders))


def test_sync_module_has_no_network_provider():
    """The only sync provider is a folder. vaultsync must not grow
    a network transport without this gate being revisited."""
    src = _read("vaultsync.py")
    assert "FolderProvider" in src or "folder" in src.lower()
    for token in ("urllib", "requests", "http", "socket", "webdav"):
        assert token not in src.lower(), (
            f"vaultsync.py now mentions {token!r} — a network sync "
            "provider must be HTTPS-only with verification on, and "
            "docs/TRANSPORT_SECURITY.md + this gate must be updated "
            "in the same change")


# ---------------------------------------------------------------------------
# sync bundles: ciphertext in transit, tamper refused
# ---------------------------------------------------------------------------

def _stocked_vault(tmp_path):
    path = str(tmp_path / "vault.mykey")
    app = MyKey(MASTER, vault_file=path)
    app.add_entry(make_entry(service="github", password=SECRET,
                             username="gate-user",
                             totp_secret=TOTP_SECRET))
    return path


def test_bundle_components_are_the_ciphertext_files_verbatim(tmp_path):
    path = _stocked_vault(tmp_path)
    bundle = vaultsync.build_bundle(path)
    assert vaultsync.verify_bundle(bundle) == bundle["bundle_hash"]
    with open(path, "rb") as f:
        on_disk = f.read()
    carried = _b64d(bundle["components"]["vault"]["data"])
    assert carried == on_disk, (
        "the bundle must carry the vault file exactly as it sits "
        "encrypted on disk — sync never decrypts or re-wraps it")
    # Nothing readable travels: not the password, not the TOTP
    # secret, not the username (all live under per-entry keys).
    for plaintext in (SECRET, TOTP_SECRET, "gate-user"):
        assert plaintext.encode() not in carried


def test_bundle_tampered_in_transit_is_refused(tmp_path):
    path = _stocked_vault(tmp_path)
    bundle = vaultsync.build_bundle(path)
    for name in ("vault",):
        comp = bundle["components"][name]
        raw = bytearray(_b64d(comp["data"]))
        raw[len(raw) // 2] ^= 0x01
        forged = json.loads(json.dumps(bundle))
        forged["components"][name] = {
            "sha256": comp["sha256"], "data": _b64e(bytes(raw))}
        with pytest.raises(SyncCorrupt):
            vaultsync.verify_bundle(forged)
    # A bundle whose claimed hash was recomputed by the tamperer
    # still fails: the manifest chain (next test) binds the hash,
    # and verify_bundle re-derives it from the components.
    forged = json.loads(json.dumps(bundle))
    forged["bundle_hash"] = "0" * 64
    with pytest.raises(SyncCorrupt):
        vaultsync.verify_bundle(forged)


def test_manifest_commit_signature_tamper_is_refused(tmp_path):
    ident = DeviceIdentity.generate("gate")
    bundle_hash = "a" * 64
    commit = vaultsync.sign_commit(ident, 1, bundle_hash, "", "push")
    manifest = {"format": "MKMFT", "version": 1, "commits": [commit]}
    tofu, error = vaultsync.check_chain(manifest, {}, {})
    assert error == "", f"honest chain refused: {error}"
    assert ident.device_id in tofu

    forged = json.loads(json.dumps(manifest))
    sig = bytearray(_b64d(forged["commits"][0]["sig"]))
    sig[0] ^= 0x01
    forged["commits"][0]["sig"] = _b64e(bytes(sig))
    _tofu, error = vaultsync.check_chain(forged, {}, {})
    assert error, "a commit with an altered signature was accepted"

    swapped = json.loads(json.dumps(manifest))
    swapped["commits"][0]["bundle_hash"] = "b" * 64
    _tofu, error = vaultsync.check_chain(swapped, {}, {})
    assert error, "a commit pointing at a different bundle was " \
                  "accepted under the original signature"


# ---------------------------------------------------------------------------
# agent surface: stdio only, binds nothing
# ---------------------------------------------------------------------------

def test_mcp_server_is_stdio_only(tmp_path):
    import mykey_mcp
    src = _read("mykey_mcp.py")
    assert "socket" not in src
    server = mykey_mcp.McpServer(str(tmp_path / "v.mykey"), "tok")
    out = io.StringIO()
    server.serve(io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1,
                    "method": "initialize"}) + "\n"), out)
    resp = json.loads(out.getvalue())
    assert resp["result"]["serverInfo"]["name"] == "mykey"


# ---------------------------------------------------------------------------
# plaintext export stays human-gated
# ---------------------------------------------------------------------------

def test_csv_export_is_human_gated_in_the_engine():
    tree = ast.parse(_read("mykey.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and \
                node.name == "export_vault_to_csv":
            calls = [n.func.attr for n in ast.walk(node)
                     if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Attribute)]
            assert "_require_human" in calls, (
                "export_vault_to_csv lost its human-only gate — "
                "agent sessions must never export plaintext")
            return
    raise AssertionError("export_vault_to_csv not found in mykey.py")


def test_csv_export_refused_for_agent_principal(tmp_path):
    path = _stocked_vault(tmp_path)
    app = MyKey(MASTER, vault_file=path)
    app._principal = "agent:gate"
    with pytest.raises(PermissionError):
        app.export_vault_to_csv(str(tmp_path / "out.csv"))
    assert not os.path.exists(str(tmp_path / "out.csv"))


def test_backup_package_bytes_carry_no_plaintext(tmp_path):
    import backup_pkg
    import devices
    path = _stocked_vault(tmp_path)
    app = MyKey(MASTER, vault_file=path)
    phrase = app.setup_recovery()
    assert phrase  # recovery slot exists, as in real exports
    ident = DeviceIdentity.generate("gate")
    devices.enroll_device(app, ident.card())
    out = str(tmp_path / "blob.mykeybak")
    _package, _code = backup_pkg.export_package(app, ident, out)
    with open(out, "rb") as f:
        raw = f.read()
    assert raw.startswith(b"MKBAK") or b"MKBAK" in raw[:64]
    for plaintext in (SECRET, TOTP_SECRET, "gate-user"):
        assert plaintext.encode() not in raw
