# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core. See LICENSING.md.

"""Native messaging host + extension pairing suite.

Includes the desktop half of the LEAK GATE: a full session runs over
real pipes against a fixture vault, every raw byte in both
directions is captured, and the fixture master password, usernames,
passwords and TOTP secret must appear NOWHERE in the capture. The
browser-side half lives in the extension package
(extension/tests/leak.test.ts) and drives this same host.
"""

import io
import json
import os
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import extpair
import native_host
from mykey import MyKey, _b64d, _b64e, make_entry

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

MASTER = "fixture-master-pass-13"
PW_ALPHA = "FIXTURE-PW-ALPHA-123"
PW_BETA = "FIXTURE-PW-BETA-456"
PW_GAMMA = "FIXTURE-PW-GAMMA-789"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
EXT_ID = "abcdefghijklmnopabcdefghijklmnop"


def _raw_pub(priv):
    return priv.public_key().public_bytes(Encoding.Raw,
                                          PublicFormat.Raw)


def make_vault(path):
    vault = MyKey(MASTER, vault_file=str(path))
    vault.unlock()
    vault.add_entry(make_entry(
        service="GitHub", username="octocat", password=PW_ALPHA,
        url="https://github.com", totp_secret=TOTP_SECRET))
    vault.add_entry(make_entry(
        service="Example", username="subuser", password=PW_BETA,
        url="https://example.com"))
    vault.add_entry(make_entry(
        service="Bank", username="banker", password=PW_GAMMA,
        url="https://secure.bank.example:8443"))
    return vault


@pytest.fixture()
def env(tmp_path):
    vault_path = tmp_path / "vault.mykey"
    make_vault(vault_path)
    store_path = tmp_path / "extension-host.json"
    store = extpair.ExtensionHostStore.load(str(store_path))
    store.set_setting("vault_file", str(vault_path))
    ext_priv = X25519PrivateKey.generate()
    payload = {
        "format": "MKEXTPAIR", "version": 1,
        "extension_id": EXT_ID, "label": "Test Browser",
        "x25519_pub": _b64e(_raw_pub(ext_priv)),
        "fingerprint": extpair.extension_fingerprint(_raw_pub(ext_priv)),
    }
    store.enroll(payload, ["fill", "save"])
    return {"vault": str(vault_path), "store_path": str(store_path),
            "store": store, "ext_priv": ext_priv, "payload": payload}


class Client:
    """A test-side channel client (the extension's role), built on
    the same primitives the TypeScript client uses."""

    def __init__(self, env):
        self.env = env
        self.priv = env["ext_priv"]
        self.channel = None
        self.send_seq = 0
        self.expect_seq = 0

    def hello_frame(self, ext_id=EXT_ID, priv=None):
        priv = priv or self.priv
        self.client_nonce = os.urandom(32)
        return {"kind": "hello", "extension_id": ext_id,
                "ext_pub": _b64e(_raw_pub(priv)),
                "client_nonce": _b64e(self.client_nonce)}

    def accept_hello(self, response, host_pub=None):
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PublicKey,
        )
        host_pub = host_pub or response["host_pub"]
        shared = self.priv.exchange(
            X25519PublicKey.from_public_bytes(_b64d(host_pub)))
        keys = native_host.derive_session_keys(
            shared, self.client_nonce, _b64d(response["server_nonce"]))
        self.keys = keys
        self.session = response["session"]
        ack = self.open(response["ack"])
        assert ack["kind"] == "hello_ack"
        return ack

    def seal(self, message):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        seq = self.send_seq
        nonce = b"e2h\x00" + seq.to_bytes(8, "big")
        aad = (f"{native_host.PROTOCOL}|e2h|{self.session}|".encode()
               + seq.to_bytes(8, "big"))
        ct = AESGCM(self.keys["e2h"]).encrypt(
            nonce, native_host._canonical(message), aad)
        self.send_seq += 1
        return {"kind": "sealed", "session": self.session,
                "seq": seq, "nonce": _b64e(nonce), "ct": _b64e(ct)}

    def open(self, frame):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        assert frame["kind"] == "sealed"
        assert frame["session"] == self.session
        seq = frame["seq"]
        assert seq == self.expect_seq, f"seq {seq} != {self.expect_seq}"
        nonce = _b64d(frame["nonce"])
        assert nonce == b"h2e\x00" + seq.to_bytes(8, "big")
        aad = (f"{native_host.PROTOCOL}|h2e|{self.session}|".encode()
               + seq.to_bytes(8, "big"))
        pt = AESGCM(self.keys["h2e"]).decrypt(nonce, _b64d(frame["ct"]),
                                              aad)
        self.expect_seq += 1
        return json.loads(pt.decode())


def connect(host, env):
    client = Client(env)
    response = host.handle_hello(client.hello_frame())
    client.accept_hello(response)
    host_client_channel = host.channel
    # Point the client's open/seal at the host channel by pairing the
    # counters: the client tracks its own; replies come via host.
    return client, host_client_channel


def rpc(host, client, message):
    frame = client.seal(message)
    opened = host.channel.open(frame)
    response = host.handle_message(opened)
    return client.open(host.channel.seal(response))


# ---------------------------------------------------------------------------
# origin matching — the authority (leak gate #2, desktop half)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entry_url,page,allow_sub,expected", [
    ("https://github.com", "https://github.com/login", False, True),
    ("https://github.com", "https://github.com.evil.com", False, False),
    ("https://github.com", "https://evil-github.com", False, False),
    ("https://github.com", "http://github.com", False, False),
    ("https://github.com", "https://github.com:8443", False, False),
    ("https://github.com:8443", "https://github.com:8443/x", False, True),
    ("https://example.com", "https://app.example.com", False, False),
    ("https://example.com", "https://app.example.com", True, True),
    ("https://example.com", "https://deep.app.example.com", True, True),
    ("https://example.com", "https://example.com.evil.com", True, False),
    ("https://example.com", "https://notexample.com", True, False),
    ("https://secure.bank.example:8443",
     "https://secure.bank.example:8443/login", False, True),
    ("https://secure.bank.example:8443",
     "https://secure.bank.example/login", False, False),
])
def test_origin_matching(entry_url, page, allow_sub, expected):
    entry = {"url": entry_url, "service": ""}
    page_org = native_host.parse_origin(page)
    assert native_host.origin_matches(
        native_host.entry_origin(entry), page_org, allow_sub) is expected


def test_origin_parsing_rejects_userinfo_and_junk():
    assert native_host.parse_origin("https://user:pw@github.com") is None
    assert native_host.parse_origin("javascript://github.com") is None
    assert native_host.parse_origin("github.com") is None
    assert native_host.parse_origin("") is None


def test_service_fallback_only_for_host_shaped_names():
    assert native_host.entry_origin(
        {"service": "github.com", "url": ""}) == ("https", "github.com",
                                                  443)
    assert native_host.entry_origin(
        {"service": "GitHub", "url": ""}) is None
    assert native_host.entry_origin(
        {"service": "my bank login", "url": ""}) is None


# ---------------------------------------------------------------------------
# pairing gates (leak gate #6)
# ---------------------------------------------------------------------------

def test_hello_refused_for_unknown_revoked_expired_disabled(env):
    host = native_host.NativeHost(env["store"], env["vault"])
    client = Client(env)
    assert host.handle_hello(client.hello_frame())["kind"] == "hello"

    # wrong key for a known id
    stranger = X25519PrivateKey.generate()
    with pytest.raises(native_host.ProtocolError):
        host.handle_hello(client.hello_frame(priv=stranger))

    # unknown id
    with pytest.raises(native_host.ProtocolError):
        host.handle_hello(client.hello_frame(ext_id="z" * 32))

    env["store"].revoke(EXT_ID)
    with pytest.raises(native_host.ProtocolError):
        host.handle_hello(client.hello_frame())


def test_expired_pairing_refused(env, tmp_path):
    store = extpair.ExtensionHostStore.load(str(tmp_path / "s2.json"))
    priv = X25519PrivateKey.generate()
    payload = {"format": "MKEXTPAIR", "version": 1,
               "extension_id": "ponmlkjihgfedcbaponmlkjihgfedcba",
               "label": "Old", "x25519_pub": _b64e(_raw_pub(priv)),
               "fingerprint": extpair.extension_fingerprint(
                   _raw_pub(priv))}
    store.enroll(payload, ["fill"], expires_days=-1)
    host = native_host.NativeHost(store, env["vault"])
    client = Client(env)
    client.priv = priv
    with pytest.raises(native_host.ProtocolError):
        host.handle_hello(client.hello_frame(
            ext_id="ponmlkjihgfedcbaponmlkjihgfedcba", priv=priv))


def test_enroll_rejects_bad_fingerprint_and_revoked_reenroll(env):
    bad = dict(env["payload"], fingerprint="0" * 8 + ":0000")
    with pytest.raises(extpair.ExtensionPairingError):
        extpair.verify_payload(bad)
    env["store"].revoke(EXT_ID)
    with pytest.raises(extpair.ExtensionPairingError):
        env["store"].enroll(env["payload"], ["fill"])


def test_store_file_is_0600_and_settings_bounds(env, tmp_path):
    mode = os.stat(env["store_path"]).st_mode & 0o777
    assert mode == 0o600
    with pytest.raises(extpair.ExtensionPairingError):
        env["store"].set_setting("clipboard_clear_seconds", 59)
    with pytest.raises(extpair.ExtensionPairingError):
        env["store"].set_setting("clipboard_clear_seconds", 301)
    assert env["store"].set_setting("clipboard_clear_seconds",
                                     120) == 120


# ---------------------------------------------------------------------------
# session behaviour: unlock, match, fill, totp, save, lock (gates #2/#5)
# ---------------------------------------------------------------------------

@pytest.fixture()
def session(env):
    host = native_host.NativeHost(env["store"], env["vault"])
    client, _ = connect(host, env)
    return host, client


def test_unlock_match_fill_totp(session):
    host, client = session
    # locked: match refused
    r = rpc(host, client, {"id": 1, "kind": "match",
                           "origin": "https://github.com"})
    assert r["ok"] is False and r["code"] == "locked"

    r = rpc(host, client, {"id": 2, "kind": "unlock",
                           "password": "wrong-password-xx"})
    assert r["ok"] is False and r["code"] == "wrong_password"

    r = rpc(host, client, {"id": 3, "kind": "unlock",
                           "password": MASTER})
    assert r["ok"] is True and r["unlocked"] is True

    r = rpc(host, client, {"id": 4, "kind": "match",
                           "origin": "https://github.com/login"})
    assert [m["username"] for m in r["matches"]] == ["octocat"]
    entry_id = r["matches"][0]["id"]
    assert r["matches"][0]["has_totp"] is True
    # match metadata carries NO secret
    assert PW_ALPHA not in json.dumps(r)

    # lookalike origin gets nothing (gate #2)
    r = rpc(host, client, {"id": 5, "kind": "match",
                           "origin": "https://github.com.evil.com"})
    assert r["matches"] == []

    # fill re-validates origin: asking for github's entry on a
    # different origin is refused even with a valid entry id
    r = rpc(host, client, {"id": 6, "kind": "fill",
                           "entry_id": entry_id,
                           "origin": "https://example.com"})
    assert r["ok"] is False and r["code"] == "origin_mismatch"

    r = rpc(host, client, {"id": 7, "kind": "fill",
                           "entry_id": entry_id,
                           "origin": "https://github.com/login"})
    assert r["username"] == "octocat" and r["password"] == PW_ALPHA

    r = rpc(host, client, {"id": 8, "kind": "totp",
                           "entry_id": entry_id,
                           "origin": "https://github.com"})
    assert len(r["code"]) == 6 and r["code"].isdigit()
    vault = MyKey(MASTER, vault_file=session[0].vault_file)
    vault.unlock()
    assert r["code"] == vault.totp_for("GitHub", "octocat")


def test_subdomain_toggle(session):
    host, client = session
    rpc(host, client, {"id": 1, "kind": "unlock", "password": MASTER})
    r = rpc(host, client, {"id": 2, "kind": "match",
                           "origin": "https://app.example.com"})
    assert r["matches"] == []
    r = rpc(host, client, {"id": 3, "kind": "match",
                           "origin": "https://example.com"})
    entry_id = r["matches"][0]["id"]
    r = rpc(host, client, {"id": 4, "kind": "set_entry_pref",
                           "entry_id": entry_id,
                           "fill_subdomains": True})
    assert r["fill_subdomains"] is True
    r = rpc(host, client, {"id": 5, "kind": "match",
                           "origin": "https://app.example.com"})
    assert [m["username"] for m in r["matches"]] == ["subuser"]


def test_save_flow(session):
    host, client = session
    rpc(host, client, {"id": 1, "kind": "unlock", "password": MASTER})
    origin = "https://newsite.example"
    r = rpc(host, client, {"id": 2, "kind": "save_check",
                           "origin": origin, "username": "newbie",
                           "password": "a-brand-new-pw-1"})
    assert r["status"] == "new"
    r = rpc(host, client, {"id": 3, "kind": "save_commit",
                           "origin": origin, "username": "newbie",
                           "password": "a-brand-new-pw-1"})
    assert r["saved"] is True
    r = rpc(host, client, {"id": 4, "kind": "save_check",
                           "origin": origin, "username": "newbie",
                           "password": "a-brand-new-pw-1"})
    assert r["status"] == "exists_same"
    r = rpc(host, client, {"id": 5, "kind": "save_check",
                           "origin": origin, "username": "newbie",
                           "password": "changed-pw-2"})
    assert r["status"] == "exists_diff"
    r = rpc(host, client, {"id": 6, "kind": "save_commit",
                           "origin": origin, "username": "newbie",
                           "password": "changed-pw-2",
                           "entry_id": r["entry_id"]})
    assert r["changed"] == ["password"]
    vault = MyKey(MASTER, vault_file=host.vault_file)
    vault.unlock()
    assert vault.get_password("newsite.example") == "changed-pw-2"


def test_lock_wipes_access(session):
    host, client = session
    rpc(host, client, {"id": 1, "kind": "unlock", "password": MASTER})
    r = rpc(host, client, {"id": 2, "kind": "lock"})
    assert r["unlocked"] is False
    assert host.vault is None
    r = rpc(host, client, {"id": 3, "kind": "match",
                           "origin": "https://github.com"})
    assert r["ok"] is False and r["code"] == "locked"


def test_auto_lock_with_fake_clock(env):
    clock = {"t": 1000.0}
    store = env["store"]
    store.set_setting("auto_lock_seconds", 30)
    host = native_host.NativeHost(store, env["vault"],
                                  time_fn=lambda: clock["t"])
    client, _ = connect(host, env)
    rpc(host, client, {"id": 1, "kind": "unlock", "password": MASTER})
    clock["t"] += 31
    r = rpc(host, client, {"id": 2, "kind": "match",
                           "origin": "https://github.com"})
    assert r["ok"] is False and r["code"] == "locked"


def test_replay_and_reorder_end_session(env):
    host = native_host.NativeHost(env["store"], env["vault"])
    client, _ = connect(host, env)
    frame = client.seal({"id": 1, "kind": "ping"})
    host.channel.open(frame)
    with pytest.raises(native_host.ProtocolError):
        host.channel.open(frame)  # exact replay


# ---------------------------------------------------------------------------
# subprocess end-to-end + frame-capture leak assertion (gate #1)
# ---------------------------------------------------------------------------

def test_subprocess_no_plaintext_on_the_wire(env, tmp_path):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(repo, "native_host.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        env={**os.environ, "MYKEY_EXT_STORE": env["store_path"],
             "MYKEY_EXT_VAULT": env["vault"]})
    captured = bytearray()
    lock = threading.Lock()

    def send(frame):
        body = json.dumps(frame).encode()
        with lock:
            captured.extend(body)
        proc.stdin.write(len(body).to_bytes(4, "little"))
        proc.stdin.write(body)
        proc.stdin.flush()

    def recv():
        import struct
        header = proc.stdout.read(4)
        assert len(header) == 4
        (n,) = struct.unpack("<I", header)
        body = proc.stdout.read(n)
        with lock:
            captured.extend(body)
        return json.loads(body.decode())

    try:
        client = Client(env)
        send(client.hello_frame())
        response = recv()
        ack = client.accept_hello(response)
        assert ack["unlocked"] is False

        def call(message):
            send(client.seal(message))
            return client.open(recv())

        r = call({"id": 1, "kind": "unlock", "password": MASTER})
        assert r["unlocked"] is True
        r = call({"id": 2, "kind": "match",
                  "origin": "https://github.com"})
        entry_id = r["matches"][0]["id"]
        r = call({"id": 3, "kind": "fill", "entry_id": entry_id,
                  "origin": "https://github.com"})
        assert r["password"] == PW_ALPHA
        r = call({"id": 4, "kind": "totp", "entry_id": entry_id,
                  "origin": "https://github.com"})
        code = r["code"]
        r = call({"id": 5, "kind": "lock"})
        assert r["unlocked"] is False
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)

    wire = bytes(captured)
    for secret in (MASTER, PW_ALPHA, PW_BETA, PW_GAMMA, "octocat",
                   "subuser", "banker", TOTP_SECRET, code):
        assert secret.encode() not in wire, \
            f"LEAK: {secret!r} appeared in captured frames"


# ---------------------------------------------------------------------------
# Launcher interpreter (found on the owner's laptop, 2026-10-13)
# ---------------------------------------------------------------------------


def test_launcher_embeds_the_installing_interpreter(tmp_path):
    """The browser runs the launcher with whatever PATH the
    browser session has; a bare "python" there may lack MyKey's
    dependencies entirely. The launcher must name the interpreter
    that ran ext-host-install (sys.executable)."""
    import mykey_cli

    launcher = mykey_cli._ext_write_launcher(
        str(tmp_path), str(tmp_path))
    with open(launcher, encoding="utf-8") as f:
        content = f.read()
    assert sys.executable in content
    assert "native_host.py" in content


def test_fatal_frame_shape_for_refused_hello(env):
    """A refused hello must answer {kind: fatal, code, message} —
    the extension surfaces code+message to the user; an earlier
    build sent only {"error": ...} and every refusal collapsed
    into one generic line (found on the laptop, 2026-10-13)."""
    import struct

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(repo, "native_host.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        env={**os.environ, "MYKEY_EXT_STORE": env["store_path"]})
    try:
        hello = {"kind": "hello",
                 "extension_id": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                 "ext_pub": _b64e(b"\x01" * 32),
                 "client_nonce": _b64e(b"\x02" * 32)}
        body = json.dumps(hello).encode()
        proc.stdin.write(len(body).to_bytes(4, "little"))
        proc.stdin.write(body)
        proc.stdin.flush()
        header = proc.stdout.read(4)
        (n,) = struct.unpack("<I", header)
        frame = json.loads(proc.stdout.read(n))
        assert frame["kind"] == "fatal"
        assert frame["code"] == "pairing_refused"
        assert "pairing refused" in frame["message"]
        assert proc.wait(timeout=30) == 1
    finally:
        proc.kill()
