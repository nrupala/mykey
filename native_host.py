# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Native messaging host: the desktop end of the browser extension.

The browser extension holds NO vault copy. It talks to this host over
the browser's native messaging pipe (length-prefixed JSON on
stdin/stdout), and this host — a desktop MyKey process — brokers
unlock state and entry queries for ONE paired extension at a time.

Transit encryption (owner directive: encryption in transit, not just
at rest). Native messaging is a local pipe, and we encrypt anyway:

* Pairing (extpair.py) gives both sides a static X25519 keypair and
  pins the peer's public key, approved by the human with a
  fingerprint comparison on the desktop.
* Each connection runs a handshake: both sides contribute a fresh
  32-byte nonce, the session keys are HKDF-SHA256 over the X25519
  shared secret and both nonces (one key per direction), and every
  message after the handshake is AES-256-GCM sealed with a
  counter nonce and direction/session-bound AAD. Sequence numbers
  are strict: a replayed, reordered or forged frame ends the
  session. A capture of the pipe shows only ciphertext — the leak
  test suite proves that against fixture secrets.
* The master password crosses only inside this channel, only when
  the human types it into the extension popup, and is never stored
  or logged by either side. The host keeps the unlocked vault in
  memory only, behind an idle auto-lock.

Origin discipline: fills are matched strictly by origin (scheme +
host + port of the entry's website). An entry may fill on its
subdomains only when the human turned that on for that entry (a
per-entry preference in the host store, default off). The host
re-validates the origin on every fill — the extension's own match
is a convenience, never the authority.

Fills happen only on explicit user action in the extension; the
host never pushes a credential unasked, and it never auto-submits
anything (submission is the page's own behaviour, not ours).

Run:  python3 native_host.py            (under native messaging)
      python3 native_host.py --check    (print host payload + exit)
"""

import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import sys
import time
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import extpair
from mykey import MyKey, MyKeyError, WrongPassword, make_entry

PROTOCOL = "mykey-ext-v1"
MAX_FRAME_BYTES = 1 << 20
_DIRECTIONS = ("e2h", "h2e")


class ProtocolError(Exception):
    """Framing or channel failure — the session is over.

    Carries the fatal-frame code the extension surfaces; the
    wire shape is {kind: "fatal", code, message} (EXTENSION_HOST.md).
    """

    def __init__(self, message, code="protocol"):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# channel cryptography (mirrored byte-for-byte in extension/src/channel.ts)
# ---------------------------------------------------------------------------

def derive_session_keys(shared_secret: bytes, client_nonce: bytes,
                        server_nonce: bytes) -> dict:
    """HKDF-SHA256 over the X25519 secret, salted by both nonces."""
    salt = client_nonce + server_nonce
    out = {}
    for direction in _DIRECTIONS:
        out[direction] = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            info=f"{PROTOCOL} {direction}".encode(),
        ).derive(shared_secret)
    return out


def _nonce(direction: str, seq: int) -> bytes:
    return direction.encode()[:3] + b"\x00" + seq.to_bytes(8, "big")


def _aad(direction: str, session_id: str, seq: int) -> bytes:
    return (f"{PROTOCOL}|{direction}|{session_id}|".encode()
            + seq.to_bytes(8, "big"))


class Channel:
    """One sealed session. Counters start at 0 per direction; any
    gap, replay or tag failure raises ProtocolError."""

    def __init__(self, keys: dict, session_id: str):
        self._keys = keys
        self.session_id = session_id
        self._send_seq = 0
        self._expect_seq = 0

    def seal(self, message: dict) -> dict:
        seq = self._send_seq
        nonce = _nonce("h2e", seq)
        ct = AESGCM(self._keys["h2e"]).encrypt(
            nonce, _canonical(message),
            _aad("h2e", self.session_id, seq))
        self._send_seq += 1
        from mykey import _b64e
        return {"kind": "sealed", "session": self.session_id,
                "seq": seq, "nonce": _b64e(nonce), "ct": _b64e(ct)}

    def open(self, frame: dict) -> dict:
        from mykey import _b64d
        if frame.get("kind") != "sealed" \
                or frame.get("session") != self.session_id:
            raise ProtocolError("frame is not for this session")
        seq = frame.get("seq")
        if seq != self._expect_seq:
            raise ProtocolError(
                f"sequence mismatch: expected {self._expect_seq}, "
                f"got {seq!r} (replay or reorder — session ended)")
        try:
            nonce = _b64d(frame["nonce"])
            if nonce != _nonce("e2h", seq):
                raise ProtocolError("nonce does not match sequence")
            pt = AESGCM(self._keys["e2h"]).decrypt(
                nonce, _b64d(frame["ct"]),
                _aad("e2h", self.session_id, seq))
        except ProtocolError:
            raise
        except (InvalidTag, Exception) as exc:
            raise ProtocolError(f"frame failed to open: {exc}") from exc
        self._expect_seq += 1
        try:
            message = json.loads(pt.decode("utf-8"))
        except Exception as exc:
            raise ProtocolError("frame plaintext is not JSON") from exc
        if not isinstance(message, dict):
            raise ProtocolError("frame plaintext is not an object")
        return message


def _canonical(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# origin matching (the authority lives here, not in the browser)
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"https": 443, "http": 80}
_HOSTISH_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+"
    r"(:\d{1,5})?$")


def parse_origin(value):
    """Parse a URL or origin into (scheme, host, port) or None.

    Only http/https. Userinfo is rejected. Host is lowercased and a
    trailing dot is stripped (``example.com.`` is the same host —
    keeping it would let a lookalike slip classification, dropping
    it is the conservative direction here because matching is an
    allowlist, and both spellings denote the same DNS name).
    """
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if "://" not in value:
        return None
    try:
        parts = urlparse(value)
    except Exception:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if parts.username or parts.password:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    return (scheme, host, int(port))


def entry_origin(entry) -> tuple | None:
    """Origin of an entry's website. Falls back to a host-shaped
    service name (``github.com``) over https — never to a fuzzy
    substring match."""
    origin = parse_origin(entry.get("url") or "")
    if origin:
        return origin
    service = (entry.get("service") or "").strip().lower()
    if service and " " not in service and _HOSTISH_RE.match(service):
        host = service
        port = _DEFAULT_PORTS["https"]
        if ":" in host:
            host, _, p = host.rpartition(":")
            port = int(p)
        return ("https", host.rstrip("."), port)
    return None


def origin_matches(entry_org, page_org, allow_subdomains: bool) -> bool:
    if entry_org is None or page_org is None:
        return False
    e_scheme, e_host, e_port = entry_org
    p_scheme, p_host, p_port = page_org
    if e_scheme != p_scheme or e_port != p_port:
        return False
    if e_host == p_host:
        return True
    # Parent-domain entry filling a subdomain page — only with the
    # human's per-entry allowance. Lookalikes never satisfy this:
    # the page host must END with "." + entry host.
    return bool(allow_subdomains) and p_host.endswith("." + e_host)


def _service_for_origin(page_org) -> str:
    host = page_org[1]
    return host[4:] if host.startswith("www.") else host


# ---------------------------------------------------------------------------
# framing (native messaging: 4-byte little-endian length + JSON)
# ---------------------------------------------------------------------------

def read_frame(stream) -> dict | None:
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        raise ProtocolError("truncated frame header")
    (length,) = struct.unpack("<I", header)
    if length > MAX_FRAME_BYTES:
        raise ProtocolError("frame exceeds the size cap")
    body = stream.read(length)
    if len(body) < length:
        raise ProtocolError("truncated frame body")
    try:
        frame = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError("frame is not JSON") from exc
    if not isinstance(frame, dict):
        raise ProtocolError("frame is not an object")
    return frame


def write_frame(stream, frame: dict):
    body = json.dumps(frame, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(body)))
    stream.write(body)
    stream.flush()


# ---------------------------------------------------------------------------
# the host
# ---------------------------------------------------------------------------

class NativeHost:
    def __init__(self, store: extpair.ExtensionHostStore,
                 vault_file: str = "", time_fn=time.time):
        self.store = store
        self.vault_file = vault_file \
            or os.environ.get("MYKEY_EXT_VAULT") \
            or store.settings.get("vault_file") or ""
        self._time = time_fn
        self.channel: Channel | None = None
        self.pairing: dict | None = None
        self.vault: MyKey | None = None
        self._last_activity = 0.0
        self._unlock_failures = 0
        self._backoff_until = 0.0

    # -- session ---------------------------------------------------------

    def handle_hello(self, frame: dict) -> dict:
        from mykey import _b64d, _b64e
        if frame.get("kind") != "hello":
            raise ProtocolError("first frame must be a hello")
        extension_id = extpair.validate_extension_id(
            frame.get("extension_id"))
        record = self.store.get(extension_id)
        if record is None or not self.store.pairing_active(extension_id):
            raise ProtocolError(
                "pairing refused: unknown, disabled, expired or "
                "revoked extension", code="pairing_refused")
        try:
            ext_pub_raw = _b64d(frame["ext_pub"])
            client_nonce = _b64d(frame["client_nonce"])
            ext_pub = X25519PublicKey.from_public_bytes(ext_pub_raw)
        except Exception as exc:
            raise ProtocolError(f"malformed hello: {exc}") from exc
        if not hmac_mod.compare_digest(
                ext_pub_raw, _b64d(record["x25519_pub"])):
            raise ProtocolError(
                "hello key does not match the paired key — refused",
                code="pairing_refused")
        if len(client_nonce) != 32:
            raise ProtocolError("client nonce must be 32 bytes")
        server_nonce = os.urandom(32)
        shared = self.store.host_private_key.exchange(ext_pub)
        keys = derive_session_keys(shared, client_nonce, server_nonce)
        session_id = hashlib.sha256(
            client_nonce + server_nonce).hexdigest()[:32]
        self.channel = Channel(keys, session_id)
        self.pairing = record
        self._touch()
        ack = self.channel.seal({
            "kind": "hello_ack", "protocol": PROTOCOL,
            "unlocked": self.vault is not None,
            "vault_configured": bool(self.vault_file),
            "scopes": list(record.get("scopes") or []),
        })
        return {"kind": "hello", "session": session_id,
                "host_pub": _b64e(self.store.host_public_key),
                "server_nonce": _b64e(server_nonce), "ack": ack}

    # -- vault state -------------------------------------------------------

    @property
    def unlocked(self) -> bool:
        return self.vault is not None

    def _touch(self):
        self._last_activity = self._time()

    def _lock(self):
        self.vault = None

    def _maybe_auto_lock(self):
        if self.vault is not None:
            idle = self._time() - self._last_activity
            if idle > int(self.store.settings.get(
                    "auto_lock_seconds",
                    extpair.DEFAULT_AUTO_LOCK_SECONDS)):
                self._lock()

    # -- message dispatch ----------------------------------------------------

    def handle_message(self, message: dict) -> dict:
        req_id = message.get("id")
        kind = message.get("kind")
        self._maybe_auto_lock()
        handler = {
            "ping": self._msg_ping,
            "status": self._msg_status,
            "unlock": self._msg_unlock,
            "lock": self._msg_lock,
            "match": self._msg_match,
            "fill": self._msg_fill,
            "totp": self._msg_totp,
            "save_check": self._msg_save_check,
            "save_commit": self._msg_save_commit,
            "set_entry_pref": self._msg_set_entry_pref,
        }.get(kind)
        if handler is None:
            return self._error(req_id, "unknown_kind",
                               f"unknown message kind: {kind!r}")
        try:
            result = handler(message)
        except _Refused as refused:
            return self._error(req_id, refused.code, refused.message)
        self._touch()
        result.setdefault("kind", "result")
        result["id"] = req_id
        result["ok"] = True
        return result

    @staticmethod
    def _error(req_id, code, message) -> dict:
        return {"kind": "error", "id": req_id, "ok": False,
                "code": code, "message": message}

    # -- helpers ---------------------------------------------------------------

    def _require_unlocked(self):
        if self.vault is None:
            raise _Refused("locked", "the desktop vault is locked")

    def _require_scope(self, scope):
        if scope not in (self.pairing.get("scopes") or []):
            raise _Refused(
                "scope", f"this pairing does not hold the {scope!r} "
                "scope — re-pair from the desktop to change scopes")

    def _entries(self):
        return self.vault.list_entries() if self.vault else []

    def _entry_by_id(self, entry_id):
        for entry in self._entries():
            if entry.get("id") == entry_id:
                return entry
        return None

    def _matches_for(self, page_org):
        out = []
        for entry in self._entries():
            e_org = entry_origin(entry)
            allow_sub = bool(self.store.entry_pref(
                entry.get("id"), "fill_subdomains", False))
            if origin_matches(e_org, page_org, allow_sub):
                out.append((entry, e_org))
        return out

    # -- messages ---------------------------------------------------------------

    def _msg_ping(self, message):
        return {"kind": "pong", "unlocked": self.unlocked}

    def _msg_status(self, message):
        settings = self.store.settings
        return {
            "unlocked": self.unlocked,
            "vault_configured": bool(self.vault_file),
            "scopes": list(self.pairing.get("scopes") or []),
            "clipboard_clear_seconds": int(settings.get(
                "clipboard_clear_seconds",
                extpair.DEFAULT_CLIPBOARD_CLEAR_SECONDS)),
            "auto_lock_seconds": int(settings.get(
                "auto_lock_seconds",
                extpair.DEFAULT_AUTO_LOCK_SECONDS)),
        }

    def _msg_unlock(self, message):
        if self.vault is not None:
            return {"unlocked": True, "already": True}
        now = self._time()
        if now < self._backoff_until:
            raise _Refused(
                "backoff",
                "too many wrong passwords — wait "
                f"{int(self._backoff_until - now) + 1} seconds")
        if not self.vault_file:
            raise _Refused(
                "no_vault",
                "no vault is configured on the desktop yet — set "
                "one with: mykey ext-set-vault <path-to-vault.mykey>")
        password = message.get("password")
        if not isinstance(password, str) or not password:
            raise _Refused("bad_request", "a password is required")
        try:
            vault = MyKey(password, vault_file=self.vault_file)
            vault.unlock()
        except WrongPassword:
            self._unlock_failures += 1
            if self._unlock_failures >= 3:
                self._backoff_until = now + min(
                    2 ** (self._unlock_failures - 3), 60)
            raise _Refused("wrong_password",
                           "that master password does not open the "
                           "desktop vault")
        except MyKeyError as exc:
            raise _Refused("vault_error", str(exc)) from exc
        self.vault = vault
        self._unlock_failures = 0
        self._backoff_until = 0.0
        return {"unlocked": True, "entries": len(self._entries())}

    def _msg_lock(self, message):
        self._lock()
        return {"unlocked": False}

    def _msg_match(self, message):
        self._require_unlocked()
        self._require_scope("fill")
        page_org = parse_origin(message.get("origin") or "")
        if page_org is None:
            raise _Refused("bad_origin", "the page origin is not a "
                                         "web origin")
        matches = [{
            "id": entry["id"],
            "service": entry.get("service", ""),
            "username": entry.get("username", ""),
            "has_totp": bool(entry.get("totp_secret")),
            "fill_subdomains": bool(self.store.entry_pref(
                entry["id"], "fill_subdomains", False)),
        } for entry, _ in self._matches_for(page_org)]
        return {"matches": matches}

    def _validated_fill_target(self, message):
        """Shared gate for fill/totp: unlocked, scope, the entry
        exists, and its origin STILL matches the page origin —
        re-validated here, at the moment of release."""
        self._require_unlocked()
        self._require_scope("fill")
        entry = self._entry_by_id(message.get("entry_id"))
        if entry is None:
            raise _Refused("no_entry", "that entry no longer exists")
        page_org = parse_origin(message.get("origin") or "")
        allow_sub = bool(self.store.entry_pref(
            entry["id"], "fill_subdomains", False))
        if not origin_matches(entry_origin(entry), page_org, allow_sub):
            raise _Refused(
                "origin_mismatch",
                "the entry does not belong to this page's origin — "
                "nothing was sent")
        return entry

    def _msg_fill(self, message):
        entry = self._validated_fill_target(message)
        return {"username": entry.get("username", ""),
                "password": entry.get("password", "")}

    def _msg_totp(self, message):
        entry = self._validated_fill_target(message)
        if not entry.get("totp_secret"):
            raise _Refused("no_totp", "this entry has no sign-in code")
        code = self.vault.totp_for(entry["service"],
                                   entry.get("username") or None)
        return {"code": code}

    def _msg_save_check(self, message):
        self._require_unlocked()
        self._require_scope("save")
        page_org = parse_origin(message.get("origin") or "")
        if page_org is None:
            raise _Refused("bad_origin", "the page origin is not a "
                                         "web origin")
        username = str(message.get("username") or "")
        password = message.get("password")
        if not isinstance(password, str) or not password:
            raise _Refused("bad_request", "nothing to save")
        for entry, _ in self._matches_for(page_org):
            if (entry.get("username") or "").lower() == username.lower():
                if entry.get("password") == password:
                    return {"status": "exists_same",
                            "entry_id": entry["id"]}
                return {"status": "exists_diff",
                        "entry_id": entry["id"],
                        "service": entry.get("service", "")}
        return {"status": "new"}

    def _msg_save_commit(self, message):
        self._require_unlocked()
        self._require_scope("save")
        page_org = parse_origin(message.get("origin") or "")
        if page_org is None:
            raise _Refused("bad_origin", "the page origin is not a "
                                         "web origin")
        username = str(message.get("username") or "")
        password = message.get("password")
        if not isinstance(password, str) or not password:
            raise _Refused("bad_request", "nothing to save")
        entry_id = message.get("entry_id")
        if entry_id:
            entry = self._entry_by_id(entry_id)
            if entry is None:
                raise _Refused("no_entry", "that entry no longer "
                                           "exists")
            allow_sub = bool(self.store.entry_pref(
                entry["id"], "fill_subdomains", False))
            if not origin_matches(entry_origin(entry), page_org,
                                  allow_sub):
                raise _Refused("origin_mismatch",
                               "the entry does not belong to this "
                               "page's origin — nothing was saved")
            if entry.get("password") == password:
                return {"saved": False, "changed": [],
                        "entry_id": entry["id"]}
            self.vault.update_entry(entry["service"],
                                    entry.get("username") or None,
                                    password=password)
            return {"saved": True, "changed": ["password"],
                    "entry_id": entry["id"]}
        service = _service_for_origin(page_org)
        scheme, host, port = page_org
        url = f"{scheme}://{host}"
        if port != _DEFAULT_PORTS[scheme]:
            url += f":{port}"
        record = make_entry(service=service, username=username,
                            password=password, url=url)
        self.vault.add_entry(record)
        return {"saved": True, "changed": ["new entry"],
                "entry_id": record["id"]}

    def _msg_set_entry_pref(self, message):
        self._require_unlocked()
        entry = self._entry_by_id(message.get("entry_id"))
        if entry is None:
            raise _Refused("no_entry", "that entry no longer exists")
        value = self.store.set_entry_pref(
            entry["id"], "fill_subdomains",
            bool(message.get("fill_subdomains")))
        return {"entry_id": entry["id"], "fill_subdomains": value}

    # -- main loop ---------------------------------------------------------------

    def serve(self, in_stream, out_stream) -> int:
        try:
            first = read_frame(in_stream)
            if first is None:
                return 0
            write_frame(out_stream, self.handle_hello(first))
            while True:
                frame = read_frame(in_stream)
                if frame is None:
                    return 0
                message = self.channel.open(frame)
                response = self.handle_message(message)
                write_frame(out_stream, self.channel.seal(response))
        except (ProtocolError, extpair.ExtensionPairingError) as exc:
            try:
                code = getattr(exc, "code", "pairing_refused")
                write_frame(out_stream,
                            {"kind": "fatal", "code": code,
                             "message": str(exc)})
            except Exception:
                pass
            return 1


class _Refused(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    store_path = os.environ.get("MYKEY_EXT_STORE") \
        or extpair.default_store_path()
    store = extpair.ExtensionHostStore.load(store_path)
    if "--check" in argv:
        print(json.dumps(store.host_payload(), indent=2))
        return 0
    host = NativeHost(store)
    return host.serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    sys.exit(main())
