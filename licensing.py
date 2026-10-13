# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (licence verification
# and tier limits). It is NOT licensed under Apache 2.0, MIT, or any
# other open licence. No patent licence is granted by this file; all
# patent rights are expressly reserved. See LICENSING.md for the
# licence map.

"""Product licensing — free tier, signed licence keys, pooled limits.

THE SHAPE (owner rulings, 2026-10-13):

* The free version holds up to ``FREE_ENTRY_LIMIT`` (50) passwords.
  A licence unlocks unlimited passwords. Only the COUNT is capped —
  security is never gated: TOTP, sync, encrypted backups with
  two-factor recovery, pairing, rotation reminders, skins and
  export stay fully available on the free tier.
* Devices, agents and paired browsers draw from ONE connections
  pool: ``FREE_MAX_CONNECTIONS`` (4) free, ``max_connections``
  (20 on a standard licence) when licensed. Enforcement happens at
  enrollment/pairing time only.
* GRANDFATHER RULE: a vault already over any limit opens fully —
  read, copy, edit, export and sync all keep working. Only ADDING
  pauses until a licence is entered or the vault is trimmed back
  under the limit. Data is never held hostage.
* The limits are a fairness limit enforced in the app, offline.
  There is no activation server and no phone-home check; the
  licence key's signature is what the app verifies.

LICENCE KEYS. A licence key ("MKLIC1.…") is a signed statement:
a canonical-JSON payload plus a raw Ed25519 signature over it,
made by the company's licence authority key — a GPG keypair
("MyKey Licence Authority <info@aimlds.org>", fingerprint in
``LICENCE_AUTHORITY_FINGERPRINT``; the armored public key is
embedded below so anyone can check a statement externally too).
Verification is fully offline against the raw public key.

The signed statement carries a per-licence PASSCODE. The passcode
is an identifier, not a secret and not key material: it is
SHA-256 over (buyer email ‖ payment date ‖ buyer date of birth ‖
a random 128-bit serial). SECURITY NOTE, stated plainly because it
matters: the email / payment-date / DOB inputs only IDENTIFY a
licence and authorize its reissue from the issuer's registry (see
tools/issue_licence.py). They never derive key material for the
vault or the licence signature. What makes the passcode and the
registry hashes non-brute-forceable is the random serial, which
only the issuer and the buyer hold. The buyer's DOB is never
written into the licence key, the statement, or any buyer-facing
file — it exists only inside the passcode hash input and the
registry's salted hash.

STORAGE. A verified licence key is kept (a) in the vault's
encrypted settings, so it travels with the vault file / backup
blob to the owner's other devices, and (b) in a device-local file
(~/.mykey/licence.key, mode 0600), so a licensed user who creates
a NEW vault on the same device starts unlocked. Either copy alone
suffices; the stored text is the signed key itself (signed, not
secret — tampering just fails verification).

TEST SEAM. Every helper accepts ``public_key_b64=`` (directly or
via a ``licence_public_key_b64`` attribute on the vault object) so
tests can inject a test authority keypair. Production behaviour
always defaults to the embedded authority key.
"""

import base64
import hashlib
import json
import os
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mykey import MyKeyError

# -- the licence authority (public material — safe to embed) --------

LICENCE_AUTHORITY_FINGERPRINT = "EE62F41972E84A9ABDEDF14A565D3A0C9B65B996"
LICENCE_PUBLIC_KEY_B64 = "t0KP/Om3sbo4nUusE2XP8uAF/MFgTOSIQ6AhbPN/L9E="
GPG_PUBLIC_KEY_ASC = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEas5hhBYJKwYBBAHaRw8BAQdAt0KP/Om3sbo4nUusE2XP8uAF/MFgTOSIQ6Ah
bPN/L9G0KU15S2V5IExpY2VuY2UgQXV0aG9yaXR5IDxpbmZvQGFpbWxkcy5vcmc+
iJMEExYKADsWIQTuYvQZcuhKmr3t8UpWXToMm2W5lgUCas5hhAIbAwULCQgHAgIi
AgYVCgkICwIEFgIDAQIeBwIXgAAKCRBWXToMm2W5loz3AP9jBtn8NW/f1EuYYJ8U
2yKVHsROg7dlqzLWJE80/azargD+J6wLD5oCoN6rGIBa70BMckUBbe9EHd+0OHmB
fGTGMQ0=
=HpvB
-----END PGP PUBLIC KEY BLOCK-----
"""
# -- tier constants ---------------------------------------------------

FREE_ENTRY_LIMIT = 50
FREE_MAX_CONNECTIONS = 4
LICENSED_MAX_CONNECTIONS = 20

TOKEN_PREFIX = "MKLIC1"
PRODUCT = "mykey"
EDITION = "unlimited"

_PAYLOAD_FIELDS = {
    "licence_id", "licensee", "product", "edition", "issued_at",
    "payment_date", "serial", "passcode", "max_connections",
}


class LicenceError(MyKeyError):
    """Base class for licence errors."""


class LicenceInvalidError(LicenceError):
    """A licence key is malformed, tampered with, or not ours."""


class LicenceRequiredError(LicenceError):
    """A free-tier limit has been reached; adding pauses here."""


# -- canonical statement + token -------------------------------------

def canonical_statement(payload: dict) -> bytes:
    """The one canonical byte form of a licence statement.

    Sorted keys, tight separators, ensure_ascii (byte-identical
    to the TS client's canonicalJson in encoding.ts — the same
    convention the MKBAK signatures already use across both
    clients). Both clients produce and verify exactly these
    bytes; a token whose payload segment is not already in
    canonical form is refused.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def normalize_token(text) -> str:
    """Strip whitespace/grouping a human may have introduced while
    copying. Base64url is case-sensitive, so nothing else is folded."""
    if not isinstance(text, str):
        raise LicenceInvalidError("a licence key must be text")
    return "".join(text.split()).strip("\"'")


def make_token(payload: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign a statement payload and return the MKLIC1 token string.

    Issuer-side (and test) helper — the private key never ships in
    the client; it lives with the issuer tooling only.
    """
    body = canonical_statement(payload)
    signature = private_key.sign(body)
    return f"{TOKEN_PREFIX}.{_b64url_encode(body)}.{_b64url_encode(signature)}"


def parse_token(text):
    """Split a token into (payload dict, signature bytes, body bytes)."""
    token = normalize_token(text)
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise LicenceInvalidError(
            "that does not look like a MyKey licence key "
            f"(it should start with {TOKEN_PREFIX}.)"
        )
    try:
        body = _b64url_decode(parts[1])
        signature = _b64url_decode(parts[2])
        payload = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise LicenceInvalidError(
            "this licence key is damaged or incomplete — copy the "
            "whole key exactly as it was issued"
        ) from exc
    if not isinstance(payload, dict) or canonical_statement(payload) != body:
        raise LicenceInvalidError(
            "this licence key is not in its original form and cannot "
            "be verified"
        )
    return payload, signature, body


def verify_token(text, public_key_b64: str = LICENCE_PUBLIC_KEY_B64) -> dict:
    """Verify a licence key fully offline. Returns the payload.

    Fails closed: any damage, wrong signer, wrong product or wrong
    edition raises LicenceInvalidError.
    """
    payload, signature, body = parse_token(text)
    missing = _PAYLOAD_FIELDS - set(payload)
    if missing:
        raise LicenceInvalidError(
            "this licence key is missing part of its statement "
            f"({', '.join(sorted(missing))})"
        )
    if payload.get("product") != PRODUCT or payload.get("edition") != EDITION:
        raise LicenceInvalidError(
            "this licence key is not a MyKey unlimited licence"
        )
    if not isinstance(payload.get("max_connections"), int) or (
        payload["max_connections"] < 0
    ):
        raise LicenceInvalidError(
            "this licence key carries an unreadable connections limit"
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64)
        )
        public_key.verify(signature, body)
    except InvalidSignature as exc:
        raise LicenceInvalidError(
            "this licence key did not pass verification — it may "
            "have been copied incompletely or altered"
        ) from exc
    except LicenceInvalidError:
        raise
    except Exception as exc:
        raise LicenceInvalidError(
            "this licence key could not be verified"
        ) from exc
    return payload


def format_token_for_display(token: str) -> str:
    """Group a key into 6-character blocks for error-free copying."""
    token = normalize_token(token)
    return " ".join(token[i:i + 6] for i in range(0, len(token), 6))


# -- issuer support: passcodes + recovery hashes ----------------------
# These helpers serve tools/issue_licence.py (admin tooling). They
# are pure functions over issuer-side inputs. The buyer's DOB is an
# input to hashes ONLY — it is never stored, printed, or embedded.

def compute_passcode(email: str, payment_date: str, dob: str,
                     serial_hex: str) -> str:
    """Per-licence passcode: grouped-hex SHA-256 over the buyer's
    email, the payment date, the buyer's DOB and the licence's
    random 128-bit serial. Deterministic for fixed inputs; any
    input change changes the passcode. The serial is what makes
    this non-brute-forceable — the personal inputs alone would not
    be enough, and they are never used to derive key material."""
    material = f"{email.strip().lower()}|{payment_date}|{dob}|{serial_hex}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def make_recovery_salt() -> str:
    return secrets.token_hex(16)


def recovery_hash(email: str, dob: str, payment_date: str,
                  salt_hex: str) -> str:
    """Salted registry hash for the reinstall/recovery lookup.

    SHA-256 over salt ‖ (email ‖ DOB ‖ payment date). The registry
    stores the salt and this hash — never the DOB itself — so a
    lost-key lookup can test a candidate without a database of
    birth dates, and the per-record salt + the licence serials
    keep the table useless for bulk guessing.
    """
    material = f"{email.strip().lower()}|{dob}|{payment_date}"
    return hashlib.sha256(
        bytes.fromhex(salt_hex) + material.encode("utf-8")
    ).hexdigest()


# -- device-local licence slot ----------------------------------------

def device_licence_path() -> str:
    """~/.mykey/licence.key — the same state directory the device
    keys live in (devices.default_device_keys_path)."""
    return os.path.join(os.path.expanduser("~"), ".mykey", "licence.key")


def read_device_licence():
    """The device-local licence key text, or None. A damaged file
    reads as 'no licence' — verification downstream fails closed."""
    try:
        with open(device_licence_path(), encoding="utf-8") as f:
            text = f.read().strip()
        return text or None
    except OSError:
        return None


def write_device_licence(token: str) -> str:
    path = device_licence_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (normalize_token(token) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


def clear_device_licence():
    try:
        os.unlink(device_licence_path())
    except OSError:
        pass


# -- vault-facing helpers ----------------------------------------------
# A vault may carry a `licence_public_key_b64` attribute (the test
# seam); production vaults never set it and the embedded authority
# key is used.

def _public_key_for(vault) -> str:
    return getattr(vault, "licence_public_key_b64", None) or LICENCE_PUBLIC_KEY_B64


def vault_licence_payload(vault):
    """Verified payload of the licence stored in THIS vault, or None."""
    token = vault.get_setting("licence_key")
    if not token:
        return None
    try:
        return verify_token(token, _public_key_for(vault))
    except LicenceError:
        return None


def device_licence_payload(vault=None):
    token = read_device_licence()
    if not token:
        return None
    try:
        return verify_token(token, _public_key_for(vault) if vault else
                            LICENCE_PUBLIC_KEY_B64)
    except LicenceError:
        return None


def licence_payload(vault):
    """The vault's own stored licence wins; the device copy is the
    fallback (it is what makes a NEW vault on a licensed device
    start unlocked). Either copy alone suffices."""
    return vault_licence_payload(vault) or device_licence_payload(vault)


def is_licensed(vault) -> bool:
    return licence_payload(vault) is not None


def activate_licence(vault, token: str) -> dict:
    """Verify a pasted licence key and store it in BOTH slots:
    the vault's encrypted settings (travels with the vault) and
    the device-local file (covers future vaults on this device).
    Returns the verified payload. Raises LicenceInvalidError."""
    vault._require_human("enter a licence key")
    payload = verify_token(token, _public_key_for(vault))
    normalized = normalize_token(token)
    vault.set_setting("licence_key", normalized)
    vault._persist()
    write_device_licence(normalized)
    return payload


# -- entry cap ------------------------------------------------------------

def entry_count(vault) -> int:
    return len(vault._require_unlocked())


def entry_allowance(vault):
    """How many MORE entries may be added: None when licensed
    (unlimited), else the remaining room under FREE_ENTRY_LIMIT —
    0 for a grandfathered vault already over the limit."""
    if is_licensed(vault):
        return None
    return max(0, FREE_ENTRY_LIMIT - entry_count(vault))


def entry_cap_reached(vault) -> bool:
    allowance = entry_allowance(vault)
    return allowance is not None and allowance <= 0


def require_entry_slot(vault):
    """Raise LicenceRequiredError when one more entry would cross
    the free limit. Called before every entry-creating path
    (manual add, save, agent pending acceptance)."""
    if entry_cap_reached(vault):
        raise LicenceRequiredError(
            f"the free version holds up to {FREE_ENTRY_LIMIT} passwords "
            f"and this vault already has {entry_count(vault)}. Nothing "
            "is locked away — everything already saved keeps working. "
            "To add more, enter a licence key (Settings/About, or the "
            "licence-activate command)."
        )


# -- connections pool (devices + agents + paired browsers) ---------------

def active_device_count(vault) -> int:
    """Enrolled devices that still count: revoking a device frees
    its place in the pool immediately."""
    return sum(
        1 for rec in (vault._devices or {}).values()
        if not rec.get("revoked_at")
    )


def agent_count(vault) -> int:
    """Enrolled agents. Revoking an agent removes its registry
    record and frees its place; disabling keeps the enrollment
    (and its place) so re-enabling never needs a free slot."""
    return len(vault._agents or {})


def browser_pairing_count(vault) -> int:
    """Paired browsers — THE EXTENSION WAVE'S SEAM.

    Browser pairings live in the vault's encrypted settings under
    ``browser_pairings`` (a list of records, written via
    register_browser_pairing below). Until the browser-extension
    wave lands, no client writes them and this returns 0. Cloud /
    export pairing targets (the blob wave's registry) are NOT
    connections and are never counted here — they are
    destinations, not live connections to the vault.
    """
    pairings = vault.get_setting("browser_pairings")
    return len(pairings) if isinstance(pairings, list) else 0


def connections_breakdown(vault) -> dict:
    devices = active_device_count(vault)
    agents = agent_count(vault)
    browsers = browser_pairing_count(vault)
    return {
        "devices": devices,
        "agents": agents,
        "browsers": browsers,
        "total": devices + agents + browsers,
    }


def connections_used(vault) -> int:
    return connections_breakdown(vault)["total"]


def connection_limit(vault) -> int:
    """The pool size: the licence statement's max_connections when
    licensed (a licence with a different pool size is honoured),
    else the free pool."""
    payload = licence_payload(vault)
    if payload is not None:
        return int(payload.get("max_connections") or LICENSED_MAX_CONNECTIONS)
    return FREE_MAX_CONNECTIONS


def require_connection_slot(vault, kind: str = "connection"):
    """Raise LicenceRequiredError when the pool is full. Called at
    enrollment/pairing time only — existing connections are never
    disturbed (grandfather rule)."""
    used = connections_used(vault)
    limit = connection_limit(vault)
    if used >= limit:
        payload = licence_payload(vault)
        tier = "licensed" if payload is not None else "free"
        raise LicenceRequiredError(
            f"the {tier} limit is {limit} connections — devices, "
            "agents and paired browsers share one pool — and this "
            f"vault already uses {used}. Revoke a device or an agent "
            "to free a place"
            + ("" if payload is not None else
               ", or enter a licence key to raise the pool to "
               f"{LICENSED_MAX_CONNECTIONS}.")
        )


def register_browser_pairing(vault, record: dict) -> dict:
    """Enroll a paired browser (extension-wave seam): enforces the
    connections pool, then appends the record to the vault's
    encrypted ``browser_pairings`` settings and persists."""
    vault._require_human("pair a browser")
    pairings = vault.get_setting("browser_pairings")
    if not isinstance(pairings, list):
        pairings = []
    if any(p.get("id") == record.get("id") for p in pairings):
        raise LicenceError(f"browser already paired: {record.get('id')}")
    require_connection_slot(vault, "browser")
    pairings = pairings + [dict(record)]
    vault.set_setting("browser_pairings", pairings)
    vault._persist()
    return dict(record)


def unregister_browser_pairing(vault, pairing_id: str) -> bool:
    """Remove a paired browser, freeing its pool place at once."""
    vault._require_human("unpair a browser")
    pairings = vault.get_setting("browser_pairings")
    if not isinstance(pairings, list):
        return False
    kept = [p for p in pairings if p.get("id") != pairing_id]
    if len(kept) == len(pairings):
        return False
    vault.set_setting("browser_pairings", kept)
    vault._persist()
    return True


# -- status (CLI / GUI / About) ------------------------------------------

def licence_status(vault) -> dict:
    payload = licence_payload(vault)
    breakdown = connections_breakdown(vault)
    return {
        "licensed": payload is not None,
        "licence_id": payload.get("licence_id") if payload else None,
        "licensee": payload.get("licensee") if payload else None,
        "entries": entry_count(vault),
        "entry_limit": None if payload is not None else FREE_ENTRY_LIMIT,
        "connections": breakdown["total"],
        "connections_breakdown": breakdown,
        "connection_limit": connection_limit(vault),
    }


def status_line(vault) -> str:
    """The plain-words licence line for Settings/About:
    'Free · 37 of 50 passwords · 3 of 4 connections' or
    'Licensed · unlimited passwords · 6 of 20 connections'."""
    st = licence_status(vault)
    if st["licensed"]:
        return (
            f"Licensed · unlimited passwords · "
            f"{st['connections']} of {st['connection_limit']} connections"
        )
    return (
        f"Free · {st['entries']} of {st['entry_limit']} passwords · "
        f"{st['connections']} of {st['connection_limit']} connections"
    )
