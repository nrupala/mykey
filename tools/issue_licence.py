# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (licence issuance
# tooling). It is NOT licensed under Apache 2.0, MIT, or any other
# open licence. No patent licence is granted by this file; all
# patent rights are expressly reserved. See LICENSING.md for the
# licence map.

"""Licence issuer — ADMIN TOOLING. Never shipped to buyers.

Mints MyKey licence keys under the company's licence authority:
a GPG keypair ("MyKey Licence Authority <info@aimlds.org>",
ed25519, certify+sign). The authority's private material lives
ONLY in ~/workspace/corporate/licensing/ (dir 0700, files 0600) —
never in a repository, a log, or a report.

For each licence the tool writes, into the output directory:

  <licence_id>.licence-key.txt    the MKLIC1.… key (grouped for
                                  error-free copying)
  <licence_id>.statement.json     the signed statement (canonical
                                  JSON — the exact bytes the key's
                                  signature covers)
  <licence_id>.statement.json.asc an armored detached GPG signature
                                  over the statement, so a buyer can
                                  verify it externally with
                                  `gpg --verify` against the
                                  published authority public key

and appends one record to the licence registry
(~/workspace/corporate/licensing/registry.jsonl, mode 0600).

THE PASSCODE + THE THREE INPUTS. At issuance the tool computes the
licence's passcode = SHA-256(email ‖ payment date ‖ buyer DOB ‖
random 128-bit serial), shown in the statement. The registry stores
the passcode and a SALTED SHA-256 of (email ‖ DOB ‖ payment date),
so a buyer who loses their key can be re-issued it: `recover`
takes the same three inputs, finds the matching record by hash,
re-mints the identical key (Ed25519 signatures are deterministic,
and every statement field is in the registry), and prints it. The
documented procedure sends the re-issued key ONLY to the email on
file. The raw DOB is NEVER written anywhere — not the registry,
not the statement, not the key: it exists only as a transient hash
input. (The tool scans its own outputs for the DOB string before
finishing, and fails loudly if it ever appears.)

Security note, also in licensing.py: the three personal inputs
IDENTIFY a licence and authorize its reissue. They never derive
key material. The random serial is what makes both hashes
non-brute-forceable.

KEY HANDLING. Two derivations of the authority, cross-checked on
every run:
  * the raw Ed25519 scalar, loaded from a PKCS8 PEM
    (env MYKEY_LICENCE_SIGNING_KEY, default the corporate path).
    The PEM is itself derived from the GPG secret export — see
    `derive-pem` below and LICENCE.md, "Authority setup".
  * the authority's GPG home (env MYKEY_LICENCE_GPG_HOME, default
    the corporate gnupg dir), used for the detached .asc signature.
The tool REFUSES to run if the key file is group/world-readable,
if the PEM's public key does not match the GPG home's key, or if
the loaded key is not the production authority (a test authority
is accepted only with MYKEY_LICENCE_ALLOW_TEST_KEY=1, for tests).
"""

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import licensing  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

CORPORATE_DIR = os.path.join(
    os.path.expanduser("~"), "workspace", "corporate", "licensing")
DEFAULT_KEY_PATH = os.path.join(CORPORATE_DIR, "mykey-licence-signing.pem")
DEFAULT_GPG_HOME = os.path.join(CORPORATE_DIR, "gnupg")
DEFAULT_REGISTRY = os.path.join(CORPORATE_DIR, "registry.jsonl")


class LicenceToolError(Exception):
    pass


# -- minimal OpenPGP key-packet parsing -------------------------------
# Used to read the RAW Ed25519 public key out of a `gpg --export`
# (and, in derive-pem, the scalar out of a `gpg --export-secret-keys`
# for an unprotected key). Only v4 ed25519 key packets are handled;
# anything else fails closed. This parses the authority's OWN key
# material at setup/issuance time — it is not a general OpenPGP
# implementation.

def _packets(data: bytes):
    i = 0
    while i < len(data):
        b = data[i]
        if not b & 0x80:
            raise LicenceToolError("corrupt OpenPGP packet stream")
        if b & 0x40:  # new format
            tag = b & 0x3F
            i += 1
            first = data[i]
            if first < 192:
                length = first
                i += 1
            elif first <= 223:
                length = ((first - 192) << 8) + data[i + 1] + 192
                i += 2
            elif first == 255:
                length = int.from_bytes(data[i + 1:i + 5], "big")
                i += 5
            else:
                raise LicenceToolError("partial packet lengths unsupported")
        else:  # old format
            tag = (b >> 2) & 0x0F
            lt = b & 0x03
            i += 1
            if lt == 0:
                length = data[i]
                i += 1
            elif lt == 1:
                length = int.from_bytes(data[i:i + 2], "big")
                i += 2
            elif lt == 2:
                length = int.from_bytes(data[i:i + 4], "big")
                i += 4
            else:
                raise LicenceToolError("indeterminate packet length")
        yield tag, data[i:i + length]
        i += length


def _read_mpi(buf: bytes, off: int):
    bits = int.from_bytes(buf[off:off + 2], "big")
    off += 2
    nbytes = (bits + 7) // 8
    return buf[off:off + nbytes], off + nbytes


def _parse_ed25519_key_packet(body: bytes, secret: bool):
    if body[0] != 4 or body[5] != 22:
        raise LicenceToolError("not a v4 Ed25519 key packet")
    off = 6
    oid_len = body[off]
    off += 1 + oid_len
    point, off = _read_mpi(body, off)
    if len(point) != 33 or point[0] != 0x40:
        raise LicenceToolError("unexpected Ed25519 public point encoding")
    public = point[1:33]
    seed = None
    if secret:
        s2k = body[off]
        off += 1
        if s2k != 0:
            raise LicenceToolError(
                "the authority key is passphrase-protected; derive-pem "
                "needs the unprotected export (the corporate key is "
                "kept unprotected behind 0600 file permissions)")
        raw, _off = _read_mpi(body, off)
        seed = raw.rjust(32, b"\x00")[-32:]
    return public, seed


def raw_public_from_gpg_export(data: bytes) -> bytes:
    for tag, body in _packets(data):
        if tag == 6:
            public, _ = _parse_ed25519_key_packet(body, secret=False)
            return public
    raise LicenceToolError("no public key packet in the GPG export")


# -- authority loading ---------------------------------------------------

def _require_private_file(path: str, what: str):
    if not os.path.exists(path):
        raise LicenceToolError(f"{what} not found: {path}")
    if os.stat(path).st_mode & 0o077:
        raise LicenceToolError(
            f"{what} must not be group/world-readable: {path} "
            "(chmod 600 it — the issuer refuses otherwise)")


def load_authority():
    """Return (private_key, gpg_fingerprint). Cross-checks the PEM
    against the GPG home's exported key and the production constant."""
    key_path = os.environ.get("MYKEY_LICENCE_SIGNING_KEY", DEFAULT_KEY_PATH)
    gpg_home = os.environ.get("MYKEY_LICENCE_GPG_HOME", DEFAULT_GPG_HOME)
    _require_private_file(key_path, "licence signing key")
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise LicenceToolError("the signing key is not an Ed25519 key")
    pem_public = private_key.public_key().public_bytes_raw()

    env = dict(os.environ, GNUPGHOME=gpg_home)
    export = subprocess.run(
        ["gpg", "--batch", "--export"], capture_output=True, env=env)
    if export.returncode != 0 or not export.stdout:
        raise LicenceToolError(f"cannot export the GPG authority key "
                               f"from {gpg_home}")
    gpg_public = raw_public_from_gpg_export(export.stdout)
    if gpg_public != pem_public:
        raise LicenceToolError(
            "the PEM signing key does not match the GPG authority "
            "key — refusing to issue under a mismatched authority")
    listing = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-keys"],
        capture_output=True, env=env, text=True)
    fingerprint = ""
    for line in listing.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr":
            fingerprint = fields[9]
            break
    production = (
        base64.b64encode(pem_public).decode()
        == licensing.LICENCE_PUBLIC_KEY_B64)
    if not production and os.environ.get("MYKEY_LICENCE_ALLOW_TEST_KEY") != "1":
        raise LicenceToolError(
            "the loaded key is NOT the production licence authority "
            f"({licensing.LICENCE_AUTHORITY_FINGERPRINT}) — refusing. "
            "Tests may set MYKEY_LICENCE_ALLOW_TEST_KEY=1.")
    return private_key, fingerprint, gpg_home


# -- registry --------------------------------------------------------------

def _registry_path(explicit=None):
    return explicit or os.environ.get("MYKEY_LICENCE_REGISTRY",
                                      DEFAULT_REGISTRY)


def _read_registry(path):
    if not os.path.exists(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _append_registry(path, record):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    os.chmod(path, 0o600)


def _statement_payload(record):
    """Rebuild the signed statement from a registry record — every
    field of the statement is stored, so recovery re-mints the
    identical key (Ed25519 signatures are deterministic)."""
    return {
        "licence_id": record["licence_id"],
        "licensee": record["licensee"],
        "product": licensing.PRODUCT,
        "edition": licensing.EDITION,
        "issued_at": record["issued_at"],
        "payment_date": record["payment_date"],
        "serial": record["serial"],
        "passcode": record["passcode"],
        "max_connections": record["max_connections"],
    }


# -- subcommands -------------------------------------------------------------

def cmd_derive_pem(args):
    with open(args.secret_export, "rb") as f:
        data = f.read()
    public = seed = None
    for tag, body in _packets(data):
        if tag == 5:
            public, seed = _parse_ed25519_key_packet(body, secret=True)
        elif tag == 6 and public is None:
            public, _ = _parse_ed25519_key_packet(body, secret=False)
    if seed is None or public is None:
        raise LicenceToolError("no Ed25519 secret key packet found")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    if key.public_key().public_bytes_raw() != public:
        raise LicenceToolError("derived key does not match the export")
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    if os.path.exists(args.out):
        raise LicenceToolError(f"refusing to overwrite {args.out}")
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"derived signing PEM written to {args.out} (mode 0600); "
          f"public key cross-checked against the export")
    return 0


def cmd_issue(args):
    private_key, fingerprint, gpg_home = load_authority()
    email = args.email.strip().lower()
    serial = secrets.token_hex(16)  # 128-bit random serial
    passcode = licensing.compute_passcode(
        email, args.payment_date, args.dob, serial)
    salt = licensing.make_recovery_salt()
    record = {
        "licence_id": "lic-" + uuid.uuid4().hex[:16],
        "licensee": email,
        "payment_date": args.payment_date,
        "serial": serial,
        "passcode": passcode,
        "issued_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "max_connections": args.max_connections,
        "recovery_salt": salt,
        "recovery_hash": licensing.recovery_hash(
            email, args.dob, args.payment_date, salt),
        "status": "active",
    }
    payload = _statement_payload(record)
    token = licensing.make_token(payload, private_key)
    statement = licensing.canonical_statement(payload)

    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, record["licence_id"])
    with open(base + ".licence-key.txt", "w", encoding="utf-8") as f:
        f.write(licensing.format_token_for_display(token) + "\n")
    with open(base + ".statement.json", "wb") as f:
        f.write(statement + b"\n")
    env = dict(os.environ, GNUPGHOME=gpg_home)
    sign = subprocess.run(
        ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
         "--homedir", gpg_home, "--local-user", fingerprint,
         "--detach-sign", "--armor",
         "--output", base + ".statement.json.asc",
         base + ".statement.json"],
        capture_output=True, env=env, text=True)
    if sign.returncode != 0:
        raise LicenceToolError(
            f"gpg detached signing failed: {sign.stderr.strip()}")
    registry = _registry_path(args.registry)
    _append_registry(registry, record)
    # Self-check: the buyer's DOB must appear in NOTHING we wrote.
    for suffix in (".licence-key.txt", ".statement.json",
                   ".statement.json.asc"):
        with open(base + suffix, "r", encoding="utf-8") as f:
            if args.dob in f.read():
                raise LicenceToolError(
                    f"FATAL: buyer DOB found in {base + suffix}")
    print(f"licence issued: {record['licence_id']} for {email}")
    print(f"  key file:       {base}.licence-key.txt")
    print(f"  statement:      {base}.statement.json (+ .asc, "
          f"signed by {fingerprint})")
    print(f"  registry:       {registry} (record appended, mode 0600)")
    print("  Send the buyer the key file and the statement pair. "
          "Keep the passcode on file — it is in the registry, not "
          "in anything sent.")
    return 0


def cmd_recover(args):
    private_key, _fpr, _home = load_authority()
    registry = _registry_path(args.registry)
    email = args.email.strip().lower()
    for record in _read_registry(registry):
        if record.get("licensee") != email:
            continue
        candidate = licensing.recovery_hash(
            email, args.dob, args.payment_date, record["recovery_salt"])
        if secrets.compare_digest(candidate, record["recovery_hash"]):
            token = licensing.make_token(
                _statement_payload(record), private_key)
            sys.stderr.write(
                "Match found. Re-issue procedure: send this key ONLY "
                f"to the email on file ({email}) — never to a "
                "different address, however the request arrives.\n")
            print(licensing.format_token_for_display(token))
            return 0
    sys.stderr.write(
        "No licence matches those details. Check the email, the "
        "payment date, and the date of birth against the purchase "
        "record — or ask the buyer for their payment receipt and "
        "handle it as a manual support case.\n")
    return 1


def cmd_verify(args):
    public_b64 = os.environ.get("MYKEY_LICENCE_PUBLIC_KEY_B64",
                                licensing.LICENCE_PUBLIC_KEY_B64)
    payload = licensing.verify_token(args.token, public_key_b64=public_b64)
    print(f"valid licence: {payload['licence_id']} for "
          f"{payload['licensee']} — edition {payload['edition']}, "
          f"max {payload['max_connections']} connections, "
          f"issued {payload['issued_at']}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description="MyKey licence issuer (admin tooling — see the "
                    "module docstring)")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser(
        "derive-pem",
        help="derive the issuer PEM from a GPG secret-key export "
             "(authority setup; run once)")
    d.add_argument("--secret-export", required=True)
    d.add_argument("--out", required=True)
    d.set_defaults(fn=cmd_derive_pem)

    i = sub.add_parser("issue", help="mint a new licence")
    i.add_argument("--email", required=True, help="buyer email (licensee)")
    i.add_argument("--payment-date", required=True,
                   help="payment date, ISO (YYYY-MM-DD)")
    i.add_argument("--dob", required=True,
                   help="buyer date of birth, ISO — hashed into the "
                        "passcode + registry only; never written out")
    i.add_argument("--max-connections", type=int,
                   default=licensing.LICENSED_MAX_CONNECTIONS)
    i.add_argument("--out-dir", default=".",
                   help="where the buyer artefacts are written")
    i.add_argument("--registry", default=None)
    i.set_defaults(fn=cmd_issue)

    r = sub.add_parser(
        "recover",
        help="re-issue a lost key from email + payment date + DOB")
    r.add_argument("--email", required=True)
    r.add_argument("--payment-date", required=True)
    r.add_argument("--dob", required=True)
    r.add_argument("--registry", default=None)
    r.set_defaults(fn=cmd_recover)

    v = sub.add_parser("verify", help="verify a licence key offline")
    v.add_argument("--token", required=True)
    v.set_defaults(fn=cmd_verify)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except LicenceToolError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 2
    except licensing.LicenceInvalidError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
