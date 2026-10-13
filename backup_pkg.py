# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Encrypted backup packages (Phase 3A) — portable, multi-recipient.

A backup package (``.mykeybak``) carries the whole vault bundle
(vault bytes + audit log + anchor) encrypted under a random
content key. The content key is wrapped for:

* every **enrolled, non-revoked device** in the vault registry
  (sealed to its X25519 public key), and
* a **recovery recipient** whose X25519 keypair is re-derived
  from the user's BIP-39 recovery phrase (per-vault Argon2id —
  see recovery.recovery_backup_keypair), so a replacement device
  can recover after total device loss with the phrase alone.

The package is signed with the exporting device's Ed25519 key.
A signature proves **device-key provenance only** — possession of
that device's private key file — not that a human approved this
particular package; exports through the shipped client happen in
a human-unlocked session, but a stolen key file bypasses clients.
That is stated here, not smoothed over.

Import is strict and fails closed. It refuses: malformed or
duplicate-key JSON; unknown format/version; a bundled vault that
is not Vault v3 (downgrade); a signature that does not verify;
on a fresh device, a source fingerprint that does not match the
one the human supplies from an independent channel (TOFU without
that comparison proves nothing); over an existing vault, a source
device that the unlocked registry does not show as enrolled and
unrevoked; a caller who is not a recipient (no device key, no
valid recovery phrase); and a package older than the newest one
seen for this vault, unless the human explicitly allows older.

Inherent limit, stated plainly: revoking a device cannot make
packages exported BEFORE the revocation undecryptable to a
private key that device retained. Revocation governs new
packages and signature trust, never copies already out the door.
"""

import hashlib
import json
import os
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from devices import active_devices, read_revocations
from mykey import MyKey, MyKeyError, _b64d, _b64e, _dec, _enc
from recovery import recovery_backup_keypair
from vaultsync import _atomic_write, _strict_loads, vault_header

_FORMAT = "MKBAK"
_VERSION = 1
_WRAP_INFO = b"mkbak-wrap-v1"


class BackupError(MyKeyError):
    """Backup export/import failed."""


class BackupRefused(BackupError):
    """Import refused a package (tampered, wrong recipient,
    revoked signer, malformed, or a downgrade)."""


def _now() -> int:
    return int(time.time())


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _recovery_fingerprint(pub_raw: bytes) -> str:
    digest = hashlib.sha256(pub_raw).hexdigest()
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


# ---------------------------------------------------------------------------
# recipient sealing (ephemeral ECDH -> HKDF -> AES-256-GCM), bound by AAD
# ---------------------------------------------------------------------------

def _seal_to_pub(pub_raw: bytes, plaintext: bytes, aad: bytes) -> dict:
    pub = X25519PublicKey.from_public_bytes(pub_raw)
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(pub)
    if shared == b"\x00" * 32:
        raise BackupError("recipient key produced a null shared secret")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_WRAP_INFO).derive(shared)
    blob = _enc(key, plaintext, aad)
    blob["ephemeral"] = _b64e(
        eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return blob


def _open_sealed(priv_raw: bytes, blob: dict, aad: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(priv_raw)
    eph_pub = X25519PublicKey.from_public_bytes(_b64d(blob["ephemeral"]))
    shared = priv.exchange(eph_pub)
    if shared == b"\x00" * 32:
        raise BackupRefused("sealed key produced a null shared secret")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_WRAP_INFO).derive(shared)
    return _dec(key, blob, aad)


def _wrap_aad(package_id, vault_id, recipient_id):
    return f"mkbak-wrap:v1:{package_id}:{vault_id}:{recipient_id}".encode()


# ---------------------------------------------------------------------------
# anti-rollback high-water mark (advisory — local, editable; it is a
# policy gate, not a proof. See SYNC_BACKUP.md.)
# ---------------------------------------------------------------------------

def _state_path(vault_path):
    return vault_path + ".backup-state.json"


def _read_newest_seen(vault_path):
    try:
        with open(_state_path(vault_path), "rb") as f:
            data = _strict_loads(f.read(), "backup state")
        return int(data.get("newest_created_at") or 0)
    except Exception:
        return 0


def _note_seen(vault_path, created_at):
    newest = max(_read_newest_seen(vault_path), int(created_at))
    _atomic_write(_state_path(vault_path),
                  json.dumps({"format": "MKBKS", "version": 1,
                              "newest_created_at": newest}).encode())


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

def export_package(vault: MyKey, identity, out_path=None) -> dict:
    """Build a backup package from a human-unlocked vault session.

    The exporting device must itself be enrolled (so its owner can
    always open their own backups alongside the recovery phrase).
    """
    if not isinstance(vault, MyKey):
        raise PermissionError("agent sessions cannot export backups")
    vault._require_unlocked()
    vault._require_human("export a backup package")
    devices = active_devices(vault)
    if identity.device_id not in devices:
        raise BackupError(
            "this device is not enrolled in the vault — enroll it "
            "first (device-enroll --self) so your own backups always "
            "have a device recipient")
    if vault._backup_recovery_pub is None:
        raise BackupError(
            "this vault has no backup recovery recipient — set up "
            "(or rotate) the recovery phrase once so backup packages "
            "can be recovered from the phrase after total device loss")
    vault_path = vault.vault_file
    with open(vault_path, "rb") as f:
        vault_bytes = f.read()
    header = vault_header(vault_bytes)
    content = {"vault_id": header["vault_id"], "exported_at": _now(),
               "vault": _b64e(vault_bytes)}
    for name, suffix in (("audit", ".audit.jsonl"),
                         ("anchor", ".audit-anchor.json")):
        path = vault_path + suffix
        content[name] = _b64e(open(path, "rb").read()) \
            if os.path.exists(path) else None
    package_id = uuid.uuid4().hex
    content_key = os.urandom(32)
    content_blob = _enc(content_key, _canonical(content),
                        f"mkbak:v1:{header['vault_id']}".encode())
    recipients = []
    for device_id, rec in sorted(devices.items()):
        recipients.append({
            "type": "device",
            "device_id": device_id,
            "fingerprint": rec.get("fingerprint", ""),
            "wrapped_key": _seal_to_pub(
                _b64d(rec["x25519_pub"]), content_key,
                _wrap_aad(package_id, header["vault_id"], device_id)),
        })
    recipients.append({
        "type": "recovery",
        "fingerprint": _recovery_fingerprint(vault._backup_recovery_pub),
        "wrapped_key": _seal_to_pub(
            vault._backup_recovery_pub, content_key,
            _wrap_aad(package_id, header["vault_id"], "recovery")),
    })
    package = {
        "format": _FORMAT,
        "version": _VERSION,
        "package_id": package_id,
        "created_at": _now(),
        "source": {
            "device_id": identity.device_id,
            "fingerprint": identity.fingerprint,
            "x25519_pub": _b64e(identity.x_pub),
            "ed25519_pub": _b64e(identity.e_pub),
            "vault_id": header["vault_id"],
        },
        "recipients": recipients,
        "content": content_blob,
    }
    package["signature"] = _b64e(identity.sign(
        _canonical({k: v for k, v in package.items()
                    if k != "signature"})))
    if out_path:
        _atomic_write(out_path, json.dumps(package, indent=1).encode())
    _note_seen(vault_path, package["created_at"])
    return package


# ---------------------------------------------------------------------------
# inspection + import
# ---------------------------------------------------------------------------

def _load_package(path) -> dict:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        raise BackupRefused(f"cannot read package: {exc}") from exc
    try:
        package = _strict_loads(raw, "backup package")
    except Exception as exc:
        raise BackupRefused(f"package is malformed: {exc}") from exc
    if not isinstance(package, dict) or package.get("format") != _FORMAT:
        raise BackupRefused("not a backup package (bad format token)")
    if package.get("version") != _VERSION:
        raise BackupRefused(
            f"unsupported package version {package.get('version')!r} — "
            "refusing a possible downgrade")
    for field in ("package_id", "created_at", "source",
                  "recipients", "content", "signature"):
        if field not in package:
            raise BackupRefused(f"package is missing {field!r}")
    return package


def _source_fingerprint(package) -> str:
    from devices import device_fingerprint
    source = package.get("source") or {}
    try:
        return device_fingerprint(_b64d(source["x25519_pub"]),
                                  _b64d(source["ed25519_pub"]))
    except Exception as exc:
        raise BackupRefused("package source keys are malformed") from exc


def _verify_signature(package):
    source = package.get("source") or {}
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64d(source["ed25519_pub"]))
        pub.verify(_b64d(package["signature"]),
                   _canonical({k: v for k, v in package.items()
                               if k != "signature"}))
    except InvalidSignature as exc:
        raise BackupRefused(
            "package signature does not verify — it was tampered "
            "with or re-signed by another key") from exc
    except BackupRefused:
        raise
    except Exception as exc:
        raise BackupRefused(f"package signature is malformed: {exc}") from exc


def inspect_package(path) -> dict:
    """Metadata + self-consistency, without decrypting anything."""
    package = _load_package(path)
    fingerprint = _source_fingerprint(package)
    stated = (package.get("source") or {}).get("fingerprint")
    sig_ok = True
    try:
        _verify_signature(package)
    except BackupRefused:
        sig_ok = False
    return {
        "package_id": package.get("package_id"),
        "created_at": package.get("created_at"),
        "vault_id": (package.get("source") or {}).get("vault_id"),
        "source_device_id": (package.get("source") or {}).get("device_id"),
        "source_fingerprint": fingerprint,
        "fingerprint_matches_header": stated == fingerprint,
        "signature_valid": sig_ok,
        "recipients": [
            {"type": r.get("type"),
             "device_id": r.get("device_id"),
             "fingerprint": r.get("fingerprint")}
            for r in package.get("recipients") or []],
    }


def import_package(path, target_vault_path, identity=None,
                   recovery_phrase=None, expect_fingerprint=None,
                   allow_older=False, registry=None):
    """Import a backup package as the vault at *target_vault_path*.

    *registry* is the target vault's device registry (from a
    human-unlocked session). When a vault file already exists at
    the target, registry is REQUIRED — the source device must be
    shown enrolled and unrevoked there. On a fresh target,
    *expect_fingerprint* (obtained independently of the package)
    is required instead.
    """
    package = _load_package(path)
    source = package.get("source") or {}
    vault_id = source.get("vault_id")
    fingerprint = _source_fingerprint(package)
    if source.get("fingerprint") != fingerprint:
        raise BackupRefused(
            "package source fingerprint does not match its keys")
    target_exists = os.path.exists(target_vault_path)
    if target_exists:
        if registry is None:
            raise BackupRefused(
                "a vault already exists at the target — unlock it "
                "first so the source device can be checked against "
                "its registry")
        record = registry.get(source.get("device_id") or "")
        if record is None:
            raise BackupRefused(
                "the package's source device is not enrolled in "
                "this vault — refusing it")
        if record.get("revoked_at"):
            raise BackupRefused(
                "the package's source device has been REVOKED — "
                "refusing its packages")
        if record.get("ed25519_pub") != source.get("ed25519_pub") or \
                record.get("fingerprint") != fingerprint:
            raise BackupRefused(
                "the package's source keys do not match the registry")
        revoked = read_revocations(target_vault_path)
        if source.get("device_id") in revoked:
            raise BackupRefused(
                "the package's source device is in this device's "
                "revocation record — refusing its packages")
    else:
        if not expect_fingerprint:
            raise BackupRefused(
                "fresh-device import requires the source fingerprint "
                "obtained independently of the package "
                "(--expect-fingerprint)")
        if expect_fingerprint.replace(":", "").lower() != \
                fingerprint.replace(":", "").lower():
            raise BackupRefused(
                "source fingerprint does not match the one supplied "
                "independently — refusing the package")
    _verify_signature(package)

    # -- unwrap the content key: device key, else recovery phrase.
    content_key = None
    via = None
    package_id = package["package_id"]
    for recipient in package.get("recipients") or []:
        if recipient.get("type") == "device" and identity is not None \
                and recipient.get("device_id") == identity.device_id:
            if recipient.get("fingerprint") != identity.fingerprint:
                raise BackupRefused(
                    "the device recipient fingerprint does not match "
                    "this device — the package was built for another "
                    "key under this device id")
            try:
                content_key = _open_sealed(
                    identity.x_priv_raw, recipient["wrapped_key"],
                    _wrap_aad(package_id, vault_id, identity.device_id))
                via = f"device:{identity.device_id}"
            except Exception:
                content_key = None
            break
    if content_key is None and recovery_phrase:
        for recipient in package.get("recipients") or []:
            if recipient.get("type") != "recovery":
                continue
            raw, pub = recovery_backup_keypair(recovery_phrase, vault_id)
            if _recovery_fingerprint(pub) != recipient.get("fingerprint"):
                raise BackupRefused(
                    "the recovery phrase does not match this "
                    "package's recovery recipient")
            try:
                content_key = _open_sealed(
                    raw, recipient["wrapped_key"],
                    _wrap_aad(package_id, vault_id, "recovery"))
                via = "recovery"
            except Exception as exc:
                raise BackupRefused(
                    "recovery unwrap failed — package is damaged") from exc
            break
    if content_key is None:
        raise BackupRefused(
            "not a recipient of this package: neither this device's "
            "key nor a recovery phrase opens it")

    try:
        content = json.loads(_dec(
            content_key, package["content"],
            f"mkbak:v1:{vault_id}".encode()))
    except Exception as exc:
        raise BackupRefused(
            "package content failed to decrypt — it was tampered "
            "with") from exc
    if content.get("vault_id") != vault_id:
        raise BackupRefused("package content names a different vault")
    try:
        vault_bytes = _b64d(content["vault"])
    except Exception as exc:
        raise BackupRefused("package vault content is malformed") from exc
    try:
        header = vault_header(vault_bytes)  # refuses non-v3 (downgrade)
    except Exception as exc:
        raise BackupRefused(
            f"bundled vault is not an acceptable Vault v3 file: {exc}"
        ) from exc
    if header["vault_id"] != vault_id:
        raise BackupRefused("bundled vault belongs to a different vault id")
    if target_exists:
        try:
            with open(target_vault_path, "rb") as f:
                target_header = vault_header(f.read())
        except Exception as exc:
            raise BackupRefused(
                f"existing target vault is unreadable: {exc}") from exc
        if target_header["vault_id"] != vault_id:
            raise BackupRefused(
                "the target already holds a DIFFERENT vault — "
                "refusing to replace it with this package")

    newest = _read_newest_seen(target_vault_path)
    if int(package["created_at"]) < newest and not allow_older:
        raise BackupRefused(
            "this package is older than the newest backup already "
            "seen for this vault — refusing a possible rollback "
            "(pass --allow-older if you mean to restore it)")

    # -- install. Snapshot the outgoing vault; quarantine sidecars
    # that the package does not replace (never delete evidence).
    snapshot = None
    if target_exists:
        snapshot = f"{target_vault_path}.pre-import-{_now()}"
        with open(target_vault_path, "rb") as f:
            _atomic_write(snapshot, f.read())
    _atomic_write(target_vault_path, vault_bytes)
    for name, suffix in (("audit", ".audit.jsonl"),
                         ("anchor", ".audit-anchor.json")):
        raw = content.get(name)
        path = target_vault_path + suffix
        if raw:
            incoming = _b64d(raw)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    current = f.read()
                if current != incoming:
                    # Preserve the outgoing sidecar as evidence;
                    # the package's copy becomes the live one.
                    quarantine = f"{path}.suspect-{_now()}"
                    _atomic_write(quarantine, current)
            _atomic_write(path, incoming)
        elif os.path.exists(path):
            quarantine = f"{path}.suspect-{_now()}"
            os.replace(path, quarantine)
            os.chmod(quarantine, 0o600)
    # Imported ancestry is unknown to the sync layer until the
    # human re-syncs deliberately.
    try:
        os.unlink(target_vault_path + ".sync.json")
    except OSError:
        pass
    _note_seen(target_vault_path, package["created_at"])
    return {"result": "imported", "via": via, "vault_id": vault_id,
            "source_fingerprint": fingerprint,
            "snapshot_of_previous": snapshot}
