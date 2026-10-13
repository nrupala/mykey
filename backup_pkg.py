# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Encrypted backup packages — portable, multi-recipient.

A backup package (``.mykeybak``) carries the whole vault bundle
(vault bytes + audit log + anchor) encrypted under a random
content key. The content key is wrapped for:

* every **enrolled, non-revoked device** in the vault registry
  (sealed to its X25519 public key),
* every **paired target** holding the ``export`` scope (package
  format v2 — see pairings.py), sealed to the target's X25519
  public key, and
* a **recovery recipient** whose X25519 keypair is re-derived
  from the user's BIP-39 recovery phrase (per-vault Argon2id —
  see recovery.recovery_backup_keypair), so a replacement device
  can recover after total device loss.

**Two-factor recovery (format v2, the default).** In a v2
package the recovery slot is wrapped TWICE: the content key is
sealed to the phrase-derived key as before, and that sealed blob
is then encrypted under a second key derived from a **backup
code** — 8 words (88 bits) generated at export, shown to the user
exactly once, and never stored in the package, the vault, or any
file. Opening a v2 package outside the app therefore needs BOTH
factors: the recovery phrase AND the backup code. Either one
alone fails; a wrong code fails closed. This is deliberate: a
photograph of the phrase, or a backup code found on its own,
opens nothing. Keep the code somewhere different from the phrase.

**Legacy v1 packages** keep their original semantics — the
recovery slot opens with the phrase alone — and are labelled
LEGACY wherever they are inspected or imported, so the weaker
guarantee is never mistaken for the v2 one. New exports are v2
unless v1 is explicitly requested.

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
unrevoked; a pairing target the supplied registry shows revoked;
a caller who is not a recipient (no device key, no pairing key,
no valid recovery phrase + backup code); and a package older
than the newest one seen for this vault, unless the human
explicitly allows older.

Inherent limit, stated plainly: revoking a device or a pairing
cannot make packages exported BEFORE the revocation undecryptable
to a private key that device or target retained. Revocation
governs new packages and signature trust, never copies already
out the door.
"""

import hashlib
import json
import os
import time
import uuid

from argon2 import low_level
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
from pairings import active_pairings, pairing_fingerprint
from recovery import (
    generate_backup_code,
    normalize_backup_code,
    recovery_backup_keypair,
)
from vaultsync import _atomic_write, _strict_loads, vault_header

_FORMAT = "MKBAK"
_VERSION = 2
_LEGACY_VERSION = 1
_SUPPORTED_VERSIONS = (1, 2)
_WRAP_INFO = {1: b"mkbak-wrap-v1", 2: b"mkbak-wrap-v2"}
# The backup code gets its own memory-hard derivation, so guessing
# codes against a captured package is expensive per guess even
# before the phrase factor is considered.
_CODE_KDF_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
_CODE_HKDF_INFO = b"mkbak-v2:backup-code"


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


def _wrap_aad(package_id, vault_id, recipient_id, version=1):
    return f"mkbak-wrap:v{version}:{package_id}:{vault_id}:{recipient_id}".encode()


def _content_aad(vault_id, version):
    return f"mkbak:v{version}:{vault_id}".encode()


def _code_aad(package_id, vault_id):
    return f"mkbak-code:v2:{package_id}:{vault_id}".encode()


def _code_wrap_key(code: str, salt: bytes, params: dict) -> bytes:
    """Derive the backup-code wrap key: Argon2id over the code,
    then HKDF with a domain-separation label. The code alone
    derives this key but nothing else — it only peels the outer
    layer of the v2 recovery slot."""
    raw = low_level.hash_secret_raw(
        secret=code.encode(), salt=salt,
        time_cost=params.get("time_cost", _CODE_KDF_PARAMS["time_cost"]),
        memory_cost=params.get("memory_cost",
                                _CODE_KDF_PARAMS["memory_cost"]),
        parallelism=params.get("parallelism",
                               _CODE_KDF_PARAMS["parallelism"]),
        hash_len=32, type=low_level.Type.ID)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_CODE_HKDF_INFO).derive(raw)


# ---------------------------------------------------------------------------
# recipient sealing (ephemeral ECDH -> HKDF -> AES-256-GCM), bound by AAD
# ---------------------------------------------------------------------------

def _seal_to_pub(pub_raw: bytes, plaintext: bytes, aad: bytes,
                 version: int = 1) -> dict:
    pub = X25519PublicKey.from_public_bytes(pub_raw)
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(pub)
    if shared == b"\x00" * 32:
        raise BackupError("recipient key produced a null shared secret")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_WRAP_INFO[version]).derive(shared)
    blob = _enc(key, plaintext, aad)
    blob["ephemeral"] = _b64e(
        eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return blob


def _open_sealed(priv_raw: bytes, blob: dict, aad: bytes,
                 version: int = 1) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(priv_raw)
    eph_pub = X25519PublicKey.from_public_bytes(_b64d(blob["ephemeral"]))
    shared = priv.exchange(eph_pub)
    if shared == b"\x00" * 32:
        raise BackupRefused("sealed key produced a null shared secret")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_WRAP_INFO[version]).derive(shared)
    return _dec(key, blob, aad)


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

def export_package(vault: MyKey, identity, out_path=None,
                   backup_code=None, version=_VERSION):
    """Build a backup package from a human-unlocked vault session.

    Returns ``(package, backup_code)``. For a v2 package the backup
    code is the recovery slot's second factor: the caller MUST show
    it to the user once and must never store it (it is not written
    to *out_path* or anywhere else). For a legacy v1 package the
    code is None. The exporting device must itself be enrolled (so
    its owner can always open their own backups alongside the
    recovery path).
    """
    if not isinstance(vault, MyKey):
        raise PermissionError("agent sessions cannot export backups")
    vault._require_unlocked()
    vault._require_human("export a backup package")
    if version not in _SUPPORTED_VERSIONS:
        raise BackupError(f"unsupported package version: {version!r}")
    code = None
    if version == 2:
        code = (normalize_backup_code(backup_code) if backup_code
                else generate_backup_code())
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
    vault_id = header["vault_id"]
    content = {"vault_id": vault_id, "exported_at": _now(),
               "vault": _b64e(vault_bytes)}
    for name, suffix in (("audit", ".audit.jsonl"),
                         ("anchor", ".audit-anchor.json")):
        path = vault_path + suffix
        content[name] = _b64e(open(path, "rb").read()) \
            if os.path.exists(path) else None
    package_id = uuid.uuid4().hex
    content_key = os.urandom(32)
    content_blob = _enc(content_key, _canonical(content),
                        _content_aad(vault_id, version))
    recipients = []
    for device_id, rec in sorted(devices.items()):
        recipients.append({
            "type": "device",
            "device_id": device_id,
            "fingerprint": rec.get("fingerprint", ""),
            "wrapped_key": _seal_to_pub(
                _b64d(rec["x25519_pub"]), content_key,
                _wrap_aad(package_id, vault_id, device_id, version),
                version),
        })
    if version == 2:
        # Paired export targets: enabled, unexpired, holding the
        # export scope. Anything else gets NO slot — pairing is the
        # gate, not a courtesy copy.
        for target_id, rec in sorted(
                active_pairings(vault, scope="export").items()):
            recipients.append({
                "type": "pairing",
                "target_id": target_id,
                "fingerprint": rec.get("fingerprint", ""),
                "wrapped_key": _seal_to_pub(
                    _b64d(rec["x25519_pub"]), content_key,
                    _wrap_aad(package_id, vault_id, target_id, version),
                    version),
            })
    if version == 1:
        recipients.append({
            "type": "recovery",
            "fingerprint": _recovery_fingerprint(
                vault._backup_recovery_pub),
            "wrapped_key": _seal_to_pub(
                vault._backup_recovery_pub, content_key,
                _wrap_aad(package_id, vault_id, "recovery", 1), 1),
        })
    else:
        sealed = _seal_to_pub(
            vault._backup_recovery_pub, content_key,
            _wrap_aad(package_id, vault_id, "recovery", 2), 2)
        salt = os.urandom(16)
        code_key = _code_wrap_key(code, salt, _CODE_KDF_PARAMS)
        recipients.append({
            "type": "recovery",
            "version": 2,
            "fingerprint": _recovery_fingerprint(
                vault._backup_recovery_pub),
            "code_kdf": {"salt": _b64e(salt), **_CODE_KDF_PARAMS},
            "wrapped_key": _enc(
                code_key, _canonical(sealed),
                _code_aad(package_id, vault_id)),
        })
    package = {
        "format": _FORMAT,
        "version": version,
        "package_id": package_id,
        "created_at": _now(),
        "source": {
            "device_id": identity.device_id,
            "fingerprint": identity.fingerprint,
            "x25519_pub": _b64e(identity.x_pub),
            "ed25519_pub": _b64e(identity.e_pub),
            "vault_id": vault_id,
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
    return package, code


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
    if package.get("version") not in _SUPPORTED_VERSIONS:
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
    version = package.get("version")
    return {
        "package_id": package.get("package_id"),
        "version": version,
        "legacy": version == _LEGACY_VERSION,
        "recovery_two_factor": version == 2,
        "created_at": package.get("created_at"),
        "vault_id": (package.get("source") or {}).get("vault_id"),
        "source_device_id": (package.get("source") or {}).get("device_id"),
        "source_fingerprint": fingerprint,
        "fingerprint_matches_header": stated == fingerprint,
        "signature_valid": sig_ok,
        "recipients": [
            {"type": r.get("type"),
             "device_id": r.get("device_id"),
             "target_id": r.get("target_id"),
             "fingerprint": r.get("fingerprint")}
            for r in package.get("recipients") or []],
    }


def import_package(path, target_vault_path, identity=None,
                   recovery_phrase=None, backup_code=None,
                   pairing_priv=None, expect_fingerprint=None,
                   allow_older=False, registry=None,
                   pairing_registry=None):
    """Import a backup package as the vault at *target_vault_path*.

    *registry* is the target vault's device registry (from a
    human-unlocked session). When a vault file already exists at
    the target, registry is REQUIRED — the source device must be
    shown enrolled and unrevoked there. On a fresh target,
    *expect_fingerprint* (obtained independently of the package)
    is required instead.

    Opening paths: an enrolled device's key (*identity*), a paired
    target's key (*pairing_priv*, raw X25519 private bytes), or —
    outside the app — the recovery path: the BIP-39 phrase, plus
    the backup code for v2 packages (two-factor). *pairing_registry*,
    when supplied, refuses a pairing target it shows as revoked.
    """
    package = _load_package(path)
    version = package["version"]
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

    # -- unwrap the content key: device key, else pairing key,
    # else the recovery path (phrase, + backup code for v2).
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
                    _wrap_aad(package_id, vault_id,
                              identity.device_id, version), version)
                via = f"device:{identity.device_id}"
            except Exception:
                content_key = None
            break
    if content_key is None and pairing_priv is not None:
        pub_raw = X25519PrivateKey.from_private_bytes(pairing_priv) \
            .public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        my_fingerprint = pairing_fingerprint(pub_raw)
        for recipient in package.get("recipients") or []:
            if recipient.get("type") != "pairing":
                continue
            if recipient.get("fingerprint") != my_fingerprint:
                continue
            target_id = recipient.get("target_id")
            if pairing_registry is not None:
                record = pairing_registry.get(target_id or "")
                if record is not None and record.get("revoked_at"):
                    raise BackupRefused(
                        "this pairing target has been REVOKED in "
                        "the target vault — refusing to open the "
                        "package with its key")
            try:
                content_key = _open_sealed(
                    pairing_priv, recipient["wrapped_key"],
                    _wrap_aad(package_id, vault_id, target_id, version),
                    version)
                via = f"pairing:{target_id}"
            except Exception as exc:
                raise BackupRefused(
                    "pairing unwrap failed — package is damaged") from exc
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
            if version == _LEGACY_VERSION:
                try:
                    content_key = _open_sealed(
                        raw, recipient["wrapped_key"],
                        _wrap_aad(package_id, vault_id, "recovery", 1), 1)
                    via = "recovery"
                except Exception as exc:
                    raise BackupRefused(
                        "recovery unwrap failed — package is damaged"
                    ) from exc
                break
            # v2: the phrase alone is NOT enough — peel the
            # backup-code layer first, then the phrase seal.
            if not backup_code:
                raise BackupRefused(
                    "this backup uses two-factor recovery: it needs "
                    "the backup code as well as the recovery phrase. "
                    "The code was shown once when the backup was made.")
            try:
                code = normalize_backup_code(backup_code)
            except ValueError as exc:
                raise BackupRefused(
                    f"the backup code is not usable: {exc}") from exc
            kdf = recipient.get("code_kdf") or {}
            try:
                code_key = _code_wrap_key(
                    code, _b64d(kdf["salt"]),
                    {"time_cost": kdf.get("time_cost"),
                     "memory_cost": kdf.get("memory_cost"),
                     "parallelism": kdf.get("parallelism")})
                sealed = json.loads(_dec(
                    code_key, recipient["wrapped_key"],
                    _code_aad(package_id, vault_id)))
            except Exception as exc:
                raise BackupRefused(
                    "the backup code did not open this backup — "
                    "check the words and try again") from exc
            try:
                content_key = _open_sealed(
                    raw, sealed,
                    _wrap_aad(package_id, vault_id, "recovery", 2), 2)
                via = "recovery"
            except Exception as exc:
                raise BackupRefused(
                    "recovery unwrap failed — package is damaged") from exc
            break
    if content_key is None:
        raise BackupRefused(
            "not a recipient of this package: no device key, pairing "
            "key, or recovery phrase + backup code opens it")

    try:
        content = json.loads(_dec(
            content_key, package["content"],
            _content_aad(vault_id, version)))
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
            "package_version": version,
            "legacy": version == _LEGACY_VERSION,
            "source_fingerprint": fingerprint,
            "snapshot_of_previous": snapshot}
