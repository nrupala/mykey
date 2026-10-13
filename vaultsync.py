# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""User-cloud sync (Phase 3A) — ciphertext bundles over a folder.

Sync runs over the USER's own cloud: the v1 provider is any local
or synced folder (Drive / iCloud / OneDrive / Dropbox / Syncthing /
NAS folders all work through their clients). No OAuth cloud APIs,
no server of ours. Everything the provider ever holds is ciphertext:
the vault file is envelope-encrypted, and this module never
decrypts anything — sync operations need no master password and
read only the vault's plaintext header (format, version, vault id).

The synced unit is a **bundle**: one content-addressed JSON object
holding the vault bytes, the audit log bytes and the audit anchor
bytes (each component hash-bound, presence/absence explicit). A
**manifest** in the provider root is an append-only commit chain:
each commit names a bundle hash, its parent bundle hash, the
pushing device and a timestamp, and is **signed with the pushing
device's Ed25519 key**. Devices pin signer keys from the vault's
device registry at human unlock (trust-on-first-use before that,
with conflicts alarmed — see SYNC_BACKUP.md for exactly what is
and is not proven).

Safety rules enforced here:

* A device accepts a remote head only if its own last accepted
  bundle is an ancestor of that head in the signed chain (or it
  has accepted nothing yet). Rollback and forked chains surface as
  conflicts, never silent overwrites.
* If local and remote both moved since the last accepted state,
  sync refuses: both copies are preserved and the human resolves
  (restore / force). Force operations require a human-unlocked
  session at the CLI; a manifest ``kind`` label proves nothing.
* Bundles are written before the manifest commit that references
  them, and every pull verifies component hashes against the
  manifest — a corrupted or incomplete synced copy is refused
  without touching local files.
* Snapshots: the provider retains the bundles of the last N
  commits; every local overwrite first snapshots the local bundle
  beside the vault. Restoring a snapshot is a local act; the next
  publish needs an explicit human force.
"""

import base64
import hashlib
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agents import vault_lock
from devices import read_revocations
from mykey import MyKeyError, _b64d, _b64e

_BUNDLE_FORMAT = "MKBND"
_MANIFEST_FORMAT = "MKMFT"
_STATE_FORMAT = "MKSYN"
_BUNDLE_VERSION = 1
_RETENTION_COMMITS = 10
_LOCAL_SNAPSHOTS_KEPT = 10
_COMPONENTS = ("vault", "audit", "anchor")


class SyncError(MyKeyError):
    """Sync operation failed safely (nothing was overwritten)."""


class SyncConflict(SyncError):
    """Local and remote state diverged; a human must resolve it."""


class SyncCorrupt(SyncError):
    """Synced data failed integrity checks; local files untouched."""


def _now() -> int:
    return int(time.time())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_loads(raw: bytes, what: str):
    """JSON parse that rejects duplicate keys (fleet review, F13)."""
    def no_dupes(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise SyncCorrupt(f"{what}: duplicate key {key!r}")
            obj[key] = value
        return obj
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
    except SyncCorrupt:
        raise
    except Exception as exc:
        raise SyncCorrupt(f"{what}: not valid JSON: {exc}") from exc


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _atomic_write(path, data: bytes):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# provider
# ---------------------------------------------------------------------------

class FolderProvider:
    """A folder on a local filesystem (possibly cloud-synced)."""

    def __init__(self, root):
        self.root = os.path.abspath(root)

    def _path(self, name):
        path = os.path.join(self.root, name)
        if os.path.commonpath([self.root, os.path.abspath(path)]) != self.root:
            raise SyncError(f"provider path escapes its root: {name!r}")
        return path

    def read(self, name):
        path = self._path(name)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def write_atomic(self, name, data: bytes):
        path = self._path(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _atomic_write(path, data)

    def delete(self, name):
        try:
            os.unlink(self._path(name))
        except OSError:
            pass

    def list_names(self, prefix=""):
        out = []
        base = self._path(prefix) if prefix else self.root
        if not os.path.isdir(base):
            return out
        for entry in sorted(os.listdir(base)):
            out.append(f"{prefix}/{entry}" if prefix else entry)
        return out


# ---------------------------------------------------------------------------
# bundles
# ---------------------------------------------------------------------------

def vault_header(vault_bytes: bytes) -> dict:
    """Parse ONLY the plaintext header of a vault file (no keys)."""
    try:
        data = json.loads(vault_bytes.decode("utf-8"))
    except Exception as exc:
        raise SyncCorrupt(f"vault file is not readable JSON: {exc}") from exc
    if data.get("format") != "MKVLT":
        raise SyncCorrupt("not a vault file (bad format token)")
    if data.get("version") != 3:
        raise SyncError(
            "sync supports Vault v3 files only — a human must unlock "
            "this vault once to migrate it")
    if not data.get("vault_id"):
        raise SyncCorrupt("vault file has no vault id")
    return data


def bundle_hash_of(components: dict) -> str:
    """Bundle identity: hashes of ALL components, absence explicit."""
    h = hashlib.sha256(b"mkbnd:v1")
    for name in _COMPONENTS:
        comp = components.get(name)
        h.update(b"\x00" + name.encode() + b"\x00")
        h.update((comp["sha256"] if comp else "-").encode())
    return h.hexdigest()


def build_bundle(vault_path: str) -> dict:
    """Assemble the bundle for the local vault + its sidecars."""
    if not os.path.exists(vault_path):
        raise SyncError(f"no vault file at {vault_path}")
    with open(vault_path, "rb") as f:
        vault_bytes = f.read()
    header = vault_header(vault_bytes)
    components = {"vault": {"sha256": _sha(vault_bytes),
                            "data": _b64e(vault_bytes)}}
    for name, suffix in (("audit", ".audit.jsonl"),
                         ("anchor", ".audit-anchor.json")):
        path = vault_path + suffix
        if os.path.exists(path):
            with open(path, "rb") as f:
                raw = f.read()
            components[name] = {"sha256": _sha(raw), "data": _b64e(raw)}
        else:
            components[name] = None
    bundle = {
        "format": _BUNDLE_FORMAT,
        "version": _BUNDLE_VERSION,
        "vault_id": header["vault_id"],
        "components": components,
    }
    bundle["bundle_hash"] = bundle_hash_of(components)
    return bundle


def verify_bundle(bundle) -> str:
    """Check a bundle object's internal consistency; return its hash."""
    if not isinstance(bundle, dict) or bundle.get("format") != _BUNDLE_FORMAT \
            or bundle.get("version") != _BUNDLE_VERSION:
        raise SyncCorrupt("bundle has an unrecognized format or version")
    components = bundle.get("components") or {}
    for name in _COMPONENTS:
        comp = components.get(name)
        if comp is None:
            continue
        try:
            raw = _b64d(comp["data"])
        except Exception as exc:
            raise SyncCorrupt(f"bundle component {name} is malformed") from exc
        if _sha(raw) != comp.get("sha256"):
            raise SyncCorrupt(
                f"bundle component {name} does not match its hash — "
                "the synced copy is corrupted or was tampered with")
    if components.get("vault") is None:
        raise SyncCorrupt("bundle has no vault component")
    digest = bundle_hash_of(components)
    if bundle.get("bundle_hash") != digest:
        raise SyncCorrupt("bundle hash mismatch — corrupted or tampered")
    vault_header(_b64d(components["vault"]["data"]))
    if vault_header(_b64d(components["vault"]["data"]))["vault_id"] \
            != bundle.get("vault_id"):
        raise SyncCorrupt("bundle vault id does not match its vault file")
    return digest


def bundle_component(bundle, name):
    comp = (bundle.get("components") or {}).get(name)
    return _b64d(comp["data"]) if comp else None


def audit_relation(local: bytes, remote: bytes):
    """Prefix relation between two audit chains (line-wise).

    Returns 'equal', 'local-extends', 'remote-extends' or 'forked'.
    This is a STRUCTURAL comparison of hash-chained files; the
    cryptographic verification (MACs, seal, anchor) happens at the
    next human unlock, which remains the gate.
    """
    if local == remote:
        return "equal"
    local_lines = local.split(b"\n")
    remote_lines = remote.split(b"\n")
    n = min(len(local_lines), len(remote_lines))
    for i in range(n):
        if local_lines[i] != remote_lines[i]:
            return "forked"
    return "local-extends" if len(local_lines) > len(remote_lines) \
        else "remote-extends"


# ---------------------------------------------------------------------------
# manifest (signed commit chain)
# ---------------------------------------------------------------------------

def _commit_body(commit) -> dict:
    return {k: v for k, v in commit.items() if k != "sig"}


def sign_commit(identity, generation, bundle_hash, parent, kind):
    commit = {
        "generation": int(generation),
        "bundle_hash": bundle_hash,
        "parent": parent or "",
        "device_id": identity.device_id,
        "signer_pub": _b64e(identity.e_pub),
        "ts": _now(),
        "kind": kind,
    }
    commit["sig"] = _b64e(identity.sign(_canonical(commit)))
    return commit


def load_manifest(provider):
    raw = provider.read("manifest.json")
    if raw is None:
        return None
    manifest = _strict_loads(raw, "sync manifest")
    if not isinstance(manifest, dict) \
            or manifest.get("format") != _MANIFEST_FORMAT \
            or manifest.get("version") != 1:
        raise SyncCorrupt("sync manifest has an unrecognized format")
    if not isinstance(manifest.get("commits"), list):
        raise SyncCorrupt("sync manifest has no commit list")
    return manifest


def save_manifest(provider, manifest):
    provider.write_atomic("manifest.json",
                          json.dumps(manifest, indent=1).encode())


def check_chain(manifest, known_devices, revoked):
    """Verify links + signatures of the commit chain.

    Returns (tofu, error): *tofu* maps device ids whose signatures
    verified against keys carried nowhere trusted yet (first
    contact) to their public keys; *error* is a string when the
    chain is broken, mis-signed by a PINNED key, signed after
    revocation, or otherwise unacceptable.
    """
    tofu = {}
    prev_hash = ""
    for i, commit in enumerate(manifest.get("commits") or []):
        if commit.get("generation") != i + 1:
            return tofu, f"manifest generation gap at commit {i + 1}"
        if (commit.get("parent") or "") != prev_hash:
            return tofu, f"manifest commit {i + 1} does not link to its parent"
        device_id = commit.get("device_id") or ""
        pin = known_devices.get(device_id)
        carried = commit.get("signer_pub") or ""
        if pin is not None and pin.get("ed25519_pub"):
            # A registry pin is authoritative: the carried key must
            # be the pinned key, and the signature must verify under
            # it. A mismatch is exactly the TOFU-conflict alarm.
            if carried != pin["ed25519_pub"]:
                return tofu, (f"manifest commit {i + 1}: signer key for "
                              f"device {device_id} does not match the "
                              "key pinned from the vault registry")
            pub_raw = _b64d(pin["ed25519_pub"])
        elif device_id in tofu:
            if carried != tofu[device_id]:
                return tofu, (f"manifest commit {i + 1}: device "
                              f"{device_id} changed its signer key "
                              "mid-chain")
            pub_raw = _b64d(tofu[device_id])
        else:
            # First contact: TOFU. The signature is verified against
            # the key the commit carries (self-consistent only);
            # the caller pins it, marked unverified, and a later
            # registry pin overrides it with an alarm on conflict.
            if not carried:
                return tofu, (f"manifest commit {i + 1} carries no "
                              "signer key")
            tofu[device_id] = carried
            pub_raw = _b64d(carried)
        try:
            Ed25519PublicKey.from_public_bytes(pub_raw).verify(
                _b64d(commit.get("sig") or ""),
                _canonical(_commit_body(commit)))
        except Exception:
            return tofu, (f"manifest commit {i + 1} has an invalid "
                          f"signature for device {device_id}")
        rec = revoked.get(device_id)
        revoked_at = int(rec.get("revoked_at") or 0) if rec else 0
        if pin is not None and pin.get("revoked_at"):
            revoked_at = max(revoked_at, int(pin["revoked_at"]))
        if revoked_at and int(commit.get("ts") or 0) > revoked_at:
            return tofu, (f"manifest commit {i + 1} was signed by device "
                          f"{device_id} AFTER it was revoked")
        prev_hash = commit.get("bundle_hash") or ""
    return tofu, ""


# ---------------------------------------------------------------------------
# local sync state
# ---------------------------------------------------------------------------

def state_path_for(vault_path: str) -> str:
    return vault_path + ".sync.json"


def load_state(vault_path: str):
    path = state_path_for(vault_path)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        state = _strict_loads(f.read(), "sync state")
    if state.get("format") != _STATE_FORMAT:
        raise SyncCorrupt("sync state has an unrecognized format")
    return state


def save_state(vault_path: str, state: dict):
    state["format"] = _STATE_FORMAT
    state["version"] = 1
    state["updated_at"] = _now()
    _atomic_write(state_path_for(vault_path),
                  json.dumps(state, indent=1).encode())


def refresh_pins(vault, state: dict):
    """Pin signer keys from the (unlocked) vault's device registry
    into the sync state, including revocation marks. This is how a
    device stops trusting TOFU pins and starts verifying commits
    against the human-managed registry."""
    known = state.setdefault("known_devices", {})
    for device_id, rec in vault._devices.items():
        known[device_id] = {
            "ed25519_pub": rec.get("ed25519_pub", ""),
            "fingerprint": rec.get("fingerprint", ""),
            "source": "registry",
            "revoked_at": rec.get("revoked_at"),
        }
    return state


def refresh_pairing_pins(vault, state: dict):
    """Pin pairing records from the (unlocked) vault's pairing
    registry into the sync state. Sync itself never unlocks the
    vault, so a folder bound to a pairing target is gated by these
    pins: scopes, expiry, enabled and revocation state as of the
    last human unlock — the same trust pattern as signer pins."""
    pins = state.setdefault("pairing_pins", {})
    for target_id, rec in vault._pairings.items():
        pins[target_id] = {
            "fingerprint": rec.get("fingerprint", ""),
            "type": rec.get("type", ""),
            "scopes": list(rec.get("scopes") or []),
            "expires_at": rec.get("expires_at"),
            "enabled": bool(rec.get("enabled", False)),
            "revoked_at": rec.get("revoked_at"),
            "source": "registry",
        }
    return state


# ---------------------------------------------------------------------------
# the sync engine
# ---------------------------------------------------------------------------

class VaultSync:
    def __init__(self, vault_path):
        self.vault_path = vault_path

    # -- pairing gate --------------------------------------------------------
    def _require_pairing(self, state, op):
        """Gate a push/pull on the folder's paired target, if any.

        A folder with no bound target keeps the pre-pairing
        behaviour. A bound folder proceeds only while its target's
        pin (refreshed from the vault registry at human unlock)
        shows the pairing enabled, unrevoked, unexpired, and
        holding the scope this operation needs."""
        target_id = (state or {}).get("pairing_target")
        if not target_id:
            return
        pin = (state.get("pairing_pins") or {}).get(target_id)
        if pin is None:
            raise SyncError(
                f"this sync folder is bound to pairing target "
                f"{target_id[:12]}… but no pairing pin is recorded "
                "for it — unlock the vault once and run sync-pin so "
                "the pairing comes from the vault registry, not "
                "from the folder")
        if pin.get("revoked_at"):
            raise SyncError(
                f"pairing target {target_id[:12]}… has been REVOKED "
                "— sync to this folder is stopped")
        if not pin.get("enabled", False):
            raise SyncError(
                f"pairing target {target_id[:12]}… is disabled — "
                "sync to this folder is stopped")
        expires = pin.get("expires_at")
        if expires and _now() > int(expires):
            raise SyncError(
                f"pairing target {target_id[:12]}… has EXPIRED — "
                "re-enroll it in a human session to resume sync")
        if op not in (pin.get("scopes") or []):
            raise SyncError(
                f"pairing target {target_id[:12]}… does not hold "
                f"the {op!r} scope — sync {op} is not allowed")

    # -- configuration -----------------------------------------------------
    def configure(self, root, identity, device_keys_path=None,
                  target_id=None):
        vault_dir = os.path.dirname(os.path.abspath(self.vault_path))
        root_abs = os.path.abspath(root)
        if root_abs == vault_dir:
            raise SyncError(
                "the sync folder must not be the vault's own folder")
        keys_path = device_keys_path or identity_path_hint()
        if keys_path and os.path.commonpath(
                [root_abs, os.path.abspath(keys_path)]) == root_abs:
            raise SyncError(
                "the device key file must not live inside the sync "
                "folder — private keys never sync")
        provider = FolderProvider(root_abs)
        manifest = load_manifest(provider)
        vault_id = None
        if os.path.exists(self.vault_path):
            with open(self.vault_path, "rb") as f:
                vault_id = vault_header(f.read())["vault_id"]
        if manifest is not None:
            if vault_id and manifest.get("vault_id") != vault_id:
                raise SyncConflict(
                    "the sync folder already serves a different vault")
            vault_id = manifest.get("vault_id") or vault_id
        state = load_state(self.vault_path) or {}
        state.update({
            "provider": {"type": "folder", "root": root_abs},
            "vault_id": vault_id,
            "accepted_generation": state.get("accepted_generation", 0),
            "accepted_bundle_hash": state.get("accepted_bundle_hash", ""),
            "last_synced_vault_hash": state.get("last_synced_vault_hash"),
        })
        if target_id is not None:
            # Bind (or, with an empty value, unbind) this folder to
            # a pairing target. The binding only takes effect once
            # the target's pin has been refreshed from the registry
            # at a human unlock — see _require_pairing.
            state["pairing_target"] = target_id or None
        save_state(self.vault_path, state)
        return state

    def _provider(self, state):
        provider_cfg = (state or {}).get("provider") or {}
        if provider_cfg.get("type") != "folder" or not provider_cfg.get("root"):
            raise SyncError("sync is not configured — run sync-configure")
        return FolderProvider(provider_cfg["root"])

    def _checked_manifest(self, state, provider, allow_tofu):
        """Load + chain-check the manifest; returns (manifest, head).

        Raises on broken chains and bad pinned signatures. Unknown
        signers are refused once this device holds an accepted
        checkpoint, unless allow_tofu (first contact) — in which
        case their keys are pinned as TOFU by the caller on success.
        """
        self._tofu = {}
        manifest = load_manifest(provider)
        if manifest is None:
            return None, None
        if state.get("vault_id") and \
                manifest.get("vault_id") != state["vault_id"]:
            raise SyncConflict("sync folder serves a different vault")
        revoked = read_revocations(self.vault_path)
        tofu, error = check_chain(
            manifest, state.get("known_devices") or {}, revoked)
        self._tofu = tofu
        if error:
            raise SyncCorrupt(f"sync manifest rejected: {error}")
        unknown = [d for d, pub in tofu.items()]
        if unknown and state.get("accepted_bundle_hash") and not allow_tofu:
            raise SyncError(
                "manifest contains commits from unpinned device(s) "
                f"{unknown} — unlock once and run sync-pin so signer "
                "keys come from the vault registry, not from the folder")
        commits = manifest.get("commits") or []
        head = commits[-1] if commits else None
        return manifest, head

    def _require_ancestry(self, state, manifest):
        """The accepted bundle must be an ancestor of the head."""
        accepted = state.get("accepted_bundle_hash") or ""
        if not accepted:
            return
        hashes = [c.get("bundle_hash") for c in manifest.get("commits") or []]
        if accepted not in hashes:
            raise SyncConflict(
                "the synced history no longer contains the state this "
                "device last accepted — it was rolled back or forked. "
                "Nothing was overwritten; resolve by inspecting both "
                "copies, then restore or force from the one you trust")
        if int(state.get("accepted_generation") or 0) > len(hashes):
            raise SyncConflict("accepted generation is ahead of the chain")

    def _pin_tofu(self, state, manifest):
        """Record first-contact signer keys (marked TOFU/unverified;
        a registry pin from a human unlock replaces them)."""
        known = state.setdefault("known_devices", {})
        for device_id, pub in (getattr(self, "_tofu", None) or {}).items():
            if device_id and device_id not in known:
                known[device_id] = {"ed25519_pub": pub,
                                    "fingerprint": "",
                                    "source": "tofu",
                                    "revoked_at": None}

    # -- status ------------------------------------------------------------
    def status(self):
        state = load_state(self.vault_path)
        if state is None:
            return {"state": "unconfigured"}
        provider = self._provider(state)
        local_bundle = None
        if os.path.exists(self.vault_path):
            local_bundle = build_bundle(self.vault_path)
        try:
            manifest, head = self._checked_manifest(
                state, provider, allow_tofu=True)
        except SyncError as exc:
            return {"state": "error", "detail": str(exc)}
        out = {
            "provider_root": state["provider"]["root"],
            "vault_id": state.get("vault_id"),
            "accepted_generation":
                int(state.get("accepted_generation") or 0),
            "remote_generation": len(manifest["commits"]) if manifest else 0,
            "local_bundle_hash":
                local_bundle["bundle_hash"] if local_bundle else None,
            "remote_bundle_hash": head["bundle_hash"] if head else None,
        }
        target_id = state.get("pairing_target")
        out["pairing_target"] = target_id
        if target_id:
            pin = (state.get("pairing_pins") or {}).get(target_id)
            if pin is None:
                out["pairing_state"] = "unpinned — unlock + sync-pin"
            elif pin.get("revoked_at"):
                out["pairing_state"] = "revoked"
            elif not pin.get("enabled", False):
                out["pairing_state"] = "disabled"
            elif pin.get("expires_at") and \
                    _now() > int(pin["expires_at"]):
                out["pairing_state"] = "expired"
            else:
                out["pairing_state"] = "active"
        if manifest is None or head is None:
            out["state"] = "no-remote"
            return out
        try:
            self._require_ancestry(state, manifest)
        except SyncConflict as exc:
            out["state"] = "diverged"
            out["detail"] = str(exc)
            return out
        if local_bundle is None:
            out["state"] = "no-local"
            return out
        local_hash = local_bundle["bundle_hash"]
        head_hash = head["bundle_hash"]
        accepted = state.get("accepted_bundle_hash") or ""
        if local_hash == head_hash:
            out["state"] = "in-sync"
        elif local_hash == accepted and head_hash != accepted:
            out["state"] = "behind"
        elif head_hash == accepted and local_hash != accepted:
            out["state"] = "ahead"
        else:
            out["state"] = "diverged"
            out["detail"] = ("both this device and the synced copy "
                             "changed since the last accepted state")
        return out

    # -- snapshot helpers ----------------------------------------------------
    def _snapshot_local(self):
        """Preserve the current local bundle beside the vault."""
        if not os.path.exists(self.vault_path):
            return None
        bundle = build_bundle(self.vault_path)
        snap_dir = self.vault_path + ".snapshots"
        os.makedirs(snap_dir, exist_ok=True)
        name = f"{_now()}-{bundle['components']['vault']['sha256'][:12]}.json"
        path = os.path.join(snap_dir, name)
        _atomic_write(path, json.dumps(bundle).encode())
        snaps = sorted(os.listdir(snap_dir))
        for old in snaps[:-_LOCAL_SNAPSHOTS_KEPT]:
            try:
                os.unlink(os.path.join(snap_dir, old))
            except OSError:
                pass
        return path

    def list_snapshots(self):
        state = load_state(self.vault_path)
        out = {"provider": [], "local": []}
        if state is not None:
            provider = self._provider(state)
            manifest = load_manifest(provider)
            if manifest:
                out["provider"] = [
                    {"bundle_hash": c["bundle_hash"],
                     "generation": c["generation"], "ts": c["ts"],
                     "device_id": c["device_id"], "kind": c["kind"]}
                    for c in manifest.get("commits") or []]
        snap_dir = self.vault_path + ".snapshots"
        if os.path.isdir(snap_dir):
            out["local"] = sorted(os.listdir(snap_dir))
        return out

    def _fetch_bundle(self, provider, bundle_hash):
        raw = provider.read(f"bundles/{bundle_hash}.json")
        if raw is None:
            raise SyncCorrupt(
                f"synced bundle {bundle_hash[:12]}… is missing from the "
                "folder (incomplete sync — wait for the folder to "
                "finish syncing, then retry)")
        bundle = _strict_loads(raw, "synced bundle")
        if verify_bundle(bundle) != bundle_hash:
            raise SyncCorrupt("synced bundle failed verification")
        return bundle

    def _write_bundle_locally(self, bundle):
        """Install a verified bundle as the local vault + sidecars."""
        for name, suffix in (("vault", ""), ("audit", ".audit.jsonl"),
                             ("anchor", ".audit-anchor.json")):
            raw = bundle_component(bundle, name)
            path = self.vault_path + suffix
            if raw is None:
                if os.path.exists(path):
                    os.unlink(path)
                continue
            _atomic_write(path, raw)

    # -- push ------------------------------------------------------------------
    def push(self, identity, force=False, human_unlocked=False):
        if force and not human_unlocked:
            raise SyncError(
                "a forced push must be authorized in a human-unlocked "
                "session")
        with vault_lock(self.vault_path):
            return self._push(identity, force)

    def _push(self, identity, force):
        state = load_state(self.vault_path)
        if state is None:
            raise SyncError("sync is not configured — run sync-configure")
        self._require_pairing(state, "push")
        provider = self._provider(state)
        local_bundle = build_bundle(self.vault_path)
        manifest, head = self._checked_manifest(
            state, provider, allow_tofu=not state.get("accepted_bundle_hash"))
        if manifest is not None:
            self._require_ancestry(state, manifest)
        head_hash = head["bundle_hash"] if head else ""
        accepted = state.get("accepted_bundle_hash") or ""
        if head_hash == local_bundle["bundle_hash"]:
            self._accept(state, head, local_bundle)
            self._pin_self(state, identity)
            save_state(self.vault_path, state)
            return {"result": "no-change",
                    "generation": head["generation"] if head else 0}
        if head is not None and head_hash != accepted and not force:
            raise SyncConflict(
                "the synced copy moved since this device last "
                "accepted it — pull first, or force with a human "
                "unlock if you mean to overwrite it")
        # Publish the bundle object BEFORE the commit that names it.
        provider.write_atomic(
            f"bundles/{local_bundle['bundle_hash']}.json",
            json.dumps(local_bundle).encode())
        if manifest is None:
            manifest = {"format": _MANIFEST_FORMAT, "version": 1,
                        "vault_id": local_bundle["vault_id"],
                        "commits": []}
        if state.get("vault_id") and \
                manifest.get("vault_id") != state["vault_id"]:
            raise SyncConflict("sync folder serves a different vault")
        generation = len(manifest["commits"]) + 1
        commit = sign_commit(identity, generation,
                             local_bundle["bundle_hash"], head_hash,
                             "force" if force else "push")
        manifest["commits"].append(commit)
        save_manifest(provider, manifest)
        self._prune(provider, manifest)
        self._accept(state, commit, local_bundle)
        self._pin_self(state, identity)
        save_state(self.vault_path, state)
        if manifest:
            self._pin_tofu(state, manifest)
            save_state(self.vault_path, state)
        return {"result": "forced" if force else "pushed",
                "generation": generation,
                "bundle_hash": local_bundle["bundle_hash"]}

    @staticmethod
    def _pin_self(state, identity):
        """A device trusts its OWN signer key by construction — pin
        it, or its next sync would meet its own commits as a
        stranger's and refuse them."""
        state.setdefault("known_devices", {})[identity.device_id] = {
            "ed25519_pub": _b64e(identity.e_pub),
            "fingerprint": identity.fingerprint,
            "source": "self", "revoked_at": None}

    def _accept(self, state, commit, bundle):
        if commit is not None:
            state["accepted_generation"] = int(commit["generation"])
            state["accepted_bundle_hash"] = commit["bundle_hash"]
        if bundle is not None:
            state["last_synced_vault_hash"] = \
                bundle["components"]["vault"]["sha256"]
        save_state(self.vault_path, state)

    def _prune(self, provider, manifest):
        keep = {c["bundle_hash"]
                for c in (manifest.get("commits") or [])[-_RETENTION_COMMITS:]}
        for name in provider.list_names("bundles"):
            bundle_hash = name.split("/")[-1].removesuffix(".json")
            if bundle_hash not in keep:
                provider.delete(name)

    # -- pull ------------------------------------------------------------------
    def pull(self, force=False, human_unlocked=False):
        if force and not human_unlocked:
            raise SyncError(
                "a forced pull must be authorized in a human-unlocked "
                "session")
        with vault_lock(self.vault_path):
            return self._pull(force)

    def _pull(self, force):
        state = load_state(self.vault_path)
        if state is None:
            raise SyncError("sync is not configured — run sync-configure")
        self._require_pairing(state, "pull")
        provider = self._provider(state)
        manifest, head = self._checked_manifest(
            state, provider,
            allow_tofu=not state.get("accepted_bundle_hash"))
        if manifest is None or head is None:
            return {"result": "no-remote"}
        self._require_ancestry(state, manifest)
        bundle = self._fetch_bundle(provider, head["bundle_hash"])
        local_exists = os.path.exists(self.vault_path)
        local_bundle = build_bundle(self.vault_path) if local_exists else None
        if local_bundle and \
                local_bundle["bundle_hash"] == bundle["bundle_hash"]:
            self._accept(state, head, bundle)
            return {"result": "no-change", "generation": head["generation"]}
        # Is the local vault untouched since the last accepted state?
        local_vault_hash = (local_bundle["components"]["vault"]["sha256"]
                            if local_bundle else None)
        untouched = (not local_exists) or \
            local_vault_hash == state.get("last_synced_vault_hash")
        keep_local_audit = False
        if local_bundle is not None:
            local_audit = bundle_component(local_bundle, "audit")
            remote_audit = bundle_component(bundle, "audit")
            if local_audit is not None and remote_audit is not None:
                relation = audit_relation(local_audit, remote_audit)
                if relation == "forked" and not force:
                    raise SyncConflict(
                        "the audit logs on this device and in the "
                        "synced copy have forked (both grew from the "
                        "same point). Nothing was overwritten. A "
                        "forced pull quarantines this device's log "
                        "and anchor beside the vault — never deletes "
                        "them — and takes the synced copies.")
                if relation in ("forked", "remote-extends", "equal"):
                    pass  # take the remote bundle wholesale
                elif relation == "local-extends" and untouched:
                    # Only the audit grew here; the vault itself is
                    # untouched. Keep the longer local chain, take
                    # the remote vault + anchor (the anchor travels
                    # with the vault it checkpoints; its head is a
                    # prefix of the kept chain by construction).
                    if bundle_component(bundle, "anchor") is None and \
                            bundle_component(local_bundle, "anchor") \
                            is not None:
                        raise SyncError(
                            "the synced copy has no audit anchor but "
                            "this device's log is longer — pull refused "
                            "to avoid an unverifiable anchor state; "
                            "unlock once on the other device (which "
                            "writes its anchor), sync, then retry")
                    keep_local_audit = True
        if not untouched and not force:
            raise SyncConflict(
                "this device's vault changed since the last accepted "
                "sync — pulling would overwrite it. Push first, or "
                "force with a human unlock (the current copy is "
                "snapshotted before any overwrite).")
        snapshot = self._snapshot_local()
        if keep_local_audit:
            local_audit = bundle_component(local_bundle, "audit")
            self._write_bundle_locally(bundle)
            _atomic_write(self.vault_path + ".audit.jsonl", local_audit)
        else:
            if force and local_bundle is not None:
                self._quarantine_sidecars()
            self._write_bundle_locally(bundle)
        self._accept(state, head, bundle)
        self._pin_tofu(state, manifest)
        save_state(self.vault_path, state)
        return {"result": "pulled", "generation": head["generation"],
                "snapshot": snapshot,
                "kept_local_audit": keep_local_audit}

    def _quarantine_sidecars(self):
        ts = _now()
        for suffix in (".audit.jsonl", ".audit-anchor.json"):
            path = self.vault_path + suffix
            if os.path.exists(path):
                os.replace(path, f"{path}.suspect-{ts}")
                os.chmod(f"{path}.suspect-{ts}", 0o600)

    # -- restore -----------------------------------------------------------------
    def restore(self, bundle_hash, human_unlocked=False):
        """Install a retained bundle (provider history or the local
        snapshot whose name contains the hash) as the local state.
        Local act only: publishing it again needs a forced push."""
        if not human_unlocked:
            raise SyncError(
                "restoring a snapshot must be authorized in a "
                "human-unlocked session")
        with vault_lock(self.vault_path):
            state = load_state(self.vault_path)
            bundle = None
            if state is not None:
                provider = self._provider(state)
                raw = provider.read(f"bundles/{bundle_hash}.json")
                if raw is not None:
                    bundle = _strict_loads(raw, "synced bundle")
                    verify_bundle(bundle)
            if bundle is None:
                snap_dir = self.vault_path + ".snapshots"
                if os.path.isdir(snap_dir):
                    for name in sorted(os.listdir(snap_dir)):
                        if bundle_hash[:12] in name:
                            with open(os.path.join(snap_dir, name),
                                      "rb") as f:
                                bundle = _strict_loads(f.read(), "snapshot")
                            verify_bundle(bundle)
                            break
            if bundle is None:
                raise SyncError(f"no snapshot found for {bundle_hash}")
            if state is not None and state.get("vault_id") and \
                    bundle.get("vault_id") != state["vault_id"]:
                raise SyncConflict(
                    "that snapshot belongs to a different vault")
            snapshot = self._snapshot_local()
            self._quarantine_sidecars()
            self._write_bundle_locally(bundle)
            if state is not None:
                # The restored state is deliberately NOT marked as
                # synced: the next publish needs a human force.
                state["last_synced_vault_hash"] = None
                state["restored_bundle_hash"] = bundle["bundle_hash"]
                save_state(self.vault_path, state)
            return {"result": "restored",
                    "bundle_hash": bundle["bundle_hash"],
                    "snapshot_of_previous": snapshot}


def identity_path_hint():
    """The device key path in effect (for configure-time checks)."""
    try:
        from devices import default_device_keys_path
        return default_device_keys_path()
    except Exception:
        return None
