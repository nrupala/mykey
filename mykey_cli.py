# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Command-line shell (Apache 2.0 interface layer).

All cryptography lives in the proprietary engine (mykey.py); this
module only parses arguments, prompts, and prints. All brand strings
come from brand.py — none are hard-coded here.
"""

import argparse
import getpass
import json
import os
import sys
import time

import brand
from mykey import (MIN_GENERATED_PASSWORD_LENGTH, MyKey, MyKeyError,
                   make_entry, rotation_line, rotation_status)


def _fmt_expires(expires_at):
    """An effective expiry in plain terms: a date, or 'never'.

    Enrollment output must always show which one the operator
    actually got (issue #12) — never leave it to a later listing.
    """
    if not expires_at:
        return "never"
    return time.strftime("%Y-%m-%d", time.localtime(int(expires_at)))


def _print_entry(e, status=None):
    line = (f"- {e['service']}  user={e['username'] or '-'}  url={e['url'] or '-'}"
            f"{'  ★' if e['favourite'] else ''}")
    if status is not None:
        if status["state"] == "overdue":
            line += "  ⚠️ password change overdue"
        elif status["state"] == "due_soon":
            line += "  ⏰ password change due soon"
    print(line)


def _prompt_secret(prompt):
    """Read a secret (master password, recovery phrase, entry password).

    Everywhere: getpass, which hides typed input and already falls
    back to reading stdin itself when stdin is not a terminal.

    The one exception is Windows with piped stdin (scripts,
    automation, the MACHINE access mode): getpass's redirected-stdin
    path on Windows (CPython 3.14) leaves the interpreter hanging at
    exit with ``_enter_buffered_busy`` on <stdin> — the packaging
    wave's smoke test reproduced that with ``getpass`` alone. There,
    read one line from stdin directly. (An earlier version of this
    helper took the stdin path on every platform and broke the test
    suite's getpass monkeypatch under pytest; the gate is Windows
    -only so behaviour elsewhere is byte-identical to before.)
    """
    if sys.platform == "win32" and not sys.stdin.isatty():
        sys.stderr.write(prompt)
        sys.stderr.flush()
        return sys.stdin.readline().rstrip("\r\n")
    return getpass.getpass(prompt)


def _load_identity(args):
    """Load this device's identity, or None (error already shown)."""
    import devices

    path = args.device_keys or devices.default_device_keys_path()
    try:
        return devices.DeviceIdentity.load(path)
    except devices.DeviceError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return None


# ----------------------------------------------------------------------
# Browser extension: native messaging installation.
#
# The browser starts the host by name (com.usemykey.mykey). Each
# browser family has its own manifest location and, for Chromium
# builds, its own allowed_origins list — which is why installation
# reads the pairing store: only paired Chromium extension ids are
# allowed to open the pipe. Re-run after pairing a new browser.
# ----------------------------------------------------------------------

_EXT_HOST_NAME = brand.APP_ID
_EXT_GECKO_ID = f"mykey@{brand.DOMAIN}"


def _ext_write_launcher(repo_dir, mykey_dir):
    """The tiny launcher the browser actually starts.

    It embeds THIS interpreter (sys.executable): the one running
    the CLI is the one that has MyKey's dependencies installed.
    A bare "python" from PATH may be a different interpreter
    without them — the host would die on its first import, with
    the browser showing only a silent disconnect. (A packaged
    build must point the launcher at its bundled host entry
    instead; that packaging step owns the substitution.)
    """
    host_py = os.path.join(repo_dir, "native_host.py")
    python = sys.executable or "python3"
    if os.name == "nt":
        path = os.path.join(mykey_dir, "mykey-native-host.bat")
        with open(path, "w", encoding="utf-8", newline="\r\n") as f:
            f.write("@echo off\r\n")
            f.write(f'"{python}" "{host_py}"\r\n')
        return path
    path = os.path.join(mykey_dir, "mykey-native-host.sh")
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n")
        f.write(f'exec "{python}" "{host_py}"\n')
    os.chmod(path, 0o755)
    return path


def _ext_manifest(launcher, browser, store):
    manifest = {
        "name": _EXT_HOST_NAME,
        "description": f"{brand.PRODUCT_NAME} native messaging host — "
                       "brokers the desktop vault to the paired "
                       "browser extension over an encrypted channel.",
        "path": launcher,
        "type": "stdio",
    }
    if browser == "firefox":
        manifest["allowed_extensions"] = [_EXT_GECKO_ID]
    else:
        import re as _re

        origins = []
        for record in store.list_pairings():
            ext_id = record["extension_id"]
            if _re.fullmatch(r"[a-p]{32}", ext_id) \
                    and not record["revoked_at"]:
                origins.append(f"chrome-extension://{ext_id}/")
        manifest["allowed_origins"] = origins
    return manifest


def _ext_host_install(args, store):
    import platform

    repo_dir = os.path.dirname(os.path.abspath(__file__))
    mykey_dir = os.path.join(os.path.expanduser("~"), ".mykey")
    os.makedirs(mykey_dir, exist_ok=True)
    launcher = _ext_write_launcher(repo_dir, mykey_dir)
    system = platform.system()
    home = os.path.expanduser("~")

    chromium_dirs = {
        "chrome": {
            "Linux": ".config/google-chrome/NativeMessagingHosts",
            "Darwin": "Library/Application Support/Google/Chrome/"
                      "NativeMessagingHosts",
        },
        "chromium": {
            "Linux": ".config/chromium/NativeMessagingHosts",
            "Darwin": "Library/Application Support/Chromium/"
                      "NativeMessagingHosts",
        },
        "edge": {
            "Linux": ".config/microsoft-edge/NativeMessagingHosts",
            "Darwin": "Library/Application Support/Microsoft Edge/"
                      "NativeMessagingHosts",
        },
        "brave": {
            "Linux": ".config/BraveSoftware/Brave-Browser/"
                     "NativeMessagingHosts",
            "Darwin": "Library/Application Support/BraveSoftware/"
                      "Brave-Browser/NativeMessagingHosts",
        },
    }
    firefox_dirs = {
        "Linux": ".mozilla/native-messaging-hosts",
        "Darwin": "Library/Application Support/Mozilla/"
                  "NativeMessagingHosts",
    }
    windows_keys = {
        "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
        "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
        "brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
        "firefox": r"Software\Mozilla\NativeMessagingHosts",
    }

    wanted = ["chrome", "chromium", "edge", "brave", "firefox"] \
        if args.browser == "all" else [args.browser]
    written = []
    for browser in wanted:
        manifest = _ext_manifest(launcher, browser, store)
        if system == "Windows":
            manifest_path = os.path.join(
                mykey_dir, f"{_EXT_HOST_NAME}.{browser}.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=1)
            try:
                import winreg

                key_path = windows_keys[browser] + "\\" + _EXT_HOST_NAME
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                      key_path) as key:
                    winreg.SetValueEx(key, None, 0, winreg.REG_SZ,
                                      manifest_path)
                written.append(f"{browser}: registry → {manifest_path}")
            except OSError as exc:
                print(f"⚠️  {browser}: could not write the registry "
                      f"key ({exc}); manifest is at {manifest_path}",
                      file=sys.stderr)
            continue
        rel = (firefox_dirs if browser == "firefox"
               else chromium_dirs[browser]).get(system)
        if rel is None:
            print(f"⚠️  {browser}: no known manifest location on "
                  f"{system}", file=sys.stderr)
            continue
        directory = os.path.join(home, rel)
        os.makedirs(directory, exist_ok=True)
        manifest_path = os.path.join(directory, _EXT_HOST_NAME + ".json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=1)
        written.append(f"{browser}: {manifest_path}")

    print(f"🔌 Native host launcher: {launcher}")
    for line in written:
        print(f"   {line}")
    if not any("chrome-extension://" in json.dumps(
            _ext_manifest(launcher, b, store)) for b in wanted
            if b != "firefox"):
        print("Note: no paired Chromium extension ids yet — Chromium "
              "manifests allow none until you pair (ext-enroll) and "
              "re-run this install.")
    return 0


def main():
    # Windows consoles/pipes default to a legacy code page that cannot
    # encode this CLI's status glyphs (🔑 ✅ ❌ …): printing one crashed
    # the command. Force UTF-8 output everywhere; on Linux/macOS this
    # is already the norm, so the reconfigure is a no-op there.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser(
        description=f"{brand.PRODUCT_NAME}: {brand.PRODUCT_TAGLINE}"
    )
    p.add_argument("action", choices=[
        "gen", "get", "add", "list", "search", "edit", "delete",
        "import", "export", "totp", "recovery-setup", "recovery-unlock",
        "recovery-rotate", "change-master",
        # Password age + rotation: report, mark-changed.
        "rotation", "mark-changed",
        # Phase 2A agent surfaces. agent-get/agent-list are the AGENT
        # principal (token from env, no master prompt); the rest are
        # human-only registry management after a master unlock.
        "agent-get", "agent-list",
        "agent-enroll", "agent-revoke", "agent-disable", "agent-enable",
        "agents", "agent-audit", "agent-audit-reset",
        "rotate-vault-key",
        # Phase 3A: device identity, user-cloud sync, backup packages.
        "device-init", "device-card", "device-enroll", "devices",
        "device-revoke",
        "sync-configure", "sync-status", "sync-push", "sync-pull",
        "sync-snapshots", "sync-restore", "sync-pin",
        "backup-export", "backup-import", "backup-inspect",
        # Blob wave: key-value pairing for cloud/export targets.
        "pairing-keygen", "pairing-payload",
        "pair-enroll", "pairings", "pair-revoke", "pair-disable",
        "pair-enable",
        # Browser extension wave: extension pairing (same key-value
        # pattern), host settings, native-messaging installation.
        "ext-host-payload", "ext-enroll", "ext-pairings",
        "ext-revoke", "ext-disable", "ext-enable",
        "ext-set-vault", "ext-set", "ext-host-install",
        # Licensing wave: free-tier status + licence key activation.
        "licence", "licence-activate",
    ])
    p.add_argument("--agent-id", help="Agent id (agent-enroll/-revoke/...)")
    p.add_argument("--scopes", default="",
                   help="Comma-separated agent scopes, e.g. list,get:github")
    p.add_argument("--expires-days", type=int,
                   help="Lifetime in days for an agent token or pairing "
                        "target (minimum 1; omit for no expiry)")
    p.add_argument("--service")
    p.add_argument("--username", default="")
    p.add_argument("--url", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--password", help="New password value (edit action)")
    p.add_argument("--rotate-days", type=int, default=None,
                   help="Per-entry rotation period in days (edit action); "
                        "0 = never rotate this entry")
    p.add_argument("--rotate-days-clear", action="store_true",
                   help="Remove the per-entry rotation period (edit action); "
                        "the vault default applies again")
    p.add_argument("--set-default-days", type=int, default=None,
                   help="Set the vault default rotation period in days "
                        "(rotation action); 0 = no rotation by default")
    p.add_argument("--set-default-never", action="store_true",
                   help="Turn the vault default rotation off (rotation action)")
    p.add_argument("--all", action="store_true",
                   help="Show every entry, not just due ones (rotation action)")
    p.add_argument("--len", type=int, default=16)
    p.add_argument("--kdf", choices=["argon2id", "pbkdf2"], default="argon2id")
    p.add_argument("--vault", default="vault.mykey")
    p.add_argument("--file", help="Import/export file path")
    p.add_argument("--format", help="Import format (auto-detected if omitted)")
    p.add_argument("--on-conflict", choices=["skip", "overwrite", "keep_both"],
                   default="skip")
    p.add_argument("--dry-run", action="store_true", help="Import preview only")
    p.add_argument("--query", default="")
    # Phase 3A arguments.
    p.add_argument("--folder", help="Sync folder (sync-configure)")
    p.add_argument("--card", help="Device card JSON file (device-enroll)")
    p.add_argument("--device", help="Device id (device-revoke)")
    p.add_argument("--label", default="", help="Device label (device-init)")
    p.add_argument("--device-keys",
                   help="Device key file path (default: ~/.mykey/device-keys.json)")
    p.add_argument("--key", dest="licence_key",
                   help="Licence key (licence-activate; prompted if omitted — "
                        "a prompt keeps the key out of shell history)")
    p.add_argument("--self", dest="self_enroll", action="store_true",
                   help="Enroll THIS device (device-enroll)")
    p.add_argument("--yes", action="store_true",
                   help="Confirm a device enrollment without prompting")
    p.add_argument("--force", action="store_true",
                   help="Force a sync push/pull/restore (human unlock required)")
    p.add_argument("--snapshot", help="Bundle hash to restore (sync-restore)")
    p.add_argument("--expect-fingerprint",
                   help="Source fingerprint obtained independently (backup-import)")
    p.add_argument("--allow-older", action="store_true",
                   help="Allow importing an older backup package")
    p.add_argument("--recovery", action="store_true",
                   help="Open the package with the recovery phrase (backup-import)")
    # Blob-wave arguments.
    p.add_argument("--payload", help="Pairing payload JSON file (pair-enroll)")
    p.add_argument("--target", help="Pairing target id (pair-revoke/-disable/"
                                    "-enable; sync-configure binds the folder "
                                    "to this target, empty string unbinds)")
    p.add_argument("--pairing-keys",
                   help="Pairing target key file (pairing-payload; "
                        "backup-import opens pairing-wrapped packages)")
    p.add_argument("--pairing-type", default="export",
                   choices=["device", "cloud-folder", "export"],
                   help="Pairing target type (pairing-keygen)")
    p.add_argument("--backup-code",
                   help="Backup code for a v2 package (backup-import; "
                        "prompted when --recovery is used without it)")
    # Browser-extension-wave arguments.
    p.add_argument("--extension", help="Extension id (ext-revoke/"
                                       "ext-disable/ext-enable)")
    p.add_argument("--browser",
                   choices=["chrome", "chromium", "edge", "brave",
                            "firefox", "all"],
                   default="all",
                   help="Browser for ext-host-install (default: all)")
    p.add_argument("--clipboard-seconds", type=int,
                   help="Clipboard clear delay for copied secrets, "
                        "60–300 (ext-set)")
    p.add_argument("--auto-lock-seconds", type=int,
                   help="Idle auto-lock for the extension host "
                        "session (ext-set)")
    args = p.parse_args()

    if args.action == "gen" and args.len < MIN_GENERATED_PASSWORD_LENGTH:
        print(f"❌ --len must be at least {MIN_GENERATED_PASSWORD_LENGTH}", file=sys.stderr)
        return 2

    try:
        if args.action in ("agent-get", "agent-list"):
            from agents import open_agent_session

            token = os.environ.get("MYKEY_AGENT_KEY", "")
            if not token:
                print("❌ MYKEY_AGENT_KEY is not set — an agent token is "
                      "required (the human enrolls one with agent-enroll).",
                      file=sys.stderr)
                return 2
            session = open_agent_session(args.vault, token)
            if args.action == "agent-list":
                for e in session.list_metadata():
                    _print_entry(e)
            else:
                if not args.service:
                    print("❌ --service required", file=sys.stderr)
                    return 2
                from agents import AgentScopeError

                try:
                    e = session.get(args.service, args.username or None)
                except (KeyError, AgentScopeError):
                    # Missing vs out-of-scope MUST look identical
                    # (existence oracle — fleet review, finding 6).
                    # The audit log keeps the detail for the human.
                    print("❌ Not available for this agent.", file=sys.stderr)
                    return 1
                # Authorized display of a credential to the agent the
                # human scoped for it; the purpose of 'agent-get'.
                # codeql[py/clear-text-logging-sensitive-data]
                print(f"🔑 {e['service']} ({e['username']}): {e['password']}")
            return 0

        # ---- Phase 3A surfaces that never decrypt the vault --------
        if args.action == "device-init":
            import devices

            path = args.device_keys or devices.default_device_keys_path()
            if os.path.exists(path) and not args.force:
                print(f"❌ A device identity already exists at {path}. "
                      "Use --force to replace it — the new identity "
                      "cannot open backups wrapped to the old one.",
                      file=sys.stderr)
                return 2
            identity = devices.DeviceIdentity.generate(args.label)
            identity.save(path)
            print(f"🖥  Device identity created: {identity.device_id}")
            print(f"    Fingerprint: {identity.fingerprint}")
            print(f"    Keys: {path} (mode 0600 — protect this file; "
                  "it is never synced)")
            return 0

        if args.action == "device-card":
            identity = _load_identity(args)
            if identity is None:
                return 2
            card = json.dumps(identity.card(), indent=1)
            if args.file:
                with open(args.file, "w", encoding="utf-8") as f:
                    f.write(card + "\n")
                os.chmod(args.file, 0o600)
                print(f"📇 Card written to {args.file}")
            else:
                print(card)
            print(f"Fingerprint (compare out-of-band): {identity.fingerprint}",
                  file=sys.stderr)
            return 0

        if args.action == "pairing-keygen":
            import pairings

            if not args.pairing_keys:
                print("❌ --pairing-keys FILE required (where the new "
                      "target key file will be stored)", file=sys.stderr)
                return 2
            if os.path.exists(args.pairing_keys) and not args.force:
                print(f"❌ A pairing target key already exists at "
                      f"{args.pairing_keys}. Use --force to replace it "
                      "— packages wrapped to the old key cannot be "
                      "opened by the new one.", file=sys.stderr)
                return 2
            target = pairings.PairingTargetIdentity.generate(
                args.pairing_type, args.label)
            target.save(args.pairing_keys)
            print(f"🎯 Pairing target created: {target.target_id}")
            print(f"    Type: {target.target_type}  "
                  f"Fingerprint: {target.fingerprint}")
            print(f"    Keys: {args.pairing_keys} (mode 0600 — "
                  "protect this file; it is never synced)")
            payload = json.dumps(target.payload(), indent=1)
            if args.file:
                with open(args.file, "w", encoding="utf-8") as f:
                    f.write(payload + "\n")
                os.chmod(args.file, 0o600)
                print(f"📇 Pairing payload written to {args.file} — "
                      "give it to the vault owner to enroll "
                      "(pair-enroll). It carries no secrets.")
            else:
                print("Pairing payload (give it to the vault owner; "
                      "it carries no secrets):")
                print(payload)
            return 0

        if args.action == "pairing-payload":
            import pairings

            if not args.pairing_keys:
                print("❌ --pairing-keys FILE required",
                      file=sys.stderr)
                return 2
            try:
                target = pairings.PairingTargetIdentity.load(
                    args.pairing_keys)
            except pairings.PairingError as exc:
                print(f"❌ {exc}", file=sys.stderr)
                return 2
            payload = json.dumps(target.payload(), indent=1)
            if args.file:
                with open(args.file, "w", encoding="utf-8") as f:
                    f.write(payload + "\n")
                os.chmod(args.file, 0o600)
                print(f"📇 Pairing payload written to {args.file}")
            else:
                print(payload)
            print(f"Fingerprint (compare out-of-band): "
                  f"{target.fingerprint}", file=sys.stderr)
            return 0

        # ---- Browser extension wave (host store, never the vault) ----
        if args.action in ("ext-host-payload", "ext-enroll",
                           "ext-pairings", "ext-revoke", "ext-disable",
                           "ext-enable", "ext-set-vault", "ext-set",
                           "ext-host-install"):
            import extpair

            store = extpair.ExtensionHostStore.load(
                os.environ.get("MYKEY_EXT_STORE")
                or extpair.default_store_path())

            if args.action == "ext-host-payload":
                payload = json.dumps(store.host_payload(), indent=1)
                if args.file:
                    with open(args.file, "w", encoding="utf-8") as f:
                        f.write(payload + "\n")
                    os.chmod(args.file, 0o600)
                    print(f"📇 Host payload written to {args.file} — "
                          "paste it into the extension's options. "
                          "It carries no secrets.")
                else:
                    print(payload)
                print(f"Host fingerprint (the extension must show "
                      f"the same): {store.host_fingerprint}")
                return 0

            if args.action == "ext-enroll":
                if not args.payload:
                    print("❌ --payload FILE required (the pairing "
                          "payload from the extension's options)",
                          file=sys.stderr)
                    return 2
                try:
                    # utf-8-sig: payloads saved by Windows editors
                    # routinely carry a BOM, which strict JSON
                    # parsing rejects — a pairing must not fail
                    # over an invisible byte.
                    with open(args.payload, encoding="utf-8-sig") as f:
                        payload = json.load(f)
                    record = extpair.verify_payload(payload)
                except Exception as exc:
                    print(f"❌ {exc}", file=sys.stderr)
                    return 2
                print(f"Extension: {record['extension_id']}")
                print(f"Label:     {record['label'] or '-'}")
                print(f"Fingerprint: {record['fingerprint']}")
                print("Compare this fingerprint with the one the "
                      "extension shows in its options. Pair only if "
                      "they match exactly.")
                if not args.yes:
                    answer = input("Pair this extension? [y/N] ")
                    if answer.strip().lower() not in ("y", "yes"):
                        print("Not paired.")
                        return 1
                scopes = [s for s in (args.scopes or "").split(",")
                          if s.strip()] or ["fill", "save"]
                try:
                    record = store.enroll(payload, scopes,
                                          expires_days=args.expires_days)
                except extpair.ExtensionPairingError as exc:
                    print(f"❌ {exc}", file=sys.stderr)
                    return 2
                print(f"🔗 Paired. Scopes: {', '.join(record['scopes'])}"
                      + (f"  Expires: {record['expires_at']}"
                         if record["expires_at"] else "  No expiry"))
                print("Run ext-host-install so the browser can "
                      "reach the desktop host.")
                return 0

            if args.action == "ext-pairings":
                rows = store.list_pairings()
                if not rows:
                    print("No browser extensions paired.")
                    return 0
                for r in rows:
                    state = ("active" if r["active"] else
                             "revoked" if r["revoked_at"] else
                             "disabled" if not r["enabled"] else
                             "expired")
                    print(f"- {r['extension_id']}  [{state}]  "
                          f"scopes={','.join(r['scopes'])}  "
                          f"label={r['label'] or '-'}")
                    print(f"    fingerprint: {r['fingerprint']}")
                return 0

            if args.action in ("ext-revoke", "ext-disable",
                               "ext-enable"):
                if not args.extension:
                    print("❌ --extension ID required", file=sys.stderr)
                    return 2
                try:
                    if args.action == "ext-revoke":
                        store.revoke(args.extension)
                        print(f"⛔ Pairing revoked: {args.extension}. "
                              "It can never be re-enrolled — the "
                              "browser profile must reset its pairing "
                              "identity to pair again.")
                    elif args.action == "ext-disable":
                        store.set_enabled(args.extension, False)
                        print(f"⏸ Pairing disabled: {args.extension}")
                    else:
                        store.set_enabled(args.extension, True)
                        print(f"▶️ Pairing enabled: {args.extension}")
                except extpair.ExtensionPairingError as exc:
                    print(f"❌ {exc}", file=sys.stderr)
                    return 2
                return 0

            if args.action == "ext-set-vault":
                path = os.path.abspath(args.vault)
                if not os.path.exists(path):
                    print(f"❌ No vault file at {path}", file=sys.stderr)
                    return 2
                store.set_setting("vault_file", path)
                print(f"🗄 Extension host will serve the vault at "
                      f"{path}")
                return 0

            if args.action == "ext-set":
                changed = False
                try:
                    if args.clipboard_seconds is not None:
                        store.set_setting("clipboard_clear_seconds",
                                          args.clipboard_seconds)
                        print(f"📋 Copied secrets clear after "
                              f"{args.clipboard_seconds} seconds")
                        changed = True
                    if args.auto_lock_seconds is not None:
                        store.set_setting("auto_lock_seconds",
                                          args.auto_lock_seconds)
                        print(f"🔒 Extension session auto-locks after "
                              f"{args.auto_lock_seconds} idle seconds")
                        changed = True
                except extpair.ExtensionPairingError as exc:
                    print(f"❌ {exc}", file=sys.stderr)
                    return 2
                if not changed:
                    settings = store.settings
                    print(f"clipboard_clear_seconds="
                          f"{settings.get('clipboard_clear_seconds')}")
                    print(f"auto_lock_seconds="
                          f"{settings.get('auto_lock_seconds')}")
                    print(f"vault_file={settings.get('vault_file') or '-'}")
                return 0

            if args.action == "ext-host-install":
                return _ext_host_install(args, store)

        if args.action == "backup-inspect":
            from backup_pkg import inspect_package

            info = inspect_package(args.file)
            for key, value in info.items():
                print(f"{key}: {value}")
            if info["legacy"]:
                print("⚠️  LEGACY package: its recovery slot opens "
                      "with the recovery phrase alone (no backup "
                      "code). New exports use two-factor recovery.")
            return 0 if info["signature_valid"] else 1

        if args.action in ("sync-configure", "sync-status",
                           "sync-snapshots"):
            import vaultsync

            sync = vaultsync.VaultSync(args.vault)
            if args.action == "sync-configure":
                if not args.folder:
                    print("❌ --folder required", file=sys.stderr)
                    return 2
                identity = _load_identity(args)
                if identity is None:
                    return 2
                sync.configure(args.folder, identity,
                               device_keys_path=args.device_keys,
                               target_id=args.target)
                print(f"🔄 Sync configured: folder {args.folder}")
            elif args.action == "sync-status":
                for key, value in sync.status().items():
                    print(f"{key}: {value}")
            else:
                snaps = sync.list_snapshots()
                for s in snaps["provider"]:
                    print(f"remote  gen={s['generation']}  {s['bundle_hash'][:16]}…"
                          f"  kind={s['kind']}  device={s['device_id'][:8]}…")
                for name in snaps["local"]:
                    print(f"local   {name}")
            return 0

        if args.action in ("sync-push", "sync-pull") and not args.force:
            import vaultsync

            sync = vaultsync.VaultSync(args.vault)
            if args.action == "sync-push":
                identity = _load_identity(args)
                if identity is None:
                    return 2
                result = sync.push(identity)
            else:
                result = sync.pull()
            print(f"🔄 {args.action}: {json.dumps(result)}")
            return 0

        if args.action == "backup-import":
            import backup_pkg
            import devices as devices_mod

            identity = None
            keys_path = args.device_keys or \
                devices_mod.default_device_keys_path()
            if os.path.exists(keys_path):
                identity = _load_identity(args)
                if identity is None:
                    return 2
            registry = None
            pairing_registry = None
            if os.path.exists(args.vault):
                print("A vault exists at the target — unlocking it to "
                      "check the package's source against its registry.")
                master = _prompt_secret("Enter Master Password: ")
                probe = MyKey(master, vault_file=args.vault)
                probe.unlock()
                registry = probe._devices
                pairing_registry = probe._pairings
            phrase = None
            code = args.backup_code
            if args.recovery:
                phrase = _prompt_secret("Recovery phrase: ")
                if not code:
                    entered = _prompt_secret(
                        "Backup code (8 words — needed for newer "
                        "backups; leave empty for older ones): ")
                    code = entered.strip() or None
            pairing_priv = None
            if args.pairing_keys:
                import pairings as pairings_mod

                try:
                    target = pairings_mod.PairingTargetIdentity.load(
                        args.pairing_keys)
                except pairings_mod.PairingError as exc:
                    print(f"❌ {exc}", file=sys.stderr)
                    return 2
                pairing_priv = target.x_priv_raw
            expect = args.expect_fingerprint
            if registry is None and not expect:
                expect = input("Source device fingerprint (read it on "
                               "the source device, not from the package): "
                               ).strip()
            result = backup_pkg.import_package(
                args.file, args.vault, identity=identity,
                recovery_phrase=phrase, backup_code=code,
                pairing_priv=pairing_priv,
                expect_fingerprint=expect,
                allow_older=args.allow_older, registry=registry,
                pairing_registry=pairing_registry)
            legacy_note = " (LEGACY package — phrase-only recovery)" \
                if result.get("legacy") else ""
            print(f"📦 Backup imported via {result['via']} — "
                  f"vault {result['vault_id'][:12]}… is in place. "
                  f"Unlock it with its master password as usual."
                  f"{legacy_note}")
            if result["snapshot_of_previous"]:
                print(f"    Previous vault preserved at: "
                      f"{result['snapshot_of_previous']}")
            return 0

        if args.action == "recovery-unlock":
            phrase = _prompt_secret("Recovery phrase: ")
            probe = MyKey("recovery-probe-0000", vault_file=args.vault)
            entries = probe.unlock_via_recovery(phrase)
            print(f"✅ Recovery phrase unlocks this vault ({len(entries)} entries).")
            return 0

        master = _prompt_secret("Enter Master Password: ")
        app = MyKey(master, algo=args.kdf, vault_file=args.vault)

        # ---- Licensing wave --------------------------------------
        if args.action in ("licence", "licence-activate"):
            import licensing

            app.unlock()  # human principal from here on
            if args.action == "licence":
                st = licensing.licence_status(app)
                if st["licensed"]:
                    print(f"✅ Licensed to {st['licensee']} "
                          f"(licence {st['licence_id']})")
                    print("   Passwords: unlimited")
                else:
                    print("Free version")
                    print(f"   Passwords: {st['entries']} of "
                          f"{st['entry_limit']}")
                    print(f"   Buy a licence: {brand.LICENCE_BUY_URL} — "
                          "then run licence-activate and paste the key.")
                bd = st["connections_breakdown"]
                print(f"   Connections: {st['connections']} of "
                      f"{st['connection_limit']} in use "
                      f"({bd['devices']} devices, {bd['agents']} agents, "
                      f"{bd['browsers']} paired browsers)")
                print("   The limits are a fairness limit checked in "
                      "the app, offline — nothing is sent anywhere, "
                      "and everything already saved always works.")
            else:
                key = args.licence_key or input(
                    "Paste your licence key: ").strip()
                payload = licensing.activate_licence(app, key)
                print(f"✅ Licence active — thank you. Licence "
                      f"{payload['licence_id']} for "
                      f"{payload['licensee']}: unlimited passwords, "
                      f"{payload['max_connections']} connections. "
                      "The key is stored in this vault (it travels "
                      "with it) and on this device (new vaults here "
                      "start licensed).")
            return 0

        if args.action in ("agent-enroll", "agent-revoke", "agent-disable",
                           "agent-enable", "agents", "agent-audit",
                           "agent-audit-reset", "rotate-vault-key"):
            from agents import (audit_mac_keys, enroll_agent, list_agents,
                                read_audit, reset_audit, revoke_agent,
                                set_agent_enabled, verify_audit)

            if args.action == "agent-audit-reset":
                # The reset flow is the recovery path for an anchor or
                # chain failure, so it must be able to unlock through
                # one: quarantine happens inside the engine.
                from mykey import AuditAnchorError

                try:
                    app.unlock()
                except AuditAnchorError:
                    app._anchor_recovery = True
                    app._entries = None
                    app.unlock()
            else:
                app.unlock()  # human principal from here on
            if app._migrated_from:
                print(f"ℹ️  Vault migrated from format v{app._migrated_from} to v3 "
                      "on this unlock. Agent enrollments were retired — "
                      "re-enroll agents; if you migrated with the master "
                      "password, set up the recovery phrase again too.",
                      file=sys.stderr)
            if args.action == "agents":
                for a in list_agents(app):
                    state = "enabled" if a["enabled"] else "DISABLED"
                    print(f"- {a['agent_id']}  [{state}]  scopes={','.join(a['scopes']) or '-'}"
                          f"  expires={a['expires_at'] or 'never'}"
                          f"  last_used={a['last_used_at'] or 'never'}")
            elif args.action == "agent-audit":
                check = verify_audit(
                    args.vault, expected_head=app._audit_head,
                    mac_keys=audit_mac_keys(app),
                    mac_since=app._audit_mac_since)
                for r in read_audit(args.vault):
                    print(f"{r['ts']}  {r['agent']}  {r['action']} "
                          f"{r['service'] or '-'}  {r['result']}"
                          f"{(' (' + r['reason'] + ')') if r['reason'] else ''}")
                print(f"Chain: {'OK' if check['ok'] else 'BROKEN — ' + check['error']}"
                      f" ({check['count']} records)")
                return 0 if check["ok"] else 1
            elif args.action == "agent-audit-reset":
                archive = reset_audit(app)
                print("🧾 Audit log reset. "
                      f"Suspect log preserved at: {archive or '(none existed)'}")
            elif args.action == "rotate-vault-key":
                result = app.rotate_vault_key()
                print("🔄 Vault key rotated. All old slots are dead: "
                      f"{result['agents_dropped']} agent(s) to re-enroll, "
                      f"recovery {'must be set up again' if result['recovery_dropped'] else 'was not set up'}. "
                      "Your master password is unchanged.")
            else:
                if not args.agent_id:
                    print("❌ --agent-id required", file=sys.stderr)
                    return 2
                if args.action == "agent-enroll":
                    scopes = [s.strip() for s in
                              (args.scopes or "list").split(",") if s.strip()]
                    token = enroll_agent(app, args.agent_id, scopes,
                                         expires_days=args.expires_days)
                    rec = next(a for a in list_agents(app)
                               if a["agent_id"] == args.agent_id)
                    print(f"🤖 Agent '{args.agent_id}' enrolled.")
                    print(f"   Scopes: {', '.join(rec['scopes']) or '-'}")
                    print(f"   Expires: {_fmt_expires(rec['expires_at'])}")
                    print("Token (shown ONCE, store it in the agent's "
                          "environment as MYKEY_AGENT_KEY):")
                    print(token)
                elif args.action == "agent-revoke":
                    revoke_agent(app, args.agent_id)
                    print(f"🗑 Agent '{args.agent_id}' revoked — its token is dead.")
                elif args.action == "agent-disable":
                    set_agent_enabled(app, args.agent_id, False)
                    print(f"⏸ Agent '{args.agent_id}' disabled.")
                elif args.action == "agent-enable":
                    set_agent_enabled(app, args.agent_id, True)
                    print(f"▶️ Agent '{args.agent_id}' enabled.")
            return 0

        # ---- Phase 3A human-gated surfaces -------------------------
        if args.action in ("device-enroll", "devices", "device-revoke",
                           "backup-export", "sync-pin", "sync-restore",
                           "pair-enroll", "pairings", "pair-revoke",
                           "pair-disable", "pair-enable") or \
                (args.action in ("sync-push", "sync-pull") and args.force):
            import devices as devices_mod
            import pairings as pairings_mod
            import vaultsync

            app.unlock()  # human principal from here on
            sync = vaultsync.VaultSync(args.vault)

            def _refresh_pins():
                state = vaultsync.load_state(args.vault)
                if state is not None:
                    vaultsync.refresh_pins(app, state)
                    vaultsync.refresh_pairing_pins(app, state)
                    vaultsync.save_state(args.vault, state)

            if args.action == "devices":
                for d in devices_mod.list_devices(app):
                    state = "REVOKED" if d["revoked_at"] else "active"
                    print(f"- {d['device_id'][:12]}…  [{state}]  "
                          f"{d['label'] or '-'}  fp={d['fingerprint']}")
            elif args.action == "device-enroll":
                if args.self_enroll:
                    identity = _load_identity(args)
                    if identity is None:
                        return 2
                    card = identity.card()
                elif args.card:
                    card = json.loads(
                        open(args.card, encoding="utf-8").read())
                else:
                    print("❌ --self or --card FILE required",
                          file=sys.stderr)
                    return 2
                record = devices_mod.verify_card(card)
                print(f"Enrolling device {record['device_id']}")
                print(f"    Fingerprint: {record['fingerprint']}")
                print("    Only proceed if that fingerprint matches "
                      "what the device itself shows.")
                if not args.yes and not args.self_enroll:
                    answer = input("Type 'yes' to enroll: ").strip()
                    if answer != "yes":
                        print("Aborted.")
                        return 1
                devices_mod.enroll_device(app, card)
                _refresh_pins()
                print("✅ Device enrolled. It becomes a recipient of "
                      "new backup packages, and its sync commits can "
                      "be verified against the registry.")
            elif args.action == "device-revoke":
                if not args.device:
                    print("❌ --device required", file=sys.stderr)
                    return 2
                full = next((d for d in app._devices
                             if d.startswith(args.device)), args.device)
                devices_mod.revoke_device(app, full)
                _refresh_pins()
                print(f"🗑 Device {full[:12]}… revoked. New backup "
                      "packages exclude it; packages already exported "
                      "stay openable by a key it retained (see "
                      "SYNC_BACKUP.md).")
            elif args.action == "pair-enroll":
                if not args.payload:
                    print("❌ --payload FILE required (the pairing "
                          "payload the target presented)",
                          file=sys.stderr)
                    return 2
                payload = json.loads(
                    open(args.payload, encoding="utf-8").read())
                record = pairings_mod.verify_payload(payload)
                scopes = [s.strip() for s in
                          (args.scopes or "export").split(",") if s.strip()]
                print(f"Pairing target {record['target_id']}")
                print(f"    Type: {record['type']}  "
                      f"Label: {record['label'] or '-'}")
                print(f"    Fingerprint: {record['fingerprint']}")
                print(f"    Scopes: {', '.join(scopes)}")
                print("    Only proceed if that fingerprint matches "
                      "what the target itself shows.")
                if not args.yes:
                    answer = input("Type 'yes' to pair: ").strip()
                    if answer != "yes":
                        print("Aborted.")
                        return 1
                record = pairings_mod.enroll_pairing(
                    app, payload, scopes,
                    expires_days=args.expires_days)
                _refresh_pins()
                print(f"    Expires: {_fmt_expires(record['expires_at'])}")
                print("✅ Target paired. It receives backup packages "
                      "and sync access only within its scopes.")
            elif args.action == "pairings":
                for t in pairings_mod.list_pairings(app):
                    if t["revoked_at"]:
                        state = "REVOKED"
                    elif not t["enabled"]:
                        state = "DISABLED"
                    elif not t["active"]:
                        state = "EXPIRED"
                    else:
                        state = "active"
                    print(f"- {t['target_id'][:12]}…  [{state}]  "
                          f"{t['type']}  {t['label'] or '-'}  "
                          f"scopes={','.join(t['scopes']) or '-'}  "
                          f"fp={t['fingerprint']}")
            elif args.action in ("pair-revoke", "pair-disable",
                                 "pair-enable"):
                if not args.target:
                    print("❌ --target required", file=sys.stderr)
                    return 2
                full = next((t for t in app._pairings
                             if t.startswith(args.target)), args.target)
                if args.action == "pair-revoke":
                    pairings_mod.revoke_pairing(app, full)
                    _refresh_pins()
                    print(f"🗑 Pairing {full[:12]}… revoked. New "
                          "backup packages give it no slot and sync "
                          "to its folder stops; packages already "
                          "exported stay openable by a key it "
                          "retained (see SYNC_BACKUP.md).")
                elif args.action == "pair-disable":
                    pairings_mod.set_pairing_enabled(app, full, False)
                    _refresh_pins()
                    print(f"⏸ Pairing {full[:12]}… disabled.")
                else:
                    pairings_mod.set_pairing_enabled(app, full, True)
                    _refresh_pins()
                    print(f"▶️ Pairing {full[:12]}… enabled.")
            elif args.action == "backup-export":
                if not args.file:
                    print("❌ --file required", file=sys.stderr)
                    return 2
                from backup_pkg import export_package

                identity = _load_identity(args)
                if identity is None:
                    return 2
                package, code = export_package(
                    app, identity, out_path=args.file)
                names = []
                for r in package["recipients"]:
                    if r["type"] == "device":
                        names.append(r["device_id"][:12] + "…")
                    elif r["type"] == "pairing":
                        names.append("paired:" + r["target_id"][:12] + "…")
                    else:
                        names.append("recovery (phrase + backup code)")
                print(f"📦 Backup package written: {args.file}")
                print(f"    Recipients: {', '.join(names)}")
                print("    The package is ciphertext — safe to store "
                      "or send. Keep it like a vault copy.")
                if code:
                    print()
                    print("🔑 YOUR BACKUP CODE (shown ONCE — it is "
                          "not stored anywhere):")
                    print(f"    {code}")
                    print("    Opening this backup outside the app "
                          "needs BOTH your recovery phrase AND this "
                          "code. Write the code down and keep it "
                          "somewhere DIFFERENT from the phrase.")
            elif args.action == "sync-pin":
                state = vaultsync.load_state(args.vault)
                if state is None:
                    print("❌ sync is not configured", file=sys.stderr)
                    return 2
                vaultsync.refresh_pins(app, state)
                vaultsync.refresh_pairing_pins(app, state)
                vaultsync.save_state(args.vault, state)
                print("📌 Signer keys + pairing pins refreshed from "
                      "the vault registry.")
            elif args.action == "sync-restore":
                if not args.snapshot:
                    print("❌ --snapshot BUNDLE_HASH required",
                          file=sys.stderr)
                    return 2
                result = sync.restore(args.snapshot, human_unlocked=True)
                print(f"🔄 Restored snapshot {result['bundle_hash'][:16]}… "
                      "Publishing it again needs sync-push --force.")
            elif args.action == "sync-push":  # --force (gate above)
                identity = _load_identity(args)
                if identity is None:
                    return 2
                result = sync.push(identity, force=True,
                                   human_unlocked=True)
                print(f"🔄 sync-push: {json.dumps(result)}")
            elif args.action == "sync-pull":  # --force (gate above)
                result = sync.pull(force=True, human_unlocked=True)
                print(f"🔄 sync-pull: {json.dumps(result)}")
            return 0

        if args.action == "gen":
            pw = app.generate_password(args.len)
            if args.service:
                app.save_password(args.service, pw, username=args.username,
                                  url=args.url, notes=args.notes)
                # Do not echo the saved password; retrieve it with 'get'.
                print(f"✅ Generated and saved for {args.service}.")
            else:
                # Explicit user-requested display of their own generated
                # password on their own terminal; the purpose of 'gen'.
                # codeql[py/clear-text-logging-sensitive-data]
                print(f"✨ Generated: {pw}")
        elif args.action == "add":
            if not args.service:
                print("❌ --service required", file=sys.stderr); return 2
            pwd = _prompt_secret(f"Password for {args.service} (your existing one): ")
            app.add_entry(make_entry(service=args.service, password=pwd,
                                     username=args.username, url=args.url,
                                     notes=args.notes))
            print(f"💾 Saved {args.service} to vault.")
        elif args.action == "get":
            if not args.service:
                print("❌ --service required", file=sys.stderr); return 2
            e = app.get_entry(args.service, args.username or None)
            # Explicit user-requested display of their own credential
            # on their own terminal; the purpose of the 'get' action.
            # codeql[py/clear-text-logging-sensitive-data]
            print(f"🔑 {e['service']} ({e['username']}): {e['password']}")
        elif args.action == "list":
            entries = app.list_entries()
            default = app.vault_settings()["default_rotate_days"]
            for e in entries:
                _print_entry(e, rotation_status(e, default))
            print(f"({len(entries)} entries)")
        elif args.action == "search":
            default = app.vault_settings()["default_rotate_days"]
            for e in app.search_entries(args.query):
                _print_entry(e, rotation_status(e, default))
        elif args.action == "edit":
            fields = {}
            if args.password is not None:
                fields["password"] = args.password
            if args.url:
                fields["url"] = args.url
            if args.notes:
                fields["notes"] = args.notes
            if args.rotate_days is not None:
                fields["rotate_days"] = args.rotate_days
            if args.rotate_days_clear:
                fields["rotate_days"] = None
            app.update_entry(args.service, args.username or None, **fields)
            print(f"✅ Updated {args.service}.")
        elif args.action == "rotation":
            if args.set_default_never or args.set_default_days is not None:
                value = None if args.set_default_never \
                    else args.set_default_days
                app.set_default_rotate_days(value)
                print("✅ Vault default updated: "
                      + ("no rotation by default."
                         if not value else
                         f"change passwords every {value} days."))
            default = app.vault_settings()["default_rotate_days"]
            print("Default: " + ("no rotation by default" if not default
                                 else f"change every {default} days")
                  + " (per-entry settings win over the default)")
            report = app.rotation_report()
            rows = report if args.all else [
                r for r in report
                if r["state"] in ("overdue", "due_soon", "unknown")]
            if not rows:
                print("Nothing needs changing right now.")
            for r in rows:
                line = rotation_line(
                    {"password_set_at": r["password_set_at"],
                     "rotate_days": r["rotate_days"]}, None)
                suffix = {"overdue": " — overdue",
                          "due_soon": " — due soon",
                          "unknown": ""}.get(r["state"], "")
                print(f"- {r['service']}  user={r['username'] or '-'}  "
                      f"{line}{suffix}")
            due = sum(1 for r in report
                      if r["state"] in ("overdue", "due_soon"))
            print(f"({due} of {len(report)} passwords due for a change)")
        elif args.action == "mark-changed":
            if not args.service:
                print("❌ --service required", file=sys.stderr); return 2
            app.mark_password_changed(args.service, args.username or None)
            print(f"✅ {args.service}: marked as changed today.")
        elif args.action == "delete":
            app.delete_entry(args.service, args.username or None)
            print(f"🗑 Deleted {args.service}.")
        elif args.action == "totp":
            print(app.totp_for(args.service, args.username or None))
        elif args.action == "import":
            from importers import parse_import, preview_import
            text = open(args.file, encoding="utf-8").read()
            fmt, records = parse_import(text, args.format)
            if args.dry_run:
                preview = preview_import(records, app.list_entries())
                print(f"Format: {fmt}")
                print(f"New: {len(preview['new'])}  Duplicates: "
                      f"{len(preview['duplicates'])}  Conflicts: "
                      f"{len(preview['conflicts'])}")
                return 0
            stats = app.import_entries(records, on_conflict=args.on_conflict)
            print(f"✅ Imported ({fmt}): {json.dumps(stats)}")
            if stats.get("held_back"):
                print(f"⏸  {stats['held_back']} password(s) were NOT "
                      "imported: the free version holds up to 50. "
                      "Enter a licence key (licence-activate) and run "
                      "the same import again to bring them in — the "
                      "ones already imported are skipped as duplicates.")
            print("⚠️  Delete the plaintext export file now — it is unencrypted.")
        elif args.action == "export":
            ok, msg = app.export_vault_to_csv(args.file or "mykey_export.csv")
            print(("✅ " if ok else "❌ ") + msg)
            if ok:
                print("⚠️  The export is plaintext CSV. Guard it and delete it.")
            return 0 if ok else 1
        elif args.action == "recovery-setup":
            app.unlock()
            print("Type the recovery phrase back to verify it was written down.")
            phrase = app.setup_recovery()
            print("\n📝 YOUR EMERGENCY RECOVERY PHRASE (shown once):")
            print(phrase)
            check = input("Re-type the phrase to verify: ").strip()
            from recovery import validate_mnemonic
            if check != phrase or not validate_mnemonic(check):
                # Slot stays valid; the warning matters more than a lockout here.
                print("⚠️  What you typed does not match. Write the phrase above "
                      "down exactly, in order, before closing this terminal.")
            else:
                print("✅ Recovery phrase verified and active.")
        elif args.action == "recovery-rotate":
            phrase = app.rotate_recovery()
            print("📝 NEW RECOVERY PHRASE (the old one no longer works):")
            print(phrase)
        elif args.action == "change-master":
            new_master = _prompt_secret("New Master Password: ")
            app.change_master(new_master)
            print("✅ Master password changed.")
    except KeyError as exc:
        print(f"❌ Not Found. {exc}", file=sys.stderr)
        return 1
    except (MyKeyError, ValueError) as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
