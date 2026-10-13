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

import brand
from mykey import MIN_GENERATED_PASSWORD_LENGTH, MyKey, MyKeyError, make_entry


def _print_entry(e):
    print(f"- {e['service']}  user={e['username'] or '-'}  url={e['url'] or '-'}"
          f"{'  ★' if e['favourite'] else ''}")


def main():
    p = argparse.ArgumentParser(
        description=f"{brand.PRODUCT_NAME}: {brand.PRODUCT_TAGLINE}"
    )
    p.add_argument("action", choices=[
        "gen", "get", "add", "list", "search", "edit", "delete",
        "import", "export", "totp", "recovery-setup", "recovery-unlock",
        "recovery-rotate", "change-master",
        # Phase 2A agent surfaces. agent-get/agent-list are the AGENT
        # principal (token from env, no master prompt); the rest are
        # human-only registry management after a master unlock.
        "agent-get", "agent-list",
        "agent-enroll", "agent-revoke", "agent-disable", "agent-enable",
        "agents", "agent-audit", "agent-audit-reset",
        "rotate-vault-key",
    ])
    p.add_argument("--agent-id", help="Agent id (agent-enroll/-revoke/...)")
    p.add_argument("--scopes", default="",
                   help="Comma-separated agent scopes, e.g. list,get:github")
    p.add_argument("--expires-days", type=int,
                   help="Agent token lifetime in days (default: no expiry)")
    p.add_argument("--service")
    p.add_argument("--username", default="")
    p.add_argument("--url", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--password", help="New password value (edit action)")
    p.add_argument("--len", type=int, default=16)
    p.add_argument("--kdf", choices=["argon2id", "pbkdf2"], default="argon2id")
    p.add_argument("--vault", default="vault.mykey")
    p.add_argument("--file", help="Import/export file path")
    p.add_argument("--format", help="Import format (auto-detected if omitted)")
    p.add_argument("--on-conflict", choices=["skip", "overwrite", "keep_both"],
                   default="skip")
    p.add_argument("--dry-run", action="store_true", help="Import preview only")
    p.add_argument("--query", default="")
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

        if args.action == "recovery-unlock":
            phrase = getpass.getpass("Recovery phrase: ")
            probe = MyKey("recovery-probe-0000", vault_file=args.vault)
            entries = probe.unlock_via_recovery(phrase)
            print(f"✅ Recovery phrase unlocks this vault ({len(entries)} entries).")
            return 0

        master = getpass.getpass("Enter Master Password: ")
        app = MyKey(master, algo=args.kdf, vault_file=args.vault)

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
                    print(f"🤖 Agent '{args.agent_id}' enrolled. Token (shown ONCE, "
                          "store it in the agent's environment as MYKEY_AGENT_KEY):")
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
            pwd = getpass.getpass(f"Password for {args.service} (your existing one): ")
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
            for e in entries:
                _print_entry(e)
            print(f"({len(entries)} entries)")
        elif args.action == "search":
            for e in app.search_entries(args.query):
                _print_entry(e)
        elif args.action == "edit":
            fields = {}
            if args.password is not None:
                fields["password"] = args.password
            if args.url:
                fields["url"] = args.url
            if args.notes:
                fields["notes"] = args.notes
            app.update_entry(args.service, args.username or None, **fields)
            print(f"✅ Updated {args.service}.")
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
            new_master = getpass.getpass("New Master Password: ")
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
