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
    ])
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
        if args.action == "recovery-unlock":
            phrase = getpass.getpass("Recovery phrase: ")
            probe = MyKey("recovery-probe-0000", vault_file=args.vault)
            entries = probe.unlock_via_recovery(phrase)
            print(f"✅ Recovery phrase unlocks this vault ({len(entries)} entries).")
            return 0

        master = getpass.getpass("Enter Master Password: ")
        app = MyKey(master, algo=args.kdf, vault_file=args.vault)

        if args.action == "gen":
            pw = app.generate_password(args.len)
            if args.service:
                app.save_password(args.service, pw, username=args.username,
                                  url=args.url, notes=args.notes)
                print(f"✅ Generated and saved for {args.service}: {pw}")
            else:
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
