# MIT License
#
# Copyright (c) 2026 Nrupal Akolkar
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

import argparse
import getpass
import sys

from mykey import (
    MIN_GENERATED_PASSWORD_LENGTH,
    MyKey,
    MyKeyError,
)


def main():
    parser = argparse.ArgumentParser(description="mykey: Zero-Trust Password Manager")
    parser.add_argument("action", choices=["gen", "get", "add"], help="Action to perform")
    parser.add_argument("--service", help="The service name (e.g., github)")
    parser.add_argument(
        "--len", type=int, default=16, help="Password length (minimum 16)"
    )
    parser.add_argument("--kdf", choices=["argon2id", "pbkdf2"], default="argon2id")
    args = parser.parse_args()

    if args.action == "gen" and args.len < MIN_GENERATED_PASSWORD_LENGTH:
        print(
            f"❌ Error: --len must be at least {MIN_GENERATED_PASSWORD_LENGTH}.",
            file=sys.stderr,
        )
        return 2

    master = getpass.getpass("Enter Master Password: ")
    try:
        app = MyKey(master, algo=args.kdf)
        if args.action == "gen":
            pw = app.generate_password(args.len)
            if args.service:
                app.save_password(args.service, pw)
                print(f"✅ Generated and saved for {args.service}: {pw}")
            else:
                print(f"✨ Generated: {pw}")
        elif args.action == "get":
            if not args.service:
                print("❌ Error: --service required for 'get' action.", file=sys.stderr)
                return 2
            print(f"🔑 Password for {args.service}: {app.get_password(args.service)}")
        elif args.action == "add":
            if not args.service:
                print("❌ Error: --service required for 'add' action.", file=sys.stderr)
                return 2
            pwd = getpass.getpass(f"Enter password for {args.service}: ")
            app.save_password(args.service, pwd)
            print(f"💾 Saved {args.service} to vault.")
    except KeyError as exc:
        print(f"❌ Not Found. {exc}", file=sys.stderr)
        return 1
    except (MyKeyError, ValueError) as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
