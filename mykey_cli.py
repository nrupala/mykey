import argparse
import getpass
from mykey import MyKey

def main():

    parser = argparse.ArgumentParser(description="mykey: Zero-Trust Password Manager")
    parser.add_argument("action", choices=["gen", "get", "add"], help="Action to perform")
    parser.add_argument("--service", help="The service name (e.g., github)")
    parser.add_argument("--len", type=int, default=16, help="Password length (NIST/CISA min 12-16)")
    # snippet for mykey_cli.py
    parser.add_argument("--kdf", choices=["argon2id", "pbkdf2"], default="argon2id")
    
    args = parser.parse_args()
    master = getpass.getpass("Enter Master Password: ")
    
    #app = MyKey(master)
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
            print("❌ Error: --service required for 'get' action.")
            return
        print(f"🔑 Password for {args.service}: {app.get_password(args.service)}")

    elif args.action == "add":
        pwd = getpass.getpass(f"Enter password for {args.service}: ")
        app.save_password(args.service, pwd)
        print(f"💾 Saved {args.service} to vault.")

if __name__ == "__main__":
    main()
