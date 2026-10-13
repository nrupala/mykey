🗝️ mykey: Zero-Trust Password Manager
**NIST 800-63B & CISA compliant offline vault**
"Secure Our World" Compliant
mykey is a stateless, local-first password generator and vault. It ensures that your master password and secrets never leave your machine. It is a Python-based, zero-knowledge password generator and manager. It utilizes Argon2id for key derivation and AES-256-GCM for authenticated local encryption.

🌟 Key Features
    **Argon2id KDF**: NIST-preferred key derivation to resist GPU brute-force attacks.
     **CISA Compliant**: Enforces 16-character minimum entropy.
    AES-256-GCM: Authenticated encryption for the local vault.
    Zero-Knowledge: No cloud, no tracking, no "Forgot Password" backdoors.
    Secure Clipboard: Auto-wipes your clipboard 60 seconds after copying.
    Emergency Recovery: BIP-39 style recovery key support.
    Sync & Backup (2.1–2.2): conflict-safe sync through your own cloud folder, device keys, and portable encrypted backup packages openable by your devices or — outside the app, with two factors — your recovery phrase plus a one-time backup code; key-value pairing decides which cloud/export targets receive blobs — see SYNC_BACKUP.md for the design, security model and exact limitations.
    Password Rotation: every entry remembers when its password was set and when it should change — see below.
    **🍁100% Canadian Built🍁**: Developed with a focus on digital sovereignty.
    
    
🛠️ Installation
```bash
git clone https://github.com/nrupala/mykey
cd mykey
pip install -r requirements.txt
python mykey_gui.py
```

Or install dependencies directly:

```bash
pip install cryptography argon2-cffi pyperclip
```


🚀 Usage
    Launch: Run python mykey_gui.py.
    Authenticate: Enter your Master Password. (Note: If you lose this and your recovery key, the data is gone forever).
    Generate: Enter a service name (e.g., "GitHub") and click Generate & Save.
    Retrieve: Type the service name and click Retrieve. Use the 👁️ icon to toggle visibility.

🔄 Password rotation
    MyKey records the day each password was set — automatically when you add an entry or change its password, and never when you only edit notes, tags or other details. Each entry shows plain words: "Password set 13 Oct 2026 · change by 11 Apr 2027".
    Out of the box, passwords are due for a change after 180 days. You can change that default for the whole vault, give a single entry its own period, or turn rotation off for an entry or for the vault — the choice is yours, per password.
    Nothing nags you: when you unlock, a calm count shows how many passwords are due, and the rotation view (CLI: `rotation`; GUI: Vault → Password rotation) lists what is due soon or overdue. Changed a password on the website itself? "Mark as changed today" (CLI: `mark-changed`) restarts that entry's clock without touching the stored password.
    The dates live inside the encrypted vault, next to the passwords themselves — never in a separate readable file. Notifications are not sent in this version.

# Security Policy
If you find a vulnerability, please do not open a public issue. 
Email the maintainer directly at [nrupalakolkar@gmail.com] to ensure a coordinated fix.
