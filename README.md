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
    **🍁100% Canadian Built🍁**: Developed with a focus on digital sovereignty.
    
    
🛠️ Installation
```bash
# Clone and Setup
git clone https://g
cd mykey
python setup_mykey.
python mykey_gui.py

# Clone the repository
git clone https://github.com
cd mykey

# Install dependencies
pip install cryptography argon2-cffi pyperclip
# Run
python mykey_gui.py

Use code with caution.
🚀 Usage
    Launch: Run python mykey_gui.py.
    Authenticate: Enter your Master Password. (Note: If you lose this and your recovery key, the data is gone forever).
    Generate: Enter a service name (e.g., "GitHub") and click Generate & Save.
    Retrieve: Type the service name and click Retrieve. Use the 👁️ icon to toggle visibility.

# Security Policy
If you find a vulnerability, please do not open a public issue. 
Email the maintainer directly at [nrupalakolkar@gmail.com] to ensure a coordinated fix.
