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

import os
import subprocess
import sys

def setup():
    print("🚀 Initializing mykey: Zero-Trust Environment...")

    # 1. Create .gitignore to prevent accidental vault uploads
    gitignore_content = """# Local Vault (CRITICAL)
vault.mykey
salt.bin
mykey_export.csv

# Python environment & cache
__pycache__/
*.py[cod]
venv/
.env

# OS files
.DS_Store
Thumbs.db
"""
    with open(".gitignore", "w") as f:
        f.write(gitignore_content)
    print("✅ Created .gitignore")

    # 2. Create Requirements file
    requirements = "cryptography\nargon2-cffi\npyperclip\n"
    with open("requirements.txt", "w") as f:
        f.write(requirements)
    print("✅ Created requirements.txt")

    # 3. Install dependencies
    print("📦 Installing NIST-compliant cryptographic libraries...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully.")
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")

    # 4. Create dummy README if not exists
    if not os.path.exists("README.md"):
        with open("README.md", "w") as f:
            f.write("# mykey\nZero-Trust Password Manager. Run `mykey_gui.py` to start.")
        print("✅ Created basic README.md")

    print("\n🎉 Setup Complete! You can now run 'python mykey_gui.py'")

if __name__ == "__main__":
    setup()
