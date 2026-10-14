#!/usr/bin/env python3
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

"""Build the MyKey desktop binaries with PyInstaller.

One script for every desktop platform — run it on the machine whose
binaries you want (PyInstaller does not cross-compile):

    python -m venv .build-venv
    .build-venv/bin/pip install pyinstaller -r requirements.txt   # (Scripts\\ on Windows)
    .build-venv/bin/python packaging/build_desktop.py

Outputs land in packaging/dist/:

  * GUI app  -- MyKey            (MyKey.exe on Windows, MyKey.app on macOS)
  * CLI tool -- mykey-cli        (mykey-cli.exe on Windows)

Both are single-file builds. The BIP-39 wordlist (bip39_english.txt)
is bundled next to the frozen modules, which is exactly where
recovery.py looks for it.

Signing: these builds are UNSIGNED. A signed build needs a code
-signing certificate on the build machine (Windows: signtool +
Authenticode cert; macOS: Developer ID + notarization). Until then,
Windows shows a SmartScreen prompt and macOS Gatekeeper requires an
explicit open — the README Download section says so in plain words.

macOS note: run this script on an Apple-silicon (or Intel) Mac. It
produces MyKey.app in packaging/dist/. There is no .dmg step and no
signing/notarization here — bundle the .app into a zip for download.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "packaging", "dist")
WORK = os.path.join(ROOT, "packaging", "build")
SPEC = os.path.join(ROOT, "packaging", "spec")


def build(entry, name, windowed, icon=None):
    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--clean", "--noconfirm",
        "--name", name,
        "--distpath", DIST, "--workpath", WORK, "--specpath", SPEC,
        "--add-data", os.path.join(ROOT, "bip39_english.txt") + os.pathsep + ".",
    ]
    if icon:
        args += ["--icon", icon]
    if windowed and sys.platform in ("win32", "darwin"):
        args.append("--windowed")
    args.append(os.path.join(ROOT, entry))
    print("+", " ".join(args))
    subprocess.run(args, check=True, cwd=ROOT)


# App icon per platform, from the brand masters in packaging/assets/
# (logo-tile.svg / logo-key.svg — the refined-key mark, navy #111D54).
ICON_FILES = {"win32": "icon.ico", "darwin": "icon.icns"}


def main():
    os.makedirs(DIST, exist_ok=True)
    icon = None
    icon_name = ICON_FILES.get(sys.platform)
    if icon_name:
        candidate = os.path.join(ROOT, "packaging", "assets", icon_name)
        if os.path.exists(candidate):
            icon = candidate
    build("mykey_gui.py", "MyKey", windowed=True, icon=icon)
    build("mykey_cli.py", "mykey-cli", windowed=False)
    print("\nBuilt into", DIST)
    for f in sorted(os.listdir(DIST)):
        print(" -", f)


if __name__ == "__main__":
    main()
