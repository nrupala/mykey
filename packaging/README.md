# Desktop packaging

Ready-made downloads live on the repo's
[Releases page](https://github.com/nrupala/mykey/releases).
This folder holds the build inputs for making them.

## Build it yourself

PyInstaller does not cross-compile — run the script on the platform
you want binaries for:

```bash
python -m venv .build-venv
.build-venv/bin/pip install pyinstaller -r requirements.txt   # Windows: .build-venv\Scripts\pip
.build-venv/bin/python packaging/build_desktop.py              # Windows: .build-venv\Scripts\python
```

Outputs in `packaging/dist/`:

| Platform | App | CLI |
|---|---|---|
| Windows | `MyKey.exe` | `mykey-cli.exe` |
| Linux | `MyKey` | `mykey-cli` |
| macOS | `MyKey.app` | `mykey-cli` |

`mykey.desktop` is the Linux launcher shipped in the Linux bundle.

## App icon

The brand masters live in `packaging/assets/` (`logo-tile.svg`,
`logo-key.svg` — the refined-key mark on navy #111D54), with rendered
`icon.ico` (Windows), `icon.icns` (macOS) and `icon.png` beside them.
`build_desktop.py` passes the platform icon to PyInstaller for the
GUI build on Windows and macOS. The Linux bundle keeps the themed
`Icon=dialog-password` in `mykey.desktop` until the bundle step
installs `icon.png` into an icon-theme path alongside the launcher.

## Signing status — read this before distributing

The release builds are **unsigned**. There is no code-signing
certificate yet (buying one is the owner's call).

- **Windows:** SmartScreen shows "Windows protected your PC" on
  first run; the release notes tell users to click *More info → Run
  anyway*, and publish SHA-256 sums so a download can be verified.
- **macOS:** the build script produces `MyKey.app` on a Mac, but
  without a Developer ID certificate and notarization Gatekeeper
  will block a downloaded copy. That is why there is **no macOS
  download yet** — script only, until a certificate exists. Do not
  ship a `.dmg` built any other way and call it ready.
- **Linux:** no signing convention applies; the tarball ships with
  SHA-256 sums.

## Release checklist (what the v2.2.0 wave did)

1. Build on each target platform from a clean checkout.
2. Smoke-test the packaged binaries (never the source): open a
   fixture vault, read a fixture entry, confirm an out-of-scope
   agent read is refused and a wrong master password is refused;
   launch the GUI binary and confirm it stays up; run a
   recovery-phrase setup round trip to prove the bundled BIP-39
   wordlist loads frozen.
3. Run the source test suite in a fresh venv.
4. Attach the binaries + `SHA256SUMS.txt` to the GitHub release
   and verify each asset downloads byte-identical (sha256 match).
