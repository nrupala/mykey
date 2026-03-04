# 📽️ mykey: Presentation Deck

---
## 🎯 The Problem
Standard password managers sync to the cloud. If their server is hacked, your "Zero Trust" is gone.
---
## 🛡️ The Solution: mykey
- **Local-Only**: Your vault never touches the internet.
- **Argon2id**: Brute-force resistant encryption.
- **Custom UI**: Dark, Light, and Sepia modes for user comfort.
---
## 🎨 Theme Preview
- **Dark Mode**: High contrast for developers.
- **Sepia**: Soft tones for long-session security audits.
- **Light Mode**: Clean, system-native look.
---
## 🛠️ Security Architecture
1. **Master Password** -> Argon2id Key Derivation
2. **Key** -> AES-256-GCM Encryption
3. **Vault** -> Local JSON Binary Storage
