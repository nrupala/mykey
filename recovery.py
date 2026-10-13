# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
#
# This file is part of the MyKey proprietary core (vault engine,
# cryptography, recovery and unlock mechanisms). It is NOT licensed
# under Apache 2.0, MIT, or any other open licence. No patent licence
# is granted by this file; all patent rights are expressly reserved.
# See LICENSING.md for the licence map.

"""Real BIP-39 recovery for MyKey (Phase 1).

Replaces the Phase-0-era stub (24 words, ~55 bits, wired to nothing)
with the full BIP-39 specification:

* the complete 2048-word English wordlist (vendored as
  ``bip39_english.txt`` from the BIP-39 specification),
* entropy of 128–256 bits with the BIP-39 checksum (first
  ENT/32 bits of SHA-256(entropy)) encoded in the final word(s),
* checksum verification on decode — a mistyped or invented phrase is
  rejected, never silently accepted,
* seed derivation per BIP-39 (PBKDF2-HMAC-SHA512, 2048 rounds), and
* a recovery wrapping key derived from the seed with Argon2id, used by
  the vault engine to wrap/unwrap the Vault v2 vault key.
"""

import hashlib
import os
import secrets
import unicodedata

from argon2 import low_level
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def _wordlist_candidates():
    here = os.path.dirname(os.path.abspath(__file__))
    yield os.path.join(here, "bip39_english.txt")
    yield os.path.join(os.sys.prefix, "share", "mykey", "bip39_english.txt")
    yield os.path.join(os.getcwd(), "bip39_english.txt")


def _load_wordlist():
    path = next((p for p in _wordlist_candidates() if os.path.exists(p)), None)
    if path is None:
        raise RuntimeError("bip39_english.txt not found next to recovery.py")
    with open(path, encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048 or len(set(words)) != 2048:
        raise RuntimeError("BIP-39 wordlist is corrupt: expected 2048 unique words")
    return words


WORDLIST = _load_wordlist()
_INDEX = {w: i for i, w in enumerate(WORDLIST)}
_VALID_STRENGTHS = (128, 160, 192, 224, 256)


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) * 8 not in _VALID_STRENGTHS:
        raise ValueError("entropy must be 128–256 bits in 32-bit steps")
    checksum_len = len(entropy) * 8 // 32
    digest = hashlib.sha256(entropy).digest()
    checksum = int.from_bytes(digest, "big") >> (256 - checksum_len)
    bits = (int.from_bytes(entropy, "big") << checksum_len) | checksum
    total = len(entropy) * 8 + checksum_len
    words = []
    for i in range(total // 11):
        shift = total - 11 * (i + 1)
        words.append(WORDLIST[(bits >> shift) & 0x7FF])
    return " ".join(words)


def generate_mnemonic(strength: int = 128) -> str:
    """Generate a BIP-39 mnemonic. Default 128 bits (12 words)."""
    if strength not in _VALID_STRENGTHS:
        raise ValueError(f"strength must be one of {_VALID_STRENGTHS}")
    return entropy_to_mnemonic(secrets.token_bytes(strength // 8))


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    words = unicodedata.normalize("NFKD", mnemonic).strip().split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must be 12, 15, 18, 21 or 24 words")
    bits = 0
    for word in words:
        if word not in _INDEX:
            raise ValueError(f"word not in BIP-39 wordlist: {word!r}")
        bits = (bits << 11) | _INDEX[word]
    total = len(words) * 11
    checksum_len = total // 33
    entropy_len = total - checksum_len
    entropy = (bits >> checksum_len).to_bytes(entropy_len // 8, "big")
    digest = hashlib.sha256(entropy).digest()
    expected = int.from_bytes(digest, "big") >> (256 - checksum_len)
    actual = bits & ((1 << checksum_len) - 1)
    if actual != expected:
        raise ValueError("mnemonic checksum mismatch — phrase is mistyped or invalid")
    return entropy


def validate_mnemonic(mnemonic: str) -> bool:
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except Exception:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 rounds. Validates first."""
    mnemonic_to_entropy(mnemonic)  # raises on a bad phrase
    normalized = unicodedata.normalize("NFKD", mnemonic)
    salt = "mnemonic" + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", normalized.encode(), salt.encode(), 2048, dklen=64)


def derive_recovery_key(mnemonic: str, salt: bytes) -> bytes:
    """Derive the 32-byte recovery wrapping key for a vault slot."""
    seed = mnemonic_to_seed(mnemonic)
    return low_level.hash_secret_raw(
        secret=seed, salt=salt, time_cost=3, memory_cost=65536,
        parallelism=4, hash_len=32, type=low_level.Type.ID,
    )


def recovery_backup_keypair(mnemonic: str, vault_id: str):
    """Deterministic X25519 keypair for backup packages (Phase 3A).

    Returns (private_raw, public_raw). Re-derivable from the
    recovery phrase alone, per vault: the BIP-39 seed passes
    through Argon2id with a per-vault salt, so (a) offline checking
    of phrase guesses against the public key costs a memory-hard
    derivation per guess, and (b) keys are domain-separated per
    vault — reusing one phrase across vaults does not link their
    backup keys. Anyone holding the phrase holds this key: it is
    exactly as strong as the phrase, by design.
    """
    seed = mnemonic_to_seed(mnemonic)  # validates the phrase
    salt = hashlib.sha256(
        b"mkbak-recovery-v1:" + vault_id.encode()).digest()[:16]
    raw = low_level.hash_secret_raw(
        secret=seed, salt=salt, time_cost=3, memory_cost=65536,
        parallelism=4, hash_len=32, type=low_level.Type.ID,
    )
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw, pub


if __name__ == "__main__":
    phrase = generate_mnemonic()
    print("\n📝 YOUR EMERGENCY RECOVERY PHRASE:")
    print("------------------------------------")
    print(phrase)
    print("------------------------------------")
    print("⚠️  Write this down and keep it in a safe. Do not save it digitally.")
