# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

import pytest

from recovery import (
    WORDLIST,
    derive_recovery_key,
    entropy_to_mnemonic,
    generate_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
    validate_mnemonic,
)


def test_wordlist_is_full_bip39():
    assert len(WORDLIST) == 2048
    assert len(set(WORDLIST)) == 2048
    assert WORDLIST[0] == "abandon"
    assert WORDLIST[-1] == "zoo"


def test_bip39_known_vector_zero_entropy():
    # BIP-39 test vector: 128 bits of 0x00.
    phrase = entropy_to_mnemonic(bytes(16))
    assert phrase == " ".join(["abandon"] * 11 + ["about"])
    assert mnemonic_to_entropy(phrase) == bytes(16)


def test_bip39_known_vector_ff_entropy():
    # BIP-39 test vector: 128 bits of 0xff.
    phrase = entropy_to_mnemonic(b"\xff" * 16)
    assert phrase == " ".join(["zoo"] * 11 + ["wrong"])
    assert mnemonic_to_entropy(phrase) == b"\xff" * 16


def test_generated_phrases_are_valid_and_strong_enough():
    for strength in (128, 256):
        phrase = generate_mnemonic(strength)
        assert validate_mnemonic(phrase)
        assert len(mnemonic_to_entropy(phrase)) * 8 == strength
    assert len(generate_mnemonic(128).split()) == 12
    assert len(generate_mnemonic(256).split()) == 24


def test_bad_checksum_rejected():
    words = generate_mnemonic().split()
    words[-1] = "zoo" if words[-1] != "zoo" else "abandon"
    tampered = " ".join(words)
    if validate_mnemonic(tampered):
        pytest.skip("tamper accidentally produced a valid checksum")
    with pytest.raises(ValueError):
        mnemonic_to_entropy(tampered)


def test_non_wordlist_word_rejected():
    with pytest.raises(ValueError):
        mnemonic_to_entropy("abandon " * 11 + "notaword")


def test_recovery_key_is_deterministic_and_salt_bound():
    phrase = generate_mnemonic()
    salt = b"1234567812345678"
    k1 = derive_recovery_key(phrase, salt)
    k2 = derive_recovery_key(phrase, salt)
    k3 = derive_recovery_key(phrase, b"8765432187654321")
    assert k1 == k2 and len(k1) == 32 and k1 != k3


def test_seed_matches_bip39_vector():
    # BIP-39 reference vector (TREZOR): abandon x11 + about, passphrase "TREZOR".
    phrase = " ".join(["abandon"] * 11 + ["about"])
    seed = mnemonic_to_seed(phrase, "TREZOR")
    assert seed.hex() == (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )
