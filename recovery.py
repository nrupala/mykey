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

import secrets

# A small sample of the BIP-39 wordlist (20 words for demo)

WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", 
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", 
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual"
]

def generate_mnemonic(count=12):
    """Generates a user-friendly 12-word recovery phrase."""
    return " ".join(secrets.choice(WORDLIST) for _ in range(count))

if __name__ == "__main__":
    print("\n📝 YOUR EMERGENCY RECOVERY PHRASE:")
    print("------------------------------------")
    print(generate_mnemonic())
    print("------------------------------------")
    print("⚠️  Write this down and keep it in a safe. Do not save it digitally.")
