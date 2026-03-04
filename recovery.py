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
