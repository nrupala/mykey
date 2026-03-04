import os, json, base64, secrets, string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level

class MyKey:
    def __init__(self, secret_input, algo="argon2id"):
        self.vault_file = "vault.mykey"
        self.secret_input = secret_input
        self.algo = algo

    def _derive_key(self, salt, algo):
        try:
            if algo == "argon2id":
                return low_level.hash_secret_raw(
                    secret=self.secret_input.encode(),
                    salt=salt,
                    time_cost=3, memory_cost=65536, parallelism=4,
                    hash_len=32, type=low_level.Type.ID
                )
            else:
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
                return kdf.derive(self.secret_input.encode())
        except Exception:
            return None

    def generate_password(self, length=16):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def save_password(self, service, password):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt, self.algo)
        
        # Load existing, update, then encrypt
        vault_data = self._read_physical_vault()
        if isinstance(vault_data, str): vault_data = {} # Reset if corrupted
        
        vault_data[service] = password
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(vault_data).encode(), None)

        full_data = {
            "algo": self.algo,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        with open(self.vault_file, "w") as f:
            json.dump(full_data, f)

    def _read_physical_vault(self):
        if not os.path.exists(self.vault_file): return {}
        try:
            with open(self.vault_file, "r") as f:
                data = json.load(f)
            
            key = self._derive_key(base64.b64decode(data["salt"]), data["algo"])
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(base64.b64decode(data["nonce"]), 
                                       base64.b64decode(data["ciphertext"]), None)
            return json.loads(decrypted)
        except Exception:
            return "❌ Access Denied: Wrong Password."

    def get_password(self, service):
        vault = self._read_physical_vault()
        if isinstance(vault, str): return vault
        return vault.get(service, "❌ Not Found.")

    def export_vault_to_csv(self):
        vault = self._read_physical_vault()
        if isinstance(vault, str) or not vault: return False, "Auth Failed"
        import csv
        with open("mykey_export.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Service", "Password"])
            for k, v in vault.items(): writer.writerow([k, v])
        return True, "Exported!"
