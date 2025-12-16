import os
import json
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
FILENAME = "passwords.vault"

# KEY MANAGER
def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Deriva una chiave a 32 byte dalla password usando PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

# CRYPTO ENGINE
def encrypt_data(key: bytes, plaintext_dict: dict) -> tuple[bytes, bytes, bytes]:
    """Trasforma il dizionario in bytes cifrati."""
    json_str = json.dumps(plaintext_dict)
    data_bytes = json_str.encode('utf-8') 
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data=None)
    
    return nonce, ciphertext

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    """Trasforma i bytes cifrati in dizionario."""
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    
    json_str = plaintext_bytes.decode('utf-8')
    return json.loads(json_str)

# STORAGE MANAGER
def save_vault(data: dict, password: str):
    """Salva su disco: Salt + Nonce + Ciphertext"""
    try:
        key, salt = derive_key(password, salt=None)
        nonce, ciphertext = encrypt_data(key, data)
        
        with open(FILENAME, 'wb') as f:
            f.write(salt)       # 16 bytes
            f.write(nonce)      # 12 bytes
            f.write(ciphertext) # Rest of the File
            
    except Exception as e:
        print(f"ERRORE CRITICO salvataggio: {e}")

def load_vault(password: str) -> dict:
    """Carica dal disco e decifra."""
    if not os.path.exists(FILENAME):
        print("! Creating new Vault...")
        return {}
    
    try:
        with open(FILENAME, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()
            
        key, _ = derive_key(password, salt)
        data = decrypt_data(key, nonce, ciphertext)
        return data
        
    except Exception:
        print("\n[!] ERROR.")
        return None

# MAIN INTERFACE
def main():

    asci_name = r"""
┌─────────────────────────────────────────────┐
│    ____  ______ __      __ _____  ______    │
│   / ___)(   __ \) \    / ((  __ \(_  __ \   │
│  / /     ) (__) )\ \  / /  ) )_) ) ) ) \ \  │
│ ( (     (    __/  \ \/ /  (  ___/ ( (   ) ) │
│ ( (      ) \ \  _  \  /    ) )     ) )  ) ) │
│  \ \___ ( ( \ \_))  )(    ( (     / /__/ /  │
│   \____) )_) \__/  /__\   /__\   (______/   │
└─────────────────────────────────────────────┘                                                                                                                                                 
"""
    print(asci_name)
    
    password = getpass.getpass("# Insert Master Password: ")
    
    vault = load_vault(password)

    print(f"\n# Saved Passwords: {len(vault)}")

    if vault is None:
        return

    print("\n[1] Search Service")
    print("[2] Add Service")
    print("[3] Delete Service")
    print("[4] Show Services")
    print("[q] Exit")

    while True:
        
        choice = input("\n>> ").strip().lower()
        
        if choice == '1' or choice == 'search':
            service = input("\n# Service Name: ")
            if service in vault:
                print(f"# Password: {vault[service]}")
            else:
                print("! Service not Found.")
                
        elif choice == '2' or choice == 'add':
            service = input("\n# Service Name: ")
            pwd = input(f"# Password for {service}: ")

            vault[service] = pwd
            save_vault(vault, password)
            print("! Service Created.")
            
        elif choice == '3' or choice == 'delete':
            service = input("\n# Service Name: ")
            if service in vault:
                del vault[service]
                save_vault(vault, password)
                print("! Service Deleted.")
            else:
                print("! Service not Found.")

        elif choice == '4' or choice == 'show':
            print(f"\n# All Services ({len(vault)}):\n", list(vault.keys()))
            
        elif choice == 'q' or choice == 'exit':
            break
        else:
            print("! Invalid Command.")

if __name__ == "__main__":
    main()
