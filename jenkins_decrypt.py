#!/usr/bin/env python3
import sys
import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def derive_conf_key(master_path, hudson_path):
    with open(master_path, 'rb') as f:
        master_key = f.read().strip()
    master_aes = hashlib.sha256(master_key).digest()[:16]

    with open(hudson_path, 'rb') as f:
        hudson_data = f.read()[:32]   # only first 1-2 blocks needed

    # Ensure block alignment (fixes the ECB boundary error)
    hudson_data = hudson_data[:len(hudson_data) & ~0xF]

    cipher = AES.new(master_aes, AES.MODE_ECB)
    decrypted = cipher.decrypt(hudson_data)
    conf_key = decrypted[:16]
    print(f"[+] Derived confidentiality key (hex): {conf_key.hex()}")
    return conf_key

def decrypt_secret(conf_key, encrypted_b64):
    try:
        encrypted = base64.b64decode(encrypted_b64)
        cipher = AES.new(conf_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8', errors='ignore').strip()
    except Exception as e:
        return f"[ERROR decrypting] {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 jenkins_decrypt.py <master.key> <hudson.util.Secret.trim.bin>")
        sys.exit(1)

    master = sys.argv[1]
    hudson = sys.argv[2]

    conf_key = derive_conf_key(master, hudson)

    print("\n=== Paste one base64 secret (AQ...=) at a time ===")
    print("Type 'quit' or Ctrl+C to stop.\n")

    while True:
        try:
            blob = input("Base64 secret: ").strip()
            if not blob or blob.lower() in ['quit', 'exit']:
                break
            if not blob.startswith('AQ'):
                print("Warning: Doesn't look like a Jenkins encrypted blob (should start with AQ)")
            plain = decrypt_secret(conf_key, blob)
            print(f"→ Decrypted: {plain}\n")
        except KeyboardInterrupt:
            print("\nDone.")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
