#!/usr/bin/env python3
"""
Roundcube/3DES password decryptor

Usage:
  1) Install dependency: pip install pycryptodome
  2) Run: python3 roundcube_des_decryptor.py
  3) When prompted, paste the Base64 "password" value from the session table,
     the auth_secret (if you have it), and the DES key from Roundcube config.

This script implements the common Roundcube decryption pattern: Base64 decode the stored password, split the first 8 bytes as the IV,
use the remaining bytes as the 3DES ciphertext, and decrypt with the DES key.

The script tries the provided DES key first. If that fails and an auth_secret is
provided, it will try the auth_secret as an alternate key.

Note about keys: 3DES expects a 16 or 24 byte key. The script will automatically
pad short keys with null bytes and truncate long keys to 24 bytes.

This is a best-effort tool for forensic or learning purposes only. Use it only on
systems you own or have explicit permission to test.
"""

import base64
import sys
from getpass import getpass

try:
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import unpad
except Exception as e:
    print("Missing dependency. Install pycryptodome: pip install pycryptodome")
    raise


def normalize_key(key_bytes: bytes) -> bytes:
    """Ensure the key is 16 or 24 bytes for DES3 by padding or truncating.

    If length is 16, it is a valid two-key 3DES key. If not, we pad/truncate to 24.
    """
    if len(key_bytes) == 16 or len(key_bytes) == 24:
        return key_bytes
    if len(key_bytes) < 24:
        return key_bytes.ljust(24, b"\x00")
    return key_bytes[:24]


def try_decrypt(enc_b64: str, key_str: str) -> str:
    """Attempt to decrypt and return plaintext string on success, or raise."""
    raw = base64.b64decode(enc_b64)
    if len(raw) <= 8:
        raise ValueError("Decoded data too short: need at least 9 bytes (8-byte IV + ciphertext)")

    iv = raw[:8]
    ciphertext = raw[8:]

    key_bytes = normalize_key(key_str.encode("utf-8"))

    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    # Roundcube uses PKCS#7-like padding for 3DES in many builds. Try to unpad.
    try:
        plain = unpad(decrypted, 8)
    except ValueError:
        # If unpad fails, fall back to stripping trailing nulls and whitespace
        plain = decrypted.rstrip(b"\x00\r\n \t")

    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        # return a hex representation if decoding fails
        return plain.hex()


def main():
    print("Roundcube 3DES decryptor tool")
    print()

    enc = input("Enter encrypted password (base64): ").strip()
    if not enc:
        print("Encrypted password required. Exiting.")
        sys.exit(1)

    auth_secret = input("Enter auth_secret (optional, press Enter to skip): ").strip()
    des_key = getpass("Enter DES key (will be hidden): ").strip()
    if not des_key:
        print("DES key required. Exiting.")
        sys.exit(1)

    # Try primary key first
    try:
        res = try_decrypt(enc, des_key)
        print("\nDecrypted password:\n", res)
        return
    except Exception as e:
        print("First attempt failed:", str(e))

    # If user provided auth_secret, try that next
    if auth_secret:
        print("Trying auth_secret as key...")
        try:
            res = try_decrypt(enc, auth_secret)
            print("\nDecrypted password (using auth_secret as key):\n", res)
            return
        except Exception as e:
            print("Second attempt failed:", str(e))

    print("\nAll attempts failed. Confirm the inputs are correct and the encrypted value"
          " is indeed a Roundcube-style 3DES blob.")


if __name__ == '__main__':
    main()
