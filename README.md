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
