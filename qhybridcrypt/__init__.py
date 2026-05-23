"""
Q-HybridCrypt v2.0 "PHOENIX"
Quantum-Resistant Hybrid Cryptographic Library

A production-grade cryptographic library combining:
- Real Module-LWE Key Encapsulation (quantum-resistant)
- Triple-Cascade Encryption (ChaCha20 -> AES-256-GCM -> SHA3-Keystream)
- Argon2id Password Hashing with real Blake2b
- Fujisaki-Okamoto CCA2 Transform
- Triple Authentication (Poly1305 + GCM + HMAC-SHA3)
- Migration SDK for seamless transition from other libraries

Security: ~192-bit classical, ~128-bit quantum (NIST Level 3)

Quick Start:
    from qhybridcrypt import QHybridCrypt

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    ciphertext = crypto.encrypt(b"secret data", public_key)
    plaintext = crypto.decrypt(ciphertext, private_key)

    # Password hashing
    password_hash, salt = crypto.hash_password("my_password")
    is_valid = crypto.verify_password("my_password", salt, password_hash)

    # Migration from other libraries
    from qhybridcrypt.migration import migrate_from
    new_ct, pk = migrate_from('pycryptodome', old_ct, my_decrypt_fn)
"""

from .core import QHybridCrypt, encrypt_message, decrypt_message, generate_keypair
from .utils import constant_time_compare
from .entropy import secure_random_bytes
from .constants import PROTOCOL_VERSION

__version__ = "2.0.0"
__author__ = "Q-HybridCrypt Development Team"
__codename__ = "PHOENIX"

__all__ = [
    "QHybridCrypt",
    "encrypt_message",
    "decrypt_message",
    "generate_keypair",
    "secure_random_bytes",
    "constant_time_compare",
    "migration",
]
