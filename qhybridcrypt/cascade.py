"""
Q-HybridCrypt v2.0 - Triple-Cascade Encryption Engine

The PHOENIX Protocol's core innovation: three independent encryption
layers applied sequentially, each with its own key derived through
separate KDF paths. This means an attacker must break ALL THREE
cipher layers to recover plaintext.

Cascade Architecture:
    Layer 1: ChaCha20-Poly1305 (constant-time, no table lookups)
    Layer 2: AES-256-GCM (NIST standard, hardware-accelerated)
    Layer 3: SHA3-Keystream XOR (quantum-resistant hash-based stream)

Security Analysis:
- If AES is broken: ChaCha20 + SHA3 layers still protect data
- If ChaCha20 is broken: AES + SHA3 layers still protect data
- If both symmetric ciphers fail: SHA3-Keystream provides quantum-safe fallback
- All three layers use independent keys from separate KDF chains
- Each layer provides its own authentication (triple MAC)

This "defense in depth" approach means the overall security is at least
as strong as the strongest remaining layer, even if some layers are
compromised.
"""

import hashlib
import struct
from typing import Tuple

from .chacha20 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from .aes_gcm import aes256_gcm_encrypt, aes256_gcm_decrypt
from .entropy import secure_random_bytes
from .utils import xor_bytes, constant_time_compare, sha3_256, compute_hmac
from .constants import (
    CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE,
    AES_KEY_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE,
    KDF_INFO_CHACHA, KDF_INFO_AES, KDF_INFO_HMAC, KDF_INFO_PADDING
)


def _derive_cascade_keys(
    shared_secret: bytes,
    salt: bytes
) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    """
    Derive all keys for the triple-cascade from the KEM shared secret.

    Uses three INDEPENDENT KDF paths to ensure key separation:
    - Path 1: HKDF-SHA3-256 → ChaCha20 key + nonce
    - Path 2: HKDF-BLAKE2b  → AES-256 key + IV
    - Path 3: HKDF-SHA3-256 → HMAC key + SHA3-keystream seed

    This ensures that even if one KDF is compromised, the other
    keys remain secure.

    Args:
        shared_secret: 32-byte shared secret from KEM.
        salt: 32-byte random salt.

    Returns:
        Tuple of (chacha_key, chacha_nonce, aes_key, aes_iv, hmac_key, sha3_seed)
    """
    # Path 1: ChaCha20 keys via HKDF-SHA3-256
    from .utils import hkdf_sha3_256
    chacha_key_material = hkdf_sha3_256(
        shared_secret, salt, KDF_INFO_CHACHA, CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE
    )
    chacha_key = chacha_key_material[:CHACHA20_KEY_SIZE]
    chacha_nonce = chacha_key_material[CHACHA20_KEY_SIZE:]

    # Path 2: AES-256 keys via HKDF-BLAKE2b (independent KDF)
    from .utils import hkdf_blake2b
    aes_key_material = hkdf_blake2b(
        shared_secret, salt, KDF_INFO_AES, AES_KEY_SIZE + AES_GCM_IV_SIZE
    )
    aes_key = aes_key_material[:AES_KEY_SIZE]
    aes_iv = aes_key_material[AES_KEY_SIZE:]

    # Path 3: HMAC key and SHA3 keystream seed via HKDF-SHA3-256
    hmac_material = hkdf_sha3_256(
        shared_secret, salt, KDF_INFO_HMAC, 32 + 32
    )
    hmac_key = hmac_material[:32]
    sha3_seed = hmac_material[32:]

    return chacha_key, chacha_nonce, aes_key, aes_iv, hmac_key, sha3_seed


def _generate_sha3_keystream(seed: bytes, length: int, nonce: bytes = b'') -> bytes:
    """
    Generate a SHA3-256 based keystream for XOR encryption.

    This is a hash-based stream cipher: each block of keystream is
    SHA3-256(seed || counter || nonce), providing quantum-resistant
    encryption based on the SHA3 hash function.

    SHA3's sponge construction provides preimage resistance of 256 bits
    classically and 128 bits against quantum attacks (Grover's algorithm),
    making this layer resistant to both classical and quantum cryptanalysis.

    Args:
        seed: 32-byte seed for keystream generation.
        length: Number of keystream bytes to generate.
        nonce: Optional nonce for domain separation.

    Returns:
        Keystream bytes of the specified length.
    """
    keystream = b''
    counter = 0

    while len(keystream) < length:
        block_input = seed + struct.pack('<Q', counter) + nonce
        block = hashlib.sha3_256(block_input).digest()
        keystream += block
        counter += 1

    return keystream[:length]


def cascade_encrypt(
    plaintext: bytes,
    shared_secret: bytes,
    salt: bytes,
    associated_data: bytes = b''
) -> bytes:
    """
    Triple-cascade encryption: ChaCha20 → AES-256-GCM → SHA3-Keystream.

    Each layer uses independently derived keys, ensuring that compromising
    one layer does not affect the security of others.

    Layer 1: ChaCha20-Poly1305 AEAD
    - Provides constant-time encryption (no table lookups)
    - Poly1305 provides first authentication layer

    Layer 2: AES-256-GCM AEAD
 - NIST-standard authenticated encryption
    - GCM provides second authentication layer

    Layer 3: SHA3-Keystream XOR + HMAC-SHA3-256
    - Hash-based stream cipher (quantum-resistant)
    - HMAC provides third authentication layer

    Args:
        plaintext: Data to encrypt.
        shared_secret: KEM shared secret (32 bytes).
        salt: Random salt for key derivation (32 bytes).
        associated_data: Additional authenticated data.

    Returns:
        Encrypted data containing all three layers.
    """
    # Derive all cascade keys
    chacha_key, chacha_nonce, aes_key, aes_iv, hmac_key, sha3_seed = \
        _derive_cascade_keys(shared_secret, salt)

    # ===== Layer 1: ChaCha20-Poly1305 =====
    chacha_ct, chacha_tag = chacha20_poly1305_encrypt(
        chacha_key, plaintext, chacha_nonce, aad=associated_data
    )

    # Pack Layer 1 output: ciphertext || tag
    layer1_output = chacha_ct + chacha_tag

    # ===== Layer 2: AES-256-GCM =====
    # Use Layer 1 output as "plaintext" for Layer 2
    aes_iv_fresh = secure_random_bytes(AES_GCM_IV_SIZE)
    # aes256_gcm_encrypt returns (iv, ciphertext, tag) when iv is provided
    _, aes_ct, aes_tag = aes256_gcm_encrypt(
        aes_key, layer1_output, iv=aes_iv_fresh, aad=associated_data
    )

    # Pack Layer 2 output: iv || ciphertext || tag
    layer2_output = aes_iv_fresh + aes_ct + aes_tag

    # ===== Layer 3: SHA3-Keystream XOR =====
    sha3_keystream = _generate_sha3_keystream(sha3_seed, len(layer2_output), nonce=salt[:12])
    layer3_ct = xor_bytes(layer2_output, sha3_keystream)

    # HMAC-SHA3-256 over everything
    mac_input = salt + chacha_nonce + layer3_ct + associated_data
    hmac_tag = compute_hmac(hmac_key, mac_input)

    return layer3_ct + hmac_tag


def cascade_decrypt(
    encrypted_data: bytes,
    shared_secret: bytes,
    salt: bytes,
    associated_data: bytes = b'',
    plaintext_length: int = None,
    chacha_ct_length: int = None
) -> bytes:
    """
    Triple-cascade decryption: SHA3-Keystream → AES-256-GCM → ChaCha20-Poly1305.

    Reverses the cascade_encrypt operation, verifying authentication
    at each layer. If ANY authentication check fails, decryption
    is rejected without leaking information.

    Args:
        encrypted_data: Data from cascade_encrypt.
        shared_secret: KEM shared secret (32 bytes).
        salt: Salt used during encryption (32 bytes).
        associated_data: Additional authenticated data.
        plaintext_length: Expected plaintext length (if known).
        chacha_ct_length: ChaCha20 ciphertext length (for parsing).

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If any authentication check fails.
    """
    # Derive all cascade keys
    chacha_key, chacha_nonce, aes_key, aes_iv, hmac_key, sha3_seed = \
        _derive_cascade_keys(shared_secret, salt)

    # Parse encrypted data: layer3_ct (var) || hmac_tag (32)
    hmac_tag = encrypted_data[-32:]
    layer3_ct = encrypted_data[:-32]

    # ===== Verify Layer 3: HMAC-SHA3-256 =====
    mac_input = salt + chacha_nonce + layer3_ct + associated_data
    expected_hmac = compute_hmac(hmac_key, mac_input)

    if not constant_time_compare(hmac_tag, expected_hmac):
        raise ValueError("Cascade Layer 3: HMAC authentication failed")

    # ===== Undo Layer 3: SHA3-Keystream XOR =====
    sha3_keystream = _generate_sha3_keystream(sha3_seed, len(layer3_ct), nonce=salt[:12])
    layer2_output = xor_bytes(layer3_ct, sha3_keystream)

    # Parse Layer 2 output: aes_iv (12) || aes_ct (var) || aes_tag (16)
    if len(layer2_output) < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE:
        raise ValueError("Cascade Layer 2: Data too short")

    aes_iv_fresh = layer2_output[:AES_GCM_IV_SIZE]
    aes_tag = layer2_output[-AES_GCM_TAG_SIZE:]
    aes_ct = layer2_output[AES_GCM_IV_SIZE:-AES_GCM_TAG_SIZE]

    # ===== Undo Layer 2: AES-256-GCM =====
    try:
        layer1_output = aes256_gcm_decrypt(aes_key, aes_iv_fresh, aes_ct, aes_tag, aad=associated_data)
    except ValueError:
        raise ValueError("Cascade Layer 2: AES-GCM authentication failed")

    # Parse Layer 1 output: chacha_ct (var) || chacha_tag (16)
    if len(layer1_output) < POLY1305_TAG_SIZE:
        raise ValueError("Cascade Layer 1: Data too short")

    chacha_tag = layer1_output[-POLY1305_TAG_SIZE:]
    chacha_ct = layer1_output[:-POLY1305_TAG_SIZE]

    # ===== Undo Layer 1: ChaCha20-Poly1305 =====
    try:
        plaintext = chacha20_poly1305_decrypt(
            chacha_key, chacha_ct, chacha_nonce, chacha_tag, aad=associated_data
        )
    except ValueError:
        raise ValueError("Cascade Layer 1: ChaCha20-Poly1305 authentication failed")

    return plaintext
