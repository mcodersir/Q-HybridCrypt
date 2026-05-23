"""
Q-HybridCrypt v2.0 - ChaCha20-Poly1305 AEAD Implementation

Implements ChaCha20 stream cipher and Poly1305 one-time MAC
for authenticated encryption with associated data (AEAD).

ChaCha20 advantages over AES:
- No table lookups (immune to cache-timing attacks)
- Constant-time execution on all platforms
- Better software performance without hardware acceleration
- 256-bit key size provides quantum resistance (Grover's: 128-bit)

Poly1305 provides 128-bit authentication with information-theoretic
security when used with a one-time key.
"""

import struct
from typing import Tuple

from .entropy import secure_random_bytes
from .utils import constant_time_compare, xor_bytes


# =============================================================================
# ChaCha20 Quarter Round and Core
# =============================================================================

def _rotl32(v: int, n: int) -> int:
    """32-bit left rotation."""
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _quarter_round(state: list, a: int, b: int, c: int, d: int) -> None:
    """
    ChaCha20 quarter round operation.

    Performs the mixing operation on four 32-bit words:
    a += b; d ^= a; d <<<= 16
    c += d; b ^= c; b <<<= 12
    a += b; d ^= a; d <<<= 8
    c += d; b ^= c; b <<<= 7

    Modifies state in-place.
    """
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Generate a 64-byte ChaCha20 keystream block.

    ChaCha20 state layout (4x4 matrix of 32-bit words):
    Row 0: "expa" "nd 3" "2-by" "te k"  (constant)
    Row 1: key[0..3]                      (key words 0-3)
    Row 2: key[4..7]                      (key words 4-7)
    Row 3: counter nonce[0..2]            (counter + nonce)

    Args:
        key: 32-byte ChaCha20 key.
        counter: 32-bit block counter.
        nonce: 12-byte nonce.

    Returns:
        64-byte keystream block.
    """
    # Constants: "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    # Key words (8 x 32-bit, little-endian)
    key_words = list(struct.unpack('<8I', key))

    # Counter + nonce
    counter_word = counter & 0xFFFFFFFF
    nonce_words = list(struct.unpack('<3I', nonce))

    # Initial state
    state = constants + key_words + [counter_word] + nonce_words
    working = state[:]

    # 20 rounds (10 double-rounds)
    for _ in range(10):
        # Column rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    # Add original state
    result = b''
    for i in range(16):
        result += struct.pack('<I', (working[i] + state[i]) & 0xFFFFFFFF)

    return result


# =============================================================================
# Poly1305 MAC
# =============================================================================

def _poly1305_mac(message: bytes, key: bytes) -> bytes:
    """
    Compute Poly1305 MAC for a message.

    Poly1305 is a one-time MAC that provides information-theoretic
    security when used with a unique key for each message.

    The key is 32 bytes: r (16 bytes, clamped) || s (16 bytes).
    - r: evaluation point in GF(2^130-5)
    - s: encryption key for the final addition

    Args:
        message: Message to authenticate.
        key: 32-byte one-time key.

    Returns:
        16-byte Poly1305 tag.
    """
    # Clamp r
    r = bytearray(key[:16])
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252

    r_int = int.from_bytes(r, byteorder='little')
    s_int = int.from_bytes(key[16:32], byteorder='little')

    p = (1 << 130) - 5  # Prime: 2^130 - 5

    # Process message in 16-byte blocks
    acc = 0
    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        block_int = int.from_bytes(block, byteorder='little')
        # Add high bit marker (1 beyond the block)
        block_int += (1 << (8 * len(block)))
        acc = ((acc + block_int) * r_int) % p

    # Add s
    tag = (acc + s_int) & ((1 << 128) - 1)
    return tag.to_bytes(16, byteorder='little')


# =============================================================================
# ChaCha20-Poly1305 AEAD
# =============================================================================

def chacha20_poly1305_encrypt(
    key: bytes,
    plaintext: bytes,
    nonce: bytes,
    aad: bytes = b''
) -> Tuple[bytes, bytes]:
    """
    Encrypt and authenticate data using ChaCha20-Poly1305 AEAD.

    Algorithm:
    1. Generate Poly1305 key from ChaCha20 block 0
    2. Encrypt plaintext with ChaCha20 starting from counter 1
    3. Construct MAC input: pad(aad) || pad(ciphertext) || len(aad) || len(ct)
    4. Compute Poly1305 tag

    Args:
        key: 32-byte encryption key.
        plaintext: Data to encrypt.
        nonce: 12-byte nonce (must be unique per key).
        aad: Additional authenticated data.

    Returns:
        Tuple of (ciphertext, tag).
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    # Step 1: Generate Poly1305 one-time key from block 0
    block0 = _chacha20_block(key, 0, nonce)
    poly_key = block0[:32]

    # Step 2: Encrypt plaintext with ChaCha20 (counter starts at 1)
    ciphertext = bytearray()
    counter = 1
    offset = 0

    while offset < len(plaintext):
        keystream = _chacha20_block(key, counter, nonce)
        chunk_size = min(64, len(plaintext) - offset)
        for i in range(chunk_size):
            ciphertext.append(plaintext[offset + i] ^ keystream[i])
        offset += chunk_size
        counter += 1

    ciphertext = bytes(ciphertext)

    # Step 3: Construct MAC input
    mac_data = _pad16(aad) + _pad16(ciphertext)
    mac_data += struct.pack('<Q', len(aad))
    mac_data += struct.pack('<Q', len(ciphertext))

    # Step 4: Compute Poly1305 tag
    tag = _poly1305_mac(mac_data, poly_key)

    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    aad: bytes = b''
) -> bytes:
    """
    Decrypt and verify data using ChaCha20-Poly1305 AEAD.

    Args:
        key: 32-byte encryption key.
        ciphertext: Encrypted data.
        nonce: 12-byte nonce.
        tag: 16-byte authentication tag.
        aad: Additional authenticated data.

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If authentication fails.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")

    # Step 1: Generate Poly1305 one-time key
    block0 = _chacha20_block(key, 0, nonce)
    poly_key = block0[:32]

    # Step 2: Verify tag first (authenticate before decrypt)
    mac_data = _pad16(aad) + _pad16(ciphertext)
    mac_data += struct.pack('<Q', len(aad))
    mac_data += struct.pack('<Q', len(ciphertext))

    expected_tag = _poly1305_mac(mac_data, poly_key)

    if not constant_time_compare(tag, expected_tag):
        raise ValueError("ChaCha20-Poly1305 authentication failed")

    # Step 3: Decrypt with ChaCha20
    plaintext = bytearray()
    counter = 1
    offset = 0

    while offset < len(ciphertext):
        keystream = _chacha20_block(key, counter, nonce)
        chunk_size = min(64, len(ciphertext) - offset)
        for i in range(chunk_size):
            plaintext.append(ciphertext[offset + i] ^ keystream[i])
        offset += chunk_size
        counter += 1

    return bytes(plaintext)


def _pad16(data: bytes) -> bytes:
    """Pad data to a 16-byte boundary."""
    remainder = len(data) % 16
    if remainder == 0:
        return data
    return data + b'\x00' * (16 - remainder)
