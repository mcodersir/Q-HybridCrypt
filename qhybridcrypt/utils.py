"""
Q-HybridCrypt v2.0 - Utility Functions

Core utility functions for cryptographic operations including
constant-time comparisons, byte manipulation, and secure memory handling.
"""

import os
import hashlib
import hmac
from typing import List, Tuple


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time to prevent timing attacks.

    This implementation ensures that the comparison time does not depend
    on the content of the bytes, only on their length. This prevents
    attackers from gaining information through timing side-channels.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        True if sequences are equal, False otherwise.
    """
    if len(a) != len(b):
        # Still do a comparison to avoid leaking length info
        result = 0
        for byte in a:
            result |= byte ^ byte  # Always 0, but takes same time
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte sequences of equal length.

    Args:
        a: First byte sequence.
        b: Second byte sequence (must be same length as a).

    Returns:
        XOR of the two sequences.

    Raises:
        ValueError: If sequences have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Byte sequences must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def zero_memory(data: bytearray) -> None:
    """
    Securely zero a bytearray in memory.

    Overwrites the bytearray with zeros to minimize the window during
    which sensitive data is present in memory. This is a best-effort
    approach; Python's memory management may retain copies.

    Args:
        data: Bytearray to zero out.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0


def compute_hmac(key: bytes, message: bytes, hash_func: str = 'sha3_256') -> bytes:
    """
    Compute HMAC using the specified hash function.

    Args:
        key: HMAC key.
        message: Message to authenticate.
        hash_func: Hash function name (default: sha3_256).

    Returns:
        HMAC digest bytes.
    """
    return hmac.new(key, message, hash_func).digest()


def shake256(data: bytes, output_length: int) -> bytes:
    """
    SHAKE-256 Extendable Output Function (XOF).

    Args:
        data: Input data.
        output_length: Desired output length in bytes.

    Returns:
        Extended output of the specified length.
    """
    return hashlib.shake_256(data).digest(output_length)


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash."""
    return hashlib.sha3_256(data).digest()


def sha3_512(data: bytes) -> bytes:
    """SHA3-512 hash."""
    return hashlib.sha3_512(data).digest()


def blake2b_hash(data: bytes, digest_size: int = 64, key: bytes = b'') -> bytes:
    """
    BLAKE2b hash function.

    Args:
        data: Input data.
        digest_size: Output digest size (1-64 bytes).
        key: Optional key for keyed mode.

    Returns:
        BLAKE2b digest bytes.
    """
    h = hashlib.blake2b(data, digest_size=digest_size, key=key)
    return h.digest()


def hkdf_sha3_256(input_key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF (HMAC-based Key Derivation Function) using SHA3-256.

    Implements RFC 5869 HKDF with SHA3-256 as the underlying hash function.

    Args:
        input_key: Input keying material.
        salt: Random salt (must be at least 16 bytes for security).
        info: Context/application-specific information.
        length: Desired output length in bytes (max 8160).

    Returns:
        Derived key material of the specified length.

    Raises:
        ValueError: If length exceeds maximum or salt is too short.
    """
    if length > 255 * 32:
        raise ValueError(f"Cannot derive more than {255 * 32} bytes")
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")

    # Extract phase: PRK = HMAC-Hash(salt, IKM)
    prk = hmac.new(salt, input_key, 'sha3_256').digest()

    # Expand phase: OKM = T(1) || T(2) || ... || T(n)
    n = (length + 31) // 32
    okm = b''
    t = b''

    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), 'sha3_256').digest()
        okm += t

    return okm[:length]


def hkdf_blake2b(input_key: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF using BLAKE2b as the underlying hash.

    Provides an alternative KDF path for defense-in-depth.
    If SHA3-256 is ever compromised, this provides independent security.

    Args:
        input_key: Input keying material.
        salt: Random salt.
        info: Context/application-specific information.
        length: Desired output length.

    Returns:
        Derived key material.
    """
    if length > 255 * 64:
        raise ValueError(f"Cannot derive more than {255 * 64} bytes")

    # Extract using BLAKE2b in keyed mode
    prk = hashlib.blake2b(input_key, digest_size=64, key=salt).digest()

    # Expand
    n = (length + 63) // 64
    okm = b''
    t = b''

    for i in range(1, n + 1):
        t = hashlib.blake2b(
            t + info + bytes([i]),
            digest_size=64,
            key=prk
        ).digest()
        okm += t

    return okm[:length]


def encode_length(length: int, size: int = 4) -> bytes:
    """Encode an integer length as little-endian bytes."""
    return length.to_bytes(size, byteorder='little')


def decode_length(data: bytes, size: int = 4) -> int:
    """Decode a little-endian integer from bytes."""
    return int.from_bytes(data[:size], byteorder='little')
