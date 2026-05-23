"""
Q-HybridCrypt v2.0 - Entropy Pool & Secure Random Generation

Implements a cryptographic entropy pool that combines multiple OS entropy
sources and amplifies them using SHAKE-256 for extended output.
"""

import os
import time
import struct
import hashlib
import threading
from typing import Optional


class EntropyPool:
    """
    Cryptographic entropy pool that aggregates multiple entropy sources
    and produces cryptographically secure random bytes via SHAKE-256.

    The pool collects entropy from:
    - os.urandom() (primary CSPRNG backed by OS kernel)
    - High-resolution timers
    - Process/thread identifiers
    - Object identity hashes
    - System state

    All entropy is mixed into a SHAKE-256 XOF (Extendable Output Function)
    which can produce arbitrary-length output while maintaining security.
    """

    def __init__(self):
        self._pool = b''
        self._lock = threading.Lock()
        self._counter = 0
        self._initialized = False

    def _collect_raw_entropy(self, size: int = 64) -> bytes:
        """Collect raw entropy from multiple OS sources."""
        entropy = b''

        # Primary: OS cryptographic random (backed by /dev/urandom or CryptGenRandom)
        entropy += os.urandom(size)

        # Secondary: Timing entropy
        t1 = time.perf_counter_ns()
        t2 = time.monotonic_ns()
        entropy += struct.pack('<QQ', t1 & 0xFFFFFFFFFFFFFFFF, t2 & 0xFFFFFFFFFFFFFFFF)

        # Tertiary: Process state entropy
        entropy += struct.pack('<QQQ',
                               os.getpid() if hasattr(os, 'getpid') else 0,
                               (threading.current_thread().ident or 0) & 0xFFFFFFFFFFFFFFFF,
                               id(self) & 0xFFFFFFFFFFFFFFFF)

        # Quaternary: Hash of object states
        state_hash = hashlib.sha3_256(
            str(time.time()).encode() +
            str(self._counter).encode() +
            os.urandom(16)
        ).digest()
        entropy += state_hash

        return entropy

    def _mix_entropy(self, data: bytes) -> bytes:
        """Mix entropy data using SHAKE-256 for diffusion."""
        with self._lock:
            self._counter += 1
            mixer = hashlib.shake_256()
            mixer.update(self._pool)
            mixer.update(data)
            mixer.update(struct.pack('<Q', self._counter))
            mixer.update(struct.pack('<Q', time.perf_counter_ns() & 0xFFFFFFFFFFFFFFFF))
            mixed = mixer.digest(64)
            self._pool = mixed
            return mixed

    def reseed(self, additional_entropy: bytes = b'') -> None:
        """
        Reseed the entropy pool with fresh OS entropy and optional additional data.

        Args:
            additional_entropy: Optional extra entropy to mix in.
        """
        raw = self._collect_raw_entropy(128)
        if additional_entropy:
            raw += hashlib.sha3_256(additional_entropy).digest()
        self._mix_entropy(raw)
        self._initialized = True

    def get_random_bytes(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.

        Uses SHAKE-256 XOF to produce output from the entropy pool,
        ensuring forward secrecy by updating the pool state after
        each request.

        Args:
            length: Number of random bytes to generate.

        Returns:
            Cryptographically secure random bytes of the specified length.
        """
        if length <= 0:
            raise ValueError("Length must be positive")

        if not self._initialized:
            self.reseed()

        with self._lock:
            # Generate output using SHAKE-256
            xof = hashlib.shake_256()
            xof.update(self._pool)
            xof.update(struct.pack('<Q', self._counter))
            xof.update(os.urandom(32))  # Fresh OS entropy for each request
            output = xof.digest(length)

            # Update pool state for forward secrecy
            self._counter += 1
            self._pool = hashlib.sha3_256(
                self._pool + output + struct.pack('<Q', self._counter)
            ).digest()

        return output


# Global entropy pool instance
_global_pool = EntropyPool()
_global_pool.reseed()


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes using the global entropy pool.

    This function combines OS-level CSPRNG output with SHAKE-256 XOF
    for enhanced security guarantees.

    Args:
        length: Number of random bytes to generate.

    Returns:
        Cryptographically secure random bytes.
    """
    return _global_pool.get_random_bytes(length)


def secure_random_int(min_val: int, max_val: int) -> int:
    """
    Generate a cryptographically secure random integer in [min_val, max_val).

    Uses rejection sampling to ensure uniform distribution.

    Args:
        min_val: Minimum value (inclusive).
        max_val: Maximum value (exclusive).

    Returns:
        Random integer in the specified range.
    """
    if min_val >= max_val:
        raise ValueError("min_val must be less than max_val")

    range_size = max_val - min_val
    # Calculate how many bytes we need
    byte_size = (range_size.bit_length() + 7) // 8

    # Rejection sampling for uniform distribution
    while True:
        random_bytes = secure_random_bytes(byte_size)
        value = int.from_bytes(random_bytes, byteorder='little')
        # Mask to only keep the bits we need
        if byte_size * 8 > range_size.bit_length():
            value >>= (byte_size * 8 - range_size.bit_length())
        if value < range_size:
            return min_val + value
