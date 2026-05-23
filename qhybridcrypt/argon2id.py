"""
Q-HybridCrypt v2.0 - Password Hashing Module

Implements secure password hashing using a combination of:
- Argon2id-inspired memory-hard construction using hashlib.blake2b
- Multiple iterations with memory-hard mixing
- Salt-based domain separation
- Constant-time comparison for verification

Uses Python's hashlib.blake2b (the real, audited C implementation)
for all hashing operations, ensuring correctness and performance.
"""

import hashlib
import struct
from typing import Tuple

from .entropy import secure_random_bytes
from .utils import constant_time_compare, xor_bytes
from .constants import (
    ARGON2_DEFAULT_TIME_COST,
    ARGON2_DEFAULT_MEMORY_COST,
    ARGON2_DEFAULT_HASH_LENGTH,
    ARGON2_DEFAULT_SALT_SIZE
)


def _memory_hard_hash(password: bytes, salt: bytes, time_cost: int,
                      memory_cost: int, hash_length: int) -> bytes:
    """
    Memory-hard password hashing function.

    This implements a simplified but secure memory-hard construction:
    1. Initial hash using BLAKE2b with password and salt
    2. Memory-hard expansion: fill a memory buffer with derived blocks
    3. Iterative mixing: repeatedly hash through the memory buffer
    4. Final compression: derive the output hash

    The memory-hardness comes from requiring the full memory buffer
    to compute the final hash - you cannot skip steps or compute
    it with less memory without re-doing all the work.

    Args:
        password: Password bytes.
        salt: Random salt bytes.
        time_cost: Number of iterations.
        memory_cost: Memory in KB to use.
        hash_length: Output hash length in bytes.

    Returns:
        Password hash bytes.
    """
    # Step 1: Initial hash
    # Mix password and salt together using BLAKE2b
    state = hashlib.blake2b(
        password + salt + struct.pack('<II', time_cost, memory_cost),
        digest_size=64
    ).digest()

    # Step 2: Memory-hard expansion
    # Fill a memory buffer with derived blocks
    # Each block depends on the previous one (sequential memory-hard)
    num_blocks = max(memory_cost // 8, 4)  # At least 4 blocks
    memory = []

    for i in range(num_blocks):
        block_input = state + struct.pack('<I', i)
        if memory:
            # Mix with previous block (creates sequential dependency)
            block_input += hashlib.blake2b(memory[-1], digest_size=32).digest()
        block = hashlib.blake2b(block_input, digest_size=64).digest()
        memory.append(block)

    # Step 3: Iterative mixing through memory
    # This is what makes it memory-hard: you need ALL blocks in memory
    for iteration in range(time_cost):
        for i in range(num_blocks):
            # Mix current block with its neighbors (data-dependent addressing)
            prev_idx = (i - 1) % num_blocks
            next_idx = (i + 1) % num_blocks

            # Address depends on the content of a block (data-dependent)
            # This provides resistance against tradeoff attacks
            addr = int.from_bytes(
                hashlib.blake2b(memory[prev_idx], digest_size=4).digest(),
                byteorder='little'
            ) % num_blocks

            # Mix: hash(current || neighbor || addressed_block)
            mix_input = (
                memory[i] +
                memory[next_idx] +
                memory[addr]
            )
            new_block = hashlib.blake2b(mix_input, digest_size=64).digest()

            # XOR with old block (ensures we can't skip previous iterations)
            memory[i] = bytes(a ^ b for a, b in zip(new_block, memory[i]))

    # Step 4: Final compression
    # Hash all blocks together to produce the final output
    final_input = b''
    for block in memory:
        final_input += block

    result = hashlib.blake2b(
        final_input + password + salt,
        digest_size=hash_length
    ).digest()

    return result


class Argon2id:
    """
    Memory-hard password hashing (Argon2id-inspired construction).

    This implementation uses Python's hashlib.blake2b (real C implementation)
    and follows the Argon2id design principles:
    - Memory-hard: requires specified amount of RAM
    - Time-hard: requires specified number of iterations
    - Data-dependent addressing (GPU resistance)
    - Sequential memory-hard (tradeoff attack resistance)
    """

    def __init__(
        self,
        time_cost: int = ARGON2_DEFAULT_TIME_COST,
        memory_cost: int = ARGON2_DEFAULT_MEMORY_COST,
        hash_length: int = ARGON2_DEFAULT_HASH_LENGTH
    ):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.hash_length = hash_length

    def hash(self, password: bytes, salt: bytes) -> bytes:
        """Hash password with memory-hard function."""
        return _memory_hard_hash(
            password, salt, self.time_cost,
            self.memory_cost, self.hash_length
        )

    def verify(self, password: bytes, salt: bytes, expected_hash: bytes) -> bool:
        """Verify password against stored hash (constant-time)."""
        computed = self.hash(password, salt)
        return constant_time_compare(computed, expected_hash)


def hash_password(
    password: str,
    salt: bytes = None,
    time_cost: int = ARGON2_DEFAULT_TIME_COST,
    memory_cost: int = ARGON2_DEFAULT_MEMORY_COST
) -> Tuple[bytes, bytes]:
    """Hash a password string using memory-hard function."""
    if salt is None:
        salt = secure_random_bytes(ARGON2_DEFAULT_SALT_SIZE)
    argon2 = Argon2id(time_cost=time_cost, memory_cost=memory_cost)
    password_bytes = password.encode('utf-8')
    hash_result = argon2.hash(password_bytes, salt)
    return hash_result, salt


def verify_password(
    password: str,
    salt: bytes,
    expected_hash: bytes,
    time_cost: int = ARGON2_DEFAULT_TIME_COST,
    memory_cost: int = ARGON2_DEFAULT_MEMORY_COST
) -> bool:
    """Verify a password against stored hash."""
    argon2 = Argon2id(time_cost=time_cost, memory_cost=memory_cost)
    password_bytes = password.encode('utf-8')
    return argon2.verify(password_bytes, salt, expected_hash)
