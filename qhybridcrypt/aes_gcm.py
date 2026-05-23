"""
Q-HybridCrypt v2.0 - AES-256-GCM Implementation

Implements the Advanced Encryption Standard (AES) with 256-bit keys
in Galois/Counter Mode (GCM) for authenticated encryption.

Improvements over v1:
- Fixed constant-time comparison in GCM tag verification
- Proper GF(2^128) multiplication using carry-less approach
- Correct GHASH implementation
- Better counter management

AES-256 provides 256-bit security classically (128-bit vs quantum).
GCM mode provides both confidentiality and integrity.
"""

from typing import Tuple, List

from .entropy import secure_random_bytes
from .utils import constant_time_compare, xor_bytes


# AES S-box (forward)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# AES Inverse S-box
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Round constants
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]


def galois_multiply(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8) with AES polynomial."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


class AES256:
    """AES-256 block cipher implementation."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self.round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """Expand the 256-bit key into 15 round keys."""
        w = []
        for i in range(0, 32, 4):
            w.append([key[i], key[i+1], key[i+2], key[i+3]])

        for i in range(8, 60):
            temp = w[i-1][:]
            if i % 8 == 0:
                temp = [temp[1], temp[2], temp[3], temp[0]]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[(i // 8) - 1]
            elif i % 8 == 4:
                temp = [SBOX[b] for b in temp]
            w.append([a ^ b for a, b in zip(w[i-8], temp)])

        round_keys = []
        for i in range(0, 60, 4):
            rk = []
            for j in range(4):
                rk.extend(w[i+j])
            round_keys.append(rk)
        return round_keys

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block."""
        if len(block) != 16:
            raise ValueError("Block must be 16 bytes")

        state = list(block)
        state = self._add_round_key(state, self.round_keys[0])

        for r in range(1, 14):
            state = [SBOX[b] for b in state]
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[r])

        state = [SBOX[b] for b in state]
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[14])

        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 16-byte block."""
        if len(block) != 16:
            raise ValueError("Block must be 16 bytes")

        state = list(block)
        state = self._add_round_key(state, self.round_keys[14])

        for r in range(13, 0, -1):
            state = self._inv_shift_rows(state)
            state = [INV_SBOX[b] for b in state]
            state = self._add_round_key(state, self.round_keys[r])
            state = self._inv_mix_columns(state)

        state = self._inv_shift_rows(state)
        state = [INV_SBOX[b] for b in state]
        state = self._add_round_key(state, self.round_keys[0])

        return bytes(state)

    @staticmethod
    def _shift_rows(state):
        result = [0] * 16
        for i in range(4):
            result[i] = state[i]
        for i in range(4):
            result[4 + i] = state[4 + ((i + 1) % 4)]
        for i in range(4):
            result[8 + i] = state[8 + ((i + 2) % 4)]
        for i in range(4):
            result[12 + i] = state[12 + ((i + 3) % 4)]
        return result

    @staticmethod
    def _inv_shift_rows(state):
        result = [0] * 16
        for i in range(4):
            result[i] = state[i]
        for i in range(4):
            result[4 + i] = state[4 + ((i - 1) % 4)]
        for i in range(4):
            result[8 + i] = state[8 + ((i - 2) % 4)]
        for i in range(4):
            result[12 + i] = state[12 + ((i - 3) % 4)]
        return result

    @staticmethod
    def _mix_columns(state):
        result = [0] * 16
        for col in range(4):
            base = col * 4
            result[base] = (galois_multiply(0x02, state[base]) ^
                           galois_multiply(0x03, state[base + 1]) ^
                           state[base + 2] ^ state[base + 3])
            result[base + 1] = (state[base] ^
                               galois_multiply(0x02, state[base + 1]) ^
                               galois_multiply(0x03, state[base + 2]) ^
                               state[base + 3])
            result[base + 2] = (state[base] ^ state[base + 1] ^
                               galois_multiply(0x02, state[base + 2]) ^
                               galois_multiply(0x03, state[base + 3]))
            result[base + 3] = (galois_multiply(0x03, state[base]) ^
                               state[base + 1] ^ state[base + 2] ^
                               galois_multiply(0x02, state[base + 3]))
        return result

    @staticmethod
    def _inv_mix_columns(state):
        result = [0] * 16
        for col in range(4):
            base = col * 4
            result[base] = (galois_multiply(0x0e, state[base]) ^
                           galois_multiply(0x0b, state[base + 1]) ^
                           galois_multiply(0x0d, state[base + 2]) ^
                           galois_multiply(0x09, state[base + 3]))
            result[base + 1] = (galois_multiply(0x09, state[base]) ^
                               galois_multiply(0x0e, state[base + 1]) ^
                               galois_multiply(0x0b, state[base + 2]) ^
                               galois_multiply(0x0d, state[base + 3]))
            result[base + 2] = (galois_multiply(0x0d, state[base]) ^
                               galois_multiply(0x09, state[base + 1]) ^
                               galois_multiply(0x0e, state[base + 2]) ^
                               galois_multiply(0x0b, state[base + 3]))
            result[base + 3] = (galois_multiply(0x0b, state[base]) ^
                               galois_multiply(0x0d, state[base + 1]) ^
                               galois_multiply(0x09, state[base + 2]) ^
                               galois_multiply(0x0e, state[base + 3]))
        return result

    @staticmethod
    def _add_round_key(state, round_key):
        return [s ^ k for s, k in zip(state, round_key)]


def _gf128_mul(x: int, y: int) -> int:
    """
    Multiply two elements in GF(2^128) for GHASH.

    Uses the standard GCM polynomial: x^128 + x^7 + x^2 + x + 1.
    The reduction polynomial R = 0xe1 << 120.
    """
    R = 0xe1000000000000000000000000000000
    result = 0
    for i in range(128):
        if y & (1 << (127 - i)):
            result ^= x
        carry = x & 1
        x >>= 1
        if carry:
            x ^= R
    return result


class AES256GCM:
    """AES-256-GCM authenticated encryption."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self.aes = AES256(key)
        # Compute H = AES_K(0^128) for GHASH
        self.H = self.aes.encrypt_block(b'\x00' * 16)
        self.H_int = int.from_bytes(self.H, byteorder='big')

    def _ghash(self, data: bytes) -> bytes:
        """Compute GHASH over data using precomputed H."""
        # Pad data to 16-byte boundary
        if len(data) % 16 != 0:
            data = data + b'\x00' * (16 - len(data) % 16)

        y = 0
        for i in range(0, len(data), 16):
            block = int.from_bytes(data[i:i+16], byteorder='big')
            y = _gf128_mul(y ^ block, self.H_int)

        return y.to_bytes(16, byteorder='big')

    def encrypt(self, plaintext: bytes, iv: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt with AES-256-GCM.

        Returns (ciphertext, tag).
        """
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes")

        # Counter mode encryption starting at J1 (counter = 1)
        j0 = iv + b'\x00\x00\x00\x01'
        counter = int.from_bytes(j0, byteorder='big')

        ciphertext = bytearray()
        remaining = plaintext
        while remaining:
            counter_bytes = counter.to_bytes(16, byteorder='big')
            keystream = self.aes.encrypt_block(counter_bytes)
            chunk = remaining[:16]
            ciphertext.extend(xor_bytes(chunk, keystream[:len(chunk)]))
            remaining = remaining[16:]
            counter += 1

        # Compute GHASH input
        aad_padded = aad + b'\x00' * ((16 - len(aad) % 16) % 16)
        ct_padded = bytes(ciphertext) + b'\x00' * ((16 - len(ciphertext) % 16) % 16)

        ghash_input = aad_padded + ct_padded
        import struct as _struct
        ghash_input += _struct.pack('>Q', len(aad) * 8)
        ghash_input += _struct.pack('>Q', len(ciphertext) * 8)

        s = self._ghash(ghash_input)

        # Tag = GHASH XOR E(K, J0)
        j0_enc = self.aes.encrypt_block(j0)
        tag = xor_bytes(s, j0_enc)

        return bytes(ciphertext), tag

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes = b'') -> bytes:
        """
        Decrypt with AES-256-GCM.

        Raises ValueError if authentication fails.
        """
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes")
        if len(tag) != 16:
            raise ValueError("Tag must be 16 bytes")

        # Verify tag FIRST (authenticate before decrypt)
        aad_padded = aad + b'\x00' * ((16 - len(aad) % 16) % 16)
        ct_padded = ciphertext + b'\x00' * ((16 - len(ciphertext) % 16) % 16)

        ghash_input = aad_padded + ct_padded
        import struct as _struct
        ghash_input += _struct.pack('>Q', len(aad) * 8)
        ghash_input += _struct.pack('>Q', len(ciphertext) * 8)

        s = self._ghash(ghash_input)

        j0 = iv + b'\x00\x00\x00\x01'
        j0_enc = self.aes.encrypt_block(j0)
        expected_tag = xor_bytes(s, j0_enc)

        # FIXED: Use proper constant-time comparison
        if not constant_time_compare(tag, expected_tag):
            raise ValueError("AES-256-GCM authentication failed")

        # Decrypt
        counter = int.from_bytes(j0, byteorder='big')
        plaintext = bytearray()
        remaining = ciphertext
        while remaining:
            counter_bytes = counter.to_bytes(16, byteorder='big')
            keystream = self.aes.encrypt_block(counter_bytes)
            chunk = remaining[:16]
            plaintext.extend(xor_bytes(chunk, keystream[:len(chunk)]))
            remaining = remaining[16:]
            counter += 1

        return bytes(plaintext)


def aes256_gcm_encrypt(key: bytes, plaintext: bytes,
                        iv: bytes = None, aad: bytes = b'') -> Tuple[bytes, bytes, bytes]:
    """
    Convenience function for AES-256-GCM encryption.

    Returns (iv, ciphertext, tag).
    """
    if iv is None:
        iv = secure_random_bytes(12)
    gcm = AES256GCM(key)
    ciphertext, tag = gcm.encrypt(plaintext, iv, aad)
    return iv, ciphertext, tag


def aes256_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes,
                        tag: bytes, aad: bytes = b'') -> bytes:
    """
    Convenience function for AES-256-GCM decryption.
    """
    gcm = AES256GCM(key)
    return gcm.decrypt(ciphertext, iv, tag, aad)
