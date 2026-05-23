"""
Q-HybridCrypt v2.0 "PHOENIX" - Security Constants & Configuration

This module defines all cryptographic parameters used throughout the library.
Parameters are chosen based on NIST PQC recommendations and conservative
security estimates for both classical and quantum adversaries.
"""

# =============================================================================
# Protocol Version
# =============================================================================
PROTOCOL_VERSION = 2
MAGIC_HEADER = b'QHC2'  # 4-byte magic header for v2

# =============================================================================
# LWE-Based KEM Parameters (Kyber-768 equivalent security)
# =============================================================================
KEM_N = 256           # Polynomial ring degree (Z_q[X]/(X^256 + 1))
KEM_Q = 3329          # Prime modulus
KEM_K = 3             # Module rank (3 = Kyber-768 level ~AES-192)
KEM_ETA1 = 2          # Noise parameter for secret/error in keygen
KEM_ETA2 = 2          # Noise parameter for encapsulation noise
KEM_DU = 10           # Compression bits for u-component
KEM_DV = 4            # Compression bits for v-component

# Derived KEM sizes
KEM_POLY_BYTES = 384  # Bytes per polynomial after compression (12 bits * 256 / 8)
KEM_PUBLIC_KEY_SIZE = KEM_K * 384 + 32  # k * PolyCompress12(t) + seed(32) = 1184
KEM_SECRET_KEY_SIZE = KEM_K * 384 + KEM_PUBLIC_KEY_SIZE + 32 + 32  # sk + pk + h(pk) + z
KEM_CIPHERTEXT_SIZE = KEM_K * (KEM_DU * KEM_N // 8) + (KEM_DV * KEM_N // 8)  # 1088
KEM_SHARED_SECRET_SIZE = 32

# =============================================================================
# Symmetric Cipher Parameters
# =============================================================================
AES_KEY_SIZE = 32      # 256-bit AES key
AES_GCM_IV_SIZE = 12   # 96-bit IV for GCM
AES_GCM_TAG_SIZE = 16  # 128-bit authentication tag

CHACHA20_KEY_SIZE = 32  # 256-bit ChaCha20 key
CHACHA20_NONCE_SIZE = 12  # 96-bit nonce
POLY1305_TAG_SIZE = 16  # 128-bit Poly1305 tag

# =============================================================================
# Key Derivation Parameters
# =============================================================================
HKDF_HASH_SIZE = 32    # SHA3-256 output
HKDF_SALT_SIZE = 32    # Salt size for HKDF
KDF_INFO_CHACHA = b'Q-HybridCrypt-v2-ChaCha20-Key'
KDF_INFO_AES = b'Q-HybridCrypt-v2-AES256-Key'
KDF_INFO_HMAC = b'Q-HybridCrypt-v2-HMAC-Key'
KDF_INFO_PADDING = b'Q-HybridCrypt-v2-Padding-Key'

# =============================================================================
# Cascade Encryption Configuration
# =============================================================================
# Triple-cascade: ChaCha20-Poly1305 → AES-256-GCM → SHA3-Keystream XOR
CASCADE_LAYERS = 3

# =============================================================================
# Argon2id Password Hashing Parameters
# =============================================================================
ARGON2_DEFAULT_TIME_COST = 4       # Iterations
ARGON2_DEFAULT_MEMORY_COST = 102400  # 100 MB in KB
ARGON2_DEFAULT_PARALLELISM = 2     # Threads
ARGON2_DEFAULT_HASH_LENGTH = 32    # Output bytes
ARGON2_DEFAULT_SALT_SIZE = 16      # Salt bytes

# =============================================================================
# Entropy & Random Generation
# =============================================================================
ENTROPY_POOL_SIZE = 256   # Internal entropy pool size in bytes
MIN_RANDOM_SEED_SIZE = 32 # Minimum seed size

# =============================================================================
# Message Format Configuration
# =============================================================================
MAX_PLAINTEXT_SIZE = 2**30  # 1 GB max plaintext size
MIN_PADDING_BYTES = 16      # Minimum random padding
MAX_PADDING_BYTES = 256     # Maximum random padding

# =============================================================================
# Security Levels (NIST equivalents)
# =============================================================================
SECURITY_LEVELS = {
    1: {'name': 'AES-128 equivalent', 'bits': 128, 'kem_k': 2, 'eta1': 3, 'eta2': 2},
    3: {'name': 'AES-192 equivalent', 'bits': 192, 'kem_k': 3, 'eta1': 2, 'eta2': 2},
    5: {'name': 'AES-256 equivalent', 'bits': 256, 'kem_k': 4, 'eta1': 2, 'eta2': 2},
}

DEFAULT_SECURITY_LEVEL = 3  # Kyber-768 equivalent
