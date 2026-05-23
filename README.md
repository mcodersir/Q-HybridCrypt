<div align="center">

# Q-HybridCrypt v2.0 "PHOENIX"

### Advanced Quantum-Resistant Hybrid Cryptographic Library

<!-- Language Switcher -->
<p>
  <a href="README.md"><img src="https://img.shields.io/badge/English-✓-blue.svg?style=for-the-badge" alt="English"/></a>
  <a href="docs/README_FA.md"><img src="https://img.shields.io/badge/فارسی-✓-green.svg?style=for-the-badge" alt="فارسی"/></a>
  <a href="docs/README_ZH.md"><img src="https://img.shields.io/badge/中文-✓-red.svg?style=for-the-badge" alt="中文"/></a>
</p>

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Level](https://img.shields.io/badge/security-NIST%20Level%203-red.svg)](docs/ARCHITECTURE.md)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/mcodersir/Q-HybridCrypt/releases)
[![Quantum Resistant](https://img.shields.io/badge/quantum-resistant-8A2BE2.svg)](docs/SECURITY.md)
[![Migration SDK](https://img.shields.io/badge/migration-SDK-orange.svg)](docs/MIGRATION_GUIDE.md)
[![PyPI](https://img.shields.io/badge/PyPI-q--hybridcrypt-1DAFB3.svg)](https://pypi.org/project/q-hybridcrypt/)

**Triple-Cascade Encryption · Module-LWE KEM · Argon2id · CCA2 Secure · Migration SDK**

[Quick Start](#-quick-start) · [Architecture](#-architecture-overview) · [API Reference](docs/API_REFERENCE.md) · [Migration Guide](docs/MIGRATION_GUIDE.md) · [Security Analysis](docs/SECURITY.md)

</div>

---

## What Makes Q-HybridCrypt Different?

Q-HybridCrypt v2.0 "PHOENIX" is not just another cryptographic library. It implements a **triple-cascade encryption architecture** where data is encrypted sequentially through three independent cipher layers — ChaCha20-Poly1305, AES-256-GCM, and SHA3-Keystream XOR — each with its own key derived through separate KDF paths. This means **an attacker must break ALL THREE layers** to recover your data. Even if a future cryptanalytic breakthrough defeats AES or ChaCha20, the remaining layers continue to protect your information. Combined with a real Module-LWE key encapsulation mechanism, triple authentication, and the Fujisaki-Okamoto CCA2 transform, PHOENIX provides defense-in-depth that no single-algorithm library can match.

The library also ships with a complete **Migration SDK** that enables seamless, one-step migration from PyCryptodome, cryptography/Fernet, PyNaCl, and custom AES-GCM implementations — with zero plaintext exposure in your application code. This makes it practical to upgrade your existing encrypted data to quantum-resistant protection without rewriting your entire security layer.

| Feature | Q-HybridCrypt v2 | Typical Crypto Lib | Benefit |
|---------|------------------|--------------------|---------|
| **KEM** | Real Module-LWE (polynomial arithmetic) | RSA/ECDH (quantum-vulnerable) | Resistant to Shor's algorithm on quantum computers |
| **Encryption** | Triple-Cascade (3 layers) | Single cipher | Must break all 3 layers to recover data |
| **Key Derivation** | Dual-path (SHA3-256 + BLAKE2b) | Single KDF | Independent paths; compromising one doesn't affect the other |
| **Authentication** | Triple (Poly1305 + GCM + HMAC-SHA3) | Single tag | Three independent MACs must all verify |
| **CCA2 Security** | Fujisaki-Okamoto Transform | Often missing | Proven security against adaptive chosen-ciphertext attacks |
| **Password Hashing** | Argon2id with real Blake2b (100 MB) | SHA256/bcrypt | Memory-hard; defeats GPU/ASIC brute-force attacks |
| **Quantum Resistant** | Yes — NIST Level 3 (~128-bit quantum) | No | Protected against "harvest now, decrypt later" threats |
| **Migration SDK** | Built-in (4 libraries supported) | None | Seamless upgrade from existing encryption |
| **Length Hiding** | Random padding (16–256 bytes) | None | Prevents traffic analysis from ciphertext sizes |
| **Forward Secrecy** | Per-message KEM encapsulation | Rare | Compromising one message doesn't affect others |

---

## Architecture Overview

![Architecture](docs/images/architecture_overview.png)

The PHOENIX protocol combines five major cryptographic subsystems into a unified, defense-in-depth architecture. Each subsystem provides independent security guarantees, so the overall system remains secure even if individual components are compromised.

```
┌──────────────────────────────────────────────────────────────┐
│                   Q-HybridCrypt v2.0 "PHOENIX"                │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐ │
│  │ Module-LWE   │   │ Triple-Cascade│   │    Argon2id      │ │
│  │ KEM          │──▶│ Encryption   │   │ Password Hashing │ │
│  │ (Quantum-Safe)│   │ (3 layers)   │   │ (100 MB memory)  │ │
│  └──────────────┘   └──────┬───────┘   └──────────────────┘ │
│                            │                                  │
│                   ┌────────┼────────┐                         │
│                   ▼        ▼        ▼                         │
│             ┌─────────┐┌─────────┐┌──────────┐               │
│             │ChaCha20 ││AES-256  ││SHA3-256  │               │
│             │Poly1305 ││GCM      ││Keystream │               │
│             │(Layer 1)││(Layer 2)││(Layer 3) │               │
│             └─────────┘└─────────┘└──────────┘               │
│                   │        │        │                          │
│                   ▼        ▼        ▼                          │
│             ┌────────────────────────────────────┐             │
│             │   Triple Authentication:           │             │
│             │   Poly1305 + GCM Tag + HMAC-SHA3   │             │
│             └────────────────────────────────────┘             │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐ │
│  │ HKDF-SHA3    │   │ HKDF-BLAKE2b │   │  Migration SDK   │ │
│  │ (KDF Path 1) │   │ (KDF Path 2) │   │  (4 libraries)   │ │
│  └──────────────┘   └──────────────┘   └──────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Encryption Flow

![Encryption Flow](docs/images/encryption_flow.png)

1. **Padding**: Random 16–256 bytes added for length hiding
2. **KEM Encapsulation**: Quantum-safe shared secret via Module-LWE
3. **Triple Key Derivation**: Three independent KDF paths (SHA3 + BLAKE2b)
4. **Cascade Encryption**: ChaCha20 → AES-256-GCM → SHA3-Keystream
5. **Triple Authentication**: Poly1305 + GCM + HMAC-SHA3-256

### Key Derivation Pipeline

![Key Derivation](docs/images/key_derivation.png)

Each cascade layer receives its key from an **independent** KDF path:

- **Path 1**: `HKDF-SHA3-256` → ChaCha20 key (32B) + nonce (12B)
- **Path 2**: `HKDF-BLAKE2b` → AES-256 key (32B) + IV (12B)
- **Path 3**: `HKDF-SHA3-256` → HMAC key (32B) + SHA3 seed (32B)

If SHA3 is compromised, the BLAKE2b path still protects the AES layer. If both KDFs are compromised, the keys still derive from the quantum-safe KEM shared secret.

---

## Quick Start

### Installation

```bash
# Install from PyPI
pip install q-hybridcrypt

# Install from source
git clone https://github.com/mcodersir/Q-HybridCrypt.git
cd Q-HybridCrypt
pip install -e .

# With optional performance backends
pip install q-hybridcrypt[performance]  # cryptography + argon2-cffi

# Development dependencies
pip install q-hybridcrypt[dev]  # pytest + black

# Migration helpers
pip install q-hybridcrypt[migration]  # cryptography library

# Everything
pip install q-hybridcrypt[all]
```

### 30-Second Example

```python
from qhybridcrypt import QHybridCrypt

# Initialize with NIST Level 3 security (default, recommended)
crypto = QHybridCrypt()

# Generate quantum-resistant keypair
public_key, private_key = crypto.generate_keypair()

# Encrypt — triple-cascade with triple authentication
message = b"Top secret quantum-safe message"
ciphertext = crypto.encrypt(message, public_key)

# Decrypt — verifies all three authentication layers
plaintext = crypto.decrypt(ciphertext, private_key)
assert plaintext == message

print("Quantum-resistant encryption successful!")
```

### With Associated Data (AAD)

AAD is authenticated but NOT encrypted — perfect for metadata like user IDs, timestamps, and request IDs that must be bound to the ciphertext but don't need confidentiality. Mismatched AAD during decryption causes authentication failure, preventing ciphertext-context confusion attacks.

```python
# Include context in AAD to bind ciphertext to its purpose
aad = b"user_id:12345|timestamp:1700000000|request_id:abc"
ciphertext = crypto.encrypt(message, public_key, associated_data=aad)

# Same AAD must be provided during decryption
plaintext = crypto.decrypt(ciphertext, private_key, associated_data=aad)

# Wrong AAD is rejected (authentication fails)
try:
    crypto.decrypt(ciphertext, private_key, associated_data=b"wrong")
except ValueError:
    print("Wrong AAD correctly rejected")
```

### Password Hashing

```python
# Hash with Argon2id (100 MB memory, 4 iterations — OWASP recommended)
password_hash, salt = crypto.hash_password("my_secure_password")

# Verify (constant-time comparison — immune to timing attacks)
is_valid = crypto.verify_password("my_secure_password", salt, password_hash)
assert is_valid is True

# Wrong password returns False (not an exception)
is_valid = crypto.verify_password("wrong_password", salt, password_hash)
assert is_valid is False
```

### SDK Usage — Migrate from Any Library

```python
from qhybridcrypt.migration import migrate_from

# One-step migration from any supported library
def my_old_decrypt(ciphertext: bytes) -> bytes:
    # Your existing decryption code — works with ANY library
    return plaintext_bytes

new_ciphertext, phoenix_public_key = migrate_from(
    library='pycryptodome',  # or 'cryptography', 'nacl', 'custom'
    old_ciphertext=old_encrypted_data,
    old_decrypt_fn=my_old_decrypt,
    security_level=3
)

# new_ciphertext is now PHOENIX-encrypted with quantum-resistant protection
```

### Migration from Fernet (One-Liner)

```python
from qhybridcrypt.migration import CryptographyIOMigrator

migrator = CryptographyIOMigrator()
new_ct, pk = migrator.migrate_fernet(fernet_token, fernet_key)
```

---

## Security Layers Explained

![Cascade Layers](docs/images/cascade_layers.png)

The PHOENIX triple-cascade encrypts data through three sequential layers, each with an independent key from a separate KDF path. This defense-in-depth approach means the overall security is at least as strong as the strongest remaining layer, even if one or two layers are compromised by future cryptanalytic advances.

### Layer 1: ChaCha20-Poly1305 AEAD

ChaCha20 is a stream cipher designed by Daniel Bernstein that operates through 20 rounds of quarter-round operations on a 4x4 matrix of 32-bit words. Unlike AES, ChaCha20 performs no table lookups, making it immune to cache-timing attacks that can leak information through variable memory access patterns. The Poly1305 one-time MAC provides information-theoretic authentication when used with a unique key per message, which is guaranteed by the per-message KEM encapsulation. Together, ChaCha20-Poly1305 provides 256-bit confidentiality and 128-bit authentication, both of which offer 128-bit security against quantum adversaries via Grover's algorithm.

- **Algorithm**: ChaCha20 stream cipher (20 rounds) + Poly1305 one-time MAC
- **Key**: 256-bit, derived via HKDF-SHA3-256 (Path 1)
- **Authentication**: Poly1305 tag (128-bit)
- **Quantum Security**: 128-bit (Grover's algorithm on 256-bit key)

### Layer 2: AES-256-GCM AEAD

AES-256 is the most widely analyzed block cipher in history, standardized by NIST in FIPS 197. The GCM (Galois/Counter Mode) mode provides authenticated encryption by combining counter-mode encryption with GHASH authentication over the Galois field GF(2^128). AES-256-GCM benefits from hardware acceleration (AES-NI) on modern x86 and ARM processors, making it the fastest layer in the cascade on supported platforms. The 14-round AES-256 provides full diffusion after just two rounds, and the 256-bit key offers 128-bit security against quantum attacks.

- **Algorithm**: AES-256 block cipher (14 rounds) + GCM mode
- **Key**: 256-bit, derived via HKDF-BLAKE2b (Path 2 — independent from Layer 1!)
- **Authentication**: GCM tag (128-bit)
- **Quantum Security**: 128-bit (Grover's algorithm on 256-bit key)

### Layer 3: SHA3-Keystream XOR + HMAC-SHA3-256

The third layer uses SHA3-256 as a hash-based stream cipher: `keystream[i] = SHA3-256(seed || counter || nonce)`. The plaintext output from Layer 2 is XORed with this keystream, and the result is authenticated with HMAC-SHA3-256. This layer serves as the "quantum safety net" because SHA3's sponge construction has no algebraic structure that quantum algorithms can exploit, unlike AES's algebraic structure over GF(2^8). Even if both AES and ChaCha20 are broken by future advances, this layer continues to protect data with 256-bit classical and 128-bit quantum preimage resistance.

- **Algorithm**: SHA3-256 keystream generation + HMAC-SHA3-256
- **Key**: Derived via HKDF-SHA3-256 (Path 3 — third independent path!)
- **Authentication**: HMAC-SHA3-256 tag (256-bit)
- **Quantum Security**: 128-bit (Grover's algorithm on SHA3-256 preimage)

**Key Insight**: Each layer uses keys from **independent KDF paths** (two SHA3-256 paths and one BLAKE2b path). Compromising one KDF does not affect the others. Compromising two KDFs still leaves the KEM shared secret as the root of security.

---

## Feature Highlights

### Real Module-LWE Key Encapsulation

The KEM performs genuine polynomial arithmetic over the ring Z_3329[X]/(X^256+1), including schoolbook polynomial multiplication with negacyclic reduction and centered binomial distribution noise sampling. This is not a simulation — it implements the same mathematical framework as ML-KEM (Kyber-768), the NIST post-quantum cryptography standard. The Fujisaki-Okamoto transform provides proven CCA2 security with implicit rejection, ensuring that invalid ciphertexts produce pseudorandom shared secrets rather than error signals.

### Triple Authentication

Every encrypted message carries three independent authentication tags: a Poly1305 MAC (128-bit) from Layer 1, a GCM tag (128-bit) from Layer 2, and an HMAC-SHA3-256 tag (256-bit) from Layer 3. All three must verify for decryption to succeed, and the library deliberately does not reveal which tag failed, preventing attackers from targeting individual layers. This provides 128+128+256 = 512 bits of total authentication strength.

### Per-Message Forward Secrecy

Each encryption operation generates a fresh KEM encapsulation, producing unique symmetric keys for every message. This means that even if an attacker compromises the private key after a message was sent, they cannot retroactively decrypt previously captured messages because each message's keys were ephemeral and derived from a different KEM shared secret. This per-message forward secrecy is stronger than the session-level forward secrecy provided by protocols like TLS.

### Length-Hiding Padding

By default, PHOENIX adds 16 to 256 bytes of random padding to every message before encryption. This hides the true length of the plaintext, preventing traffic analysis attacks that could infer the type or content of messages from their sizes. For example, without padding, an observer could distinguish a short "yes" response from a long "detailed explanation" response based on ciphertext size alone.

### Migration SDK

The built-in Migration SDK supports one-step migration from PyCryptodome, cryptography/Fernet, PyNaCl, and custom AES-GCM implementations. The Transparent Re-encryption feature ensures that plaintext never appears in your application code during migration — the old decryption and PHOENIX re-encryption happen within the SDK's internal scope. Batch migration is supported for large datasets, with progress callbacks for monitoring.

---

## Performance

| Operation | Time (approx.) | Notes |
|-----------|---------------|-------|
| Key Generation | ~2–5 seconds | Pure Python LWE polynomial arithmetic |
| Encryption (1 KB) | ~1–3 seconds | Triple cascade (ChaCha20 + AES-GCM + SHA3) |
| Decryption (1 KB) | ~1–3 seconds | Triple cascade + verify 3 auth tags |
| Password Hash | ~1–3 seconds | Argon2id (100 MB memory, 4 iterations) |
| Stream Encrypt (1 MB) | ~30–90 seconds | 64 KB chunks, independent KEM per chunk |
| Migration (1 item) | ~3–8 seconds | Decrypt old + encrypt new |
| Batch Migration (100 items) | ~5–15 minutes | Single keypair, progress callback |

> **Note**: Performance is limited by the pure Python implementation, which prioritizes correctness and auditability over raw speed. For production deployments requiring high throughput, consider installing the `cryptography` library as an optional backend (`pip install q-hybridcrypt[performance]`). The triple-cascade architecture inherently requires approximately 3x the computation of a single-cipher approach, but this overhead buys you triple the security margin against future cryptanalytic breakthroughs.

### Ciphertext Size Overhead

| Plaintext Size | Ciphertext Size | Overhead |
|---------------|----------------|----------|
| 0 bytes (empty) | ~1,250 bytes | ~1,250 bytes (headers + KEM + padding) |
| 100 bytes | ~1,400 bytes | ~1,300 bytes |
| 1 KB | ~2,300 bytes | ~1,300 bytes |
| 10 KB | ~11,400 bytes | ~1,400 bytes |
| 100 KB | ~101,400 bytes | ~1,400 bytes |
| 1 MB | ~1,001,400 bytes | ~1,400 bytes (~0.14% overhead) |

The fixed overhead of approximately 1,300–1,400 bytes comes from the KEM ciphertext (~1,088 bytes), salt (32 bytes), nonce/IV material (36 bytes), authentication tags (64 bytes), and message headers (8 bytes). This overhead is constant regardless of plaintext size, making PHOENIX efficient for larger messages.

---

## Module Structure

```
qhybridcrypt/
├── __init__.py          # Public API exports & version info
├── core.py              # Main QHybridCrypt class & convenience functions
├── lattice_kem.py       # Module-LWE KEM (real polynomial math)
│                         #   - KeyGen, Encapsulate, Decapsulate
│                         #   - CBD noise sampling
│                         #   - Fujisaki-Okamoto CCA2 transform
├── cascade.py           # Triple-cascade encryption engine
│                         #   - ChaCha20 → AES-GCM → SHA3-Keystream
│                         #   - Independent key derivation per layer
├── chacha20.py          # ChaCha20-Poly1305 AEAD implementation
│                         #   - Quarter round, block function
│                         #   - Poly1305 one-time MAC
├── aes_gcm.py           # AES-256-GCM AEAD implementation
│                         #   - Full AES-256 with S-box
│                         #   - GCM mode with GHASH
├── argon2id.py          # Argon2id password hashing
│                         #   - Memory-hard construction
│                         #   - Real hashlib.blake2b backend
├── entropy.py           # Cryptographic entropy pool
│                         #   - Multi-source OS entropy
│                         #   - SHAKE-256 XOF output
├── migration.py         # Migration SDK
│                         #   - PyCryptodomeMigrator
│                         #   - CryptographyIOMigrator
│                         #   - NaClMigrator
│                         #   - CustomAESMigrator
│                         #   - Batch migration support
├── utils.py             # HKDF, HMAC, hash utilities
│                         #   - HKDF-SHA3-256, HKDF-BLAKE2b
│                         #   - Constant-time compare
│                         #   - Secure memory zeroing
└── constants.py         # All security parameters
                          #   - KEM, AES, ChaCha20, Argon2id params
```

---

## Documentation

| Document | Language | Description |
|----------|----------|-------------|
| [Architecture Deep-Dive](docs/ARCHITECTURE.md) | EN | Full protocol specification, message format, parameter choices |
| [Security Analysis](docs/SECURITY.md) | EN | Threat model, security proofs, attack resistance, known limitations |
| [API Reference](docs/API_REFERENCE.md) | EN | Complete API documentation with type annotations |
| [Migration Guide](docs/MIGRATION_GUIDE.md) | EN | Step-by-step migration from PyCryptodome, Fernet, NaCl, custom AES-GCM |
| [مستندات فارسی](docs/README_FA.md) | FA | مستندات کامل به زبان فارسی |
| [معماری فارسی](docs/ARCHITECTURE_FA.md) | FA | معماری و پروتکل PHOENIX به فارسی |
| [راهنمای مهاجرت فارسی](docs/MIGRATION_FA.md) | FA | راهنمای مهاجرت به فارسی |
| [تحلیل امنیتی فارسی](docs/SECURITY_FA.md) | FA | تحلیل امنیتی به فارسی |
| [中文文档](docs/README_ZH.md) | ZH | 中文完整文档 |
| [架构说明](docs/ARCHITECTURE_ZH.md) | ZH | PHOENIX协议架构详解 |
| [迁移指南](docs/MIGRATION_ZH.md) | ZH | 从其他加密库迁移的完整指南 |
| [安全分析](docs/SECURITY_ZH.md) | ZH | 安全性分析与威胁模型 |
| [Examples](examples/) | — | Working code examples for all features |

---

## Comparison with v1

| Aspect | v1 (Old) | v2.0 PHOENIX |
|--------|----------|--------------|
| KEM | Fake (just hashing) | Real Module-LWE polynomial arithmetic |
| Encryption | Single AES-GCM | Triple cascade (ChaCha20 + AES + SHA3) |
| KDF | HKDF with zero salt | Dual-path HKDF (SHA3-256 + BLAKE2b) |
| Password Hash | Broken pure-Python Blake2b | Real hashlib.blake2b (audited C implementation) |
| CCA2 | None | Fujisaki-Okamoto transform with implicit rejection |
| Authentication | Single GCM tag | Triple (Poly1305 + GCM + HMAC-SHA3) |
| Key Separation | None | Domain-separated per layer with unique info strings |
| Padding | None | Random length-hiding padding (16–256 bytes) |
| Migration | Not supported | Full SDK with 4 library migrators |
| Forward Secrecy | None | Per-message ephemeral KEM |
| Entropy | Basic os.urandom | Multi-source pool with SHAKE-256 XOF |

---

## Contributing

Contributions are welcome! Whether you're fixing bugs, adding features, improving documentation, or enhancing test coverage, your help makes Q-HybridCrypt better for everyone. Please read our contributing guidelines and ensure all tests pass before submitting pull requests.

```bash
# Run the test suite
python -m pytest tests/

# Or run manually
python tests/test_core.py
python tests/test_migration.py

# Run the demo
python examples/basic_usage.py
python examples/migration_example.py

# Code formatting
black qhybridcrypt/
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for a post-quantum future.**

If this project is useful to you, please consider giving it a star!

[Report Bugs](https://github.com/mcodersir/Q-HybridCrypt/issues) · [Request Features](https://github.com/mcodersir/Q-HybridCrypt/issues) · [Contribute](https://github.com/mcodersir/Q-HybridCrypt/pulls)

</div>
