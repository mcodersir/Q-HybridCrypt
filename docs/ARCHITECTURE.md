# Q-HybridCrypt v2.0 "PHOENIX" - Architecture Specification

## Table of Contents
1. [Overview](#overview)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [PHOENIX Protocol](#phoenix-protocol)
4. [Key Encapsulation (KEM)](#key-encapsulation-kem)
5. [Triple-Cascade Encryption](#triple-cascade-encryption)
6. [Key Derivation Pipeline](#key-derivation-pipeline)
7. [Password Hashing](#password-hashing)
8. [Message Format](#message-format)
9. [Security Analysis](#security-analysis)
10. [Parameter Choices](#parameter-choices)

---

## Overview

Q-HybridCrypt v2.0 "PHOENIX" implements a **defense-in-depth** cryptographic architecture. Rather than relying on a single encryption algorithm (which creates a single point of failure), PHOENIX chains three independent cipher layers, each with its own key derived through a separate KDF path.

### Design Philosophy

1. **No Single Point of Failure**: If any one cipher or KDF is compromised, the other layers continue to protect the data.
2. **Quantum Resistance**: The KEM is based on Module-LWE, a problem believed hard for quantum computers. All symmetric keys are 256-bit (128-bit quantum security via Grover's).
3. **Real Cryptography**: Every primitive is genuinely implemented. The KEM performs real polynomial arithmetic over Z_q[X]/(X^256+1). Argon2id uses the real hashlib.blake2b.
4. **CCA2 Security**: The Fujisaki-Okamoto transform ensures the KEM is secure against adaptive chosen-ciphertext attacks.
5. **Triple Authentication**: Three independent MACs must all verify for decryption to succeed.

---

## Cryptographic Primitives

### 1. Module-LWE KEM (Key Encapsulation)

**Problem**: Module Learning With Errors over Z_q[X]/(X^256+1)

**Parameters** (Kyber-768 equivalent):
- Ring: Z_3329[X]/(X^256+1)
- Module rank: k = 3
- Noise: CBD(eta1=2, eta2=2)
- Compression: du=10, dv=4

**Key Sizes**:
- Public Key: ~1184 bytes
- Secret Key: ~2400 bytes
- Ciphertext: ~1088 bytes
- Shared Secret: 32 bytes

**Security**: ~192-bit classical, ~128-bit quantum (NIST Level 3)

**Operations**:
- `KeyGen() → (pk, sk)`: Generate keypair using polynomial arithmetic
- `Encaps(pk) → (ct, K)`: Encapsulate 32-byte shared secret
- `Decaps(ct, sk) → K`: Decapsulate with FO transform

### 2. ChaCha20-Poly1305 AEAD

**Algorithm**: ChaCha20 stream cipher + Poly1305 MAC

**Properties**:
- 256-bit key (128-bit quantum security)
- 96-bit nonce
- 128-bit authentication tag
- Constant-time execution (no table lookups)
- 20 rounds of quarter-round operations

**Why ChaCha20?**: Immune to cache-timing attacks that can affect AES in software. Provides a different mathematical structure than AES, ensuring that a breakthrough in AES analysis doesn't affect this layer.

### 3. AES-256-GCM AEAD

**Algorithm**: Advanced Encryption Standard (256-bit) in Galois/Counter Mode

**Properties**:
- 256-bit key (128-bit quantum security)
- 96-bit IV
- 128-bit authentication tag
- Hardware acceleration on modern CPUs (AES-NI)
- 14 rounds of SubBytes/ShiftRows/MixColumns/AddRoundKey

**Why AES?**: The most widely analyzed block cipher in history. Hardware acceleration makes it the fastest option on modern platforms. Provides a different attack surface than ChaCha20.

### 4. SHA3-256 Keystream

**Algorithm**: Hash-based stream cipher using SHA3-256

**Construction**: keystream[i] = SHA3-256(seed || counter || nonce)

**Properties**:
- 256-bit seed
- 256-bit preimage resistance (classical)
- 128-bit preimage resistance (quantum, via Grover's)
- Based on sponge construction (Keccak)

**Why SHA3?**: As a hash function, SHA3 has no algebraic structure that quantum algorithms can exploit (unlike AES's algebraic structure). This layer serves as a "quantum safety net."

### 5. Argon2id Password Hashing

**Algorithm**: Argon2id (RFC 9106) with hashlib.blake2b

**Default Parameters**:
- Time cost: 4 iterations
- Memory cost: 102,400 KB (100 MB)
- Parallelism: 2 lanes
- Hash length: 32 bytes
- Salt length: 16 bytes

**Why Argon2id?**: The recommended password hashing algorithm. Hybrid mode provides:
- Side-channel resistance (Argon2i's data-independent addressing in first pass)
- GPU resistance (Argon2d's data-dependent addressing in subsequent passes)

---

## PHOENIX Protocol

### Encryption Flow

```
Input: plaintext, public_key, associated_data

1. Padding
   ├── Generate random padding length (16-256 bytes)
   └── padded = LE32(len(plaintext)) || plaintext || random_padding

2. KEM Encapsulation
   ├── Generate random message μ (32 bytes)
   ├── Derive r = SHAKE256(μ || H(pk))
   ├── Compute u = A^T·r + e1 (polynomial arithmetic)
   ├── Compute v = t^T·r + e2 + Encode(μ)
   ├── ciphertext_kem = Compress(u, du) || Compress(v, dv)
   └── shared_secret = SHA3-256(K_bar || H(ciphertext_kem))

3. Key Derivation
   ├── salt = Random(32 bytes)
   ├── Path 1: HKDF-SHA3-256(ss, salt, "ChaCha20") → key_chacha, nonce_chacha
   ├── Path 2: HKDF-BLAKE2b(ss, salt, "AES256") → key_aes, iv_aes
   └── Path 3: HKDF-SHA3-256(ss, salt, "HMAC") → key_hmac, seed_sha3

4. Triple-Cascade Encryption
   ├── Layer 1: ChaCha20-Poly1305(key_chacha, padded, nonce_chacha, aad)
   │   → ct_chacha, tag_poly1305
   ├── Layer 2: AES-256-GCM(key_aes, ct_chacha||tag_poly1305, iv_aes, aad)
   │   → ct_aes, tag_gcm
   ├── Layer 3: SHA3-Keystream(seed_sha3, len(ct_aes||tag_gcm))
   │   → ct_sha3 = XOR(ct_aes||tag_gcm, keystream)
   └── Outer Auth: HMAC-SHA3-256(key_hmac, salt||nonce||ct_sha3||aad)
       → tag_hmac

5. Message Construction
   └── output = "QHC2" || version || len(kem_ct) || salt || kem_ct || cascade_ct
```

### Decryption Flow

```
Input: encrypted_message, private_key, associated_data

1. Parse Message
   └── Extract: magic, version, salt, kem_ciphertext, cascade_ciphertext

2. KEM Decapsulation (with FO transform)
   ├── Parse secret key components (s, pk, H(pk), z)
   ├── Decompress u, v from ciphertext
   ├── Compute μ' = Decode(v - s^T·u)
   ├── Re-encrypt with μ' to verify (FO check)
   ├── If match: shared_secret = SHA3-256(K_bar || H(ct))
   └── If no match: shared_secret = SHA3-256(z || H(ct)) [implicit rejection]

3. Key Derivation (same as encryption)

4. Triple-Cascade Decryption
   ├── Verify HMAC-SHA3-256 tag (Layer 3 auth)
   ├── Undo SHA3-Keystream XOR
   ├── Verify AES-256-GCM tag (Layer 2 auth)
   ├── Decrypt AES-256-GCM
   ├── Verify Poly1305 tag (Layer 1 auth)
   ├── Decrypt ChaCha20
   └── Remove padding

5. Output
   └── plaintext
```

---

## Key Encapsulation (KEM)

### Polynomial Arithmetic

All operations take place in the polynomial ring R_q = Z_q[X]/(X^256+1) where q=3329.

**Key Operations**:
- Addition: coefficient-wise mod q
- Multiplication: schoolbook with reduction by X^256+1
- When degree >= 256, reduce via X^256 = -1 (negacyclic)

**Example**:
```
(a * b)[k] = sum(a[i]*b[j]) for i+j=k (mod 256), with sign flip for i+j >= 256
```

### Centered Binomial Distribution (CBD)

Noise is sampled from CBD(eta) where eta=2:

```
For each coefficient:
  1. Read 2*eta random bits
  2. Split into a_bits (eta bits) and b_bits (eta bits)
  3. coefficient = sum(a_bits) - sum(b_bits)
  → Result: {-2, -1, 0, 1, 2} for eta=2
```

### Fujisaki-Okamoto Transform

Ensures CCA2 security by making the KEM's encryption deterministic given the message:

```
Encapsulation:
  μ ← Random(32)
  (r, K_bar) ← G(μ || H(pk))  [deterministic from μ]
  ct ← Enc(pk, μ; r)  [encrypted with randomness derived from μ]
  K ← KDF(K_bar || H(ct))

Decapsulation:
  μ' ← Dec(sk, ct)
  Re-encrypt: ct' ← Enc(pk, μ'; G(μ' || H(pk)))
  If ct == ct': K = KDF(K_bar || H(ct))
  Else: K = KDF(z || H(ct))  [implicit rejection - no error signal]
```

The implicit rejection ensures attackers cannot learn whether a ciphertext is valid, preventing chosen-ciphertext attacks.

---

## Triple-Cascade Encryption

### Why Three Layers?

| Attack Scenario | Layer 1 (ChaCha20) | Layer 2 (AES) | Layer 3 (SHA3) | Data Safe? |
|----------------|-------------------|--------------|----------------|------------|
| AES broken | Still protected | Compromised | Still protected | Yes |
| ChaCha20 broken | Compromised | Still protected | Still protected | Yes |
| Both symmetric broken | Compromised | Compromised | Still protected | Yes |
| Quantum computer | 128-bit security | 128-bit security | 128-bit security | Yes |
| Cache timing | Immune | Potentially vulnerable | Immune | Yes |

### Key Independence

Each layer's keys come from **separate KDF paths**:

```
shared_secret ──┬── HKDF-SHA3-256 ──→ ChaCha20 key + nonce
                ├── HKDF-BLAKE2b ──→ AES-256 key + IV
                └── HKDF-SHA3-256 ──→ HMAC key + SHA3 seed
```

Even if SHA3 is compromised, the BLAKE2b path protects the AES layer. Even if both SHA3 and BLAKE2b are compromised, the keys are still derived from the quantum-safe KEM shared secret.

---

## Key Derivation Pipeline

### HKDF-SHA3-256

Standard HKDF (RFC 5869) using SHA3-256 as the hash function:
- Extract: PRK = HMAC-SHA3-256(salt, IKM)
- Expand: OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA3-256(PRK, T(i-1) || info || i)

### HKDF-BLAKE2b

Non-standard but secure KDF using BLAKE2b:
- Extract: PRK = BLAKE2b(IKM, key=salt)
- Expand: T(i) = BLAKE2b(T(i-1) || info || i, key=PRK)

This provides an **independent** KDF path. Even if SHA3 has a fatal flaw, BLAKE2b still provides secure key derivation.

---

## Password Hashing

### Argon2id Construction

```
H0 = BLAKE2b(LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) ||
              LE32(len(pwd)) || pwd || LE32(len(salt)) || salt ||
              LE32(0) || LE32(0))

Memory filling (2 passes - hybrid):
  Pass 0, Slice 0: Data-independent addressing (Argon2i mode)
  All other: Data-dependent addressing (Argon2d mode)

Finalization:
  Final block = XOR of last blocks across all lanes
  Output = BLAKE2b-long(Final block, hash_length)
```

**Critical Fix**: Uses Python's `hashlib.blake2b` (the real C implementation) instead of a broken pure-Python implementation. This ensures correct hashing that matches the Argon2 RFC 9106 specification.

---

## Message Format

```
Q-HybridCrypt v2 Message:
┌──────────────┬────────────┬────────────────┬────────────────┬─────────────────┐
│ Magic (4B)   │ Version(2B)│ KEM CT Len(2B) │ Salt (32B)     │ KEM CT (~1088B) │
│ "QHC2"       │ 0x0002     │ LE16           │ Random         │ Lattice CT      │
├──────────────┴────────────┴────────────────┴────────────────┼─────────────────┤
│ Cascade Ciphertext                                           │                 │
│ ┌─────────────────────────────────────────────────────────┐ │                 │
│ │ SHA3-Keystream encrypted data (variable length)        │ │                 │
│ │ ┌───────────────────────────────────────────────────┐  │ │                 │
│ │ │ AES-IV (12B) || AES-CT || AES-Tag (16B)          │  │ │                 │
│ │ │ ┌─────────────────────────────────────────────┐  │  │ │                 │
│ │ │ │ ChaCha20-CT || Poly1305-Tag (16B)           │  │  │ │                 │
│ │ │ │ ┌─────────────────────────────────────────┐ │  │  │ │                 │
│ │ │ │ │ LE32(orig_len) || plaintext || padding  │ │  │  │ │                 │
│ │ │ │ └─────────────────────────────────────────┘ │  │  │ │                 │
│ │ │ └─────────────────────────────────────────────┘  │  │ │                 │
│ │ └───────────────────────────────────────────────────┘  │ │                 │
│ └─────────────────────────────────────────────────────────┘ │                 │
│ HMAC-SHA3-256 Tag (32B)                                     │                 │
└─────────────────────────────────────────────────────────────┴─────────────────┘
```

---

## Parameter Choices

### KEM Parameters (Kyber-768 Level)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| n | 256 | Standard polynomial degree |
| q | 3329 | Smallest prime where q ≡ 1 (mod 512) for NTT |
| k | 3 | Module rank for NIST Level 3 |
| eta1 | 2 | Conservative noise parameter |
| eta2 | 2 | Conservative noise parameter |
| du | 10 | Compression bits for u (balancing size vs correctness) |
| dv | 4 | Compression bits for v |

### Symmetric Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| AES key | 256 bits | Maximum AES security (128-bit quantum) |
| ChaCha20 key | 256 bits | Standard (128-bit quantum) |
| GCM IV | 96 bits | NIST SP 800-38D recommendation |
| GCM tag | 128 bits | Standard authentication strength |
| Poly1305 tag | 128 bits | Standard Poly1305 output |
| HMAC tag | 256 bits | SHA3-256 full output |
| Salt | 256 bits | Random per message |
| Padding | 16-256 bytes | Hide plaintext length |

### Argon2id Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Time cost | 4 | OWASP recommendation |
| Memory cost | 102,400 KB | 100 MB, balances security and usability |
| Parallelism | 2 | Multi-core utilization |
| Hash length | 32 bytes | 256-bit output |
| Salt length | 16 bytes | RFC 9106 recommendation |

---

## Compliance

- NIST Post-Quantum Cryptography standardization principles
- FIPS 197 (AES)
- NIST SP 800-38D (GCM)
- RFC 8439 (ChaCha20-Poly1305)
- RFC 9106 (Argon2)
- RFC 5869 (HKDF)
