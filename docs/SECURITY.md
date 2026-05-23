# Q-HybridCrypt v2.0 - Security Analysis

## Threat Model

### Adversary Capabilities

| Capability | Classical Adversary | Quantum Adversary |
|-----------|-------------------|-------------------|
| Brute force | 2^192 (infeasible) | 2^128 (infeasible) |
| Shor's algorithm | N/A | Effective against RSA/ECC only |
| Grover's algorithm | N/A | 2^128 for 256-bit keys |
| Chosen plaintext | Handled by AEAD | Handled by AEAD |
| Chosen ciphertext | Handled by FO transform | Handled by FO transform |
| Side-channel (timing) | Mitigated (ChaCha20, constant-time) | Same |
| Cache attacks | Mitigated (ChaCha20) | Same |
| GPU/ASIC brute force | Mitigated (Argon2id) | Same |

## Security Proofs (Informal)

### 1. KEM Security (IND-CCA2)

The KEM is CCA2-secure under the Module-LWE assumption via the Fujisaki-Okamoto transform.

**Theorem**: If the underlying PKE scheme is IND-CPA secure under Module-LWE, then the FO-transformed KEM is IND-CCA2 secure.

**Sketch**:
- Module-LWE is believed hard for both classical and quantum adversaries
- The FO transform makes the encryption deterministic given the message μ
- Any modified ciphertext will fail re-encryption verification
- Implicit rejection prevents information leakage through error responses
- The shared secret depends on both the message μ and the ciphertext hash

### 2. Cascade Security

**Theorem**: The triple-cascade encryption is at least as secure as the strongest remaining layer.

**Proof sketch**:
- Each layer uses an independently derived key
- Keys are derived through separate KDF paths (SHA3-256 and BLAKE2b)
- Compromising one key doesn't help recover other keys
- To recover plaintext, an adversary must break ALL three layers
- The overall security is: max(security_layer1, security_layer2, security_layer3)

### 3. Key Separation

**Theorem**: Keys derived from different KDF paths are computationally independent.

**Argument**:
- Path 1 uses HKDF-SHA3-256 with domain separation info "Q-HybridCrypt-v2-ChaCha20-Key"
- Path 2 uses HKDF-BLAKE2b with domain separation info "Q-HybridCrypt-v2-AES256-Key"
- Path 3 uses HKDF-SHA3-256 with domain separation info "Q-HybridCrypt-v2-HMAC-Key"
- Different hash functions (SHA3 vs BLAKE2b) provide mathematical separation
- Same hash function with different info strings provides domain separation
- Recovering one key from another would require breaking the underlying hash function

## Attack Resistance

### Classical Cryptanalysis

| Attack | Resistance | Mechanism |
|--------|-----------|-----------|
| Linear cryptanalysis | Resistant | ChaCha20 (no linear approximations) |
| Differential cryptanalysis | Resistant | AES-256 (14 rounds, full diffusion) |
| Related-key attacks | Resistant | Independent keys per layer |
| Meet-in-the-middle | Resistant | Three layers require breaking all |
| Birthday attacks | Resistant | 256-bit hash outputs |

### Quantum Cryptanalysis

| Attack | Resistance | Mechanism |
|--------|-----------|-----------|
| Shor's algorithm | Resistant | Module-LWE (not factoring/discrete log) |
| Grover's algorithm | 128-bit security | 256-bit symmetric keys |
| Quantum period finding | Resistant | LWE has no exploitable periodicity |
| Quantum random walk | Unknown | Conservative parameters mitigate risk |

### Side-Channel Attacks

| Attack | Resistance | Mechanism |
|--------|-----------|-----------|
| Timing attacks | Partial | ChaCha20 is constant-time; AES is not |
| Cache attacks | Partial | ChaCha20 has no table lookups |
| Power analysis | Not addressed | Hardware-level countermeasures needed |
| EM attacks | Not addressed | Hardware-level countermeasures needed |

### Protocol-Level Attacks

| Attack | Resistance | Mechanism |
|--------|-----------|-----------|
| Replay attacks | Application responsibility | Use timestamps/sequence numbers in AAD |
| Chosen-ciphertext | Resistant | FO transform + triple auth |
| Padding oracle | Resistant | Verify-then-decrypt pattern |
| Key compromise impersonation | Not addressed | Use certificate-based key validation |
| Forward secrecy | Partial | Ephemeral KEM per message |

## Known Limitations

1. **Pure Python Performance**: The current implementation is in pure Python, making it significantly slower than C/C++ implementations. For high-throughput applications, consider using optimized backends.

2. **Timing Side-Channels in AES**: The pure-Python AES implementation may have timing variability through table lookups (S-box). The ChaCha20 layer mitigates this as the first encryption layer.

3. **No Side-Channel Hardening at Hardware Level**: Power analysis and EM attacks are not addressed. This is a software library; hardware countermeasures are outside its scope.

4. **Memory Usage**: Argon2id with default parameters uses ~100MB of RAM. This is intentional (memory-hardness) but may be unsuitable for constrained devices.

5. **Large Key Sizes**: Lattice-based KEM keys are ~1-2KB, significantly larger than RSA-2048 (256 bytes) or ECC-P256 (64 bytes). This is inherent to lattice-based cryptography.

6. **No Key Rotation Protocol**: The library provides cryptographic primitives but does not implement a key management or rotation protocol. Applications must implement their own.

## Security Recommendations

1. **Always use AAD**: Include contextual information (user ID, timestamp, purpose) as associated data to bind the ciphertext to its context.

2. **Never reuse nonces**: Each encryption uses a fresh KEM encapsulation, ensuring unique keys per message. Do not attempt to reuse key material.

3. **Use strong passwords**: Argon2id protects weak passwords but cannot compensate for extremely weak ones. Use long, random passwords.

4. **Validate public keys**: Always verify that a public key belongs to the intended recipient before encrypting. Key substitution attacks are possible without authentication.

5. **Secure key storage**: Private keys must be stored securely. Consider using hardware security modules (HSMs) for key storage in production.

6. **Keep software updated**: Monitor for security updates and cryptographic advances, especially in the post-quantum cryptography space.

## Comparison with NIST PQC Standards

| Aspect | Q-HybridCrypt v2 | ML-KEM (Kyber) Standard |
|--------|------------------|------------------------|
| KEM Basis | Module-LWE | Module-LWE |
| KEM Security | NIST Level 3 | Configurable (1/3/5) |
| Symmetric | Triple cascade | Not specified |
| CCA2 | FO transform | FO transform |
| Implementation | Pure Python | Reference C |

Note: Q-HybridCrypt implements the same mathematical framework as ML-KEM (Kyber) but is NOT a certified implementation. For applications requiring NIST certification, use a validated ML-KEM implementation.
