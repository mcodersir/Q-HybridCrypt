# Q-HybridCrypt v2.0 "PHOENIX" — Complete API Reference

## Table of Contents

1. [QHybridCrypt Class](#qhybridcrypt-class)
2. [Migration SDK API](#migration-sdk-api)
3. [Convenience Functions](#convenience-functions)
4. [Constants Reference](#constants-reference)
5. [Utility Functions](#utility-functions)
6. [Error Handling](#error-handling)
7. [Type Annotations](#type-annotations)

---

## QHybridCrypt Class

The `QHybridCrypt` class is the primary entry point for all cryptographic operations in the PHOENIX protocol. It integrates the lattice-based key encapsulation mechanism, triple-cascade encryption engine, Argon2id password hashing, and streaming encryption into a single, cohesive API. Each instance maintains its own security level configuration and KEM state, allowing you to create multiple instances with different security parameters in the same application.

### Constructor

```python
QHybridCrypt(security_level: int = 3)
```

Creates a new QHybridCrypt instance configured with the specified NIST security level. The security level determines the lattice KEM parameters (module rank, noise distribution) and affects key sizes, ciphertext sizes, and the theoretical security guarantees of the system. The default level 3 provides a balanced trade-off between security and performance, equivalent to AES-192 in classical security and targeting NIST PQC Level 3 (approximately 128-bit quantum security).

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `security_level` | `int` | `3` | NIST security level: `1` (AES-128 equivalent, ~128-bit classical), `3` (AES-192 equivalent, ~192-bit classical, default), or `5` (AES-256 equivalent, ~256-bit classical) |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `ValueError` | If `security_level` is not 1, 3, or 5 |

**Example**:

```python
from qhybridcrypt import QHybridCrypt

# Default: NIST Level 3 (recommended for most applications)
crypto = QHybridCrypt()

# Maximum security: NIST Level 5 (for highly sensitive data)
crypto_max = QHybridCrypt(security_level=5)

# Lower security for testing: NIST Level 1 (faster operations)
crypto_test = QHybridCrypt(security_level=1)
```

---

### generate_keypair

```python
generate_keypair(seed: bytes = None) -> Tuple[bytes, bytes]
```

Generates a quantum-resistant key pair based on Module-LWE (Module Learning With Errors) polynomial arithmetic. The public key can be freely shared and is used by senders to encrypt data, while the private key must be kept secret and is used by recipients to decrypt data. The key generation process involves sampling polynomial vectors from a centered binomial distribution, performing polynomial arithmetic over the ring Z_3329[X]/(X^256+1), and applying the Fujisaki-Okamoto transform for CCA2 security.

When a `seed` is provided, the key generation becomes deterministic, producing the same key pair for the same seed value. This is primarily useful for testing and reproducible builds. In production, always leave `seed` as `None` to use the cryptographic entropy pool for random key generation, ensuring that each key pair is unique and unpredictable.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `seed` | `bytes` | `None` | Optional 64-byte seed for deterministic key generation. In production, leave as `None` for cryptographically random key generation. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `public_key` | `bytes` | The public key (~1184 bytes at Level 3). Safe to share with anyone who needs to send you encrypted data. |
| `private_key` | `bytes` | The private key (~2400 bytes at Level 3). Must be kept secret. Store securely (HSM, KMS, or encrypted storage). |

**Key Sizes by Security Level**:

| Level | Public Key | Private Key | KEM Ciphertext | Shared Secret |
|-------|-----------|-------------|----------------|---------------|
| 1 | ~800 bytes | ~1632 bytes | ~768 bytes | 32 bytes |
| 3 | ~1184 bytes | ~2400 bytes | ~1088 bytes | 32 bytes |
| 5 | ~1568 bytes | ~3168 bytes | ~1568 bytes | 32 bytes |

**Example**:

```python
crypto = QHybridCrypt()

# Random keypair (production use)
public_key, private_key = crypto.generate_keypair()

# Deterministic keypair (testing only)
pk_test, sk_test = crypto.generate_keypair(seed=b'test_seed_' + b'0' * 55)

# Verify key sizes
info = crypto.get_info()
print(f"Public key: {info['key_sizes']['public_key']} bytes")
print(f"Secret key: {info['key_sizes']['secret_key']} bytes")
```

---

### encrypt

```python
encrypt(
    plaintext: bytes,
    public_key: bytes,
    associated_data: bytes = b'',
    padding: bool = True
) -> bytes
```

Encrypts data using the full PHOENIX triple-cascade protocol. This method performs five sequential operations: (1) adds random length-hiding padding to the plaintext if enabled, (2) encapsulates a shared secret using the lattice-based KEM with the recipient's public key, (3) derives three independent cascade keys through separate KDF paths (HKDF-SHA3-256 and HKDF-BLAKE2b), (4) applies triple-cascade encryption through ChaCha20-Poly1305, AES-256-GCM, and SHA3-Keystream XOR layers, and (5) constructs the final message with the magic header, protocol version, salt, KEM ciphertext, and cascade ciphertext.

Each encryption operation generates a fresh KEM encapsulation, which means every ciphertext uses unique symmetric keys even if the same public key is used repeatedly. This provides forward secrecy at the message level: compromising one message's keys does not affect the security of any other message. The optional padding feature adds between 16 and 256 random bytes to the plaintext, which hides the true length of the encrypted data and prevents traffic analysis attacks that could infer information from ciphertext sizes.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `plaintext` | `bytes` | required | Data to encrypt. Can be empty if padding is enabled. |
| `public_key` | `bytes` | required | Recipient's public key from `generate_keypair()`. |
| `associated_data` | `bytes` | `b''` | Additional authenticated data (AAD). Authenticated but not encrypted. Must be provided identically during decryption. |
| `padding` | `bool` | `True` | If `True`, adds 16–256 bytes of random padding for length hiding. Recommended for most use cases. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `encrypted_message` | `bytes` | The PHOENIX-encrypted message. Format: `QHC2` header + version + KEM CT length + salt + KEM ciphertext + cascade ciphertext. |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `ValueError` | If plaintext is empty and padding is disabled. |
| `ValueError` | If public_key is invalid or malformed. |

**Message Format**:

```
┌──────────┬──────────┬──────────────┬──────────┬──────────────┬──────────────┐
│ Magic(4B)│ Ver(2B)  │ KEM CT Len(2B)│ Salt(32B)│ KEM CT(var)  │ Cascade CT   │
│ "QHC2"   │ 0x0002   │ LE16         │ random   │ ~1088B (L3)  │ (variable)   │
└──────────┴──────────┴──────────────┴──────────┴──────────────┴──────────────┘
```

**Example**:

```python
crypto = QHybridCrypt()
public_key, private_key = crypto.generate_keypair()

# Basic encryption
ciphertext = crypto.encrypt(b"secret message", public_key)

# With associated data (authenticated but not encrypted)
aad = b"user:alice|timestamp:1700000000|request_id:abc123"
ciphertext = crypto.encrypt(
    b"secret message",
    public_key,
    associated_data=aad
)

# Without padding (exact ciphertext size, no length hiding)
ciphertext = crypto.encrypt(b"exact size data", public_key, padding=False)

# Encrypt empty data (requires padding=True, which is the default)
ciphertext = crypto.encrypt(b"", public_key)
```

---

### decrypt

```python
decrypt(
    encrypted_message: bytes,
    private_key: bytes,
    associated_data: bytes = b''
) -> bytes
```

Decrypts data using the full PHOENIX protocol, performing the reverse of the encryption process with authentication verification at each layer. The method first parses the message format and validates the magic header and protocol version. It then decapsulates the KEM shared secret using the recipient's private key, derives the same three cascade keys through the independent KDF paths, and applies triple-cascade decryption in reverse order (SHA3-Keystream → AES-256-GCM → ChaCha20-Poly1305). All three authentication tags are verified during decryption, and if any check fails, the operation is rejected without revealing which layer failed.

The security of the decryption process is strengthened by the Fujisaki-Okamoto transform in the KEM. If the KEM ciphertext has been tampered with, the decapsulation produces a pseudorandom shared secret (implicit rejection) rather than signaling an error, which prevents chosen-ciphertext attacks from learning information about the secret key. This design ensures that an attacker cannot distinguish between a valid and invalid ciphertext based on the decryption behavior.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `encrypted_message` | `bytes` | required | Encrypted message from `encrypt()`. |
| `private_key` | `bytes` | required | Recipient's private key from `generate_keypair()`. |
| `associated_data` | `bytes` | `b''` | Must match the AAD used during encryption. Mismatched AAD causes authentication failure. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `plaintext` | `bytes` | The original plaintext data. |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `ValueError` | If message is too short or has invalid format. |
| `ValueError` | If magic header is not `QHC2`. |
| `ValueError` | If protocol version is unsupported. |
| `ValueError` | If KEM decapsulation fails. |
| `ValueError` | If any cascade authentication check fails (Poly1305, GCM, or HMAC). |
| `ValueError` | If decrypted plaintext length is inconsistent. |

**Important**: Error messages do NOT reveal which authentication layer failed, preventing attackers from targeting specific layers.

**Example**:

```python
crypto = QHybridCrypt()
public_key, private_key = crypto.generate_keypair()

# Basic decryption
ciphertext = crypto.encrypt(b"secret message", public_key)
plaintext = crypto.decrypt(ciphertext, private_key)
assert plaintext == b"secret message"

# With AAD (must match encryption AAD exactly)
aad = b"user:alice|timestamp:1700000000"
ciphertext = crypto.encrypt(b"secret", public_key, associated_data=aad)
plaintext = crypto.decrypt(ciphertext, private_key, associated_data=aad)

# Wrong AAD is rejected
try:
    crypto.decrypt(ciphertext, private_key, associated_data=b"wrong")
except ValueError as e:
    print(f"Decryption failed (expected): {e}")
```

---

### encrypt_stream

```python
encrypt_stream(
    data: bytes,
    public_key: bytes,
    chunk_size: int = 65536
) -> bytes
```

Encrypts large data by splitting it into independently encrypted chunks. Each chunk is encrypted with its own KEM encapsulation, providing forward secrecy within the stream. The chunk index is included as associated data for each chunk, ensuring that chunks cannot be reordered or substituted without detection. This method is suitable for encrypting files or data streams that exceed the practical size limit for single-message encryption.

The streaming approach offers several advantages over single-message encryption for large data. First, memory usage is bounded by the chunk size rather than the total data size, making it practical to encrypt multi-gigabyte files on systems with limited RAM. Second, each chunk has its own KEM encapsulation, so compromising the keys for one chunk does not affect the security of other chunks. Third, the chunk index AAD prevents undetected reordering or removal of chunks, which is important for data integrity in streaming scenarios.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | `bytes` | required | Data to encrypt (can be very large). |
| `public_key` | `bytes` | required | Recipient's public key. |
| `chunk_size` | `int` | `65536` | Size of each chunk in bytes (64 KB default). |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `encrypted_stream` | `bytes` | Concatenated encrypted chunks, each prefixed with its length. |

**Example**:

```python
crypto = QHybridCrypt()
public_key, private_key = crypto.generate_keypair()

# Encrypt a large file
large_data = b"x" * (10 * 1024 * 1024)  # 10 MB
encrypted = crypto.encrypt_stream(large_data, public_key, chunk_size=65536)

# Decrypt the stream
decrypted = crypto.decrypt_stream(encrypted, private_key)
assert decrypted == large_data
```

---

### decrypt_stream

```python
decrypt_stream(
    encrypted_data: bytes,
    private_key: bytes
) -> bytes
```

Decrypts a stream of encrypted chunks produced by `encrypt_stream()`. The method iterates through the encrypted data, reading each chunk's length prefix, extracting the chunk, and decrypting it independently. Decrypted chunks are concatenated to produce the original plaintext. The method validates each chunk's authentication tags independently, so if any chunk is tampered with, the operation fails immediately.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `encrypted_data` | `bytes` | required | Data from `encrypt_stream()`. |
| `private_key` | `bytes` | required | Recipient's private key. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `plaintext` | `bytes` | The original concatenated plaintext data. |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `ValueError` | If stream format is invalid or any chunk decryption fails. |

---

### hash_password

```python
hash_password(
    password: str,
    salt: bytes = None,
    time_cost: int = None,
    memory_cost: int = None
) -> Tuple[bytes, bytes]
```

Hashes a password using the Argon2id algorithm with Python's `hashlib.blake2b` as the underlying hash function. Argon2id is the RFC 9106 recommended password hashing algorithm, combining data-independent addressing (for side-channel resistance) in the first pass with data-dependent addressing (for GPU resistance) in subsequent passes. The default parameters (4 iterations, 100 MB memory) follow OWASP recommendations and provide strong protection against brute-force attacks on modern GPU hardware, which can compute billions of SHA-256 hashes per second but is severely limited by Argon2id's memory requirements.

When no salt is provided, a cryptographically random 16-byte salt is generated automatically. The salt must be stored alongside the hash for later verification. If you need deterministic hashing (e.g., for key derivation from a password), provide an explicit salt. The time and memory cost parameters allow you to tune the hashing intensity: higher values provide more security but take longer and use more memory, which may be problematic on resource-constrained devices.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `str` | required | Password to hash. Will be UTF-8 encoded internally. |
| `salt` | `bytes` | `None` | Salt bytes. Generated randomly (16 bytes) if `None`. |
| `time_cost` | `int` | `4` | Number of iterations. Higher = more secure, slower. |
| `memory_cost` | `int` | `102400` | Memory in KB to use. Default: 100 MB. Higher = more GPU-resistant. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `hash_result` | `bytes` | 32-byte password hash. |
| `salt` | `bytes` | 16-byte salt used for hashing. |

**Example**:

```python
crypto = QHybridCrypt()

# Default parameters (OWASP recommended)
password_hash, salt = crypto.hash_password("my_secure_password")

# Custom parameters for constrained environments
password_hash, salt = crypto.hash_password(
    "my_secure_password",
    time_cost=2,
    memory_cost=32768  # 32 MB
)

# With explicit salt (for key derivation)
import os
my_salt = os.urandom(16)
password_hash, _ = crypto.hash_password("my_password", salt=my_salt)
```

---

### verify_password

```python
verify_password(
    password: str,
    salt: bytes,
    expected_hash: bytes,
    time_cost: int = None,
    memory_cost: int = None
) -> bool
```

Verifies a password against a stored hash using constant-time comparison to prevent timing attacks. The method recomputes the hash with the same parameters and salt, then compares the result against the expected hash in constant time. This ensures that an attacker cannot learn information about the hash by measuring the time taken to verify different password guesses, which is a critical defense against remote timing attacks.

The time_cost and memory_cost parameters must match the values used during hashing. If they differ, the computed hash will not match the expected hash, and verification will always fail. It is strongly recommended to store the time_cost and memory_cost alongside the salt and hash to ensure consistent verification.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `str` | required | Password to verify. |
| `salt` | `bytes` | required | Salt used during the original hashing. |
| `expected_hash` | `bytes` | required | Hash to verify against. |
| `time_cost` | `int` | `4` | Must match the time_cost used during hashing. |
| `memory_cost` | `int` | `102400` | Must match the memory_cost used during hashing. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `is_valid` | `bool` | `True` if password matches, `False` otherwise. |

**Example**:

```python
crypto = QHybridCrypt()

# Hash and store
password_hash, salt = crypto.hash_password("correct_password")

# Later: verify
if crypto.verify_password("correct_password", salt, password_hash):
    print("Access granted!")
else:
    print("Access denied!")

# Wrong password returns False (not an exception)
if not crypto.verify_password("wrong_password", salt, password_hash):
    print("Correctly rejected wrong password")
```

---

### get_info

```python
get_info() -> Dict
```

Returns a comprehensive dictionary describing the cryptographic system's configuration, algorithms, parameters, and security claims. This method is useful for logging, debugging, compliance reporting, and building user interfaces that display encryption metadata. The returned dictionary is structured with nested keys for easy programmatic access to specific information.

**Returns**: A dictionary with the following top-level keys:

| Key | Type | Description |
|-----|------|-------------|
| `name` | `str` | System name: `"Q-HybridCrypt"` |
| `version` | `str` | Protocol version string |
| `codename` | `str` | Release codename: `"PHOENIX"` |
| `quantum_resistant` | `bool` | Always `True` |
| `security_level` | `int` | NIST security level (1, 3, or 5) |
| `algorithms` | `dict` | All algorithms used, keyed by component |
| `parameters` | `dict` | Cryptographic parameters (key sizes, etc.) |
| `key_sizes` | `dict` | Key and ciphertext sizes in bytes |
| `security_claims` | `dict` | Security guarantees and threat resistance |

**Example**:

```python
crypto = QHybridCrypt()
info = crypto.get_info()

print(f"System: {info['name']} v{info['version']} '{info['codename']}'")
print(f"Quantum Resistant: {info['quantum_resistant']}")
print(f"Security Level: NIST Level {info['security_level']}")
print(f"Classical Security: {info['security_claims']['classical_bits']}-bit")
print(f"Quantum Security: {info['security_claims']['quantum_bits']}-bit")
print(f"KEM Algorithm: {info['algorithms']['kem']}")
print(f"Public Key Size: {info['key_sizes']['public_key']} bytes")
```

---

## Migration SDK API

The Migration SDK provides a complete toolkit for migrating encrypted data from other cryptographic libraries to Q-HybridCrypt. It supports four source libraries through dedicated migrator classes, a universal convenience function, and batch migration capabilities. The entire SDK is built around the Transparent Re-encryption principle, where decryption of the old format and re-encryption under PHOENIX happen within the SDK without exposing plaintext in application code.

![Migration Flow](images/migration_flow.png)

### MigrationSDK

```python
MigrationSDK(security_level: int = 3)
```

The core migration class that provides all migration functionality. It wraps a `QHybridCrypt` instance and maintains an internal migration log for audit purposes. All library-specific migrators delegate to this class, so it can be used directly for any migration scenario.

**Constructor Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `security_level` | `int` | `3` | NIST security level for the new PHOENIX encryption. |

#### migrate_encrypted_data

```python
migrate_encrypted_data(
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    associated_data: bytes = b'',
    keep_old_key_ref: bool = True
) -> Tuple[bytes, bytes]
```

The primary migration method implementing Transparent Re-encryption. Takes old-format ciphertext and a decryption callback, decrypts the old data internally, generates a new PHOENIX keypair, and re-encrypts the plaintext. The plaintext never appears in your application code.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `old_ciphertext` | `bytes` | required | Ciphertext from the old library. |
| `old_decrypt_fn` | `Callable[[bytes], bytes]` | required | Function that decrypts old ciphertext. Must accept `bytes` and return `bytes`. |
| `associated_data` | `bytes` | `b''` | Optional AAD for the new PHOENIX encryption. |
| `keep_old_key_ref` | `bool` | `True` | If `True`, stores SHA3-256 hash of old ciphertext prefix for audit trail. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `new_ciphertext` | `bytes` | PHOENIX-encrypted data. |
| `public_key` | `bytes` | PHOENIX public key for future encryption. |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `MigrationError` | If `old_decrypt_fn` raises an exception or returns non-bytes. |

**Example**:

```python
from qhybridcrypt.migration import MigrationSDK

sdk = MigrationSDK()

def my_old_decrypt(ct: bytes) -> bytes:
    # Your existing decryption logic
    return plaintext

new_ct, pk = sdk.migrate_encrypted_data(
    old_ciphertext=old_encrypted_data,
    old_decrypt_fn=my_old_decrypt,
    associated_data=b"context:db_migration"
)
```

#### migrate_with_keypair

```python
migrate_with_keypair(
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    public_key: bytes,
    associated_data: bytes = b''
) -> bytes
```

Migrates encrypted data using an existing PHOENIX keypair instead of generating a new one. Use this when you already have a PHOENIX keypair and want to migrate additional data to the same key. This is useful for incremental migrations where new data is added to a set that was previously migrated.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `old_ciphertext` | `bytes` | required | Ciphertext from the old library. |
| `old_decrypt_fn` | `Callable[[bytes], bytes]` | required | Decryption function for old format. |
| `public_key` | `bytes` | required | Existing PHOENIX public key. |
| `associated_data` | `bytes` | `b''` | Optional AAD. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `new_ciphertext` | `bytes` | PHOENIX-encrypted data (using the provided public key). |

#### batch_migrate

```python
batch_migrate(
    old_ciphertexts: List[bytes],
    old_decrypt_fn: Callable[[bytes], bytes],
    associated_data: bytes = b'',
    on_progress: Optional[Callable[[int, int], None]] = None
) -> Tuple[List[bytes], bytes]
```

Batch-migrates multiple encrypted data items to a single PHOENIX keypair. All items are encrypted under the same key, simplifying key management for large datasets. Each item receives a unique AAD suffix (its index) to ensure cryptographic separation. The method supports an optional progress callback for monitoring long-running migrations.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `old_ciphertexts` | `List[bytes]` | required | List of old-format ciphertexts. |
| `old_decrypt_fn` | `Callable[[bytes], bytes]` | required | Decryption function for all items. |
| `associated_data` | `bytes` | `b''` | Base AAD for all items. Index is appended automatically. |
| `on_progress` | `Callable[[int, int], None]` | `None` | Progress callback: `on_progress(current, total)`. |

**Returns**:

| Return Value | Type | Description |
|--------------|------|-------------|
| `new_ciphertexts` | `List[bytes]` | List of PHOENIX-encrypted ciphertexts. |
| `public_key` | `bytes` | Single PHOENIX public key for all items. |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `MigrationError` | If any item fails to migrate. Batch is aborted at the first failure. |

#### get_migration_log

```python
get_migration_log() -> List[Dict]
```

Returns a copy of the internal migration log, which records details about each migration operation. Each entry contains the migration status, hash of the old format, optional old key reference, hash of the new public key, security level, and protocol version. This log is useful for compliance auditing and post-migration verification.

**Returns**: `List[Dict]` — Each dictionary contains:

| Key | Type | Description |
|-----|------|-------------|
| `status` | `str` | Always `"migrated"`. |
| `old_format_hash` | `str` | SHA3-256 hex digest of the old ciphertext. |
| `old_key_ref` | `str` or `None` | SHA3-256 hex digest of old ciphertext prefix (if `keep_old_key_ref=True`). |
| `new_key_hash` | `str` | SHA3-256 hex digest of the new PHOENIX public key. |
| `security_level` | `int` | NIST security level used. |
| `protocol_version` | `int` | PHOENIX protocol version (2). |

#### clear_migration_log

```python
clear_migration_log() -> None
```

Clears the internal migration log. Call this after you have exported or persisted the log to free memory.

---

### PyCryptodomeMigrator

```python
PyCryptodomeMigrator(security_level: int = 3)
```

Migrator for data encrypted with PyCryptodome (AES-GCM, AES-CBC, RSA, etc.). Delegates to `MigrationSDK` internally but provides a library-specific interface for clarity and discoverability.

#### migrate

```python
migrate(
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Migrate PyCryptodome-encrypted data to Q-HybridCrypt. Parameters and return values are identical to `MigrationSDK.migrate_encrypted_data()`.

**Example**:

```python
from qhybridcrypt.migration import PyCryptodomeMigrator

migrator = PyCryptodomeMigrator()

def pyaes_decrypt(ct: bytes) -> bytes:
    from Crypto.Cipher import AES
    nonce, tag, data = ct[:16], ct[16:32], ct[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(data, tag)

new_ct, pk = migrator.migrate(old_ciphertext, pyaes_decrypt)
```

---

### CryptographyIOMigrator

```python
CryptographyIOMigrator(security_level: int = 3)
```

Migrator for data encrypted with the `cryptography` library (Fernet, AES-GCM, ChaCha20-Poly1305, etc.). Includes a specialized `migrate_fernet()` method for direct Fernet token migration.

#### migrate

```python
migrate(
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Standard migration method. Same interface as `PyCryptodomeMigrator.migrate()`.

#### migrate_fernet

```python
migrate_fernet(
    fernet_token: bytes,
    fernet_key: bytes,
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Convenience method that directly migrates Fernet tokens by handling the Fernet decryption internally. You only need to provide the Fernet token and key; the method creates a temporary Fernet instance, decrypts the token, and re-encrypts under PHOENIX. This eliminates the need to write a decryption callback for the common Fernet case.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fernet_token` | `bytes` | required | Fernet-encrypted token. |
| `fernet_key` | `bytes` | required | Fernet key (URL-safe base64 encoded). |
| `associated_data` | `bytes` | `b''` | Optional AAD for PHOENIX encryption. |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `MigrationError` | If the `cryptography` library is not installed. |

**Example**:

```python
from qhybridcrypt.migration import CryptographyIOMigrator

migrator = CryptographyIOMigrator()
new_ct, pk = migrator.migrate_fernet(fernet_token, fernet_key)
```

---

### NaClMigrator

```python
NaClMigrator(security_level: int = 3)
```

Migrator for data encrypted with PyNaCl / NaCl (SecretBox, SealedBox, etc.). NaCl uses XSalsa20-Poly1305 for symmetric encryption and X25519 for key exchange, both of which are quantum-vulnerable in the key exchange component. Migration to Q-HybridCrypt replaces the X25519 key exchange with Module-LWE KEM.

#### migrate

```python
migrate(
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Standard migration method with the same interface as other migrators.

**Example**:

```python
from qhybridcrypt.migration import NaClMigrator

migrator = NaClMigrator()

def nacl_secretbox_decrypt(ct: bytes) -> bytes:
    from nacl.secret import SecretBox
    box = SecretBox(nacl_key)
    return box.decrypt(ct)

new_ct, pk = migrator.migrate(old_ct, nacl_secretbox_decrypt)
```

---

### CustomAESMigrator

```python
CustomAESMigrator(security_level: int = 3)
```

Migrator for custom AES-GCM implementations. Provides a specialized `migrate_aes_gcm()` method that accepts raw AES-GCM components (nonce, ciphertext, tag, key) as separate parameters, eliminating the need to write a decryption callback for the common AES-GCM case. The method attempts decryption using the `cryptography` library first, falling back to PyCryptodome if the `cryptography` library is not available.

#### migrate

```python
migrate(
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Standard migration method for custom formats that require a decryption callback.

#### migrate_aes_gcm

```python
migrate_aes_gcm(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aes_key: bytes,
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Convenience method for migrating raw AES-GCM components. Handles decryption internally using either the `cryptography` library or PyCryptodome as a backend. This is the recommended method when your AES-GCM data is stored as separate components rather than a single concatenated byte string.

**Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `nonce` | `bytes` | required | GCM nonce/IV (typically 12 bytes). |
| `ciphertext` | `bytes` | required | AES-GCM ciphertext (without tag). |
| `tag` | `bytes` | required | GCM authentication tag (typically 16 bytes). |
| `aes_key` | `bytes` | required | AES key used for decryption (16, 24, or 32 bytes). |
| `associated_data` | `bytes` | `b''` | AAD used during original encryption (if any). |

**Raises**:

| Exception | Condition |
|-----------|-----------|
| `MigrationError` | If neither `cryptography` nor PyCryptodome is available. |

**Example**:

```python
from qhybridcrypt.migration import CustomAESMigrator

migrator = CustomAESMigrator()
new_ct, pk = migrator.migrate_aes_gcm(
    nonce=nonce_bytes,
    ciphertext=ct_bytes,
    tag=tag_bytes,
    aes_key=key_bytes
)
```

---

### MigrationError

```python
class MigrationError(Exception)
```

Raised when a migration operation fails. Common causes include: the old decryption function raises an exception (indicating corrupted ciphertext, wrong key, or invalid format), the old decryption function returns a non-bytes value, or a required dependency (e.g., the `cryptography` library for `migrate_fernet()`) is not installed.

**Example**:

```python
from qhybridcrypt.migration import MigrationSDK, MigrationError

sdk = MigrationSDK()

try:
    new_ct, pk = sdk.migrate_encrypted_data(old_ct, old_decrypt_fn)
except MigrationError as e:
    print(f"Migration failed: {e}")
    # Handle failure: log, alert, retry, etc.
```

---

## Convenience Functions

These module-level functions provide quick, one-shot access to common operations without creating a `QHybridCrypt` instance. Each function internally creates a temporary instance, performs the operation, and returns the result. They are convenient for scripts and simple use cases, but for repeated operations, creating a persistent `QHybridCrypt` instance is more efficient because it avoids the overhead of re-initializing the KEM on each call.

### encrypt_message

```python
encrypt_message(
    plaintext: bytes,
    public_key: bytes,
    associated_data: bytes = b''
) -> bytes
```

One-shot encryption. Equivalent to `QHybridCrypt().encrypt(plaintext, public_key, associated_data)`.

### decrypt_message

```python
decrypt_message(
    encrypted_message: bytes,
    private_key: bytes,
    associated_data: bytes = b''
) -> bytes
```

One-shot decryption. Equivalent to `QHybridCrypt().decrypt(encrypted_message, private_key, associated_data)`.

### generate_keypair

```python
generate_keypair(seed: bytes = None) -> Tuple[bytes, bytes]
```

One-shot keypair generation. Equivalent to `QHybridCrypt().generate_keypair(seed)`.

### secure_random_bytes

```python
secure_random_bytes(length: int) -> bytes
```

Generates cryptographically secure random bytes using the global entropy pool. The pool combines `os.urandom()` output with SHAKE-256 XOF for enhanced security and forward secrecy. Each call also mixes fresh OS entropy into the pool state.

### constant_time_compare

```python
constant_time_compare(a: bytes, b: bytes) -> bool
```

Compares two byte sequences in constant time. The comparison time depends only on the length of the sequences, not their content, which prevents timing attacks. Returns `True` if the sequences are identical, `False` otherwise. If the sequences have different lengths, the function still performs a dummy comparison to avoid leaking length information through timing.

### migrate_from

```python
migrate_from(
    library: str,
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    security_level: int = 3,
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]
```

Universal one-step migration from any supported library. This is the simplest migration function: specify the source library name, provide the old ciphertext and a decryption callback, and receive PHOENIX-encrypted data. The function creates a `MigrationSDK` instance internally, so it is best used for one-off migrations rather than bulk operations.

**Supported library names**:

| Library Name Aliases | Source Library |
|---------------------|---------------|
| `'pycryptodome'`, `'pycrypto'` | PyCryptodome |
| `'cryptography'`, `'fernet'` | cryptography library |
| `'nacl'`, `'pynacl'` | PyNaCl / NaCl |
| `'custom'`, `'aes-gcm'` | Custom AES-GCM |
| `'hashlib'`, `'custom-hash'` | hashlib-based implementations |

**Example**:

```python
from qhybridcrypt.migration import migrate_from

new_ct, pk = migrate_from(
    library='pycryptodome',
    old_ciphertext=old_data,
    old_decrypt_fn=my_decrypt,
    security_level=3,
    associated_data=b"migration_context"
)
```

---

## Constants Reference

All cryptographic parameters are defined in `qhybridcrypt.constants` and are used throughout the library to ensure consistency and correctness. These constants are based on NIST PQC recommendations, OWASP guidelines, and conservative security estimates. You should not modify these constants unless you fully understand the cryptographic implications.

### Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION` | `2` | PHOENIX protocol version number. |
| `MAGIC_HEADER` | `b'QHC2'` | 4-byte magic header identifying PHOENIX v2 messages. |

### KEM Parameters (Kyber-768 Equivalent)

| Constant | Value | Description |
|----------|-------|-------------|
| `KEM_N` | `256` | Polynomial ring degree (Z_q[X]/(X^256+1)). |
| `KEM_Q` | `3329` | Prime modulus (smallest prime where q ≡ 1 mod 512). |
| `KEM_K` | `3` | Module rank for NIST Level 3 security. |
| `KEM_ETA1` | `2` | Noise parameter for key generation. |
| `KEM_ETA2` | `2` | Noise parameter for encapsulation. |
| `KEM_DU` | `10` | Compression bits for u-component. |
| `KEM_DV` | `4` | Compression bits for v-component. |
| `KEM_PUBLIC_KEY_SIZE` | `1184` | Public key size in bytes (Level 3). |
| `KEM_SECRET_KEY_SIZE` | `2400` | Secret key size in bytes (Level 3). |
| `KEM_CIPHERTEXT_SIZE` | `1088` | KEM ciphertext size in bytes (Level 3). |
| `KEM_SHARED_SECRET_SIZE` | `32` | Shared secret size in bytes. |

### Symmetric Cipher Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `AES_KEY_SIZE` | `32` | AES-256 key size (256 bits). |
| `AES_GCM_IV_SIZE` | `12` | GCM IV size (96 bits). |
| `AES_GCM_TAG_SIZE` | `16` | GCM authentication tag size (128 bits). |
| `CHACHA20_KEY_SIZE` | `32` | ChaCha20 key size (256 bits). |
| `CHACHA20_NONCE_SIZE` | `12` | ChaCha20 nonce size (96 bits). |
| `POLY1305_TAG_SIZE` | `16` | Poly1305 tag size (128 bits). |

### Key Derivation Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `HKDF_HASH_SIZE` | `32` | SHA3-256 output size. |
| `HKDF_SALT_SIZE` | `32` | Salt size for HKDF operations. |
| `KDF_INFO_CHACHA` | `b'Q-HybridCrypt-v2-ChaCha20-Key'` | Domain separation for ChaCha20 key derivation. |
| `KDF_INFO_AES` | `b'Q-HybridCrypt-v2-AES256-Key'` | Domain separation for AES key derivation. |
| `KDF_INFO_HMAC` | `b'Q-HybridCrypt-v2-HMAC-Key'` | Domain separation for HMAC key derivation. |
| `KDF_INFO_PADDING` | `b'Q-HybridCrypt-v2-Padding-Key'` | Domain separation for padding key derivation. |
| `CASCADE_LAYERS` | `3` | Number of cascade encryption layers. |

### Argon2id Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `ARGON2_DEFAULT_TIME_COST` | `4` | Number of iterations (OWASP recommended). |
| `ARGON2_DEFAULT_MEMORY_COST` | `102400` | Memory in KB (100 MB). |
| `ARGON2_DEFAULT_PARALLELISM` | `2` | Number of parallel lanes. |
| `ARGON2_DEFAULT_HASH_LENGTH` | `32` | Output hash length in bytes. |
| `ARGON2_DEFAULT_SALT_SIZE` | `16` | Salt size in bytes (RFC 9106). |

### Message Format Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PLAINTEXT_SIZE` | `2**30` | Maximum plaintext size (1 GB). |
| `MIN_PADDING_BYTES` | `16` | Minimum random padding. |
| `MAX_PADDING_BYTES` | `256` | Maximum random padding. |

### Security Levels

| Level | Name | Classical Bits | KEM k | eta1 |
|-------|------|---------------|-------|------|
| `1` | AES-128 equivalent | 128 | 2 | 3 |
| `3` | AES-192 equivalent | 192 | 3 | 2 |
| `5` | AES-256 equivalent | 256 | 4 | 2 |

---

## Utility Functions

The `qhybridcrypt.utils` module provides low-level cryptographic utilities that are used internally by the library but may also be useful for application developers who need fine-grained control over cryptographic operations.

### hkdf_sha3_256

```python
hkdf_sha3_256(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int
) -> bytes
```

HKDF (HMAC-based Key Derivation Function) using SHA3-256 as the hash function, implementing RFC 5869. The function performs an extract phase (PRK = HMAC-SHA3-256(salt, input_key)) followed by an expand phase (OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA3-256(PRK, T(i-1) || info || i)). Raises `ValueError` if length exceeds 8160 bytes or salt is less than 16 bytes.

### hkdf_blake2b

```python
hkdf_blake2b(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int
) -> bytes
```

HKDF using BLAKE2b as the underlying hash function. Uses BLAKE2b's keyed mode for the extract phase, providing an independent KDF path from `hkdf_sha3_256`. Raises `ValueError` if length exceeds 16320 bytes.

### sha3_256

```python
sha3_256(data: bytes) -> bytes
```

Computes SHA3-256 hash. Returns 32 bytes.

### sha3_512

```python
sha3_512(data: bytes) -> bytes
```

Computes SHA3-512 hash. Returns 64 bytes.

### shake256

```python
shake256(data: bytes, output_length: int) -> bytes
```

SHAKE-256 Extendable Output Function (XOF). Produces arbitrary-length output from any input.

### blake2b_hash

```python
blake2b_hash(
    data: bytes,
    digest_size: int = 64,
    key: bytes = b''
) -> bytes
```

BLAKE2b hash function. Supports variable output size (1-64 bytes) and keyed mode for MAC computation.

### compute_hmac

```python
compute_hmac(
    key: bytes,
    message: bytes,
    hash_func: str = 'sha3_256'
) -> bytes
```

Computes HMAC using the specified hash function. Defaults to SHA3-256.

### xor_bytes

```python
xor_bytes(a: bytes, b: bytes) -> bytes
```

XORs two byte sequences of equal length. Raises `ValueError` if lengths differ.

### zero_memory

```python
zero_memory(data: bytearray) -> None
```

Securely overwrites a bytearray with zeros in place. Best-effort approach; Python's memory management may retain copies. Only works on `bytearray` (not `bytes`, which is immutable).

### encode_length / decode_length

```python
encode_length(length: int, size: int = 4) -> bytes
decode_length(data: bytes, size: int = 4) -> int
```

Encode/decode integer lengths as little-endian bytes. Used internally for message format construction.

---

## Error Handling

All cryptographic operations in Q-HybridCrypt follow a consistent error handling pattern. Operations that fail raise `ValueError` with a descriptive (but security-conscious) message. Migration operations raise `MigrationError` for migration-specific failures. This section describes the error handling philosophy and provides guidance on handling errors in production code.

### Security-Conscious Error Messages

Q-HybridCrypt deliberately does not reveal which authentication layer failed during decryption. If decryption fails, the error message indicates "Decryption failed" but does not specify whether the Poly1305 tag, GCM tag, or HMAC-SHA3 tag was the one that failed verification. This prevents an attacker from learning which layer to target, forcing them to break all three layers simultaneously.

### Error Categories

| Error Type | Exception | Common Causes |
|------------|-----------|---------------|
| Invalid input | `ValueError` | Empty plaintext without padding, wrong key size, invalid nonce |
| Authentication failure | `ValueError` | Wrong private key, tampered ciphertext, wrong AAD, corrupted data |
| Format error | `ValueError` | Invalid magic header, unsupported version, truncated message |
| Migration failure | `MigrationError` | Old decryption fails, wrong key, corrupted old ciphertext |
| KEM failure | `ValueError` | Invalid KEM ciphertext, corrupted public key |

### Error Handling Patterns

```python
from qhybridcrypt import QHybridCrypt
from qhybridcrypt.migration import MigrationSDK, MigrationError

# Pattern 1: Encryption/Decryption errors
crypto = QHybridCrypt()
try:
    plaintext = crypto.decrypt(ciphertext, private_key, associated_data=aad)
except ValueError as e:
    # Log the error (but don't expose which layer failed)
    logger.warning(f"Decryption failed: {e}")
    # Do NOT distinguish between "wrong key" and "tampered data"
    # in user-facing messages, as this could aid attackers
    raise PermissionError("Authentication failed")

# Pattern 2: Migration errors
sdk = MigrationSDK()
try:
    new_ct, pk = sdk.migrate_encrypted_data(old_ct, old_decrypt_fn)
except MigrationError as e:
    logger.error(f"Migration failed: {e}")
    # Keep old ciphertext for retry; do NOT delete it
    store_for_retry(old_ct)

# Pattern 3: Password verification (returns bool, not exception)
is_valid = crypto.verify_password(password, salt, expected_hash)
if not is_valid:
    logger.info("Password verification failed")
    # Use constant-time delay to prevent timing attacks
```

---

## Type Annotations

Q-HybridCrypt uses comprehensive type annotations throughout the codebase. The following type aliases are used consistently across the API for clarity and type safety:

```python
from typing import Tuple, Optional, Callable, Dict, List, Any

# Core types
PublicKey = bytes       # PHOENIX public key (~1184 bytes at Level 3)
PrivateKey = bytes      # PHOENIX private key (~2400 bytes at Level 3)
Ciphertext = bytes      # PHOENIX encrypted message (variable length)
Plaintext = bytes       # Unencrypted data
SharedSecret = bytes    # 32-byte KEM shared secret
PasswordHash = bytes    # 32-byte Argon2id hash
Salt = bytes            # 16-byte Argon2id salt
AAD = bytes             # Additional Authenticated Data

# Migration types
DecryptCallback = Callable[[bytes], bytes]
ProgressCallback = Callable[[int, int], None]

# Return types
Keypair = Tuple[PublicKey, PrivateKey]
PasswordHashResult = Tuple[PasswordHash, Salt]
MigrationResult = Tuple[Ciphertext, PublicKey]
BatchMigrationResult = Tuple[List[Ciphertext], PublicKey]
```

### Full Type Signature Reference

```python
class QHybridCrypt:
    def __init__(self, security_level: int = 3) -> None: ...
    def generate_keypair(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]: ...
    def encrypt(self, plaintext: bytes, public_key: bytes,
                associated_data: bytes = b'', padding: bool = True) -> bytes: ...
    def decrypt(self, encrypted_message: bytes, private_key: bytes,
                associated_data: bytes = b'') -> bytes: ...
    def encrypt_stream(self, data: bytes, public_key: bytes,
                       chunk_size: int = 65536) -> bytes: ...
    def decrypt_stream(self, encrypted_data: bytes, private_key: bytes) -> bytes: ...
    def hash_password(self, password: str, salt: Optional[bytes] = None,
                      time_cost: Optional[int] = None,
                      memory_cost: Optional[int] = None) -> Tuple[bytes, bytes]: ...
    def verify_password(self, password: str, salt: bytes, expected_hash: bytes,
                        time_cost: Optional[int] = None,
                        memory_cost: Optional[int] = None) -> bool: ...
    def get_info(self) -> Dict[str, Any]: ...

class MigrationSDK:
    def __init__(self, security_level: int = 3) -> None: ...
    def migrate_encrypted_data(self, old_ciphertext: bytes,
                                old_decrypt_fn: Callable[[bytes], bytes],
                                associated_data: bytes = b'',
                                keep_old_key_ref: bool = True) -> Tuple[bytes, bytes]: ...
    def migrate_with_keypair(self, old_ciphertext: bytes,
                              old_decrypt_fn: Callable[[bytes], bytes],
                              public_key: bytes,
                              associated_data: bytes = b'') -> bytes: ...
    def batch_migrate(self, old_ciphertexts: List[bytes],
                      old_decrypt_fn: Callable[[bytes], bytes],
                      associated_data: bytes = b'',
                      on_progress: Optional[Callable[[int, int], None]] = None
                      ) -> Tuple[List[bytes], bytes]: ...
    def get_migration_log(self) -> List[Dict[str, Any]]: ...
    def clear_migration_log(self) -> None: ...

# Module-level functions
def encrypt_message(plaintext: bytes, public_key: bytes,
                    associated_data: bytes = b'') -> bytes: ...
def decrypt_message(encrypted_message: bytes, private_key: bytes,
                    associated_data: bytes = b'') -> bytes: ...
def generate_keypair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]: ...
def secure_random_bytes(length: int) -> bytes: ...
def constant_time_compare(a: bytes, b: bytes) -> bool: ...
def migrate_from(library: str, old_ciphertext: bytes,
                  old_decrypt_fn: Callable[[bytes], bytes],
                  security_level: int = 3,
                  associated_data: bytes = b'') -> Tuple[bytes, bytes]: ...
```

![Architecture Overview](images/architecture_overview.png)
