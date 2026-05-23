# Q-HybridCrypt v2.0 "PHOENIX" — Migration Guide

## Table of Contents

1. [Overview](#overview)
2. [Migration Process](#migration-process)
3. [Migration from PyCryptodome](#migration-from-pycryptodome)
4. [Migration from cryptography/Fernet](#migration-from-cryptographyfernet)
5. [Migration from PyNaCl](#migration-from-pynacl)
6. [Migration from Custom AES-GCM](#migration-from-custom-aes-gcm)
7. [Batch Migration](#batch-migration)
8. [Transparent Re-encryption](#transparent-re-encryption)
9. [Best Practices and Security Considerations](#best-practices-and-security-considerations)
10. [Rollback Strategies](#rollback-strategies)

---

## Overview

Migrating from an existing cryptographic library to Q-HybridCrypt v2.0 "PHOENIX" is designed to be a straightforward, low-risk process. The Migration SDK provides dedicated migrator classes for the most common Python cryptography libraries, along with a universal `migrate_from()` convenience function that works with any encryption scheme. The entire migration framework is built around the principle of **Transparent Re-encryption**: your application code never handles intermediate plaintext, and the old decryption logic is encapsulated within a single callback function that the SDK invokes internally.

The migration journey typically involves three phases. First, you assess your current encryption inventory, identifying which libraries and algorithms are in use, where encrypted data is stored, and which keys are involved. Second, you execute the migration using the SDK, either item by item or in batches, to re-encrypt all data under the PHOENIX triple-cascade protocol. Third, you validate the migration by decrypting a sample of the newly encrypted data and comparing it against the original plaintext, ensuring no data was lost or corrupted during the transition.

![Migration Flow](images/migration_flow.png)

Q-HybridCrypt's migration SDK supports four primary source libraries: PyCryptodome, the `cryptography` package (including Fernet), PyNaCl/NaCl, and custom AES-GCM implementations. Each migrator class provides a streamlined API tailored to the conventions and data formats of its source library, while the universal `migrate_from()` function offers a library-agnostic entry point that requires only a decryption callback. This flexibility means you can migrate from virtually any encryption scheme, including proprietary or home-grown implementations, without writing custom integration code.

---

## Migration Process

### Step-by-Step Migration Workflow

The migration process follows a well-defined sequence of steps that ensures data integrity and security at every stage. Understanding each step helps you plan your migration effectively and avoid common pitfalls that could lead to data loss or security vulnerabilities.

1. **Inventory Assessment**: Before writing any migration code, you must catalog all encrypted data in your system. Identify which library encrypted each piece of data, which keys were used, and where both the ciphertexts and keys are stored. This inventory forms the foundation of your migration plan and helps you estimate the effort involved. Pay special attention to data that may be encrypted with multiple layers or with keys that have been rotated over time.

2. **Key Extraction**: Ensure you have access to all decryption keys required for the old format. If keys are stored in a key management service (KMS), hardware security module (HSM), or environment variables, verify that the migration process can access them. Test decryption of a small sample before committing to a full migration, because discovering a missing key mid-migration can halt the entire process and leave your data in an inconsistent state.

3. **Migration Execution**: Use the appropriate migrator class or the `migrate_from()` function to re-encrypt each data item. The SDK handles decryption of the old format and re-encryption under PHOENIX internally, so your application code never sees the plaintext. Each migration call returns the new ciphertext along with the PHOENIX public key needed for future encryption operations.

4. **Validation**: After migration, validate a statistically significant sample of the migrated data by decrypting it with PHOENIX and comparing against the original plaintext. Automated validation scripts are strongly recommended, especially for large datasets where manual verification is impractical. Consider keeping a checksum (e.g., SHA3-256) of the original plaintext for comparison purposes.

5. **Key Rotation**: Once migration is validated, securely destroy the old encryption keys using a certified destruction method. Retain the PHOENIX private keys in secure storage. Update all application configuration to point to the new ciphertexts and keys, and remove references to the old encryption library from your codebase.

### Migration Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Old Ciphertext   │────▶│  Migration SDK   │────▶│  PHOENIX CT      │
│  (any format)     │     │  (transparent     │     │  (QHC2 format)   │
│                   │     │   re-encryption)  │     │                  │
└──────────────────┘     └────────┬─────────┘     └──────────────────┘
                                  │
                         ┌────────┴─────────┐
                         │  Old Decrypt Fn   │
                         │  (your callback)  │
                         └──────────────────┘
```

The migration SDK never stores plaintext in memory longer than necessary. After re-encryption is complete, the plaintext buffer is released and eligible for garbage collection. For additional security, you can use the `zero_memory()` utility function from `qhybridcrypt.utils` to explicitly overwrite sensitive buffers before they go out of scope.

---

## Migration from PyCryptodome

PyCryptodome is one of the most widely used cryptographic libraries in the Python ecosystem, offering a broad range of algorithms including AES, RSA, ChaCha20, and numerous hash functions. Migrating from PyCryptodome to Q-HybridCrypt is straightforward because the `PyCryptodomeMigrator` class accepts a simple decryption callback that wraps your existing PyCryptodome decryption logic. This means you do not need to change how you use PyCryptodome for decryption; you simply pass the decryption function to the migrator and receive PHOENIX-encrypted output.

The most common PyCryptodome encryption patterns involve AES-GCM, AES-CBC with PKCS7 padding, and RSA-OAEP. Each of these patterns requires a slightly different decryption callback, but the migration process itself remains identical. The key insight is that the migrator does not care about the internal structure of the old ciphertext; it only needs a function that can transform old ciphertext bytes into plaintext bytes. This design decouples the migration logic from the specific encryption scheme, making it robust against variations in how PyCryptodome is configured.

### Migrating AES-GCM Data

```python
from qhybridcrypt.migration import PyCryptodomeMigrator

# Your existing PyCryptodome AES-GCM setup
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

aes_key = get_random_bytes(32)  # Your existing AES-256 key

# Old encryption function (how you currently encrypt)
def old_aes_gcm_encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext  # nonce(16) + tag(16) + ciphertext

# Define the decryption callback for the migrator
def old_aes_gcm_decrypt(ciphertext_bytes: bytes) -> bytes:
    nonce = ciphertext_bytes[:16]
    tag = ciphertext_bytes[16:32]
    ct = ciphertext_bytes[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# --- Migration ---
migrator = PyCryptodomeMigrator(security_level=3)

# Migrate a single encrypted item
old_ciphertext = old_aes_gcm_encrypt(b"Sensitive data encrypted with PyCryptodome")
new_ciphertext, phoenix_public_key = migrator.migrate(
    old_ciphertext,
    old_aes_gcm_decrypt,
    associated_data=b"migration:pycryptodome->phoenix"
)

print(f"Old ciphertext size: {len(old_ciphertext)} bytes")
print(f"New PHOENIX ciphertext size: {len(new_ciphertext)} bytes")
print(f"PHOENIX public key size: {len(phoenix_public_key)} bytes")

# Verify the migration by decrypting with PHOENIX
from qhybridcrypt import QHybridCrypt
crypto = QHybridCrypt()
# You must securely store the private key returned during migration!
# For this example, we generate it alongside:
public_key, private_key = crypto.generate_keypair()
# Re-encrypt with a known keypair for verification
new_ct, pk = migrator.migrate(old_ciphertext, old_aes_gcm_decrypt)
# The private key is generated internally by the migrator
# Store it securely along with the new ciphertext
```

### Migrating AES-CBC Data

```python
from qhybridcrypt.migration import PyCryptodomeMigrator
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

aes_key = b'your-32-byte-aes-key-here-1234567890'  # Your existing key

def old_aes_cbc_decrypt(ciphertext_bytes: bytes) -> bytes:
    iv = ciphertext_bytes[:16]
    ct = ciphertext_bytes[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

migrator = PyCryptodomeMigrator()
old_ct = b'...'  # Your AES-CBC encrypted data
new_ct, new_pk = migrator.migrate(old_ct, old_aes_cbc_decrypt)
```

### Migrating RSA-Encrypted Data

```python
from qhybridcrypt.migration import PyCryptodomeMigrator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load your existing RSA private key
with open('private_key.pem', 'rb') as f:
    rsa_key = RSA.import_key(f.read())

def old_rsa_decrypt(ciphertext_bytes: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext_bytes)

migrator = PyCryptodomeMigrator(security_level=5)  # Max security for RSA replacement
new_ct, new_pk = migrator.migrate(old_rsa_ciphertext, old_rsa_decrypt)
```

**Important Note**: RSA encryption has a limited plaintext size (e.g., 190 bytes for RSA-2048 with OAEP-SHA256). If your application uses hybrid RSA+AES encryption (RSA to encrypt an AES key, then AES for the data), your decryption callback should handle the full hybrid decryption logic internally, returning the final plaintext to the migrator.

---

## Migration from cryptography/Fernet

The `cryptography` library is the most feature-rich and well-maintained cryptographic library for Python. It provides both low-level primitives (AES-GCM, ChaCha20) and high-level constructs like Fernet. The `CryptographyIOMigrator` class offers dedicated support for Fernet tokens through the `migrate_fernet()` convenience method, which handles the base64 decoding and Fernet decryption automatically. For other `cryptography` library primitives, the standard `migrate()` method with a custom decryption callback works seamlessly.

Fernet is particularly popular because it provides a simple, self-contained encryption API that handles key generation, nonce management, and authentication in a single `encrypt()`/`decrypt()` interface. However, Fernet uses AES-128-CBC with HMAC-SHA256 for authentication, which provides only 128-bit security — well below the 192-bit classical and 128-bit quantum security offered by PHOENIX. Migrating from Fernet to Q-HybridCrypt represents a significant security upgrade, especially for organizations concerned about post-quantum threats.

### Migrating Fernet Tokens

```python
from qhybridcrypt.migration import CryptographyIOMigrator

# Your existing Fernet setup
from cryptography.fernet import Fernet

fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

# Encrypt some data with Fernet (old way)
old_token = fernet.encrypt(b"Data previously encrypted with Fernet")

# --- One-step migration using migrate_fernet() ---
migrator = CryptographyIOMigrator(security_level=3)
new_ciphertext, phoenix_pk = migrator.migrate_fernet(
    old_token,
    fernet_key,  # Pass the Fernet key directly
    associated_data=b"migration:fernet->phoenix"
)

print(f"Fernet token size: {len(old_token)} bytes")
print(f"PHOENIX ciphertext size: {len(new_ciphertext)} bytes")
```

### Migrating AES-GCM from cryptography library

```python
from qhybridcrypt.migration import CryptographyIOMigrator
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes_key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(aes_key)
nonce = b'12-byte-nonce'

# Old encryption
old_ct = aesgcm.encrypt(nonce, b"Data encrypted with cryptography lib AES-GCM", None)

# Decryption callback
def old_decrypt(ciphertext_bytes: bytes) -> bytes:
    # Assume format: nonce(12) + aes_gcm_ct
    n = ciphertext_bytes[:12]
    ct = ciphertext_bytes[12:]
    return aesgcm.decrypt(n, ct, None)

# Migration
migrator = CryptographyIOMigrator()
combined_old = nonce + old_ct  # Combine for the migrator
new_ct, new_pk = migrator.migrate(combined_old, old_decrypt)
```

### Migrating from cryptography.io ChaCha20-Poly1305

```python
from qhybridcrypt.migration import CryptographyIOMigrator
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = b'12-byte-nc'

old_ct = chacha.encrypt(nonce, b"ChaCha20 encrypted data", None)

def old_chacha_decrypt(ct_bytes: bytes) -> bytes:
    n = ct_bytes[:12]
    ct = ct_bytes[12:]
    return chacha.decrypt(n, ct, None)

migrator = CryptographyIOMigrator()
new_ct, new_pk = migrator.migrate(nonce + old_ct, old_chacha_decrypt)
```

---

## Migration from PyNaCl

PyNaCl provides bindings to the NaCl (Networking and Cryptography) library, which implements Daniel Bernstein's cryptographic primitives including XSalsa20-Poly1305 authenticated encryption, X25519 key exchange, and Ed25519 signatures. The `NaClMigrator` class is specifically designed to handle the NaCl ciphertext format, which includes a 16-byte Poly1305 tag prepended to the ciphertext. The migration process is identical to other migrators: you provide a decryption callback that uses your existing NaCl decryption code, and the migrator returns PHOENIX-encrypted output.

NaCl's `SecretBox` uses XSalsa20-Poly1305, which provides 256-bit key security with a 192-bit nonce. While XSalsa20-Poly1305 is considered secure, it is not quantum-resistant in the KEM sense — the key exchange mechanism (X25519) is vulnerable to Shor's algorithm on a quantum computer. By migrating to Q-HybridCrypt, you replace the quantum-vulnerable X25519 key exchange with a Module-LWE KEM that resists both classical and quantum cryptanalysis, while also gaining the benefit of triple-cascade encryption.

### Migrating SecretBox Data

```python
from qhybridcrypt.migration import NaClMigrator

# Your existing PyNaCl setup
from nacl.secret import SecretBox
from nacl.utils import random

nacl_key = random(SecretBox.KEY_SIZE)  # 32 bytes
box = SecretBox(nacl_key)

# Old encryption
old_ciphertext = box.encrypt(b"Data encrypted with PyNaCl SecretBox")

# Decryption callback
def nacl_decrypt(ct_bytes: bytes) -> bytes:
    return box.decrypt(ct_bytes)

# --- Migration ---
migrator = NaClMigrator(security_level=3)
new_ciphertext, phoenix_pk = migrator.migrate(
    old_ciphertext,
    nacl_decrypt,
    associated_data=b"migration:nacl->phoenix"
)

print(f"NaCl ciphertext size: {len(old_ciphertext)} bytes")
print(f"PHOENIX ciphertext size: {len(new_ciphertext)} bytes")
```

### Migrating SealedBox (Public-Key Encryption)

```python
from qhybridcrypt.migration import NaClMigrator
from nacl.public import PrivateKey, SealedBox

# Your existing NaCl keypair
nacl_private_key = PrivateKey.generate()
nacl_public_key = nacl_private_key.public_key

sealed_box = SealedBox(nacl_private_key)

# Old encryption
old_ct = SealedBox(nacl_public_key).encrypt(b"Public-key encrypted data")

# Decryption callback
def nacl_sealed_decrypt(ct_bytes: bytes) -> bytes:
    return sealed_box.decrypt(ct_bytes)

# Migration — replaces quantum-vulnerable X25519 with Module-LWE
migrator = NaClMigrator(security_level=3)
new_ct, new_pk = migrator.migrate(old_ct, nacl_sealed_decrypt)
```

---

## Migration from Custom AES-GCM

Many applications implement their own AES-GCM encryption, often with custom nonce management, key derivation, or ciphertext packaging formats. The `CustomAESMigrator` class provides a specialized `migrate_aes_gcm()` method that accepts the raw AES-GCM components (nonce, ciphertext, tag, and key) as separate parameters, handling the decryption internally using either the `cryptography` library or PyCryptodome as a backend. This eliminates the need for you to write a decryption callback for the common case where your data is simply AES-GCM encrypted.

The migrator supports the most common AES-GCM ciphertext formats, including nonce-prepended (nonce + ciphertext + tag), tag-appended (nonce + ciphertext + tag), and separate-component formats where the nonce, ciphertext, and tag are stored in different locations. By providing the components individually, `migrate_aes_gcm()` can handle any of these formats without requiring you to concatenate them into a single byte string first. The method also accepts optional associated data (AAD) that was used during the original encryption, which is critical for formats where AAD is part of the authentication.

### Using migrate_aes_gcm()

```python
from qhybridcrypt.migration import CustomAESMigrator

# Your existing AES-GCM components
aes_key = b'0123456789abcdef0123456789abcdef'  # 32-byte key
nonce = b'0123456789ab'                         # 12-byte nonce
ciphertext = b'...'                             # AES-GCM ciphertext
tag = b'0123456789abcdef'                       # 16-byte GCM tag

# --- Migration ---
migrator = CustomAESMigrator(security_level=3)
new_ciphertext, phoenix_pk = migrator.migrate_aes_gcm(
    nonce=nonce,
    ciphertext=ciphertext,
    tag=tag,
    aes_key=aes_key,
    associated_data=b"optional_aad"
)

print(f"New PHOENIX ciphertext size: {len(new_ciphertext)} bytes")
```

### Migrating Custom Format with Separate Components

```python
from qhybridcrypt.migration import CustomAESMigrator

# If your custom format stores components separately
# (e.g., nonce in one DB column, ciphertext in another)
import base64

# Load components from your storage
nonce = base64.b64decode(stored_nonce_b64)
ciphertext = base64.b64decode(stored_ct_b64)
tag = base64.b64decode(stored_tag_b64)
aes_key = kms_get_key('my-aes-key-id')

migrator = CustomAESMigrator()
new_ct, pk = migrator.migrate_aes_gcm(
    nonce=nonce,
    ciphertext=ciphertext,
    tag=tag,
    aes_key=aes_key
)

# Store new_ct and pk in your database
store_phoenix_ciphertext(record_id, new_ct, pk)
```

### Migrating with a Custom Decryption Callback

```python
from qhybridcrypt.migration import CustomAESMigrator

# For truly custom implementations (e.g., non-standard padding, custom key derivation)
def my_custom_decrypt(ct_bytes: bytes) -> bytes:
    # Your custom decryption logic here
    nonce = ct_bytes[:12]
    tag = ct_bytes[-16:]
    ct = ct_bytes[12:-16]
    # ... custom decryption ...
    return plaintext

migrator = CustomAESMigrator()
new_ct, pk = migrator.migrate(old_ct_bytes, my_custom_decrypt)
```

---

## Batch Migration

For applications with large datasets — such as databases containing thousands or millions of encrypted records — the Migration SDK provides a `batch_migrate()` method that efficiently processes multiple ciphertexts in a single operation. All items in a batch are migrated to the same PHOENIX keypair, which reduces key management overhead and simplifies the deployment of the migrated data. The batch migrator also supports a progress callback that allows you to monitor migration progress in real-time, which is essential for long-running migrations of large datasets.

Batch migration is designed with fault tolerance in mind. If any single item fails to migrate (e.g., because the decryption callback raises an exception for a corrupted ciphertext), the entire batch is aborted with a descriptive error message indicating which item failed and why. This "all or nothing" approach ensures data consistency: either all items are successfully migrated, or none are, preventing partial migrations that could leave your data in an inconsistent state. For datasets where individual item failures should not block the entire migration, you can implement retry logic or skip logic in your decryption callback.

### Batch Migration Example

```python
from qhybridcrypt.migration import MigrationSDK

# Suppose you have 1000 encrypted records from an old system
old_records = []  # List of bytes, each an old-format ciphertext
for i in range(1000):
    old_records.append(old_encrypt(f"Record {i}".encode()))

# Define the old decryption function
def old_decrypt(ct: bytes) -> bytes:
    # Your existing decryption logic
    return old_decrypt_impl(ct)

# --- Batch migration ---
sdk = MigrationSDK(security_level=3)

def progress_callback(current: int, total: int) -> None:
    pct = (current / total) * 100
    print(f"\rMigrating: {current}/{total} ({pct:.1f}%)", end='', flush=True)

new_ciphertexts, phoenix_pk = sdk.batch_migrate(
    old_ciphertexts=old_records,
    old_decrypt_fn=old_decrypt,
    associated_data=b"batch:migration:2024",
    on_progress=progress_callback
)

print(f"\nMigration complete! {len(new_ciphertexts)} records migrated.")
print(f"PHOENIX public key: {phoenix_pk.hex()[:32]}...")

# Verify a sample
from qhybridcrypt import QHybridCrypt
crypto = QHybridCrypt()
# Decrypt requires the private key (generated internally during batch_migrate)
# Store the private key securely alongside the public key reference
```

### Batch Migration with Error Handling

```python
from qhybridcrypt.migration import MigrationSDK, MigrationError

sdk = MigrationSDK()

# For datasets where some records may be corrupted, use individual migration
# with error handling instead of batch_migrate()
successful = []
failed = []

for i, old_ct in enumerate(old_records):
    try:
        new_ct, pk = sdk.migrate_encrypted_data(old_ct, old_decrypt)
        successful.append((i, new_ct, pk))
    except MigrationError as e:
        failed.append((i, str(e)))
        print(f"Record {i} failed: {e}")

print(f"Successful: {len(successful)}, Failed: {len(failed)}")
```

---

## Transparent Re-encryption

The **Transparent Re-encryption** feature is the flagship capability of the Q-HybridCrypt Migration SDK. It provides a one-step migration path that reads old-format ciphertext and outputs PHOENIX-format ciphertext without ever exposing the plaintext in your application code. This is a critical security feature: because the decryption and re-encryption happen inside the SDK, there is no window where plaintext exists as a variable in your application's memory space that could be logged, dumped, or accidentally exposed through an exception traceback.

The implementation of Transparent Re-encryption is simple but powerful. The `migrate_encrypted_data()` method takes two primary arguments: the old ciphertext bytes and a decryption callback function. The SDK invokes the callback to obtain the plaintext, immediately re-encrypts it under the PHOENIX protocol with a fresh KEM encapsulation, and returns the new ciphertext along with the public key needed for future encryption. The plaintext exists only as a temporary variable within the SDK's internal scope and is eligible for garbage collection as soon as re-encryption completes.

### How Transparent Re-encryption Works

```
┌─────────────────┐
│  Old Ciphertext  │
│  (any format)    │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│           Migration SDK Internals            │
│                                              │
│  1. Call old_decrypt_fn(old_ciphertext)      │
│     └──▶ plaintext (temporary, in-memory)   │
│                                              │
│  2. Generate new PHOENIX keypair             │
│     └──▶ public_key, private_key             │
│                                              │
│  3. crypto.encrypt(plaintext, public_key)    │
│     └──▶ new_ciphertext                      │
│                                              │
│  4. Release plaintext from memory            │
│                                              │
└────────┬──────────────────────┬──────────────┘
         │                      │
         ▼                      ▼
┌─────────────────┐   ┌─────────────────┐
│  New Ciphertext  │   │  Public Key      │
│  (QHC2 format)   │   │  (for future     │
│                  │   │   encryption)     │
└─────────────────┘   └─────────────────┘
```

### Using the Convenience Function

The simplest way to use Transparent Re-encryption is through the `migrate_from()` convenience function, which requires only the name of the source library, the old ciphertext, and a decryption callback. This function automatically selects the appropriate migrator class and handles the entire migration in a single call.

```python
from qhybridcrypt.migration import migrate_from

# Universal one-step migration from any library
def my_decrypt(ct: bytes) -> bytes:
    # Your existing decryption logic — works with ANY library
    return plaintext_bytes

new_ct, pk = migrate_from(
    library='pycryptodome',  # or 'cryptography', 'nacl', 'custom', 'aes-gcm'
    old_ciphertext=old_encrypted_data,
    old_decrypt_fn=my_decrypt,
    security_level=3,
    associated_data=b"optional_context"
)

# new_ct is now PHOENIX-encrypted; pk is the public key for future encryption
```

---

## Best Practices and Security Considerations

### Pre-Migration Checklist

Before beginning a migration, ensure that you have addressed each of the following items. Failing to prepare adequately can result in data loss, extended downtime, or security vulnerabilities during the migration window.

1. **Complete Data Inventory**: Document every location where encrypted data is stored, including databases, file systems, backups, caches, and message queues. Encrypted data that is not included in the migration will remain in the old format, potentially creating a dual-encryption maintenance burden.

2. **Key Accessibility**: Verify that all decryption keys for the old format are accessible and functional. Test decryption of a representative sample before starting the full migration. Keys stored in HSMs or cloud KMS services may require special access permissions that need to be configured in advance.

3. **Backup Strategy**: Create verified backups of all encrypted data and decryption keys before starting the migration. These backups serve as your safety net in case the migration encounters unexpected issues or produces corrupted output.

4. **Rollback Plan**: Define a clear rollback procedure that allows you to revert to the old encryption format if the migration fails or produces unexpected results. See the [Rollback Strategies](#rollback-strategies) section for detailed guidance.

5. **Downtime Window**: Plan for a maintenance window during which the data being migrated is not being actively read or written. Concurrent modifications during migration can lead to data inconsistency or loss.

### Security Considerations During Migration

- **Key Storage**: PHOENIX private keys generated during migration must be stored with the same or greater level of protection as the original keys. Consider using a hardware security module (HSM) or a cloud KMS for production key storage. Never store private keys in source code, configuration files in version control, or unencrypted environment variables.

- **Memory Handling**: Although the Migration SDK minimizes plaintext exposure, Python's garbage collector does not guarantee immediate memory zeroing. For applications handling highly sensitive data, consider using the `zero_memory()` utility function from `qhybridcrypt.utils` to explicitly overwrite sensitive bytearrays before they go out of scope.

- **Migration Logging**: The SDK maintains an internal migration log that records the hash of each old ciphertext, the hash of the new public key, and the migration status. Access this log via `sdk.get_migration_log()` for audit purposes. Be aware that this log contains cryptographic hashes of ciphertexts, which could be useful to an attacker if compromised — protect the log accordingly.

- **Associated Data Consistency**: When migrating with associated data (AAD), ensure that the AAD used during migration matches the AAD that will be used during decryption. Mismatched AAD will cause decryption to fail, even with the correct private key. A good practice is to include a migration timestamp and source library identifier in the AAD to provide context for future decryption operations.

- **Quantum Threat Timeline**: While current quantum computers cannot break RSA, ECC, or symmetric encryption, the "harvest now, decrypt later" threat is real. Adversaries may be collecting encrypted data today with the intention of decrypting it once quantum computers become available. Migrating to Q-HybridCrypt as soon as possible ensures that data encrypted under the PHOENIX protocol remains secure even against future quantum adversaries.

### Performance Optimization

- **Batch Processing**: Use `batch_migrate()` for large datasets instead of calling `migrate_encrypted_data()` in a loop. Batch migration generates a single keypair for all items, reducing key management overhead and simplifying storage.

- **Lower Security for Testing**: During development and testing, use `security_level=1` for faster key generation and encryption. Switch to `security_level=3` (default) or `security_level=5` for production.

- **Concurrent Migration**: For very large datasets, you can partition the data and run multiple migration processes in parallel, each handling a subset of the records. Ensure that each partition uses its own keypair to maintain key separation.

---

## Rollback Strategies

A robust rollback strategy is essential for any migration project. Even with thorough testing, unexpected issues can arise during production migrations that require reverting to the old encryption format. The Q-HybridCrypt Migration SDK is designed to support rollback through several mechanisms, each suitable for different scenarios and risk tolerance levels.

### Strategy 1: Dual-Write (Recommended for Production)

The dual-write strategy maintains both old-format and new-format ciphertexts simultaneously during the migration period. Application code reads from the new format but continues to write to both formats until the migration is fully validated. This approach provides the safest rollback path because you can instantly revert to the old format by switching the read path, with zero risk of data loss.

```python
# Dual-write pattern during migration
class DualWriteCrypto:
    def __init__(self, old_encrypt_fn, old_decrypt_fn, phoenix_crypto, phoenix_pk):
        self.old_encrypt = old_encrypt_fn
        self.old_decrypt = old_decrypt_fn
        self.phoenix = phoenix_crypto
        self.phoenix_pk = phoenix_pk
        self.use_phoenix = True  # Toggle for rollback

    def encrypt(self, plaintext: bytes) -> dict:
        old_ct = self.old_encrypt(plaintext)
        new_ct = self.phoenix.encrypt(plaintext, self.phoenix_pk)
        return {'old': old_ct, 'new': new_ct}

    def decrypt(self, data: dict) -> bytes:
        if self.use_phoenix:
            return self.phoenix.decrypt(data['new'], self.phoenix_sk)
        else:
            return self.old_decrypt(data['old'])
```

### Strategy 2: Key Reference Retention

The `migrate_encrypted_data()` method supports a `keep_old_key_ref` parameter that stores a hash reference to the old encryption key. While this does not enable direct rollback (the old key itself is not stored), it provides an audit trail that links each PHOENIX ciphertext to its source encryption. This is useful for compliance and forensic purposes.

```python
sdk = MigrationSDK()

# Keep reference to old key for audit trail
new_ct, pk = sdk.migrate_encrypted_data(
    old_ciphertext,
    old_decrypt_fn,
    keep_old_key_ref=True  # Stores SHA3-256(old_ct[:64]) in migration log
)

# View the audit trail
log = sdk.get_migration_log()
for entry in log:
    print(f"Status: {entry['status']}")
    print(f"Old format hash: {entry['old_format_hash']}")
    print(f"Old key reference: {entry['old_key_ref']}")
    print(f"New key hash: {entry['new_key_hash']}")
```

### Strategy 3: Backup-and-Restore

The simplest rollback strategy is to maintain complete backups of the old encrypted data and decryption keys. If the migration needs to be reverted, you restore the old ciphertexts from backup and reconfigure the application to use the old encryption library. This approach requires sufficient storage for the backups and a tested restoration procedure.

```python
# Before migration: create verified backups
import shutil

def backup_before_migration(data_store_path, backup_path):
    shutil.copytree(data_store_path, backup_path)
    # Verify backup integrity
    verify_backup_integrity(data_store_path, backup_path)

# After migration: if rollback is needed
def rollback_to_old_format(backup_path, data_store_path):
    shutil.copytree(backup_path, data_store_path, dirs_exist_ok=True)
    # Reconfigure application to use old encryption library
    update_config('encryption_library', 'old_library')
```

### Strategy 4: Gradual Migration with Feature Flags

For large-scale deployments, use feature flags to control which encryption format is used for each component or user segment. This allows you to migrate incrementally, validate each segment independently, and roll back individual segments without affecting the entire system.

```python
# Feature-flag based migration
import flags  # Your feature flag system

def get_crypto_for_user(user_id: str):
    if flags.is_enabled('phoenix_encryption', user_id):
        return phoenix_crypto, phoenix_pk
    else:
        return old_crypto, old_key

# Migrate users one segment at a time
for segment in user_segments:
    migrate_segment(segment)
    validate_segment(segment)
    flags.enable('phoenix_encryption', segment)
```

---

## Quick Reference

| Migrator Class | Source Library | Key Method | Convenience |
|---|---|---|---|
| `PyCryptodomeMigrator` | PyCryptodome | `.migrate(ct, decrypt_fn)` | — |
| `CryptographyIOMigrator` | cryptography/Fernet | `.migrate(ct, decrypt_fn)` | `.migrate_fernet(token, key)` |
| `NaClMigrator` | PyNaCl/NaCl | `.migrate(ct, decrypt_fn)` | — |
| `CustomAESMigrator` | Custom AES-GCM | `.migrate(ct, decrypt_fn)` | `.migrate_aes_gcm(n, ct, tag, key)` |
| `migrate_from()` | Any | — | Universal function |
| `MigrationSDK.batch_migrate()` | Any (batch) | — | Progress callback support |

![Comparison Chart](images/comparison_chart.png)
