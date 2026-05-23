"""
Q-HybridCrypt v2.0 - Migration SDK Examples

Demonstrates how to migrate from various cryptographic libraries
to Q-HybridCrypt's triple-cascade encryption.
"""

from qhybridcrypt import QHybridCrypt
from qhybridcrypt.migration import (
    MigrationSDK,
    PyCryptodomeMigrator,
    CryptographyIOMigrator,
    NaClMigrator,
    CustomAESMigrator,
    migrate_from,
)


def example_migration_from_pycryptodome():
    """
    Example: Migrate from PyCryptodome AES-GCM to Q-HybridCrypt.

    This shows how to take data that was encrypted with PyCryptodome's
    AES-GCM and re-encrypt it with Q-HybridCrypt's triple-cascade.
    """
    print("\n=== Migration from PyCryptodome ===")

    # Simulate existing PyCryptodome encrypted data
    # In real usage, you would have actual AES-GCM encrypted data
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes

        aes_key = get_random_bytes(32)
        plaintext = b"Secret data encrypted with PyCryptodome"

        # Encrypt with PyCryptodome AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        old_encrypted = cipher.nonce + tag + ciphertext

        # Define decryption function
        def pycryptodome_decrypt(encrypted_data):
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ct = encrypted_data[32:]
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct, tag)

        # Migrate using the migrator
        migrator = PyCryptodomeMigrator()
        new_ciphertext, public_key = migrator.migrate(old_encrypted, pycryptodome_decrypt)

        print(f"  Old ciphertext size: {len(old_encrypted)} bytes")
        print(f"  New ciphertext size: {len(new_ciphertext)} bytes")
        print(f"  Public key size: {len(public_key)} bytes")
        print("  Migration successful!")

    except ImportError:
        print("  PyCryptodome not installed. Install with: pip install pycryptodome")


def example_migration_from_fernet():
    """
    Example: Migrate from Fernet (cryptography library) to Q-HybridCrypt.

    Fernet provides AES-128-CBC with HMAC-SHA256 authentication.
    Q-HybridCrypt provides much stronger triple-cascade encryption.
    """
    print("\n=== Migration from Fernet ===")

    try:
        from cryptography.fernet import Fernet

        fernet_key = Fernet.generate_key()
        f = Fernet(fernet_key)
        plaintext = b"Data previously encrypted with Fernet"
        fernet_token = f.encrypt(plaintext)

        # Use the specialized Fernet migrator
        migrator = CryptographyIOMigrator()
        new_ciphertext, public_key = migrator.migrate_fernet(fernet_token, fernet_key)

        print(f"  Fernet token size: {len(fernet_token)} bytes")
        print(f"  Q-HybridCrypt ciphertext size: {len(new_ciphertext)} bytes")
        print("  Fernet -> Q-HybridCrypt migration successful!")

    except ImportError:
        print("  cryptography library not installed. Install with: pip install cryptography")


def example_migration_simple():
    """
    Example: Simple one-step migration using migrate_from().
    """
    print("\n=== Simple Migration (migrate_from) ===")

    # Simulate any encrypted data with a custom decrypt function
    fake_key = b'\x42' * 32

    def my_custom_decrypt(ciphertext):
        # Simple XOR decryption for demo purposes
        return bytes(a ^ b for a, b in zip(ciphertext, fake_key[:len(ciphertext)]))

    fake_ciphertext = bytes(a ^ b for a, b in zip(b"Hello World!", fake_key[:12]))

    # One-step migration
    new_ct, pk = migrate_from('custom', fake_ciphertext, my_custom_decrypt)

    print(f"  Old ciphertext size: {len(fake_ciphertext)} bytes")
    print(f"  New ciphertext size: {len(new_ct)} bytes")
    print("  Simple migration successful!")


def example_batch_migration():
    """
    Example: Batch migration of multiple encrypted items.
    """
    print("\n=== Batch Migration ===")

    # Simulate multiple encrypted items
    items = [f"Secret item {i}".encode() for i in range(5)]

    # Simulate a simple encrypt/decrypt
    key = b'\xAB' * 32

    def simple_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ciphertexts = [bytes(a ^ b for a, b in zip(item, key[:len(item)])) for item in items]

    # Batch migrate
    sdk = MigrationSDK()

    def progress(current, total):
        print(f"  Progress: {current}/{total}")

    new_ciphertexts, public_key = sdk.batch_migrate(
        old_ciphertexts, simple_decrypt, on_progress=progress
    )

    print(f"  Migrated {len(new_ciphertexts)} items successfully!")
    print(f"  All items use the same public key ({len(public_key)} bytes)")


def example_backward_compatible():
    """
    Example: Using migration with backward compatibility.

    Keeps old keys for fallback while using Q-HybridCrypt for new data.
    """
    print("\n=== Backward-Compatible Migration ===")

    crypto = QHybridCrypt()
    old_key = b'\x55' * 32

    # Old encryption (simple XOR for demo)
    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, old_key[:len(ct)]))

    old_data = bytes(a ^ b for a, b in zip(b"Legacy encrypted data", old_key[:20]))

    # Migrate with key reference kept
    sdk = MigrationSDK()
    new_ct, pk = sdk.migrate_encrypted_data(old_data, old_decrypt, keep_old_key_ref=True)

    # Check migration log
    log = sdk.get_migration_log()
    if log:
        print(f"  Migration record: {log[-1]['status']}")
        print(f"  Old format hash: {log[-1]['old_format_hash'][:16]}...")
        print(f"  New key hash: {log[-1]['new_key_hash'][:16]}...")

    print("  Backward-compatible migration done!")


def run_all_examples():
    """Run all migration examples."""
    print("=" * 60)
    print("Q-HybridCrypt v2.0 PHOENIX - Migration SDK Examples")
    print("=" * 60)

    example_migration_simple()
    example_batch_migration()
    example_backward_compatible()
    example_migration_from_pycryptodome()
    example_migration_from_fernet()

    print("\n" + "=" * 60)
    print("All migration examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_examples()
