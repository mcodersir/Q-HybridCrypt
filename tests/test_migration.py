"""
Q-HybridCrypt v2.0 - Migration SDK Tests
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qhybridcrypt import QHybridCrypt
from qhybridcrypt.migration import (
    MigrationSDK,
    PyCryptodomeMigrator,
    CryptographyIOMigrator,
    NaClMigrator,
    CustomAESMigrator,
    migrate_from,
    MigrationError,
)


def test_migration_sdk_basic():
    """Test basic MigrationSDK functionality."""
    print("\n--- Testing MigrationSDK Basic ---")

    sdk = MigrationSDK()
    crypto = QHybridCrypt()

    # Simulate old encrypted data with a simple XOR cipher
    key = b'\x42' * 32
    plaintext = b"Secret data from old library"

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ct = bytes(a ^ b for a, b in zip(plaintext, key[:len(plaintext)]))

    # Migrate
    new_ct, pk = sdk.migrate_encrypted_data(old_ct, old_decrypt)

    assert isinstance(new_ct, bytes), "Ciphertext should be bytes"
    assert isinstance(pk, bytes), "Public key should be bytes"
    assert len(new_ct) > len(old_ct), "Q-HybridCrypt ciphertext should be larger"
    print("  Basic migration: PASS")


def test_migration_with_keypair():
    """Test migration with existing keypair."""
    print("\n--- Testing Migration With Existing Keypair ---")

    sdk = MigrationSDK()
    crypto = QHybridCrypt()

    # Generate keypair
    pk, sk = crypto.generate_keypair()

    # Simulate old data
    key = b'\x55' * 32
    plaintext = b"Data to migrate to existing key"

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ct = bytes(a ^ b for a, b in zip(plaintext, key[:len(plaintext)]))

    # Migrate to existing keypair
    new_ct = sdk.migrate_with_keypair(old_ct, old_decrypt, pk)

    # Verify we can decrypt with the private key
    decrypted = crypto.decrypt(new_ct, sk)
    assert decrypted == plaintext, "Decrypted data should match original"
    print("  Migration with keypair: PASS")


def test_migration_log():
    """Test migration logging."""
    print("\n--- Testing Migration Log ---")

    sdk = MigrationSDK()
    key = b'\x33' * 32
    plaintext = b"Logged migration data"

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ct = bytes(a ^ b for a, b in zip(plaintext, key[:len(plaintext)]))

    # Migrate
    sdk.migrate_encrypted_data(old_ct, old_decrypt, keep_old_key_ref=True)

    # Check log
    log = sdk.get_migration_log()
    assert len(log) == 1, "Should have 1 migration log entry"
    assert log[0]['status'] == 'migrated', "Status should be 'migrated'"
    assert 'old_format_hash' in log[0], "Should have old format hash"
    assert 'new_key_hash' in log[0], "Should have new key hash"

    # Clear log
    sdk.clear_migration_log()
    assert len(sdk.get_migration_log()) == 0, "Log should be empty after clear"
    print("  Migration log: PASS")


def test_batch_migration():
    """Test batch migration."""
    print("\n--- Testing Batch Migration ---")

    sdk = MigrationSDK()
    key = b'\x77' * 32

    items = [f"Item {i}".encode() for i in range(10)]
    old_cts = [bytes(a ^ b for a, b in zip(item, key[:len(item)])) for item in items]

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    progress_calls = []

    def on_progress(current, total):
        progress_calls.append((current, total))

    new_cts, pk = sdk.batch_migrate(old_cts, old_decrypt, on_progress=on_progress)

    assert len(new_cts) == len(old_cts), "Should have same number of items"
    assert len(pk) > 0, "Should have a public key"
    assert len(progress_calls) == len(old_cts), "Progress should be called for each item"
    print("  Batch migration: PASS")


def test_migration_error_handling():
    """Test migration error handling."""
    print("\n--- Testing Migration Error Handling ---")

    sdk = MigrationSDK()

    def bad_decrypt(ct):
        raise ValueError("Decryption failed!")

    try:
        sdk.migrate_encrypted_data(b"fake data", bad_decrypt)
        assert False, "Should have raised MigrationError"
    except MigrationError as e:
        assert "Old decryption failed" in str(e), "Error message should mention old decryption"

    # Test with non-bytes return
    def bad_return_type(ct):
        return "not bytes"

    try:
        sdk.migrate_encrypted_data(b"fake data", bad_return_type)
        assert False, "Should have raised MigrationError"
    except MigrationError as e:
        assert "bytes" in str(e).lower(), "Error should mention bytes"

    print("  Error handling: PASS")


def test_migrate_from_convenience():
    """Test migrate_from convenience function."""
    print("\n--- Testing migrate_from Convenience ---")

    key = b'\x99' * 32
    plaintext = b"Convenience migration test"

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ct = bytes(a ^ b for a, b in zip(plaintext, key[:len(plaintext)]))

    # Test with different library names
    for lib_name in ['custom', 'pycryptodome', 'cryptography', 'nacl', 'hashlib']:
        new_ct, pk = migrate_from(lib_name, old_ct, old_decrypt)
        assert isinstance(new_ct, bytes), f"Should work for library: {lib_name}"

    print("  migrate_from convenience: PASS")


def test_custom_aes_migrator():
    """Test CustomAESMigrator."""
    print("\n--- Testing CustomAESMigrator ---")

    migrator = CustomAESMigrator()
    key = b'\x88' * 32
    plaintext = b"Custom AES test data"

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ct = bytes(a ^ b for a, b in zip(plaintext, key[:len(plaintext)]))

    new_ct, pk = migrator.migrate(old_ct, old_decrypt)
    assert isinstance(new_ct, bytes), "Should return bytes ciphertext"
    print("  CustomAESMigrator: PASS")


def test_round_trip_migration():
    """Test that migrated data can be decrypted correctly."""
    print("\n--- Testing Round-Trip Migration ---")

    crypto = QHybridCrypt()
    sdk = MigrationSDK()

    key = b'\xAA' * 32
    original_plaintext = b"This is important data that must survive migration intact!"

    def old_decrypt(ct):
        return bytes(a ^ b for a, b in zip(ct, key[:len(ct)]))

    old_ct = bytes(a ^ b for a, b in zip(original_plaintext, key[:len(original_plaintext)]))

    # Migrate
    new_ct, pk = sdk.migrate_encrypted_data(old_ct, old_decrypt)

    # We need to find the private key to decrypt
    # Since migrate_encrypted_data generates a new keypair internally,
    # we need to use migrate_with_keypair for round-trip testing
    pk2, sk2 = crypto.generate_keypair()
    new_ct2 = sdk.migrate_with_keypair(old_ct, old_decrypt, pk2)

    # Decrypt with Q-HybridCrypt
    decrypted = crypto.decrypt(new_ct2, sk2)
    assert decrypted == original_plaintext, "Decrypted data should match original"
    print("  Round-trip migration: PASS")


def run_all_tests():
    """Run all migration tests."""
    print("=" * 60)
    print("Q-HybridCrypt v2.0 PHOENIX - Migration SDK Tests")
    print("=" * 60)

    tests = [
        test_migration_sdk_basic,
        test_migration_with_keypair,
        test_migration_log,
        test_batch_migration,
        test_migration_error_handling,
        test_migrate_from_convenience,
        test_custom_aes_migrator,
        test_round_trip_migration,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
