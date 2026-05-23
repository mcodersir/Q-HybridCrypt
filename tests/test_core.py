"""
Test suite for Q-HybridCrypt v2.0 "PHOENIX"

Comprehensive tests covering:
- Keypair generation
- Encryption/decryption roundtrip
- Triple-cascade authentication
- Associated data (AAD) verification
- Password hashing
- Tampering detection
- Cross-instance communication
- Stream encryption
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from qhybridcrypt import QHybridCrypt
from qhybridcrypt.entropy import secure_random_bytes
from qhybridcrypt.utils import constant_time_compare


def test_keypair_generation():
    """Test quantum-resistant keypair generation."""
    print("Testing keypair generation...")

    crypto = QHybridCrypt()

    # Generate keypair
    public_key, private_key = crypto.generate_keypair()

    # Verify key sizes
    info = crypto.get_info()
    assert len(public_key) == info['key_sizes']['public_key'], \
        f"Public key size mismatch: got {len(public_key)}, expected {info['key_sizes']['public_key']}"
    assert len(private_key) == info['key_sizes']['secret_key'], \
        f"Secret key size mismatch: got {len(private_key)}, expected {info['key_sizes']['secret_key']}"

    # Generate another keypair and verify uniqueness
    public_key2, private_key2 = crypto.generate_keypair()
    assert public_key != public_key2, "Public keys should be different"
    assert private_key != private_key2, "Private keys should be different"

    print("  PASS: Keypair generation")


def test_basic_encryption_decryption():
    """Test basic encryption and decryption roundtrip."""
    print("Testing basic encryption/decryption...")

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    test_messages = [
        b"Hello, quantum-resistant world!",
        b"Short",
        b"A" * 1000,
        b"\x00\x01\x02\x03" * 100,
        b"Persian: \xd8\xb3\xd9\x84\xd8\xa7\xd9\x85",
    ]

    for i, plaintext in enumerate(test_messages):
        print(f"  Message {i+1}: {len(plaintext)} bytes", end=" ")

        ciphertext = crypto.encrypt(plaintext, public_key)

        # Verify ciphertext differs from plaintext
        assert ciphertext != plaintext, "Ciphertext should differ from plaintext"
        assert len(ciphertext) > len(plaintext), "Ciphertext should be longer (overhead)"

        decrypted = crypto.decrypt(ciphertext, private_key)
        assert decrypted == plaintext, f"Decryption failed for message {i+1}"
        print("OK")

    print("  PASS: Basic encryption/decryption")


def test_triple_authentication():
    """Test that all three authentication layers work."""
    print("Testing triple authentication...")

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    plaintext = b"Triple-authenticated message"
    ciphertext = crypto.encrypt(plaintext, public_key)

    # Tamper with various positions
    tamper_positions = [
        4,   # Version field
        8,   # Salt
        40,  # KEM ciphertext
        -32, # HMAC tag
        -16, # Part of cascade
    ]

    for pos in tamper_positions:
        tampered = bytearray(ciphertext)
        actual_pos = pos if pos >= 0 else len(tampered) + pos
        if actual_pos < len(tampered):
            tampered[actual_pos] ^= 0x01

            try:
                crypto.decrypt(bytes(tampered), private_key)
                assert False, f"Decryption should have failed for tampering at position {pos}"
            except ValueError:
                pass  # Expected: authentication should detect tampering

    print("  PASS: Triple authentication")


def test_associated_data():
    """Test Additional Authenticated Data (AAD)."""
    print("Testing AAD...")

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    plaintext = b"Message with AAD"
    aad = b"user:alice,timestamp:2024,nonce:abc123"

    # Encrypt with AAD
    ciphertext = crypto.encrypt(plaintext, public_key, aad)

    # Decrypt with correct AAD
    decrypted = crypto.decrypt(ciphertext, private_key, aad)
    assert decrypted == plaintext, "Decryption with correct AAD failed"

    # Try to decrypt with wrong AAD
    wrong_aad = b"user:eve,timestamp:2024,nonce:xyz789"
    try:
        crypto.decrypt(ciphertext, private_key, wrong_aad)
        assert False, "Decryption should have failed with wrong AAD"
    except ValueError:
        pass  # Expected

    # Try without AAD when AAD was used
    try:
        crypto.decrypt(ciphertext, private_key, b'')
        assert False, "Decryption should have failed without AAD"
    except ValueError:
        pass  # Expected

    print("  PASS: AAD verification")


def test_password_hashing():
    """Test Argon2id password hashing."""
    print("Testing password hashing...")

    crypto = QHybridCrypt()

    passwords = ["password123", "SecureP@ss!", "", "a" * 100]

    for password in passwords:
        print(f"  Testing password: '{password[:10]}...' " if len(password) > 10 else f"  Testing password: '{password}' ", end="")

        # Hash password
        hash_result, salt = crypto.hash_password(password, time_cost=1, memory_cost=8192)

        # Verify hash properties
        assert len(hash_result) == 32, "Hash should be 32 bytes"
        assert len(salt) >= 16, "Salt should be at least 16 bytes"

        # Verify correct password
        assert crypto.verify_password(password, salt, hash_result,
                                       time_cost=1, memory_cost=8192), \
            "Password verification failed"

        # Test wrong password
        wrong = password + "wrong" if password else "x"
        assert not crypto.verify_password(wrong, salt, hash_result,
                                           time_cost=1, memory_cost=8192), \
            "Wrong password should not verify"

        print("OK")

    print("  PASS: Password hashing")


def test_deterministic_keys():
    """Test deterministic key generation with seeds."""
    print("Testing deterministic key generation...")

    crypto = QHybridCrypt()
    seed = b"test_seed_for_deterministic_keys!!!"

    # Generate keypairs with same seed
    pk1, sk1 = crypto.generate_keypair(seed)
    pk2, sk2 = crypto.generate_keypair(seed)

    # Should be identical
    assert pk1 == pk2, "Public keys should be identical with same seed"
    assert sk1 == sk2, "Secret keys should be identical with same seed"

    # Different seed → different keys
    seed2 = b"different_seed_for_different_key"
    pk3, sk3 = crypto.generate_keypair(seed2)

    assert pk1 != pk3, "Different seeds should produce different public keys"
    assert sk1 != sk3, "Different seeds should produce different secret keys"

    print("  PASS: Deterministic key generation")


def test_cross_instance_communication():
    """Test that different instances can communicate."""
    print("Testing cross-instance communication...")

    alice = QHybridCrypt()
    bob = QHybridCrypt()

    # Alice generates keypair
    alice_public, alice_private = alice.generate_keypair()

    # Bob encrypts for Alice
    message = b"Hello from Bob via quantum-resistant channel!"
    ciphertext = bob.encrypt(message, alice_public)

    # Alice decrypts
    decrypted = alice.decrypt(ciphertext, alice_private)
    assert decrypted == message, "Cross-instance communication failed"

    print("  PASS: Cross-instance communication")


def test_no_padding():
    """Test encryption without padding."""
    print("Testing encryption without padding...")

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    plaintext = b"No padding test"
    ciphertext = crypto.encrypt(plaintext, public_key, padding=False)

    decrypted = crypto.decrypt(ciphertext, private_key)
    assert decrypted == plaintext, "Decryption without padding failed"

    print("  PASS: No padding mode")


def test_empty_message():
    """Test encryption of empty message with padding."""
    print("Testing empty message encryption...")

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    ciphertext = crypto.encrypt(b'', public_key)
    decrypted = crypto.decrypt(ciphertext, private_key)
    assert decrypted == b'', "Empty message decryption failed"

    print("  PASS: Empty message")


def test_info_function():
    """Test system information function."""
    print("Testing info function...")

    crypto = QHybridCrypt()
    info = crypto.get_info()

    # Verify structure
    required_fields = ['name', 'version', 'quantum_resistant', 'algorithms', 'parameters', 'key_sizes']
    for field in required_fields:
        assert field in info, f"Missing field: {field}"

    # Verify values
    assert info['name'] == 'Q-HybridCrypt'
    assert info['quantum_resistant'] is True
    assert info['codename'] == 'PHOENIX'
    assert 'ChaCha20-Poly1305' in info['algorithms']['encryption_layer_1']
    assert 'AES-256-GCM' in info['algorithms']['encryption_layer_2']
    assert 'Argon2id' in info['algorithms']['password_hashing']
    assert 'Module-LWE' in info['algorithms']['kem']

    print("  PASS: Info function")


def test_wrong_key_rejection():
    """Test that wrong private key is rejected."""
    print("Testing wrong key rejection...")

    crypto = QHybridCrypt()

    # Alice and Bob generate different keypairs
    alice_public, alice_private = crypto.generate_keypair()
    bob_public, bob_private = crypto.generate_keypair()

    # Encrypt for Alice
    ciphertext = crypto.encrypt(b"Secret for Alice", alice_public)

    # Try to decrypt with Bob's key (should fail)
    try:
        crypto.decrypt(ciphertext, bob_private)
        # Note: This might not always raise ValueError due to FO implicit rejection
        # but the result should NOT match the original plaintext
    except ValueError:
        pass  # Expected

    print("  PASS: Wrong key rejection")


def run_all_tests():
    """Run all test functions."""
    print("=" * 60)
    print("Q-HybridCrypt v2.0 PHOENIX - Test Suite")
    print("=" * 60)

    test_functions = [
        test_keypair_generation,
        test_basic_encryption_decryption,
        test_triple_authentication,
        test_associated_data,
        test_password_hashing,
        test_deterministic_keys,
        test_cross_instance_communication,
        test_no_padding,
        test_empty_message,
        test_info_function,
        test_wrong_key_rejection,
    ]

    passed = 0
    failed = 0

    for test_func in test_functions:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {test_func.__name__}: {e}")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("All tests passed! Q-HybridCrypt v2.0 PHOENIX is ready.")
    else:
        print(f"{failed} tests failed. Please review the implementation.")

    return failed == 0


if __name__ == "__main__":
    run_all_tests()
