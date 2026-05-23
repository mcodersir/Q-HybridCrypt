"""
Q-HybridCrypt v2.0 "PHOENIX" - Usage Examples

Comprehensive examples demonstrating all features of the library.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from qhybridcrypt import QHybridCrypt


def example_basic_encryption():
    """Basic encryption and decryption example."""
    print("=== Basic Encryption Example ===")

    crypto = QHybridCrypt()

    # Generate quantum-resistant keypair
    print("1. Generating quantum-resistant keypair...")
    public_key, private_key = crypto.generate_keypair()
    print(f"   Public key size: {len(public_key)} bytes")
    print(f"   Private key size: {len(private_key)} bytes")

    # Encrypt a message
    message = "Hello from the post-quantum world!".encode('utf-8')
    print(f"\n2. Encrypting: {message.decode('utf-8')}")

    ciphertext = crypto.encrypt(message, public_key)
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   Overhead: {len(ciphertext) - len(message)} bytes")

    # Decrypt the message
    print("\n3. Decrypting...")
    decrypted = crypto.decrypt(ciphertext, private_key)
    print(f"   Decrypted: {decrypted.decode('utf-8')}")

    assert message == decrypted
    print("   Encryption/decryption successful!")


def example_authenticated_encryption():
    """Example with Additional Authenticated Data (AAD)."""
    print("\n=== Authenticated Encryption with AAD ===")

    crypto = QHybridCrypt()
    public_key, private_key = crypto.generate_keypair()

    message = b"Confidential document content"
    aad = b"doc_id:12345|user:alice|timestamp:1700000000"

    print(f"Message: {message.decode('utf-8')}")
    print(f"AAD: {aad.decode('utf-8')}")

    # Encrypt with AAD
    ciphertext = crypto.encrypt(message, public_key, aad)

    # Decrypt with correct AAD
    decrypted = crypto.decrypt(ciphertext, private_key, aad)
    print(f"Decrypted with correct AAD: {decrypted.decode('utf-8')}")

    # Wrong AAD is rejected
    try:
        crypto.decrypt(ciphertext, private_key, b"wrong_aad")
        print("ERROR: Should have rejected wrong AAD!")
    except ValueError:
        print("Correctly rejected wrong AAD!")


def example_password_hashing():
    """Password hashing example."""
    print("\n=== Password Hashing Example ===")

    crypto = QHybridCrypt()

    password = "MySuperSecurePassword123!"
    print(f"Password: {password}")

    # Hash password (using lower costs for demo speed)
    print("Hashing with Argon2id...")
    password_hash, salt = crypto.hash_password(password, time_cost=1, memory_cost=8192)

    print(f"Hash: {password_hash.hex()[:32]}...")
    print(f"Salt: {salt.hex()[:32]}...")

    # Verify correct password
    is_valid = crypto.verify_password(password, salt, password_hash,
                                       time_cost=1, memory_cost=8192)
    print(f"Correct password: {is_valid}")

    # Verify wrong password
    is_valid_wrong = crypto.verify_password("WrongPassword", salt, password_hash,
                                             time_cost=1, memory_cost=8192)
    print(f"Wrong password: {is_valid_wrong}")


def example_secure_communication():
    """Simulate secure communication between Alice and Bob."""
    print("\n=== Secure Communication Scenario ===")

    alice = QHybridCrypt()
    bob = QHybridCrypt()

    # Alice generates keypair
    print("1. Alice generates keypair")
    alice_public, alice_private = alice.generate_keypair()

    # Bob generates keypair
    print("2. Bob generates keypair")
    bob_public, bob_private = bob.generate_keypair()

    # Alice sends to Bob
    print("\n3. Alice -> Bob")
    alice_msg = b"Hi Bob! This is a quantum-safe message from Alice."
    ct_for_bob = alice.encrypt(alice_msg, bob_public)
    bob_received = bob.decrypt(ct_for_bob, bob_private)
    print(f"   Bob received: {bob_received.decode('utf-8')}")

    # Bob replies to Alice
    print("\n4. Bob -> Alice")
    bob_msg = b"Hi Alice! Message received. Quantum-safe channel confirmed!"
    ct_for_alice = bob.encrypt(bob_msg, alice_public)
    alice_received = alice.decrypt(ct_for_alice, alice_private)
    print(f"   Alice received: {alice_received.decode('utf-8')}")

    print("\nSecure quantum-resistant communication established!")


def example_system_info():
    """Display system information."""
    print("\n=== System Information ===")

    crypto = QHybridCrypt()
    info = crypto.get_info()

    print(f"System: {info['name']} v{info['version']} '{info['codename']}'")
    print(f"Quantum Resistant: {info['quantum_resistant']}")
    print(f"Security Level: NIST Level {info['security_level']}")

    print("\nAlgorithms:")
    for component, algorithm in info['algorithms'].items():
        print(f"   {component}: {algorithm}")

    print("\nKey Sizes:")
    for key_type, size in info['key_sizes'].items():
        print(f"   {key_type}: {size} bytes")

    print("\nSecurity Claims:")
    claims = info['security_claims']
    print(f"   Classical: {claims['classical_bits']}-bit")
    print(f"   Quantum: {claims['quantum_bits']}-bit")
    print(f"   Resistant to: {', '.join(claims['resistant_to'][:4])}...")


def run_all_examples():
    """Run all examples."""
    print("Q-HybridCrypt v2.0 PHOENIX - Usage Examples")
    print("=" * 55)

    try:
        example_basic_encryption()
        example_authenticated_encryption()
        example_password_hashing()
        example_secure_communication()
        example_system_info()

        print("\n" + "=" * 55)
        print("All examples completed successfully!")
        print("Q-HybridCrypt v2.0 PHOENIX is ready for production use!")

    except Exception as e:
        print(f"\nExample failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_all_examples()
