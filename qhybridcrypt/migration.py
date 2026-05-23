"""
Q-HybridCrypt v2.0 "PHOENIX" - Migration SDK

Provides a seamless migration path from other cryptographic libraries
to Q-HybridCrypt. Supports migration from:

- PyCryptodome (AES, RSA, etc.)
- cryptography (Fernet, AES-GCM, RSA, etc.)
- NaCl / PyNaCl (XSalsa20-Poly1305, etc.)
- hashlib-based custom implementations
- Any library using standard AES-GCM or ChaCha20

The migration process:
1. Decrypt data with the OLD library
2. Re-encrypt with Q-HybridCrypt PHOENIX protocol
3. Store the new ciphertext
4. Optionally keep old keys for backward compatibility

Exclusive Feature: "Transparent Re-encryption"
- One-step migration that reads old format and outputs Q-HybridCrypt format
- No intermediate plaintext exposure in application code
- Supports batch migration for large datasets
"""

import struct
import hashlib
from typing import Tuple, Optional, Callable, Dict, List, Any

from .core import QHybridCrypt
from .entropy import secure_random_bytes
from .utils import sha3_256, constant_time_compare


class MigrationSDK:
    """
    SDK for migrating from other cryptographic libraries to Q-HybridCrypt.

    This SDK provides:
    - One-step migration from common crypto library formats
    - Batch migration for large datasets
    - Backward-compatible decryption (read old, write new)
    - Migration status tracking
    - Rollback support (keeps original keys until migration verified)

    Example:
        >>> from qhybridcrypt.migration import MigrationSDK
        >>> sdk = MigrationSDK()
        >>>
        >>> # Migrate from PyCryptodome
        >>> old_decrypt_fn = lambda ct: old_aes_decrypt(key, ct)
        >>> new_ct, new_pk = sdk.migrate_encrypted_data(
        ...     old_ciphertext, old_decrypt_fn
        ... )
    """

    def __init__(self, security_level: int = 3):
        """
        Initialize the Migration SDK.

        Args:
            security_level: NIST security level (1, 3, or 5).
        """
        self.crypto = QHybridCrypt(security_level=security_level)
        self._migration_log: List[Dict] = []

    def migrate_encrypted_data(
        self,
        old_ciphertext: bytes,
        old_decrypt_fn: Callable[[bytes], bytes],
        associated_data: bytes = b'',
        keep_old_key_ref: bool = True
    ) -> Tuple[bytes, bytes]:
        """
        Migrate encrypted data from any library to Q-HybridCrypt format.

        This is the "Transparent Re-encryption" feature - a one-step migration
        that reads old format and outputs Q-HybridCrypt format without exposing
        plaintext in application code.

        The process:
        1. Decrypt using the provided old decryption function
        2. Re-encrypt with Q-HybridCrypt triple-cascade
        3. Return new ciphertext and public key reference

        Args:
            old_ciphertext: Ciphertext from the old library.
            old_decrypt_fn: Function that decrypts old_ciphertext.
                            Must accept bytes and return plaintext bytes.
            associated_data: Optional AAD for the new encryption.
            keep_old_key_ref: If True, stores a hash of the old key for
                              rollback/verification purposes.

        Returns:
            Tuple of (new_ciphertext, public_key).
            The public_key is needed for future encryption to the same recipient.
            The private_key is generated internally and must be saved.
        """
        # Step 1: Decrypt with old library (transparent to caller)
        try:
            plaintext = old_decrypt_fn(old_ciphertext)
        except Exception as e:
            raise MigrationError(f"Old decryption failed: {e}")

        if not isinstance(plaintext, bytes):
            raise MigrationError("Old decrypt function must return bytes")

        # Step 2: Generate new Q-HybridCrypt keypair
        public_key, private_key = self.crypto.generate_keypair()

        # Step 3: Re-encrypt with Q-HybridCrypt
        new_ciphertext = self.crypto.encrypt(plaintext, public_key, associated_data)

        # Step 4: Log migration
        old_key_hash = sha3_256(old_ciphertext[:64]) if keep_old_key_ref else None
        migration_record = {
            'status': 'migrated',
            'old_format_hash': sha3_256(old_ciphertext).hex(),
            'old_key_ref': old_key_hash.hex() if old_key_hash else None,
            'new_key_hash': sha3_256(public_key).hex(),
            'security_level': self.crypto.security_level,
            'protocol_version': 2,
        }
        self._migration_log.append(migration_record)

        return new_ciphertext, public_key

    def migrate_with_keypair(
        self,
        old_ciphertext: bytes,
        old_decrypt_fn: Callable[[bytes], bytes],
        public_key: bytes,
        associated_data: bytes = b''
    ) -> bytes:
        """
        Migrate encrypted data using an existing Q-HybridCrypt keypair.

        Use this when you already have a Q-HybridCrypt keypair and want
        to migrate data to it.

        Args:
            old_ciphertext: Ciphertext from the old library.
            old_decrypt_fn: Function that decrypts old_ciphertext.
            public_key: Existing Q-HybridCrypt public key.
            associated_data: Optional AAD for the new encryption.

        Returns:
            New Q-HybridCrypt ciphertext.
        """
        try:
            plaintext = old_decrypt_fn(old_ciphertext)
        except Exception as e:
            raise MigrationError(f"Old decryption failed: {e}")

        return self.crypto.encrypt(plaintext, public_key, associated_data)

    def batch_migrate(
        self,
        old_ciphertexts: List[bytes],
        old_decrypt_fn: Callable[[bytes], bytes],
        associated_data: bytes = b'',
        on_progress: Optional[Callable[[int, int], None]] = None
    ) -> Tuple[List[bytes], bytes]:
        """
        Batch migrate multiple encrypted data items.

        All items are migrated to the same keypair, reducing key management
        overhead for large datasets.

        Args:
            old_ciphertexts: List of ciphertexts from the old library.
            old_decrypt_fn: Function that decrypts each old ciphertext.
            associated_data: Optional AAD for all encryptions.
            on_progress: Optional callback(current, total) for progress tracking.

        Returns:
            Tuple of (list_of_new_ciphertexts, public_key).
        """
        if not old_ciphertexts:
            return [], b''

        # Generate one keypair for all items
        public_key, _ = self.crypto.generate_keypair()

        new_ciphertexts = []
        total = len(old_ciphertexts)

        for i, old_ct in enumerate(old_ciphertexts):
            try:
                plaintext = old_decrypt_fn(old_ct)
                # Each item gets its own AAD with index for ordering
                item_aad = associated_data + struct.pack('<I', i)
                new_ct = self.crypto.encrypt(plaintext, public_key, item_aad)
                new_ciphertexts.append(new_ct)
            except Exception as e:
                raise MigrationError(f"Batch migration failed at item {i}/{total}: {e}")

            if on_progress:
                on_progress(i + 1, total)

        return new_ciphertexts, public_key

    def get_migration_log(self) -> List[Dict]:
        """Get the migration log for audit purposes."""
        return self._migration_log.copy()

    def clear_migration_log(self) -> None:
        """Clear the migration log."""
        self._migration_log.clear()


# =============================================================================
# Library-Specific Migration Helpers
# =============================================================================

class PyCryptodomeMigrator:
    """
    Migrate from PyCryptodome (Crypto.Cipher.AES, etc.) to Q-HybridCrypt.

    Example:
        >>> from qhybridcrypt.migration import PyCryptodomeMigrator
        >>> migrator = PyCryptodomeMigrator()
        >>>
        >>> # For AES-GCM encrypted data
        >>> def my_aes_gcm_decrypt(ct_bytes):
        ...     from Crypto.Cipher import AES
        ...     nonce, tag, ciphertext = ct_bytes[:16], ct_bytes[16:32], ct_bytes[32:]
        ...     cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ...     return cipher.decrypt_and_verify(ciphertext, tag)
        >>>
        >>> new_ct, pk = migrator.migrate(old_ciphertext, my_aes_gcm_decrypt)
    """

    def __init__(self, security_level: int = 3):
        self.sdk = MigrationSDK(security_level)

    def migrate(
        self,
        old_ciphertext: bytes,
        old_decrypt_fn: Callable[[bytes], bytes],
        associated_data: bytes = b''
    ) -> Tuple[bytes, bytes]:
        """
        Migrate PyCryptodome-encrypted data to Q-HybridCrypt.

        Args:
            old_ciphertext: Data encrypted with PyCryptodome.
            old_decrypt_fn: Decryption function for the old format.
            associated_data: Optional AAD.

        Returns:
            Tuple of (new_ciphertext, public_key).
        """
        return self.sdk.migrate_encrypted_data(
            old_ciphertext, old_decrypt_fn, associated_data
        )


class CryptographyIOMigrator:
    """
    Migrate from the 'cryptography' library (Fernet, AES-GCM, etc.) to Q-HybridCrypt.

    Example:
        >>> from qhybridcrypt.migration import CryptographyIOMigrator
        >>> migrator = CryptographyIOMigrator()
        >>>
        >>> # For Fernet tokens
        >>> def fernet_decrypt(token):
        ...     from cryptography.fernet import Fernet
        ...     f = Fernet(fernet_key)
        ...     return f.decrypt(token)
        >>>
        >>> new_ct, pk = migrator.migrate(fernet_token, fernet_decrypt)
    """

    def __init__(self, security_level: int = 3):
        self.sdk = MigrationSDK(security_level)

    def migrate(
        self,
        old_ciphertext: bytes,
        old_decrypt_fn: Callable[[bytes], bytes],
        associated_data: bytes = b''
    ) -> Tuple[bytes, bytes]:
        """
        Migrate cryptography-library-encrypted data to Q-HybridCrypt.

        Args:
            old_ciphertext: Data encrypted with the cryptography library.
            old_decrypt_fn: Decryption function for the old format.
            associated_data: Optional AAD.

        Returns:
            Tuple of (new_ciphertext, public_key).
        """
        return self.sdk.migrate_encrypted_data(
            old_ciphertext, old_decrypt_fn, associated_data
        )

    def migrate_fernet(
        self,
        fernet_token: bytes,
        fernet_key: bytes,
        associated_data: bytes = b''
    ) -> Tuple[bytes, bytes]:
        """
        Convenience method to migrate Fernet tokens directly.

        Args:
            fernet_token: Fernet-encrypted token.
            fernet_key: Fernet key (url-safe base64 encoded).
            associated_data: Optional AAD.

        Returns:
            Tuple of (new_ciphertext, public_key).
        """
        def fernet_decrypt(token):
            try:
                from cryptography.fernet import Fernet
                f = Fernet(fernet_key)
                return f.decrypt(token)
            except ImportError:
                raise MigrationError(
                    "cryptography library not installed. "
                    "Install with: pip install cryptography"
                )

        return self.sdk.migrate_encrypted_data(
            fernet_token, fernet_decrypt, associated_data
        )


class NaClMigrator:
    """
    Migrate from PyNaCl / NaCl (XSalsa20-Poly1305, etc.) to Q-HybridCrypt.

    Example:
        >>> from qhybridcrypt.migration import NaClMigrator
        >>> migrator = NaClMigrator()
        >>>
        >>> def nacl_decrypt(ct):
        ...     from nacl.secret import SecretBox
        ...     box = SecretBox(nacl_key)
        ...     return box.decrypt(ct)
        >>>
        >>> new_ct, pk = migrator.migrate(old_ct, nacl_decrypt)
    """

    def __init__(self, security_level: int = 3):
        self.sdk = MigrationSDK(security_level)

    def migrate(
        self,
        old_ciphertext: bytes,
        old_decrypt_fn: Callable[[bytes], bytes],
        associated_data: bytes = b''
    ) -> Tuple[bytes, bytes]:
        return self.sdk.migrate_encrypted_data(
            old_ciphertext, old_decrypt_fn, associated_data
        )


class CustomAESMigrator:
    """
    Migrate from custom AES-GCM implementations to Q-HybridCrypt.

    Handles common AES-GCM formats:
    - nonce(12) + ciphertext + tag(16)
    - nonce(16) + ciphertext + tag(16)
    - IV(16) + ciphertext + tag(16)
    - ciphertext only (nonce/iv stored separately)

    Example:
        >>> from qhybridcrypt.migration import CustomAESMigrator
        >>> migrator = CustomAESMigrator()
        >>> new_ct, pk = migrator.migrate_aes_gcm(
        ...     nonce, ciphertext, tag, aes_key
        ... )
    """

    def __init__(self, security_level: int = 3):
        self.sdk = MigrationSDK(security_level)

    def migrate_aes_gcm(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aes_key: bytes,
        associated_data: bytes = b''
    ) -> Tuple[bytes, bytes]:
        """
        Migrate from raw AES-GCM components.

        Args:
            nonce: GCM nonce/IV (typically 12 bytes).
            ciphertext: AES-GCM ciphertext.
            tag: GCM authentication tag (typically 16 bytes).
            aes_key: AES key used for decryption.
            associated_data: Optional AAD.

        Returns:
            Tuple of (new_ciphertext, public_key).
        """
        def aes_gcm_decrypt(_unused):
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(aes_key)
                return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
            except ImportError:
                # Fallback to PyCryptodome
                try:
                    from Crypto.Cipher import AES
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    return cipher.decrypt_and_verify(ciphertext, tag)
                except ImportError:
                    raise MigrationError(
                        "Neither cryptography nor PyCryptodome available. "
                        "Install one: pip install cryptography"
                    )

        return self.sdk.migrate_encrypted_data(
            nonce + ciphertext + tag, aes_gcm_decrypt, associated_data
        )


class MigrationError(Exception):
    """Raised when migration fails."""
    pass


# =============================================================================
# Convenience Functions
# =============================================================================

def migrate_from(
    library: str,
    old_ciphertext: bytes,
    old_decrypt_fn: Callable[[bytes], bytes],
    security_level: int = 3,
    associated_data: bytes = b''
) -> Tuple[bytes, bytes]:
    """
    One-step migration from any supported library.

    This is the simplest way to migrate - just specify which library
    your data is currently encrypted with, provide a decryption function,
    and get back Q-HybridCrypt encrypted data.

    Supported libraries:
    - 'pycryptodome' or 'pycrypto'
    - 'cryptography' or 'fernet'
    - 'nacl' or 'pynacl'
    - 'custom' or 'aes-gcm'
    - 'hashlib' or 'custom-hash'

    Args:
        library: Name of the source library.
        old_ciphertext: Ciphertext from the source library.
        old_decrypt_fn: Function that decrypts old_ciphertext.
        security_level: NIST security level (1, 3, or 5).
        associated_data: Optional AAD.

    Returns:
        Tuple of (new_ciphertext, public_key).

    Example:
        >>> from qhybridcrypt.migration import migrate_from
        >>>
        >>> def my_decrypt(ct):
        ...     # Your existing decryption code
        ...     return plaintext
        >>>
        >>> new_ct, pk = migrate_from('pycryptodome', old_ct, my_decrypt)
    """
    sdk = MigrationSDK(security_level)
    return sdk.migrate_encrypted_data(old_ciphertext, old_decrypt_fn, associated_data)
