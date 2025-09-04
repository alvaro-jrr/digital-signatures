from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from digital_signatures.crypto.signer.ecc_signer import EccSigner
from digital_signatures.crypto.verifier.ecc_verifier import EccVerifier
from digital_signatures.utils.hash_generator import HashGenerator
from tests.fixtures.utils import fixture


class TestEccVerifier:
    """Test cases for the EccVerifier class."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        # Generate a test key pair
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # Create hash generator with SHA256
        self.hash_generator = HashGenerator(hashes.SHA256())
        
        # Create EccVerifier instance
        self.verifier = EccVerifier(self.public_key, self.hash_generator)
        
        # Create EccSigner instance for generating valid signatures
        self.signer = EccSigner(self.private_key, self.hash_generator)
        
        # Test messages
        self.str_message = "Hello, world!"
        self.bytes_message = b"Hello, world!"
        self.file_path = fixture('hello_world.txt')

    def test_init_with_valid_parameters(self):
        """Test that EccVerifier initializes correctly with valid parameters."""
        verifier = EccVerifier(self.public_key, self.hash_generator)
        
        assert verifier.public_key == self.public_key
        assert verifier.hash_generator == self.hash_generator

    def test_init_with_invalid_public_key_type(self):
        """Test that EccVerifier raises an error with invalid public key type."""
        # Create a non-ECC public key (RSA for example)
        from cryptography.hazmat.primitives.asymmetric import rsa
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        rsa_public_key = rsa_private_key.public_key()
        
        with pytest.raises(ValueError, match="Public key must be an instance of EllipticCurvePublicKey."):
            EccVerifier(rsa_public_key, self.hash_generator)

    def test_verify_with_valid_signature_bytes_message(self):
        """Test verifying a valid signature with bytes message."""
        # Generate a valid signature
        signature = self.signer.sign(self.bytes_message)
        
        # Verify the signature
        result = self.verifier.verify(signature, self.bytes_message)
        
        assert result is True

    def test_verify_with_valid_signature_string_message(self):
        """Test verifying a valid signature with string message."""
        # Generate a valid signature
        signature = self.signer.sign(self.str_message)
        
        # Verify the signature
        result = self.verifier.verify(signature, self.str_message)
        
        assert result is True

    def test_verify_with_valid_signature_file_message(self):
        """Test verifying a valid signature with file message."""
        # Generate a valid signature
        signature = self.signer.sign(self.file_path)
        
        # Verify the signature
        result = self.verifier.verify(signature, self.file_path)
        
        assert result is True

    def test_verify_with_invalid_signature(self):
        """Test verifying with an invalid signature."""
        # Create an invalid signature (random bytes)
        invalid_signature = b"invalid_signature_bytes"
        
        # Verify the signature
        result = self.verifier.verify(invalid_signature, self.bytes_message)
        
        assert result is False

    def test_verify_with_corrupted_signature(self):
        """Test verifying with a corrupted signature."""
        # Generate a valid signature
        valid_signature = self.signer.sign(self.bytes_message)
        
        # Corrupt the signature by changing one byte
        corrupted_signature = bytearray(valid_signature)
        corrupted_signature[0] = (corrupted_signature[0] + 1) % 256
        
        # Verify the corrupted signature
        result = self.verifier.verify(bytes(corrupted_signature), self.bytes_message)
        
        assert result is False

    def test_verify_with_different_message(self):
        """Test verifying a signature with a different message."""
        # Generate a signature for one message
        signature = self.signer.sign(self.bytes_message)
        
        # Try to verify with a different message
        different_message = b"Different message!"
        result = self.verifier.verify(signature, different_message)
        
        assert result is False

    def test_verify_with_empty_message(self):
        """Test verifying a signature with an empty message."""
        # Generate a signature for empty message
        empty_message = b""
        signature = self.signer.sign(empty_message)
        
        # Verify the signature
        result = self.verifier.verify(signature, empty_message)
        
        assert result is True

    def test_verify_with_large_message(self):
        """Test verifying a signature with a large message."""
        # Generate a signature for large message
        large_message = b"x" * 10000
        signature = self.signer.sign(large_message)
        
        # Verify the signature
        result = self.verifier.verify(signature, large_message)
        
        assert result is True

    def test_verify_with_different_hash_algorithms(self):
        """Test verifying with different hash algorithms."""
        # Test with SHA384
        sha384_generator = HashGenerator(hashes.SHA384())
        sha384_verifier = EccVerifier(self.public_key, sha384_generator)
        sha384_signer = EccSigner(self.private_key, sha384_generator)
        
        # Generate and verify signature
        signature = sha384_signer.sign(self.bytes_message)
        result = sha384_verifier.verify(signature, self.bytes_message)
        
        assert result is True

    def test_verify_with_different_curves(self):
        """Test verifying with different elliptic curves."""
        # Test with SECP384R1 curve
        secp384r1_private_key = ec.generate_private_key(ec.SECP384R1())
        secp384r1_public_key = secp384r1_private_key.public_key()
        
        secp384r1_verifier = EccVerifier(secp384r1_public_key, self.hash_generator)
        secp384r1_signer = EccSigner(secp384r1_private_key, self.hash_generator)
        
        # Generate and verify signature
        signature = secp384r1_signer.sign(self.bytes_message)
        result = secp384r1_verifier.verify(signature, self.bytes_message)
        
        assert result is True

    def test_verify_inherits_from_verifier_base_class(self):
        """Test that EccVerifier inherits from the Verifier base class."""
        from digital_signatures.crypto.verifier.base import Verifier
        
        assert isinstance(self.verifier, Verifier)

    def test_verify_uses_correct_hash_algorithm(self):
        """Test that the verifier uses the correct hash algorithm from the hash generator."""
        # Create a custom hash generator with SHA512
        sha512_generator = HashGenerator(hashes.SHA512())
        sha512_verifier = EccVerifier(self.public_key, sha512_generator)
        sha512_signer = EccSigner(self.private_key, sha512_generator)
        
        # Generate and verify signature
        signature = sha512_signer.sign(self.bytes_message)
        result = sha512_verifier.verify(signature, self.bytes_message)
        
        assert result is True

    def test_verify_with_wrong_public_key(self):
        """Test verifying with a different public key."""
        # Generate a different key pair
        different_private_key = ec.generate_private_key(ec.SECP256R1())
        different_public_key = different_private_key.public_key()
        different_verifier = EccVerifier(different_public_key, self.hash_generator)
        
        # Generate signature with original private key
        signature = self.signer.sign(self.bytes_message)
        
        # Try to verify with different public key
        result = different_verifier.verify(signature, self.bytes_message)
        
        assert result is False

    def test_verify_with_none_signature(self):
        """Test that verifying with None signature returns False."""
        result = self.verifier.verify(None, self.bytes_message)
        
        assert result is False

    def test_verify_with_none_message(self):
        """Test that verifying with None message raises an appropriate error."""
        signature = self.signer.sign(self.bytes_message)
        
        with pytest.raises((TypeError, ValueError)):
            self.verifier.verify(signature, None)

    def test_verify_with_invalid_message_type(self):
        """Test that verifying with invalid message type raises an appropriate error."""
        signature = self.signer.sign(self.bytes_message)
        
        with pytest.raises(ValueError, match="Invalid message type"):
            self.verifier.verify(signature, 123)  # Integer is not a valid message type

    def test_verify_with_empty_signature(self):
        """Test verifying with an empty signature."""
        empty_signature = b""
        
        result = self.verifier.verify(empty_signature, self.bytes_message)
        
        assert result is False

    def test_verify_with_very_short_signature(self):
        """Test verifying with a very short signature."""
        short_signature = b"short"
        
        result = self.verifier.verify(short_signature, self.bytes_message)
        
        assert result is False

    def test_verify_with_very_long_signature(self):
        """Test verifying with a very long signature."""
        long_signature = b"x" * 1000
        
        result = self.verifier.verify(long_signature, self.bytes_message)
        
        assert result is False

    def test_verify_consistency(self):
        """Test that verifying the same signature multiple times produces consistent results."""
        signature = self.signer.sign(self.bytes_message)
        
        # Verify multiple times
        result1 = self.verifier.verify(signature, self.bytes_message)
        result2 = self.verifier.verify(signature, self.bytes_message)
        result3 = self.verifier.verify(signature, self.bytes_message)
        
        # All results should be the same
        assert result1 == result2 == result3 is True

    def test_verify_with_mixed_message_types(self):
        """Test verifying signatures with different message types."""
        # Test with string message
        str_signature = self.signer.sign(self.str_message)
        str_result = self.verifier.verify(str_signature, self.str_message)
        assert str_result is True
        
        # Test with bytes message
        bytes_signature = self.signer.sign(self.bytes_message)
        bytes_result = self.verifier.verify(bytes_signature, self.bytes_message)
        assert bytes_result is True
        
        # Test with file message
        file_signature = self.signer.sign(self.file_path)
        file_result = self.verifier.verify(file_signature, self.file_path)
        assert file_result is True

    def test_verify_with_special_characters(self):
        """Test verifying signatures with messages containing special characters."""
        special_message = "Hello, 世界! 🚀 @#$%^&*()"
        signature = self.signer.sign(special_message)
        
        result = self.verifier.verify(signature, special_message)
        
        assert result is True
