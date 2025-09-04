from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import pytest

from digital_signatures.crypto.signer.ecc_signer import EccSigner
from digital_signatures.utils.hasher import Hasher
from tests.fixtures.utils import fixture


class TestEccSigner:
    """Test cases for the EccSigner class."""

    def setup_method(self):
        """Set up test fixtures before each test method."""
        # Generate a test private key
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Create hash generator with SHA256
        self.hasher = Hasher(hashes.SHA256())
        
        # Create EccSigner instance
        self.signer = EccSigner(self.private_key, self.hasher)
        
        # Test messages
        self.str_message = "Hello, world!"
        self.bytes_message = b"Hello, world!"
        self.file_path = fixture('hello_world.txt')

    def test_init_with_valid_parameters(self):
        """Test that EccSigner initializes correctly with valid parameters."""
        signer = EccSigner(self.private_key, self.hasher)
        
        assert signer.private_key == self.private_key
        assert signer.hasher == self.hasher

    def test_init_with_invalid_private_key_type(self):
        """Test that EccSigner only accepts ECC private keys."""
        
        # Create a non-ECC private key (RSA for example)
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # EccSigner should raise an error if the private key is not an ECC private key.
        with pytest.raises(ValueError):
            EccSigner(rsa_private_key, self.hasher)

    def test_sign_with_bytes_message(self):
        """Test signing a bytes message."""
        signature = self.signer.sign(self.bytes_message)
        
        # Check that signature is bytes
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature using the public key
        public_key = self.private_key.public_key()
        message_digest = self.hasher.hash(self.bytes_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_with_string_message(self):
        """Test signing a string message."""
        signature = self.signer.sign(self.str_message)
        
        # Check that signature is bytes
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature using the public key
        public_key = self.private_key.public_key()
        message_digest = self.hasher.hash(self.str_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_with_file_message(self):
        """Test signing a file message."""
        signature = self.signer.sign(self.file_path)
        
        # Check that signature is bytes
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature using the public key
        public_key = self.private_key.public_key()
        message_digest = self.hasher.hash(self.file_path)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_with_empty_message(self):
        """Test signing an empty message."""
        empty_message = b""
        signature = self.signer.sign(empty_message)
        
        # Check that signature is bytes
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature using the public key
        public_key = self.private_key.public_key()
        message_digest = self.hasher.hash(empty_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_with_large_message(self):
        """Test signing a large message."""
        large_message = b"x" * 10000
        signature = self.signer.sign(large_message)
        
        # Check that signature is bytes
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature using the public key
        public_key = self.private_key.public_key()
        message_digest = self.hasher.hash(large_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_consistency(self):
        """Test that signing the same message multiple times produces valid signatures."""
        signature1 = self.signer.sign(self.bytes_message)
        signature2 = self.signer.sign(self.bytes_message)
        
        # Both signatures should be valid (ECC signatures are not deterministic due to random k)
        assert isinstance(signature1, bytes)
        assert isinstance(signature2, bytes)
        assert len(signature1) > 0
        assert len(signature2) > 0
        
        # Both signatures should verify correctly
        public_key = self.private_key.public_key()
        message_digest = self.hasher.hash(self.bytes_message)
        
        public_key.verify(signature1, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))
        public_key.verify(signature2, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_different_messages_produce_different_signatures(self):
        """Test that different messages produce different signatures."""
        message1 = b"Hello, world!"
        message2 = b"Hello, world!!"
        
        signature1 = self.signer.sign(message1)
        signature2 = self.signer.sign(message2)
        
        # Signatures should be different for different messages
        assert signature1 != signature2

    def test_sign_with_different_hash_algorithms(self):
        """Test signing with different hash algorithms."""
        # Test with SHA384
        sha384_generator = Hasher(hashes.SHA384())
        sha384_signer = EccSigner(self.private_key, sha384_generator)
        
        signature = sha384_signer.sign(self.bytes_message)
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature
        public_key = self.private_key.public_key()
        message_digest = sha384_generator.hash(self.bytes_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(sha384_generator.algorithm)))

    def test_sign_with_different_curves(self):
        """Test signing with different elliptic curves."""
        # Test with SECP384R1 curve
        secp384r1_key = ec.generate_private_key(ec.SECP384R1())
        secp384r1_signer = EccSigner(secp384r1_key, self.hasher)
        
        signature = secp384r1_signer.sign(self.bytes_message)
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify the signature
        public_key = secp384r1_key.public_key()
        message_digest = self.hasher.hash(self.bytes_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    def test_sign_inherits_from_signer_base_class(self):
        """Test that EccSigner inherits from the Signer base class."""
        from digital_signatures.crypto.signer.base import Signer
        
        assert isinstance(self.signer, Signer)

    def test_sign_uses_correct_hash_algorithm(self):
        """Test that the signer uses the correct hash algorithm from the hash generator."""
        # Create a custom hash generator with SHA512
        sha512_generator = Hasher(hashes.SHA512())
        sha512_signer = EccSigner(self.private_key, sha512_generator)
        
        signature = sha512_signer.sign(self.bytes_message)
        
        # Verify using the correct algorithm
        public_key = self.private_key.public_key()
        message_digest = sha512_generator.hash(self.bytes_message)
        
        public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(sha512_generator.algorithm)))

    def test_sign_with_invalid_message_type_raises_error(self):
        """Test that signing with invalid message type raises an appropriate error."""
        with pytest.raises((TypeError, ValueError)):
            self.signer.sign(123)
