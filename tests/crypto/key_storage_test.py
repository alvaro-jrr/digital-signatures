import os
import tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from digital_signatures.crypto.key_storage import KeyStorage
from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator


def test_key_storage_initialization_default():
    """Test KeyStorage initialization with default parameters."""
    storage = KeyStorage()
    
    assert storage.encoding_format == serialization.Encoding.PEM
    assert storage.private_format == serialization.PrivateFormat.PKCS8
    assert storage.public_format == serialization.PublicFormat.SubjectPublicKeyInfo


def test_key_storage_initialization_custom():
    """Test KeyStorage initialization with custom parameters."""
    storage = KeyStorage(
        encoding_format=serialization.Encoding.DER,
        private_format=serialization.PrivateFormat.TraditionalOpenSSL,
        public_format=serialization.PublicFormat.PKCS1
    )
    
    assert storage.encoding_format == serialization.Encoding.DER
    assert storage.private_format == serialization.PrivateFormat.TraditionalOpenSSL
    assert storage.public_format == serialization.PublicFormat.PKCS1


def test_serialize_private_key_no_password():
    """Test private key serialization without password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    private_key, _ = key_generator.generate()
    
    serialized = storage.serialize_private_key(private_key)
    
    # Verify it's bytes
    assert isinstance(serialized, bytes)
    
    # Verify it contains PEM markers
    assert b'BEGIN PRIVATE KEY' in serialized
    assert b'END PRIVATE KEY' in serialized


def test_serialize_private_key_with_string_password():
    """Test private key serialization with string password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    private_key, _ = key_generator.generate()
    password = "test_password"
    
    serialized = storage.serialize_private_key(private_key, password)
    
    # Verify it's bytes
    assert isinstance(serialized, bytes)
    
    # Verify it contains PEM markers
    assert b'BEGIN ENCRYPTED PRIVATE KEY' in serialized
    assert b'END ENCRYPTED PRIVATE KEY' in serialized


def test_serialize_private_key_with_bytes_password():
    """Test private key serialization with bytes password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    private_key, _ = key_generator.generate()
    password = b"test_password"
    
    serialized = storage.serialize_private_key(private_key, password)
    
    # Verify it's bytes
    assert isinstance(serialized, bytes)
    
    # Verify it contains PEM markers
    assert b'BEGIN ENCRYPTED PRIVATE KEY' in serialized
    assert b'END ENCRYPTED PRIVATE KEY' in serialized


def test_serialize_public_key():
    """Test public key serialization."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    _, public_key = key_generator.generate()
    
    serialized = storage.serialize_public_key(public_key)
    
    # Verify it's bytes
    assert isinstance(serialized, bytes)
    
    # Verify it contains PEM markers
    assert b'BEGIN PUBLIC KEY' in serialized
    assert b'END PUBLIC KEY' in serialized


def test_load_public_key_from_file():
    """Test loading key from file (auto-detect format)."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    _, original_public_key = key_generator.generate()
    
    # Serialize and save to file
    serialized_public = storage.serialize_public_key(original_public_key)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file.write(serialized_public)
        temp_file_path = temp_file.name
    
    try:
        # Load the public key
        loaded_public_key = storage.load_public_key_from_file(temp_file_path)
        
        # Verify the loaded key matches the original
        assert loaded_public_key.public_bytes(
            storage.encoding_format, 
            storage.public_format
        ) == serialized_public
        
    finally:
        os.unlink(temp_file_path)


def test_load_private_key_from_file_no_password():
    """Test loading key from file (auto-detect format) without password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    
    # Serialize and save to file
    serialized_private = storage.serialize_private_key(original_private_key)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file.write(serialized_private)
        temp_file_path = temp_file.name
    
    try:
        # Load the private key
        loaded_private_key = storage.load_private_key_from_file(temp_file_path)
        
        # Verify the loaded key matches the original
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == serialized_private
        
    finally:
        os.unlink(temp_file_path)


def test_load_private_key_from_file_with_string_password():
    """Test loading key from file (auto-detect format) with string password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    password = "test_password"
    
    # Serialize and save to file
    serialized_private = storage.serialize_private_key(original_private_key, password)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file.write(serialized_private)
        temp_file_path = temp_file.name
    
    try:
        # Load the private key
        loaded_private_key = storage.load_private_key_from_file(temp_file_path, password)
        
        # Verify the loaded key is functionally equivalent to the original
        # (we can't compare encrypted serializations directly as they're non-deterministic)
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == original_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        )
        
    finally:
        os.unlink(temp_file_path)


def test_load_private_key_from_file_with_bytes_password():
    """Test loading key from file (auto-detect format) with bytes password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    password = b"test_password"
    
    # Serialize and save to file
    serialized_private = storage.serialize_private_key(original_private_key, password)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file.write(serialized_private)
        temp_file_path = temp_file.name
    
    try:
        # Load the private key
        loaded_private_key = storage.load_private_key_from_file(temp_file_path, password)
        
        # Verify the loaded key is functionally equivalent to the original
        # (we can't compare encrypted serializations directly as they're non-deterministic)
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == original_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        )
        
    finally:
        os.unlink(temp_file_path)


def test_load_private_key_wrong_password():
    """Test loading private key with wrong password raises exception."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    password = "correct_password"
    wrong_password = "wrong_password"
    
    # Serialize and save to file
    serialized_private = storage.serialize_private_key(original_private_key, password)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file.write(serialized_private)
        temp_file_path = temp_file.name
    
    try:
        # This should raise an exception
        try:
            storage.load_private_key_from_file(temp_file_path, wrong_password)
            assert False, "Expected an exception for wrong password"
        except Exception as e:
            # Should be some kind of decryption error
            assert "decrypt" in str(e).lower() or "password" in str(e).lower() or "invalid" in str(e).lower()
        
    finally:
        os.unlink(temp_file_path)


def test_load_public_key_file_not_found():
    """Test loading public key from non-existent file raises exception."""
    storage = KeyStorage()
    
    try:
        storage.load_public_key_from_file("nonexistent_file.pem")
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass  # Expected


def test_load_private_key_file_not_found():
    """Test loading private key from non-existent file raises exception."""
    storage = KeyStorage()
    
    try:
        storage.load_private_key_from_file("nonexistent_file.pem")
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass  # Expected


def test_complete_roundtrip_no_password():
    """Test complete roundtrip: generate -> serialize -> save -> load -> verify."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    
    # Generate keys
    original_private_key, original_public_key = key_generator.generate()
    
    # Serialize keys
    serialized_private = storage.serialize_private_key(original_private_key)
    serialized_public = storage.serialize_public_key(original_public_key)
    
    # Save to files
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as private_file:
        private_file.write(serialized_private)
        private_file_path = private_file.name
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as public_file:
        public_file.write(serialized_public)
        public_file_path = public_file.name
    
    try:
        # Load keys back
        loaded_private_key = storage.load_private_key_from_file(private_file_path)
        loaded_public_key = storage.load_public_key_from_file(public_file_path)
        
        # Verify they match
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == serialized_private
        
        assert loaded_public_key.public_bytes(
            storage.encoding_format,
            storage.public_format
        ) == serialized_public
        
        # Verify the public keys are equivalent
        assert loaded_private_key.public_key().public_bytes(
            storage.encoding_format,
            storage.public_format
        ) == serialized_public
        
    finally:
        os.unlink(private_file_path)
        os.unlink(public_file_path)


def test_complete_roundtrip_with_password():
    """Test complete roundtrip with password protection."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    password = "secure_password"
    
    # Generate keys
    original_private_key, original_public_key = key_generator.generate()
    
    # Serialize keys
    serialized_private = storage.serialize_private_key(original_private_key, password)
    serialized_public = storage.serialize_public_key(original_public_key)
    
    # Save to files
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as private_file:
        private_file.write(serialized_private)
        private_file_path = private_file.name
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as public_file:
        public_file.write(serialized_public)
        public_file_path = public_file.name
    
    try:
        # Load keys back
        loaded_private_key = storage.load_private_key_from_file(private_file_path, password)
        loaded_public_key = storage.load_public_key_from_file(public_file_path)
        
        # Verify public key matches exactly
        assert loaded_public_key.public_bytes(
            storage.encoding_format,
            storage.public_format
        ) == serialized_public
        
        # Verify private key is functionally equivalent (encrypted serialization is non-deterministic)
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == original_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        )
        
        # Verify the public keys are equivalent
        assert loaded_private_key.public_key().public_bytes(
            storage.encoding_format,
            storage.public_format
        ) == serialized_public
        
    finally:
        os.unlink(private_file_path)
        os.unlink(public_file_path)


def test_different_encoding_formats():
    """Test KeyStorage with different encoding formats."""
    # Test DER encoding
    storage_der = KeyStorage(encoding_format=serialization.Encoding.DER)
    key_generator = EccKeyGenerator()
    private_key, public_key = key_generator.generate()
    
    # Serialize with DER
    serialized_private_der = storage_der.serialize_private_key(private_key)
    serialized_public_der = storage_der.serialize_public_key(public_key)
    
    # Verify DER format (should not contain PEM markers)
    assert b'BEGIN' not in serialized_private_der
    assert b'END' not in serialized_private_der
    assert b'BEGIN' not in serialized_public_der
    assert b'END' not in serialized_public_der
    
    # Verify they are bytes
    assert isinstance(serialized_private_der, bytes)
    assert isinstance(serialized_public_der, bytes)


def test_different_private_formats():
    """Test KeyStorage with different private key formats."""
    # Test TraditionalOpenSSL format
    storage_traditional = KeyStorage(private_format=serialization.PrivateFormat.TraditionalOpenSSL)
    key_generator = EccKeyGenerator()
    private_key, _ = key_generator.generate()
    
    # Serialize with TraditionalOpenSSL format
    serialized_private = storage_traditional.serialize_private_key(private_key)
    
    # Verify it contains the correct PEM markers
    assert b'BEGIN EC PRIVATE KEY' in serialized_private
    assert b'END EC PRIVATE KEY' in serialized_private


def test_different_public_formats():
    """Test KeyStorage with different public key formats."""
    # Test SubjectPublicKeyInfo format (default for ECC)
    storage_spki = KeyStorage(public_format=serialization.PublicFormat.SubjectPublicKeyInfo)
    key_generator = EccKeyGenerator()
    _, public_key = key_generator.generate()
    
    # Serialize with SubjectPublicKeyInfo format
    serialized_public = storage_spki.serialize_public_key(public_key)
    
    # Verify it contains the correct PEM markers
    assert b'BEGIN PUBLIC KEY' in serialized_public
    assert b'END PUBLIC KEY' in serialized_public
    
    # Verify it's bytes
    assert isinstance(serialized_public, bytes)


def test_save_public_key_to_file():
    """Test saving public key to file."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    _, original_public_key = key_generator.generate()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Save the public key to file
        storage.save_public_key_to_file(original_public_key, temp_file_path)
        
        # Verify file was created and contains the key
        assert os.path.exists(temp_file_path)
        
        # Load it back and verify it matches
        loaded_public_key = storage.load_public_key_from_file(temp_file_path)
        assert loaded_public_key.public_bytes(
            storage.encoding_format, 
            storage.public_format
        ) == original_public_key.public_bytes(
            storage.encoding_format, 
            storage.public_format
        )
        
    finally:
        os.unlink(temp_file_path)


def test_save_private_key_to_file():
    """Test saving private key to file."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Save the private key to file
        storage.save_private_key_to_file(original_private_key, temp_file_path)
        
        # Verify file was created and contains the key
        assert os.path.exists(temp_file_path)
        
        # Load it back and verify it matches
        loaded_private_key = storage.load_private_key_from_file(temp_file_path)
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == original_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        )
        
    finally:
        os.unlink(temp_file_path)


def test_save_private_key_to_file_with_password():
    """Test saving private key to file with password."""
    storage = KeyStorage()
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    password = "test_password"
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Save the private key to file with password
        storage.save_private_key_to_file(original_private_key, temp_file_path, password)
        
        # Verify file was created and contains the key
        assert os.path.exists(temp_file_path)
        
        # Load it back and verify it matches
        loaded_private_key = storage.load_private_key_from_file(temp_file_path, password)
        assert loaded_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        ) == original_private_key.private_bytes(
            storage.encoding_format,
            storage.private_format,
            serialization.NoEncryption()
        )
        
    finally:
        os.unlink(temp_file_path)


def test_load_public_key_from_der_file():
    """Test loading public key from DER file."""
    storage_der = KeyStorage(encoding_format=serialization.Encoding.DER)
    storage = KeyStorage()  # Default PEM storage for loading
    key_generator = EccKeyGenerator()
    _, original_public_key = key_generator.generate()
    
    # Serialize with DER format
    serialized_public = storage_der.serialize_public_key(original_public_key)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.der') as temp_file:
        temp_file.write(serialized_public)
        temp_file_path = temp_file.name
    
    try:
        # Load using generic method (should auto-detect DER)
        loaded_public_key = storage.load_public_key_from_file(temp_file_path)
        
        # Verify the loaded key matches the original
        assert loaded_public_key.public_bytes(
            storage_der.encoding_format,
            storage_der.public_format
        ) == serialized_public
        
    finally:
        os.unlink(temp_file_path)


def test_load_private_key_from_der_file():
    """Test loading private key from DER file."""
    storage_der = KeyStorage(encoding_format=serialization.Encoding.DER)
    storage = KeyStorage()  # Default PEM storage for loading
    key_generator = EccKeyGenerator()
    original_private_key, _ = key_generator.generate()
    
    # Serialize with DER format
    serialized_private = storage_der.serialize_private_key(original_private_key)
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.der') as temp_file:
        temp_file.write(serialized_private)
        temp_file_path = temp_file.name
    
    try:
        # Load using generic method (should auto-detect DER)
        loaded_private_key = storage.load_private_key_from_file(temp_file_path)
        
        # Verify the loaded key matches the original
        assert loaded_private_key.private_bytes(
            storage_der.encoding_format,
            storage_der.private_format,
            serialization.NoEncryption()
        ) == serialized_private
        
    finally:
        os.unlink(temp_file_path)
