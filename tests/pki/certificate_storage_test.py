import os
import tempfile
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.pki.certificate_generator.self_signed_certificate_generator import SelfSignedCertificateGenerator
from digital_signatures.pki.certificate_generator.root_certificate_generator import RootCertificateGenerator
from digital_signatures.pki.certificate_generator.intermediate_certificate_generator import IntermediateCertificateGenerator
from digital_signatures.pki.certificate_generator.end_entity_certificate_generator import EndEntityCertificateGenerator
from digital_signatures.pki.certificate_storage import CertificateStorage
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher


class TestCertificateStorage:
    """Test cases for the CertificateStorage class."""

    def test_certificate_storage_initialization_default(self):
        """Test CertificateStorage initialization with default parameters."""
        storage = CertificateStorage()
        assert storage.encoding_format == serialization.Encoding.PEM

    def test_certificate_storage_initialization_custom(self):
        """Test CertificateStorage initialization with custom parameters."""
        storage = CertificateStorage(encoding_format=serialization.Encoding.DER)
        assert storage.encoding_format == serialization.Encoding.DER

    def test_serialize_certificate_pem(self):
        """Test certificate serialization in PEM format."""
        storage = CertificateStorage(encoding_format=serialization.Encoding.PEM)
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        private_key, public_key, certificate = generator.generate(entity)
        
        serialized = storage.serialize_certificate(certificate)
        
        assert isinstance(serialized, bytes)
        assert b'BEGIN CERTIFICATE' in serialized
        assert b'END CERTIFICATE' in serialized

    def test_serialize_certificate_der(self):
        """Test certificate serialization in DER format."""
        storage = CertificateStorage(encoding_format=serialization.Encoding.DER)
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        private_key, public_key, certificate = generator.generate(entity)
        
        serialized = storage.serialize_certificate(certificate)
        
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        # DER is binary format, so no text markers
        assert b'BEGIN CERTIFICATE' not in serialized

    def test_save_and_load_certificate_pem(self):
        """Test saving and loading certificate in PEM format."""
        storage = CertificateStorage(encoding_format=serialization.Encoding.PEM)
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        original_private_key, original_public_key, original_certificate = generator.generate(entity)
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            # Save certificate to file
            storage.save_certificate_to_file(original_certificate, temp_file_path)
            
            # Verify file was created
            assert os.path.exists(temp_file_path)
            
            # Load certificate back
            loaded_certificate = storage.load_certificate_from_file(temp_file_path)
            
            # Verify certificates match
            assert loaded_certificate.public_bytes(serialization.Encoding.PEM) == \
                   original_certificate.public_bytes(serialization.Encoding.PEM)
            assert loaded_certificate.subject == original_certificate.subject
            assert loaded_certificate.issuer == original_certificate.issuer
            assert loaded_certificate.serial_number == original_certificate.serial_number
            
        finally:
            os.unlink(temp_file_path)

    def test_save_and_load_certificate_der(self):
        """Test saving and loading certificate in DER format."""
        storage = CertificateStorage(encoding_format=serialization.Encoding.DER)
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        original_private_key, original_public_key, original_certificate = generator.generate(entity)
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.der') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            # Save certificate to file
            storage.save_certificate_to_file(original_certificate, temp_file_path)
            
            # Verify file was created
            assert os.path.exists(temp_file_path)
            
            # Load certificate back
            loaded_certificate = storage.load_certificate_from_file(temp_file_path)
            
            # Verify certificates match
            assert loaded_certificate.public_bytes(serialization.Encoding.DER) == \
                   original_certificate.public_bytes(serialization.Encoding.DER)
            assert loaded_certificate.subject == original_certificate.subject
            assert loaded_certificate.issuer == original_certificate.issuer
            assert loaded_certificate.serial_number == original_certificate.serial_number
            
        finally:
            os.unlink(temp_file_path)

    def test_save_and_load_certificate_chain(self):
        """Test saving and loading certificate chains."""
        storage = CertificateStorage(encoding_format=serialization.Encoding.PEM)
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        # Create a certificate chain: Root -> Intermediate -> End Entity
        # Root CA
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Intermediate CA
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # End Entity
        ee_generator = EndEntityCertificateGenerator(key_generator, hasher)
        ee_entity = Entity("End Entity", "ee@example.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        ee_private_key, ee_public_key, ee_certificate = ee_generator.generate(
            ee_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Certificate chain (end entity first)
        certificate_chain = [ee_certificate, intermediate_certificate, root_certificate]
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            # Save certificate chain to file
            storage.save_certificate_chain_to_pem_file(certificate_chain, temp_file_path)
            
            # Verify file was created
            assert os.path.exists(temp_file_path)
            
            # Load certificate chain back
            loaded_chain = storage.load_certificate_chain_from_pem_file(temp_file_path)
            
            # Verify chain length
            assert len(loaded_chain) == 3
            
            # Verify certificates match (order should be preserved)
            for original, loaded in zip(certificate_chain, loaded_chain):
                assert loaded.public_bytes(serialization.Encoding.PEM) == \
                       original.public_bytes(serialization.Encoding.PEM)
                assert loaded.subject == original.subject
                assert loaded.issuer == original.issuer
                assert loaded.serial_number == original.serial_number
            
        finally:
            os.unlink(temp_file_path)

    def test_save_certificate_chain_empty_list(self):
        """Test that saving an empty certificate chain raises an error."""
        storage = CertificateStorage()
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            with pytest.raises(ValueError, match="Certificate chain cannot be empty"):
                storage.save_certificate_chain_to_pem_file([], temp_file_path)
        finally:
            os.unlink(temp_file_path)

    def test_load_certificate_invalid_format(self):
        """Test loading certificate with invalid format."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
            temp_file.write(b"invalid certificate data")
            temp_file_path = temp_file.name
        
        try:
            with pytest.raises(ValueError, match="Invalid certificate file format"):
                CertificateStorage.load_certificate_from_file(temp_file_path)
        finally:
            os.unlink(temp_file_path)

    def test_load_certificate_file_not_found(self):
        """Test loading certificate from non-existent file."""
        with pytest.raises(FileNotFoundError):
            CertificateStorage.load_certificate_from_file("non_existent_file.pem")

    def test_load_certificate_chain_invalid_format(self):
        """Test loading certificate chain with invalid format."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
            temp_file.write(b"invalid certificate chain data")
            temp_file_path = temp_file.name
        
        try:
            with pytest.raises(ValueError, match="No certificates found in file"):
                CertificateStorage.load_certificate_chain_from_pem_file(temp_file_path)
        finally:
            os.unlink(temp_file_path)

    def test_load_certificate_chain_empty_file(self):
        """Test loading certificate chain from empty file."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
            temp_file_path = temp_file.name
        
        try:
            with pytest.raises(ValueError, match="No certificates found in file"):
                CertificateStorage.load_certificate_chain_from_pem_file(temp_file_path)
        finally:
            os.unlink(temp_file_path)

    def test_create_pkcs12_bundle_no_password(self):
        """Test creating PKCS#12 bundle without password."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        private_key, public_key, certificate = generator.generate(entity)
        
        bundle = storage.create_pkcs12_bundle(private_key, certificate)
        
        assert isinstance(bundle, bytes)
        assert len(bundle) > 0

    def test_create_pkcs12_bundle_with_password(self):
        """Test creating PKCS#12 bundle with password."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        private_key, public_key, certificate = generator.generate(entity)
        
        password = "test_password"
        bundle = storage.create_pkcs12_bundle(private_key, certificate, password=password)
        
        assert isinstance(bundle, bytes)
        assert len(bundle) > 0

    def test_create_pkcs12_bundle_with_ca_certificates(self):
        """Test creating PKCS#12 bundle with CA certificates."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        # Create CA certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Create end entity certificate
        ee_generator = SelfSignedCertificateGenerator(key_generator, hasher)
        ee_entity = Entity("End Entity", "ee@example.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        ee_private_key, ee_public_key, ee_certificate = ee_generator.generate(ee_entity)
        
        bundle = storage.create_pkcs12_bundle(
            ee_private_key, 
            ee_certificate, 
            ca_certificates=[root_certificate]
        )
        
        assert isinstance(bundle, bytes)
        assert len(bundle) > 0

    def test_save_and_load_pkcs12_bundle(self):
        """Test saving and loading PKCS#12 bundle."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        original_private_key, original_public_key, original_certificate = generator.generate(entity)
        
        password = "test_password"
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.p12') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            # Save PKCS#12 bundle to file
            storage.save_pkcs12_bundle_to_file(
                original_private_key, 
                original_certificate, 
                temp_file_path, 
                password=password
            )
            
            # Verify file was created
            assert os.path.exists(temp_file_path)
            
            # Load PKCS#12 bundle back
            loaded_private_key, loaded_certificate, loaded_ca_certificates = \
                storage.load_pkcs12_bundle_from_file(temp_file_path, password)
            
            # Verify private key matches
            assert loaded_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ) == original_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            
            # Verify certificate matches
            assert loaded_certificate.public_bytes(serialization.Encoding.PEM) == \
                   original_certificate.public_bytes(serialization.Encoding.PEM)
            
            # No CA certificates in this test
            assert loaded_ca_certificates is None or len(loaded_ca_certificates) == 0
            
        finally:
            os.unlink(temp_file_path)

    def test_save_and_load_pkcs12_bundle_with_ca_certificates(self):
        """Test saving and loading PKCS#12 bundle with CA certificates."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        # Create CA certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Create end entity certificate
        ee_generator = SelfSignedCertificateGenerator(key_generator, hasher)
        ee_entity = Entity("End Entity", "ee@example.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        ee_private_key, ee_public_key, ee_certificate = ee_generator.generate(ee_entity)
        
        password = "test_password"
        ca_certificates = [root_certificate]
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.p12') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            # Save PKCS#12 bundle to file
            storage.save_pkcs12_bundle_to_file(
                ee_private_key, 
                ee_certificate, 
                temp_file_path, 
                ca_certificates=ca_certificates,
                password=password
            )
            
            # Verify file was created
            assert os.path.exists(temp_file_path)
            
            # Load PKCS#12 bundle back
            loaded_private_key, loaded_certificate, loaded_ca_certificates = \
                storage.load_pkcs12_bundle_from_file(temp_file_path, password)
            
            # Verify certificate matches
            assert loaded_certificate.public_bytes(serialization.Encoding.PEM) == \
                   ee_certificate.public_bytes(serialization.Encoding.PEM)
            
            # Verify CA certificates
            assert loaded_ca_certificates is not None
            assert len(loaded_ca_certificates) == 1
            assert loaded_ca_certificates[0].public_bytes(serialization.Encoding.PEM) == \
                   root_certificate.public_bytes(serialization.Encoding.PEM)
            
        finally:
            os.unlink(temp_file_path)

    def test_load_pkcs12_bundle_invalid_password(self):
        """Test loading PKCS#12 bundle with invalid password."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity("Test Entity", "test@example.com", "US", "CA", "SF", "Test Org", "Test Unit")
        private_key, public_key, certificate = generator.generate(entity)
        
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.p12') as temp_file:
            temp_file_path = temp_file.name
        
        try:
            # Save PKCS#12 bundle to file
            storage.save_pkcs12_bundle_to_file(
                private_key, 
                certificate, 
                temp_file_path, 
                password=correct_password
            )
            
            # Try to load with wrong password
            with pytest.raises(ValueError, match="Failed to load PKCS#12 bundle"):
                storage.load_pkcs12_bundle_from_file(temp_file_path, wrong_password)
            
        finally:
            os.unlink(temp_file_path)

    def test_complete_roundtrip_with_chain(self):
        """Test complete roundtrip with certificate chain storage."""
        storage = CertificateStorage()
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        # Create a complete certificate chain
        # Root CA
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Intermediate CA
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # End Entity
        ee_generator = EndEntityCertificateGenerator(key_generator, hasher)
        ee_entity = Entity("End Entity", "ee@example.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        ee_private_key, ee_public_key, ee_certificate = ee_generator.generate(
            ee_entity, intermediate_certificate, intermediate_private_key
        )
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save individual certificates
            root_cert_path = os.path.join(temp_dir, "root.pem")
            intermediate_cert_path = os.path.join(temp_dir, "intermediate.pem")
            ee_cert_path = os.path.join(temp_dir, "ee.pem")
            
            storage.save_certificate_to_file(root_certificate, root_cert_path)
            storage.save_certificate_to_file(intermediate_certificate, intermediate_cert_path)
            storage.save_certificate_to_file(ee_certificate, ee_cert_path)
            
            # Save certificate chain
            chain_path = os.path.join(temp_dir, "chain.pem")
            certificate_chain = [ee_certificate, intermediate_certificate, root_certificate]
            storage.save_certificate_chain_to_pem_file(certificate_chain, chain_path)
            
            # Save PKCS#12 bundle
            p12_path = os.path.join(temp_dir, "bundle.p12")
            password = "bundle_password"
            storage.save_pkcs12_bundle_to_file(
                ee_private_key,
                ee_certificate,
                p12_path,
                ca_certificates=[intermediate_certificate, root_certificate],
                password=password
            )
            
            # Load and verify individual certificates
            loaded_root = storage.load_certificate_from_file(root_cert_path)
            loaded_intermediate = storage.load_certificate_from_file(intermediate_cert_path)
            loaded_ee = storage.load_certificate_from_file(ee_cert_path)
            
            assert loaded_root.subject == root_certificate.subject
            assert loaded_intermediate.subject == intermediate_certificate.subject
            assert loaded_ee.subject == ee_certificate.subject
            
            # Load and verify certificate chain
            loaded_chain = storage.load_certificate_chain_from_pem_file(chain_path)
            assert len(loaded_chain) == 3
            assert loaded_chain[0].subject == ee_certificate.subject
            assert loaded_chain[1].subject == intermediate_certificate.subject
            assert loaded_chain[2].subject == root_certificate.subject
            
            # Load and verify PKCS#12 bundle
            loaded_key, loaded_cert, loaded_cas = storage.load_pkcs12_bundle_from_file(p12_path, password)
            assert loaded_cert.subject == ee_certificate.subject
            assert loaded_cas is not None
            assert len(loaded_cas) == 2
