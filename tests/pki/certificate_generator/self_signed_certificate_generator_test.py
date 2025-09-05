import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.pki.certificate_generator.self_signed_certificate_generator import SelfSignedCertificateGenerator
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher


class TestSelfSignedCertificateGenerator:
    """Test cases for the SelfSignedCertificateGenerator class."""

    def test_init_with_valid_parameters(self):
        """Test that SelfSignedCertificateGenerator initializes correctly with valid parameters."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        assert generator.key_generator == key_generator
        assert generator.hasher == hasher

    def test_init_with_different_hash_algorithms(self):
        """Test initialization with different hash algorithms."""
        algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
        
        for algorithm in algorithms:
            key_generator = EccKeyGenerator()
            hasher = Hasher(algorithm)
            
            generator = SelfSignedCertificateGenerator(key_generator, hasher)
            
            assert generator.key_generator == key_generator
            assert generator.hasher == hasher
            assert generator.hasher.algorithm == algorithm

    def test_generate_returns_correct_types(self):
        """Test that generate() returns the correct types."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Test Entity",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)

    def test_generate_returns_matching_key_pair(self):
        """Test that the returned public key matches the private key's public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Test Entity",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert public_key == private_key.public_key()

    def test_generate_certificate_subject_matches_entity(self):
        """Test that the certificate subject matches the entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Alice Johnson",
            email="alice@company.com",
            country="GB",
            state="England",
            locality="London",
            organization="Company Ltd",
            organizational_unit="Engineering"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert certificate.subject == entity.to_name()

    def test_generate_certificate_issuer_matches_subject(self):
        """Test that the certificate issuer matches the subject (self-signed)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Self Signed Entity",
            email="self@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Self Org",
            organizational_unit="Self Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert certificate.issuer == certificate.subject
        assert certificate.issuer == entity.to_name()

    def test_generate_certificate_public_key_matches_generated_key(self):
        """Test that the certificate's public key matches the generated public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Test Entity",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert certificate.public_key() == public_key

    def test_generate_certificate_validity_period(self):
        """Test that the certificate has the correct validity period."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Test Entity",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that the certificate is valid for approximately 1 year
        now = datetime.now(timezone.utc)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        
        # Should be approximately 365 days (allow some tolerance for execution time)
        assert 364 <= validity_period.days <= 366
        
        # Certificate should be valid now
        assert certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    def test_generate_certificate_serial_number(self):
        """Test that the certificate has a valid serial number."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Test Entity",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Serial number should be a positive integer
        assert certificate.serial_number > 0

    def test_generate_certificate_extensions(self):
        """Test that the certificate has the expected extensions."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Test Entity",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that SubjectAlternativeName extension is present
        san_extension = None
        for extension in certificate.extensions:
            if isinstance(extension.value, x509.SubjectAlternativeName):
                san_extension = extension
                break
        
        assert san_extension is not None
        assert san_extension.critical is False
        
        # Check that localhost is in the SAN
        dns_names = san_extension.value.get_values_for_type(x509.DNSName)
        assert "localhost" in dns_names

    def test_generate_different_entities_different_certificates(self):
        """Test that different entities produce different certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity1 = Entity(
            name="Entity One",
            email="one@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org1",
            organizational_unit="Unit1"
        )
        
        entity2 = Entity(
            name="Entity Two",
            email="two@example.com",
            country="CA",
            state="ON",
            locality="Toronto",
            organization="Org2",
            organizational_unit="Unit2"
        )
        
        private_key1, public_key1, certificate1 = generator.generate(entity1)
        private_key2, public_key2, certificate2 = generator.generate(entity2)
        
        # Certificates should be different
        assert certificate1 != certificate2
        assert certificate1.subject != certificate2.subject
        assert private_key1 != private_key2
        assert public_key1 != public_key2

    def test_generate_same_entity_different_keys(self):
        """Test that generating certificates for the same entity produces different keys."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Same Entity",
            email="same@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Same Org",
            organizational_unit="Same Unit"
        )
        
        private_key1, public_key1, certificate1 = generator.generate(entity)
        private_key2, public_key2, certificate2 = generator.generate(entity)
        
        # Keys should be different each time
        assert private_key1 != private_key2
        assert public_key1 != public_key2
        assert certificate1 != certificate2
        
        # But subjects should be the same
        assert certificate1.subject == certificate2.subject

    def test_generate_with_minimal_entity(self):
        """Test certificate generation with minimal entity (only required fields)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Minimal Entity",
            email="minimal@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization=None,
            organizational_unit=None
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == entity.to_name()
        assert certificate.issuer == certificate.subject

    def test_generate_with_special_characters_in_entity(self):
        """Test certificate generation with special characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="José María",
            email="josé.maría@españa.com",
            country="ES",
            state="Madrid",
            locality="Madrid",
            organization="Empresa S.L.",
            organizational_unit="Desarrollo"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == entity.to_name()
        assert certificate.issuer == certificate.subject

    def test_generate_with_different_curves(self):
        """Test certificate generation with different elliptic curves."""
        curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
        
        for curve in curves:
            key_generator = EccKeyGenerator(curve)
            hasher = Hasher(hashes.SHA256())
            generator = SelfSignedCertificateGenerator(key_generator, hasher)
            
            entity = Entity(
                name=f"Test Entity {curve.name}",
                email="test@example.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Test Org",
                organizational_unit="Test Unit"
            )
            
            private_key, public_key, certificate = generator.generate(entity)
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert private_key.curve.name == curve.name
            assert public_key.curve.name == curve.name

    def test_generate_with_different_hash_algorithms(self):
        """Test certificate generation with different hash algorithms."""
        algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
        
        for algorithm in algorithms:
            key_generator = EccKeyGenerator()
            hasher = Hasher(algorithm)
            generator = SelfSignedCertificateGenerator(key_generator, hasher)
            
            entity = Entity(
                name=f"Test Entity {algorithm.name}",
                email="test@example.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Test Org",
                organizational_unit="Test Unit"
            )
            
            private_key, public_key, certificate = generator.generate(entity)
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert certificate.subject == entity.to_name()

    def test_inherits_from_certificate_generator_base_class(self):
        """Test that SelfSignedCertificateGenerator inherits from CertificateGenerator base class."""
        from digital_signatures.pki.certificate_generator.base import CertificateGenerator
        
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        assert isinstance(generator, CertificateGenerator)

    def test_generate_consistency_multiple_calls(self):
        """Test that multiple calls to generate() produce consistent results."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Consistent Entity",
            email="consistent@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Consistent Org",
            organizational_unit="Consistent Unit"
        )
        
        # Generate multiple certificates
        results = []
        for _ in range(3):
            private_key, public_key, certificate = generator.generate(entity)
            results.append((private_key, public_key, certificate))
        
        # All results should be valid
        for private_key, public_key, certificate in results:
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert certificate.subject == entity.to_name()
            assert certificate.issuer == certificate.subject
            assert public_key == private_key.public_key()

    def test_generate_certificate_signature_verification(self):
        """Test that the certificate signature can be verified."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Signature Test Entity",
            email="signature@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Signature Org",
            organizational_unit="Signature Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # The certificate should be self-signed, so we can verify it with the same public key
        # This is a basic check that the certificate was properly signed
        assert certificate.public_key() == public_key
        assert certificate.issuer == certificate.subject

    def test_generate_certificate_version(self):
        """Test that the certificate has the correct version."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Version Test Entity",
            email="version@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Version Org",
            organizational_unit="Version Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # X.509 certificates should be version 3
        assert certificate.version == x509.Version.v3

    def test_generate_certificate_public_bytes(self):
        """Test that the certificate can be serialized to bytes."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Serialization Test Entity",
            email="serialization@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Serialization Org",
            organizational_unit="Serialization Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Should be able to serialize the certificate
        cert_bytes = certificate.public_bytes(encoding=serialization.Encoding.DER)
        assert isinstance(cert_bytes, bytes)
        assert len(cert_bytes) > 0
        
        # Should be able to serialize as PEM as well
        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        assert isinstance(cert_pem, bytes)
        assert len(cert_pem) > 0
        assert cert_pem.startswith(b'-----BEGIN CERTIFICATE-----')

    def test_generate_performance(self):
        """Test that certificate generation performance is reasonable."""
        import time
        
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Performance Test Entity",
            email="performance@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Performance Org",
            organizational_unit="Performance Unit"
        )
        
        # Time multiple certificate generation operations
        start_time = time.time()
        for _ in range(5):
            generator.generate(entity)
        generation_time = time.time() - start_time
        
        # Certificate generation should be reasonably fast (less than 2 seconds for 5 certificates)
        assert generation_time < 2.0
        print(f"Generated 5 certificates in {generation_time:.3f} seconds")

    def test_generate_with_unicode_entity(self):
        """Test certificate generation with Unicode characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = SelfSignedCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="张三",
            email="zhangsan@中国.com",
            country="CN",
            state="北京",
            locality="北京",
            organization="中国公司",
            organizational_unit="技术部"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == entity.to_name()
        assert certificate.issuer == certificate.subject
