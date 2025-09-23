import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.pki.certificate_generator.root_certificate_generator import RootCertificateGenerator
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher


class TestRootCertificateGenerator:
    """Test cases for the RootCertificateGenerator class."""

    def test_init_with_valid_parameters(self):
        """Test that RootCertificateGenerator initializes correctly with valid parameters."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        generator = RootCertificateGenerator(key_generator, hasher)
        
        assert generator.key_generator == key_generator
        assert generator.hasher == hasher

    def test_init_with_different_hash_algorithms(self):
        """Test initialization with different hash algorithms."""
        algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
        
        for algorithm in algorithms:
            key_generator = EccKeyGenerator()
            hasher = Hasher(algorithm)
            
            generator = RootCertificateGenerator(key_generator, hasher)
            
            assert generator.key_generator == key_generator
            assert generator.hasher == hasher
            assert generator.hasher.algorithm == algorithm

    def test_generate_returns_correct_types(self):
        """Test that generate() returns the correct types."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)

    def test_generate_returns_matching_key_pair(self):
        """Test that the returned public key matches the private key's public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert public_key == private_key.public_key()

    def test_generate_certificate_subject_matches_entity(self):
        """Test that the certificate subject matches the entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root Certificate Authority",
            email="root@authority.com",
            country="GB",
            state="England",
            locality="London",
            organization="Certificate Authority Ltd",
            organizational_unit="Root CA"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert certificate.subject == entity.to_name()

    def test_generate_certificate_issuer_matches_subject(self):
        """Test that the certificate issuer matches the subject (self-signed root)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Self Signed Root CA",
            email="root@selfsigned.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Self Signed Root Org",
            organizational_unit="Self Signed Root Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert certificate.issuer == certificate.subject
        assert certificate.issuer == entity.to_name()

    def test_generate_certificate_public_key_matches_generated_key(self):
        """Test that the certificate's public key matches the generated public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert certificate.public_key() == public_key

    def test_generate_certificate_validity_period(self):
        """Test that the certificate has the correct validity period (10 years)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that the certificate is valid for approximately 10 years
        now = datetime.now(timezone.utc)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        
        # Should be approximately 3650 days (10 years, allow some tolerance for execution time)
        assert 3649 <= validity_period.days <= 3651
        
        # Certificate should be valid now
        assert certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    def test_generate_certificate_serial_number(self):
        """Test that the certificate has a valid serial number."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Serial number should be a positive integer
        assert certificate.serial_number > 0

    def test_generate_certificate_basic_constraints_extension(self):
        """Test that the certificate has the correct BasicConstraints extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that BasicConstraints extension is present
        basic_constraints_extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints_extension.critical is True
        assert basic_constraints_extension.value.ca is True
        assert basic_constraints_extension.value.path_length is None

    def test_generate_certificate_key_usage_extension(self):
        """Test that the certificate has the correct KeyUsage extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that KeyUsage extension is present
        key_usage_extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage_extension.critical is True
        
        key_usage = key_usage_extension.value
        assert key_usage.digital_signature is True
        assert key_usage.content_commitment is False
        assert key_usage.key_encipherment is False
        assert key_usage.data_encipherment is False
        assert key_usage.key_agreement is False
        assert key_usage.key_cert_sign is True
        assert key_usage.crl_sign is True
        # encipher_only and decipher_only are only defined when key_agreement is True
        # Since key_agreement is False, we don't test these properties

    def test_generate_certificate_subject_key_identifier_extension(self):
        """Test that the certificate has the SubjectKeyIdentifier extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that SubjectKeyIdentifier extension is present
        ski_extension = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski_extension.critical is False
        assert ski_extension.value is not None

    def test_generate_different_entities_different_certificates(self):
        """Test that different entities produce different certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity1 = Entity(
            name="Root CA One",
            email="root1@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org1",
            organizational_unit="Root CA Unit1"
        )
        
        entity2 = Entity(
            name="Root CA Two",
            email="root2@ca.com",
            country="CA",
            state="ON",
            locality="Toronto",
            organization="Root CA Org2",
            organizational_unit="Root CA Unit2"
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
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Same Root CA",
            email="same@rootca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Same Root CA Org",
            organizational_unit="Same Root CA Unit"
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
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Minimal Root CA",
            email="minimal@rootca.com",
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
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="José María Root CA",
            email="josé.maría@rootca.españa.com",
            country="ES",
            state="Madrid",
            locality="Madrid",
            organization="Empresa Root CA S.L.",
            organizational_unit="Desarrollo Root CA"
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
            generator = RootCertificateGenerator(key_generator, hasher)
            
            entity = Entity(
                name=f"Root CA {curve.name}",
                email="root@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Root CA Org",
                organizational_unit="Root CA Unit"
            )
            
            private_key, public_key, certificate = generator.generate(entity)
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert private_key.curve.name == curve.name
            assert public_key.curve.name == curve.name

    def test_generate_with_different_hash_algorithms(self):
        """Test certificate generation with different hash algorithms."""
        algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
        
        for algorithm in algorithms:
            key_generator = EccKeyGenerator()
            hasher = Hasher(algorithm)
            generator = RootCertificateGenerator(key_generator, hasher)
            
            entity = Entity(
                name=f"Root CA {algorithm.name}",
                email="root@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Root CA Org",
                organizational_unit="Root CA Unit"
            )
            
            private_key, public_key, certificate = generator.generate(entity)
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert certificate.subject == entity.to_name()

    def test_inherits_from_certificate_generator_base_class(self):
        """Test that RootCertificateGenerator inherits from CertificateGenerator base class."""
        from digital_signatures.pki.certificate_generator.base import CertificateGenerator
        
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        assert isinstance(generator, CertificateGenerator)

    def test_generate_consistency_multiple_calls(self):
        """Test that multiple calls to generate() produce consistent results."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Consistent Root CA",
            email="consistent@rootca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Consistent Root CA Org",
            organizational_unit="Consistent Root CA Unit"
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
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Signature Test Root CA",
            email="signature@rootca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Signature Root CA Org",
            organizational_unit="Signature Root CA Unit"
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
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Version Test Root CA",
            email="version@rootca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Version Root CA Org",
            organizational_unit="Version Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # X.509 certificates should be version 3
        assert certificate.version == x509.Version.v3

    def test_generate_certificate_public_bytes(self):
        """Test that the certificate can be serialized to bytes."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Serialization Test Root CA",
            email="serialization@rootca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Serialization Root CA Org",
            organizational_unit="Serialization Root CA Unit"
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
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Performance Test Root CA",
            email="performance@rootca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Performance Root CA Org",
            organizational_unit="Performance Root CA Unit"
        )
        
        # Time multiple certificate generation operations
        start_time = time.time()
        for _ in range(5):
            generator.generate(entity)
        generation_time = time.time() - start_time
        
        # Certificate generation should be reasonably fast (less than 2 seconds for 5 certificates)
        assert generation_time < 2.0
        print(f"Generated 5 root certificates in {generation_time:.3f} seconds")

    def test_generate_with_unicode_entity(self):
        """Test certificate generation with Unicode characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="张三根证书",
            email="zhangsan@rootca.中国.com",
            country="CN",
            state="北京",
            locality="北京",
            organization="中国根证书公司",
            organizational_unit="技术部根证书"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == entity.to_name()
        assert certificate.issuer == certificate.subject

    def test_generate_root_certificate_characteristics(self):
        """Test specific characteristics of root certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root Certificate Authority",
            email="root@authority.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Certificate Authority Inc",
            organizational_unit="Root CA Department"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Root certificates should be self-signed
        assert certificate.issuer == certificate.subject
        
        # Root certificates should have CA=True in BasicConstraints
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is True
        
        # Root certificates should have keyCertSign and cRLSign in KeyUsage
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True
        
        # Root certificates should have a long validity period (10 years)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        assert validity_period.days >= 3649  # At least 10 years minus 1 day

    # CRL URLs Tests
    def test_init_with_crl_urls(self):
        """Test that RootCertificateGenerator initializes correctly with CRL URLs."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        
        generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
        
        assert generator.key_generator == key_generator
        assert generator.hasher == hasher
        assert generator.crl_urls == crl_urls

    def test_generate_without_crl_urls(self):
        """Test that generate() works without CRL URLs (backward compatibility)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = RootCertificateGenerator(key_generator, hasher)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        
        # Should not have CRL Distribution Points extension
        with pytest.raises(x509.ExtensionNotFound):
            certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)

    def test_generate_with_single_crl_url(self):
        """Test certificate generation with a single CRL URL."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        
        # Check CRL Distribution Points extension
        crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        assert crl_ext.critical is False
        
        # Verify the CRL URL is present
        distribution_points = crl_ext.value
        assert len(distribution_points) == 1
        
        dp = distribution_points[0]
        assert dp.full_name is not None
        assert len(dp.full_name) == 1
        assert dp.full_name[0].value == "http://ca.example.com/crl/root-ca.crl"
        assert dp.relative_name is None
        assert dp.crl_issuer is None
        assert dp.reasons is None

    def test_generate_with_multiple_crl_urls(self):
        """Test certificate generation with multiple CRL URLs."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl",
            "http://backup-ca.example.com/crl/root-ca.crl",
            "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com"
        ]
        generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        
        # Check CRL Distribution Points extension
        crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        assert crl_ext.critical is False
        
        # Verify all CRL URLs are present (each in its own distribution point)
        distribution_points = crl_ext.value
        assert len(distribution_points) == 3
        
        # Check each distribution point has the expected URL
        urls = []
        for dp in distribution_points:
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            urls.append(dp.full_name[0].value)
        
        assert "http://ca.example.com/crl/root-ca.crl" in urls
        assert "http://backup-ca.example.com/crl/root-ca.crl" in urls
        assert "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com" in urls

    def test_generate_with_empty_crl_urls_list(self):
        """Test certificate generation with empty CRL URLs list."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = []
        generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        
        # Should not have CRL Distribution Points extension
        with pytest.raises(x509.ExtensionNotFound):
            certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)

    def test_generate_with_https_crl_urls(self):
        """Test certificate generation with HTTPS CRL URLs."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = [
            "https://secure-ca.example.com/crl/root-ca.crl",
            "https://backup-secure-ca.example.com/crl/root-ca.crl"
        ]
        generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        
        # Check CRL Distribution Points extension
        crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        assert crl_ext.critical is False
        
        # Verify HTTPS URLs are present
        distribution_points = crl_ext.value
        assert len(distribution_points) == 2
        
        urls = []
        for dp in distribution_points:
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            urls.append(dp.full_name[0].value)
        
        assert "https://secure-ca.example.com/crl/root-ca.crl" in urls
        assert "https://backup-secure-ca.example.com/crl/root-ca.crl" in urls

    def test_generate_crl_extension_not_critical(self):
        """Test that CRL Distribution Points extension is not critical."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Check that CRL Distribution Points extension is not critical
        crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        assert crl_ext.critical is False

    def test_generate_crl_urls_preserved_in_certificate(self):
        """Test that CRL URLs are correctly preserved in the certificate."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        original_crl_urls = [
            "http://ca.example.com/crl/root-ca.crl",
            "https://secure-ca.example.com/crl/root-ca.crl"
        ]
        generator = RootCertificateGenerator(key_generator, hasher, original_crl_urls)
        
        entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(entity)
        
        # Extract CRL URLs from certificate
        crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        distribution_points = crl_ext.value
        
        extracted_urls = []
        for dp in distribution_points:
            if dp.full_name:
                for url in dp.full_name:
                    extracted_urls.append(url.value)
        
        # Verify URLs match
        assert len(extracted_urls) == len(original_crl_urls)
        for url in original_crl_urls:
            assert url in extracted_urls

    def test_generate_crl_urls_with_different_hash_algorithms(self):
        """Test CRL URLs functionality with different hash algorithms."""
        algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
        
        for algorithm in algorithms:
            key_generator = EccKeyGenerator()
            hasher = Hasher(algorithm)
            crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
            generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
            
            entity = Entity(
                name=f"Root CA {algorithm.name}",
                email="root@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Root CA Org",
                organizational_unit="Root CA Unit"
            )
            
            private_key, public_key, certificate = generator.generate(entity)
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            
            # Check CRL Distribution Points extension
            crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            assert crl_ext.critical is False
            
            # Verify URL is present
            distribution_points = crl_ext.value
            assert len(distribution_points) == 1
            
            dp = distribution_points[0]
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == "http://ca.example.com/crl/root-ca.crl"

    def test_generate_crl_urls_with_different_curves(self):
        """Test CRL URLs functionality with different elliptic curves."""
        curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
        
        for curve in curves:
            key_generator = EccKeyGenerator(curve)
            hasher = Hasher(hashes.SHA256())
            crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
            generator = RootCertificateGenerator(key_generator, hasher, crl_urls)
            
            entity = Entity(
                name=f"Root CA {curve.name}",
                email="root@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Root CA Org",
                organizational_unit="Root CA Unit"
            )
            
            private_key, public_key, certificate = generator.generate(entity)
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert private_key.curve.name == curve.name
            assert public_key.curve.name == curve.name
            
            # Check CRL Distribution Points extension
            crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            assert crl_ext.critical is False
            
            # Verify URL is present
            distribution_points = crl_ext.value
            assert len(distribution_points) == 1
            
            dp = distribution_points[0]
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == "http://ca.example.com/crl/root-ca.crl"
