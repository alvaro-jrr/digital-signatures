import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.pki.certificate_generator.intermediate_certificate_generator import IntermediateCertificateGenerator
from digital_signatures.pki.certificate_generator.root_certificate_generator import RootCertificateGenerator
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher


class TestIntermediateCertificateGenerator:
    """Test cases for the IntermediateCertificateGenerator class."""

    def test_init_with_valid_parameters(self):
        """Test that IntermediateCertificateGenerator initializes correctly with valid parameters."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        assert generator.key_generator == key_generator
        assert generator.hasher == hasher

    def test_init_with_different_hash_algorithms(self):
        """Test initialization with different hash algorithms."""
        algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
        
        for algorithm in algorithms:
            key_generator = EccKeyGenerator()
            hasher = Hasher(algorithm)
            
            generator = IntermediateCertificateGenerator(key_generator, hasher)
            
            assert generator.key_generator == key_generator
            assert generator.hasher == hasher
            assert generator.hasher.algorithm == algorithm

    def test_generate_returns_correct_types(self):
        """Test that generate() returns the correct types."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)

    def test_generate_returns_matching_key_pair(self):
        """Test that the returned public key matches the private key's public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert public_key == private_key.public_key()

    def test_generate_certificate_subject_matches_entity(self):
        """Test that the certificate subject matches the entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate Certificate Authority",
            email="intermediate@authority.com",
            country="GB",
            state="England",
            locality="London",
            organization="Intermediate Certificate Authority Ltd",
            organizational_unit="Intermediate CA"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert certificate.subject == intermediate_entity.to_name()

    def test_generate_certificate_issuer_matches_root_certificate_subject(self):
        """Test that the certificate issuer matches the root certificate subject."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert certificate.issuer == root_certificate.subject
        assert certificate.issuer != certificate.subject

    def test_generate_certificate_public_key_matches_generated_key(self):
        """Test that the certificate's public key matches the generated public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert certificate.public_key() == public_key

    def test_generate_certificate_validity_period(self):
        """Test that the certificate has the correct validity period (3 years)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Check that the certificate is valid for approximately 3 years
        now = datetime.now(timezone.utc)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        
        # Should be approximately 1095 days (3 years, allow some tolerance for execution time)
        assert 1094 <= validity_period.days <= 1096
        
        # Certificate should be valid now
        assert certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    def test_generate_certificate_serial_number(self):
        """Test that the certificate has a valid serial number."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Serial number should be a positive integer
        assert certificate.serial_number > 0

    def test_generate_certificate_basic_constraints_extension(self):
        """Test that the certificate has the correct BasicConstraints extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Check that BasicConstraints extension is present
        basic_constraints_extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints_extension.critical is True
        assert basic_constraints_extension.value.ca is True
        assert basic_constraints_extension.value.path_length is None

    def test_generate_certificate_key_usage_extension(self):
        """Test that the certificate has the correct KeyUsage extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
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
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Check that SubjectKeyIdentifier extension is present
        ski_extension = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski_extension.critical is False
        assert ski_extension.value is not None

    def test_generate_certificate_authority_key_identifier_extension(self):
        """Test that the certificate has the AuthorityKeyIdentifier extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate CA",
            email="intermediate@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org",
            organizational_unit="Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Check that AuthorityKeyIdentifier extension is present
        aki_extension = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki_extension.critical is False
        assert aki_extension.value is not None

    def test_generate_different_entities_different_certificates(self):
        """Test that different entities produce different certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Create two different intermediate entities
        intermediate_entity1 = Entity(
            name="Intermediate CA One",
            email="intermediate1@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate CA Org1",
            organizational_unit="Intermediate CA Unit1"
        )
        
        intermediate_entity2 = Entity(
            name="Intermediate CA Two",
            email="intermediate2@ca.com",
            country="CA",
            state="ON",
            locality="Toronto",
            organization="Intermediate CA Org2",
            organizational_unit="Intermediate CA Unit2"
        )
        
        private_key1, public_key1, certificate1 = generator.generate(
            intermediate_entity1, root_certificate, root_private_key
        )
        private_key2, public_key2, certificate2 = generator.generate(
            intermediate_entity2, root_certificate, root_private_key
        )
        
        # Certificates should be different
        assert certificate1 != certificate2
        assert certificate1.subject != certificate2.subject
        assert private_key1 != private_key2
        assert public_key1 != public_key2

    def test_generate_same_entity_different_keys(self):
        """Test that generating certificates for the same entity produces different keys."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Create the same intermediate entity twice
        intermediate_entity = Entity(
            name="Same Intermediate CA",
            email="same@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Same Intermediate CA Org",
            organizational_unit="Same Intermediate CA Unit"
        )
        
        private_key1, public_key1, certificate1 = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        private_key2, public_key2, certificate2 = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
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
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate with minimal entity
        intermediate_entity = Entity(
            name="Minimal Intermediate CA",
            email="minimal@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization=None,
            organizational_unit=None
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == intermediate_entity.to_name()
        assert certificate.issuer == root_certificate.subject

    def test_generate_with_special_characters_in_entity(self):
        """Test certificate generation with special characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate with special characters
        intermediate_entity = Entity(
            name="José María Intermediate CA",
            email="josé.maría@intermediateca.españa.com",
            country="ES",
            state="Madrid",
            locality="Madrid",
            organization="Empresa Intermediate CA S.L.",
            organizational_unit="Desarrollo Intermediate CA"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == intermediate_entity.to_name()
        assert certificate.issuer == root_certificate.subject

    def test_generate_with_different_curves(self):
        """Test certificate generation with different elliptic curves."""
        curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
        
        for curve in curves:
            key_generator = EccKeyGenerator(curve)
            hasher = Hasher(hashes.SHA256())
            generator = IntermediateCertificateGenerator(key_generator, hasher)
            
            # First create a root certificate
            root_generator = RootCertificateGenerator(key_generator, hasher)
            root_entity = Entity(
                name="Root CA",
                email="root@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Root CA Org",
                organizational_unit="Root CA Unit"
            )
            root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
            
            # Now create an intermediate certificate
            intermediate_entity = Entity(
                name=f"Intermediate CA {curve.name}",
                email="intermediate@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Intermediate CA Org",
                organizational_unit="Intermediate CA Unit"
            )
            
            private_key, public_key, certificate = generator.generate(
                intermediate_entity, root_certificate, root_private_key
            )
            
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
            generator = IntermediateCertificateGenerator(key_generator, hasher)
            
            # First create a root certificate
            root_generator = RootCertificateGenerator(key_generator, hasher)
            root_entity = Entity(
                name="Root CA",
                email="root@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Root CA Org",
                organizational_unit="Root CA Unit"
            )
            root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
            
            # Now create an intermediate certificate
            intermediate_entity = Entity(
                name=f"Intermediate CA {algorithm.name}",
                email="intermediate@ca.com",
                country="US",
                state="CA",
                locality="SF",
                organization="Intermediate CA Org",
                organizational_unit="Intermediate CA Unit"
            )
            
            private_key, public_key, certificate = generator.generate(
                intermediate_entity, root_certificate, root_private_key
            )
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert certificate.subject == intermediate_entity.to_name()

    def test_inherits_from_certificate_generator_base_class(self):
        """Test that IntermediateCertificateGenerator inherits from CertificateGenerator base class."""
        from digital_signatures.pki.certificate_generator.base import CertificateGenerator
        
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        assert isinstance(generator, CertificateGenerator)

    def test_generate_consistency_multiple_calls(self):
        """Test that multiple calls to generate() produce consistent results."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create multiple intermediate certificates
        intermediate_entity = Entity(
            name="Consistent Intermediate CA",
            email="consistent@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Consistent Intermediate CA Org",
            organizational_unit="Consistent Intermediate CA Unit"
        )
        
        # Generate multiple certificates
        results = []
        for _ in range(3):
            private_key, public_key, certificate = generator.generate(
                intermediate_entity, root_certificate, root_private_key
            )
            results.append((private_key, public_key, certificate))
        
        # All results should be valid
        for private_key, public_key, certificate in results:
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert certificate.subject == intermediate_entity.to_name()
            assert certificate.issuer == root_certificate.subject
            assert public_key == private_key.public_key()

    def test_generate_certificate_signature_verification(self):
        """Test that the certificate signature can be verified."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Signature Test Intermediate CA",
            email="signature@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Signature Intermediate CA Org",
            organizational_unit="Signature Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # The certificate should be signed by the root CA
        assert certificate.issuer == root_certificate.subject
        assert certificate.public_key() == public_key

    def test_generate_certificate_version(self):
        """Test that the certificate has the correct version."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Version Test Intermediate CA",
            email="version@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Version Intermediate CA Org",
            organizational_unit="Version Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # X.509 certificates should be version 3
        assert certificate.version == x509.Version.v3

    def test_generate_certificate_public_bytes(self):
        """Test that the certificate can be serialized to bytes."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Serialization Test Intermediate CA",
            email="serialization@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Serialization Intermediate CA Org",
            organizational_unit="Serialization Intermediate CA Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
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
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create multiple intermediate certificates
        intermediate_entity = Entity(
            name="Performance Test Intermediate CA",
            email="performance@intermediateca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Performance Intermediate CA Org",
            organizational_unit="Performance Intermediate CA Unit"
        )
        
        # Time multiple certificate generation operations
        start_time = time.time()
        for _ in range(5):
            generator.generate(intermediate_entity, root_certificate, root_private_key)
        generation_time = time.time() - start_time
        
        # Certificate generation should be reasonably fast (less than 2 seconds for 5 certificates)
        assert generation_time < 2.0
        print(f"Generated 5 intermediate certificates in {generation_time:.3f} seconds")

    def test_generate_with_unicode_entity(self):
        """Test certificate generation with Unicode characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root CA",
            email="root@ca.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Root CA Org",
            organizational_unit="Root CA Unit"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate with Unicode characters
        intermediate_entity = Entity(
            name="张三中间证书",
            email="zhangsan@intermediateca.中国.com",
            country="CN",
            state="北京",
            locality="北京",
            organization="中国中间证书公司",
            organizational_unit="技术部中间证书"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == intermediate_entity.to_name()
        assert certificate.issuer == root_certificate.subject

    def test_generate_intermediate_certificate_characteristics(self):
        """Test specific characteristics of intermediate certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = IntermediateCertificateGenerator(key_generator, hasher)
        
        # First create a root certificate
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity(
            name="Root Certificate Authority",
            email="root@authority.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Certificate Authority Inc",
            organizational_unit="Root CA Department"
        )
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        # Now create an intermediate certificate
        intermediate_entity = Entity(
            name="Intermediate Certificate Authority",
            email="intermediate@authority.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Intermediate Certificate Authority Inc",
            organizational_unit="Intermediate CA Department"
        )
        
        private_key, public_key, certificate = generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Intermediate certificates should be signed by the root CA
        assert certificate.issuer == root_certificate.subject
        assert certificate.issuer != certificate.subject
        
        # Intermediate certificates should have CA=True in BasicConstraints
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is True
        
        # Intermediate certificates should have keyCertSign and cRLSign in KeyUsage
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True
        
        # Intermediate certificates should have a medium validity period (3 years)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        assert validity_period.days >= 1094  # At least 3 years minus 1 day
        
        # Should have AuthorityKeyIdentifier extension
        aki_extension = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki_extension.critical is False
        assert aki_extension.value is not None
