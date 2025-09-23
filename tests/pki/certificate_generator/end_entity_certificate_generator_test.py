import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.pki.certificate_generator.end_entity_certificate_generator import EndEntityCertificateGenerator
from digital_signatures.pki.certificate_generator.intermediate_certificate_generator import IntermediateCertificateGenerator
from digital_signatures.pki.certificate_generator.root_certificate_generator import RootCertificateGenerator
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher


class TestEndEntityCertificateGenerator:
    """Test cases for the EndEntityCertificateGenerator class."""

    def test_init_with_valid_parameters(self):
        """Test that EndEntityCertificateGenerator initializes correctly with valid parameters."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        assert generator.key_generator == key_generator
        assert generator.hasher == hasher

    def test_generate_returns_correct_types(self):
        """Test that generate() returns the correct types."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain: Root -> Intermediate -> End Entity
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Now create an end entity certificate
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)

    def test_generate_returns_matching_key_pair(self):
        """Test that the returned public key matches the private key's public key."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert public_key == private_key.public_key()

    def test_generate_certificate_subject_matches_entity(self):
        """Test that the certificate subject matches the entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity User", "end@user.com", "GB", "England", "London", "End Entity Ltd", "End Entity Dept")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert certificate.subject == end_entity.to_name()

    def test_generate_certificate_issuer_matches_intermediate_certificate_subject(self):
        """Test that the certificate issuer matches the intermediate certificate subject."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert certificate.issuer == intermediate_certificate.subject
        assert certificate.issuer != certificate.subject

    def test_generate_certificate_validity_period(self):
        """Test that the certificate has the correct validity period (1 year)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that the certificate is valid for approximately 1 year
        now = datetime.now(timezone.utc)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        
        # Should be approximately 365 days (1 year, allow some tolerance for execution time)
        assert 364 <= validity_period.days <= 366
        
        # Certificate should be valid now
        assert certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    def test_generate_certificate_basic_constraints_extension(self):
        """Test that the certificate has the correct BasicConstraints extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that BasicConstraints extension is present
        basic_constraints_extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints_extension.critical is True
        assert basic_constraints_extension.value.ca is False
        assert basic_constraints_extension.value.path_length is None

    def test_generate_certificate_key_usage_extension(self):
        """Test that the certificate has the correct KeyUsage extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that KeyUsage extension is present
        key_usage_extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage_extension.critical is True
        
        key_usage = key_usage_extension.value
        assert key_usage.digital_signature is True
        assert key_usage.content_commitment is False
        assert key_usage.key_encipherment is True
        assert key_usage.data_encipherment is False
        assert key_usage.key_agreement is False
        assert key_usage.key_cert_sign is False
        assert key_usage.crl_sign is True
        # encipher_only and decipher_only are only defined when key_agreement is True
        # Since key_agreement is False, we don't test these properties

    def test_generate_certificate_extended_key_usage_extension(self):
        """Test that the certificate has the ExtendedKeyUsage extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that ExtendedKeyUsage extension is present
        eku_extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert eku_extension.critical is False
        
        eku = eku_extension.value
        assert x509.ExtendedKeyUsageOID.CLIENT_AUTH in eku
        assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku

    def test_generate_certificate_subject_key_identifier_extension(self):
        """Test that the certificate has the SubjectKeyIdentifier extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that SubjectKeyIdentifier extension is present
        ski_extension = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski_extension.critical is False
        assert ski_extension.value is not None

    def test_generate_certificate_authority_key_identifier_extension(self):
        """Test that the certificate has the AuthorityKeyIdentifier extension."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that AuthorityKeyIdentifier extension is present
        aki_extension = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki_extension.critical is False
        assert aki_extension.value is not None

    def test_generate_different_entities_different_certificates(self):
        """Test that different entities produce different certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Create two different end entities
        end_entity1 = Entity("End Entity One", "end1@entity.com", "US", "CA", "SF", "End Entity Org1", "End Entity Unit1")
        end_entity2 = Entity("End Entity Two", "end2@entity.com", "CA", "ON", "Toronto", "End Entity Org2", "End Entity Unit2")
        
        private_key1, public_key1, certificate1 = generator.generate(
            end_entity1, intermediate_certificate, intermediate_private_key
        )
        private_key2, public_key2, certificate2 = generator.generate(
            end_entity2, intermediate_certificate, intermediate_private_key
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
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Create the same end entity twice
        end_entity = Entity("Same End Entity", "same@endentity.com", "US", "CA", "SF", "Same End Entity Org", "Same End Entity Unit")
        
        private_key1, public_key1, certificate1 = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        private_key2, public_key2, certificate2 = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
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
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Create end entity with minimal fields
        end_entity = Entity("Minimal End Entity", "minimal@endentity.com", "US", "CA", "SF", None, None)
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == end_entity.to_name()
        assert certificate.issuer == intermediate_certificate.subject

    def test_generate_with_special_characters_in_entity(self):
        """Test certificate generation with special characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Create end entity with special characters
        end_entity = Entity("José María End Entity", "josé.maría@endentity.españa.com", "ES", "Madrid", "Madrid", "Empresa End Entity S.L.", "Desarrollo End Entity")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == end_entity.to_name()
        assert certificate.issuer == intermediate_certificate.subject

    def test_generate_with_different_curves(self):
        """Test certificate generation with different elliptic curves."""
        curves = [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]
        
        for curve in curves:
            key_generator = EccKeyGenerator(curve)
            hasher = Hasher(hashes.SHA256())
            generator = EndEntityCertificateGenerator(key_generator, hasher)
            
            # Create certificate chain
            root_generator = RootCertificateGenerator(key_generator, hasher)
            root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
            root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
            
            intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
            intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
            intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
                intermediate_entity, root_certificate, root_private_key
            )
            
            # Create end entity
            end_entity = Entity(f"End Entity {curve.name}", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
            
            private_key, public_key, certificate = generator.generate(
                end_entity, intermediate_certificate, intermediate_private_key
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
            generator = EndEntityCertificateGenerator(key_generator, hasher)
            
            # Create certificate chain
            root_generator = RootCertificateGenerator(key_generator, hasher)
            root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
            root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
            
            intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
            intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
            intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
                intermediate_entity, root_certificate, root_private_key
            )
            
            # Create end entity
            end_entity = Entity(f"End Entity {algorithm.name}", "end@entity.com", "US", "CA", "SF", "End Entity Org", "End Entity Unit")
            
            private_key, public_key, certificate = generator.generate(
                end_entity, intermediate_certificate, intermediate_private_key
            )
            
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            assert isinstance(certificate, x509.Certificate)
            assert certificate.subject == end_entity.to_name()

    def test_inherits_from_certificate_generator_base_class(self):
        """Test that EndEntityCertificateGenerator inherits from CertificateGenerator base class."""
        from digital_signatures.pki.certificate_generator.base import CertificateGenerator
        
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        assert isinstance(generator, CertificateGenerator)

    def test_generate_certificate_version(self):
        """Test that the certificate has the correct version."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("Version Test End Entity", "version@endentity.com", "US", "CA", "SF", "Version End Entity Org", "Version End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # X.509 certificates should be version 3
        assert certificate.version == x509.Version.v3

    def test_generate_certificate_public_bytes(self):
        """Test that the certificate can be serialized to bytes."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("Serialization Test End Entity", "serialization@endentity.com", "US", "CA", "SF", "Serialization End Entity Org", "Serialization End Entity Unit")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
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
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("Performance Test End Entity", "performance@endentity.com", "US", "CA", "SF", "Performance End Entity Org", "Performance End Entity Unit")
        
        # Time multiple certificate generation operations
        start_time = time.time()
        for _ in range(5):
            generator.generate(end_entity, intermediate_certificate, intermediate_private_key)
        generation_time = time.time() - start_time
        
        # Certificate generation should be reasonably fast (less than 2 seconds for 5 certificates)
        assert generation_time < 2.0
        print(f"Generated 5 end entity certificates in {generation_time:.3f} seconds")

    def test_generate_with_unicode_entity(self):
        """Test certificate generation with Unicode characters in entity."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        # Create end entity with Unicode characters
        end_entity = Entity("张三终端实体", "zhangsan@endentity.中国.com", "CN", "北京", "北京", "中国终端实体公司", "技术部终端实体")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert isinstance(certificate, x509.Certificate)
        assert certificate.subject == end_entity.to_name()
        assert certificate.issuer == intermediate_certificate.subject

    def test_generate_end_entity_certificate_characteristics(self):
        """Test specific characteristics of end entity certificates."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root Certificate Authority", "root@authority.com", "US", "CA", "SF", "Certificate Authority Inc", "Root CA Department")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate Certificate Authority", "intermediate@authority.com", "US", "CA", "SF", "Intermediate Certificate Authority Inc", "Intermediate CA Department")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        end_entity = Entity("End Entity User", "end@user.com", "US", "CA", "SF", "End Entity Inc", "End Entity Department")
        
        private_key, public_key, certificate = generator.generate(
            end_entity, intermediate_certificate, intermediate_private_key
        )
        
        # End entity certificates should be signed by the intermediate CA
        assert certificate.issuer == intermediate_certificate.subject
        assert certificate.issuer != certificate.subject
        
        # End entity certificates should have CA=False in BasicConstraints
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is False
        
        # End entity certificates should have keyEncipherment=True and keyCertSign=False in KeyUsage
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_encipherment is True
        assert key_usage.value.key_cert_sign is False
        
        # End entity certificates should have ExtendedKeyUsage with client and server auth
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        
        # End entity certificates should have a short validity period (1 year)
        validity_period = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        assert validity_period.days >= 364  # At least 1 year minus 1 day
        
        # Should have AuthorityKeyIdentifier extension
        aki_extension = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki_extension.critical is False
        assert aki_extension.value is not None

    # CRL URLs Tests
    def test_init_with_crl_urls(self):
        """Test that EndEntityCertificateGenerator initializes correctly with CRL URLs."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = ["http://ca.example.com/crl/end-entity.crl"]
        
        generator = EndEntityCertificateGenerator(key_generator, hasher, crl_urls)
        
        assert generator.key_generator == key_generator
        assert generator.hasher == hasher
        assert generator.crl_urls == crl_urls

    def test_generate_without_crl_urls(self):
        """Test that generate() works without CRL URLs (backward compatibility)."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        generator = EndEntityCertificateGenerator(key_generator, hasher)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        entity = Entity(
            name="End Entity",
            email="end@entity.com",
            country="US",
            state="CA",
            locality="SF",
            organization="End Entity Org",
            organizational_unit="End Entity Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            entity, intermediate_certificate, intermediate_private_key
        )
        
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
        crl_urls = ["http://ca.example.com/crl/end-entity.crl"]
        generator = EndEntityCertificateGenerator(key_generator, hasher, crl_urls)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        entity = Entity(
            name="End Entity",
            email="end@entity.com",
            country="US",
            state="CA",
            locality="SF",
            organization="End Entity Org",
            organizational_unit="End Entity Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            entity, intermediate_certificate, intermediate_private_key
        )
        
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
        assert dp.full_name[0].value == "http://ca.example.com/crl/end-entity.crl"
        assert dp.relative_name is None
        assert dp.crl_issuer is None
        assert dp.reasons is None

    def test_generate_with_multiple_crl_urls(self):
        """Test certificate generation with multiple CRL URLs."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = [
            "http://ca.example.com/crl/end-entity.crl",
            "http://backup-ca.example.com/crl/end-entity.crl",
            "ldap://ldap.example.com/cn=end-entity,ou=crl,dc=example,dc=com"
        ]
        generator = EndEntityCertificateGenerator(key_generator, hasher, crl_urls)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        entity = Entity(
            name="End Entity",
            email="end@entity.com",
            country="US",
            state="CA",
            locality="SF",
            organization="End Entity Org",
            organizational_unit="End Entity Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            entity, intermediate_certificate, intermediate_private_key
        )
        
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
        
        assert "http://ca.example.com/crl/end-entity.crl" in urls
        assert "http://backup-ca.example.com/crl/end-entity.crl" in urls
        assert "ldap://ldap.example.com/cn=end-entity,ou=crl,dc=example,dc=com" in urls

    def test_generate_crl_extension_not_critical(self):
        """Test that CRL Distribution Points extension is not critical."""
        key_generator = EccKeyGenerator()
        hasher = Hasher(hashes.SHA256())
        crl_urls = ["http://ca.example.com/crl/end-entity.crl"]
        generator = EndEntityCertificateGenerator(key_generator, hasher, crl_urls)
        
        # Create certificate chain
        root_generator = RootCertificateGenerator(key_generator, hasher)
        root_entity = Entity("Root CA", "root@ca.com", "US", "CA", "SF", "Root CA Org", "Root CA Unit")
        root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
        
        intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
        intermediate_entity = Entity("Intermediate CA", "intermediate@ca.com", "US", "CA", "SF", "Intermediate CA Org", "Intermediate CA Unit")
        intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
            intermediate_entity, root_certificate, root_private_key
        )
        
        entity = Entity(
            name="End Entity",
            email="end@entity.com",
            country="US",
            state="CA",
            locality="SF",
            organization="End Entity Org",
            organizational_unit="End Entity Unit"
        )
        
        private_key, public_key, certificate = generator.generate(
            entity, intermediate_certificate, intermediate_private_key
        )
        
        # Check that CRL Distribution Points extension is not critical
        crl_ext = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        assert crl_ext.critical is False
