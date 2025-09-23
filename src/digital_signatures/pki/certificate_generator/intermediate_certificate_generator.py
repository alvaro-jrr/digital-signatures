from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

from digital_signatures.crypto.key_generator.base import KeyGenerator
from digital_signatures.pki.certificate_generator.base import CertificateGenerator
from digital_signatures.pki.certificate_generator.utils import (
  append_crl_distribution_points,
)
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher

class IntermediateCertificateGenerator(CertificateGenerator):
  """This class represents an intermediate certificate generator in the PKI."""

  def __init__(self, key_generator: KeyGenerator, hasher: Hasher, crl_urls: list[str] = []):
    super().__init__(key_generator, hasher, crl_urls)

  def generate(
    self,
    entity: Entity,
    root_certificate: x509.Certificate,
    root_private_key: PrivateKeyTypes,
  ) -> tuple[PrivateKeyTypes, PublicKeyTypes, x509.Certificate]:
    """Generates an intermediate certificate of the root certificate for the entity."""
    
    # Generate a key pair.
    intermediate_private_key, intermediate_public_key = self.key_generator.generate()

    # The creation and expiration dates of the certificate (~3 years).
    creation_date = datetime.now(timezone.utc)
    expiration_date = creation_date + timedelta(days=365 * 3) 

    # Generate a certificate.
    intermediate_certificate_builder = x509.CertificateBuilder().subject_name(
      entity.to_name()
    ).issuer_name(
      root_certificate.subject
    ).public_key(
      intermediate_public_key
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      creation_date
    ).not_valid_after(
      expiration_date
    ).add_extension(
      # Don't allow further intermediate certificates to be issued.
      x509.BasicConstraints(ca=True, path_length=None),
      critical=True,
    ).add_extension(
      x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
      ),
      critical=True,
    ).add_extension(
      x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key),
      critical=False,
    ).add_extension(
      x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        root_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
      ),
      critical=False,
    )

    # Add the CRL distribution points if any.
    intermediate_certificate_builder = append_crl_distribution_points(intermediate_certificate_builder, self.crl_urls)

    # Sign the certificate.
    intermediate_certificate = intermediate_certificate_builder.sign(root_private_key, self.hasher.algorithm)

    return intermediate_private_key, intermediate_public_key, intermediate_certificate