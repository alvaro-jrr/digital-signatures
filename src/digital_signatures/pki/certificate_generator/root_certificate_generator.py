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

class RootCertificateGenerator(CertificateGenerator):
  """This class represents a root certificate generator in the PKI."""

  def __init__(self, key_generator: KeyGenerator, hasher: Hasher, crl_urls: list[str] = []):
    super().__init__(key_generator, hasher, crl_urls)

  def generate(self, entity: Entity) -> tuple[PrivateKeyTypes, PublicKeyTypes, x509.Certificate]:
    """Generates a root certificate for the entity."""

    # The issuer is the entity itself.
    issuer = entity

    # Generate a key pair.
    root_private_key, root_public_key = self.key_generator.generate()

    # The creation and expiration dates of the certificate (10 years).
    creation_date = datetime.now(timezone.utc)
    expiration_date = creation_date + timedelta(days=365 * 10) 

    # Generate a certificate.
    root_certificate_builder = x509.CertificateBuilder().subject_name(
      entity.to_name()
    ).issuer_name(
      issuer.to_name()
    ).public_key(
      root_public_key
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      creation_date
    ).not_valid_after(
      expiration_date
    ).add_extension(
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
      x509.SubjectKeyIdentifier.from_public_key(root_public_key),
      critical=False,
    )

    # Add the CRL distribution points if any.
    root_certificate_builder = append_crl_distribution_points(root_certificate_builder, self.crl_urls)
    
    # Sign the certificate.
    root_certificate = root_certificate_builder.sign(root_private_key, self.hasher.algorithm)

    return root_private_key, root_public_key, root_certificate