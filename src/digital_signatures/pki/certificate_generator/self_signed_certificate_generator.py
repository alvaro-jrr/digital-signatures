from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

from digital_signatures.crypto.key_generator.base import KeyGenerator
from digital_signatures.pki.certificate_generator.base import CertificateGenerator
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher

class SelfSignedCertificateGenerator(CertificateGenerator):
  """This class represents a self-signed certificate generator in the PKI."""

  def __init__(self, key_generator: KeyGenerator, hasher: Hasher):
    super().__init__(key_generator, hasher)

  def generate(self, entity: Entity) -> tuple[PrivateKeyTypes, PublicKeyTypes, x509.Certificate]:
    """Generates a self-signed certificate for the entity."""

    # The issuer is the entity itself.
    issuer = entity

    # Generate a key pair.
    private_key, public_key = self.key_generator.generate()

    # The creation and expiration dates of the certificate (1 year).
    creation_date = datetime.now(timezone.utc)
    expiration_date = creation_date + timedelta(days=365) 

    # Generate a certificate.
    certificate = x509.CertificateBuilder().subject_name(
      entity.to_name()
    ).issuer_name(
      issuer.to_name()
    ).public_key(
      public_key
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      creation_date
    ).not_valid_after(
      expiration_date
    ).add_extension(
      x509.SubjectAlternativeName([x509.DNSName("localhost")]),
      critical=False,
    ).sign(private_key, self.hasher.algorithm)

    return private_key, public_key, certificate