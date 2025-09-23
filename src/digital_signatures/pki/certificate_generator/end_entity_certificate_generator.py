from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

from digital_signatures.crypto.key_generator.base import KeyGenerator
from digital_signatures.pki.certificate_generator.base import CertificateGenerator
from digital_signatures.pki.certificate_generator.utils import append_crl_distribution_points
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher


class EndEntityCertificateGenerator(CertificateGenerator):
  """This class represents an end entity certificate generator in the PKI."""

  def __init__(self, key_generator: KeyGenerator, hasher: Hasher, crl_urls: list[str] = []):
    super().__init__(key_generator, hasher, crl_urls)

  def generate(
    self, 
    entity: Entity,
    intermediate_certificate: x509.Certificate, 
    intermediate_private_key: PrivateKeyTypes,
  ) -> tuple[PrivateKeyTypes, PublicKeyTypes, x509.Certificate]:
    """Generates an end entity certificate for the entity."""
    
    # Generate a key pair.
    ee_private_key, ee_public_key = self.key_generator.generate()

    # The creation and expiration dates of the certificate (1 year).
    creation_date = datetime.now(timezone.utc)
    expiration_date = creation_date + timedelta(days=365) 

    # Generate a certificate.
    certificate_builder = x509.CertificateBuilder().subject_name(
      entity.to_name()
    ).issuer_name(
      intermediate_certificate.subject
    ).public_key(
      ee_public_key
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      creation_date
    ).not_valid_after(
      expiration_date
    ).add_extension(
      x509.BasicConstraints(ca=False, path_length=None),
      critical=True,
    ).add_extension(
      x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
      ),
      critical=True,
    ).add_extension(
      x509.ExtendedKeyUsage([
        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        x509.ExtendedKeyUsageOID.SERVER_AUTH,
      ]),
      critical=False,
    ).add_extension(
      x509.SubjectKeyIdentifier.from_public_key(ee_public_key),
      critical=False,
    ).add_extension(
      x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        intermediate_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
      ),
      critical=False,
    )

    # Add the CRL distribution points if any.
    certificate_builder = append_crl_distribution_points(certificate_builder, self.crl_urls)

    # Sign the certificate.
    certificate = certificate_builder.sign(intermediate_private_key, self.hasher.algorithm)

    return ee_private_key, ee_public_key, certificate