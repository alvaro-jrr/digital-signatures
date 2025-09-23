from abc import ABC, abstractmethod

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

from digital_signatures.crypto.key_generator.base import KeyGenerator
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher

class CertificateGenerator(ABC):
  """This class represents a certificate generator in the PKI."""

  key_generator: KeyGenerator
  """The key generator to use for generating the certificate."""

  hasher: Hasher
  """The hasher to use for generating the certificate."""

  crl_urls: list[str]
  """The Certificate Revocation List URLs to use for generating the certificate."""

  def __init__(self, key_generator: KeyGenerator, hasher: Hasher, crl_urls: list[str] = []):
    self.key_generator = key_generator
    self.hasher = hasher
    self.crl_urls = crl_urls

  @abstractmethod
  def generate(self, entity: Entity) -> tuple[PrivateKeyTypes, PublicKeyTypes, x509.Certificate]:
    """Generates a certificate for the entity."""
    pass