from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from digital_signatures.utils.hash_generator import HashGenerator

class Signer(ABC):
  """This class is responsible for signing a message."""

  private_key: PrivateKeyTypes
  """The private key to use for signing."""

  hash_generator: HashGenerator
  """The hash generator to generate the hash of the message."""

  def __init__(self, private_key: PrivateKeyTypes, hash_generator: HashGenerator):
    self.private_key = private_key
    self.hash_generator = hash_generator

  @abstractmethod
  def sign(self, message: str | bytes) -> bytes:
    """Signs the message."""
    pass