from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from digital_signatures.utils.hasher import Hasher

class Signer(ABC):
  """This class is responsible for signing a message."""

  private_key: PrivateKeyTypes
  """The private key to use for signing."""

  hasher: Hasher
  """The hasher to generate the hash of the message."""

  def __init__(self, private_key: PrivateKeyTypes, hash_generator: Hasher):
    self.private_key = private_key
    self.hasher = hash_generator

  @abstractmethod
  def sign(self, message: str | bytes) -> bytes:
    """Signs the message."""
    pass