from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from digital_signatures.utils.hash_generator import HashGenerator

class Verifier(ABC):
  """This class is responsible for verifying a message."""

  public_key: PublicKeyTypes
  """The public key to use for verifying the message."""

  hash_generator: HashGenerator
  """The hash generator to generate the hash of the message."""
  
  @abstractmethod
  def verify(self, signature: bytes, message: bytes) -> bool:
    """Verifies the message."""
    pass