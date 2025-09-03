from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

class KeyGenerator(ABC):
  """This class is responsible for generating the key pair for the digital signature."""

  @abstractmethod
  def generate(self) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
    pass
