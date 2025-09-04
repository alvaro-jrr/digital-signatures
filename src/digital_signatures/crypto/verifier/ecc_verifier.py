from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from digital_signatures.crypto.verifier.base import Verifier
from digital_signatures.utils.hash_generator import HashGenerator

class EccVerifier(Verifier):
  """This class is responsible for verifying a message using Elliptic Curve Cryptography."""

  public_key: PublicKeyTypes
  """The public key to use for verifying the message."""

  hash_generator: HashGenerator
  """The hash generator to generate the hash of the message."""

  def __init__(self, public_key: PublicKeyTypes, hash_generator: HashGenerator):
    # Validate the public key.
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
      raise ValueError("Public key must be an instance of EllipticCurvePublicKey.")

    self.public_key = public_key
    self.hash_generator = hash_generator

  def verify(self, signature: bytes, message: str | bytes) -> bool:
    """Verifies the message."""

    # Generate the hash of the message.
    message_digest = self.hash_generator.generate(message)

    try:
      self.public_key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(self.hash_generator.algorithm)))

      return True
    except:
      return False
