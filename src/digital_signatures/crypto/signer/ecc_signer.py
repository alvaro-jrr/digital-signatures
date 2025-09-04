from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from digital_signatures.crypto.signer.base import Signer
from digital_signatures.utils.hash_generator import HashGenerator


class EccSigner(Signer):
  """This class is responsible for signing a message using Elliptic Curve Cryptography."""

  private_key: EllipticCurvePrivateKey
  """The private key to use for signing."""

  hash_generator: HashGenerator
  """The hash generator to generate the hash of the message."""

  def __init__(self, private_key: EllipticCurvePrivateKey, hash_generator: HashGenerator):
    self.private_key = private_key
    self.hash_generator = hash_generator

  def sign(self, message: bytes) -> bytes:
    """Signs the message."""

    # Generate the hash of the message.
    message_digest = self.hash_generator.generate(message)

    # Sign the message.
    signature = self.private_key.sign(message_digest, ec.ECDSA(utils.Prehashed(self.hash_generator.algorithm)))

    return signature