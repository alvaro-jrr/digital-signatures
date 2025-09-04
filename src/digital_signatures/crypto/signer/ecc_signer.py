from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from digital_signatures.crypto.signer.base import Signer
from digital_signatures.utils.hasher import Hasher

class EccSigner(Signer):
  """This class is responsible for signing a message using Elliptic Curve Cryptography."""

  private_key: PrivateKeyTypes
  """The private key to use for signing."""

  hasher: Hasher
  """The hasher to generate the hash of the message."""

  def __init__(self, private_key: PrivateKeyTypes, hasher: Hasher):
    # Validate the private key.
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
      raise ValueError("Private key must be an instance of EllipticCurvePrivateKey.")
    
    self.private_key = private_key
    self.hasher = hasher

  def sign(self, message: str | bytes) -> bytes:
    """Signs the message."""

    # Generate the hash of the message.
    message_digest = self.hasher.hash(message)

    # Sign the message.
    signature = self.private_key.sign(message_digest, ec.ECDSA(utils.Prehashed(self.hasher.algorithm)))

    return signature