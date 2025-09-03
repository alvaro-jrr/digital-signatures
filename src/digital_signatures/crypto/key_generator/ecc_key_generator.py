from cryptography.hazmat.primitives.asymmetric import ec

from digital_signatures.crypto.key_generator.base import KeyGenerator

class EccKeyGenerator(KeyGenerator):
  """This class is responsible for generating the key pair for the digital signature using Elliptic Curve Cryptography."""

  # The curve to use for the elliptic curve.
  CURVE = ec.SECP256R1()

  def generate(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a key pair using Elliptic Curve Cryptography."""

    # Generate a private key.
    private_key = ec.generate_private_key(self.CURVE)

    # Derive the public key from the private key.
    public_key = private_key.public_key()

    return private_key, public_key