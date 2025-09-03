from cryptography.hazmat.primitives.asymmetric import ec

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator

# Initialize the key manager.
key_manager = EccKeyGenerator()

def test_generate():
  private_key, public_key = key_manager.generate()

  # Check if the keys are elliptic curve keys.
  assert isinstance(private_key, ec.EllipticCurvePrivateKey)
  assert isinstance(public_key, ec.EllipticCurvePublicKey)

  # Check if the curve is the same as the curve used for the key manager.
  assert private_key.curve.name == key_manager.CURVE.name

  # Check if the public key is the same as the private key's public key.
  assert public_key == private_key.public_key()

