
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)

from digital_signatures.utils.files import create_file

class KeyStorage:
  """This class is responsible for storing the key pair."""

  encoding_format: serialization.Encoding
  """The encoding format to use for the private key."""

  private_format: serialization.PrivateFormat
  """The format type to use for the private key."""

  public_format: serialization.PublicFormat
  """The format type to use for the public key."""

  def __init__(
    self,
    encoding_format: serialization.Encoding = serialization.Encoding.PEM,
    private_format: serialization.PrivateFormat = serialization.PrivateFormat.PKCS8, 
    public_format: serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo
  ):
    self.encoding_format = encoding_format
    self.private_format = private_format
    self.public_format = public_format

  def serialize_private_key(
    self,
    private_key: PrivateKeyTypes,
    password: str | bytes | None = None,
  ) -> bytes:
    """Serializes the private key."""

    # Convert the password to bytes if it is a string.
    if isinstance(password, str):
      password = password.encode()

    # Create the appropriate encryption algorithm.
    if isinstance(password, bytes):
      encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
      encryption_algorithm = serialization.NoEncryption()

    return private_key.private_bytes(self.encoding_format, self.private_format, encryption_algorithm)

  def serialize_public_key(self, public_key: PublicKeyTypes) -> bytes:
    """Serializes the public key."""

    return public_key.public_bytes(self.encoding_format, self.public_format)

  def save_public_key_to_file(self, public_key: PublicKeyTypes, file_path: str) -> None:
    """Saves the public key to a file."""

    # Creates the file with the public key.
    create_file(file_path, self.serialize_public_key(public_key))

  def save_private_key_to_file(self, private_key: PrivateKeyTypes, file_path: str, password: str | bytes | None = None) -> None:
    """Saves the private key to a file."""

    # Creates the file with the private key.
    create_file(file_path, self.serialize_private_key(private_key, password))
  
  @staticmethod
  def load_public_key_from_file(file_path: str) -> PublicKeyTypes:
    """Loads the public key from a file."""

    # Load the public key from the file.
    with open(file_path, "rb") as file:
      file_buffer = file.read()

      try:
        public_key = serialization.load_pem_public_key(file_buffer)
      except Exception:
        try:
          public_key = serialization.load_der_public_key(file_buffer)
        except Exception:
          try:
            public_key = serialization.load_ssh_public_key(file_buffer)
          except Exception:
            raise ValueError("Invalid public key file format.")

    return public_key

  @staticmethod
  def load_private_key_from_file(file_path: str, password: str | bytes | None = None) -> PrivateKeyTypes:
    """Loads the private key from a file."""

    # Convert the password to bytes if it is a string.
    if isinstance(password, str):
      password = password.encode()

    # Load the private key from the file.
    with open(file_path, "rb") as file:
      file_buffer = file.read()

      try:
        private_key = serialization.load_pem_private_key(file_buffer, password)
      except Exception:
        try:
          private_key = serialization.load_der_private_key(file_buffer, password)
        except Exception:
          try:
            private_key = serialization.load_ssh_private_key(file_buffer, password)
          except Exception:
            raise ValueError("Invalid private key file format.")

    return private_key
