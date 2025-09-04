import os

from cryptography.hazmat.primitives import hashes

class Hasher:
  """This class is responsible for hashing the message."""

  algorithm: hashes.HashAlgorithm
  """The hashing algorithm to use."""

  DEFAULT_CHUNK_SIZE = 1024
  """The default chunk size for file reading."""

  def __init__(self, algorithm: hashes.HashAlgorithm):
    self.algorithm = algorithm

  def hash(self, message: str | bytes) -> bytes:
    """Generate the hash from the message."""

    # Handle bytes message.
    if isinstance(message, bytes):
      return self.from_bytes(message)
    
    if isinstance(message, str):
      # Handle file.
      if os.path.isfile(message):
        return self.from_file(message)

      # Handle string.
      return self.from_string(message)
    
    raise ValueError(f"Invalid message type: {type(message)}")

  def from_bytes(self, bytes: bytes) -> bytes:
    """Generate the hash from the bytes."""

    # Create a hash function.
    hash_function = hashes.Hash(self.algorithm)
    hash_function.update(bytes)

    return hash_function.finalize()

  def from_string(self, message: str) -> bytes:
    """Generate the hash from the string."""

    return self.from_bytes(message.encode())

  def from_file(self, file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """Generate the hash from the file."""

    # Use the default chunk size if the chunk size is not provided.
    if chunk_size <= 0:
      chunk_size = self.DEFAULT_CHUNK_SIZE

    # Check if the file exists.
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
      raise FileNotFoundError(f"File not found: {file_path}")

    # Create a hash function.
    hash_function = hashes.Hash(self.algorithm)

    # Read the file in chunks (to avoid memory issues).
    with open(file_path, 'rb') as file:
      while content := file.read(self.DEFAULT_CHUNK_SIZE):
        hash_function.update(content)

    return hash_function.finalize()
