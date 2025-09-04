from cryptography.hazmat.primitives import hashes

from digital_signatures.utils.hasher import Hasher
from tests.fixtures.utils import fixture

hasher = Hasher(hashes.SHA256())

# The data to use for the tests.
str_message = 'Hello, world!'
bytes_message = b'Hello, world!'
file_path = fixture('hello_world.txt')
non_existent_file_path = 'nonexistent.txt'

messages = [str_message, bytes_message, file_path]

def assert_result(hash, message):
  # Check that the hash is a bytes object.
  assert isinstance(hash, bytes)

  # Check that the hash is the same as the generated hash for the same message.
  assert hash == hasher.hash(message)

# Test from_bytes.
def test_from_bytes_returns_bytes():
  assert_result(hasher.from_bytes(bytes_message), bytes_message)

# Test from_string.
def test_from_string_returns_bytes():
  assert_result(hasher.from_string(str_message), str_message)

# Test from_file.
def test_from_file_returns_bytes():
  assert_result(hasher.from_file(file_path), file_path)

def test_from_file_raises_file_not_found_error_when_file_does_not_exist():
  try:
    hasher.from_file(non_existent_file_path)
  except Exception as e:
    assert isinstance(e, FileNotFoundError)

# Test generate.
def test_generate_returns_bytes():
  for message in messages:
    assert_result(hasher.hash(message), message)

def test_generate_returns_bytes_when_file_does_not_exist():
  assert_result(hasher.hash(non_existent_file_path), non_existent_file_path)

def test_generate_raises_value_error_when_message_is_not_in_valid_types():
  try:
    hasher.hash(123)
  except Exception as e:
    assert isinstance(e, ValueError)