# Digital Signatures

A Python library for creating and verifying digital signatures. This project provides a clean, type-safe interface for cryptographic operations with support for multiple hash algorithms and elliptic curves.

## Features

- 🔐 **Elliptic Curve Cryptography (ECC)** - Secure digital signatures using ECDSA
- 🔑 **Key Generation** - Automatic generation of ECC key pairs
- 📝 **Message Signing** - Sign strings, bytes, and files
- ✅ **Signature Verification** - Verify signatures with public keys
- 🗜️ **Multiple Hash Algorithms** - Support for SHA256, SHA384, SHA512, and more
- 📁 **File Support** - Sign and verify file contents
- 🧪 **Comprehensive Testing** - Full test coverage with pytest
- 🏗️ **Extensible Architecture** - Abstract base classes for easy extension

## Installation

This project uses [uv](https://github.com/astral-sh/uv) as the package manager. Make sure you have uv installed.

### Prerequisites

- Python 3.13 or higher
- uv package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd digital-signatures
```

2. Install dependencies:
```bash
uv sync
```

## Usage

### Quick Start

For a complete walkthrough, see the [examples directory](examples/):

```bash
# Run basic usage example
uv run python examples/basic_usage.py

# Run file signing example
uv run python examples/file_signing.py
```

### Basic Example

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.crypto.signer.ecc_signer import EccSigner
from digital_signatures.crypto.verifier.ecc_verifier import EccVerifier
from digital_signatures.utils.hash_generator import HashGenerator

# Generate a key pair
key_generator = EccKeyGenerator()
private_key, public_key = key_generator.generate()

# Create hash generator and signer
hash_generator = HashGenerator(hashes.SHA256())
signer = EccSigner(private_key, hash_generator)

# Sign a message
message = "Hello, world!"
signature = signer.sign(message)

# Verify the signature
verifier = EccVerifier(public_key, hash_generator)
is_valid = verifier.verify(signature, message)
print(f"Signature is valid: {is_valid}")  # True
```

### Signing Different Types of Data

```python
# Sign a string
signature1 = signer.sign("Hello, world!")

# Sign bytes
signature2 = signer.sign(b"Hello, world!")

# Sign a file
signature3 = signer.sign("path/to/file.txt")
```

### Using Different Hash Algorithms

```python
# SHA384
sha384_generator = HashGenerator(hashes.SHA384())
sha384_signer = EccSigner(private_key, sha384_generator)
signature = sha384_signer.sign(message)

# SHA512
sha512_generator = HashGenerator(hashes.SHA512())
sha512_verifier = EccVerifier(public_key, sha512_generator)
is_valid = sha512_verifier.verify(signature, message)
```

## API Reference

### Key Generation

#### `EccKeyGenerator`

Generates ECC key pairs using the SECP256R1 curve.

```python
from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator

key_generator = EccKeyGenerator()
private_key, public_key = key_generator.generate()
```

**Methods:**
- `generate() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]`: Generates a new key pair

### Signing

#### `EccSigner`

Creates digital signatures using ECC private keys.

```python
from digital_signatures.crypto.signer.ecc_signer import EccSigner

signer = EccSigner(private_key, hash_generator)
```

**Constructor:**
- `private_key`: ECC private key
- `hash_generator`: Hash generator instance

**Methods:**
- `sign(message: str | bytes) -> bytes`: Signs the message and returns the signature

### Verification

#### `EccVerifier`

Verifies digital signatures using ECC public keys.

```python
from digital_signatures.crypto.verifier.ecc_verifier import EccVerifier

verifier = EccVerifier(public_key, hash_generator)
```

**Constructor:**
- `public_key`: ECC public key
- `hash_generator`: Hash generator instance

**Methods:**
- `verify(signature: bytes, message: str | bytes) -> bool`: Verifies the signature and returns True if valid

### Hash Generation

#### `Hasher`

Generates cryptographic hashes for messages.

```python
from digital_signatures.utils.hash_generator import HashGenerator

hash_generator = HashGenerator(hashes.SHA256())
```

**Constructor:**
- `algorithm`: Hash algorithm (e.g., `hashes.SHA256()`, `hashes.SHA384()`, `hashes.SHA512()`)

**Methods:**
- `generate(message: str | bytes) -> bytes`: Generates hash from message
- `from_bytes(bytes: bytes) -> bytes`: Generates hash from bytes
- `from_string(message: str) -> bytes`: Generates hash from string
- `from_file(file_path: str, chunk_size: int = 1024) -> bytes`: Generates hash from file

## Development

### Running Examples

The project includes comprehensive examples demonstrating library usage:

```bash
# Basic usage example
uv run python examples/basic_usage.py

# File signing example
uv run python examples/file_signing.py
```

### Running Tests

The project uses [pytest](https://docs.pytest.org/en/stable/) for testing. To run the tests:

```bash
uv run pytest
```

To run tests with verbose output:
```bash
uv run pytest -v
```

To run specific test files:
```bash
uv run pytest tests/crypto/signer/ecc_signer_test.py
```

### Project Structure

```
digital-signatures/
├── src/digital_signatures/
│   ├── crypto/
│   │   ├── key_generator/
│   │   │   ├── base.py              # Abstract key generator
│   │   │   └── ecc_key_generator.py # ECC key generation
│   │   ├── signer/
│   │   │   ├── base.py              # Abstract signer
│   │   │   └── ecc_signer.py        # ECC signing
│   │   └── verifier/
│   │       ├── base.py              # Abstract verifier
│   │       └── ecc_verifier.py      # ECC verification
│   ├── utils/
│   │   └── hasher.py                # Hash generation utilities
│   └── __init__.py
├── tests/
│   ├── crypto/
│   │   ├── key_generator/
│   │   ├── signer/
│   │   └── verifier/
│   ├── utils/
│   └── fixtures/
├── pyproject.toml
└── README.md
```

### Adding New Features

The project is designed with extensibility in mind:

1. **New Hash Algorithms**: Add support by using different `hashes.HashAlgorithm` instances
2. **New Curves**: Extend `EccKeyGenerator` to support additional elliptic curves
3. **New Signing Algorithms**: Implement new signer classes inheriting from `Signer`
4. **New Verification Algorithms**: Implement new verifier classes inheriting from `Verifier`

### Code Style

- Follow PEP 8 guidelines
- Use type hints throughout
- Write comprehensive docstrings
- Maintain test coverage

## Security Considerations

- **Key Management**: Always store private keys securely and never share them
- **Key Generation**: Use cryptographically secure random number generators
- **Hash Algorithms**: Choose appropriate hash algorithms based on security requirements
- **Curve Selection**: Consider the security level of different elliptic curves
- **Signature Verification**: Always verify signatures before trusting signed data

## Dependencies

- **cryptography**: Core cryptographic operations
- **pytest**: Testing framework (dev dependency)
