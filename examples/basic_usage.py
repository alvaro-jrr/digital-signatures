#!/usr/bin/env python3
"""
Basic usage example for the digital signatures library.

This script demonstrates how to:
1. Generate ECC key pairs
2. Sign messages using different data types
3. Verify signatures
4. Use different hash algorithms
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.crypto.signer.ecc_signer import EccSigner
from digital_signatures.crypto.verifier.ecc_verifier import EccVerifier
from digital_signatures.utils.hasher import Hasher


def main():
    print("🔐 Digital Signatures Library - Basic Usage Example")
    print("=" * 50)
    
    # Step 1: Generate a key pair
    print("\n1. Generating ECC key pair...")
    key_generator = EccKeyGenerator()
    private_key, public_key = key_generator.generate()
    print(f"   ✅ Generated key pair using {private_key.curve.name} curve")
    
    # Step 2: Create hash generator and signer
    print("\n2. Setting up signer and verifier...")
    hasher = Hasher(hashes.SHA256())
    signer = EccSigner(private_key, hasher)
    verifier = EccVerifier(public_key, hasher)
    print(f"   ✅ Using {hasher.algorithm.name} hash algorithm")
    
    # Step 3: Sign different types of messages
    print("\n3. Signing different types of messages...")
    
    # String message
    str_message = "Hello, world!"
    str_signature = signer.sign(str_message)
    print(f"   📝 Signed string: '{str_message}'")
    print(f"   📄 Signature length: {len(str_signature)} bytes")
    
    # Bytes message
    bytes_message = b"Binary data message"
    bytes_signature = signer.sign(bytes_message)
    print(f"   📝 Signed bytes: {bytes_message}")
    print(f"   📄 Signature length: {len(bytes_signature)} bytes")
    
    # Step 4: Verify signatures
    print("\n4. Verifying signatures...")
    
    # Verify string signature
    str_valid = verifier.verify(str_signature, str_message)
    print(f"   ✅ String signature valid: {str_valid}")
    
    # Verify bytes signature
    bytes_valid = verifier.verify(bytes_signature, bytes_message)
    print(f"   ✅ Bytes signature valid: {bytes_valid}")
    
    # Step 5: Demonstrate signature verification failure
    print("\n5. Testing signature verification with wrong message...")
    wrong_message = "Wrong message!"
    wrong_valid = verifier.verify(str_signature, wrong_message)
    print(f"   ❌ Wrong message verification: {wrong_valid}")
    
    # Step 6: Use different hash algorithm
    print("\n6. Using different hash algorithm (SHA384)...")
    sha384_generator = Hasher(hashes.SHA384())
    sha384_signer = EccSigner(private_key, sha384_generator)
    sha384_verifier = EccVerifier(public_key, sha384_generator)
    
    sha384_signature = sha384_signer.sign(str_message)
    sha384_valid = sha384_verifier.verify(sha384_signature, str_message)
    print(f"   📝 SHA384 signature length: {len(sha384_signature)} bytes")
    print(f"   ✅ SHA384 signature valid: {sha384_valid}")
    
    # Step 7: Performance demonstration
    print("\n7. Performance demonstration...")
    import time
    
    # Time multiple signing operations
    start_time = time.time()
    for i in range(100):
        signer.sign(f"Message {i}")
    signing_time = time.time() - start_time
    print(f"   ⚡ 100 signing operations: {signing_time:.3f} seconds")
    
    # Time multiple verification operations
    test_signature = signer.sign("Test message")
    start_time = time.time()
    for i in range(100):
        verifier.verify(test_signature, "Test message")
    verification_time = time.time() - start_time
    print(f"   ⚡ 100 verification operations: {verification_time:.3f} seconds")
    
    print("\n" + "=" * 50)
    print("🎉 Example completed successfully!")
    print("\nKey takeaways:")
    print("• ECC digital signatures provide strong security")
    print("• The library supports multiple data types (strings, bytes, files)")
    print("• Different hash algorithms can be used")
    print("• Signatures are deterministic and verifiable")
    print("• Performance is suitable for most applications")


if __name__ == "__main__":
    main()
