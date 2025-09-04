#!/usr/bin/env python3
"""
Advanced example demonstrating file signing and verification.

This script shows how to:
1. Sign file contents
2. Verify file signatures
3. Handle different file types
4. Demonstrate tamper detection
"""

import os
import tempfile
from cryptography.hazmat.primitives import hashes
from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.crypto.signer.ecc_signer import EccSigner
from digital_signatures.crypto.verifier.ecc_verifier import EccVerifier
from digital_signatures.utils.hasher import Hasher


def create_test_file(content: str, file_path: str):
    """Create a test file with the given content."""
    with open(file_path, 'w') as f:
        f.write(content)
    print(f"   📁 Created test file: {file_path}")


def sign_and_verify_file(file_path: str, signer: EccSigner, verifier: EccVerifier):
    """Sign a file and verify its signature."""
    print(f"\n📝 Signing file: {file_path}")
    
    # Sign the file
    signature = signer.sign(file_path)
    print(f"   ✅ File signed successfully")
    print(f"   📄 Signature length: {len(signature)} bytes")
    
    # Verify the signature
    is_valid = verifier.verify(signature, file_path)
    print(f"   ✅ Signature verification: {is_valid}")
    
    return signature


def demonstrate_tamper_detection(file_path: str, original_signature: bytes, verifier: EccVerifier):
    """Demonstrate how tampering is detected."""
    print(f"\n🔍 Demonstrating tamper detection...")
    
    # Read original content
    with open(file_path, 'r') as f:
        original_content = f.read()
    
    # Tamper with the file
    with open(file_path, 'w') as f:
        f.write(original_content + "\n# TAMPERED!")
    
    print(f"   ⚠️  File content modified")
    
    # Try to verify with tampered content
    is_valid = verifier.verify(original_signature, file_path)
    print(f"   ❌ Tampered file verification: {is_valid}")
    
    # Restore original content
    with open(file_path, 'w') as f:
        f.write(original_content)
    print(f"   🔄 File content restored")


def main():
    print("🔐 Digital Signatures Library - File Signing Example")
    print("=" * 55)
    
    # Setup
    print("\n1. Setting up cryptographic components...")
    key_generator = EccKeyGenerator()
    private_key, public_key = key_generator.generate()
    hasher = Hasher(hashes.SHA256())
    signer = EccSigner(private_key, hasher)
    verifier = EccVerifier(public_key, hasher)
    print(f"   ✅ Using {private_key.curve.name} curve and {hasher.algorithm.name}")
    
    # Create temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"\n2. Creating test files in: {temp_dir}")
        
        # Create different types of test files
        files_to_sign = []
        
        # Text file
        text_file = os.path.join(temp_dir, "document.txt")
        create_test_file("This is an important document that needs to be signed.\nIt contains sensitive information.", text_file)
        files_to_sign.append(text_file)
        
        # Configuration file
        config_file = os.path.join(temp_dir, "config.json")
        create_test_file('{"version": "1.0", "settings": {"debug": false, "timeout": 30}}', config_file)
        files_to_sign.append(config_file)
        
        # Large file (simulate)
        large_file = os.path.join(temp_dir, "large_data.txt")
        large_content = "Large file content\n" * 1000  # ~20KB
        create_test_file(large_content, large_file)
        files_to_sign.append(large_file)
        
        # Sign and verify each file
        print(f"\n3. Signing and verifying {len(files_to_sign)} files...")
        signatures = {}
        
        for file_path in files_to_sign:
            file_name = os.path.basename(file_path)
            print(f"\n--- Processing {file_name} ---")
            
            # Get file size
            file_size = os.path.getsize(file_path)
            print(f"   📊 File size: {file_size} bytes")
            
            # Sign and verify
            signature = sign_and_verify_file(file_path, signer, verifier)
            signatures[file_path] = signature
        
        # Demonstrate tamper detection
        print(f"\n4. Tamper detection demonstration...")
        demonstrate_tamper_detection(text_file, signatures[text_file], verifier)
        
        # Test with different hash algorithms
        print(f"\n5. Testing different hash algorithms...")
        algorithms = [
            ("SHA256", hashes.SHA256()),
            ("SHA384", hashes.SHA384()),
            ("SHA512", hashes.SHA512()),
        ]
        
        for name, algorithm in algorithms:
            print(f"\n   🔐 Using {name}...")
            hasher = Hasher(algorithm)
            test_signer = EccSigner(private_key, hasher)
            test_verifier = EccVerifier(public_key, hasher)
            
            signature = test_signer.sign(text_file)
            is_valid = test_verifier.verify(signature, text_file)
            print(f"   ✅ {name} signature valid: {is_valid}")
            print(f"   📄 {name} signature length: {len(signature)} bytes")
        
        # Performance comparison
        print(f"\n6. Performance comparison...")
        import time
        
        # Test signing performance with different file sizes
        test_files = [
            ("Small file (1KB)", text_file),
            ("Medium file (20KB)", large_file),
        ]
        
        for file_desc, file_path in test_files:
            print(f"\n   ⚡ Testing {file_desc}...")
            
            # Time signing
            start_time = time.time()
            for _ in range(10):
                signer.sign(file_path)
            signing_time = time.time() - start_time
            print(f"   📝 10 signing operations: {signing_time:.3f} seconds")
            
            # Time verification
            test_signature = signer.sign(file_path)
            start_time = time.time()
            for _ in range(10):
                verifier.verify(test_signature, file_path)
            verification_time = time.time() - start_time
            print(f"   ✅ 10 verification operations: {verification_time:.3f} seconds")
    
    print("\n" + "=" * 55)
    print("🎉 File signing example completed successfully!")
    print("\nKey takeaways:")
    print("• Files can be signed and verified just like text messages")
    print("• Any modification to the file will invalidate the signature")
    print("• Different hash algorithms provide different security levels")
    print("• File size affects performance but not security")
    print("• The library handles large files efficiently")


if __name__ == "__main__":
    main()
