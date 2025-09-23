"""
Certificate storage example for the digital signatures library.

This script demonstrates how to:
1. Generate certificates (root, intermediate, end entity)
2. Store certificates in different formats (PEM, DER)
3. Save certificate chains
4. Create and manage PKCS#12 bundles
5. Load certificates back from storage
"""

import os
import tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import (
  PrivateKeyTypes,
  PublicKeyTypes,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate
from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.crypto.key_storage import KeyStorage
from digital_signatures.pki.certificate_generator.root_certificate_generator import RootCertificateGenerator
from digital_signatures.pki.certificate_generator.intermediate_certificate_generator import IntermediateCertificateGenerator
from digital_signatures.pki.certificate_generator.end_entity_certificate_generator import EndEntityCertificateGenerator
from digital_signatures.pki.certificate_storage import CertificateStorage
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher

def create_certificate_hierarchy():
    """Create a complete certificate hierarchy: Root -> Intermediate -> End Entity."""
    print("\n🔗 Creating certificate hierarchy...")
    
    # Setup
    key_generator = EccKeyGenerator()
    hasher = Hasher(hashes.SHA256())
    
    # Root CA
    print("   📋 Creating Root CA certificate...")
    root_generator = RootCertificateGenerator(key_generator, hasher)
    root_entity = Entity(
        name="Example Root CA",
        email="root-ca@example.com",
        country="US",
        state="CA",
        locality="San Francisco",
        organization="Example Corp",
        organizational_unit="Root Certificate Authority"
    )
    root_private_key, root_public_key, root_certificate = root_generator.generate(root_entity)
    print(f"   ✅ Root CA certificate created (Serial: {root_certificate.serial_number})")
    
    # Intermediate CA
    print("   📋 Creating Intermediate CA certificate...")
    intermediate_generator = IntermediateCertificateGenerator(key_generator, hasher)
    intermediate_entity = Entity(
        name="Example Intermediate CA",
        email="intermediate-ca@example.com",
        country="US",
        state="CA",
        locality="San Francisco",
        organization="Example Corp",
        organizational_unit="Intermediate Certificate Authority"
    )
    intermediate_private_key, intermediate_public_key, intermediate_certificate = intermediate_generator.generate(
        intermediate_entity, root_certificate, root_private_key
    )
    print(f"   ✅ Intermediate CA certificate created (Serial: {intermediate_certificate.serial_number})")
    
    # End Entity Certificate
    print("   📋 Creating End Entity certificate...")
    ee_generator = EndEntityCertificateGenerator(key_generator, hasher)
    ee_entity = Entity(
        name="Example Server",
        email="server@example.com",
        country="US",
        state="CA",
        locality="San Francisco",
        organization="Example Corp",
        organizational_unit="IT Department"
    )
    ee_private_key, ee_public_key, ee_certificate = ee_generator.generate(
        ee_entity, intermediate_certificate, intermediate_private_key
    )
    print(f"   ✅ End Entity certificate created (Serial: {ee_certificate.serial_number})")
    
    return {
        'root': (root_private_key, root_public_key, root_certificate),
        'intermediate': (intermediate_private_key, intermediate_public_key, intermediate_certificate),
        'end_entity': (ee_private_key, ee_public_key, ee_certificate)
    }


def demonstrate_certificate_storage(certificates: dict[str, tuple[PrivateKeyTypes, PublicKeyTypes, Certificate]]):
    """Demonstrate different certificate storage formats."""
    print("\n💾 Demonstrating certificate storage...")
    
    root_private_key, root_public_key, root_certificate = certificates['root']
    intermediate_private_key, intermediate_public_key, intermediate_certificate = certificates['intermediate']
    ee_private_key, ee_public_key, ee_certificate = certificates['end_entity']
    
    # Create temporary directory for demonstration
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"   📁 Using temporary directory: {temp_dir}")
        
        # 1. Store individual certificates in PEM format
        print("\n   📄 Storing individual certificates in PEM format...")
        pem_storage = CertificateStorage()  # Default is PEM
        
        root_pem_path = os.path.join(temp_dir, "root-ca.pem")
        intermediate_pem_path = os.path.join(temp_dir, "intermediate-ca.pem")
        ee_pem_path = os.path.join(temp_dir, "server.pem")
        
        pem_storage.save_certificate_to_file(root_certificate, root_pem_path)
        pem_storage.save_certificate_to_file(intermediate_certificate, intermediate_pem_path)
        pem_storage.save_certificate_to_file(ee_certificate, ee_pem_path)
        
        print(f"      ✅ Root CA saved to: {os.path.basename(root_pem_path)}")
        print(f"      ✅ Intermediate CA saved to: {os.path.basename(intermediate_pem_path)}")
        print(f"      ✅ End Entity saved to: {os.path.basename(ee_pem_path)}")
        
        # Show file sizes
        print(f"      📊 File sizes: Root={os.path.getsize(root_pem_path)} bytes, "
              f"Intermediate={os.path.getsize(intermediate_pem_path)} bytes, "
              f"EE={os.path.getsize(ee_pem_path)} bytes")
        
        # 2. Store individual certificates in DER format
        print("\n   📄 Storing individual certificates in DER format...")
        der_storage = CertificateStorage(encoding_format=serialization.Encoding.DER)
        
        root_der_path = os.path.join(temp_dir, "root-ca.der")
        intermediate_der_path = os.path.join(temp_dir, "intermediate-ca.der")
        ee_der_path = os.path.join(temp_dir, "server.der")
        
        der_storage.save_certificate_to_file(root_certificate, root_der_path)
        der_storage.save_certificate_to_file(intermediate_certificate, intermediate_der_path)
        der_storage.save_certificate_to_file(ee_certificate, ee_der_path)
        
        print(f"      ✅ Root CA saved to: {os.path.basename(root_der_path)}")
        print(f"      ✅ Intermediate CA saved to: {os.path.basename(intermediate_der_path)}")
        print(f"      ✅ End Entity saved to: {os.path.basename(ee_der_path)}")
        
        # Show file sizes (DER is typically smaller)
        print(f"      📊 File sizes: Root={os.path.getsize(root_der_path)} bytes, "
              f"Intermediate={os.path.getsize(intermediate_der_path)} bytes, "
              f"EE={os.path.getsize(ee_der_path)} bytes")
        
        # 3. Store certificate chain
        print("\n   🔗 Storing certificate chain...")
        chain_path = os.path.join(temp_dir, "certificate-chain.pem")
        certificate_chain = [ee_certificate, intermediate_certificate, root_certificate]
        
        pem_storage.save_certificate_chain_to_pem_file(certificate_chain, chain_path)
        print(f"      ✅ Certificate chain saved to: {os.path.basename(chain_path)}")
        print(f"      📊 Chain file size: {os.path.getsize(chain_path)} bytes")
        
        # 4. Store private keys alongside certificates
        print("\n   🔐 Storing private keys...")
        key_storage = KeyStorage()
        
        root_key_path = os.path.join(temp_dir, "root-ca-key.pem")
        intermediate_key_path = os.path.join(temp_dir, "intermediate-ca-key.pem")
        ee_key_path = os.path.join(temp_dir, "server-key.pem")
        
        key_storage.save_private_key_to_file(root_private_key, root_key_path, password="root-password")
        key_storage.save_private_key_to_file(intermediate_private_key, intermediate_key_path, password="intermediate-password")
        key_storage.save_private_key_to_file(ee_private_key, ee_key_path, password="server-password")
        
        print(f"      ✅ Root CA private key saved (encrypted)")
        print(f"      ✅ Intermediate CA private key saved (encrypted)")
        print(f"      ✅ End Entity private key saved (encrypted)")
        
        # 5. Create PKCS#12 bundles
        print("\n   📦 Creating PKCS#12 bundles...")
        
        # Server bundle (most common use case)
        server_p12_path = os.path.join(temp_dir, "server.p12")
        pem_storage.save_pkcs12_bundle_to_file(
            ee_private_key,
            ee_certificate,
            server_p12_path,
            ca_certificates=[intermediate_certificate, root_certificate],
            password="server-bundle-password"
        )
        print(f"      ✅ Server PKCS#12 bundle saved: {os.path.basename(server_p12_path)}")
        print(f"      📊 Bundle size: {os.path.getsize(server_p12_path)} bytes")
            
        # Intermediate CA bundle
        intermediate_p12_path = os.path.join(temp_dir, "intermediate-ca.p12")
        pem_storage.save_pkcs12_bundle_to_file(
            intermediate_private_key,
            intermediate_certificate,
            intermediate_p12_path,
            ca_certificates=[root_certificate],
            password="intermediate-bundle-password"
        )
        print(f"      ✅ Intermediate CA PKCS#12 bundle saved: {os.path.basename(intermediate_p12_path)}")
        
        # 6. Demonstrate loading certificates back
        print("\n   📖 Loading certificates back from storage...")
        
        # Load individual certificates
        loaded_root = pem_storage.load_certificate_from_file(root_pem_path)
        loaded_intermediate = pem_storage.load_certificate_from_file(intermediate_pem_path)
        loaded_ee = pem_storage.load_certificate_from_file(ee_pem_path)
        
        print(f"      ✅ Loaded Root CA: {loaded_root.subject.rfc4514_string()}")
        print(f"      ✅ Loaded Intermediate CA: {loaded_intermediate.subject.rfc4514_string()}")
        print(f"      ✅ Loaded End Entity: {loaded_ee.subject.rfc4514_string()}")
        
        # Load certificate chain
        loaded_chain = pem_storage.load_certificate_chain_from_pem_file(chain_path)
        print(f"      ✅ Loaded certificate chain with {len(loaded_chain)} certificates")
        
        # Load PKCS#12 bundle
        loaded_key, loaded_cert, loaded_cas = pem_storage.load_pkcs12_bundle_from_file(
            server_p12_path, 
            "server-bundle-password"
        )
        print(f"      ✅ Loaded PKCS#12 bundle: certificate + private key + {len(loaded_cas or [])} CA certificates")
        
        # 7. Verify loaded certificates match originals
        print("\n   🔍 Verifying loaded certificates...")
        
        # Verify subjects match
        assert loaded_root.subject == root_certificate.subject
        assert loaded_intermediate.subject == intermediate_certificate.subject
        assert loaded_ee.subject == ee_certificate.subject
        assert loaded_cert.subject == ee_certificate.subject
        
        # Verify serial numbers match
        assert loaded_root.serial_number == root_certificate.serial_number
        assert loaded_intermediate.serial_number == intermediate_certificate.serial_number
        assert loaded_ee.serial_number == ee_certificate.serial_number
        
        print("      ✅ All certificate verifications passed!")
        
        # 8. Show directory contents
        print(f"\n   📂 Generated files in {temp_dir}:")
        for file_name in sorted(os.listdir(temp_dir)):
            file_path = os.path.join(temp_dir, file_name)
            file_size = os.path.getsize(file_path)
            print(f"      📄 {file_name} ({file_size} bytes)")


def demonstrate_certificate_validation(certificates: dict[str, tuple[PrivateKeyTypes, PublicKeyTypes, Certificate]]):
    """Demonstrate certificate validation and chain verification."""
    print("\n🔍 Demonstrating certificate validation...")
    
    root_private_key, root_public_key, root_certificate = certificates['root']
    intermediate_private_key, intermediate_public_key, intermediate_certificate = certificates['intermediate']
    ee_private_key, ee_public_key, ee_certificate = certificates['end_entity']
    
    # Basic certificate information
    print("\n   📋 Certificate Information:")
    print(f"      Root CA Subject: {root_certificate.subject.rfc4514_string()}")
    print(f"      Root CA Valid: {root_certificate.not_valid_before_utc} to {root_certificate.not_valid_after_utc}")
    print(f"      Root CA Serial: {root_certificate.serial_number}")
    
    print(f"      Intermediate CA Subject: {intermediate_certificate.subject.rfc4514_string()}")
    print(f"      Intermediate CA Issuer: {intermediate_certificate.issuer.rfc4514_string()}")
    print(f"      Intermediate CA Valid: {intermediate_certificate.not_valid_before_utc} to {intermediate_certificate.not_valid_after_utc}")
    
    print(f"      End Entity Subject: {ee_certificate.subject.rfc4514_string()}")
    print(f"      End Entity Issuer: {ee_certificate.issuer.rfc4514_string()}")
    print(f"      End Entity Valid: {ee_certificate.not_valid_before_utc} to {ee_certificate.not_valid_after_utc}")
    
    # Certificate extensions
    print("\n   🔧 Certificate Extensions:")
    for cert_name, certificate in [("Root", root_certificate), ("Intermediate", intermediate_certificate), ("End Entity", ee_certificate)]:
        print(f"      {cert_name} CA Extensions:")
        for extension in certificate.extensions:
            print(f"        - {extension.oid._name}: {extension.critical}")
    
    # Verify certificate chain relationships
    print("\n   🔗 Certificate Chain Verification:")
    
    # Verify intermediate is signed by root
    try:
        root_public_key.verify(
            intermediate_certificate.signature,
            intermediate_certificate.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        print("      ✅ Intermediate certificate is properly signed by Root CA")
    except Exception as e:
        print(f"      ❌ Intermediate certificate verification failed: {e}")
    
    # Note: Full chain verification would require additional cryptography library features
    print("      ℹ️  Full chain verification requires additional validation logic")


def demonstrate_use_cases():
    """Demonstrate common certificate storage use cases."""
    print("\n💼 Common Certificate Storage Use Cases:")
    
    print("\n   1. 🌐 Web Server Deployment:")
    print("      • Store server certificate and private key separately")
    print("      • Keep intermediate certificates in a chain file")
    print("      • Use PKCS#12 bundles for application deployment")
    print("      • Files: server.crt, server.key, intermediate-chain.pem")
    
    print("\n   2. 🔐 Certificate Authority Management:")
    print("      • Store root CA private key securely (offline/HSM)")
    print("      • Keep intermediate CA certificates and keys accessible")
    print("      • Maintain certificate revocation lists (CRLs)")
    print("      • Files: root-ca.crt, root-ca.key, intermediate-ca.crt, intermediate-ca.key")
    
    print("\n   3. 📱 Client Certificate Authentication:")
    print("      • Distribute client certificates as PKCS#12 bundles")
    print("      • Include full certificate chain in bundle")
    print("      • Password-protect bundles for security")
    print("      • Files: client.p12 (contains cert + key + CA chain)")
    
    print("\n   4. 🔄 Certificate Renewal:")
    print("      • Backup old certificates before renewal")
    print("      • Maintain multiple versions during transition")
    print("      • Update certificate chains as needed")
    print("      • Files: cert-v1.pem, cert-v2.pem, cert-current.pem (symlink)")
    
    print("\n   5. 📊 Certificate Monitoring:")
    print("      • Store certificates with metadata")
    print("      • Track expiration dates and renewal schedules")
    print("      • Monitor certificate chain health")
    print("      • Files: certificates/ directory with organized structure")


def main():
    print("🔐 Digital Signatures Library - Certificate Storage Example")
    print("=" * 60)
    
    # Step 1: Create certificate hierarchy
    certificates = create_certificate_hierarchy()
    
    # Step 2: Demonstrate storage formats
    demonstrate_certificate_storage(certificates)
    
    # Step 3: Show certificate validation
    demonstrate_certificate_validation(certificates)
    
    # Step 4: Explain use cases
    demonstrate_use_cases()
    
    print("\n" + "=" * 60)
    print("🎉 Certificate storage example completed successfully!")
    print("\nKey takeaways:")
    print("• Certificates can be stored in PEM or DER formats")
    print("• Certificate chains simplify deployment and verification")
    print("• PKCS#12 bundles provide convenient packaging for certificates + keys")
    print("• Different use cases require different storage strategies")
    print("• Always protect private keys with strong passwords")
    print("• Consider security implications of certificate storage locations")
    
    print("\n📚 Next steps:")
    print("• Implement certificate validation and chain verification")
    print("• Add certificate revocation list (CRL) support")
    print("• Create certificate management utilities")
    print("• Add automated certificate renewal workflows")


if __name__ == "__main__":
    # Import serialization module for the example
    from cryptography.hazmat.primitives import serialization
    main()
