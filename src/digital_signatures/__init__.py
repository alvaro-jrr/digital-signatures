from cryptography.hazmat.primitives import hashes

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator
from digital_signatures.pki.certificate_generator.self_signed_certificate_generator import (
    SelfSignedCertificateGenerator,
)
from digital_signatures.pki.certificate_storage import CertificateStorage
from digital_signatures.pki.entity import Entity
from digital_signatures.utils.hasher import Hasher

def main() -> None:
    entity = Entity(
        name="Alvaro Resplandor",
        email="alvarojrr79@gmail.com",
        country="VE",
        state="Bolivar",
        locality="Puerto Ordaz", 
    )

    key_generator = EccKeyGenerator()
    hasher = Hasher(hashes.SHA256())
    certificate_storage = CertificateStorage()
    certificate_generator = SelfSignedCertificateGenerator(key_generator, hasher)

    # Generate a certificate.
    private_key, public_key, certificate = certificate_generator.generate(entity)

    # Save the certificate.
    certificate_storage.save_certificate_to_file(certificate, "certificate.pem")
    certificate_storage.save_pkcs12_bundle_to_file(private_key, certificate, "certificate.p12", [], "hola")