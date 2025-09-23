from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from digital_signatures.utils.files import create_file

class CertificateStorage:
    """This class is responsible for storing X.509 certificates."""

    encoding_format: serialization.Encoding
    """The encoding format to use for the certificate."""

    def __init__(
        self,
        encoding_format: serialization.Encoding = serialization.Encoding.PEM,
    ):
        self.encoding_format = encoding_format

    def serialize_certificate(self, certificate: x509.Certificate) -> bytes:
        """Serializes the certificate to bytes."""
        return certificate.public_bytes(self.encoding_format)

    def save_certificate_to_file(self, certificate: x509.Certificate, file_path: str) -> None:
        """Saves the certificate to a file."""
        # Creates the file with the certificate.
        create_file(file_path, self.serialize_certificate(certificate))
    
    @staticmethod
    def save_certificate_chain_to_pem_file(certificates: list[x509.Certificate], file_path: str) -> None:
        """Saves a certificate chain to a PEM file.
        
        Args:
            certificates: List of certificates in chain order (end entity first, root last)
            file_path: Path where to save the certificate chain in PEM format.
        """
        if not certificates:
            raise ValueError("Certificate chain cannot be empty")
        
        # Serialize all certificates and concatenate them.
        chain_data = b""

        for certificate in certificates:
            chain_data += certificate.public_bytes(serialization.Encoding.PEM)
            chain_data += b"\n"
        
        create_file(file_path, chain_data)

    @staticmethod
    def load_certificate_from_file(file_path: str) -> x509.Certificate:
        """Loads a certificate from a file."""
        # Load the certificate from the file.
        with open(file_path, "rb") as file:
            file_buffer = file.read()

            try:
                certificate = x509.load_pem_x509_certificate(file_buffer)
            except Exception:
                try:
                    certificate = x509.load_der_x509_certificate(file_buffer)
                except Exception:
                    raise ValueError("Invalid certificate file format.")

        return certificate

    @staticmethod
    def load_certificate_chain_from_pem_file(file_path: str) -> list[x509.Certificate]:
        """Loads a certificate chain from a PEM file.
        
        Returns:
            List of certificates in the order they appear in the PEM file.
        """
        with open(file_path, "rb") as file:
            file_buffer = file.read()

        certificates = []
        
        # Try to parse as PEM first (can contain multiple certificates)
        try:
            # Split PEM content by certificate boundaries.
            pem_data = file_buffer.decode('utf-8')
            cert_start = "-----BEGIN CERTIFICATE-----"
            cert_end = "-----END CERTIFICATE-----"
            
            start_idx = 0
            while True:
                start_pos = pem_data.find(cert_start, start_idx)
                if start_pos == -1:
                    break
                
                end_pos = pem_data.find(cert_end, start_pos)
                if end_pos == -1:
                    break
                
                # Extract individual certificate.
                cert_pem = pem_data[start_pos:end_pos + len(cert_end)]
                certificate = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                certificates.append(certificate)
                
                start_idx = end_pos + len(cert_end)
        except Exception:
            raise ValueError("Invalid certificate chain file format.")
        
        if not certificates:
            raise ValueError("No certificates found in file.")
            
        return certificates

    def create_pkcs12_bundle(
        self, 
        private_key, 
        certificate: x509.Certificate, 
        ca_certificates: list[x509.Certificate] | None = None,
        password: str | bytes | None = None
    ) -> bytes:
        """Creates a PKCS#12 bundle containing private key, certificate and CA certificates.
        
        Args:
            private_key: The private key associated with the certificate
            certificate: The end entity certificate
            ca_certificates: Optional list of CA certificates to include in the bundle
            password: Optional password to protect the bundle
            
        Returns:
            PKCS#12 bundle as bytes
        """
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode()
        
        # Create PKCS#12 bundle
        return pkcs12.serialize_key_and_certificates(
            name=b"certificate",
            key=private_key,
            cert=certificate,
            cas=ca_certificates,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )

    def save_pkcs12_bundle_to_file(
        self, 
        private_key, 
        certificate: x509.Certificate, 
        file_path: str,
        ca_certificates: list[x509.Certificate] | None = None,
        password: str | bytes | None = None
    ) -> None:
        """Saves a PKCS#12 bundle to a file.
        
        Args:
            private_key: The private key associated with the certificate
            certificate: The end entity certificate
            file_path: Path where to save the PKCS#12 bundle
            ca_certificates: Optional list of CA certificates to include in the bundle
            password: Optional password to protect the bundle
        """
        bundle_data = self.create_pkcs12_bundle(private_key, certificate, ca_certificates, password)
        
        create_file(file_path, bundle_data)

    @staticmethod
    def load_pkcs12_bundle_from_file(file_path: str, password: str | bytes | None = None):
        """Loads a PKCS#12 bundle from a file.
        
        Args:
            file_path: Path to the PKCS#12 bundle file
            password: Password to decrypt the bundle
            
        Returns:
            Tuple of (private_key, certificate, ca_certificates)
        """
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode()
            
        with open(file_path, "rb") as file:
            file_buffer = file.read()
            
        try:
            private_key, certificate, ca_certificates = pkcs12.load_key_and_certificates(
                file_buffer, password
            )
            
            return private_key, certificate, ca_certificates
        except Exception as e:
            raise ValueError(f"Failed to load PKCS#12 bundle: {str(e)}")
