import pytest
from cryptography import x509

from digital_signatures.pki.certificate_generator.utils import (
    create_distribution_points,
    append_crl_distribution_points,
)


class TestCertificateGeneratorUtils:
    """Test cases for certificate generator utility functions."""

    def test_create_distribution_points_empty_list(self):
        """Test creating distribution points with empty CRL URLs list."""
        crl_urls = []
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 0

    def test_create_distribution_points_single_url(self):
        """Test creating distribution points with a single CRL URL."""
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 1
        
        dp = distribution_points[0]
        assert isinstance(dp, x509.DistributionPoint)
        assert dp.full_name is not None
        assert len(dp.full_name) == 1
        assert dp.full_name[0].value == "http://ca.example.com/crl/root-ca.crl"
        assert dp.relative_name is None
        assert dp.crl_issuer is None
        assert dp.reasons is None

    def test_create_distribution_points_multiple_urls(self):
        """Test creating distribution points with multiple CRL URLs."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl",
            "https://secure-ca.example.com/crl/root-ca.crl",
            "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 3
        
        # Check each distribution point
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]
            assert dp.relative_name is None
            assert dp.crl_issuer is None
            assert dp.reasons is None

    def test_create_distribution_points_https_urls(self):
        """Test creating distribution points with HTTPS URLs."""
        crl_urls = [
            "https://secure-ca.example.com/crl/root-ca.crl",
            "https://backup-ca.example.com/crl/root-ca.crl"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 2
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_ldap_urls(self):
        """Test creating distribution points with LDAP URLs."""
        crl_urls = [
            "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com",
            "ldaps://secure-ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 2
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_mixed_protocols(self):
        """Test creating distribution points with mixed protocol URLs."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl",
            "https://secure-ca.example.com/crl/root-ca.crl",
            "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com",
            "ftp://ftp.example.com/crl/root-ca.crl"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 4
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_special_characters(self):
        """Test creating distribution points with URLs containing special characters."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca-2024.crl",
            "https://secure-ca.example.com/crl/root-ca_v2.crl",
            "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 3
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_append_crl_distribution_points_empty_urls(self):
        """Test appending CRL distribution points with empty URLs list."""
        from cryptography import x509
        
        builder = x509.CertificateBuilder()
        crl_urls = []
        
        result_builder = append_crl_distribution_points(builder, crl_urls)
        
        # Should return the same builder without modifications
        assert result_builder is builder

    def test_append_crl_distribution_points_single_url(self):
        """Test appending CRL distribution points with a single URL."""
        from cryptography import x509
        
        builder = x509.CertificateBuilder()
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        
        result_builder = append_crl_distribution_points(builder, crl_urls)
        
        # Should return a modified builder
        assert result_builder is not None
        assert isinstance(result_builder, x509.CertificateBuilder)

    def test_append_crl_distribution_points_multiple_urls(self):
        """Test appending CRL distribution points with multiple URLs."""
        from cryptography import x509
        
        builder = x509.CertificateBuilder()
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl",
            "https://secure-ca.example.com/crl/root-ca.crl"
        ]
        
        result_builder = append_crl_distribution_points(builder, crl_urls)
        
        # Should return a modified builder
        assert result_builder is not None
        assert isinstance(result_builder, x509.CertificateBuilder)

    def test_append_crl_distribution_points_critical_false(self):
        """Test appending CRL distribution points with critical=False (default)."""
        from cryptography import x509
        
        builder = x509.CertificateBuilder()
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        
        result_builder = append_crl_distribution_points(builder, crl_urls, critical=False)
        
        # Should return a modified builder
        assert result_builder is not None
        assert isinstance(result_builder, x509.CertificateBuilder)

    def test_append_crl_distribution_points_critical_true(self):
        """Test appending CRL distribution points with critical=True."""
        from cryptography import x509
        
        builder = x509.CertificateBuilder()
        crl_urls = ["http://ca.example.com/crl/root-ca.crl"]
        
        result_builder = append_crl_distribution_points(builder, crl_urls, critical=True)
        
        # Should return a modified builder
        assert result_builder is not None
        assert isinstance(result_builder, x509.CertificateBuilder)

    def test_append_crl_distribution_points_none_urls(self):
        """Test appending CRL distribution points with None URLs."""
        from cryptography import x509
        
        builder = x509.CertificateBuilder()
        crl_urls = None
        
        # Should handle None gracefully
        with pytest.raises((TypeError, AttributeError)):
            append_crl_distribution_points(builder, crl_urls)

    def test_create_distribution_points_preserves_url_format(self):
        """Test that distribution points preserve the exact URL format."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl",
            "https://secure-ca.example.com/crl/root-ca.crl",
            "ldap://ldap.example.com/cn=root-ca,ou=crl,dc=example,dc=com",
            "ftp://ftp.example.com/crl/root-ca.crl"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        for i, dp in enumerate(distribution_points):
            url_value = dp.full_name[0].value
            assert url_value == crl_urls[i]

    def test_create_distribution_points_with_encoded_urls(self):
        """Test creating distribution points with percent-encoded URLs."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca%20test.crl",
            "https://secure-ca.example.com/crl/root-ca%2Dv2.crl"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 2
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_with_query_parameters(self):
        """Test creating distribution points with URLs containing query parameters."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl?version=1",
            "https://secure-ca.example.com/crl/root-ca.crl?format=pem&version=2"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 2
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_with_fragments(self):
        """Test creating distribution points with URLs containing fragments."""
        crl_urls = [
            "http://ca.example.com/crl/root-ca.crl#section1",
            "https://secure-ca.example.com/crl/root-ca.crl#latest"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 2
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_with_ports(self):
        """Test creating distribution points with URLs containing ports."""
        crl_urls = [
            "http://ca.example.com:8080/crl/root-ca.crl",
            "https://secure-ca.example.com:8443/crl/root-ca.crl",
            "ldap://ldap.example.com:389/cn=root-ca,ou=crl,dc=example,dc=com"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 3
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]

    def test_create_distribution_points_with_paths(self):
        """Test creating distribution points with complex URL paths."""
        crl_urls = [
            "http://ca.example.com/path/to/crl/root-ca.crl",
            "https://secure-ca.example.com/api/v1/crl/root-ca.crl",
            "ldap://ldap.example.com/ou=crl,dc=example,dc=com?cn=root-ca"
        ]
        
        distribution_points = create_distribution_points(crl_urls)
        
        assert isinstance(distribution_points, list)
        assert len(distribution_points) == 3
        
        for i, dp in enumerate(distribution_points):
            assert isinstance(dp, x509.DistributionPoint)
            assert dp.full_name is not None
            assert len(dp.full_name) == 1
            assert dp.full_name[0].value == crl_urls[i]
