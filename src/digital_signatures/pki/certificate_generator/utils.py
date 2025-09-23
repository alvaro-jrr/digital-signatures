from cryptography import x509

def create_distribution_points(crl_urls: list[str]) -> list[x509.DistributionPoint]:
  """Creates a list of distribution points for the CRL URLs."""
  distribution_points = []

  # Create a distribution point for each CRL URL.
  for url in crl_urls:
    distribution_points.append(
      x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(url)],
        relative_name=None,
        crl_issuer=None,
        reasons=None,
      )
    )
  
  return distribution_points

def append_crl_distribution_points(
  certificate_builder: x509.CertificateBuilder,
  crl_urls: list[str],
  critical: bool = False,
) -> x509.CertificateBuilder:
  """Appends the CRL distribution points to the certificate builder."""

  # Create the distribution points.
  distribution_points = create_distribution_points(crl_urls)

  if len(distribution_points) == 0:
    return certificate_builder

  # Append the distribution points to the certificate builder.
  return certificate_builder.add_extension(
    x509.CRLDistributionPoints(distribution_points),
    critical=critical,
  )