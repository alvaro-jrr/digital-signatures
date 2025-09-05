from cryptography import x509
from cryptography.x509.oid import NameOID

class Entity:
  """
  This class represents an entity in the PKI.
  """

  name: str
  """The name of the entity."""

  email: str
  """The email of the entity."""

  country: str
  """The country of the entity."""

  state: str
  """The state of the entity."""

  locality: str
  """The locality of the entity."""

  organization: str | None
  """The organization of the entity."""

  organizational_unit: str | None
  """The organizational unit of the entity."""

  def __init__(self, name: str, email: str, country: str, state: str, locality: str, organization: str | None, organizational_unit: str | None):
    self.name = name
    self.email = email
    self.country = country
    self.state = state
    self.locality = locality
    self.organization = organization
    self.organizational_unit = organizational_unit

  def to_name(self) -> x509.Name:
    """Converts the entity to an x509 name."""

    attributes = [
      x509.NameAttribute(NameOID.COMMON_NAME, self.name),
      x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email),
      x509.NameAttribute(NameOID.COUNTRY_NAME, self.country),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state),
      x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality),
    ]
    
    # Only add organization and organizational_unit if they are not None
    if self.organization is not None:
      attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization))
    
    if self.organizational_unit is not None:
      attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit))

    return x509.Name(attributes)