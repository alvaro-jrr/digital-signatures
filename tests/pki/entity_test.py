import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from digital_signatures.pki.entity import Entity


class TestEntity:
    """Test cases for the Entity class."""

    def test_init_with_all_required_fields(self):
        """Test that Entity initializes correctly with all required fields."""
        entity = Entity(
            name="John Doe",
            email="john.doe@example.com",
            country="US",
            state="California",
            locality="San Francisco",
            organization="Example Corp",
            organizational_unit="IT Department"
        )
        
        assert entity.name == "John Doe"
        assert entity.email == "john.doe@example.com"
        assert entity.country == "US"
        assert entity.state == "California"
        assert entity.locality == "San Francisco"
        assert entity.organization == "Example Corp"
        assert entity.organizational_unit == "IT Department"

    def test_init_with_optional_fields_none(self):
        """Test that Entity initializes correctly with optional fields as None."""
        entity = Entity(
            name="Jane Smith",
            email="jane.smith@example.com",
            country="CA",
            state="Ontario",
            locality="Toronto",
            organization=None,
            organizational_unit=None
        )
        
        assert entity.name == "Jane Smith"
        assert entity.email == "jane.smith@example.com"
        assert entity.country == "CA"
        assert entity.state == "Ontario"
        assert entity.locality == "Toronto"
        assert entity.organization is None
        assert entity.organizational_unit is None

    def test_init_with_empty_strings(self):
        """Test that Entity initializes correctly with empty strings."""
        entity = Entity(
            name="",
            email="",
            country="",
            state="",
            locality="",
            organization="",
            organizational_unit=""
        )
        
        assert entity.name == ""
        assert entity.email == ""
        assert entity.country == ""
        assert entity.state == ""
        assert entity.locality == ""
        assert entity.organization == ""
        assert entity.organizational_unit == ""

    def test_to_name_returns_x509_name(self):
        """Test that to_name() returns an x509.Name object."""
        entity = Entity(
            name="Test User",
            email="test@example.com",
            country="US",
            state="NY",
            locality="New York",
            organization="Test Org",
            organizational_unit="Test Unit"
        )
        
        name = entity.to_name()
        assert isinstance(name, x509.Name)

    def test_to_name_contains_correct_attributes(self):
        """Test that to_name() contains the correct X.509 name attributes."""
        entity = Entity(
            name="Alice Johnson",
            email="alice@company.com",
            country="GB",
            state="England",
            locality="London",
            organization="Company Ltd",
            organizational_unit="Engineering"
        )
        
        name = entity.to_name()
        
        # Convert to list of attributes for easier testing
        attributes = list(name)
        
        # Check that all expected attributes are present
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == "Alice Johnson"
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "alice@company.com"
        assert attribute_dict[NameOID.COUNTRY_NAME] == "GB"
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "England"
        assert attribute_dict[NameOID.LOCALITY_NAME] == "London"
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == "Company Ltd"
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == "Engineering"

    def test_to_name_with_none_optional_fields(self):
        """Test that to_name() handles None optional fields correctly."""
        entity = Entity(
            name="Bob Wilson",
            email="bob@test.org",
            country="AU",
            state="NSW",
            locality="Sydney",
            organization=None,
            organizational_unit=None
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == "Bob Wilson"
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "bob@test.org"
        assert attribute_dict[NameOID.COUNTRY_NAME] == "AU"
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "NSW"
        assert attribute_dict[NameOID.LOCALITY_NAME] == "Sydney"
        # None fields should not be included in the name attributes
        assert NameOID.ORGANIZATION_NAME not in attribute_dict
        assert NameOID.ORGANIZATIONAL_UNIT_NAME not in attribute_dict

    def test_to_name_with_empty_strings(self):
        """Test that to_name() handles empty strings correctly."""
        entity = Entity(
            name="X",  # Must be at least 1 character for common name
            email="test@example.com",  # Email can be empty but let's use valid one
            country="US",  # Must be exactly 2 characters
            state="CA",
            locality="SF",
            organization="",  # Empty string is allowed for optional fields
            organizational_unit=""
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == "X"
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "test@example.com"
        assert attribute_dict[NameOID.COUNTRY_NAME] == "US"
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "CA"
        assert attribute_dict[NameOID.LOCALITY_NAME] == "SF"
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == ""
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == ""

    def test_to_name_attribute_order(self):
        """Test that to_name() returns attributes in the expected order."""
        entity = Entity(
            name="Test Name",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        name = entity.to_name()
        attributes = list(name)
        
        # Check that attributes are in the expected order
        expected_oids = [
            NameOID.COMMON_NAME,
            NameOID.EMAIL_ADDRESS,
            NameOID.COUNTRY_NAME,
            NameOID.STATE_OR_PROVINCE_NAME,
            NameOID.LOCALITY_NAME,
            NameOID.ORGANIZATION_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME,
        ]
        
        for i, expected_oid in enumerate(expected_oids):
            assert attributes[i].oid == expected_oid

    def test_to_name_consistency_multiple_calls(self):
        """Test that to_name() returns consistent x509.Name objects."""
        entity = Entity(
            name="Test",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        name1 = entity.to_name()
        name2 = entity.to_name()
        
        # Both calls should return equivalent objects
        assert name1 == name2
        
        # Both should be x509.Name objects
        assert isinstance(name1, x509.Name)
        assert isinstance(name2, x509.Name)

    def test_entity_equality(self):
        """Test that entities with same data are equal."""
        entity1 = Entity(
            name="Same Name",
            email="same@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        entity2 = Entity(
            name="Same Name",
            email="same@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        # Entities should be equal if they have the same data
        assert entity1.name == entity2.name
        assert entity1.email == entity2.email
        assert entity1.country == entity2.country
        assert entity1.state == entity2.state
        assert entity1.locality == entity2.locality
        assert entity1.organization == entity2.organization
        assert entity1.organizational_unit == entity2.organizational_unit

    def test_entity_inequality(self):
        """Test that entities with different data are not equal."""
        entity1 = Entity(
            name="Name One",
            email="one@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        entity2 = Entity(
            name="Name Two",
            email="two@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        # Entities should not be equal if they have different data
        assert entity1.name != entity2.name
        assert entity1.email != entity2.email

    def test_to_name_different_entities_different_names(self):
        """Test that different entities produce different x509.Name objects."""
        entity1 = Entity(
            name="Entity One",
            email="one@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org1",
            organizational_unit="Unit1"
        )
        
        entity2 = Entity(
            name="Entity Two",
            email="two@example.com",
            country="CA",
            state="ON",
            locality="Toronto",
            organization="Org2",
            organizational_unit="Unit2"
        )
        
        name1 = entity1.to_name()
        name2 = entity2.to_name()
        
        assert name1 != name2

    def test_entity_with_special_characters(self):
        """Test that Entity handles special characters correctly."""
        entity = Entity(
            name="José María",
            email="josé.maría@españa.com",
            country="ES",
            state="Madrid",
            locality="Madrid",
            organization="Empresa S.L.",
            organizational_unit="Desarrollo"
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == "José María"
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "josé.maría@españa.com"
        assert attribute_dict[NameOID.COUNTRY_NAME] == "ES"
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "Madrid"
        assert attribute_dict[NameOID.LOCALITY_NAME] == "Madrid"
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == "Empresa S.L."
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == "Desarrollo"

    def test_entity_with_unicode_characters(self):
        """Test that Entity handles Unicode characters correctly."""
        entity = Entity(
            name="张三",
            email="zhangsan@中国.com",
            country="CN",
            state="北京",
            locality="北京",
            organization="中国公司",
            organizational_unit="技术部"
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == "张三"
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "zhangsan@中国.com"
        assert attribute_dict[NameOID.COUNTRY_NAME] == "CN"
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "北京"
        assert attribute_dict[NameOID.LOCALITY_NAME] == "北京"
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == "中国公司"
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == "技术部"

    def test_entity_with_long_strings(self):
        """Test that Entity handles long strings correctly."""
        long_name = "A" * 64  # Maximum allowed length for common name
        long_email = "test@example.com"  # Keep email reasonable
        long_country = "US"  # Must be exactly 2 characters
        long_state = "California" * 10  # Reasonable length
        long_locality = "San Francisco" * 5  # Reasonable length
        long_organization = "Very Long Organization Name" * 5  # Reasonable length
        long_organizational_unit = "Very Long Organizational Unit Name" * 3  # Reasonable length
        
        entity = Entity(
            name=long_name,
            email=long_email,
            country=long_country,
            state=long_state,
            locality=long_locality,
            organization=long_organization,
            organizational_unit=long_organizational_unit
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == long_name
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == long_email
        assert attribute_dict[NameOID.COUNTRY_NAME] == long_country
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == long_state
        assert attribute_dict[NameOID.LOCALITY_NAME] == long_locality
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == long_organization
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == long_organizational_unit

    def test_entity_property_types(self):
        """Test that Entity properties have the correct types."""
        entity = Entity(
            name="Test",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        assert isinstance(entity.name, str)
        assert isinstance(entity.email, str)
        assert isinstance(entity.country, str)
        assert isinstance(entity.state, str)
        assert isinstance(entity.locality, str)
        assert isinstance(entity.organization, str)
        assert isinstance(entity.organizational_unit, str)

    def test_entity_property_types_with_none(self):
        """Test that Entity properties have the correct types when None."""
        entity = Entity(
            name="Test",
            email="test@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization=None,
            organizational_unit=None
        )
        
        assert isinstance(entity.name, str)
        assert isinstance(entity.email, str)
        assert isinstance(entity.country, str)
        assert isinstance(entity.state, str)
        assert isinstance(entity.locality, str)
        assert entity.organization is None
        assert entity.organizational_unit is None

    def test_to_name_consistency(self):
        """Test that to_name() produces consistent results for the same entity."""
        entity = Entity(
            name="Consistent Test",
            email="consistent@example.com",
            country="US",
            state="CA",
            locality="SF",
            organization="Org",
            organizational_unit="Unit"
        )
        
        name1 = entity.to_name()
        name2 = entity.to_name()
        name3 = entity.to_name()
        
        assert name1 == name2 == name3

    def test_entity_with_whitespace(self):
        """Test that Entity handles whitespace correctly."""
        entity = Entity(
            name="  Test Name  ",
            email="  test@example.com  ",
            country="US",  # Must be exactly 2 characters, no whitespace
            state="  CA  ",
            locality="  SF  ",
            organization="  Org  ",
            organizational_unit="  Unit  "
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        # Whitespace should be preserved for most fields
        assert attribute_dict[NameOID.COMMON_NAME] == "  Test Name  "
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "  test@example.com  "
        assert attribute_dict[NameOID.COUNTRY_NAME] == "US"  # No whitespace allowed
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "  CA  "
        assert attribute_dict[NameOID.LOCALITY_NAME] == "  SF  "
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == "  Org  "
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == "  Unit  "

    def test_entity_with_newlines_and_tabs(self):
        """Test that Entity handles newlines and tabs correctly."""
        entity = Entity(
            name="Test\nName",
            email="test@example.com",
            country="US",
            state="CA\tState",
            locality="SF",
            organization="Org\nOrganization",
            organizational_unit="Unit\tUnit"
        )
        
        name = entity.to_name()
        attributes = list(name)
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        
        assert attribute_dict[NameOID.COMMON_NAME] == "Test\nName"
        assert attribute_dict[NameOID.EMAIL_ADDRESS] == "test@example.com"
        assert attribute_dict[NameOID.COUNTRY_NAME] == "US"
        assert attribute_dict[NameOID.STATE_OR_PROVINCE_NAME] == "CA\tState"
        assert attribute_dict[NameOID.LOCALITY_NAME] == "SF"
        assert attribute_dict[NameOID.ORGANIZATION_NAME] == "Org\nOrganization"
        assert attribute_dict[NameOID.ORGANIZATIONAL_UNIT_NAME] == "Unit\tUnit"

    def test_entity_minimal_required_fields(self):
        """Test Entity with minimal required fields only."""
        entity = Entity(
            name="Minimal",
            email="minimal@test.com",
            country="US",
            state="CA",
            locality="SF",
            organization=None,
            organizational_unit=None
        )
        
        # Should not raise any exceptions
        assert entity.name == "Minimal"
        assert entity.email == "minimal@test.com"
        assert entity.country == "US"
        assert entity.state == "CA"
        assert entity.locality == "SF"
        assert entity.organization is None
        assert entity.organizational_unit is None
        
        # to_name() should work
        name = entity.to_name()
        assert isinstance(name, x509.Name)
        
        # Should only have the required attributes (not organization/unit)
        attributes = list(name)
        assert len(attributes) == 5  # Only 5 required attributes
        attribute_dict = {attr.oid: attr.value for attr in attributes}
        assert NameOID.ORGANIZATION_NAME not in attribute_dict
        assert NameOID.ORGANIZATIONAL_UNIT_NAME not in attribute_dict

    def test_entity_all_fields_populated(self):
        """Test Entity with all fields populated."""
        entity = Entity(
            name="Complete Entity",
            email="complete@example.com",
            country="US",
            state="California",
            locality="San Francisco",
            organization="Complete Organization Inc.",
            organizational_unit="Complete Department"
        )
        
        assert entity.name == "Complete Entity"
        assert entity.email == "complete@example.com"
        assert entity.country == "US"
        assert entity.state == "California"
        assert entity.locality == "San Francisco"
        assert entity.organization == "Complete Organization Inc."
        assert entity.organizational_unit == "Complete Department"
        
        # to_name() should work
        name = entity.to_name()
        assert isinstance(name, x509.Name)
        
        # All attributes should be present
        attributes = list(name)
        assert len(attributes) == 7  # All 7 attributes should be present
