import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from digital_signatures.crypto.key_generator.ecc_key_generator import EccKeyGenerator


class TestEccKeyGenerator:
    """Test cases for the EccKeyGenerator class."""

    def test_init_with_default_curve(self):
        """Test that EccKeyGenerator initializes correctly with default curve."""
        key_generator = EccKeyGenerator()
        
        assert key_generator.curve.name == ec.SECP256R1().name
        assert isinstance(key_generator.curve, ec.EllipticCurve)

    def test_init_with_custom_curve(self):
        """Test that EccKeyGenerator initializes correctly with custom curve."""
        custom_curve = ec.SECP384R1()
        key_generator = EccKeyGenerator(custom_curve)
        
        assert key_generator.curve.name == custom_curve.name
        assert key_generator.curve == custom_curve

    def test_generate_returns_correct_key_types(self):
        """Test that generate() returns the correct key types."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Check if the keys are elliptic curve keys
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)

    def test_generate_returns_matching_curve(self):
        """Test that generated keys use the specified curve."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Check if the curve is the same as the curve used for the key generator
        assert private_key.curve.name == key_generator.curve.name
        assert public_key.curve.name == key_generator.curve.name

    def test_generate_returns_matching_key_pair(self):
        """Test that the public key matches the private key's public key."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Check if the public key is the same as the private key's public key
        assert public_key == private_key.public_key()

    def test_generate_returns_different_keys_each_time(self):
        """Test that generate() returns different keys each time."""
        key_generator = EccKeyGenerator()
        
        # Generate multiple key pairs
        private_key1, public_key1 = key_generator.generate()
        private_key2, public_key2 = key_generator.generate()
        
        # Keys should be different
        assert private_key1 != private_key2
        assert public_key1 != public_key2

    def test_generate_with_different_curves(self):
        """Test key generation with different elliptic curves."""
        curves = [
            ec.SECP256R1(),
            ec.SECP384R1(),
            ec.SECP521R1(),
        ]
        
        for curve in curves:
            key_generator = EccKeyGenerator(curve)
            private_key, public_key = key_generator.generate()
            
            # Check curve matches
            assert private_key.curve.name == curve.name
            assert public_key.curve.name == curve.name
            
            # Check key types
            assert isinstance(private_key, EllipticCurvePrivateKey)
            assert isinstance(public_key, EllipticCurvePublicKey)
            
            # Check key pair relationship
            assert public_key == private_key.public_key()

    def test_generate_consistency(self):
        """Test that generate() produces consistent results for the same instance."""
        key_generator = EccKeyGenerator()
        
        # Generate multiple key pairs from the same instance
        key_pairs = []
        for _ in range(5):
            private_key, public_key = key_generator.generate()
            key_pairs.append((private_key, public_key))
        
        # All keys should be different
        for i in range(len(key_pairs)):
            for j in range(i + 1, len(key_pairs)):
                assert key_pairs[i][0] != key_pairs[j][0]  # Private keys different
                assert key_pairs[i][1] != key_pairs[j][1]  # Public keys different

    def test_inherits_from_key_generator_base_class(self):
        """Test that EccKeyGenerator inherits from the KeyGenerator base class."""
        from digital_signatures.crypto.key_generator.base import KeyGenerator
        
        key_generator = EccKeyGenerator()
        assert isinstance(key_generator, KeyGenerator)

    def test_curve_property_access(self):
        """Test that the curve property can be accessed."""
        curve = ec.SECP256R1()
        key_generator = EccKeyGenerator(curve)
        
        assert hasattr(key_generator, 'curve')
        assert key_generator.curve == curve

    def test_generate_with_secp256r1_curve(self):
        """Test key generation specifically with SECP256R1 curve."""
        curve = ec.SECP256R1()
        key_generator = EccKeyGenerator(curve)
        private_key, public_key = key_generator.generate()
        
        assert private_key.curve.name == "secp256r1"
        assert public_key.curve.name == "secp256r1"
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)

    def test_generate_with_secp384r1_curve(self):
        """Test key generation specifically with SECP384R1 curve."""
        curve = ec.SECP384R1()
        key_generator = EccKeyGenerator(curve)
        private_key, public_key = key_generator.generate()
        
        assert private_key.curve.name == "secp384r1"
        assert public_key.curve.name == "secp384r1"
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)

    def test_generate_with_secp521r1_curve(self):
        """Test key generation specifically with SECP521R1 curve."""
        curve = ec.SECP521R1()
        key_generator = EccKeyGenerator(curve)
        private_key, public_key = key_generator.generate()
        
        assert private_key.curve.name == "secp521r1"
        assert public_key.curve.name == "secp521r1"
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)

    def test_generate_multiple_instances_same_curve(self):
        """Test that multiple instances with the same curve produce different keys."""
        curve = ec.SECP256R1()
        key_generator1 = EccKeyGenerator(curve)
        key_generator2 = EccKeyGenerator(curve)
        
        private_key1, public_key1 = key_generator1.generate()
        private_key2, public_key2 = key_generator2.generate()
        
        # Keys should be different even with same curve
        assert private_key1 != private_key2
        assert public_key1 != public_key2
        
        # But curves should be the same
        assert private_key1.curve.name == private_key2.curve.name
        assert public_key1.curve.name == public_key2.curve.name

    def test_generate_private_key_has_public_key_method(self):
        """Test that generated private keys have the public_key() method."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Check that private key has public_key method
        assert hasattr(private_key, 'public_key')
        assert callable(private_key.public_key)
        
        # Check that calling public_key() returns the same public key
        derived_public_key = private_key.public_key()
        assert derived_public_key == public_key

    def test_generate_public_key_has_curve_property(self):
        """Test that generated public keys have the curve property."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Check that public key has curve property
        assert hasattr(public_key, 'curve')
        assert public_key.curve.name == key_generator.curve.name

    def test_generate_private_key_has_curve_property(self):
        """Test that generated private keys have the curve property."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Check that private key has curve property
        assert hasattr(private_key, 'curve')
        assert private_key.curve.name == key_generator.curve.name

    def test_generate_returns_tuple(self):
        """Test that generate() returns a tuple."""
        key_generator = EccKeyGenerator()
        result = key_generator.generate()
        
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_generate_tuple_unpacking(self):
        """Test that the returned tuple can be unpacked correctly."""
        key_generator = EccKeyGenerator()
        private_key, public_key = key_generator.generate()
        
        # Verify unpacking worked correctly
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        assert public_key == private_key.public_key()

    def test_generate_with_none_curve_raises_error(self):
        """Test that passing None as curve raises an error in constructor."""
        with pytest.raises(ValueError, match="Curve must be an instance of EllipticCurve."):
            EccKeyGenerator(None)

    def test_generate_with_invalid_curve_type_raises_error(self):
        """Test that passing invalid curve type raises an error in constructor."""
        with pytest.raises(ValueError, match="Curve must be an instance of EllipticCurve."):
            EccKeyGenerator("invalid_curve")

    def test_generate_performance(self):
        """Test that key generation performance is reasonable."""
        import time
        
        key_generator = EccKeyGenerator()
        
        # Time multiple key generation operations
        start_time = time.time()
        for _ in range(10):
            key_generator.generate()
        generation_time = time.time() - start_time
        
        # Key generation should be reasonably fast (less than 1 second for 10 keys)
        assert generation_time < 1.0
        print(f"Generated 10 key pairs in {generation_time:.3f} seconds")

    def test_generate_with_different_curve_sizes(self):
        """Test key generation with curves of different sizes."""
        curves = [
            ("SECP256R1", ec.SECP256R1()),
            ("SECP384R1", ec.SECP384R1()),
            ("SECP521R1", ec.SECP521R1()),
        ]
        
        for curve_name, curve in curves:
            key_generator = EccKeyGenerator(curve)
            private_key, public_key = key_generator.generate()
            
            print(f"Generated {curve_name} key pair successfully")
            assert private_key.curve.name == curve.name
            assert public_key.curve.name == curve.name

    def test_generate_with_edge_case_curves(self):
        """Test key generation with edge case curves."""
        # Test with the same curve instance multiple times
        curve = ec.SECP256R1()
        key_generator1 = EccKeyGenerator(curve)
        key_generator2 = EccKeyGenerator(curve)
        
        private_key1, public_key1 = key_generator1.generate()
        private_key2, public_key2 = key_generator2.generate()
        
        # Keys should be different even with same curve instance
        assert private_key1 != private_key2
        assert public_key1 != public_key2

    def test_generate_key_sizes(self):
        """Test that generated keys have appropriate sizes."""
        curves_and_expected_sizes = [
            (ec.SECP256R1(), 256),
            (ec.SECP384R1(), 384),
            (ec.SECP521R1(), 521),
        ]
        
        for curve, expected_size in curves_and_expected_sizes:
            key_generator = EccKeyGenerator(curve)
            private_key, public_key = key_generator.generate()
            
            # Check that the curve name reflects the expected size
            assert str(expected_size) in private_key.curve.name
            assert str(expected_size) in public_key.curve.name

    def test_generate_immutable_curve(self):
        """Test that the curve property is immutable after generation."""
        key_generator = EccKeyGenerator()
        original_curve = key_generator.curve
        
        # Generate keys
        private_key, public_key = key_generator.generate()
        
        # Curve should remain the same
        assert key_generator.curve == original_curve
        assert key_generator.curve.name == original_curve.name

    def test_generate_with_zero_curve_parameter(self):
        """Test that passing 0 as curve parameter raises an error in constructor."""
        with pytest.raises(ValueError, match="Curve must be an instance of EllipticCurve."):
            EccKeyGenerator(0)

    def test_generate_with_empty_string_curve(self):
        """Test that passing empty string as curve raises an error in constructor."""
        with pytest.raises(ValueError, match="Curve must be an instance of EllipticCurve."):
            EccKeyGenerator("")

