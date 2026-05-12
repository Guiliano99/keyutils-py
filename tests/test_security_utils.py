# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for ``keyutils_py.security.estimate_key_security_strength``."""

import unittest

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448

from keyutils_py import estimate_key_security_strength, generate_key
from keyutils_py.utils import OQS_AVAILABLE
from keyutils_py.security import (
    HASH_ALG_TO_STRENGTH,
    _ecc_security_strength,
    _nist_level_strength,
    _rsa_security_strength,
)


class TestRsaDsaStrength(unittest.TestCase):
    """RSA / DSA sizes map to NIST SP 800-57 Rev. 5 Table 2 strengths."""

    def test_rsa_2048(self):
        """GIVEN 2048-bit RSA / WHEN estimating / THEN 112 bits."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(estimate_key_security_strength(priv), 112)

    def test_rsa_3072(self):
        """GIVEN 3072-bit RSA / WHEN estimating / THEN 128 bits."""
        self.assertEqual(_rsa_security_strength(3072), 128)

    def test_rsa_15360(self):
        """GIVEN 15360-bit RSA / WHEN estimating / THEN 256 bits."""
        self.assertEqual(_rsa_security_strength(15360), 256)

    def test_rsa_below_1024(self):
        """GIVEN sub-1024 RSA / WHEN estimating / THEN 64 bits (legacy)."""
        self.assertEqual(_rsa_security_strength(512), 64)

    def test_dsa_public_key(self):
        """GIVEN a DSA public key / WHEN estimating / THEN matches RSA mapping."""
        priv = dsa.generate_private_key(key_size=2048)
        self.assertEqual(estimate_key_security_strength(priv.public_key()), 112)


class TestEccStrength(unittest.TestCase):
    """ECC strength based on field size."""

    def test_p256(self):
        """GIVEN P-256 / WHEN estimating / THEN 128 bits."""
        priv = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(estimate_key_security_strength(priv), 128)

    def test_p384(self):
        """GIVEN P-384 / WHEN estimating / THEN 192 bits."""
        priv = ec.generate_private_key(ec.SECP384R1())
        self.assertEqual(estimate_key_security_strength(priv), 192)

    def test_p521(self):
        """GIVEN P-521 / WHEN estimating / THEN 256 bits."""
        priv = ec.generate_private_key(ec.SECP521R1())
        self.assertEqual(estimate_key_security_strength(priv), 256)

    def test_ecc_table_boundary_223(self):
        """GIVEN field size 223 / WHEN estimating / THEN 80 bits (table edge)."""
        self.assertEqual(_ecc_security_strength(223), 80)


class TestEdAndXStrength(unittest.TestCase):
    """Ed/X25519 → 128 bits, Ed/X448 → 224 bits."""

    def test_ed25519(self):
        """GIVEN Ed25519 / WHEN estimating / THEN 128 bits."""
        priv = ed25519.Ed25519PrivateKey.generate()
        self.assertEqual(estimate_key_security_strength(priv), 128)

    def test_ed448(self):
        """GIVEN Ed448 / WHEN estimating / THEN 224 bits."""
        priv = ed448.Ed448PrivateKey.generate()
        self.assertEqual(estimate_key_security_strength(priv), 224)

    def test_x25519(self):
        """GIVEN X25519 / WHEN estimating / THEN 128 bits."""
        priv = x25519.X25519PrivateKey.generate()
        self.assertEqual(estimate_key_security_strength(priv), 128)

    def test_x448(self):
        """GIVEN X448 / WHEN estimating / THEN 224 bits."""
        priv = x448.X448PrivateKey.generate()
        self.assertEqual(estimate_key_security_strength(priv), 224)


class TestStatefulHashStrength(unittest.TestCase):
    """HSS uses LMS hash size; XMSS / XMSSMT use the hash output size halved for Grover."""

    def test_hss(self):
        """GIVEN an HSS key (n=32) / WHEN estimating / THEN 128 bits."""
        priv = generate_key("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
        self.assertEqual(estimate_key_security_strength(priv), 128)

    @unittest.skipUnless(OQS_AVAILABLE, "XMSS requires liboqs")
    def test_xmss_sha2_10_256(self):
        """GIVEN XMSS-sha2_10_256 / WHEN estimating / THEN 128 bits (256 / 2)."""
        priv = generate_key("xmss-sha2_10_256")
        self.assertEqual(estimate_key_security_strength(priv), 128)


class TestPqStrength(unittest.TestCase):
    """ML-KEM / ML-DSA strengths come from the claimed NIST level."""

    def test_ml_kem_512(self):
        """GIVEN ML-KEM-512 (NIST level 1) / WHEN estimating / THEN 128 bits."""
        priv = generate_key("ml-kem-512")
        self.assertEqual(estimate_key_security_strength(priv), 128)

    def test_ml_kem_1024(self):
        """GIVEN ML-KEM-1024 (NIST level 5) / WHEN estimating / THEN 256 bits."""
        priv = generate_key("ml-kem-1024")
        self.assertEqual(estimate_key_security_strength(priv), 256)

    def test_ml_dsa_44(self):
        """GIVEN ML-DSA-44 (NIST level 2) / WHEN estimating / THEN 192 bits."""
        priv = generate_key("ml-dsa-44")
        self.assertEqual(estimate_key_security_strength(priv), 192)


class TestHybridStrength(unittest.TestCase):
    """Composite hybrid keys take the minimum of PQ and traditional component strengths."""

    def test_xwing(self):
        """GIVEN xwing (ML-KEM-768 + X25519) / WHEN estimating / THEN min(192, 128) = 128."""
        priv = generate_key("xwing")
        self.assertEqual(estimate_key_security_strength(priv), 128)

    def test_composite_kem_ml_kem_768_rsa3072(self):
        """GIVEN composite-KEM ML-KEM-768 + RSA-3072 / WHEN estimating / THEN min(192, 128) = 128."""
        priv = generate_key("composite-kem-ml-kem-768-rsa3072")
        self.assertEqual(estimate_key_security_strength(priv), 128)


class TestHelpers(unittest.TestCase):
    """Direct coverage for the small private helpers."""

    def test_nist_level_strength_none(self):
        """GIVEN level=None / WHEN looking up / THEN 0."""
        self.assertEqual(_nist_level_strength(None), 0)

    def test_nist_level_strength_unknown(self):
        """GIVEN unknown level / WHEN looking up / THEN 0."""
        self.assertEqual(_nist_level_strength(99), 0)

    def test_hash_table_present(self):
        """GIVEN HASH_ALG_TO_STRENGTH / WHEN lookups / THEN canonical mappings."""
        self.assertEqual(HASH_ALG_TO_STRENGTH["sha256"], 128)
        self.assertEqual(HASH_ALG_TO_STRENGTH["shake256"], 256)


class TestUnsupportedKey(unittest.TestCase):
    """Unsupported types raise NotImplementedError."""

    def test_random_object_raises(self):
        """GIVEN a non-key value / WHEN estimating / THEN NotImplementedError."""
        with self.assertRaises(NotImplementedError):
            estimate_key_security_strength(object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
