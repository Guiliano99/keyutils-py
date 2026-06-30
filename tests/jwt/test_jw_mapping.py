# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for the JWK name/curve mapping tables and the family classifier."""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from keyutils_py import generate_key
from keyutils_py.exceptions import InvalidJWK
from keyutils_py.jwt.jw_mapping import (
    AKP_ALG_2_NAME,
    AKP_NAME_2_ALG,
    COMPOSITE_ALG_2_NAME,
    COMPOSITE_NAME_2_ALG,
    akp_alg_to_name,
    composite_alg_to_name,
    jwk_family,
)


class TestAkpAlgNames(unittest.TestCase):
    def test_expected_alg_names(self):
        self.assertEqual(AKP_NAME_2_ALG["ml-dsa-44"], "ML-DSA-44")
        self.assertEqual(AKP_NAME_2_ALG["ml-kem-1024"], "ML-KEM-1024")
        self.assertEqual(AKP_NAME_2_ALG["slh-dsa-sha2-128s"], "SLH-DSA-SHA2-128s")
        self.assertEqual(AKP_NAME_2_ALG["slh-dsa-shake-256f"], "SLH-DSA-SHAKE-256f")

    def test_bijective(self):
        self.assertEqual(len(AKP_ALG_2_NAME), len(AKP_NAME_2_ALG))
        for name, alg in AKP_NAME_2_ALG.items():
            self.assertEqual(AKP_ALG_2_NAME[alg], name)

    def test_case_insensitive_lookup(self):
        self.assertEqual(akp_alg_to_name("ml-dsa-44"), "ml-dsa-44")
        self.assertEqual(akp_alg_to_name("SLH-DSA-SHA2-128S"), "slh-dsa-sha2-128s")
        self.assertIsNone(akp_alg_to_name("bogus"))


class TestCompositeAlgNames(unittest.TestCase):
    def test_expected_alg_names(self):
        self.assertEqual(
            COMPOSITE_NAME_2_ALG["composite-sig-ml-dsa-44-ed25519"], "ML-DSA-44-Ed25519"
        )
        self.assertEqual(
            COMPOSITE_NAME_2_ALG["composite-sig-ml-dsa-44-ecdsa-secp256r1"], "ML-DSA-44-ECDSA-P256"
        )
        self.assertEqual(
            COMPOSITE_NAME_2_ALG["composite-sig-ml-dsa-87-ecdsa-brainpoolP384r1"],
            "ML-DSA-87-ECDSA-BP384",
        )

    def test_bijective(self):
        self.assertEqual(len(COMPOSITE_ALG_2_NAME), len(COMPOSITE_NAME_2_ALG))
        for name, alg in COMPOSITE_NAME_2_ALG.items():
            self.assertEqual(COMPOSITE_ALG_2_NAME[alg], name)

    def test_case_insensitive_lookup(self):
        self.assertEqual(
            composite_alg_to_name("ml-dsa-44-ecdsa-p256"), "composite-sig-ml-dsa-44-ecdsa-secp256r1"
        )
        self.assertIsNone(composite_alg_to_name("ML-DSA-44"))


class TestJwkFamily(unittest.TestCase):
    def test_traditional(self):
        self.assertEqual(jwk_family(rsa.generate_private_key(public_exponent=65537, key_size=2048)), "rsa")
        self.assertEqual(jwk_family(ec.generate_private_key(ec.SECP256R1())), "ec")
        self.assertEqual(jwk_family(ed25519.Ed25519PrivateKey.generate()), "okp")

    def test_pq_and_composite(self):
        self.assertEqual(jwk_family(generate_key("ml-dsa-44")), "akp")
        self.assertEqual(jwk_family(generate_key("ml-kem-768")), "akp")
        self.assertEqual(jwk_family(generate_key("slh-dsa-sha2-128s")), "akp")
        self.assertEqual(jwk_family(generate_key("composite-sig-ml-dsa-44-ed25519")), "composite")

    def test_unsupported_raises(self):
        with self.assertRaises(InvalidJWK):
            jwk_family(object())


if __name__ == "__main__":
    unittest.main()
