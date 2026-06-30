# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Round-trip, known-answer, and dispatch tests for JWK key serialisation.

These tests rely only on the bundled FIPS backend (ML-DSA / ML-KEM / SLH-DSA),
so they run without liboqs.
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519

from keyutils_py import generate_key, key_from_jwk, key_to_jwk, sign_data, verify_signature
from keyutils_py.compute import compute_decaps, compute_encaps
from keyutils_py.exceptions import InvalidJWK
from keyutils_py.jwt import dumps, loads
from keyutils_py.keys.sig_keys import MLDSAPrivateKey


def _priv_jwk(key, **kwargs):
    """Serialise a private key to a JWK dict."""
    return key_to_jwk(key, **kwargs)


class TestTraditionalRoundTrip(unittest.TestCase):
    """EC / OKP / RSA round trips. Native keys compare via re-serialised JWK."""

    def _assert_roundtrip(self, key):
        priv_jwk = _priv_jwk(key)
        restored = loads(dumps(key))
        self.assertEqual(key_to_jwk(restored), priv_jwk)

        pub_jwk = key_to_jwk(key, is_private=False)
        self.assertNotIn("d", pub_jwk)
        restored_pub = key_from_jwk(pub_jwk)
        self.assertEqual(key_to_jwk(restored_pub, is_private=False), pub_jwk)

    def test_ec_curves(self):
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1(), ec.SECP256K1()):
            with self.subTest(curve=curve.name):
                self._assert_roundtrip(ec.generate_private_key(curve))

    def test_ec_p521_coordinate_length(self):
        """GIVEN a P-521 key THEN x/y/d are zero-padded to 66 bytes."""
        from keyutils_py.jwt.jwt_utils import b64u_decode

        jwk = key_to_jwk(ec.generate_private_key(ec.SECP521R1()))
        for member in ("x", "y", "d"):
            self.assertEqual(len(b64u_decode(jwk[member])), 66)

    def test_rsa(self):
        self._assert_roundtrip(rsa.generate_private_key(public_exponent=65537, key_size=2048))

    def test_okp(self):
        self._assert_roundtrip(ed25519.Ed25519PrivateKey.generate())
        self._assert_roundtrip(ed448.Ed448PrivateKey.generate())
        self._assert_roundtrip(x25519.X25519PrivateKey.generate())
        self._assert_roundtrip(x448.X448PrivateKey.generate())

    def test_unsupported_ec_curve_rejected(self):
        """GIVEN a brainpool EC key (no JWK crv) THEN serialisation raises."""
        key = ec.generate_private_key(ec.BrainpoolP256R1())
        with self.assertRaises(InvalidJWK):
            key_to_jwk(key)


class TestTraditionalKnownAnswers(unittest.TestCase):
    def test_rfc7517_ec_public(self):
        """RFC 7517 Appendix A.1 EC public key loads and re-serialises identically."""
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        }
        pub = key_from_jwk(jwk)
        self.assertIsInstance(pub, ec.EllipticCurvePublicKey)
        self.assertEqual(key_to_jwk(pub), jwk)

    def test_rfc8037_ed25519_private(self):
        """RFC 8037 Appendix A.1 Ed25519: the public x is derived from d."""
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }
        priv = key_from_jwk(jwk)
        self.assertIsInstance(priv, ed25519.Ed25519PrivateKey)
        self.assertEqual(key_to_jwk(priv), jwk)


class TestAkpRoundTrip(unittest.TestCase):
    """ML-DSA / ML-KEM / SLH-DSA round trips, using wrapper-key equality."""

    def _assert_roundtrip(self, alg):
        key = generate_key(alg)
        restored = loads(dumps(key))
        self.assertEqual(restored, key)
        self.assertEqual(restored.public_key(), key.public_key())
        pub = key_from_jwk(key_to_jwk(key, is_private=False))
        self.assertEqual(pub, key.public_key())

    def test_ml_dsa(self):
        for alg in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
            with self.subTest(alg=alg):
                self._assert_roundtrip(alg)

    def test_ml_kem(self):
        for alg in ("ml-kem-512", "ml-kem-768", "ml-kem-1024"):
            with self.subTest(alg=alg):
                self._assert_roundtrip(alg)

    def test_slh_dsa(self):
        for alg in ("slh-dsa-sha2-128s", "slh-dsa-shake-256f"):
            with self.subTest(alg=alg):
                self._assert_roundtrip(alg)

    def test_ml_dsa_priv_is_32_byte_seed(self):
        from keyutils_py.jwt.jwt_utils import b64u_decode

        jwk = key_to_jwk(generate_key("ml-dsa-65"))
        self.assertEqual(jwk["kty"], "AKP")
        self.assertEqual(len(b64u_decode(jwk["priv"])), 32)

    def test_ml_kem_priv_is_64_byte_seed(self):
        from keyutils_py.jwt.jwt_utils import b64u_decode

        jwk = key_to_jwk(generate_key("ml-kem-768"))
        self.assertEqual(len(b64u_decode(jwk["priv"])), 64)

    def test_ml_dsa_sign_verify_after_roundtrip(self):
        key = generate_key("ml-dsa-65")
        restored = key_from_jwk(key_to_jwk(key))
        signature = sign_data(b"keyutils-py jwk", restored)
        verify_signature(key.public_key(), signature, b"keyutils-py jwk")

    def test_ml_kem_encaps_decaps_after_roundtrip(self):
        key = generate_key("ml-kem-768")
        restored = key_from_jwk(key_to_jwk(key))
        shared, ciphertext = compute_encaps(key.public_key())
        self.assertEqual(compute_decaps(restored, ciphertext), shared)

    def test_seedless_private_raises(self):
        """An ML-DSA key with no seed cannot emit a conformant priv member."""
        seeded = generate_key("ml-dsa-65")
        expanded = MLDSAPrivateKey(
            alg_name="ml-dsa-65",
            private_bytes=seeded.private_bytes_raw(),
            public_key=seeded.public_key().public_bytes_raw(),
        )
        with self.assertRaises(InvalidJWK):
            key_to_jwk(expanded)

    def test_seedless_allow_expanded(self):
        """The opt-in flag emits expanded bytes that still round-trip locally."""
        seeded = generate_key("ml-dsa-65")
        expanded = MLDSAPrivateKey(
            alg_name="ml-dsa-65",
            private_bytes=seeded.private_bytes_raw(),
            public_key=seeded.public_key().public_bytes_raw(),
        )
        jwk = key_to_jwk(expanded, allow_expanded_priv=True)
        restored = key_from_jwk(jwk)
        self.assertEqual(restored.public_key(), seeded.public_key())


class TestCompositeRoundTrip(unittest.TestCase):
    ALGORITHMS = (
        "composite-sig-ml-dsa-44-ed25519",
        "composite-sig-ml-dsa-44-ecdsa-secp256r1",
        "composite-sig-ml-dsa-44-rsa2048",
        "composite-sig-ml-dsa-87-ed448",
        "composite-sig-ml-dsa-65-ecdsa-brainpoolP256r1",
    )

    def test_roundtrip_and_sign(self):
        for alg in self.ALGORITHMS:
            with self.subTest(alg=alg):
                key = generate_key(alg)
                jwk = key_to_jwk(key)
                self.assertEqual(jwk["kty"], "AKP")
                restored = key_from_jwk(jwk)
                self.assertEqual(restored, key)
                # The reconstructed key is functional.
                signature = sign_data(b"composite jwk", restored)
                verify_signature(key.public_key(), signature, b"composite jwk")

    def test_public_only(self):
        key = generate_key("composite-sig-ml-dsa-44-ed25519")
        pub_jwk = key_to_jwk(key, is_private=False)
        self.assertNotIn("priv", pub_jwk)
        pub = key_from_jwk(pub_jwk)
        self.assertEqual(pub, key.public_key())


class TestDispatchAndErrors(unittest.TestCase):
    def test_include_kid_matches_thumbprint(self):
        from keyutils_py import jwk_thumbprint

        key = generate_key("ml-dsa-44")
        jwk = key_to_jwk(key, include_kid=True)
        self.assertEqual(jwk["kid"], jwk_thumbprint(key_to_jwk(key, is_private=False)))

    def test_extra_members_merged(self):
        key = ec.generate_private_key(ec.SECP256R1())
        jwk = key_to_jwk(key, extra={"use": "sig", "kid": "my-id"})
        self.assertEqual(jwk["use"], "sig")
        self.assertEqual(jwk["kid"], "my-id")

    def test_expect_private_mismatch_raises(self):
        pub_jwk = key_to_jwk(generate_key("ml-dsa-44"), is_private=False)
        with self.assertRaises(InvalidJWK):
            key_from_jwk(pub_jwk, expect_private=True)

    def test_expect_private_false_returns_public(self):
        key = generate_key("ml-dsa-44")
        priv_jwk = key_to_jwk(key)
        restored = key_from_jwk(priv_jwk, expect_private=False)
        self.assertEqual(restored, key.public_key())

    def test_unknown_kty_raises(self):
        with self.assertRaises(InvalidJWK):
            key_from_jwk({"kty": "oct", "k": "AAAA"})

    def test_unknown_akp_alg_raises(self):
        with self.assertRaises(InvalidJWK):
            key_from_jwk({"kty": "AKP", "alg": "ML-FOO-1", "pub": "AAAA"})

    def test_is_private_true_on_public_raises(self):
        pub = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(InvalidJWK):
            key_to_jwk(pub, is_private=True)

    def test_loads_invalid_json_raises(self):
        with self.assertRaises(InvalidJWK):
            loads("{not json")

    def test_unsupported_key_type_raises(self):
        with self.assertRaises(InvalidJWK):
            key_to_jwk(object())


if __name__ == "__main__":
    unittest.main()
