# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for the base64url codecs and RFC 7638 thumbprint helper."""

import os
import unittest

from keyutils_py.exceptions import InvalidJWK
from keyutils_py.jwt.jwt_utils import (
    b64u_decode,
    b64u_encode,
    b64u_to_int,
    int_to_b64u,
    jwk_thumbprint,
)


class TestBase64Url(unittest.TestCase):
    def test_encode_is_unpadded(self):
        """GIVEN bytes whose base64 has padding WHEN encoded THEN no '=' appears."""
        self.assertEqual(b64u_encode(b"\x00"), "AA")
        self.assertNotIn("=", b64u_encode(b"any odd length"))

    def test_roundtrip_random(self):
        """GIVEN random byte strings WHEN encoded+decoded THEN they are recovered."""
        for length in (0, 1, 2, 3, 31, 32, 64, 257):
            data = os.urandom(length)
            self.assertEqual(b64u_decode(b64u_encode(data)), data)

    def test_decode_rejects_padding(self):
        """GIVEN a padded value WHEN decoded THEN InvalidJWK is raised."""
        with self.assertRaises(InvalidJWK):
            b64u_decode("AA==")

    def test_decode_rejects_standard_base64_chars(self):
        """GIVEN '+'/'/' characters WHEN decoded THEN InvalidJWK is raised."""
        with self.assertRaises(InvalidJWK):
            b64u_decode("ab+/")

    def test_decode_rejects_non_string(self):
        with self.assertRaises(InvalidJWK):
            b64u_decode(b"AA")  # type: ignore[arg-type]


class TestIntCodec(unittest.TestCase):
    def test_minimal_length_has_no_leading_zero(self):
        """GIVEN 65537 WHEN minimally encoded THEN it is the 3-byte 'AQAB'."""
        self.assertEqual(int_to_b64u(65537), "AQAB")

    def test_fixed_length_pads_left(self):
        """GIVEN a small value and a length WHEN encoded THEN it is zero-padded."""
        encoded = int_to_b64u(1, length=66)  # P-521 coordinate width
        self.assertEqual(len(b64u_decode(encoded)), 66)
        self.assertEqual(b64u_to_int(encoded), 1)

    def test_roundtrip(self):
        for value in (0, 1, 255, 256, 65537, 2**521 - 1):
            self.assertEqual(b64u_to_int(int_to_b64u(value)), value)

    def test_negative_rejected(self):
        with self.assertRaises(InvalidJWK):
            int_to_b64u(-1)

    def test_does_not_fit_rejected(self):
        with self.assertRaises(InvalidJWK):
            int_to_b64u(256, length=1)


class TestThumbprint(unittest.TestCase):
    def test_rfc7638_rsa_known_answer(self):
        """GIVEN the RFC 7638 section 3.1 RSA JWK THEN the thumbprint matches exactly."""
        jwk = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1"
                "RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5"
                "n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8K"
                "JZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQF"
                "h6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJz"
                "KnqDKgw"
            ),
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }
        self.assertEqual(jwk_thumbprint(jwk), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")

    def test_thumbprint_ignores_non_required_members(self):
        """GIVEN extra members THEN they do not change the thumbprint."""
        base = {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
        self.assertEqual(jwk_thumbprint(base), jwk_thumbprint({**base, "use": "sig", "d": "secret"}))

    def test_missing_member_raises(self):
        with self.assertRaises(InvalidJWK):
            jwk_thumbprint({"kty": "EC", "crv": "P-256", "x": "abc"})  # missing y

    def test_unknown_kty_raises(self):
        with self.assertRaises(InvalidJWK):
            jwk_thumbprint({"kty": "oct", "k": "abc"})

    def test_unknown_hash_raises(self):
        with self.assertRaises(InvalidJWK):
            jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": "abc"}, hash_alg="md5")


if __name__ == "__main__":
    unittest.main()
