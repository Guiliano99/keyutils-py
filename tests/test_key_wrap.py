# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``wrap_cek``, ``unwrap_cek`` and ``wrap_key_length`` of ``keyutils_py.mechanisms``.

External vectors, so that a shared misreading of the OID or the mode cannot pass both sides: the six vectors of RFC 3394
Section 4 (AES key wrap with 128, 192 and 256 bit KEKs) through the OIDs of RFC 3565, and the vectors of RFC 5649
Section 6 (key wrap with padding, a 192 bit KEK, a 20 and a 7 octet key) through the OIDs of RFC 5649.
"""

import unittest

from keyutils_py import _algs, primitives
from keyutils_py.exceptions import BadAlg, BadAlgParams, IntegrityError
from keyutils_py.mechanisms import unwrap_cek, wrap_cek, wrap_key_length
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc5280, rfc5649, rfc8018, rfc8619

_KW = {16: rfc3565.id_aes128_wrap, 24: rfc3565.id_aes192_wrap, 32: rfc3565.id_aes256_wrap}
_KWP = {16: rfc5649.id_aes128_wrap_pad, 24: rfc5649.id_aes192_wrap_pad, 32: rfc5649.id_aes256_wrap_pad}


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Return an ``AlgorithmIdentifier`` with optional ASN.1 parameters."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if parameters is not None:
        alg_id["parameters"] = univ.Any(encoder.encode(parameters))
    return alg_id


class TestRfcVectors(unittest.TestCase):
    """The vectors of RFC 3394 and RFC 5649."""

    KEK = bytes(range(32))
    DATA_128 = bytes.fromhex("00112233445566778899aabbccddeeff")
    DATA_192 = bytes.fromhex("00112233445566778899aabbccddeeff0001020304050607")
    DATA_256 = bytes.fromhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f")

    def test_rfc_3394_section_4(self):
        """GIVEN the six vectors of RFC 3394 Section 4 / WHEN wrapped and unwrapped by OID / THEN the RFC value."""
        cases = (
            (16, self.DATA_128, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
            (24, self.DATA_128, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"),
            (32, self.DATA_128, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"),
            (24, self.DATA_192, "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"),
            (32, self.DATA_192, "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"),
            (
                32,
                self.DATA_256,
                "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
            ),
        )
        for kek_length, data, wrapped in cases:
            with self.subTest(kek_bits=kek_length * 8, key_bits=len(data) * 8):
                wrap = _alg_id(_KW[kek_length])
                kek = self.KEK[:kek_length]
                self.assertEqual(wrap_cek(wrap, kek, data).hex(), wrapped)
                self.assertEqual(unwrap_cek(wrap, kek, bytes.fromhex(wrapped)), data)

    def test_rfc_5649_section_6(self):
        """GIVEN the 20 and 7 octet keys of RFC 5649 Section 6 / WHEN wrapped and unwrapped / THEN the RFC values."""
        kek = bytes.fromhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
        cases = (
            (
                "c37b7e6492584340bed12207808941155068f738",
                "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            ),
            ("466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"),
        )
        for key, wrapped in cases:
            with self.subTest(octets=len(key) // 2):
                wrap = _alg_id(_KWP[24])
                self.assertEqual(wrap_cek(wrap, kek, bytes.fromhex(key)).hex(), wrapped)
                self.assertEqual(unwrap_cek(wrap, kek, bytes.fromhex(wrapped)).hex(), key)

    def test_every_row_round_trips_after_a_der_round_trip(self):
        """GIVEN each of the six rows, the identifier after DER / WHEN wrapped and unwrapped / THEN the key returns."""
        for row in _algs.WRAP_ROWS:
            with self.subTest(mode=row.mode, kek=row.kek_len):
                wrap, rest = decoder.decode(encoder.encode(_alg_id(row.oid)), asn1Spec=rfc5280.AlgorithmIdentifier())
                self.assertEqual(rest, b"")
                kek, cek = bytes(range(row.kek_len)), bytes(range(32))
                self.assertEqual(unwrap_cek(wrap, kek, wrap_cek(wrap, kek, cek)), cek)


class TestModes(unittest.TestCase):
    """AES key wrap and key wrap with padding are two algorithms."""

    def test_kwp_wraps_a_key_that_is_no_multiple_of_8_octets(self):
        """GIVEN a 3 octet key / WHEN wrapped / THEN KWP gives 16 octets and KW raises ValueError."""
        kek = bytes(16)
        wrapped = wrap_cek(_alg_id(_KWP[16]), kek, b"abc")
        self.assertEqual(len(wrapped), 16)
        self.assertEqual(unwrap_cek(_alg_id(_KWP[16]), kek, wrapped), b"abc")
        with self.assertRaises(ValueError):
            wrap_cek(_alg_id(_KW[16]), kek, b"abc")

    def test_a_value_wrapped_in_one_mode_does_not_unwrap_in_the_other(self):
        """GIVEN a key wrapped with KWP and the KW OID written / WHEN unwrapped with KW / THEN IntegrityError."""
        kek, cek = bytes(range(16)), bytes(range(16))
        for wrap_with, read_with in ((_KWP, _KW), (_KW, _KWP)):
            with self.subTest(wrapped_with=wrap_with[16]):
                wrapped = wrap_cek(_alg_id(wrap_with[16]), kek, cek)
                with self.assertRaises(IntegrityError):
                    unwrap_cek(_alg_id(read_with[16]), kek, wrapped)


class TestKekSize(unittest.TestCase):
    """The KEK must have the size that the OID names."""

    def test_wrap_key_length_names_the_kek_size_of_each_oid(self):
        """GIVEN each of the six OIDs / WHEN asked / THEN 16, 24, 32 octets."""
        for table in (_KW, _KWP):
            for kek_length, oid in table.items():
                self.assertEqual(wrap_key_length(_alg_id(oid)), kek_length)

    def test_a_kek_of_another_size_is_bad_alg_params_for_wrap_and_unwrap(self):
        """GIVEN KEKs of 15, 24 and 32 octets under the AES-128 OID / WHEN used / THEN BadAlgParams, both directions."""
        for oid in (_KW[16], _KWP[16]):
            for kek_length in (0, 15, 24, 32):
                with self.subTest(oid=str(oid), kek=kek_length):
                    with self.assertRaises(BadAlgParams):
                        wrap_cek(_alg_id(oid), bytes(kek_length), bytes(16))
                    with self.assertRaises(BadAlgParams):
                        unwrap_cek(_alg_id(oid), bytes(kek_length), bytes(24))

    def test_a_kek_that_does_not_fit_the_written_oid_is_made_with_the_lower_layer(self):
        """GIVEN an AES-192 wrap with the AES-256 OID written / WHEN the receiver unwraps / THEN BadAlgParams."""
        kek, cek = bytes(range(24)), bytes(range(16))
        wrapped = primitives.aes_kw_wrap(kek, cek)
        self.assertEqual(unwrap_cek(_alg_id(_KW[24]), kek, wrapped), cek)
        with self.assertRaises(BadAlgParams):
            unwrap_cek(_alg_id(_KW[32]), kek, wrapped)


class TestUnwrapFailures(unittest.TestCase):
    """What does not unwrap is an ``IntegrityError`` with one message."""

    def test_changed_short_empty_and_foreign_values_are_integrity_errors(self):
        """GIVEN a flipped bit, a cut, an extension, an empty value, a wrong KEK / WHEN unwrapped / THEN one message."""
        kek, cek = bytes(range(16)), bytes(range(24))
        messages = set()
        for oid in (_KW[16], _KWP[16]):
            wrap = _alg_id(oid)
            wrapped = wrap_cek(wrap, kek, cek)
            flipped = bytes([wrapped[0] ^ 1]) + wrapped[1:]
            for name, value, key in (
                ("flipped", flipped, kek),
                ("last", wrapped[:-1] + bytes([wrapped[-1] ^ 1]), kek),
                ("cut", wrapped[:-8], kek),
                ("extended", wrapped + bytes(8), kek),
                ("odd", wrapped[:-1], kek),
                ("empty", b"", kek),
                ("wrong kek", wrapped, bytes(16)),
            ):
                with self.subTest(oid=str(oid), case=name):
                    with self.assertRaises(IntegrityError) as caught:
                        unwrap_cek(wrap, key, value)
                    messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1, "the message must not tell what is wrong")


class TestTheIdentifier(unittest.TestCase):
    """The identifier is read as a strict receiver reads it."""

    def test_parameters_must_be_absent(self):
        """GIVEN NULL, an INTEGER or a SEQUENCE as parameters / WHEN used / THEN BadAlgParams (RFC 3565 2.3.2)."""
        for parameters in (univ.Null(""), univ.Integer(1), univ.Sequence()):
            for oid in (_KW[16], _KWP[16]):
                with self.subTest(parameters=type(parameters).__name__, oid=str(oid)):
                    wrap = _alg_id(oid, parameters)
                    with self.assertRaises(BadAlgParams):
                        wrap_cek(wrap, bytes(16), bytes(16))
                    with self.assertRaises(BadAlgParams):
                        unwrap_cek(wrap, bytes(16), bytes(24))
                    with self.assertRaises(BadAlgParams):
                        wrap_key_length(wrap)

    def test_an_oid_that_is_no_key_wrap_is_bad_alg(self):
        """GIVEN an HKDF, an HMAC and an unknown OID / WHEN used / THEN BadAlg."""
        for oid in (rfc8619.id_alg_hkdf_with_sha256, rfc8018.id_hmacWithSHA256, univ.ObjectIdentifier("1.2.3.4")):
            with self.subTest(oid=str(oid)):
                with self.assertRaises(BadAlg):
                    wrap_cek(_alg_id(oid), bytes(16), bytes(16))
                with self.assertRaises(BadAlg):
                    unwrap_cek(_alg_id(oid), bytes(16), bytes(24))
                with self.assertRaises(BadAlg):
                    wrap_key_length(_alg_id(oid))

    def test_an_identifier_without_oid_is_bad_alg_and_a_wrong_type_a_type_error(self):
        """GIVEN an empty identifier, an OID, bytes / WHEN used / THEN BadAlg or TypeError."""
        with self.assertRaises(BadAlg):
            wrap_cek(rfc5280.AlgorithmIdentifier(), bytes(16), bytes(16))
        for value in (rfc3565.id_aes128_wrap, b"x", None):
            with self.assertRaises(TypeError):
                wrap_cek(value, bytes(16), bytes(16))  # type: ignore[arg-type]

    def test_a_key_that_aes_key_wrap_cannot_wrap_is_a_value_error(self):
        """GIVEN keys of 8 and 17 octets / WHEN wrapped with KW / THEN ValueError of the library."""
        for size in (8, 17):
            with self.assertRaises(ValueError):
                wrap_cek(_alg_id(_KW[16]), bytes(16), bytes(size))


if __name__ == "__main__":
    unittest.main()
