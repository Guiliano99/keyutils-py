# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Limits on received MAC and PBKDF2 parameters in ``keyutils_py.mechanisms``.

The parameters of an ``AlgorithmIdentifier`` come from the message that is being checked, so the checked layer
(``compute_mac``, ``verify_mac``, ``kdf_derive``) refuses values that make the check weak or the work unbounded:

* PBMAC1 ``keyLength`` outside 16 to 4096 octets (a one octet MAC key is found in 256 tries),
* KMAC ``kMACOutputLength`` below 128 bits (an 8 bit MAC is a 1 in 256 forgery),
* PBKDF2 work, ``iterations * ceil(keyLength / digest size of the prf hash)``, above 25 000 000 blocks.

The weak inputs of the tests are made with the lower layer (``keyutils_py.primitives``), which has no limits, and with
hand-built parameters; the tests assert that the checked layer refuses them without computing anything.
"""

import hashlib
import hmac
import unittest
from typing import Optional
from unittest import mock

from keyutils_py import mechanisms, primitives
from keyutils_py.exceptions import BadAlgParams, IntegrityError
from keyutils_py.keys.key_pyasn1_utils import MAX_PBKDF2_ITERATIONS
from keyutils_py.mechanisms import compute_mac, kdf_derive, verify_mac
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc8018, rfc8702, rfc9481

_SHA1_PRF = rfc8018.id_hmacWithSHA1
_SHA256 = rfc8018.id_hmacWithSHA256
_SHA512 = rfc8018.id_hmacWithSHA512


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Return an ``AlgorithmIdentifier`` with optional ASN.1 parameters."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if parameters is not None:
        alg_id["parameters"] = univ.Any(encoder.encode(parameters))
    return alg_id


def _round_trip(alg_id: rfc5280.AlgorithmIdentifier) -> rfc5280.AlgorithmIdentifier:
    """Return the identifier as a receiver has it: DER encoded and decoded."""
    decoded, rest = decoder.decode(encoder.encode(alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
    assert not rest
    return decoded


def _pbkdf2_params(iterations: int, key_length: Optional[int], prf_oid=_SHA256) -> rfc8018.PBKDF2_params:
    """Return ``PBKDF2-params`` with salt "salty"; the prf is written with NULL parameters (RFC 8018 Appendix B.1)."""
    params = rfc8018.PBKDF2_params()
    params["salt"]["specified"] = b"salty"
    params["iterationCount"] = iterations
    if key_length is not None:
        params["keyLength"] = key_length
    params["prf"] = _alg_id(prf_oid, univ.Null(""))
    return params


def _pbkdf2_alg_id(iterations: int, key_length: Optional[int] = None, prf_oid=_SHA256):
    """Return an ``id-PBKDF2`` identifier."""
    return _round_trip(_alg_id(rfc8018.id_PBKDF2, _pbkdf2_params(iterations, key_length, prf_oid)))


def _pbmac1_alg_id(iterations: int, key_length: int, prf_oid=_SHA256, mac_oid=_SHA256):
    """Return a PBMAC1 identifier with salt "salty"."""
    params = rfc8018.PBMAC1_params()
    params["keyDerivationFunc"] = _alg_id(rfc8018.id_PBKDF2, _pbkdf2_params(iterations, key_length, prf_oid))
    params["messageAuthScheme"] = _alg_id(mac_oid)
    return _round_trip(_alg_id(rfc8018.id_PBMAC1, params))


def _kmac_alg_id(bits: Optional[int], shake: str = "shake128"):
    """Return a KMAC identifier with ``kMACOutputLength`` ``bits`` (absent parameters if None)."""
    oid = rfc9481.id_KMACWithSHAKE128 if shake == "shake128" else rfc9481.id_KMACWithSHAKE256
    if bits is None:
        return _alg_id(oid)
    spec = rfc8702.KMACwithSHAKE128_params if shake == "shake128" else rfc8702.KMACwithSHAKE256_params
    params = spec()
    params["kMACOutputLength"] = bits
    return _round_trip(_alg_id(oid, params))


class TestTheLimitsAreNamed(unittest.TestCase):
    """The limits are constants of the module that owns them."""

    def test_values(self):
        """GIVEN the module constants / WHEN read / THEN the fail-closed defaults for received parameters."""
        self.assertEqual(mechanisms.MIN_PBMAC1_KEY_LENGTH, 16)
        self.assertEqual(mechanisms.MAX_PBMAC1_KEY_LENGTH, 4096)
        self.assertEqual(mechanisms.MIN_KMAC_OUTPUT_BITS, 128)
        self.assertEqual(mechanisms.MAX_PBKDF2_WORK, 25_000_000)
        self.assertEqual(MAX_PBKDF2_ITERATIONS, 10_000_000, "the cap on the iterations stays")


class TestPbmac1KeyLength(unittest.TestCase):
    """PBMAC1 ``keyLength`` is the length of the MAC key: 16 to 4096 octets."""

    DATA = b"protected message"

    def _weak_mac(self, key_length: int) -> bytes:
        """Return the PBMAC1 value that the lower layer computes for ``key_length``, which has no limit."""
        derived = primitives.pbkdf2("sha256", b"password", b"salty", 3, key_length)
        return primitives.hmac_digest("sha256", derived, self.DATA)

    def test_a_key_length_below_16_is_refused_without_computing(self):
        """GIVEN keyLength 1, 8, 15 and the MAC primitives make / WHEN checked / THEN BadAlgParams, no work."""
        for key_length in (1, 8, 15):
            weak = self._weak_mac(key_length)
            alg_id = _pbmac1_alg_id(3, key_length)
            with self.subTest(key_length=key_length):
                with (
                    mock.patch.object(mechanisms.primitives, "pbkdf2") as pbkdf2,
                    mock.patch.object(mechanisms.primitives, "hmac_digest") as hmac_digest,
                ):
                    with self.assertRaises(BadAlgParams):
                        verify_mac(alg_id, b"password", self.DATA, weak)
                    with self.assertRaises(BadAlgParams):
                        compute_mac(alg_id, b"password", self.DATA)
                pbkdf2.assert_not_called()
                hmac_digest.assert_not_called()

    def test_a_key_length_above_4096_is_refused_without_computing(self):
        """GIVEN keyLength 4097 and 1 000 000 / WHEN checked / THEN BadAlgParams, before PBKDF2."""
        for key_length in (4097, 1_000_000):
            alg_id = _pbmac1_alg_id(1, key_length)
            with self.subTest(key_length=key_length):
                with mock.patch.object(mechanisms.primitives, "pbkdf2") as pbkdf2:
                    with self.assertRaises(BadAlgParams):
                        compute_mac(alg_id, b"password", self.DATA)
                    with self.assertRaises(BadAlgParams):
                        verify_mac(alg_id, b"password", self.DATA, bytes(32))
                pbkdf2.assert_not_called()

    def test_the_ends_of_the_range_are_accepted(self):
        """GIVEN keyLength 16 and 4096 / WHEN MACed / THEN hashlib.pbkdf2_hmac followed by hmac, as RFC 8018 says."""
        for key_length in (16, 4096):
            with self.subTest(key_length=key_length):
                derived = hashlib.pbkdf2_hmac("sha256", b"password", b"salty", 2, key_length)
                expected = hmac.new(derived, self.DATA, "sha256").digest()
                alg_id = _pbmac1_alg_id(2, key_length)
                self.assertEqual(compute_mac(alg_id, b"password", self.DATA), expected)
                self.assertIsNone(verify_mac(alg_id, b"password", self.DATA, expected))

    def test_a_normal_pbmac1_still_verifies(self):
        """GIVEN keyLength 32 and 100 000 iterations / WHEN verified / THEN it verifies, and a wrong MAC does not."""
        derived = hashlib.pbkdf2_hmac("sha256", b"password", b"salty", 100_000, 32)
        expected = hmac.new(derived, self.DATA, "sha256").digest()
        alg_id = _pbmac1_alg_id(100_000, 32)
        self.assertIsNone(verify_mac(alg_id, b"password", self.DATA, expected))
        with self.assertRaises(IntegrityError):
            verify_mac(alg_id, b"password", self.DATA, bytes(32))
        derived = hashlib.pbkdf2_hmac("sha512", b"password", b"salty", 10_000, 64)
        expected = hmac.new(derived, self.DATA, "sha512").digest()
        self.assertIsNone(verify_mac(_pbmac1_alg_id(10_000, 64, _SHA512, _SHA512), b"password", self.DATA, expected))


class TestKmacOutputLength(unittest.TestCase):
    """KMAC ``kMACOutputLength`` is at least 128 bits and a whole number of octets."""

    KEY = bytes(range(32))
    DATA = b"protected message"

    def test_8_64_and_120_bits_are_refused_without_computing(self):
        """GIVEN 8, 64 and 120 bits and a MAC value of that size / WHEN checked / THEN BadAlgParams, no KMAC."""
        for bits in (8, 64, 120):
            # pycryptodome makes no KMAC below 8 octets, so only the 64 bit value is a real one; the checked layer must
            # refuse the others before it looks at the value
            weak = primitives.kmac("shake128", self.KEY, self.DATA, mac_len=8) if bits == 64 else bytes(bits // 8)
            alg_id = _kmac_alg_id(bits)
            with self.subTest(bits=bits):
                with mock.patch.object(mechanisms.primitives, "kmac") as kmac:
                    with self.assertRaises(BadAlgParams):
                        verify_mac(alg_id, self.KEY, self.DATA, weak)
                    with self.assertRaises(BadAlgParams):
                        compute_mac(alg_id, self.KEY, self.DATA)
                kmac.assert_not_called()

    def test_128_bits_and_more_are_accepted_with_no_upper_cap(self):
        """GIVEN 128, 136 and 8192 bits / WHEN MACed / THEN the output of the lower layer, whole octets."""
        for bits in (128, 136, 8192):
            with self.subTest(bits=bits):
                expected = primitives.kmac("shake128", self.KEY, self.DATA, mac_len=bits // 8)
                alg_id = _kmac_alg_id(bits)
                self.assertEqual(compute_mac(alg_id, self.KEY, self.DATA), expected)
                self.assertIsNone(verify_mac(alg_id, self.KEY, self.DATA, expected))

    def test_absent_parameters_keep_the_default_output(self):
        """GIVEN no parameters / WHEN MACed / THEN 256 bits for KMAC128 and 512 bits for KMAC256, above the limit."""
        self.assertEqual(len(compute_mac(_kmac_alg_id(None), self.KEY, self.DATA)), 32)
        self.assertEqual(len(compute_mac(_kmac_alg_id(None, "shake256"), self.KEY, self.DATA)), 64)

    def test_the_multiple_of_8_rule_stays(self):
        """GIVEN 129 and 130 bits / WHEN MACed / THEN BadAlgParams."""
        for bits in (129, 130, 255):
            with self.assertRaises(BadAlgParams):
                compute_mac(_kmac_alg_id(bits), self.KEY, self.DATA)

    def test_a_value_of_another_length_is_an_integrity_error(self):
        """GIVEN a prefix or an extension of the MAC / WHEN verified / THEN IntegrityError, constant time."""
        for bits in (128, 256):
            alg_id = _kmac_alg_id(bits)
            mac = compute_mac(alg_id, self.KEY, self.DATA)
            for name, value in (("prefix", mac[:8]), ("half", mac[: len(mac) // 2]), ("extended", mac + b"\x00")):
                with self.subTest(bits=bits, case=name):
                    with mock.patch.object(mechanisms.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
                        with self.assertRaises(IntegrityError):
                            verify_mac(alg_id, self.KEY, self.DATA, value)
                    compare.assert_called_once_with(mac, value)


class TestPbkdf2Work(unittest.TestCase):
    """The work of PBKDF2, ``iterations * ceil(length / digest size)``, is at most 25 000 000 blocks."""

    def _derive(self, alg_id, length: int) -> mock.MagicMock:
        """Call kdf_derive with PBKDF2 stubbed out; return the stub, so that a test sees whether work was started."""
        with mock.patch.object(mechanisms.primitives, "pbkdf2", return_value=bytes(length)) as pbkdf2:
            kdf_derive(alg_id, b"password", length)
        return pbkdf2

    def _refused(self, alg_id, length: int) -> None:
        """Assert that kdf_derive refuses with BadAlgParams and starts no work."""
        with mock.patch.object(mechanisms.primitives, "pbkdf2") as pbkdf2:
            with self.assertRaises(BadAlgParams):
                kdf_derive(alg_id, b"password", length)
        pbkdf2.assert_not_called()

    def test_the_work_at_the_limit_is_accepted_and_one_more_iteration_is_not(self):
        """GIVEN HMAC-SHA1, 80 octets (4 blocks), 6 250 000 and 6 250 001 iterations / WHEN derived / THEN the bound."""
        pbkdf2 = self._derive(_pbkdf2_alg_id(6_250_000, prf_oid=_SHA1_PRF), 80)
        pbkdf2.assert_called_once_with("sha1", b"password", b"salty", 6_250_000, 80)
        self._refused(_pbkdf2_alg_id(6_250_001, prf_oid=_SHA1_PRF), 80)

    def test_the_number_of_blocks_rounds_up(self):
        """GIVEN HMAC-SHA1 and 81 octets (5 blocks) / WHEN derived / THEN 5 000 000 iterations fit, 5 000 001 do not."""
        self._derive(_pbkdf2_alg_id(5_000_000, prf_oid=_SHA1_PRF), 81)
        self._refused(_pbkdf2_alg_id(5_000_001, prf_oid=_SHA1_PRF), 81)

    def test_the_digest_size_of_the_prf_decides(self):
        """GIVEN 64 octets / WHEN derived with HMAC-SHA1 (4 blocks) and -SHA512 (1 block) / THEN the bound differs."""
        self._refused(_pbkdf2_alg_id(6_250_001, prf_oid=_SHA1_PRF), 64 + 16)
        self._derive(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS, prf_oid=_SHA512), 64)  # 10 000 000 blocks
        self._refused(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS, prf_oid=_SHA512), 64 * 3)  # 30 000 000 blocks
        self._derive(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS, prf_oid=_SHA512), 64 * 2)  # 20 000 000 blocks

    def test_the_length_of_the_caller_plays_the_role_of_key_length(self):
        """GIVEN keyLength absent and present and equal / WHEN derived / THEN both are bounded by the same length."""
        self._derive(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS, None, _SHA256), 64)  # 2 blocks, 20 000 000
        self._refused(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS, None, _SHA256), 96)  # 3 blocks, 30 000 000
        self._refused(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS, 96, _SHA256), 96)

    def test_the_iteration_cap_is_checked_first_and_stays(self):
        """GIVEN one more iteration than the cap / WHEN derived / THEN BadAlgParams, with no work."""
        self._refused(_pbkdf2_alg_id(MAX_PBKDF2_ITERATIONS + 1), 32)

    def test_a_legitimate_derivation_is_unchanged(self):
        """GIVEN 100 000 iterations and 32 octets / WHEN derived for real / THEN equal to hashlib.pbkdf2_hmac."""
        alg_id = _pbkdf2_alg_id(100_000, 32)
        self.assertEqual(
            kdf_derive(alg_id, b"password", 32), hashlib.pbkdf2_hmac("sha256", b"password", b"salty", 100_000, 32)
        )

    def test_pbmac1_has_the_same_bound_on_its_key_length(self):
        """GIVEN PBMAC1, keyLength 80, HMAC-SHA1 / WHEN MACed / THEN 6 250 000 iterations fit, 6 250 001 do not."""
        with mock.patch.object(mechanisms.primitives, "pbkdf2", return_value=bytes(80)) as pbkdf2:
            compute_mac(_pbmac1_alg_id(6_250_000, 80, _SHA1_PRF, _SHA256), b"password", b"data")
        pbkdf2.assert_called_once_with("sha1", b"password", b"salty", 6_250_000, 80)
        with mock.patch.object(mechanisms.primitives, "pbkdf2") as pbkdf2:
            with self.assertRaises(BadAlgParams):
                compute_mac(_pbmac1_alg_id(6_250_001, 80, _SHA1_PRF, _SHA256), b"password", b"data")
            with self.assertRaises(BadAlgParams):
                verify_mac(_pbmac1_alg_id(6_250_001, 80, _SHA1_PRF, _SHA256), b"password", b"data", bytes(32))
        pbkdf2.assert_not_called()

    def test_the_primitive_has_no_limit(self):
        """GIVEN a one octet derivation and key / WHEN made with primitives / THEN it works: negative tests need it."""
        self.assertEqual(len(primitives.pbkdf2("sha256", b"password", b"salty", 2, 1)), 1)
        self.assertEqual(len(primitives.hmac_digest("sha256", b"k", b"data")), 32)


if __name__ == "__main__":
    unittest.main()
