# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``compute_mac``, ``verify_mac`` and ``mac_key_length`` of ``keyutils_py.mechanisms``.

External vectors, so that a shared misreading of the OID, the parameters or the function cannot pass both sides:

* HMAC: RFC 2202 and RFC 4231 test cases 1 and 2 (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512), SHA-3 against ``hmac``.
* KMAC: the samples 1, 2, 3 (KMAC128) and 4, 5, 6 (KMAC256) of NIST SP 800-185, through the OIDs of RFC 9481.
* AES-GMAC: the GCM specification (McGrew and Viega) test cases 1, 7 and 13 and AES-GCM of ``cryptography``.
* PBMAC1: ``hashlib.pbkdf2_hmac`` followed by ``hmac``, as RFC 8018 Section 7.1 defines it.
"""

import hashlib
import hmac
import unittest
from typing import Optional
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from keyutils_py import _algs, mechanisms
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data, IntegrityError
from keyutils_py.mechanisms import compute_mac, mac_key_length, verify_mac
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3370, rfc5280, rfc8018, rfc8619, rfc8702, rfc9044, rfc9481, rfc9688

_HMAC_SHA2 = {
    "sha224": rfc8018.id_hmacWithSHA224,
    "sha256": rfc8018.id_hmacWithSHA256,
    "sha384": rfc8018.id_hmacWithSHA384,
    "sha512": rfc8018.id_hmacWithSHA512,
}
_HMAC_SHA3 = {
    "sha3_224": rfc9688.id_hmacWithSHA3_224,
    "sha3_256": rfc9688.id_hmacWithSHA3_256,
    "sha3_384": rfc9688.id_hmacWithSHA3_384,
    "sha3_512": rfc9688.id_hmacWithSHA3_512,
}
_GMAC = {16: rfc9481.id_aes128_GMAC, 24: rfc9481.id_aes192_GMAC, 32: rfc9481.id_aes256_GMAC}


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Return an ``AlgorithmIdentifier``; ``parameters`` is an ASN.1 object, DER bytes (kept as ``Any``) or None."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if isinstance(parameters, bytes):
        alg_id["parameters"] = univ.Any(parameters)
    elif parameters is not None:
        alg_id["parameters"] = univ.Any(encoder.encode(parameters))
    return alg_id


def _round_trip(alg_id: rfc5280.AlgorithmIdentifier) -> rfc5280.AlgorithmIdentifier:
    """Return the identifier as a receiver has it: DER encoded and decoded."""
    decoded, rest = decoder.decode(encoder.encode(alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
    assert not rest
    return decoded


def _gmac_alg_id(key_length: int, nonce: bytes = bytes(12), length: Optional[int] = None):
    """Return an AES-GMAC identifier whose parameters carry ``nonce`` and, if given, ``length``."""
    params = rfc9044.GCMParameters()
    params["nonce"] = nonce
    if length is not None:
        params["length"] = length
    return _alg_id(_GMAC[key_length], params)


def _pbmac1_alg_id(
    prf_oid=rfc8018.id_hmacWithSHA256,
    mac_oid=rfc8018.id_hmacWithSHA256,
    salt: bytes = b"salty",
    iterations: int = 3,
    key_length: Optional[int] = 24,
) -> rfc5280.AlgorithmIdentifier:
    """Return a PBMAC1 identifier: the prf as RFC 8018 writes it, the HMAC of the scheme without parameters."""
    pbkdf2 = rfc8018.PBKDF2_params()
    pbkdf2["salt"]["specified"] = salt
    pbkdf2["iterationCount"] = iterations
    if key_length is not None:
        pbkdf2["keyLength"] = key_length
    # RFC 8018 Appendix B.1: NULL for the SHA-1 and SHA-2 functions, none for SHA-3 (RFC 9688 Section 4)
    pbkdf2["prf"] = _alg_id(prf_oid) if prf_oid in _HMAC_SHA3.values() else _alg_id(prf_oid, univ.Null(""))
    params = rfc8018.PBMAC1_params()
    params["keyDerivationFunc"] = _alg_id(rfc8018.id_PBKDF2, pbkdf2)
    params["messageAuthScheme"] = _alg_id(mac_oid)
    return _alg_id(rfc8018.id_PBMAC1, params)


class TestHmac(unittest.TestCase):
    """HMAC: the hash is the one of the OID."""

    KEY1, DATA1 = bytes([0x0B]) * 20, b"Hi There"
    KEY2, DATA2 = b"Jefe", b"what do ya want for nothing?"

    def test_rfc_2202_sha1_with_both_oids(self):
        """GIVEN hMAC-SHA1 and id-hmacWithSHA1 / WHEN RFC 2202 test cases 1 and 2 are MACed / THEN the RFC values."""
        for oid in (rfc3370.hMAC_SHA1, rfc8018.id_hmacWithSHA1):
            with self.subTest(oid=str(oid)):
                self.assertEqual(
                    compute_mac(_alg_id(oid), self.KEY1, self.DATA1).hex(), "b617318655057264e28bc0b6fb378c8ef146be00"
                )
                self.assertEqual(
                    compute_mac(_alg_id(oid), self.KEY2, self.DATA2).hex(), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
                )

    def test_rfc_4231_test_cases_1_and_2(self):
        """GIVEN the SHA-2 OIDs / WHEN RFC 4231 test cases 1 and 2 are MACed / THEN the values of the RFC."""
        expected = {
            "sha224": (
                "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
                "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            ),
            "sha256": (
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            "sha384": (
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            ),
            "sha512": (
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4"
                "be9d914eeb61f1702e696c203a126854",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fd"
                "caeab1a34d4a6b4b636e070a38bce737",
            ),
        }
        for name, (case1, case2) in expected.items():
            with self.subTest(hash=name):
                alg_id = _alg_id(_HMAC_SHA2[name])
                self.assertEqual(compute_mac(alg_id, self.KEY1, self.DATA1).hex(), case1)
                self.assertEqual(compute_mac(alg_id, self.KEY2, self.DATA2).hex(), case2)

    def test_every_hmac_row_equals_the_standard_library(self):
        """GIVEN all 10 HMAC OIDs incl. SHA-3 / WHEN MACed / THEN equal to hmac of the standard library."""
        rows = [row for row in _algs.MAC_ROWS if row.family == "hmac"]
        self.assertEqual(len(rows), 10)
        for row in rows:
            with self.subTest(hash=row.hash, oid=str(row.oid)):
                self.assertEqual(
                    compute_mac(_round_trip(_alg_id(row.oid)), b"k" * 70, b"data"),
                    hmac.new(b"k" * 70, b"data", row.hash).digest(),
                )

    def test_null_parameters_are_accepted_for_sha_1_and_sha_2_only(self):
        """GIVEN NULL parameters / WHEN MACed / THEN SHA-1 and SHA-2 are accepted, SHA-3 is BadAlgParams (RFC 9688)."""
        for oid in (rfc3370.hMAC_SHA1, rfc8018.id_hmacWithSHA1, *_HMAC_SHA2.values()):
            self.assertEqual(
                compute_mac(_alg_id(oid, univ.Null("")), b"k", b"d"), compute_mac(_alg_id(oid), b"k", b"d")
            )
        for oid in _HMAC_SHA3.values():
            with self.assertRaises(BadAlgParams):
                compute_mac(_alg_id(oid, univ.Null("")), b"k", b"d")

    def test_other_parameters_are_refused(self):
        """GIVEN an OCTET STRING or an empty SEQUENCE as parameters / WHEN MACed / THEN BadAlgParams."""
        for parameters in (univ.OctetString(b"x"), univ.Sequence()):
            with self.assertRaises(BadAlgParams):
                compute_mac(_alg_id(rfc8018.id_hmacWithSHA256, parameters), b"k", b"d")

    def test_an_empty_key_is_a_valid_hmac_key(self):
        """GIVEN an empty key / WHEN MACed / THEN the HMAC of the standard library."""
        self.assertEqual(
            compute_mac(_alg_id(rfc8018.id_hmacWithSHA256), b"", b"d"), hmac.new(b"", b"d", "sha256").digest()
        )


class TestKmac(unittest.TestCase):
    """KMAC128 and KMAC256 through the OIDs of RFC 9481, with and without ``KMACwithSHAKE-params``."""

    KEY = bytes(range(0x40, 0x60))
    SHORT = bytes(range(4))
    LONG = bytes(range(200))
    TAG = b"My Tagged Application"

    @staticmethod
    def _params(spec, bits: Optional[int] = None, custom: bytes = b""):
        """Return KMAC parameters of ``spec`` (RFC 8702 Appendix A)."""
        params = spec()
        if bits is not None:
            params["kMACOutputLength"] = bits
        if custom:
            params["customizationString"] = custom
        return params

    def test_nist_sp_800_185_samples_without_parameters(self):
        """GIVEN absent parameters (256 or 512 bits, no customization) / WHEN MACed / THEN NIST samples 1 and 5."""
        self.assertEqual(
            compute_mac(_alg_id(rfc9481.id_KMACWithSHAKE128), self.KEY, self.SHORT).hex(),
            "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
        )
        self.assertEqual(
            compute_mac(_alg_id(rfc9481.id_KMACWithSHAKE256), self.KEY, self.LONG).hex(),
            "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691"
            "589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
        )

    def test_nist_sp_800_185_samples_with_a_customization_string(self):
        """GIVEN customizationString in the parameters / WHEN MACed / THEN NIST samples 2, 3, 4 and 6."""
        k128 = lambda custom: _alg_id(  # noqa: E731
            rfc9481.id_KMACWithSHAKE128, self._params(rfc8702.KMACwithSHAKE128_params, custom=custom)
        )
        k256 = lambda custom, bits=None: _alg_id(  # noqa: E731
            rfc9481.id_KMACWithSHAKE256, self._params(rfc8702.KMACwithSHAKE256_params, bits, custom)
        )
        self.assertEqual(
            compute_mac(k128(self.TAG), self.KEY, self.SHORT).hex(),
            "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
        )
        self.assertEqual(
            compute_mac(k128(self.TAG), self.KEY, self.LONG).hex(),
            "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
        )
        self.assertEqual(
            compute_mac(k256(self.TAG), self.KEY, self.SHORT).hex(),
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
            "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
        )
        self.assertEqual(
            compute_mac(k256(self.TAG), self.KEY, self.LONG).hex(),
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9"
            "70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
        )

    def test_output_length_of_the_parameters(self):
        """GIVEN kMACOutputLength 512 for KMAC128 / WHEN MACed / THEN 64 octets, as the lower layer computes them."""
        alg_id = _alg_id(rfc9481.id_KMACWithSHAKE128, self._params(rfc8702.KMACwithSHAKE128_params, bits=512))
        mac = compute_mac(_round_trip(alg_id), self.KEY, self.SHORT)
        self.assertEqual(len(mac), 64)
        from keyutils_py import primitives

        self.assertEqual(mac, primitives.kmac("shake128", self.KEY, self.SHORT, mac_len=64))

    def test_an_output_length_that_is_no_whole_number_of_octets_is_refused(self):
        """GIVEN kMACOutputLength 100 and 0 / WHEN MACed / THEN BadAlgParams."""
        for bits in (100, 0):
            alg_id = _alg_id(rfc9481.id_KMACWithSHAKE128, self._params(rfc8702.KMACwithSHAKE128_params, bits=bits))
            with self.subTest(bits=bits):
                with self.assertRaises(BadAlgParams):
                    compute_mac(alg_id, self.KEY, self.SHORT)

    def test_undecodable_and_trailing_parameters(self):
        """GIVEN parameters that are no SEQUENCE, and a SEQUENCE with data after it / WHEN MACed / THEN the errors."""
        with self.assertRaises(BadAsn1Data):
            compute_mac(_alg_id(rfc9481.id_KMACWithSHAKE128, b"\x04\x01x"), self.KEY, self.SHORT)
        with self.assertRaises(BadAlgParams):
            compute_mac(_alg_id(rfc9481.id_KMACWithSHAKE128, b"\x30\x00\x05\x00"), self.KEY, self.SHORT)

    def test_a_short_key_is_a_value_error(self):
        """GIVEN a 15 octet key for KMAC128 / WHEN MACed / THEN ValueError (the limit of pycryptodome)."""
        with self.assertRaises(ValueError):
            compute_mac(_alg_id(rfc9481.id_KMACWithSHAKE128), bytes(15), self.SHORT)


class TestGmac(unittest.TestCase):
    """AES-GMAC: GCM over no plaintext, the tag cut to the ``length`` of the parameters."""

    TAGS = {
        16: "58e2fccefa7e3061367f1d57a4e7455a",
        24: "cd33b28ac773f74ba00ed1f312572435",
        32: "530f8afbc74536b9a963b4f1c4cb738b",
    }

    def test_gcm_specification_test_cases_1_7_13(self):
        """GIVEN zero key and nonce, no data / WHEN MACed with length 16 / THEN the tag of the GCM specification."""
        for key_length, tag in self.TAGS.items():
            with self.subTest(key_bits=key_length * 8):
                alg_id = _round_trip(_gmac_alg_id(key_length, length=16))
                self.assertEqual(compute_mac(alg_id, bytes(key_length), b"").hex(), tag)

    def test_the_default_length_is_12_octets(self):
        """GIVEN parameters without length / WHEN MACed / THEN the first 12 octets of the tag (RFC 9044 DEFAULT 12)."""
        alg_id = _round_trip(_gmac_alg_id(16))
        self.assertEqual(compute_mac(alg_id, bytes(16), b"").hex(), self.TAGS[16][:24])

    def test_every_length_from_12_to_16_cuts_the_tag(self):
        """GIVEN lengths 12 to 16 / WHEN MACed / THEN the leftmost octets of the AES-GCM tag of cryptography."""
        key, nonce, data = bytes(range(32)), bytes(range(12)), b"authenticated only"
        full = AESGCM(key).encrypt(nonce, b"", data)
        for length in range(12, 17):
            with self.subTest(length=length):
                alg_id = _round_trip(_gmac_alg_id(32, nonce, length))
                self.assertEqual(compute_mac(alg_id, key, data), full[:length])

    def test_a_nonce_of_8_to_128_octets_is_accepted_others_refused(self):
        """GIVEN nonces of 7, 8, 128 and 129 octets / WHEN MACed / THEN the ends of the range decide."""
        for size, ok in ((7, False), (8, True), (128, True), (129, False)):
            with self.subTest(nonce=size):
                alg_id = _gmac_alg_id(16, bytes(size))
                if ok:
                    compute_mac(alg_id, bytes(16), b"x")
                else:
                    with self.assertRaises(BadAlgParams):
                        compute_mac(alg_id, bytes(16), b"x")

    def test_the_key_size_must_match_the_oid(self):
        """GIVEN a 16 octet key with the AES-256 OID, and the other way round / WHEN MACed / THEN BadAlgParams."""
        for oid_key_length, key_length in ((32, 16), (16, 32), (24, 16)):
            with self.subTest(oid=oid_key_length * 8, key=key_length * 8):
                with self.assertRaises(BadAlgParams):
                    compute_mac(_gmac_alg_id(oid_key_length), bytes(key_length), b"x")

    def test_parameters_are_required_and_must_decode(self):
        """GIVEN no parameters, a bare OCTET STRING, a length of 11 / WHEN MACed / THEN the errors."""
        with self.assertRaises(BadAlgParams):
            compute_mac(_alg_id(_GMAC[16]), bytes(16), b"x")
        with self.assertRaises(BadAsn1Data):
            compute_mac(_alg_id(_GMAC[16], b"\x04\x0c" + bytes(12)), bytes(16), b"x")
        too_short = b"\x30\x11\x04\x0c" + bytes(12) + b"\x02\x01\x0b"  # SEQUENCE { nonce, length 11 }
        with self.assertRaises(BadAsn1Data):
            compute_mac(_alg_id(_GMAC[16], too_short), bytes(16), b"x")

    def test_the_data_is_authenticated(self):
        """GIVEN two data / WHEN MACed / THEN two tags."""
        alg_id = _gmac_alg_id(16)
        self.assertNotEqual(compute_mac(alg_id, bytes(16), b"a"), compute_mac(alg_id, bytes(16), b"b"))


class TestPbmac1(unittest.TestCase):
    """PBMAC1: PBKDF2 over the password, then HMAC; compared with ``hashlib`` and ``hmac``."""

    HASH_OIDS = {"sha1": rfc8018.id_hmacWithSHA1, **_HMAC_SHA2, **_HMAC_SHA3}

    def test_equals_pbkdf2_followed_by_hmac(self):
        """GIVEN PBKDF2 and HMAC hashes that differ / WHEN MACed / THEN equal to hashlib.pbkdf2_hmac then hmac."""
        for prf in ("sha1", "sha256", "sha3_256", "sha512"):
            for mac in ("sha256", "sha384", "sha3_512"):
                with self.subTest(prf=prf, mac=mac):
                    alg_id = _round_trip(_pbmac1_alg_id(self.HASH_OIDS[prf], self.HASH_OIDS[mac]))
                    derived = hashlib.pbkdf2_hmac(prf, b"password", b"salty", 3, 24)
                    self.assertEqual(
                        compute_mac(alg_id, b"password", b"message"), hmac.new(derived, b"message", mac).digest()
                    )

    def test_the_password_and_the_salt_matter(self):
        """GIVEN another password or salt / WHEN MACed / THEN another MAC."""
        base = compute_mac(_pbmac1_alg_id(), b"password", b"m")
        self.assertNotEqual(base, compute_mac(_pbmac1_alg_id(), b"Password", b"m"))
        self.assertNotEqual(base, compute_mac(_pbmac1_alg_id(salt=b"other"), b"password", b"m"))

    def test_an_absent_key_length_is_bad_alg_params(self):
        """GIVEN PBKDF2-params without keyLength / WHEN MACed / THEN BadAlgParams: it is the key length of the MAC."""
        with self.assertRaises(BadAlgParams):
            compute_mac(_round_trip(_pbmac1_alg_id(key_length=None)), b"password", b"m")

    def test_the_key_derivation_function_must_be_pbkdf2(self):
        """GIVEN HKDF as keyDerivationFunc / WHEN MACed / THEN BadAlg."""
        params = rfc8018.PBMAC1_params()
        params["keyDerivationFunc"] = _alg_id(rfc8619.id_alg_hkdf_with_sha256)
        params["messageAuthScheme"] = _alg_id(rfc8018.id_hmacWithSHA256)
        with self.assertRaises(BadAlg):
            compute_mac(_alg_id(rfc8018.id_PBMAC1, params), b"password", b"m")

    def test_the_message_authentication_scheme_must_be_an_hmac(self):
        """GIVEN GMAC, KMAC, PBMAC1 and an unknown OID as scheme / WHEN MACed / THEN BadAlg."""
        for oid in (
            rfc9481.id_aes128_GMAC,
            rfc9481.id_KMACWithSHAKE128,
            rfc8018.id_PBMAC1,
            univ.ObjectIdentifier("1.2.3"),
        ):
            with self.subTest(oid=str(oid)):
                with self.assertRaises(BadAlg):
                    compute_mac(_round_trip(_pbmac1_alg_id(mac_oid=oid)), b"password", b"m")

    def test_parameters_are_required_and_must_decode(self):
        """GIVEN absent parameters, a bare NULL, trailing data / WHEN MACed / THEN the errors."""
        with self.assertRaises(BadAlgParams):
            compute_mac(_alg_id(rfc8018.id_PBMAC1), b"password", b"m")
        with self.assertRaises(BadAsn1Data):
            compute_mac(_alg_id(rfc8018.id_PBMAC1, b"\x05\x00"), b"password", b"m")
        good = encoder.encode(_pbmac1_alg_id())
        params_der = decoder.decode(good, asn1Spec=rfc5280.AlgorithmIdentifier())[0]["parameters"].asOctets()
        with self.assertRaises(BadAlgParams):
            compute_mac(_alg_id(rfc8018.id_PBMAC1, params_der + b"\x05\x00"), b"password", b"m")

    def test_the_iteration_cap_applies(self):
        """GIVEN more iterations than the cap / WHEN MACed / THEN BadAlgParams."""
        with self.assertRaises(BadAlgParams):
            compute_mac(_round_trip(_pbmac1_alg_id(iterations=10_000_001)), b"password", b"m")


class TestVerifyMac(unittest.TestCase):
    """``verify_mac``: constant time, ``IntegrityError``, SHA-1 only on request."""

    ALG_IDS = {
        "hmac": _alg_id(rfc8018.id_hmacWithSHA256),
        "kmac": _alg_id(rfc9481.id_KMACWithSHAKE256),
        "gmac": _gmac_alg_id(16, length=16),
        "pbmac1": _pbmac1_alg_id(),
    }
    KEYS = {"hmac": b"k" * 20, "kmac": bytes(32), "gmac": bytes(16), "pbmac1": b"password"}

    def test_a_correct_mac_verifies_for_every_family(self):
        """GIVEN the MAC from compute_mac / WHEN verified / THEN None."""
        for family, alg_id in self.ALG_IDS.items():
            with self.subTest(family=family):
                mac = compute_mac(alg_id, self.KEYS[family], b"data")
                self.assertIsNone(verify_mac(alg_id, self.KEYS[family], b"data", mac))

    def test_a_changed_mac_data_key_or_length_is_an_integrity_error_with_one_message(self):
        """GIVEN a flipped, cut, extended or empty MAC, other data or key / WHEN verified / THEN one message."""
        messages = set()
        for family, alg_id in self.ALG_IDS.items():
            key = self.KEYS[family]
            mac = compute_mac(alg_id, key, b"data")
            other_key = bytes([key[0] ^ 1]) + key[1:]
            cases = (
                (key, b"data", bytes([mac[0] ^ 1]) + mac[1:]),
                (key, b"data", mac[:-1] + bytes([mac[-1] ^ 1])),
                (key, b"data", mac[:-1]),
                (key, b"data", mac + b"\x00"),
                (key, b"data", b""),
                (key, b"datb", mac),
                (other_key, b"data", mac),
            )
            for index, (case_key, data, value) in enumerate(cases):
                with self.subTest(family=family, case=index):
                    with self.assertRaises(IntegrityError) as caught:
                        verify_mac(alg_id, case_key, data, value)
                    messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1, "the message must not tell how the MAC differs")

    def test_the_comparison_is_constant_time(self):
        """GIVEN a verification / WHEN it runs / THEN hmac.compare_digest decides."""
        alg_id = self.ALG_IDS["hmac"]
        mac = compute_mac(alg_id, b"k", b"d")
        with mock.patch.object(mechanisms.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            verify_mac(alg_id, b"k", b"d", mac)
        compare.assert_called_once_with(mac, mac)

    def test_sha_1_is_refused_unless_it_is_allowed(self):
        """GIVEN HMAC-SHA1 (both OIDs) and PBMAC1 over SHA-1 / WHEN verified / THEN BadAlg, unless allow_sha1."""
        cases = {
            "hMAC-SHA1": (_alg_id(rfc3370.hMAC_SHA1), b"k"),
            "id-hmacWithSHA1": (_alg_id(rfc8018.id_hmacWithSHA1), b"k"),
            "PBMAC1 prf": (_pbmac1_alg_id(prf_oid=rfc8018.id_hmacWithSHA1), b"password"),
            "PBMAC1 mac": (_pbmac1_alg_id(mac_oid=rfc8018.id_hmacWithSHA1), b"password"),
        }
        for name, (alg_id, key) in cases.items():
            with self.subTest(case=name):
                mac = compute_mac(alg_id, key, b"d")  # producing SHA-1 is not restricted
                with self.assertRaises(BadAlg):
                    verify_mac(alg_id, key, b"d", mac)
                self.assertIsNone(verify_mac(alg_id, key, b"d", mac, allow_sha1=True))
                with self.assertRaises(IntegrityError):
                    verify_mac(alg_id, key, b"d", bytes(len(mac)), allow_sha1=True)

    def test_sha_1_is_refused_before_the_value_is_looked_at(self):
        """GIVEN a wrong SHA-1 MAC without allow_sha1 / WHEN verified / THEN BadAlg, not IntegrityError."""
        with self.assertRaises(BadAlg):
            verify_mac(_alg_id(rfc3370.hMAC_SHA1), b"k", b"d", b"wrong")

    def test_allow_sha1_is_keyword_only_and_other_hashes_do_not_need_it(self):
        """GIVEN SHA-256 / WHEN verified without allow_sha1 / THEN it verifies; a positional flag is a TypeError."""
        alg_id = self.ALG_IDS["hmac"]
        mac = compute_mac(alg_id, b"k", b"d")
        self.assertIsNone(verify_mac(alg_id, b"k", b"d", mac))
        with self.assertRaises(TypeError):
            verify_mac(alg_id, b"k", b"d", mac, True)  # type: ignore[misc]


class TestMacKeyLength(unittest.TestCase):
    """``mac_key_length``: the key size that the OID fixes."""

    def test_gmac_fixes_the_key_size_others_do_not(self):
        """GIVEN each MAC row / WHEN asked / THEN 16, 24, 32 for AES-GMAC and None for the others."""
        for row in _algs.MAC_ROWS:
            with self.subTest(family=row.family, oid=str(row.oid)):
                expected = {128: 16, 192: 24, 256: 32}[row.bits] if row.family == "gmac" else None
                self.assertEqual(mac_key_length(_alg_id(row.oid)), expected)

    def test_an_oid_that_is_no_mac_is_bad_alg(self):
        """GIVEN an HKDF OID / WHEN asked / THEN BadAlg."""
        with self.assertRaises(BadAlg):
            mac_key_length(_alg_id(rfc8619.id_alg_hkdf_with_sha256))


class TestTheCall(unittest.TestCase):
    """What every MAC has in common."""

    def test_an_oid_that_is_no_mac_is_bad_alg(self):
        """GIVEN a KDF, a wrap and an unknown OID / WHEN MACed / THEN BadAlg."""
        for oid in (rfc8619.id_alg_hkdf_with_sha256, rfc9481.id_aes128_wrap, univ.ObjectIdentifier("1.2.3.4")):
            with self.assertRaises(BadAlg):
                compute_mac(_alg_id(oid), b"k", b"d")

    def test_an_identifier_without_oid_is_bad_alg_and_a_wrong_type_a_type_error(self):
        """GIVEN an empty identifier, an OID, bytes / WHEN MACed / THEN BadAlg or TypeError."""
        with self.assertRaises(BadAlg):
            compute_mac(rfc5280.AlgorithmIdentifier(), b"k", b"d")
        for value in (rfc8018.id_hmacWithSHA256, b"x", None):
            with self.assertRaises(TypeError):
                compute_mac(value, b"k", b"d")  # type: ignore[arg-type]

    def test_a_str_key_is_a_type_error(self):
        """GIVEN a str key / WHEN MACed / THEN TypeError, not a silent encoding."""
        with self.assertRaises(TypeError):
            compute_mac(_alg_id(rfc8018.id_hmacWithSHA256), "key", b"d")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
