# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``keyutils_py.mechanisms.kdf_derive``.

External vectors, so that a shared misreading of the OID, the parameters or the function cannot pass both sides:

* RFC 5869 Appendix A.3 (HKDF-SHA-256 without salt and info), and HKDF with SHA-2 and SHA-3 (RFC 8619, RFC 9688
  Section 5.1) against a ten-line reference written with ``hmac``.
* X9.63 (KDF2) against ``cryptography``'s ``X963KDF`` for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and SHA3-256 at
  16, 32 and 70 octets; KDF3 against RFC 9690 Appendix D.1 (the identifier is the one of the RFC, SHA-256 with NULL).
* RFC 6070 (PBKDF2-HMAC-SHA-1) through ``PBKDF2-params`` without ``prf``, the DEFAULT path of RFC 8018 Appendix A.2,
  RFC 7914 Section 11 (PBKDF2-HMAC-SHA-256) and ``hashlib.pbkdf2_hmac`` for the other hashes.
"""

import hashlib
import hmac
import unittest
from typing import Optional
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from keyutils_py import _algs, mechanisms
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data
from keyutils_py.keys.key_pyasn1_utils import MAX_PBKDF2_ITERATIONS
from keyutils_py.mechanisms import kdf_derive
from keyutils_py.oids import sha_alg_name_to_oid
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5990, rfc8018, rfc8619, rfc9481, rfc9688

_CRYPTOGRAPHY_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
}
_WITH_NULL = ("sha1", "sha224", "sha256", "sha384", "sha512")
_RFC_9690_Z = bytes.fromhex(
    "9c126102a5c1c0354672a3c2f19fc9ddea988f815e1da812c7bd4f8eb082bdd14f85a7f7c2f1af11d5333e0d6bcb375b"
    "f855f208da72ba27e6fb0655f2825aa62b93b1f9bbd3491fed58f0380fa0de36430e3a144d569600bd362609be5b9481"
    "0875990b614e406fa6dff500043cbca95968faba61f795096a7fb3687a51078c4ca2cb663366b0bea0cd9cccac72a25f"
    "3f4ed03deb68b4453bba44b943f4367b67d6cd10c8ace53f545aac50968fc3c6ecc80f3224b64e37038504e2d2c0e2b2"
    "9d45e46c62826d96331360e4c17ea3ef89a9efc5fac99eda830e81450b6534dc0bdf042b8f3b706649c631fe51fc2445"
    "cc8d447203ec2f41f79cdfea16de1ce6abdfdc1e2ef2e5d5d8a65e645f397240ef5a26f5e4ff715de782e30ecf477293"
    "e89e13171405909a8e04dd31d21d0c57935fc1ceea8e1033e31e1bc8c56da0f3d79510f3f380ff58e5a61d361f2f18e9"
    "9fbae5663172e8cd1f21deaddc5bbbea060d55f1842b93d1a9c888d0bf85d0af9947fe51acf940c7e7577eb79cabecb3"
)


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Return an ``AlgorithmIdentifier``; ``parameters`` is an ASN.1 object, DER bytes (kept as ``Any``) or None."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if isinstance(parameters, bytes):
        alg_id["parameters"] = univ.Any(parameters)
    elif parameters is not None:
        alg_id["parameters"] = univ.Any(encoder.encode(parameters))
    return alg_id


def _hash_alg_id(name: str, null: Optional[bool] = None) -> rfc5280.AlgorithmIdentifier:
    """Return the identifier of a hash, with NULL parameters for SHA-1 and SHA-2 (the form of RFC 9690 D.2)."""
    with_null = name in _WITH_NULL if null is None else null
    return _alg_id(sha_alg_name_to_oid(name), univ.Null("") if with_null else None)


def _round_trip(alg_id: rfc5280.AlgorithmIdentifier) -> rfc5280.AlgorithmIdentifier:
    """Return the identifier as a receiver has it: DER encoded and decoded, the parameters as ``Any``."""
    decoded, rest = decoder.decode(encoder.encode(alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
    assert not rest
    return decoded


def _pbkdf2_params(
    salt: bytes = b"salt",
    iterations: int = 1,
    key_length: Optional[int] = None,
    prf: Optional[rfc5280.AlgorithmIdentifier] = None,
) -> rfc8018.PBKDF2_params:
    """Return ``PBKDF2-params``; without ``prf`` the field is left to its DEFAULT (HMAC-SHA-1)."""
    params = rfc8018.PBKDF2_params()
    params["salt"]["specified"] = salt
    params["iterationCount"] = iterations
    if key_length is not None:
        params["keyLength"] = key_length
    if prf is not None:
        params["prf"] = prf
    return params


def _der_sequence(*parts: bytes) -> bytes:
    """Return the DER of a SEQUENCE of already encoded parts (shorter than 65536 octets)."""
    body = b"".join(parts)
    if len(body) < 128:
        return b"\x30" + bytes([len(body)]) + body
    return b"\x30\x82" + len(body).to_bytes(2, "big") + body


def _pbkdf2_der_with_prf(prf: rfc5280.AlgorithmIdentifier, iterations: int = 3, key_length: int = 33) -> bytes:
    """Return the DER of PBKDF2-params with salt "salty" and an explicit prf, which may have absent parameters."""
    return _der_sequence(
        encoder.encode(univ.OctetString(b"salty")),
        encoder.encode(univ.Integer(iterations)),
        encoder.encode(univ.Integer(key_length)),
        _der_sequence(
            encoder.encode(prf["algorithm"]), *([encoder.encode(univ.Null(""))] if prf["parameters"].isValue else [])
        ),
    )


def _pbkdf2_alg_id(**kwargs) -> rfc5280.AlgorithmIdentifier:
    """Return an ``id-PBKDF2`` identifier."""
    return _alg_id(rfc8018.id_PBKDF2, _pbkdf2_params(**kwargs))


def _hkdf_reference(hash_name: str, ikm: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Section 2 with ``hmac`` and no salt."""
    digest_size = hashlib.new(hash_name).digest_size
    prk = hmac.new(bytes(digest_size), ikm, hash_name).digest()
    okm, block = b"", b""
    for counter in range(1, -(-length // digest_size) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hash_name).digest()
        okm += block
    return okm[:length]


class TestHkdf(unittest.TestCase):
    """HKDF: the hash comes from the OID."""

    HKDF_OIDS = {
        "sha256": rfc8619.id_alg_hkdf_with_sha256,
        "sha384": rfc8619.id_alg_hkdf_with_sha384,
        "sha512": rfc8619.id_alg_hkdf_with_sha512,
        "sha3_224": rfc9688.id_alg_hkdf_with_sha3_224,
        "sha3_256": rfc9688.id_alg_hkdf_with_sha3_256,
        "sha3_384": rfc9688.id_alg_hkdf_with_sha3_384,
        "sha3_512": rfc9688.id_alg_hkdf_with_sha3_512,
    }

    def test_rfc_5869_a3(self):
        """GIVEN RFC 5869 A.3 and id-alg-hkdf-with-sha256 / WHEN derived / THEN the OKM of the RFC."""
        okm = kdf_derive(_alg_id(rfc8619.id_alg_hkdf_with_sha256), bytes([0x0B]) * 22, 42)
        self.assertEqual(
            okm.hex(), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )

    def test_every_hkdf_oid_equals_the_reference(self):
        """GIVEN the 7 HKDF OIDs, SHA-2 and SHA-3 / WHEN derived / THEN equal to RFC 5869 written with hmac."""
        for name, oid in self.HKDF_OIDS.items():
            for length, info in ((16, b""), (42, b"info"), (100, b"x" * 70)):
                with self.subTest(hash=name, length=length):
                    self.assertEqual(
                        kdf_derive(_alg_id(oid), b"input keying material", length, info),
                        _hkdf_reference(name, b"input keying material", info, length),
                    )

    def test_the_hash_is_the_one_of_the_oid(self):
        """GIVEN two HKDF OIDs / WHEN derived with the same input / THEN the outputs differ."""
        a = kdf_derive(_alg_id(rfc8619.id_alg_hkdf_with_sha256), b"k", 32)
        b = kdf_derive(_alg_id(rfc9688.id_alg_hkdf_with_sha3_256), b"k", 32)
        self.assertNotEqual(a, b)

    def test_parameters_must_be_absent_not_null(self):
        """GIVEN NULL, an OCTET STRING or an empty SEQUENCE as parameters / WHEN derived / THEN BadAlgParams."""
        for parameters in (univ.Null(""), univ.OctetString(b"x"), univ.Sequence()):
            with self.subTest(parameters=type(parameters).__name__):
                with self.assertRaises(BadAlgParams):
                    kdf_derive(_alg_id(rfc9688.id_alg_hkdf_with_sha3_256, parameters), b"k", 32)

    def test_hkdf_over_shake_is_bad_alg(self):
        """GIVEN an HKDF row whose hash is SHAKE / WHEN derived / THEN BadAlg: HKDF is HMAC based, not XOF based."""
        row = _algs.KdfRow(rfc9688.id_alg_hkdf_with_sha3_256, "hkdf", "shake128")
        with mock.patch.object(mechanisms, "KDF_BY_OID", {row.oid: row}):
            with self.assertRaises(BadAlg):
                kdf_derive(_alg_id(row.oid), b"k", 32)

    def test_the_fixed_oid_of_a_missing_hash_does_not_exist(self):
        """GIVEN the next free HKDF OID (id-alg 36) / WHEN derived / THEN BadAlg: it is in no table."""
        with self.assertRaises(BadAlg):
            kdf_derive(_alg_id(univ.ObjectIdentifier("1.2.840.113549.1.9.16.3.36")), b"k", 32)

    def test_info_is_used(self):
        """GIVEN two infos / WHEN derived / THEN two keys."""
        alg_id = _alg_id(rfc8619.id_alg_hkdf_with_sha256)
        self.assertNotEqual(kdf_derive(alg_id, b"k", 32, b"a"), kdf_derive(alg_id, b"k", 32, b"b"))


class TestKdf2AndKdf3(unittest.TestCase):
    """KDF2 and KDF3: the hash is the ``AlgorithmIdentifier`` in the parameters."""

    Z = bytes(range(32))
    INFO = b"shared-info" * 4

    def test_kdf2_equals_the_x963_kdf_of_cryptography(self):
        """GIVEN SHA-1/224/256/384/512 and SHA3-256 at 16, 32, 70 octets / WHEN derived / THEN equal to X963KDF."""
        for name, hash_class in _CRYPTOGRAPHY_HASHES.items():
            for length in (16, 32, 70):
                with self.subTest(hash=name, length=length):
                    expected = X963KDF(hash_class(), length, self.INFO).derive(self.Z)
                    kdf = _alg_id(rfc5990.id_kdf_kdf2, _hash_alg_id(name))
                    self.assertEqual(kdf_derive(kdf, self.Z, length, self.INFO), expected)

    def test_kdf3_rfc_9690_appendix_d1(self):
        """GIVEN the identifier of RFC 9690 D.2 (kdf3, SHA-256, NULL) / WHEN derived / THEN SS and KEK of the RFC."""
        kdf = _alg_id(rfc5990.id_kdf_kdf3, _hash_alg_id("sha256", null=True))
        ss = kdf_derive(kdf, _RFC_9690_Z, 16)
        self.assertEqual(ss.hex(), "3cf82ec41b54ed4d37402bbd8f805a52")
        info = bytes.fromhex("3010300b0609608648016503040105020110")
        self.assertEqual(kdf_derive(kdf, ss, 16, info).hex(), "e6dc9d62ff2b469bef604c617b018718")

    @staticmethod
    def _reference(hash_name: str, z: bytes, info: bytes, length: int, counter_first: bool) -> bytes:
        """Return Hash(counter || Z || info) or Hash(Z || counter || info) over the counters 1, 2, ..."""
        out = b""
        for counter in range(1, -(-length // hashlib.new(hash_name).digest_size) + 1):
            c = counter.to_bytes(4, "big")
            out += hashlib.new(hash_name, (c + z if counter_first else z + c) + info).digest()
        return out[:length]

    def test_sha_3_hashes_work_for_both(self):
        """GIVEN the four SHA-3 hashes / WHEN derived / THEN KDF2 and KDF3 equal the textbook definition."""
        for name in ("sha3_224", "sha3_256", "sha3_384", "sha3_512"):
            with self.subTest(hash=name):
                kdf2 = kdf_derive(_alg_id(rfc5990.id_kdf_kdf2, _hash_alg_id(name)), self.Z, 100, b"i")
                kdf3 = kdf_derive(_alg_id(rfc5990.id_kdf_kdf3, _hash_alg_id(name)), self.Z, 100, b"i")
                self.assertEqual(kdf2, self._reference(name, self.Z, b"i", 100, counter_first=False))
                self.assertEqual(kdf3, self._reference(name, self.Z, b"i", 100, counter_first=True))

    def test_sha_1_and_sha_2_accept_null_or_absent_parameters(self):
        """GIVEN SHA-256 with NULL and without parameters / WHEN derived / THEN the same key (RFC 5754 Section 2)."""
        with_null = _alg_id(rfc5990.id_kdf_kdf2, _hash_alg_id("sha256", null=True))
        without = _alg_id(rfc5990.id_kdf_kdf2, _hash_alg_id("sha256", null=False))
        self.assertEqual(kdf_derive(with_null, self.Z, 32), kdf_derive(without, self.Z, 32))

    def test_sha_3_with_null_parameters_is_refused(self):
        """GIVEN SHA3-256 with NULL / WHEN derived / THEN BadAlgParams (RFC 9688 Section 2: absent, not NULL)."""
        for oid in (rfc5990.id_kdf_kdf2, rfc5990.id_kdf_kdf3):
            with self.assertRaises(BadAlgParams):
                kdf_derive(_alg_id(oid, _hash_alg_id("sha3_256", null=True)), self.Z, 32)

    def test_shake_and_non_hash_oids_are_bad_alg(self):
        """GIVEN SHAKE128, SHAKE256 or an OID that is no hash / WHEN derived / THEN BadAlg."""
        for oid in (sha_alg_name_to_oid("shake128"), sha_alg_name_to_oid("shake256"), rfc9481.id_KMACWithSHAKE128):
            for kdf_oid in (rfc5990.id_kdf_kdf2, rfc5990.id_kdf_kdf3):
                with self.subTest(oid=str(oid)):
                    with self.assertRaises(BadAlg):
                        kdf_derive(_alg_id(kdf_oid, _alg_id(oid)), self.Z, 32)

    def test_parameters_are_required_and_must_decode(self):
        """GIVEN no parameters, no AlgorithmIdentifier, trailing data / WHEN derived / THEN the errors."""
        good = encoder.encode(_hash_alg_id("sha256"))
        for kdf_oid in (rfc5990.id_kdf_kdf2, rfc5990.id_kdf_kdf3):
            with self.assertRaises(BadAlgParams):
                kdf_derive(_alg_id(kdf_oid), self.Z, 32)
            with self.assertRaises(BadAsn1Data):
                kdf_derive(_alg_id(kdf_oid, b"\x04\x01x"), self.Z, 32)
            with self.assertRaises(BadAlgParams):
                kdf_derive(_alg_id(kdf_oid, good + b"\x05\x00"), self.Z, 32)

    def test_a_decoded_identifier_works_like_the_built_one(self):
        """GIVEN an identifier after a DER round trip / WHEN derived / THEN the same key as before."""
        kdf = _alg_id(rfc5990.id_kdf_kdf3, _hash_alg_id("sha384"))
        self.assertEqual(kdf_derive(_round_trip(kdf), self.Z, 50, b"x"), kdf_derive(kdf, self.Z, 50, b"x"))


class TestPbkdf2(unittest.TestCase):
    """PBKDF2: ``PBKDF2-params`` decoded with its own specification, prf from the table."""

    def test_rfc_6070_through_params_without_prf(self):
        """GIVEN RFC 6070 and PBKDF2-params without prf (DEFAULT HMAC-SHA-1) / WHEN derived / THEN the DK of the RFC."""
        cases = (
            (b"password", b"salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            (b"password", b"salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            (b"password", b"salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
            (b"pass\0word", b"sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
        )
        for password, salt, iterations, length, expected in cases:
            with self.subTest(iterations=iterations, length=length):
                alg_id = _pbkdf2_alg_id(salt=salt, iterations=iterations)
                self.assertNotIn(encoder.encode(rfc8018.id_hmacWithSHA1), encoder.encode(alg_id), "prf is omitted")
                self.assertEqual(kdf_derive(_round_trip(alg_id), password, length).hex(), expected)

    def test_rfc_6070_with_the_prf_written_as_hmac_sha1(self):
        """GIVEN prf hmacWithSHA1 with NULL (the DEFAULT) or without parameters / WHEN derived / THEN the same DK."""
        expected = "4b007901b765489abead49d926f721d065a429c1"
        with_null = _pbkdf2_alg_id(iterations=4096, key_length=20, prf=_alg_id(rfc8018.id_hmacWithSHA1, univ.Null("")))
        self.assertEqual(kdf_derive(_round_trip(with_null), b"password", 20).hex(), expected)
        der = _der_sequence(
            encoder.encode(univ.OctetString(b"salt")),
            encoder.encode(univ.Integer(4096)),
            encoder.encode(univ.Integer(20)),
            _der_sequence(encoder.encode(rfc8018.id_hmacWithSHA1)),
        )
        self.assertEqual(kdf_derive(_alg_id(rfc8018.id_PBKDF2, der), b"password", 20).hex(), expected)

    def test_rfc_7914_section_11_sha256(self):
        """GIVEN the two PBKDF2-HMAC-SHA-256 vectors of RFC 7914 Section 11 / WHEN derived / THEN the DK of the RFC."""
        prf = _alg_id(rfc8018.id_hmacWithSHA256, univ.Null(""))
        alg_id = _pbkdf2_alg_id(salt=b"salt", iterations=1, key_length=64, prf=prf)
        self.assertEqual(
            kdf_derive(_round_trip(alg_id), b"passwd", 64).hex(),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        )
        alg_id = _pbkdf2_alg_id(salt=b"NaCl", iterations=80000, prf=prf)
        self.assertEqual(
            kdf_derive(_round_trip(alg_id), b"Password", 64).hex(),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        )

    def test_every_hmac_prf_equals_hashlib(self):
        """GIVEN each HMAC OID as prf (SHA-1, SHA-2, SHA-3, both SHA-1 OIDs) / WHEN derived / THEN equal to hashlib."""
        for row in _algs.MAC_ROWS:
            if row.family != "hmac":
                continue
            for with_null in (False, True) if row.hash in _WITH_NULL else (False,):
                with self.subTest(hash=row.hash, oid=str(row.oid), null=with_null):
                    prf = _alg_id(row.oid, univ.Null("") if with_null else None)
                    alg_id = _alg_id(rfc8018.id_PBKDF2, _pbkdf2_der_with_prf(prf))
                    self.assertEqual(
                        kdf_derive(alg_id, b"pw", 33), hashlib.pbkdf2_hmac(row.hash, b"pw", b"salty", 3, 33)
                    )

    def test_a_decoded_and_a_typed_identifier_both_work(self):
        """GIVEN typed PBKDF2-params and the same after a DER round trip / WHEN derived / THEN equal."""
        typed = rfc5280.AlgorithmIdentifier()
        typed["algorithm"] = rfc8018.id_PBKDF2
        typed["parameters"] = _pbkdf2_params(iterations=5, key_length=16)
        self.assertIsInstance(typed["parameters"], rfc8018.PBKDF2_params)
        self.assertEqual(kdf_derive(typed, b"pw", 16), kdf_derive(_round_trip(typed), b"pw", 16))

    def test_key_length_absent_or_equal_is_accepted_other_is_refused(self):
        """GIVEN keyLength absent, equal and different / WHEN derived / THEN a mismatch is BadAlgParams."""
        kdf_derive(_pbkdf2_alg_id(), b"pw", 20)
        kdf_derive(_pbkdf2_alg_id(key_length=20), b"pw", 20)
        for key_length in (19, 21, 32):
            with self.subTest(key_length=key_length):
                with self.assertRaises(BadAlgParams):
                    kdf_derive(_round_trip(_pbkdf2_alg_id(key_length=key_length)), b"pw", 20)

    def test_salt_from_another_source_is_bad_alg(self):
        """GIVEN a salt in otherSource / WHEN derived / THEN BadAlg."""
        params = rfc8018.PBKDF2_params()
        params["salt"]["otherSource"]["algorithm"] = rfc8018.id_PBKDF2
        params["iterationCount"] = 1
        with self.assertRaises(BadAlg):
            kdf_derive(_alg_id(rfc8018.id_PBKDF2, params), b"pw", 20)

    def test_iteration_count_is_capped(self):
        """GIVEN one more than MAX_PBKDF2_ITERATIONS / WHEN derived / THEN BadAlgParams, before any work."""
        with self.assertRaises(BadAlgParams):
            kdf_derive(_round_trip(_pbkdf2_alg_id(iterations=MAX_PBKDF2_ITERATIONS + 1)), b"pw", 20)

    def test_prf_must_be_an_hmac_with_absent_or_null_parameters(self):
        """GIVEN a prf that is GMAC, unknown, or has parameters / WHEN derived / THEN BadAlg or BadAlgParams."""
        for prf, error in (
            (_alg_id(rfc9481.id_aes128_GMAC), BadAlg),
            (_alg_id(rfc9481.id_KMACWithSHAKE128), BadAlg),
            (_alg_id(univ.ObjectIdentifier("1.2.840.113549.2.99")), BadAlg),
            (_alg_id(rfc8018.id_hmacWithSHA256, univ.OctetString(b"x")), BadAlgParams),
        ):
            with self.subTest(prf=str(prf["algorithm"])):
                with self.assertRaises(error):
                    kdf_derive(_round_trip(_pbkdf2_alg_id(prf=prf)), b"pw", 20)

    def test_sha_3_prf_takes_no_null_but_sha_2_does(self):
        """GIVEN HMAC-SHA3-256 and HMAC-SHA-256 with NULL / WHEN derived / THEN SHA-3 is BadAlgParams (RFC 9688)."""
        sha2 = _alg_id(rfc8018.id_hmacWithSHA256, univ.Null(""))
        kdf_derive(_round_trip(_pbkdf2_alg_id(prf=sha2)), b"pw", 20)
        sha3 = _alg_id(rfc9688.id_hmacWithSHA3_256, univ.Null(""))
        with self.assertRaises(BadAlgParams):
            kdf_derive(_round_trip(_pbkdf2_alg_id(prf=sha3)), b"pw", 20)

    def test_info_is_refused(self):
        """GIVEN a non-empty info / WHEN derived / THEN BadAlgParams: PBKDF2 has no info input."""
        with self.assertRaises(BadAlgParams):
            kdf_derive(_pbkdf2_alg_id(), b"pw", 20, b"info")

    def test_parameters_are_required_and_must_decode(self):
        """GIVEN absent parameters, a non-sequence, trailing data / WHEN derived / THEN BadAlgParams or BadAsn1Data."""
        with self.assertRaises(BadAlgParams):
            kdf_derive(_alg_id(rfc8018.id_PBKDF2), b"pw", 20)
        with self.assertRaises(BadAsn1Data):
            kdf_derive(_alg_id(rfc8018.id_PBKDF2, b"\x04\x01x"), b"pw", 20)
        with self.assertRaises(BadAlgParams):
            kdf_derive(_alg_id(rfc8018.id_PBKDF2, encoder.encode(_pbkdf2_params()) + b"\x05\x00"), b"pw", 20)


class TestTheCall(unittest.TestCase):
    """What every key derivation function has in common."""

    def test_an_oid_that_is_no_kdf_is_bad_alg(self):
        """GIVEN an HMAC, a wrap and an unknown OID / WHEN derived / THEN BadAlg."""
        for oid in (rfc8018.id_hmacWithSHA256, rfc9481.id_aes128_wrap, univ.ObjectIdentifier("1.2.3.4")):
            with self.assertRaises(BadAlg):
                kdf_derive(_alg_id(oid), b"k", 16)

    def test_an_identifier_without_oid_is_bad_alg_and_a_wrong_type_a_type_error(self):
        """GIVEN an empty identifier, an OID, bytes / WHEN derived / THEN BadAlg or TypeError."""
        with self.assertRaises(BadAlg):
            kdf_derive(rfc5280.AlgorithmIdentifier(), b"k", 16)
        for value in (rfc8619.id_alg_hkdf_with_sha256, b"x", None):
            with self.assertRaises(TypeError):
                kdf_derive(value, b"k", 16)  # type: ignore[arg-type]

    def test_length_below_one_is_a_value_error(self):
        """GIVEN length 0 and -1 / WHEN derived / THEN ValueError."""
        for length in (0, -1):
            with self.assertRaises(ValueError):
                kdf_derive(_alg_id(rfc8619.id_alg_hkdf_with_sha256), b"k", length)

    def test_the_output_has_the_requested_length(self):
        """GIVEN lengths 1, 31, 32, 33 / WHEN derived with each function / THEN exactly that many octets."""
        kdfs = (
            _alg_id(rfc8619.id_alg_hkdf_with_sha256),
            _alg_id(rfc5990.id_kdf_kdf2, _hash_alg_id("sha256")),
            _alg_id(rfc5990.id_kdf_kdf3, _hash_alg_id("sha256")),
            _pbkdf2_alg_id(),
        )
        for kdf in kdfs:
            for length in (1, 31, 32, 33):
                self.assertEqual(len(kdf_derive(kdf, b"k", length)), length)


if __name__ == "__main__":
    unittest.main()
