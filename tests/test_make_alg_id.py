# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``make_alg_id``, and for ``list_algorithms`` of the kinds kdf, mac, wrap and content.

External bytes, so that a shared misreading of a table row and of the builder cannot pass both sides: the identifiers
of RFC 9690 Appendix D.2 (``kdf3`` over SHA-256 with NULL, ``id-aes128-wrap``), the OIDs and parameter structures of
RFC 9688 (HKDF), RFC 8018 (PBKDF2, written out by hand), RFC 9044 (AES-GMAC), RFC 3565 (the AES-CBC IV) and RFC 5084.
Every row that ``list_algorithms`` returns is then built, encoded, decoded and used by the mechanism of its kind.
"""

import hashlib
import hmac
import unittest

from keyutils_py import _algs, algorithms, mechanisms, primitives
from keyutils_py.algorithms import list_algorithms
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data
from keyutils_py.mechanisms import (
    compute_mac,
    decrypt_content,
    encrypt_content,
    kdf_derive,
    make_alg_id,
    unwrap_cek,
    verify_mac,
    wrap_cek,
)
from keyutils_py.oids import SIG_ALG_OID_2_INFO
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5084, rfc5280, rfc8018, rfc9044


def _der(alg_id: rfc5280.AlgorithmIdentifier) -> str:
    """Return the DER of an identifier as hex."""
    return encoder.encode(alg_id).hex()


def _round_trip(alg_id: rfc5280.AlgorithmIdentifier) -> rfc5280.AlgorithmIdentifier:
    """Return the identifier as a receiver has it: DER encoded and decoded."""
    decoded, rest = decoder.decode(encoder.encode(alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
    assert not rest
    return decoded


class TestDerOfTheBuilders(unittest.TestCase):
    """The bytes of an identifier are the ones that the RFCs write."""

    def test_rfc_9690_appendix_d2_kdf3_over_sha256_and_aes128_wrap(self):
        """GIVEN the KEMRecipientInfo identifiers of RFC 9690 D.2 / WHEN built / THEN the DER of the RFC."""
        self.assertEqual(
            _der(make_alg_id("kdf", "kdf3", hash="sha256")),
            "301b060a2b8105108648092c0102300d06096086480165030402010500",
        )
        self.assertEqual(_der(make_alg_id("wrap", "aes", bits=128, mode="kw")), "300b0609608648016503040105")

    def test_hkdf_with_sha3_256_has_absent_parameters(self):
        """GIVEN id-alg-hkdf-with-sha3-256 (id-alg 33) / WHEN built / THEN one OID, no parameters (RFC 9688 5.1)."""
        self.assertEqual(_der(make_alg_id("kdf", "hkdf", hash="sha3_256")), "300d060b2a864886f70d0109100321")

    def test_hmac_sha256_has_absent_parameters(self):
        """GIVEN id-hmacWithSHA256 / WHEN built / THEN one OID, no parameters."""
        self.assertEqual(_der(make_alg_id("mac", "hmac", hash="sha256")), "300a06082a864886f70d0209")

    def test_kdf2_over_sha3_256_has_a_hash_without_null(self):
        """GIVEN KDF2 over SHA3-256 / WHEN built / THEN the hash identifier has no parameters (RFC 9688 Section 2)."""
        alg_id = make_alg_id("kdf", "kdf2", hash="sha3_256")
        hash_id, _ = decoder.decode(alg_id["parameters"].asOctets(), asn1Spec=rfc5280.AlgorithmIdentifier())
        self.assertEqual(str(hash_id["algorithm"]), "2.16.840.1.101.3.4.2.8")
        self.assertFalse(hash_id["parameters"].isValue)

    def test_pbkdf2_equals_the_hand_written_der(self):
        """GIVEN salt "salt", 1 iteration, prf SHA-1 / WHEN built / THEN SEQUENCE { id-PBKDF2, { salt, 1 } }."""
        alg_id = make_alg_id("kdf", "pbkdf2", salt=b"salt", iterations=1, prf_hash="sha1")
        self.assertEqual(_der(alg_id), "301606092a864886f70d01050c3009040473616c74020101")

    def test_pbkdf2_reads_back_with_its_own_specification(self):
        """GIVEN PBKDF2 with keyLength and SHA-256 / WHEN decoded as PBKDF2-params / THEN every field."""
        alg_id = make_alg_id("kdf", "pbkdf2", salt=b"salt", iterations=7, key_length=32, prf_hash="sha256")
        params, rest = decoder.decode(alg_id["parameters"].asOctets(), asn1Spec=rfc8018.PBKDF2_params())
        self.assertEqual(rest, b"")
        self.assertEqual(
            (params["salt"]["specified"].asOctets(), int(params["iterationCount"]), int(params["keyLength"])),
            (b"salt", 7, 32),
        )
        self.assertEqual(str(params["prf"]["algorithm"]), "1.2.840.113549.2.9")
        self.assertEqual(params["prf"]["parameters"].asOctets(), b"\x05\x00")

    def test_the_prf_of_pbkdf2_is_the_oid_of_rfc_8018_where_there_is_one(self):
        """GIVEN prf_hash sha1, sha256, sha3_256 / WHEN built / THEN hmacWithSHA1 (DEFAULT), SHA256 (NULL), SHA3."""
        cases = {
            "sha1": ("1.2.840.113549.2.7", None),  # the DEFAULT: DER leaves the field out
            "sha256": ("1.2.840.113549.2.9", b"\x05\x00"),
            "sha3_256": ("2.16.840.1.101.3.4.2.14", b""),  # RFC 9688 Section 4: no NULL
        }
        for prf_hash, (oid, parameters) in cases.items():
            with self.subTest(prf_hash=prf_hash):
                alg_id = make_alg_id("kdf", "pbkdf2", salt=b"s", iterations=1, prf_hash=prf_hash)
                params, _ = decoder.decode(alg_id["parameters"].asOctets(), asn1Spec=rfc8018.PBKDF2_params())
                self.assertEqual(str(params["prf"]["algorithm"]), oid)
                if parameters is not None:
                    self.assertEqual(
                        params["prf"]["parameters"].asOctets() if params["prf"]["parameters"].isValue else b"",
                        parameters,
                    )

    def test_pbkdf2_without_key_length_leaves_it_out(self):
        """GIVEN key_length None / WHEN built / THEN keyLength is absent."""
        alg_id = make_alg_id("kdf", "pbkdf2", salt=b"salt", iterations=1, prf_hash="sha256", key_length=None)
        params, _ = decoder.decode(alg_id["parameters"].asOctets(), asn1Spec=rfc8018.PBKDF2_params())
        self.assertFalse(params["keyLength"].isValue)

    def test_gmac_parameters_are_the_nonce_and_an_optional_length(self):
        """GIVEN an AES-128 GMAC with a 12 octet nonce / WHEN built / THEN id-aes128-GMAC, GMACParameters (RFC 9044)."""
        alg_id = make_alg_id("mac", "gmac", bits=128, nonce=bytes(range(12)))
        self.assertEqual(_der(alg_id), "301b0609608648016503040109300e040c000102030405060708090a0b")
        longer = make_alg_id("mac", "gmac", bits=128, nonce=bytes(12), tag_length=16)
        params, _ = decoder.decode(longer["parameters"].asOctets(), asn1Spec=rfc9044.GCMParameters())
        self.assertEqual(int(params["length"]), 16)

    def test_aes_cbc_parameters_are_the_iv(self):
        """GIVEN AES-128-CBC with an IV / WHEN built / THEN id-aes128-CBC and the IV as OCTET STRING (RFC 3565)."""
        iv = bytes(range(16))
        self.assertEqual(
            _der(make_alg_id("content", "aes-cbc", bits=128, iv=iv)),
            "301d06096086480165030401020410" + iv.hex(),
        )

    def test_aes_gcm_parameters(self):
        """GIVEN AES-256-GCM with a nonce and a tag length / WHEN built / THEN id-aes256-GCM, GCMParameters."""
        alg_id = make_alg_id("content", "aes-gcm", bits=256, nonce=bytes(12), tag_length=16)
        self.assertEqual(str(alg_id["algorithm"]), "2.16.840.1.101.3.4.1.46")
        params, _ = decoder.decode(alg_id["parameters"].asOctets(), asn1Spec=rfc5084.GCMParameters())
        self.assertEqual((params["aes-nonce"].asOctets(), int(params["aes-ICVlen"])), (bytes(12), 16))

    def test_sha1_hmac_is_written_with_the_oid_of_a_mac(self):
        """GIVEN HMAC with SHA-1 / WHEN built / THEN hMAC-SHA1; PBMAC1 with a SHA-1 prf keeps the OID of its scheme."""
        self.assertEqual(str(make_alg_id("mac", "hmac", hash="sha1")["algorithm"]), "1.3.6.1.5.5.8.1.2")
        pbmac1 = make_alg_id(
            "mac", "pbmac1", salt=b"s", iterations=1, key_length=20, prf_hash="sha1", mac_hash="sha256"
        )
        params, _ = decoder.decode(pbmac1["parameters"].asOctets(), asn1Spec=rfc8018.PBMAC1_params())
        self.assertEqual(str(params["messageAuthScheme"]["algorithm"]), "1.2.840.113549.2.9")


class TestWhatABuilderWrites(unittest.TestCase):
    """A builder writes what it is asked for, so that a test can make what a receiver refuses."""

    def test_a_short_iv_a_pbkdf2_key_length_and_a_pbmac1_without_key_length_are_built(self):
        """GIVEN a 15 octet IV, a PBMAC1 keyLength of 1 and none / WHEN built / THEN a receiver refuses them."""
        iv15 = make_alg_id("content", "aes-cbc", bits=128, iv=bytes(15))
        with self.assertRaises(BadAsn1Data):
            encrypt_content(_round_trip(iv15), bytes(16), b"x")
        no_key_length = make_alg_id("mac", "pbmac1", salt=b"s", iterations=1, key_length=None, prf_hash="sha256")
        with self.assertRaises(BadAlgParams):
            compute_mac(_round_trip(no_key_length), b"pw", b"x")
        short = make_alg_id("mac", "pbmac1", salt=b"s", iterations=1, key_length=1, prf_hash="sha256")
        with self.assertRaises(BadAlgParams):
            compute_mac(_round_trip(short), b"pw", b"x")

    def test_the_kdf_key_length_that_differs_from_the_length_is_built_and_refused(self):
        """GIVEN keyLength 32 and a derivation of 16 / WHEN used / THEN BadAlgParams."""
        alg_id = make_alg_id("kdf", "pbkdf2", salt=b"s", iterations=1, key_length=32, prf_hash="sha256")
        with self.assertRaises(BadAlgParams):
            kdf_derive(_round_trip(alg_id), b"pw", 16)


class TestMisuse(unittest.TestCase):
    """Wrong calls are refused with the error of their kind."""

    def test_an_unknown_keyword_is_a_type_error(self):
        """GIVEN a misspelled or foreign keyword / WHEN built / THEN TypeError, never ignored."""
        for kind, family, params in (
            ("kdf", "hkdf", {"hash": "sha256", "salt": b"x"}),
            ("kdf", "hkdf", {"hsah": "sha256"}),
            ("mac", "hmac", {"hash": "sha256", "bits": 128}),
            ("wrap", "aes", {"bits": 128, "mode": "kw", "iv": b"x"}),
            ("content", "aes-cbc", {"bits": 128, "iv": bytes(16), "nonce": b"x"}),
            ("kdf", "pbkdf2", {"salt": b"s", "iterations": 1, "prf_hash": "sha256", "keylength": 3}),
        ):
            with self.subTest(kind=kind, family=family, params=sorted(params)):
                with self.assertRaises(TypeError):
                    make_alg_id(kind, family, **params)  # type: ignore[arg-type]

    def test_a_missing_keyword_is_a_type_error(self):
        """GIVEN no hash, no iv, no salt / WHEN built / THEN TypeError."""
        for kind, family, params in (
            ("kdf", "hkdf", {}),
            ("content", "aes-cbc", {"bits": 128}),
            ("kdf", "pbkdf2", {"iterations": 1, "prf_hash": "sha256"}),
            ("mac", "pbmac1", {"salt": b"s", "iterations": 1, "prf_hash": "sha256"}),
        ):
            with self.subTest(kind=kind, family=family):
                with self.assertRaises(TypeError):
                    make_alg_id(kind, family, **params)  # type: ignore[arg-type]

    def test_an_unknown_kind_family_hash_size_or_mode_is_bad_alg(self):
        """GIVEN names that are in no table / WHEN built / THEN BadAlg."""
        for kind, family, params in (
            ("nope", "hkdf", {"hash": "sha256"}),
            ("kdf", "nope", {}),
            ("kdf", "hkdf", {"hash": "shake128"}),
            ("kdf", "hkdf", {"hash": "SHA256"}),
            ("kdf", "kdf2", {"hash": "md5"}),
            ("kdf", "pbkdf2", {"salt": b"s", "iterations": 1, "prf_hash": "shake256"}),
            ("mac", "hmac", {"hash": "shake128"}),
            ("mac", "kmac", {"hash": "sha256"}),
            ("mac", "gmac", {"bits": 100, "nonce": bytes(12)}),
            ("wrap", "aes", {"bits": 100, "mode": "kw"}),
            ("wrap", "aes", {"bits": 128, "mode": "cbc"}),
            ("content", "aes-cbc", {"bits": 512, "iv": bytes(16)}),
            ("content", "aes-ccm", {"bits": 128, "nonce": bytes(12)}),
        ):
            with self.subTest(kind=kind, family=family, params=params):
                with self.assertRaises(BadAlg):
                    make_alg_id(kind, family, **params)  # type: ignore[arg-type]

    def test_the_kinds_kari_and_key_transport_have_no_builder_yet(self):
        """GIVEN the kinds kari and key_transport / WHEN built / THEN BadAlg: they are in no dispatch table yet."""
        for kind, family in (("kari", "stdDH"), ("key_transport", "rsa-oaep"), ("kari", "mqv")):
            with self.subTest(kind=kind, family=family):
                with self.assertRaises(BadAlg):
                    make_alg_id(kind, family, hash="sha256")  # type: ignore[arg-type]

    def test_a_value_that_cannot_be_written_is_a_value_error(self):
        """GIVEN iterations 0, a GMAC tag_length of 11, a GCM tag_length of 17 / WHEN built / THEN ValueError."""
        with self.assertRaises(ValueError):
            make_alg_id("kdf", "pbkdf2", salt=b"s", iterations=0, prf_hash="sha256")
        with self.assertRaises(ValueError):
            make_alg_id("mac", "gmac", bits=128, nonce=bytes(12), tag_length=11)
        with self.assertRaises(ValueError):
            make_alg_id("content", "aes-gcm", bits=128, nonce=bytes(12), tag_length=17)


class TestListAlgorithms(unittest.TestCase):
    """``list_algorithms`` lists the rows of kdf, mac, wrap and content as ``AlgInfo(kind, family, params, oid)``."""

    COUNTS = {"kdf": 10, "mac": 16, "wrap": 6, "content": 6}

    def test_each_kind_lists_its_rows_sorted_by_oid(self):
        """GIVEN each of the four kinds / WHEN listed / THEN a tuple of AlgInfo, one per row, sorted by OID."""
        for kind, count in self.COUNTS.items():
            with self.subTest(kind=kind):
                rows = list_algorithms(kind)
                self.assertIsInstance(rows, tuple)
                self.assertEqual(len(rows), count)
                self.assertTrue(all(isinstance(row, _algs.AlgInfo) and row.kind == kind for row in rows))
                oids = [row.oid.asTuple() for row in rows]
                self.assertEqual(oids, sorted(oids))
                self.assertEqual(len(set(oids)), count)

    def test_the_rows_carry_the_facts_of_the_table(self):
        """GIVEN rows of each kind / WHEN read / THEN family and params name the structured facts."""
        by_oid = {str(row.oid): row for kind in self.COUNTS for row in list_algorithms(kind)}
        sha3_hkdf = by_oid["1.2.840.113549.1.9.16.3.33"]
        self.assertEqual(
            (sha3_hkdf.kind, sha3_hkdf.family, dict(sha3_hkdf.params)), ("kdf", "hkdf", {"hash": "sha3_256"})
        )
        self.assertEqual(dict(by_oid["1.3.133.16.840.9.44.1.2"].params), {})
        kwp = by_oid["2.16.840.1.101.3.4.1.28"]
        self.assertEqual((kwp.family, dict(kwp.params)), ("aes", {"bits": 192, "mode": "kwp"}))
        gcm = by_oid["2.16.840.1.101.3.4.1.46"]
        self.assertEqual((gcm.family, dict(gcm.params)), ("aes-gcm", {"bits": 256}))
        gmac = by_oid["2.16.840.1.101.3.4.1.9"]
        self.assertEqual((gmac.family, dict(gmac.params)), ("gmac", {"bits": 128}))
        kmac = by_oid["2.16.840.1.101.3.4.2.20"]
        self.assertEqual((kmac.family, dict(kmac.params)), ("kmac", {"hash": "shake256"}))

    def test_params_cannot_be_changed(self):
        """GIVEN a row / WHEN its params are assigned / THEN TypeError: the listing is not a way to edit a table."""
        row = list_algorithms("kdf")[0]
        with self.assertRaises(TypeError):
            row.params["hash"] = "sha1"  # type: ignore[index]

    def test_sig_is_unchanged_and_the_kinds_not_built_yet_are_unknown(self):
        """GIVEN kind sig / WHEN listed / THEN the 81 signature rows; kari and key_transport are not kinds yet."""
        self.assertEqual({row.oid for row in list_algorithms("sig")}, set(SIG_ALG_OID_2_INFO))
        for kind in ("kari", "key_transport", "kem", ""):
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, "kdf, mac, wrap, content"):
                    list_algorithms(kind)
        self.assertIs(algorithms.list_algorithms, list_algorithms)


class TestEveryRowIsUsable(unittest.TestCase):
    """Every row is built by ``make_alg_id``, encoded, decoded, and used by the mechanism of its kind."""

    EXTRA = {
        ("kdf", "kdf2"): {"hash": "sha256"},
        ("kdf", "kdf3"): {"hash": "sha3_256"},
        ("kdf", "pbkdf2"): {"salt": b"salty", "iterations": 2, "key_length": 32, "prf_hash": "sha256"},
        ("mac", "gmac"): {"nonce": bytes(range(12)), "tag_length": 16},
        ("mac", "pbmac1"): {"salt": b"salty", "iterations": 2, "key_length": 32, "prf_hash": "sha256"},
        ("content", "aes-cbc"): {"iv": bytes(range(16))},
        ("content", "aes-gcm"): {"nonce": bytes(range(12))},
    }

    def _build(self, info: _algs.AlgInfo) -> rfc5280.AlgorithmIdentifier:
        """Return the identifier of a listed row, with the keywords that the row does not fix added."""
        return make_alg_id(info.kind, info.family, **dict(info.params), **self.EXTRA.get((info.kind, info.family), {}))  # type: ignore[arg-type]

    def test_the_builder_writes_the_oid_of_the_row(self):
        """GIVEN each of the 38 rows / WHEN built / THEN the OID of the row (HMAC-SHA1 has two, one builder)."""
        for kind in ("kdf", "mac", "wrap", "content"):
            for info in list_algorithms(kind):
                with self.subTest(kind=kind, family=info.family, oid=str(info.oid)):
                    expected = info.oid
                    if str(info.oid) == "1.2.840.113549.2.7":  # the PBKDF2 form of HMAC-SHA1; a MAC gets hMAC-SHA1
                        expected = univ.ObjectIdentifier("1.3.6.1.5.5.8.1.2")
                    self.assertEqual(self._build(info)["algorithm"], expected)

    def test_every_kdf_row_derives(self):
        """GIVEN each KDF row / WHEN built, round tripped and used / THEN kdf_derive returns the length asked."""
        for info in list_algorithms("kdf"):
            with self.subTest(family=info.family, oid=str(info.oid)):
                alg_id = _round_trip(self._build(info))
                derived = kdf_derive(alg_id, b"secret", 32, b"" if info.family == "pbkdf2" else b"info")
                self.assertEqual(len(derived), 32)
        pbkdf2 = _round_trip(make_alg_id("kdf", "pbkdf2", **self.EXTRA[("kdf", "pbkdf2")]))
        self.assertEqual(kdf_derive(pbkdf2, b"pw", 32), hashlib.pbkdf2_hmac("sha256", b"pw", b"salty", 2, 32))

    def test_every_mac_row_computes_and_verifies(self):
        """GIVEN each MAC row / WHEN built, round tripped and used / THEN compute_mac verifies with verify_mac."""
        for info in list_algorithms("mac"):
            with self.subTest(family=info.family, oid=str(info.oid)):
                alg_id = _round_trip(self._build(info))
                key = bytes(info.params["bits"] // 8) if info.family == "gmac" else bytes(range(32))
                mac = compute_mac(alg_id, key, b"data")
                self.assertTrue(mac)
                self.assertIsNone(verify_mac(alg_id, key, b"data", mac, allow_sha1=True))
        hmac_sha256 = _round_trip(make_alg_id("mac", "hmac", hash="sha256"))
        self.assertEqual(compute_mac(hmac_sha256, b"k", b"d"), hmac.new(b"k", b"d", "sha256").digest())

    def test_every_wrap_row_wraps(self):
        """GIVEN each wrap row / WHEN built, round tripped and used / THEN the CEK comes back."""
        for info in list_algorithms("wrap"):
            with self.subTest(oid=str(info.oid)):
                alg_id = _round_trip(self._build(info))
                kek, cek = bytes(range(info.params["bits"] // 8)), bytes(range(16))
                self.assertEqual(unwrap_cek(alg_id, kek, wrap_cek(alg_id, kek, cek)), cek)

    def test_every_content_row_encrypts(self):
        """GIVEN each content row / WHEN built, round tripped and used / THEN the plaintext comes back."""
        for info in list_algorithms("content"):
            with self.subTest(family=info.family, oid=str(info.oid)):
                alg_id = _round_trip(self._build(info))
                cek = bytes(range(info.params["bits"] // 8))
                encrypted = encrypt_content(alg_id, cek, b"plaintext")
                extra = {"tag": encrypted.tag} if info.family == "aes-gcm" else {}
                self.assertEqual(decrypt_content(alg_id, cek, encrypted.ciphertext, **extra), b"plaintext")

    def test_the_lower_layer_agrees_for_one_row_of_each_kind(self):
        """GIVEN HKDF-SHA3-256, HMAC-SHA3-384 and AES-192-KWP / WHEN used by identifier / THEN as the lower layer."""
        self.assertEqual(
            kdf_derive(make_alg_id("kdf", "hkdf", hash="sha3_256"), b"k", 20, b"i"),
            primitives.hkdf("sha3_256", b"k", 20, b"i"),
        )
        self.assertEqual(
            compute_mac(make_alg_id("mac", "hmac", hash="sha3_384"), b"k", b"d"),
            primitives.hmac_digest("sha3_384", b"k", b"d"),
        )
        kek = bytes(24)
        self.assertEqual(
            wrap_cek(make_alg_id("wrap", "aes", bits=192, mode="kwp"), kek, b"abc"),
            primitives.aes_kwp_wrap(kek, b"abc"),
        )

    def test_the_public_module_owns_the_builder(self):
        """GIVEN the mechanisms module / WHEN asked / THEN make_alg_id is its function and AlgKind its alias."""
        self.assertIs(make_alg_id, mechanisms.make_alg_id)
        self.assertIn("make_alg_id", mechanisms.__all__)
        self.assertIn("AlgKind", mechanisms.__all__)


if __name__ == "__main__":
    unittest.main()
