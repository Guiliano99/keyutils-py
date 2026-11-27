# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the signature algorithm table (``SIG_ALG_OID_2_INFO``) and ``get_sig_alg_info``.

The golden rows in ``tests/golden/sig_alg_table.tsv`` are not derived from the table under test: they are written
by ``tests/golden/generate_sig_alg_table.py`` from the facts of the RFCs and cross-checked against the OIDs of
``pyasn1_alt_modules``.
"""

import csv
import dataclasses
import unittest
from pathlib import Path
from typing import Dict, Optional

from keyutils_py.enums import SigAlgParametersSpec
from keyutils_py.exceptions import BadAlg, BadSigAlgID, BadSigAlgIDParams
from keyutils_py.keyutils import prepare_rsa_pss_alg_id
from keyutils_py.oids import (
    COMPOSITE_SIG_OID_TO_NAME,
    DSA_OID_2_NAME,
    ECDSA_OID_2_NAME,
    ED_OID_2_NAME,
    PQ_SIG_OID_2_NAME,
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
    RSA_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SIG_ALG_OID_2_INFO,
    SIG_ALG_OID_2_PARAMETERS_SPEC,
    SigAlgInfo,
    compute_hash,
    get_sig_alg_info,
    sha_alg_name_to_oid,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc8017, rfc9481

GOLDEN = Path(__file__).with_name("golden") / "sig_alg_table.tsv"

_PARAMS = {
    "absent": SigAlgParametersSpec.MUST_BE_ABSENT,
    "null": SigAlgParametersSpec.MUST_BE_NULL,
    "rsassa_pss_params": SigAlgParametersSpec.MUST_BE_RSASSA_PSS_PARAMS,
}


def _golden() -> Dict[univ.ObjectIdentifier, dict]:
    """Return the golden rows by OID."""
    with open(GOLDEN, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    return {univ.ObjectIdentifier(row["oid"]): row for row in rows}


def _alg_id(oid: univ.ObjectIdentifier, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Build an ``AlgorithmIdentifier`` from an OID and optional parameters."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if parameters is not None:
        alg_id["parameters"] = parameters
    return alg_id


def _pss_alg_id(
    hash_oid: Optional[univ.ObjectIdentifier] = None,
    mgf_hash_oid: Optional[univ.ObjectIdentifier] = None,
    salt_length: Optional[int] = None,
    trailer_field: Optional[int] = None,
    as_any: bool = True,
) -> rfc5280.AlgorithmIdentifier:
    """Build an id-RSASSA-PSS identifier; every argument left as ``None`` is omitted (the RFC 4055 DEFAULT)."""
    params = rfc4055.RSASSA_PSS_params()
    if hash_oid is not None:
        params["hashAlgorithm"]["algorithm"] = hash_oid
        params["hashAlgorithm"]["parameters"] = univ.Null("")
    if mgf_hash_oid is not None:
        params["maskGenAlgorithm"]["algorithm"] = rfc8017.id_mgf1
        params["maskGenAlgorithm"]["parameters"] = _alg_id(mgf_hash_oid, univ.Null(""))
    if salt_length is not None:
        params["saltLength"] = salt_length
    if trailer_field is not None:
        params["trailerField"] = trailer_field
    if not as_any:
        return _alg_id(rfc9481.id_RSASSA_PSS, params)
    return _alg_id(rfc9481.id_RSASSA_PSS, univ.Any(encoder.encode(params)))


class TestGoldenTable(unittest.TestCase):
    """``SIG_ALG_OID_2_INFO`` equals the golden table, row by row."""

    @classmethod
    def setUpClass(cls):
        """Read the golden file once."""
        cls.golden = _golden()

    def test_golden_has_81_rows(self):
        """GIVEN the golden file / WHEN counted / THEN one row per signature algorithm (80 OIDs and rsaEncryption)."""
        self.assertEqual(len(self.golden), 81)

    def test_every_oid_of_every_signature_table_has_a_row(self):
        """GIVEN all signature OID tables / WHEN compared with the golden rows / THEN the sets are equal."""
        tables = (
            RSA_OID_2_NAME,
            RSASSA_PSS_OID_2_NAME,
            ECDSA_OID_2_NAME,
            ED_OID_2_NAME,
            DSA_OID_2_NAME,
            PQ_SIG_OID_2_NAME,
            PQ_STATEFUL_HASH_SIG_OID_2_NAME,
            COMPOSITE_SIG_OID_TO_NAME,
        )
        known = {oid for table in tables for oid in table} | {rfc8017.rsaEncryption}
        self.assertEqual(known - set(self.golden), set(), "row missing from the golden table")
        self.assertEqual(set(self.golden) - known, set(), "golden row without an entry in a signature table")

    def test_table_and_golden_have_the_same_oids(self):
        """GIVEN the derived table / WHEN its OIDs are compared with the golden ones / THEN they are equal."""
        self.assertEqual(set(SIG_ALG_OID_2_INFO), set(self.golden))
        for oid, info in SIG_ALG_OID_2_INFO.items():
            self.assertEqual(info.oid, oid)

    def test_every_row_equals_its_golden_row(self):
        """GIVEN a golden row / WHEN compared with the table / THEN every one of the nine facts is equal."""
        for oid, row in self.golden.items():
            with self.subTest(name=row["name"]):
                info = SIG_ALG_OID_2_INFO[oid]
                self.assertEqual(info.name, row["name"])
                self.assertEqual(info.family, row["family"])
                self.assertEqual(info.key_name, row["key_name"] or None)
                self.assertEqual(info.hash_alg, row["hash_alg"] or None)
                self.assertEqual(info.pre_hash, row["pre_hash"] == "true")
                self.assertEqual(info.pss, row["pss"] == "true")
                self.assertEqual(info.params, _PARAMS[row["params"]])
                self.assertEqual(info.cms_digest, row["cms_digest"] or None)
                self.assertIsNone(info.mgf1_hash_alg)
                self.assertIsNone(info.salt_length)

    def test_every_hash_name_has_a_hash_oid_and_a_digest(self):
        """GIVEN the hash names used by the rows / WHEN looked up in the hash registry / THEN they are all known."""
        names = {info.hash_alg for info in SIG_ALG_OID_2_INFO.values()} | {
            info.cms_digest for info in SIG_ALG_OID_2_INFO.values()
        }
        for name in sorted(n for n in names if n is not None):
            with self.subTest(hash=name):
                self.assertIsInstance(sha_alg_name_to_oid(name), univ.ObjectIdentifier)
                self.assertGreater(len(compute_hash(name, b"x")), 0)

    def test_parameter_catalogue_is_a_view_of_the_table(self):
        """GIVEN the table / WHEN SIG_ALG_OID_2_PARAMETERS_SPEC is compared / THEN it holds the same specs."""
        self.assertEqual(SIG_ALG_OID_2_PARAMETERS_SPEC, {oid: info.params for oid, info in SIG_ALG_OID_2_INFO.items()})

    def test_rows_are_immutable(self):
        """GIVEN the table and a row / WHEN either is changed / THEN it raises."""
        info = SIG_ALG_OID_2_INFO[rfc9481.sha256WithRSAEncryption]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            info.hash_alg = "sha1"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            SIG_ALG_OID_2_INFO[rfc9481.sha256WithRSAEncryption] = info  # type: ignore[index]

    def test_rsa_encryption_is_not_a_profile_signature_oid(self):
        """GIVEN rsaEncryption / WHEN looked up / THEN it is a row but not in the traditional name tables."""
        from keyutils_py.oids import TRAD_SIG_OID_2_NAME

        self.assertIn(rfc8017.rsaEncryption, SIG_ALG_OID_2_INFO)
        self.assertNotIn(rfc8017.rsaEncryption, TRAD_SIG_OID_2_NAME)


class TestGetSigAlgInfo(unittest.TestCase):
    """``get_sig_alg_info`` resolves an OID or an ``AlgorithmIdentifier`` to its row."""

    def test_oid_and_alg_id_give_the_same_row(self):
        """GIVEN an OID and an identifier with it / WHEN resolved / THEN both give the table row."""
        oid = rfc9481.ecdsa_with_SHA384
        self.assertIs(get_sig_alg_info(oid), SIG_ALG_OID_2_INFO[oid])
        self.assertIsInstance(get_sig_alg_info(oid), SigAlgInfo)
        self.assertIs(get_sig_alg_info(_alg_id(oid)), SIG_ALG_OID_2_INFO[oid])

    def test_unknown_oid_is_bad_alg(self):
        """GIVEN an OID that is not a signature OID / WHEN resolved / THEN BadAlg."""
        for oid in (univ.ObjectIdentifier("1.2.3.4.5.99"), sha_alg_name_to_oid("sha256")):
            with self.subTest(oid=str(oid)), self.assertRaises(BadAlg):
                get_sig_alg_info(oid)

    def test_duck_typed_alg_id(self):
        """GIVEN an object with ['algorithm'] and ['parameters'] / WHEN resolved / THEN it works like pyasn1's class."""

        class OwnAlgId:
            """A stand-in for the class of a fuzzing tool."""

            def __init__(self, inner):
                self._inner = inner

            def __getitem__(self, key):
                return self._inner[key]

        info = get_sig_alg_info(OwnAlgId(_alg_id(rfc9481.id_Ed25519)))  # type: ignore[arg-type]
        self.assertEqual(info.family, "eddsa")

    def test_parameters_that_must_be_absent(self):
        """GIVEN ECDSA, EdDSA, ML-DSA, composite ids with NULL parameters / WHEN resolved / THEN BadSigAlgIDParams."""
        for oid in (rfc9481.ecdsa_with_SHA256, rfc9481.id_Ed25519, *list(COMPOSITE_SIG_OID_TO_NAME)[:2]):
            for strict in (False, True):
                with self.subTest(oid=str(oid), strict=strict), self.assertRaises(BadSigAlgIDParams):
                    get_sig_alg_info(_alg_id(oid, univ.Null("")), strict=strict)

    def test_pkcs1_null_and_absent_in_both_modes(self):
        """GIVEN sha256WithRSAEncryption / WHEN NULL or absent parameters / THEN lenient takes both, strict NULL."""
        with_null = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null(""))
        without = _alg_id(rfc9481.sha256WithRSAEncryption)
        self.assertEqual(get_sig_alg_info(with_null).hash_alg, "sha256")
        self.assertEqual(get_sig_alg_info(without).hash_alg, "sha256")
        self.assertEqual(get_sig_alg_info(with_null, strict=True).hash_alg, "sha256")
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(without, strict=True)

    def test_pkcs1_parameters_that_are_neither_null_nor_absent(self):
        """GIVEN sha256WithRSAEncryption with an OCTET STRING / WHEN resolved / THEN BadSigAlgIDParams in both modes."""
        junk = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Any(encoder.encode(univ.OctetString(b"\x01"))))
        for strict in (False, True):
            with self.subTest(strict=strict), self.assertRaises(BadSigAlgIDParams):
                get_sig_alg_info(junk, strict=strict)

    def test_rsa_encryption_carries_null_and_names_no_hash(self):
        """GIVEN rsaEncryption as a signature id / WHEN resolved / THEN family rsa, no hash, NULL (RFC 3370 3.2)."""
        info = get_sig_alg_info(_alg_id(rfc8017.rsaEncryption, univ.Null("")))
        self.assertEqual((info.family, info.hash_alg, info.cms_digest), ("rsa", None, None))
        self.assertEqual(info.params, SigAlgParametersSpec.MUST_BE_NULL)


class TestRsaPssParameters(unittest.TestCase):
    """RSASSA-PSS parameters are read with the RFC 4055 Section 3.1 DEFAULT values."""

    def test_all_defaults_is_sha1_mgf1_sha1_salt_20(self):
        """GIVEN empty RSASSA-PSS-params / WHEN resolved / THEN sha1, MGF1 with sha1, salt 20 (RFC 4055 3.1)."""
        info = get_sig_alg_info(_pss_alg_id())
        self.assertEqual((info.hash_alg, info.mgf1_hash_alg, info.salt_length), ("sha1", "sha1", 20))
        self.assertEqual(info.cms_digest, "sha1")
        self.assertTrue(info.pss)
        self.assertEqual(info.family, "rsa-pss")

    def test_defaults_with_a_decoded_structure(self):
        """GIVEN the DER of empty parameters decoded by pyasn1 / WHEN resolved / THEN the same defaults."""
        params, _ = decoder.decode(b"\x30\x00", asn1Spec=rfc4055.RSASSA_PSS_params())
        info = get_sig_alg_info(_alg_id(rfc9481.id_RSASSA_PSS, params))
        self.assertEqual((info.hash_alg, info.mgf1_hash_alg, info.salt_length), ("sha1", "sha1", 20))

    def test_explicit_hash_mgf_and_salt(self):
        """GIVEN sha384 with MGF1 sha384 and salt 48 / WHEN resolved / THEN the row carries them."""
        sha384 = sha_alg_name_to_oid("sha384")
        for as_any in (True, False):
            with self.subTest(as_any=as_any):
                info = get_sig_alg_info(_pss_alg_id(sha384, sha384, 48, as_any=as_any))
                self.assertEqual((info.hash_alg, info.mgf1_hash_alg, info.salt_length), ("sha384", "sha384", 48))
                self.assertEqual(info.cms_digest, "sha384")

    def test_salt_length_zero_is_kept(self):
        """GIVEN saltLength 0 / WHEN resolved / THEN the salt length is 0, not the default 20 or the digest size."""
        sha256 = sha_alg_name_to_oid("sha256")
        self.assertEqual(get_sig_alg_info(_pss_alg_id(sha256, sha256, 0)).salt_length, 0)

    def test_hash_given_but_mgf_default_is_a_mismatch(self):
        """GIVEN sha256 and no maskGenAlgorithm / WHEN resolved / THEN BadSigAlgIDParams (default MGF1 is sha1)."""
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(_pss_alg_id(sha_alg_name_to_oid("sha256")))

    def test_mgf1_hash_differs_from_hash(self):
        """GIVEN MGF1 with sha512 and hash sha256 / WHEN resolved / THEN BadSigAlgIDParams."""
        alg_id = prepare_rsa_pss_alg_id("sha256", mgf1_hash_alg="sha512")
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(alg_id)

    def test_trailer_field_other_than_1(self):
        """GIVEN trailerField 2 / WHEN resolved / THEN BadSigAlgIDParams (RFC 4055 3.1 allows only 1)."""
        sha256 = sha_alg_name_to_oid("sha256")
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(_pss_alg_id(sha256, sha256, 32, trailer_field=2))

    def test_unknown_hash(self):
        """GIVEN a hashAlgorithm that is no registered hash / WHEN resolved / THEN BadSigAlgIDParams."""
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(_pss_alg_id(univ.ObjectIdentifier("1.2.3.4"), univ.ObjectIdentifier("1.2.3.4"), 20))

    def test_mask_gen_function_other_than_mgf1(self):
        """GIVEN a maskGenAlgorithm with another OID / WHEN resolved / THEN BadSigAlgIDParams."""
        alg_id = _pss_alg_id(sha_alg_name_to_oid("sha256"), sha_alg_name_to_oid("sha256"), 32, as_any=False)
        params = alg_id["parameters"]
        params["maskGenAlgorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.3.4")
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(alg_id)

    def test_parameters_absent_or_not_decodable(self):
        """GIVEN id-RSASSA-PSS without parameters or with other bytes / WHEN resolved / THEN BadSigAlgIDParams."""
        for strict in (False, True):
            with self.subTest(case="absent", strict=strict), self.assertRaises(BadSigAlgIDParams):
                get_sig_alg_info(_alg_id(rfc9481.id_RSASSA_PSS), strict=strict)
            with self.subTest(case="garbage", strict=strict), self.assertRaises(BadSigAlgIDParams):
                get_sig_alg_info(_alg_id(rfc9481.id_RSASSA_PSS, univ.Any(b"\x04\x01\x00")), strict=strict)

    def test_rsassa_pss_oid_alone_has_no_hash(self):
        """GIVEN only the id-RSASSA-PSS OID / WHEN resolved / THEN the hash is unknown (it is in the parameters)."""
        info = get_sig_alg_info(rfc9481.id_RSASSA_PSS)
        self.assertEqual((info.hash_alg, info.cms_digest, info.salt_length), (None, None, None))

    def test_shake_oids_have_absent_parameters_and_a_fixed_hash(self):
        """GIVEN the SHAKE PSS OIDs / WHEN resolved / THEN the hash is the SHAKE function, parameters absent."""
        info = get_sig_alg_info(_alg_id(rfc9481.id_RSASSA_PSS_SHAKE256))
        self.assertEqual((info.hash_alg, info.pss, info.family), ("shake256", True, "rsa-pss"))
        with self.assertRaises(BadSigAlgIDParams):
            get_sig_alg_info(_alg_id(rfc9481.id_RSASSA_PSS_SHAKE256, univ.Null("")))

    def test_a_mismatch_error_is_a_bad_sig_alg_id(self):
        """GIVEN BadSigAlgIDParams / WHEN caught as its base class / THEN BadSigAlgID catches it."""
        with self.assertRaises(BadSigAlgID):
            get_sig_alg_info(_alg_id(rfc9481.id_RSASSA_PSS))


if __name__ == "__main__":
    unittest.main()
