# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the helpers around the signature algorithm table.

``check_consistency_sig_alg_id_and_key``, ``validate_sig_alg_id``, ``prepare_sig_alg_id`` and
``prepare_hash_alg_id`` read the same row as ``sign_with_alg_id`` and ``verify_signature_with_alg_id``.
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
from keyutils_py import (
    check_consistency_sig_alg_id_and_key,
    generate_key,
    sign_with_alg_id,
    validate_sig_alg_id,
    verify_signature_with_alg_id,
)
from keyutils_py.exceptions import BadAlg, BadSigAlgID, BadSigAlgIDParams
from keyutils_py.keyutils import (
    prepare_alg_id,
    prepare_hash_alg_id,
    prepare_mgf1_alg_id,
    prepare_rsa_pss_alg_id,
    prepare_sig_alg_id,
)
from keyutils_py.oids import COMPOSITE_SIG_NAME_TO_OID, PQ_NAME_2_OID
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc8017, rfc9481

DATA = b"keyutils-py signature algorithm helpers"


def _der(alg_id) -> str:
    """Return the DER of ``alg_id`` as hex."""
    return encoder.encode(alg_id).hex()


def _alg_id(oid, parameters=None):
    """Build an ``AlgorithmIdentifier``."""
    return prepare_alg_id(oid, value=parameters)


class TestCheckConsistency(unittest.TestCase):
    """``check_consistency_sig_alg_id_and_key`` raises ``BadSigAlgID`` for every mismatch, for every family."""

    @classmethod
    def setUpClass(cls):
        """Generate one key per family."""
        cls.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec = ec.generate_private_key(ec.SECP256R1())
        cls.ml_dsa = generate_key("ml-dsa-44")
        cls.composite_ec = generate_key("composite-sig-ml-dsa-44-ecdsa-secp256r1")
        cls.composite_rsa = generate_key("composite-sig-ml-dsa-44-rsa2048-pss")
        cls.hss = generate_key("hss")

    def test_rsa_key_with_id_rsassa_pss_is_consistent(self):
        """GIVEN an RSA key, private and public / WHEN checked against id-RSASSA-PSS / THEN it passes (RFC 4055 1.2)."""
        pss = prepare_rsa_pss_alg_id("sha256")
        for key in (self.rsa, self.rsa.public_key()):
            check_consistency_sig_alg_id_and_key(pss, key)
            check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.id_RSASSA_PSS_SHAKE128), key)

    def test_rsa_key_with_rsa_encryption_is_consistent(self):
        """GIVEN an RSA key / WHEN checked against rsaEncryption used as signature identifier / THEN it passes."""
        check_consistency_sig_alg_id_and_key(_alg_id(rfc8017.rsaEncryption, univ.Null("")), self.rsa)

    def test_composite_key_matches_both_oids_of_its_rsa_variants(self):
        """GIVEN a composite key with an RSA half / WHEN checked against the PSS and the PKCS#1 OID / THEN both pass."""
        for name in ("composite-sig-ml-dsa-44-rsa2048-pss", "composite-sig-ml-dsa-44-rsa2048"):
            for key in (self.composite_rsa, self.composite_rsa.public_key()):
                check_consistency_sig_alg_id_and_key(_alg_id(COMPOSITE_SIG_NAME_TO_OID[name]), key)

    def test_stateful_key_matches_its_oid(self):
        """GIVEN an HSS key / WHEN checked against the HSS OID / THEN it passes, and an XMSS OID is BadSigAlgID."""
        check_consistency_sig_alg_id_and_key(_alg_id(self.hss.get_oid()), self.hss.public_key())
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(_alg_id(PQ_NAME_2_OID["xmss"]), self.hss)

    def test_pq_key_with_composite_oid_is_bad_sig_alg_id(self):
        """GIVEN a PQ key / WHEN checked against a composite OID / THEN BadSigAlgID, not TypeError."""
        alg_id = _alg_id(COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-ecdsa-secp256r1"])
        for key in (self.ml_dsa, self.hss, self.ec, self.rsa):
            with self.subTest(key=type(key).__name__), self.assertRaises(BadSigAlgID):
                check_consistency_sig_alg_id_and_key(alg_id, key)

    def test_composite_key_with_classic_or_pq_oid_is_bad_sig_alg_id(self):
        """GIVEN a composite key / WHEN checked against ECDSA, ML-DSA, Ed25519 or RSA OIDs / THEN BadSigAlgID."""
        for alg_id in (
            _alg_id(rfc9481.ecdsa_with_SHA256),
            _alg_id(PQ_NAME_2_OID["ml-dsa-44"]),
            _alg_id(rfc9481.id_Ed25519),
            _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null("")),
            prepare_rsa_pss_alg_id("sha256"),
        ):
            with self.subTest(oid=str(alg_id["algorithm"])), self.assertRaises(BadSigAlgID):
                check_consistency_sig_alg_id_and_key(alg_id, self.composite_ec)

    def test_composite_key_with_the_oid_of_another_combination(self):
        """GIVEN a composite P-256 key / WHEN checked against the RSA-PSS combination / THEN BadSigAlgID."""
        alg_id = _alg_id(COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-rsa2048-pss"])
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(alg_id, self.composite_ec)

    def test_other_parameter_set_and_unknown_oid(self):
        """GIVEN an ML-DSA-44 key / WHEN checked against ML-DSA-65 or an unknown OID / THEN BadSigAlgID."""
        for oid in (PQ_NAME_2_OID["ml-dsa-65"], univ.ObjectIdentifier("1.2.3.4.5.99")):
            with self.assertRaises(BadSigAlgID):
                check_consistency_sig_alg_id_and_key(_alg_id(oid), self.ml_dsa.public_key())

    def test_a_key_that_is_no_signature_key_is_bad_sig_alg_id(self):
        """GIVEN a key agreement or KEM key / WHEN checked against a signature OID / THEN BadSigAlgID."""
        for key in (x25519.X25519PrivateKey.generate(), generate_key("ml-kem-512")):
            with self.subTest(key=type(key).__name__), self.assertRaises(BadSigAlgID):
                check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.id_Ed25519), key)

    def test_an_object_that_is_no_key_is_a_value_error(self):
        """GIVEN an object that is no key / WHEN checked / THEN ValueError, as documented."""
        with self.assertRaises(ValueError):
            check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.id_Ed25519), object())  # type: ignore[arg-type]

    def test_parameters_are_not_checked(self):
        """GIVEN an ECDSA identifier with NULL parameters / WHEN checked against an EC key / THEN it passes."""
        check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.ecdsa_with_SHA256, univ.Null("")), self.ec)

    def test_ed448_and_ed25519_are_told_apart(self):
        """GIVEN an Ed448 key / WHEN checked against the Ed25519 OID / THEN BadSigAlgID."""
        key = ed448.Ed448PrivateKey.generate()
        check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.id_Ed448), key)
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.id_Ed25519), key)
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(_alg_id(rfc9481.id_Ed448), ed25519.Ed25519PrivateKey.generate())


class TestValidateSigAlgId(unittest.TestCase):
    """``validate_sig_alg_id`` is strict by default and lenient with ``strict=False``, like the verifier."""

    def test_strict_default_rejects_absent_parameters_on_pkcs1(self):
        """GIVEN sha256WithRSAEncryption without parameters / WHEN validated / THEN refused unless strict=False."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption)
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(alg_id)
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(alg_id, strict=True)
        validate_sig_alg_id(alg_id, strict=False)

    def test_both_consumer_contracts_hold_for_one_identifier(self):
        """GIVEN PKCS#1 v1.5 without NULL / WHEN validated and verified / THEN validate refuses, verify accepts."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption)
        signature = sign_with_alg_id(key, alg_id, DATA)
        verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(alg_id)

    def test_parameters_that_must_be_absent_are_refused_in_both_modes(self):
        """GIVEN ECDSA, EdDSA and ML-DSA identifiers with NULL / WHEN validated / THEN refused in both modes."""
        for oid in (rfc9481.ecdsa_with_SHA256, rfc9481.id_Ed25519, PQ_NAME_2_OID["ml-dsa-44"]):
            for strict in (True, False):
                with self.subTest(oid=str(oid), strict=strict), self.assertRaises(BadSigAlgIDParams):
                    validate_sig_alg_id(_alg_id(oid, univ.Null("")), strict=strict)

    def test_rsa_encryption_validates(self):
        """GIVEN rsaEncryption with NULL / WHEN validated / THEN it passes; absent is refused in strict mode."""
        validate_sig_alg_id(_alg_id(rfc8017.rsaEncryption, univ.Null("")))
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(_alg_id(rfc8017.rsaEncryption))
        validate_sig_alg_id(_alg_id(rfc8017.rsaEncryption), strict=False)

    def test_unknown_oid_is_bad_alg(self):
        """GIVEN an OID that is no signature OID / WHEN validated / THEN BadAlg in both modes."""
        for strict in (True, False):
            with self.assertRaises(BadAlg):
                validate_sig_alg_id(_alg_id(univ.ObjectIdentifier("1.2.3.4.5.99")), strict=strict)

    def test_pss_parameters_are_checked(self):
        """GIVEN PSS with MGF1 sha512 and hash sha256 / WHEN validated / THEN BadSigAlgIDParams; plain PSS passes."""
        validate_sig_alg_id(prepare_rsa_pss_alg_id("sha256"))
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(prepare_rsa_pss_alg_id("sha256", mgf1_hash_alg="sha512"))
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(_alg_id(rfc9481.id_RSASSA_PSS))

    def test_pss_with_omitted_defaults_validates(self):
        """GIVEN RSASSA-PSS-params with every field omitted (RFC 4055 3.1) / WHEN validated / THEN no PyAsn1Error."""
        alg_id = _alg_id(rfc9481.id_RSASSA_PSS, univ.Any(encoder.encode(rfc4055.RSASSA_PSS_params())))
        validate_sig_alg_id(alg_id)


class TestPrepareSigAlgId(unittest.TestCase):
    """``prepare_sig_alg_id`` builds the identifier for any signature key; ``None`` is the family default."""

    @classmethod
    def setUpClass(cls):
        """Generate the keys."""
        cls.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec = ec.generate_private_key(ec.SECP256R1())

    def test_rsa_and_ecdsa_defaults_are_sha256_and_unchanged(self):
        """GIVEN RSA and EC keys / WHEN no hash is given / THEN the bytes are those of the explicit sha256."""
        self.assertEqual(_der(prepare_sig_alg_id(self.rsa)), "300d06092a864886f70d01010b0500")
        self.assertEqual(_der(prepare_sig_alg_id(self.rsa)), _der(prepare_sig_alg_id(self.rsa, "sha256")))
        self.assertEqual(_der(prepare_sig_alg_id(self.ec)), "300a06082a8648ce3d040302")
        self.assertEqual(_der(prepare_sig_alg_id(self.ec)), _der(prepare_sig_alg_id(self.ec, "sha256")))
        self.assertEqual(_der(prepare_sig_alg_id(self.ec.public_key(), "sha384")), "300a06082a8648ce3d040303")

    def test_rsa_pss_default_hash(self):
        """GIVEN an RSA key and use_rsa_pss / WHEN no hash is given / THEN id-RSASSA-PSS with sha256."""
        self.assertEqual(_der(prepare_sig_alg_id(self.rsa, use_rsa_pss=True)), _der(prepare_rsa_pss_alg_id("sha256")))
        self.assertEqual(
            _der(prepare_sig_alg_id(self.rsa, "shake128", use_rsa_pss=True)), _der(prepare_rsa_pss_alg_id("shake128"))
        )

    def test_eddsa_ignores_the_hash(self):
        """GIVEN Ed25519 and Ed448 keys / WHEN a hash is given or not / THEN the identifier is the EdDSA OID."""
        for key, oid in (
            (ed25519.Ed25519PrivateKey.generate(), rfc9481.id_Ed25519),
            (ed448.Ed448PrivateKey.generate(), rfc9481.id_Ed448),
        ):
            for hash_alg in (None, "sha256", "sha512"):
                self.assertEqual(prepare_sig_alg_id(key, hash_alg)["algorithm"], oid)

    def test_dsa_default(self):
        """GIVEN a DSA key / WHEN no hash is given / THEN id-dsa-with-sha256."""
        alg_id = prepare_sig_alg_id(generate_key("dsa"))
        self.assertEqual(str(alg_id["algorithm"]), "2.16.840.1.101.3.4.3.2")
        self.assertFalse(alg_id["parameters"].isValue)

    def test_ml_dsa_hash_selects_the_pre_hash_oid_only_when_registered(self):
        """GIVEN an ML-DSA key / WHEN no hash, sha512 or sha256 / THEN pure, pre-hash and pure OID."""
        key = generate_key("ml-dsa-44")
        self.assertEqual(prepare_sig_alg_id(key)["algorithm"], PQ_NAME_2_OID["ml-dsa-44"])
        self.assertEqual(prepare_sig_alg_id(key, "sha512")["algorithm"], PQ_NAME_2_OID["ml-dsa-44-sha512"])
        self.assertEqual(prepare_sig_alg_id(key.public_key(), "sha256")["algorithm"], PQ_NAME_2_OID["ml-dsa-44"])
        self.assertFalse(prepare_sig_alg_id(key, "sha512")["parameters"].isValue)

    def test_slh_dsa_without_hash_is_the_pure_oid(self):
        """GIVEN an SLH-DSA-SHA2-128s key / WHEN no hash is given / THEN the pure OID; sha256 gives the pre-hash OID."""
        key = generate_key("slh-dsa-sha2-128s")
        self.assertEqual(prepare_sig_alg_id(key)["algorithm"], PQ_NAME_2_OID["slh-dsa-sha2-128s"])
        self.assertEqual(prepare_sig_alg_id(key, "sha256")["algorithm"], PQ_NAME_2_OID["slh-dsa-sha2-128s-sha256"])
        self.assertEqual(prepare_sig_alg_id(key, "sha512")["algorithm"], PQ_NAME_2_OID["slh-dsa-sha2-128s"])

    def test_falcon_and_stateful_keys(self):
        """GIVEN Falcon, HSS, XMSS and XMSS^MT keys / WHEN an identifier is prepared / THEN it carries the key OID."""
        self.assertEqual(prepare_sig_alg_id(generate_key("falcon-512"))["algorithm"], PQ_NAME_2_OID["falcon-512"])
        for name in ("hss", "xmss", "xmssmt"):
            with self.subTest(key=name):
                key = generate_key(name)
                self.assertEqual(prepare_sig_alg_id(key)["algorithm"], key.get_oid())
                self.assertEqual(prepare_sig_alg_id(key.public_key(), "sha256")["algorithm"], key.get_oid())

    def test_composite_key_follows_use_rsa_pss(self):
        """GIVEN composite keys / WHEN use_rsa_pss is given or not / THEN the OID is that of the padding."""
        rsa_key = generate_key("composite-sig-ml-dsa-44-rsa2048-pss")
        self.assertEqual(
            prepare_sig_alg_id(rsa_key, use_rsa_pss=True)["algorithm"],
            COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-rsa2048-pss"],
        )
        self.assertEqual(
            prepare_sig_alg_id(rsa_key)["algorithm"], COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-rsa2048"]
        )
        ec_key = generate_key("composite-sig-ml-dsa-44-ecdsa-secp256r1")
        oid = COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-ecdsa-secp256r1"]
        for use_pss in (False, True):
            self.assertEqual(prepare_sig_alg_id(ec_key.public_key(), "sha256", use_rsa_pss=use_pss)["algorithm"], oid)

    def test_every_identifier_signs_and_verifies_with_its_key(self):
        """GIVEN a key of each family / WHEN prepare_sig_alg_id(key) is used to sign / THEN the pair verifies."""
        for name in (
            "ed25519",
            "ml-dsa-44",
            "slh-dsa-sha2-128s",
            "falcon-512",
            "hss",
            "composite-sig-ml-dsa-44-ed25519",
        ):
            with self.subTest(key=name):
                key = generate_key(name)
                alg_id = prepare_sig_alg_id(key)
                verify_signature_with_alg_id(key.public_key(), alg_id, DATA, sign_with_alg_id(key, alg_id, DATA))
        for key in (self.rsa, self.ec):
            alg_id = prepare_sig_alg_id(key)
            verify_signature_with_alg_id(key.public_key(), alg_id, DATA, sign_with_alg_id(key, alg_id, DATA))

    def test_keys_without_a_signature_identifier_are_bad_alg(self):
        """GIVEN a KEM key or a hash that has no OID for the key / WHEN prepared / THEN BadAlg."""
        with self.assertRaises(BadAlg):
            prepare_sig_alg_id(x25519.X25519PrivateKey.generate())  # type: ignore[arg-type]
        with self.assertRaises(BadAlg):
            prepare_sig_alg_id(generate_key("ml-kem-512"))
        with self.assertRaises(BadAlg):
            prepare_sig_alg_id(self.rsa, "md5")
        with self.assertRaises(BadAlg):
            prepare_sig_alg_id(self.ec, "shake512")


class TestPrepareHashAlgId(unittest.TestCase):
    """``with_null`` chooses between absent and NULL parameters; the default keeps today's bytes."""

    # The DER that prepare_hash_alg_id wrote before ``with_null`` existed (RFC 4055 2.1, RFC 8702, RFC 9688 2).
    DEFAULT_DER = {
        "sha1": "300906052b0e03021a0500",
        "sha224": "300d06096086480165030402040500",
        "sha256": "300d06096086480165030402010500",
        "sha384": "300d06096086480165030402020500",
        "sha512": "300d06096086480165030402030500",
        "sha3_224": "300b0609608648016503040207",
        "sha3_256": "300b0609608648016503040208",
        "sha3_384": "300b0609608648016503040209",
        "sha3_512": "300b060960864801650304020a",
        "shake128": "300b060960864801650304020b",
        "shake256": "300b060960864801650304020c",
    }

    def test_default_bytes_are_unchanged(self):
        """GIVEN each hash / WHEN the identifier is built without with_null / THEN the DER is the one from before."""
        for name, expected in self.DEFAULT_DER.items():
            with self.subTest(hash=name):
                self.assertEqual(_der(prepare_hash_alg_id(name)), expected)
                self.assertEqual(_der(prepare_hash_alg_id(name, with_null=None)), expected)

    def test_with_null_false_writes_absent_parameters(self):
        """GIVEN with_null=False / WHEN built for SHA-1 and SHA-2 / THEN the parameters are absent (RFC 5754 2)."""
        absent = {
            "sha1": "300706052b0e03021a",
            "sha224": "300b0609608648016503040204",
            "sha256": "300b0609608648016503040201",
            "sha384": "300b0609608648016503040202",
            "sha512": "300b0609608648016503040203",
        }
        for name, expected in absent.items():
            with self.subTest(hash=name):
                alg_id = prepare_hash_alg_id(name, with_null=False)
                self.assertFalse(alg_id["parameters"].isValue)
                self.assertEqual(_der(alg_id), expected)

    def test_with_null_true_writes_null_for_sha1_and_sha2(self):
        """GIVEN with_null=True / WHEN built for SHA-1 and SHA-2 / THEN the parameters are NULL."""
        for name in ("sha1", "sha224", "sha256", "sha384", "sha512"):
            with self.subTest(hash=name):
                self.assertEqual(_der(prepare_hash_alg_id(name, with_null=True)), self.DEFAULT_DER[name])

    def test_sha3_and_shake_are_absent_and_refuse_null(self):
        """GIVEN SHA-3 and SHAKE / WHEN with_null is None or False / THEN absent; with_null=True raises ValueError."""
        for name in ("sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake128", "shake256"):
            with self.subTest(hash=name):
                for with_null in (None, False):
                    self.assertEqual(_der(prepare_hash_alg_id(name, with_null=with_null)), self.DEFAULT_DER[name])
                with self.assertRaises(ValueError):
                    prepare_hash_alg_id(name, with_null=True)

    def test_random_parameters_exclude_with_null(self):
        """GIVEN fill_random_params / WHEN combined with with_null / THEN ValueError; alone it still fills."""
        with self.assertRaises(ValueError):
            prepare_hash_alg_id("sha256", fill_random_params=True, with_null=False)
        self.assertTrue(prepare_hash_alg_id("sha256", fill_random_params=True)["parameters"].isValue)

    def test_null_stays_inside_pss_and_mgf1(self):
        """GIVEN RSASSA-PSS parameters and MGF1 / WHEN built / THEN inner hash ids keep NULL (RFC 4055 2.1)."""
        mgf = prepare_mgf1_alg_id("sha256")
        self.assertIn("06096086480165030402010500", _der(mgf))
        params = prepare_rsa_pss_alg_id("sha256")["parameters"]
        self.assertIn("300d06096086480165030402010500", _der(params))

    def test_unknown_hash(self):
        """GIVEN a name that is no hash / WHEN built / THEN ValueError."""
        with self.assertRaises(ValueError):
            prepare_hash_alg_id("md5")


if __name__ == "__main__":
    unittest.main()
