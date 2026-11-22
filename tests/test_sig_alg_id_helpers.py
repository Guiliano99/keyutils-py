# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the helpers around the signature algorithm table.

``check_consistency_sig_alg_id_and_key``, ``check_consistency_sig_alg_id_and_spki``, ``validate_sig_alg_id``,
``prepare_sig_alg_id`` and
``prepare_hash_alg_id`` read the same row as ``sign_with_alg_id`` and ``verify_signature_with_alg_id``.
"""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
from keyutils_py import (
    check_consistency_sig_alg_id_and_key,
    check_consistency_sig_alg_id_and_spki,
    generate_key,
    sign_with_alg_id,
    validate_sig_alg_id,
    verify_signature_with_alg_id,
)
from keyutils_py.exceptions import BadAlg, BadSigAlgID, BadSigAlgIDParams
from keyutils_py.keyutils import (
    _has_explicit_pss_default,
    prepare_alg_id,
    prepare_hash_alg_id,
    prepare_mgf1_alg_id,
    prepare_rsa_pss_alg_id,
    prepare_sig_alg_id,
    subject_public_key_info_from_pubkey,
)
from keyutils_py.oids import COMPOSITE_SIG_NAME_TO_OID, PQ_NAME_2_OID
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc8017, rfc9481

DATA = b"keyutils-py signature algorithm helpers"


# DER of RSASSA-PSS-params with one field at its DEFAULT value (RFC 4055 Section 3.1), written by hand because the DER
# encoder of pyasn1 omits an integer DEFAULT. The loader of cryptography refuses the first three, not the fourth.
_EXPLICIT_HASH_SHA1 = bytes.fromhex("300da00b300906052b0e03021a0500")  # [0] sha1Identifier (id-sha1, NULL)
_EXPLICIT_MGF1_SHA1 = bytes.fromhex("301aa118301606092a864886f70d010108300906052b0e03021a0500")  # [1] mgf1SHA1Identifier
_EXPLICIT_SALT_20 = bytes.fromhex("3005a203020114")  # [2] 20
_EXPLICIT_TRAILER_1 = bytes.fromhex("3005a303020101")  # [3] 1
_HASH_SHA1_WITHOUT_NULL = bytes.fromhex("300ba009300706052b0e03021a")  # [0] (id-sha1): not sha1Identifier
_SALT_32 = bytes.fromhex("3005a203020120")  # [2] 32


def _der(alg_id) -> str:
    """Return the DER of ``alg_id`` as hex."""
    return encoder.encode(alg_id).hex()


def _alg_id(oid, parameters=None):
    """Build an ``AlgorithmIdentifier``."""
    return prepare_alg_id(oid, value=parameters)


def _pss_spki(public_key, parameters=None):
    """Return the id-RSASSA-PSS SPKI of ``public_key`` with ``parameters`` (absent for ``None``)."""
    spki = subject_public_key_info_from_pubkey(public_key, use_rsa_pss=True)
    spki["algorithm"] = _alg_id(rfc9481.id_RSASSA_PSS, parameters)
    return spki


def _explicit_default_pss_params():
    """Return RSASSA-PSS-params with every field present at its DEFAULT value (RFC 4055 Section 3.1)."""
    params = rfc4055.RSASSA_PSS_params()
    params["hashAlgorithm"]["algorithm"] = rfc4055.sha1Identifier["algorithm"]
    params["hashAlgorithm"]["parameters"] = rfc4055.sha1Identifier["parameters"]
    params["maskGenAlgorithm"]["algorithm"] = rfc4055.mgf1SHA1Identifier["algorithm"]
    params["maskGenAlgorithm"]["parameters"] = rfc4055.mgf1SHA1Identifier["parameters"]
    params["saltLength"] = 20
    params["trailerField"] = 1
    return params


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


class TestCheckConsistencySpki(unittest.TestCase):
    """``check_consistency_sig_alg_id_and_spki`` applies RFC 4055 Sections 1.2 and 3.3 to the SPKI of the key."""

    @classmethod
    def setUpClass(cls):
        """Generate one RSA key and the SHA-256 RSASSA-PSS-params (salt length 32) of its PSS SPKI."""
        cls.public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        cls.key_params = prepare_rsa_pss_alg_id("sha256", salt_length=32)["parameters"]

    def test_case_1_rsa_encryption_key_needs_no_parameter_validation(self):
        """GIVEN an rsaEncryption SPKI / WHEN checked against PSS, SHAKE-PSS and PKCS#1 v1.5 / THEN all pass."""
        spki = subject_public_key_info_from_pubkey(self.public_key)
        for alg_id in (
            prepare_rsa_pss_alg_id("sha512", salt_length=0),
            _alg_id(rfc9481.id_RSASSA_PSS_SHAKE256),
            _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null("")),
        ):
            with self.subTest(oid=str(alg_id["algorithm"])):
                check_consistency_sig_alg_id_and_spki(alg_id, spki)

    def test_case_2_pss_key_without_parameters_needs_no_parameter_validation(self):
        """GIVEN a PSS SPKI without parameters / WHEN checked against any PSS identifier / THEN it passes."""
        spki = _pss_spki(self.public_key)
        for alg_id in (prepare_rsa_pss_alg_id("sha384", salt_length=0), _alg_id(rfc9481.id_RSASSA_PSS_SHAKE128)):
            with self.subTest(oid=str(alg_id["algorithm"])):
                check_consistency_sig_alg_id_and_spki(alg_id, spki)

    def test_case_3_matching_parameters_pass(self):
        """GIVEN a PSS SPKI with parameters, built and decoded from DER / WHEN checked against the same / THEN pass."""
        spki = _pss_spki(self.public_key, self.key_params)
        received, _ = decoder.decode(encoder.encode(spki), asn1Spec=rfc5280.SubjectPublicKeyInfo())
        for key_spki in (spki, received):
            check_consistency_sig_alg_id_and_spki(prepare_rsa_pss_alg_id("sha256", salt_length=32), key_spki)

    def test_case_3_mismatched_hash_is_refused(self):
        """GIVEN a SHA-256 PSS SPKI / WHEN checked against SHA-384 PSS or SHAKE128-PSS, also with the key's
        parameters (RFC 8702: they must be absent) / THEN BadSigAlgIDParams.
        """
        spki = _pss_spki(self.public_key, self.key_params)
        for alg_id in (
            prepare_rsa_pss_alg_id("sha384", salt_length=32),
            _alg_id(rfc9481.id_RSASSA_PSS_SHAKE128),
            _alg_id(rfc9481.id_RSASSA_PSS_SHAKE128, self.key_params),
        ):
            with self.subTest(oid=str(alg_id["algorithm"])), self.assertRaises(BadSigAlgIDParams):
                check_consistency_sig_alg_id_and_spki(alg_id, spki)

    def test_case_3_mismatched_mgf1_hash_is_refused(self):
        """GIVEN a SHA-256 PSS SPKI / WHEN checked against PSS with MGF1-SHA-512 / THEN BadSigAlgIDParams."""
        alg_id = prepare_rsa_pss_alg_id("sha256", salt_length=32, mgf1_hash_alg="sha512")
        with self.assertRaises(BadSigAlgIDParams):
            check_consistency_sig_alg_id_and_spki(alg_id, _pss_spki(self.public_key, self.key_params))

    def test_case_3_salt_length_must_be_greater_or_equal(self):
        """GIVEN a PSS SPKI with salt length 32 / WHEN checked against 31, 32 and 64 / THEN 31 is refused."""
        spki = _pss_spki(self.public_key, self.key_params)
        with self.assertRaises(BadSigAlgIDParams):
            check_consistency_sig_alg_id_and_spki(prepare_rsa_pss_alg_id("sha256", salt_length=31), spki)
        for salt_length in (32, 64):
            check_consistency_sig_alg_id_and_spki(prepare_rsa_pss_alg_id("sha256", salt_length=salt_length), spki)

    def test_case_3_absent_and_explicit_default_parameters_are_equal(self):
        """GIVEN a PSS SPKI with empty parameters (all DEFAULT) / WHEN the signature names them absent or explicit
        / THEN it passes, and SHA-256 is refused, because the empty parameters mean SHA-1 (case 3, not case 2).
        """
        spki = _pss_spki(self.public_key, rfc4055.rSASSA_PSS_Default_Params)
        explicit = _explicit_default_pss_params()
        for sig_params in (rfc4055.rSASSA_PSS_Default_Params, explicit, univ.Any(encoder.encode(explicit))):
            with self.subTest(sig_params=_der(sig_params)):
                check_consistency_sig_alg_id_and_spki(_alg_id(rfc9481.id_RSASSA_PSS, sig_params), spki)
        with self.assertRaises(BadSigAlgIDParams):
            check_consistency_sig_alg_id_and_spki(prepare_rsa_pss_alg_id("sha256", salt_length=20), spki)

    def test_non_pss_identifier_on_pss_key_is_refused(self):
        """GIVEN a PSS SPKI, with and without parameters / WHEN checked against PKCS#1 v1.5, rsaEncryption or
        ECDSA / THEN BadSigAlgID, not BadSigAlgIDParams (RFC 4055 Section 1.2).
        """
        for spki in (_pss_spki(self.public_key), _pss_spki(self.public_key, self.key_params)):
            for alg_id in (
                _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null("")),
                _alg_id(rfc8017.rsaEncryption, univ.Null("")),
                _alg_id(rfc9481.ecdsa_with_SHA256),
            ):
                with self.subTest(oid=str(alg_id["algorithm"])), self.assertRaises(BadSigAlgID) as ctx:
                    check_consistency_sig_alg_id_and_spki(alg_id, spki)
                self.assertNotIsInstance(ctx.exception, BadSigAlgIDParams)

    def test_explicit_default_in_the_key_parameters_is_bad_sig_alg_id_params(self):
        """GIVEN a PSS SPKI whose parameters encode the DEFAULT values explicitly (not DER), as built and as DER /
        WHEN checked against a matching PSS identifier / THEN BadSigAlgIDParams chained to the loader's ValueError,
        and not that bare ValueError (RFC 4055 Section 3.1 leaves a DEFAULT out of the generated encoding).
        """
        explicit = _explicit_default_pss_params()
        sig_alg_id = _alg_id(rfc9481.id_RSASSA_PSS, explicit)  # the signature side takes the explicit form
        for key_params in (explicit, univ.Any(encoder.encode(explicit))):
            with self.subTest(key_params=type(key_params).__name__):
                spki = _pss_spki(self.public_key, key_params)
                with self.assertRaises(BadSigAlgIDParams) as ctx:
                    check_consistency_sig_alg_id_and_spki(sig_alg_id, spki)
                self.assertIsInstance(ctx.exception.__cause__, ValueError)
                self.assertIn("DER", str(ctx.exception))
                self.assertIn("DEFAULT", str(ctx.exception))
        check_consistency_sig_alg_id_and_spki(sig_alg_id, _pss_spki(self.public_key, rfc4055.rSASSA_PSS_Default_Params))

    def test_unreadable_key_parameters_are_bad_sig_alg_id_params(self):
        """GIVEN a PSS SPKI with parameters that are no RSASSA-PSS-params, have trailing data, a trailerField other
        than 1 or an MGF1 hash that differs from the hash / WHEN checked against PSS or against PKCS#1 v1.5 / THEN
        BadSigAlgIDParams, because the key parameters are read before the key is loaded and before the identifier
        is compared (the PKCS#1 v1.5 identifier is BadSigAlgID only for a key whose parameters can be read).
        """
        trailer_2 = rfc4055.RSASSA_PSS_params()
        trailer_2["trailerField"] = 2
        valid = encoder.encode(rfc4055.rSASSA_PSS_Default_Params)
        unreadable = {
            "NULL": univ.Any(b"\x05\x00"),
            "octet string": univ.Any(encoder.encode(univ.OctetString(b"junk"))),
            "trailing data": univ.Any(valid + b"\x00"),
            "trailerField 2": trailer_2,
            "MGF1 hash differs": prepare_rsa_pss_alg_id("sha256", salt_length=32, mgf1_hash_alg="sha512")["parameters"],
        }
        for name, key_params in unreadable.items():
            spki = _pss_spki(self.public_key, key_params)
            for alg_id in (
                prepare_rsa_pss_alg_id("sha256", salt_length=32),
                _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null("")),
            ):
                with self.subTest(key_params=name, oid=str(alg_id["algorithm"])):
                    with self.assertRaises(BadSigAlgIDParams):
                        check_consistency_sig_alg_id_and_spki(alg_id, spki)

    def test_a_key_that_cannot_be_loaded_for_another_reason_keeps_its_error(self):
        """GIVEN a PSS SPKI without parameters and key bits that are no RSAPublicKey / WHEN checked / THEN the
        loader's ValueError, which is no parameter error (only an explicit DEFAULT in readable parameters makes it
        a BadSigAlgIDParams).
        """
        spki = _pss_spki(self.public_key)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(b"\x30\x03\x02\x01\x00")
        with self.assertRaises(ValueError) as ctx:
            check_consistency_sig_alg_id_and_spki(prepare_rsa_pss_alg_id("sha256"), spki)
        self.assertNotIsInstance(ctx.exception, BadSigAlgIDParams)

    def test_a_corrupt_key_with_valid_parameters_keeps_the_loader_error(self):
        """GIVEN a PSS SPKI with valid parameters, without an explicit DEFAULT (SHA-256 / salt 32, the SHA-1 default
        parameters, SHA-1 without NULL, salt 32), and key bits that are no RSAPublicKey / WHEN checked / THEN the
        loader's plain ValueError, not a BadSigAlgIDParams: the parameters are not the cause.
        """
        for name, key_params in {
            "SHA-256": self.key_params,
            "default parameters": rfc4055.rSASSA_PSS_Default_Params,
            "SHA-1 without NULL": univ.Any(_HASH_SHA1_WITHOUT_NULL),
            "salt 32": univ.Any(_SALT_32),
        }.items():
            spki = _pss_spki(self.public_key, key_params)
            spki["subjectPublicKey"] = univ.BitString.fromOctetString(b"\x30\x03\x02\x01\x00")
            with self.subTest(key_params=name), self.assertRaises(ValueError) as ctx:
                check_consistency_sig_alg_id_and_spki(prepare_rsa_pss_alg_id("sha256", salt_length=32), spki)
            self.assertNotIsInstance(ctx.exception, BadSigAlgIDParams)

    def test_each_explicit_default_the_loader_refuses_is_bad_sig_alg_id_params(self):
        """GIVEN a PSS SPKI whose parameters carry hashAlgorithm sha1Identifier, maskGenAlgorithm mgf1SHA1Identifier
        or saltLength 20 explicitly (DER, one field at a time) / WHEN checked / THEN BadSigAlgIDParams chained to
        the loader's ValueError (the DER-only key loader refuses each; the signature side would accept it).
        """
        sig_alg_id = _alg_id(rfc9481.id_RSASSA_PSS, rfc4055.rSASSA_PSS_Default_Params)
        for name, der in {
            "hashAlgorithm": _EXPLICIT_HASH_SHA1,
            "maskGenAlgorithm": _EXPLICIT_MGF1_SHA1,
            "saltLength": _EXPLICIT_SALT_20,
        }.items():
            with self.subTest(field=name), self.assertRaises(BadSigAlgIDParams) as ctx:
                check_consistency_sig_alg_id_and_spki(sig_alg_id, _pss_spki(self.public_key, univ.Any(der)))
            self.assertIsInstance(ctx.exception.__cause__, ValueError)

    def test_only_a_field_at_its_default_value_is_an_explicit_default(self):
        """GIVEN RSASSA-PSS-params with a field at its DEFAULT value, at another value, or no field / WHEN asked /
        THEN only the first is an explicit DEFAULT; SHA-1 without NULL is not the sha1Identifier (RFC 4055 2.1).
        """
        for name, parameters, expected in (
            ("empty", rfc4055.rSASSA_PSS_Default_Params, False),
            ("SHA-256 / salt 32 as a structure", self.key_params, False),
            ("SHA-1 without NULL", univ.Any(_HASH_SHA1_WITHOUT_NULL), False),
            ("salt 32", univ.Any(_SALT_32), False),
            ("hashAlgorithm sha1Identifier", univ.Any(_EXPLICIT_HASH_SHA1), True),
            ("maskGenAlgorithm mgf1SHA1Identifier", univ.Any(_EXPLICIT_MGF1_SHA1), True),
            ("saltLength 20", univ.Any(_EXPLICIT_SALT_20), True),
            ("trailerField 1", univ.Any(_EXPLICIT_TRAILER_1), True),
            ("every field, as a structure", _explicit_default_pss_params(), True),
        ):
            with self.subTest(parameters=name):
                self.assertIs(_has_explicit_pss_default(parameters), expected)


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
