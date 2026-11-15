# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``sign_with_alg_id`` and ``verify_signature_with_alg_id``, which read the table row of the identifier.

The matrices run over the golden table (``tests/golden/sig_alg_table.tsv``): every row must sign and verify with its
canonical key, and every pair of a key and the OID of another family or parameter set must raise ``BadSigAlgID``.
``cryptography`` is the independent oracle for RSA PKCS#1 v1.5 and RSASSA-PSS.
"""

import csv
import functools
import unittest
from pathlib import Path
from typing import Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from keyutils_py import (
    check_consistency_sig_alg_id_and_key,
    generate_key,
    sign_data,
    sign_with_alg_id,
    verify_signature,
    verify_signature_with_alg_id,
)
from keyutils_py.exceptions import BadAlg, BadSigAlgID, BadSigAlgIDParams
from keyutils_py.keyutils import prepare_alg_id, prepare_rsa_pss_alg_id
from keyutils_py.oids import (
    COMPOSITE_SIG_NAME_TO_OID,
    ECDSA_OID_2_NAME,
    PQ_NAME_2_OID,
    sha_alg_name_to_oid,
)
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc8017, rfc9481

DATA = b"keyutils-py sign and verify by AlgorithmIdentifier"
GOLDEN = Path(__file__).with_name("golden") / "sig_alg_table.tsv"
_HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
_STATEFUL = ("hss", "xmss", "xmssmt")


def _golden_rows() -> Dict[str, dict]:
    """Return the golden rows by name."""
    with open(GOLDEN, encoding="utf-8", newline="") as handle:
        return {row["name"]: row for row in csv.DictReader(handle, delimiter="\t")}


ROWS = _golden_rows()


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Build an ``AlgorithmIdentifier``."""
    return prepare_alg_id(univ.ObjectIdentifier(oid), value=parameters)


def _pss_alg_id(hash_name, mgf_hash_name=None, salt_length=None, trailer_field=None, omit_hash=False):
    """Build an id-RSASSA-PSS identifier by hand; a ``None`` field is omitted (the RFC 4055 3.1 DEFAULT)."""
    params = rfc4055.RSASSA_PSS_params()
    if not omit_hash:
        params["hashAlgorithm"]["algorithm"] = sha_alg_name_to_oid(hash_name)
        params["hashAlgorithm"]["parameters"] = univ.Null("")
    if mgf_hash_name is not None:
        params["maskGenAlgorithm"]["algorithm"] = rfc8017.id_mgf1
        params["maskGenAlgorithm"]["parameters"] = _alg_id(sha_alg_name_to_oid(mgf_hash_name), univ.Null(""))
    if salt_length is not None:
        params["saltLength"] = salt_length
    if trailer_field is not None:
        params["trailerField"] = trailer_field
    return _alg_id(rfc9481.id_RSASSA_PSS, univ.Any(encoder.encode(params)))


def _row_alg_id(row: dict) -> rfc5280.AlgorithmIdentifier:
    """Return a valid identifier for a golden row."""
    if row["params"] == "rsassa_pss_params":
        return prepare_rsa_pss_alg_id("sha256")
    return _alg_id(row["oid"], univ.Null("") if row["params"] == "null" else None)


@functools.lru_cache(maxsize=None)
def _shared_key(kind: str):
    """Return a key that is only used for signing without state, one per kind for the whole run."""
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return generate_key(kind)


def _key(kind: str):
    """Return a key of the kind; stateful keys are fresh each time because signing consumes state."""
    return generate_key(kind) if kind in _STATEFUL else _shared_key(kind)


def _canonical_key_kind(row: dict) -> str:
    """Return the kind of the key that belongs to a golden row."""
    if row["family"] in ("rsa", "rsa-pss"):
        return "rsa"
    if row["family"] == "ecdsa":
        return "ec"
    if row["family"] == "composite":
        return row["name"].removesuffix("-pss")
    return row["key_name"]


class TestRoundTripMatrix(unittest.TestCase):
    """Every row of the table signs and verifies with its canonical key."""

    def test_every_row_round_trips(self):
        """GIVEN each golden row / WHEN signed and verified by its identifier / THEN it verifies, a wrong one not."""
        for name, row in ROWS.items():
            if row["family"] == "dsa":
                continue
            with self.subTest(name=name):
                key = _key(_canonical_key_kind(row))
                options = {"hash_alg": "sha256"} if name == "rsa-encryption" else {}
                alg_id = _row_alg_id(row)
                signature = sign_with_alg_id(key, alg_id, DATA, **options)
                # The SHA-1 rows are only verified on request (tests/test_verify_sha1_policy.py).
                verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature, allow_sha1=True, **options)
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(
                        key.public_key(), alg_id, DATA + b"x", signature, allow_sha1=True, **options
                    )

    def test_dsa_is_refused_by_alg_id(self):
        """GIVEN a DSA key / WHEN used with id-dsa-with-sha256 / THEN BadAlg for sign and verify, as before."""
        key = generate_key("dsa")
        alg_id = _row_alg_id(ROWS["dsa-sha256"])
        with self.assertRaises(BadAlg):
            sign_with_alg_id(key, alg_id, DATA)
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(key.public_key(), alg_id, DATA, b"\x00")


_MISMATCH_KINDS = (
    "rsa",
    "ec",
    "ed25519",
    "ed448",
    "ml-dsa-44",
    "ml-dsa-65",
    "slh-dsa-sha2-128s",
    "slh-dsa-shake-128f",
    "falcon-512",
    "hss",
    "xmss",
    "xmssmt",
    "composite-sig-ml-dsa-44-ecdsa-secp256r1",
    "composite-sig-ml-dsa-44-rsa2048-pss",
    "composite-sig-ml-dsa-65-ed25519",
)


def _row_belongs_to_key(kind: str, key, row: dict) -> bool:
    """Say, from the golden row alone, whether ``key`` may be used with the row (the independent expectation)."""
    if row["family"] == "composite":
        return kind.startswith("composite-") and any(
            str(key.get_oid(use_pss=pss)) == row["oid"] for pss in (False, True)
        )
    if row["family"] in _STATEFUL:
        return kind == row["family"] and str(key.get_oid()) == row["oid"]
    return row["key_name"] == ("ecdsa" if kind == "ec" else kind if kind != "rsa" else "rsa")


class TestMismatchMatrix(unittest.TestCase):
    """A key paired with the OID of another family or parameter set raises ``BadSigAlgID``, for every family."""

    def test_every_foreign_pair_is_bad_sig_alg_id(self):
        """GIVEN every key kind and row that do not belong together / WHEN signed or verified / THEN BadSigAlgID."""
        pairs = 0
        for kind in _MISMATCH_KINDS:
            key = _key(kind)
            public_key = key.public_key()
            for name, row in ROWS.items():
                if row["family"] == "dsa" or _row_belongs_to_key(kind, key, row):
                    continue
                alg_id = _row_alg_id(row)
                pairs += 1
                with self.subTest(key=kind, oid=name):
                    with self.assertRaises(BadSigAlgID) as ctx:
                        sign_with_alg_id(key, alg_id, DATA)
                    self.assertNotIsInstance(ctx.exception, BadSigAlgIDParams)
                    with self.assertRaises(BadSigAlgID) as ctx:
                        verify_signature_with_alg_id(public_key, alg_id, DATA, b"\x00")
                    self.assertNotIsInstance(ctx.exception, BadSigAlgIDParams)
        self.assertGreater(pairs, 1000)

    def test_a_key_that_belongs_does_not_raise_bad_sig_alg_id(self):
        """GIVEN pairs that belong together / WHEN verified with a bad signature / THEN not BadSigAlgID."""
        for kind in ("rsa", "ec", "ed25519", "ml-dsa-44", "composite-sig-ml-dsa-44-rsa2048-pss"):
            key = _key(kind)
            for name, row in ROWS.items():
                if row["family"] == "dsa" or name == "rsa-encryption" or not _row_belongs_to_key(kind, key, row):
                    continue
                with self.subTest(key=kind, oid=name):
                    try:
                        verify_signature_with_alg_id(key.public_key(), _row_alg_id(row), DATA, b"\x00")
                    except BadSigAlgID as err:
                        self.fail(f"The pair belongs together but raised {err!r}")
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass  # the bad signature is rejected, with whichever error the key class raises

    def test_not_a_signature_key_is_bad_alg(self):
        """GIVEN a key agreement or KEM key / WHEN used with a signature OID / THEN BadAlg."""
        for key in (x25519.X25519PrivateKey.generate(), generate_key("ml-kem-512")):
            alg_id = _row_alg_id(ROWS["ed25519"])
            with self.subTest(key=type(key).__name__):
                with self.assertRaises(BadAlg):
                    sign_with_alg_id(key, alg_id, DATA)
                with self.assertRaises(BadAlg):
                    verify_signature_with_alg_id(key.public_key(), alg_id, DATA, b"\x00")

    def test_unknown_oid_is_bad_alg(self):
        """GIVEN an OID that is no signature OID / WHEN signing / THEN BadAlg."""
        with self.assertRaises(BadAlg):
            sign_with_alg_id(_key("rsa"), _alg_id("1.2.3.4.5.99"), DATA)

    def test_pq_key_with_other_parameter_set_or_family(self):
        """GIVEN an ML-DSA-44 key / WHEN the OID is of another parameter set or family / THEN BadSigAlgID."""
        key = _key("ml-dsa-44")
        foreign = [
            PQ_NAME_2_OID["ml-dsa-65"],
            PQ_NAME_2_OID["slh-dsa-sha2-128s"],
            rfc9481.ecdsa_with_SHA256,
            rfc9481.id_Ed25519,
            COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-ecdsa-secp256r1"],
        ]
        for oid in foreign:
            with self.subTest(oid=str(oid)):
                with self.assertRaises(BadSigAlgID):
                    sign_with_alg_id(key, _alg_id(oid), DATA)
                with self.assertRaises(BadSigAlgID):
                    verify_signature_with_alg_id(key.public_key(), _alg_id(oid), DATA, b"\x00")
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(key, _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null("")), DATA)

    def test_composite_key_with_classic_or_pq_oid(self):
        """GIVEN a composite key / WHEN the OID is ECDSA, ML-DSA, Ed25519 or another combination / THEN BadSigAlgID."""
        key = _key("composite-sig-ml-dsa-44-ecdsa-secp256r1")
        other = COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-rsa2048-pss"]
        for oid in (rfc9481.ecdsa_with_SHA256, PQ_NAME_2_OID["ml-dsa-44"], rfc9481.id_Ed25519, other):
            with self.subTest(oid=str(oid)):
                with self.assertRaises(BadSigAlgID):
                    sign_with_alg_id(key, _alg_id(oid), DATA)
                with self.assertRaises(BadSigAlgID):
                    verify_signature_with_alg_id(key.public_key(), _alg_id(oid), DATA, b"\x00")


class TestConsistencyAgreesWithSigning(unittest.TestCase):
    """``check_consistency_sig_alg_id_and_key`` accepts exactly the pairs that ``sign_with_alg_id`` accepts."""

    def test_consistency_passes_iff_the_pair_belongs_together(self):
        """GIVEN every key kind, private and public, and every row / WHEN checked / THEN BadSigAlgID iff foreign."""
        checked = 0
        for kind in _MISMATCH_KINDS:
            key = _key(kind)
            for name, row in ROWS.items():
                if row["family"] == "dsa":
                    continue
                belongs = _row_belongs_to_key(kind, key, row)
                for candidate in (key, key.public_key()):
                    checked += 1
                    with self.subTest(key=kind, oid=name, private=candidate is key):
                        if belongs:
                            check_consistency_sig_alg_id_and_key(_row_alg_id(row), candidate)
                        else:
                            with self.assertRaises(BadSigAlgID):
                                check_consistency_sig_alg_id_and_key(_row_alg_id(row), candidate)
        self.assertGreater(checked, 2000)


class TestPreHashFollowsTheOid(unittest.TestCase):
    """ML-DSA and SLH-DSA run the pre-hash mode exactly when the OID is a pre-hash OID (RFC 9881 Section 8.3)."""

    CASES = (("ml-dsa-44", "sha512"), ("ml-dsa-65", "sha512"), ("slh-dsa-sha2-128s", "sha256"))

    def test_pre_hash_oid_signs_hash_ml_dsa_and_hash_slh_dsa(self):
        """GIVEN a pre-hash OID / WHEN signed / THEN the signature verifies in pre-hash mode only."""
        for name, hash_name in self.CASES:
            with self.subTest(key=name):
                key = _key(name)
                pre_alg_id = _alg_id(PQ_NAME_2_OID[f"{name}-{hash_name}"])
                signature = sign_with_alg_id(key, pre_alg_id, DATA)
                verify_signature(key.public_key(), signature, DATA, hash_alg=hash_name)
                with self.assertRaises(InvalidSignature):
                    verify_signature(key.public_key(), signature, DATA)

    def test_pure_oid_signs_pure_mode(self):
        """GIVEN a pure OID / WHEN signed / THEN the signature verifies in pure mode only."""
        for name, hash_name in self.CASES:
            with self.subTest(key=name):
                key = _key(name)
                signature = sign_with_alg_id(key, _alg_id(PQ_NAME_2_OID[name]), DATA)
                verify_signature(key.public_key(), signature, DATA)
                with self.assertRaises(InvalidSignature):
                    verify_signature(key.public_key(), signature, DATA, hash_alg=hash_name)

    def test_genuine_pre_hash_signature_verifies_under_the_pre_hash_oid_only(self):
        """GIVEN a HashML-DSA signature / WHEN verified under the pre-hash and the pure OID / THEN only the first."""
        key = _key("ml-dsa-44")
        signature = sign_data(DATA, key, hash_alg="sha512")
        verify_signature_with_alg_id(key.public_key(), _alg_id(PQ_NAME_2_OID["ml-dsa-44-sha512"]), DATA, signature)
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(key.public_key(), _alg_id(PQ_NAME_2_OID["ml-dsa-44"]), DATA, signature)

    def test_genuine_pure_signature_is_rejected_under_the_pre_hash_oid(self):
        """GIVEN a pure ML-DSA signature / WHEN verified under the pre-hash OID / THEN InvalidSignature."""
        key = _key("ml-dsa-44")
        signature = sign_data(DATA, key)
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(key.public_key(), _alg_id(PQ_NAME_2_OID["ml-dsa-44-sha512"]), DATA, signature)


class TestCompositePssFollowsTheOid(unittest.TestCase):
    """A composite ``-pss`` OID signs RSASSA-PSS and the plain OID signs PKCS#1 v1.5."""

    def test_pss_and_pkcs1_oids_of_one_key(self):
        """GIVEN an RSA composite key and its two OIDs / WHEN signed and verified / THEN each OID picks its padding."""
        key = _key("composite-sig-ml-dsa-44-rsa2048-pss")
        pss_id = _alg_id(COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-rsa2048-pss"])
        v15_id = _alg_id(COMPOSITE_SIG_NAME_TO_OID["composite-sig-ml-dsa-44-rsa2048"])
        for alg_id, use_pss in ((pss_id, True), (v15_id, False)):
            with self.subTest(use_pss=use_pss):
                signature = sign_with_alg_id(key, alg_id, DATA)
                verify_signature(key.public_key(), signature, DATA, use_rsa_pss=use_pss)
                with self.assertRaises(InvalidSignature):
                    verify_signature(key.public_key(), signature, DATA, use_rsa_pss=not use_pss)
                self.assertEqual(sign_data(DATA, key, use_rsa_pss=use_pss) != b"", True)
                genuine = sign_data(DATA, key, use_rsa_pss=use_pss)
                verify_signature_with_alg_id(key.public_key(), alg_id, DATA, genuine)
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), v15_id if use_pss else pss_id, DATA, genuine)


class TestRsaPkcs1AndRsaEncryption(unittest.TestCase):
    """RSA PKCS#1 v1.5 by identifier: SHA-1 verifies, absent parameters are accepted, rsaEncryption takes a hash."""

    @classmethod
    def setUpClass(cls):
        """Use one RSA key."""
        cls.key = _key("rsa")
        cls.pub = cls.key.public_key()

    def test_sha1_with_rsa_signs_and_verifies(self):
        """GIVEN sha1WithRSAEncryption / WHEN a SHA-1 signature of cryptography is verified / THEN it verifies."""
        alg_id = _alg_id(rfc8017.sha1WithRSAEncryption, univ.Null(""))
        signature = self.key.sign(DATA, padding.PKCS1v15(), hashes.SHA1())
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, allow_sha1=True)
        self.pub.verify(sign_with_alg_id(self.key, alg_id, DATA), DATA, padding.PKCS1v15(), hashes.SHA1())

    def test_absent_parameters_are_accepted_in_sign_and_verify(self):
        """GIVEN sha256WithRSAEncryption without parameters / WHEN signed and verified / THEN accepted (RFC 4055 5)."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption)
        signature = sign_with_alg_id(self.key, alg_id, DATA)
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)
        self.pub.verify(signature, DATA, padding.PKCS1v15(), hashes.SHA256())

    def test_parameters_that_are_not_null_are_refused(self):
        """GIVEN sha256WithRSAEncryption with an OCTET STRING as parameters / WHEN verified / THEN BadSigAlgIDParams."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Any(encoder.encode(univ.OctetString(b"\x01"))))
        with self.assertRaises(BadSigAlgIDParams):
            sign_with_alg_id(self.key, alg_id, DATA)

    def test_rsa_encryption_with_hash_alg(self):
        """GIVEN rsaEncryption, NULL or absent / WHEN signed with hash_alg / THEN PKCS#1 v1.5 with that hash."""
        for params in (univ.Null(""), None):
            with self.subTest(parameters="NULL" if params is not None else "absent"):
                alg_id = _alg_id(rfc8017.rsaEncryption, params)
                signature = sign_with_alg_id(self.key, alg_id, DATA, hash_alg="sha384")
                self.pub.verify(signature, DATA, padding.PKCS1v15(), hashes.SHA384())
                verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, hash_alg="sha384")
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, hash_alg="sha256")

    def test_rsa_encryption_without_hash_alg_is_bad_alg(self):
        """GIVEN rsaEncryption / WHEN no hash_alg is given / THEN BadAlg, the identifier names no hash."""
        alg_id = _alg_id(rfc8017.rsaEncryption, univ.Null(""))
        with self.assertRaises(BadAlg):
            sign_with_alg_id(self.key, alg_id, DATA)
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, b"\x00")

    def test_hash_alg_contradicting_the_oid_is_bad_sig_alg_id(self):
        """GIVEN sha256WithRSAEncryption / WHEN hash_alg is sha384 / THEN BadSigAlgID; the same hash is fine."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null(""))
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(self.key, alg_id, DATA, hash_alg="sha384")
        verify_signature_with_alg_id(
            self.pub, alg_id, DATA, sign_with_alg_id(self.key, alg_id, DATA, hash_alg="sha256"), hash_alg="sha256"
        )

    def test_hash_alg_is_ignored_where_the_oid_names_no_hash(self):
        """GIVEN an Ed25519 identifier / WHEN hash_alg is given (as CMS passes the digest) / THEN it is ignored."""
        key = _key("ed25519")
        alg_id = _alg_id(rfc9481.id_Ed25519)
        signature = sign_with_alg_id(key, alg_id, DATA, hash_alg="sha512")
        verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature, hash_alg="sha512")


class TestRsaPssParametersAreHonoured(unittest.TestCase):
    """The hash and the salt length of the RSASSA-PSS parameters decide what is signed and verified."""

    @classmethod
    def setUpClass(cls):
        """Use one RSA key."""
        cls.key = _key("rsa")
        cls.pub = cls.key.public_key()

    def _pss(self, hash_name: str, salt: int) -> padding.PSS:
        return padding.PSS(mgf=padding.MGF1(_HASHES[hash_name]()), salt_length=salt)

    def test_sign_honours_hash_and_salt(self):
        """GIVEN id-RSASSA-PSS with hashes and salts 0 to 64 / WHEN signed / THEN cryptography verifies it."""
        for hash_name, salt in (("sha256", 32), ("sha384", 48), ("sha512", 64), ("sha256", 0), ("sha384", 20)):
            with self.subTest(hash=hash_name, salt=salt):
                alg_id = prepare_rsa_pss_alg_id(hash_name, salt_length=salt)
                signature = sign_with_alg_id(self.key, alg_id, DATA)
                self.pub.verify(signature, DATA, self._pss(hash_name, salt), _HASHES[hash_name]())

    def test_verify_honours_hash_and_salt(self):
        """GIVEN signatures of cryptography with salt 0, 20, 48 / WHEN verified by identifier / THEN they verify."""
        for hash_name, salt in (("sha256", 0), ("sha256", 20), ("sha384", 48), ("sha512", 64)):
            with self.subTest(hash=hash_name, salt=salt):
                signature = self.key.sign(DATA, self._pss(hash_name, salt), _HASHES[hash_name]())
                alg_id = prepare_rsa_pss_alg_id(hash_name, salt_length=salt)
                verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)

    def test_verify_with_other_salt_or_hash_fails(self):
        """GIVEN a salt 0 signature / WHEN verified with salt 32 or with sha384 / THEN InvalidSignature."""
        signature = self.key.sign(DATA, self._pss("sha256", 0), hashes.SHA256())
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(self.pub, prepare_rsa_pss_alg_id("sha256", salt_length=32), DATA, signature)
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(self.pub, prepare_rsa_pss_alg_id("sha384", salt_length=0), DATA, signature)

    def test_defaults_omitted_means_sha1_and_salt_20(self):
        """GIVEN parameters with every field omitted / WHEN signed and verified / THEN SHA-1, salt 20 (RFC 4055 3.1)."""
        alg_id = _pss_alg_id("sha1", omit_hash=True)
        signature = sign_with_alg_id(self.key, alg_id, DATA)
        self.pub.verify(signature, DATA, self._pss("sha1", 20), hashes.SHA1())
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, allow_sha1=True)

    def test_pss_parameters_as_decoded_structure(self):
        """GIVEN RSASSA-PSS-params as a structure and as Any / WHEN verified / THEN both work."""
        signature = self.key.sign(DATA, self._pss("sha256", 32), hashes.SHA256())
        as_structure = prepare_rsa_pss_alg_id("sha256")
        as_any = _alg_id(rfc9481.id_RSASSA_PSS, univ.Any(encoder.encode(as_structure["parameters"])))
        for alg_id in (as_structure, as_any):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)

    def test_mgf1_hash_differing_from_the_hash_is_refused(self):
        """GIVEN MGF1 with sha512 and hash sha256 / WHEN signed or verified / THEN BadSigAlgIDParams."""
        alg_id = prepare_rsa_pss_alg_id("sha256", mgf1_hash_alg="sha512")
        with self.assertRaises(BadSigAlgIDParams):
            sign_with_alg_id(self.key, alg_id, DATA)
        with self.assertRaises(BadSigAlgIDParams):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, b"\x00")

    def test_trailer_field_other_than_1_is_refused(self):
        """GIVEN trailerField 2 / WHEN signed or verified / THEN BadSigAlgIDParams."""
        alg_id = _pss_alg_id("sha256", "sha256", 32, trailer_field=2)
        with self.assertRaises(BadSigAlgIDParams):
            sign_with_alg_id(self.key, alg_id, DATA)
        with self.assertRaises(BadSigAlgIDParams):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, b"\x00")

    def test_pss_shake_identifiers(self):
        """GIVEN the SHAKE PSS OIDs / WHEN signed and verified / THEN they round-trip and need absent parameters."""
        for oid in (rfc9481.id_RSASSA_PSS_SHAKE128, rfc9481.id_RSASSA_PSS_SHAKE256):
            with self.subTest(oid=str(oid)):
                alg_id = _alg_id(oid)
                signature = sign_with_alg_id(self.key, alg_id, DATA)
                verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)
                with self.assertRaises(BadSigAlgIDParams):
                    sign_with_alg_id(self.key, _alg_id(oid, univ.Null("")), DATA)

    def test_pss_with_any_rsa_key(self):
        """GIVEN an RSA key (rsaEncryption SPKI) / WHEN used with id-RSASSA-PSS / THEN accepted (RFC 4055 1.2)."""
        alg_id = prepare_rsa_pss_alg_id("sha256")
        verify_signature_with_alg_id(self.pub, alg_id, DATA, sign_with_alg_id(self.key, alg_id, DATA))


class TestEcdsaByIdentifier(unittest.TestCase):
    """ECDSA identifiers carry the hash; the parameters must be absent."""

    def test_hash_comes_from_the_oid(self):
        """GIVEN ecdsa-with-SHA384 / WHEN signed / THEN cryptography verifies SHA-384, not SHA-256."""
        key = _key("ec")
        alg_id = _alg_id(rfc9481.ecdsa_with_SHA384)
        signature = sign_with_alg_id(key, alg_id, DATA)
        key.public_key().verify(signature, DATA, ec.ECDSA(hashes.SHA384()))
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(signature, DATA, ec.ECDSA(hashes.SHA256()))

    def test_every_ecdsa_oid_is_in_the_table(self):
        """GIVEN the ECDSA OID table / WHEN each OID is used by a P-256 key / THEN it signs and verifies."""
        key = _key("ec")
        for oid, name in ECDSA_OID_2_NAME.items():
            with self.subTest(name=name):
                alg_id = _alg_id(oid)
                verify_signature_with_alg_id(key.public_key(), alg_id, DATA, sign_with_alg_id(key, alg_id, DATA))


if __name__ == "__main__":
    unittest.main()
