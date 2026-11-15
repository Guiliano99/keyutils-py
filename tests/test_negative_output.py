# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Every deviation that a negative test of the cmp-test-suite performs can be produced with explicit calls.

The functions that sign and verify by ``AlgorithmIdentifier`` are strict: they never sign or verify a mismatch. So a
deviation is made from a valid pair, by editing the structure afterwards or by the by-name pair (``sign_data`` and
``prepare_sig_alg_id`` do not look at each other), and the result must be refused the way a verifier refuses it. One
test per deviation; each starts from a valid pair and shows that it is valid before it is spoiled.
"""

import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from keyutils_py import (
    BadAlg,
    BadSigAlgID,
    BadSigAlgIDParams,
    check_consistency_sig_alg_id_and_key,
    generate_key,
    get_sig_alg_info,
    manipulate_pq_stateful_signature_bytes,
    manipulate_sig_based_on_key,
    prepare_hash_alg_id,
    prepare_sig_alg_id,
    sign_data,
    sign_with_alg_id,
    validate_sig_alg_id,
    verify_signature,
    verify_signature_with_alg_id,
)
from keyutils_py.keyutils import prepare_alg_id, prepare_rsa_pss_alg_id
from keyutils_py.oids import PQ_NAME_2_OID
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc8017, rfc9481

DATA = b"to be signed bytes"


class _KeysTestCase(unittest.TestCase):
    """Test case with one key of each family that the deviations are made with."""

    @classmethod
    def setUpClass(cls):
        """Generate the keys once."""
        cls.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec = ec.generate_private_key(ec.SECP256R1())
        cls.other_ec = ec.generate_private_key(ec.SECP256R1())
        cls.ed25519 = generate_key("ed25519")
        cls.ml_dsa = generate_key("ml-dsa-44")
        cls.other_ml_dsa = generate_key("ml-dsa-44")
        cls.slh_dsa = generate_key("slh-dsa-sha2-128s")
        cls.composite = generate_key("composite-sig-ml-dsa-44-ecdsa-secp256r1")
        cls.composite_rsa = generate_key("composite-sig-ml-dsa-44-rsa2048-pss")

    def _valid_pairs(self):
        """Return ``(label, key)`` for the families whose pure signatures every mutation must break."""
        return (
            ("rsa", self.rsa),
            ("ecdsa", self.ec),
            ("ed25519", self.ed25519),
            ("ml-dsa", self.ml_dsa),
            ("slh-dsa", self.slh_dsa),
            ("composite", self.composite),
        )


class TestSignatureValueDeviations(_KeysTestCase):
    """The value of the signature is wrong: flipped, longer, shorter, last bit, omitted, other state."""

    def test_first_byte_flipped(self):
        """GIVEN a valid signature / WHEN its first byte is flipped by manipulate_sig_based_on_key / THEN invalid."""
        for label, key in self._valid_pairs():
            with self.subTest(key=label):
                alg_id = prepare_sig_alg_id(key)
                signature = sign_with_alg_id(key, alg_id, DATA)
                verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)
                bad = manipulate_sig_based_on_key(signature, key)
                self.assertNotEqual(bad, signature)
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), alg_id, DATA, bad)

    def test_trailing_bytes_truncation_last_bit_and_empty(self):
        """GIVEN a valid signature / WHEN bytes are added, cut, the last bit flipped or all dropped / THEN invalid."""
        for label, key in self._valid_pairs():
            alg_id = prepare_sig_alg_id(key)
            signature = sign_with_alg_id(key, alg_id, DATA)
            spoiled = {
                "trailing bytes": signature + b"AA",
                "truncated": signature[:-1],
                "last bit": signature[:-1] + bytes([signature[-1] ^ 0x01]),
                "omitted": b"",
            }
            for how, bad in spoiled.items():
                with self.subTest(key=label, how=how), self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), alg_id, DATA, bad)

    def test_stateful_signature_payload(self):
        """GIVEN a valid HSS signature / WHEN the payload is changed by the stateful mutator / THEN invalid."""
        key = generate_key("hss")
        alg_id = prepare_sig_alg_id(key)
        signature = sign_with_alg_id(key, alg_id, DATA)
        verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)
        bad = manipulate_pq_stateful_signature_bytes(signature, key, manipulate_sig=True)
        self.assertNotEqual(bad, signature)
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(key.public_key(), alg_id, DATA, bad)

    def test_signature_over_the_wrong_bytes(self):
        """GIVEN a signature over other bytes / WHEN verified over the message / THEN invalid."""
        for label, key in self._valid_pairs():
            with self.subTest(key=label):
                alg_id = prepare_sig_alg_id(key)
                signature = sign_with_alg_id(key, alg_id, DATA + b"other")
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)

    def test_signed_by_another_key_than_the_identifier_says(self):
        """GIVEN a signature of another key / WHEN verified with the key of the identifier / THEN invalid."""
        for key, other in ((self.rsa, self.other_rsa), (self.ec, self.other_ec), (self.ml_dsa, self.other_ml_dsa)):
            with self.subTest(key=type(key).__name__):
                alg_id = prepare_sig_alg_id(key)
                signature = sign_with_alg_id(other, prepare_sig_alg_id(other), DATA)
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)

    def test_context_differs(self):
        """GIVEN a signature with a context / WHEN verified without it or with another / THEN invalid."""
        for label, key in (("ml-dsa", self.ml_dsa), ("slh-dsa", self.slh_dsa), ("composite", self.composite)):
            with self.subTest(key=label):
                signature = sign_data(DATA, key, ctx=b"context")
                verify_signature(key.public_key(), signature, DATA, ctx=b"context")
                with self.assertRaises(InvalidSignature):
                    verify_signature(key.public_key(), signature, DATA, ctx=b"other")
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), prepare_sig_alg_id(key), DATA, signature)


class TestIdentifierDeviations(_KeysTestCase):
    """The identifier is wrong: random or NULL parameters, other hash, other OID, unknown OID, broken PSS."""

    def test_random_bytes_in_the_parameters(self):
        """GIVEN a valid identifier / WHEN its parameters are replaced by random bytes / THEN BadSigAlgIDParams."""
        for label, key in self._valid_pairs():
            with self.subTest(key=label):
                alg_id = prepare_sig_alg_id(key)
                signature = sign_with_alg_id(key, alg_id, DATA)
                alg_id["parameters"] = prepare_alg_id(alg_id["algorithm"], fill_random_params=True)["parameters"]
                with self.assertRaises(BadSigAlgIDParams):
                    validate_sig_alg_id(alg_id)
                with self.assertRaises(BadSigAlgIDParams):
                    verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)
        self.assertTrue(prepare_hash_alg_id("sha256", fill_random_params=True)["parameters"].isValue)

    def test_null_where_the_parameters_must_be_absent(self):
        """GIVEN an ECDSA, EdDSA or ML-DSA identifier / WHEN NULL is added as parameters / THEN BadSigAlgIDParams."""
        for label, key in (("ecdsa", self.ec), ("ed25519", self.ed25519), ("ml-dsa", self.ml_dsa)):
            with self.subTest(key=label):
                alg_id = prepare_sig_alg_id(key)
                alg_id["parameters"] = univ.Null("")
                for strict in (True, False):
                    with self.assertRaises(BadSigAlgIDParams):
                        validate_sig_alg_id(alg_id, strict=strict)
                with self.assertRaises(BadSigAlgIDParams):
                    sign_with_alg_id(key, alg_id, DATA)

    def test_variants_that_verifiers_must_tolerate(self):
        """GIVEN PKCS#1 without NULL, rsaEncryption and SHA-2 ids with or without NULL / WHEN built / THEN accepted."""
        absent = prepare_alg_id(rfc9481.sha256WithRSAEncryption)
        signature = sign_with_alg_id(self.rsa, absent, DATA)
        verify_signature_with_alg_id(self.rsa.public_key(), absent, DATA, signature)
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(absent)

        rsa_encryption = prepare_alg_id(rfc8017.rsaEncryption, value=univ.Null(""))
        signature = sign_with_alg_id(self.rsa, rsa_encryption, DATA, hash_alg="sha256")
        verify_signature_with_alg_id(self.rsa.public_key(), rsa_encryption, DATA, signature, hash_alg="sha256")

        self.assertTrue(prepare_hash_alg_id("sha256", with_null=True)["parameters"].isValue)
        self.assertFalse(prepare_hash_alg_id("sha256", with_null=False)["parameters"].isValue)

    def test_hash_of_the_identifier_differs_from_the_hash_signed(self):
        """GIVEN a SHA-256 signature / WHEN the id says SHA-384 / THEN invalid; pure ML-DSA under a pre-hash OID too."""
        for label, key in (("rsa", self.rsa), ("ecdsa", self.ec)):
            with self.subTest(key=label):
                signature = sign_data(DATA, key, hash_alg="sha256")
                verify_signature(key.public_key(), signature, DATA, hash_alg="sha256")
                wire = prepare_sig_alg_id(key, "sha384")
                with self.assertRaises(InvalidSignature):
                    verify_signature_with_alg_id(key.public_key(), wire, DATA, signature)
        pure = sign_with_alg_id(self.ml_dsa, prepare_sig_alg_id(self.ml_dsa), DATA)
        pre_hash_id = prepare_sig_alg_id(self.ml_dsa, "sha512")
        self.assertTrue(get_sig_alg_info(pre_hash_id).pre_hash)
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(self.ml_dsa.public_key(), pre_hash_id, DATA, pure)

    def test_oid_of_another_family_parameter_set_or_padding(self):
        """GIVEN a valid pair / WHEN the identifier of another key replaces it / THEN BadSigAlgID, for every family."""
        keys = dict(self._valid_pairs())
        for label, key in keys.items():
            signature = sign_with_alg_id(key, prepare_sig_alg_id(key), DATA)
            for other_label, other in keys.items():
                if other_label == label:
                    continue
                with self.subTest(key=label, oid_of=other_label):
                    wire = prepare_sig_alg_id(other)
                    with self.assertRaises(BadSigAlgID):
                        verify_signature_with_alg_id(key.public_key(), wire, DATA, signature)
                    with self.assertRaises(BadSigAlgID):
                        check_consistency_sig_alg_id_and_key(wire, key.public_key())
        other_set = rfc5280.AlgorithmIdentifier()
        other_set["algorithm"] = PQ_NAME_2_OID["ml-dsa-65"]
        with self.assertRaises(BadSigAlgID):
            verify_signature_with_alg_id(self.ml_dsa.public_key(), other_set, DATA, b"\x00")

    def test_composite_pss_oid_with_a_pkcs1_signature(self):
        """GIVEN a composite PKCS#1 v1.5 signature / WHEN verified under the -pss OID / THEN invalid, and vice versa."""
        key = self.composite_rsa
        v15_id, pss_id = prepare_sig_alg_id(key), prepare_sig_alg_id(key, use_rsa_pss=True)
        self.assertNotEqual(v15_id["algorithm"], pss_id["algorithm"])
        v15_signature = sign_with_alg_id(key, v15_id, DATA)
        pss_signature = sign_with_alg_id(key, pss_id, DATA)
        for alg_id, signature in ((pss_id, v15_signature), (v15_id, pss_signature)):
            with self.assertRaises(InvalidSignature):
                verify_signature_with_alg_id(key.public_key(), alg_id, DATA, signature)

    def test_unknown_oid(self):
        """GIVEN a valid identifier / WHEN its OID is replaced by an unknown one / THEN BadAlg."""
        alg_id = prepare_sig_alg_id(self.ec)
        signature = sign_with_alg_id(self.ec, alg_id, DATA)
        alg_id["algorithm"] = univ.ObjectIdentifier("1.2.3.4.5.6.7.8")
        with self.assertRaises(BadAlg):
            validate_sig_alg_id(alg_id)
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.ec.public_key(), alg_id, DATA, signature)
        with self.assertRaises(BadAlg):
            sign_with_alg_id(self.ec, alg_id, DATA)

    def test_pss_salt_mgf1_hash_hash_and_structure_altered(self):
        """GIVEN a PSS signature / WHEN salt, MGF1 hash or hash of the identifier change or break / THEN refused."""
        signature = sign_with_alg_id(self.rsa, prepare_rsa_pss_alg_id("sha256", salt_length=32), DATA)
        public_key = self.rsa.public_key()
        for how, alg_id in (
            ("salt 0", prepare_rsa_pss_alg_id("sha256", salt_length=0)),
            ("salt 20", prepare_rsa_pss_alg_id("sha256", salt_length=20)),
            ("sha384", prepare_rsa_pss_alg_id("sha384", salt_length=32)),
        ):
            with self.subTest(how=how), self.assertRaises(InvalidSignature):
                verify_signature_with_alg_id(public_key, alg_id, DATA, signature)
        with self.assertRaises(BadSigAlgIDParams):
            verify_signature_with_alg_id(
                public_key, prepare_rsa_pss_alg_id("sha256", mgf1_hash_alg="sha512"), DATA, signature
            )
        broken = prepare_rsa_pss_alg_id("sha256")
        broken["parameters"] = univ.Any(b"\x04\x01\x00")
        with self.assertRaises(BadSigAlgIDParams):
            verify_signature_with_alg_id(public_key, broken, DATA, signature)
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(broken)

    def test_two_different_identifiers_for_one_signature(self):
        """GIVEN an id for the TBS part and another for the outer part / WHEN built / THEN both valid, different."""
        inner = prepare_sig_alg_id(self.rsa, "sha256")
        outer = prepare_sig_alg_id(self.rsa, "sha512")
        validate_sig_alg_id(inner)
        validate_sig_alg_id(outer)
        self.assertNotEqual(inner["algorithm"], outer["algorithm"])

    def test_identifier_left_out(self):
        """GIVEN an AlgorithmIdentifier without an OID / WHEN used / THEN BadAlg, not a pyasn1 error."""
        empty = rfc5280.AlgorithmIdentifier()
        with self.assertRaises(BadAlg):
            get_sig_alg_info(empty)
        with self.assertRaises(BadAlg):
            validate_sig_alg_id(empty)
        with self.assertRaises(BadAlg):
            sign_with_alg_id(self.rsa, empty, DATA)
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(empty, self.rsa)


class TestLegacyButValid(_KeysTestCase):
    """RSA with SHA-1 and DSA are valid output that a suite must still be able to produce and judge."""

    def test_rsa_sha1_signs_and_verifies(self):
        """GIVEN an RSA key and SHA-1 / WHEN signed and verified by identifier / THEN valid; the hash is readable."""
        alg_id = prepare_sig_alg_id(self.rsa, "sha1")
        self.assertEqual(get_sig_alg_info(alg_id).hash_alg, "sha1")
        signature = sign_with_alg_id(self.rsa, alg_id, DATA)
        verify_signature_with_alg_id(self.rsa.public_key(), alg_id, DATA, signature, allow_sha1=True)

    def test_dsa_is_signed_by_name_and_its_identifier_is_valid(self):
        """GIVEN a DSA key / WHEN signed by name with the prepared identifier / THEN valid; by identifier BadAlg."""
        key = generate_key("dsa")
        alg_id = prepare_sig_alg_id(key)
        validate_sig_alg_id(alg_id)
        signature = sign_data(DATA, key, hash_alg=get_sig_alg_info(alg_id).hash_alg)
        verify_signature(key.public_key(), signature, DATA, hash_alg="sha256")
        with self.assertRaises(BadAlg):
            sign_with_alg_id(key, alg_id, DATA)


if __name__ == "__main__":
    unittest.main()
