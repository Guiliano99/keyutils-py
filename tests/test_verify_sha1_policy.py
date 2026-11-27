# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SHA-1 policy of ``verify_signature_with_alg_id``.

Verification is a trust decision, so SHA-1 is refused unless the caller opts in with ``allow_sha1=True``. Signing is
not restricted: a conformance suite has to produce SHA-1 material, and ``cryptography`` is the oracle for the bytes.
"""

import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from keyutils_py import sign_with_alg_id, verify_signature, verify_signature_with_alg_id
from keyutils_py.exceptions import BadAlg, BadSigAlgID
from keyutils_py.keyutils import prepare_alg_id, prepare_rsa_pss_alg_id
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc8017, rfc9481

DATA = b"keyutils-py SHA-1 verification policy"


def _alg_id(oid, parameters=None):
    """Build an ``AlgorithmIdentifier``."""
    return prepare_alg_id(univ.ObjectIdentifier(oid), value=parameters)


def _pss_defaults_alg_id():
    """Build id-RSASSA-PSS with every field omitted, which means SHA-1, MGF1 with SHA-1, salt 20 (RFC 4055 3.1)."""
    params = rfc4055.RSASSA_PSS_params()
    return _alg_id(rfc9481.id_RSASSA_PSS, univ.Any(encoder.encode(params)))


class TestSha1IsRefusedByDefault(unittest.TestCase):
    """A SHA-1 signature is refused for every RSA identifier that names SHA-1, whoever made it."""

    @classmethod
    def setUpClass(cls):
        """Use one RSA key."""
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub = cls.key.public_key()

    def _pkcs1_sha1(self):
        return _alg_id(rfc8017.sha1WithRSAEncryption, univ.Null("")), self.key.sign(
            DATA, padding.PKCS1v15(), hashes.SHA1()
        )

    def test_sha1_with_rsa_is_refused(self):
        """GIVEN a genuine sha1WithRSAEncryption signature / WHEN verified by default / THEN BadAlg."""
        alg_id, signature = self._pkcs1_sha1()
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)

    def test_sha1_with_rsa_is_verified_on_request(self):
        """GIVEN the same signature / WHEN verified with allow_sha1=True / THEN it verifies, a bad one does not."""
        alg_id, signature = self._pkcs1_sha1()
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, allow_sha1=True)
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, b"\x00" * len(signature), allow_sha1=True)

    def test_pss_with_sha1_is_refused_and_verified_on_request(self):
        """GIVEN an RSASSA-PSS signature with SHA-1 / WHEN verified / THEN refused by default, verified on request."""
        alg_id = prepare_rsa_pss_alg_id("sha1", salt_length=20)
        signature = self.key.sign(
            DATA, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=20), hashes.SHA1()
        )
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, allow_sha1=True)

    def test_pss_with_the_rfc_4055_defaults_is_refused_and_verified_on_request(self):
        """GIVEN RSASSA-PSS parameters that omit every field (SHA-1) / WHEN verified / THEN same policy."""
        alg_id = _pss_defaults_alg_id()
        signature = self.key.sign(
            DATA, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=20), hashes.SHA1()
        )
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, allow_sha1=True)

    def test_rsa_encryption_with_sha1_hash_alg_is_refused_and_verified_on_request(self):
        """GIVEN rsaEncryption with hash_alg='sha1' / WHEN verified / THEN refused by default, verified on request."""
        alg_id = _alg_id(rfc8017.rsaEncryption, univ.Null(""))
        _, signature = self._pkcs1_sha1()
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, hash_alg="sha1")
        verify_signature_with_alg_id(self.pub, alg_id, DATA, signature, hash_alg="sha1", allow_sha1=True)

    def test_refusal_names_the_way_out(self):
        """GIVEN a refused SHA-1 signature / WHEN the error is read / THEN it names allow_sha1."""
        alg_id, signature = self._pkcs1_sha1()
        with self.assertRaisesRegex(BadAlg, "allow_sha1"):
            verify_signature_with_alg_id(self.pub, alg_id, DATA, signature)

    def test_key_mismatch_is_reported_before_the_policy(self):
        """GIVEN an RSA SHA-1 identifier and an EC key / WHEN verified / THEN BadSigAlgID, not the SHA-1 refusal."""
        alg_id, signature = self._pkcs1_sha1()
        ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(BadSigAlgID):
            verify_signature_with_alg_id(ec_pub, alg_id, DATA, signature)


class TestSha2AndSigningAreUnaffected(unittest.TestCase):
    """The policy covers SHA-1 verification by identifier only."""

    @classmethod
    def setUpClass(cls):
        """Use one RSA key."""
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub = cls.key.public_key()

    def test_sha256_verifies_by_default(self):
        """GIVEN SHA-256 PKCS#1 v1.5 and PSS / WHEN verified without allow_sha1 / THEN they verify."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null(""))
        verify_signature_with_alg_id(self.pub, alg_id, DATA, sign_with_alg_id(self.key, alg_id, DATA))
        pss_id = prepare_rsa_pss_alg_id("sha256")
        verify_signature_with_alg_id(self.pub, pss_id, DATA, sign_with_alg_id(self.key, pss_id, DATA))

    def test_allow_sha1_does_not_loosen_anything_else(self):
        """GIVEN allow_sha1=True / WHEN a SHA-256 signature is checked against SHA-384 / THEN InvalidSignature."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null(""))
        signature = sign_with_alg_id(self.key, alg_id, DATA)
        wrong_id = _alg_id(rfc9481.sha384WithRSAEncryption, univ.Null(""))
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(self.pub, wrong_id, DATA, signature, allow_sha1=True)

    def test_signing_with_sha1_is_not_restricted(self):
        """GIVEN sha1WithRSAEncryption / WHEN signed by identifier / THEN cryptography verifies the SHA-1 signature."""
        alg_id = _alg_id(rfc8017.sha1WithRSAEncryption, univ.Null(""))
        signature = sign_with_alg_id(self.key, alg_id, DATA)
        self.pub.verify(signature, DATA, padding.PKCS1v15(), hashes.SHA1())

    def test_verifying_by_name_is_not_restricted(self):
        """GIVEN a SHA-1 signature / WHEN verified by name with hash_alg='sha1' / THEN it verifies (caller names it)."""
        signature = self.key.sign(DATA, padding.PKCS1v15(), hashes.SHA1())
        verify_signature(self.pub, signature, DATA, hash_alg="sha1")


if __name__ == "__main__":
    unittest.main()
