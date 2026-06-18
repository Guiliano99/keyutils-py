# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""ECDSA / EdDSA sign & verify: alg_id path, generic dispatch, strict OID binding."""

import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5480, rfc8017, rfc9480, rfc9481, rfc9688

from keyutils_py import (
    sign_data,
    sign_with_alg_id,
    verify_signature,
    verify_signature_with_alg_id,
)
from keyutils_py.exceptions import BadAlg, BadSigAlgID, BadSigAlgIDParams
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keyutils import prepare_sig_alg_id, validate_sig_alg_id


def _alg_id(oid, parameters=None) -> rfc9480.AlgorithmIdentifier:
    """Build an ``AlgorithmIdentifier`` from a raw OID + optional parameters."""
    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if parameters is not None:
        alg_id["parameters"] = parameters
    return alg_id


class TestEcdsaAlgId(unittest.TestCase):
    """sign_with_alg_id / verify_signature_with_alg_id round-trips for ECDSA."""

    def _round_trip(self, curve, oid, native_hash):
        """Sign + verify via the alg_id API and confirm cryptography accepts the DER signature."""
        key = ec.generate_private_key(curve)
        alg_id = _alg_id(oid)
        msg = b"ecdsa alg-id round trip"
        sig = sign_with_alg_id(key, alg_id, msg)
        verify_signature_with_alg_id(key.public_key(), alg_id, msg, sig)
        # keyutils-py emits DER ECDSA signatures; cryptography must accept them too.
        key.public_key().verify(sig, msg, ec.ECDSA(native_hash))
        return key, alg_id, msg, sig

    def test_p256_sha256(self):
        """GIVEN P-256 + ecdsa-with-SHA256 / WHEN sign→verify / THEN succeeds."""
        self._round_trip(ec.SECP256R1(), rfc9481.ecdsa_with_SHA256, hashes.SHA256())

    def test_p384_sha384(self):
        """GIVEN P-384 + ecdsa-with-SHA384 / WHEN sign→verify / THEN succeeds."""
        self._round_trip(ec.SECP384R1(), rfc9481.ecdsa_with_SHA384, hashes.SHA384())

    def test_p521_sha512(self):
        """GIVEN P-521 + ecdsa-with-SHA512 / WHEN sign→verify / THEN succeeds."""
        self._round_trip(ec.SECP521R1(), rfc9481.ecdsa_with_SHA512, hashes.SHA512())

    def test_p256_sha3_256(self):
        """GIVEN P-256 + ecdsa-with-SHA3-256 / WHEN sign→verify / THEN succeeds."""
        self._round_trip(ec.SECP256R1(), rfc9688.id_ecdsa_with_sha3_256, hashes.SHA3_256())

    def test_p256_shake256(self):
        """GIVEN P-256 + ecdsa-with-SHAKE256 / WHEN sign→verify / THEN succeeds (512-bit digest)."""
        self._round_trip(ec.SECP256R1(), rfc9481.id_ecdsa_with_shake256, hashes.SHAKE256(64))

    def test_tampered_signature_rejected(self):
        """GIVEN a valid ECDSA signature / WHEN a byte is flipped / THEN InvalidSignature."""
        key, alg_id, msg, sig = self._round_trip(ec.SECP256R1(), rfc9481.ecdsa_with_SHA256, hashes.SHA256())
        tampered = bytearray(sig)
        tampered[-1] ^= 0x01
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(key.public_key(), alg_id, msg, bytes(tampered))

    def test_wrong_key_rejected(self):
        """GIVEN a signature from one key / WHEN verified with another / THEN InvalidSignature."""
        _, alg_id, msg, sig = self._round_trip(ec.SECP256R1(), rfc9481.ecdsa_with_SHA256, hashes.SHA256())
        other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(other.public_key(), alg_id, msg, sig)

    def test_params_present_rejected(self):
        """GIVEN an ECDSA alg_id with parameters set / WHEN signing / THEN BadSigAlgIDParams (RFC 5758 §3.2)."""
        key = ec.generate_private_key(ec.SECP256R1())
        alg_id = _alg_id(rfc9481.ecdsa_with_SHA256, univ.Null(""))
        with self.assertRaises(BadSigAlgIDParams):
            sign_with_alg_id(key, alg_id, b"data")


class TestEddsaAlgId(unittest.TestCase):
    """sign_with_alg_id / verify_signature_with_alg_id round-trips for EdDSA."""

    def test_ed25519_round_trip(self):
        """GIVEN Ed25519 + id-Ed25519 / WHEN sign→verify / THEN succeeds."""
        key = ed25519.Ed25519PrivateKey.generate()
        alg_id = _alg_id(rfc9481.id_Ed25519)
        msg = b"ed25519 alg-id round trip"
        sig = sign_with_alg_id(key, alg_id, msg)
        verify_signature_with_alg_id(key.public_key(), alg_id, msg, sig)
        key.public_key().verify(sig, msg)

    def test_ed448_round_trip(self):
        """GIVEN Ed448 + id-Ed448 / WHEN sign→verify / THEN succeeds."""
        key = ed448.Ed448PrivateKey.generate()
        alg_id = _alg_id(rfc9481.id_Ed448)
        msg = b"ed448 alg-id round trip"
        sig = sign_with_alg_id(key, alg_id, msg)
        verify_signature_with_alg_id(key.public_key(), alg_id, msg, sig)
        key.public_key().verify(sig, msg)

    def test_ed25519_tampered_rejected(self):
        """GIVEN a valid Ed25519 signature / WHEN a byte is flipped / THEN InvalidSignature."""
        key = ed25519.Ed25519PrivateKey.generate()
        alg_id = _alg_id(rfc9481.id_Ed25519)
        msg = b"ed25519"
        tampered = bytearray(sign_with_alg_id(key, alg_id, msg))
        tampered[0] ^= 0x01
        with self.assertRaises(InvalidSignature):
            verify_signature_with_alg_id(key.public_key(), alg_id, msg, bytes(tampered))


class TestStrictOidKeyBinding(unittest.TestCase):
    """The core fix: a key may only be used with an OID from its own algorithm family."""

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_ec_key_with_rsa_oid_raises(self):
        """GIVEN an EC key + an RSA OID / WHEN signing / THEN BadSigAlgID (no silent ECDSA signature)."""
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(key, _alg_id(rfc9481.sha256WithRSAEncryption), b"data")

    def test_ec_key_with_ed25519_oid_raises(self):
        """GIVEN an EC key + an Ed25519 OID / WHEN signing / THEN BadSigAlgID (no IndexError)."""
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(key, _alg_id(rfc9481.id_Ed25519), b"data")

    def test_rsa_key_with_ecdsa_oid_raises(self):
        """GIVEN an RSA key + an ECDSA OID / WHEN signing / THEN BadSigAlgID (mirror defect)."""
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(self.rsa_key, _alg_id(rfc9481.ecdsa_with_SHA256), b"data")

    def test_ed25519_key_with_ed448_oid_raises(self):
        """GIVEN an Ed25519 key + an Ed448 OID / WHEN signing / THEN BadSigAlgID."""
        key = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(key, _alg_id(rfc9481.id_Ed448), b"data")

    def test_verify_ec_key_with_rsa_oid_raises(self):
        """GIVEN an EC public key + an RSA OID / WHEN verifying / THEN BadSigAlgID."""
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(BadSigAlgID):
            verify_signature_with_alg_id(key.public_key(), _alg_id(rfc9481.sha256WithRSAEncryption), b"data", b"\x00")

    def test_verify_rsa_key_with_sha1_oid_raises_badalg(self):
        """GIVEN an RSA key + rsa-sha1 OID (NULL params) / WHEN verifying / THEN BadAlg (SHA-1 rejected)."""
        alg_id = _alg_id(rfc8017.sha1WithRSAEncryption, univ.Null(""))
        with self.assertRaises(BadAlg):
            verify_signature_with_alg_id(self.rsa_key.public_key(), alg_id, b"data", b"\x00")

    def test_sign_ec_key_with_rsa_pss_oid_raises_sig_alg_id(self):
        """GIVEN an EC key + a RSASSA-PSS OID / WHEN signing / THEN BadSigAlgID (family mismatch, not BadAlg)."""
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(BadSigAlgID):
            sign_with_alg_id(key, _alg_id(rfc9481.id_RSASSA_PSS_SHAKE256), b"data")

    def test_verify_ec_key_with_rsa_pss_oid_raises_sig_alg_id(self):
        """GIVEN an EC public key + a RSASSA-PSS OID / WHEN verifying / THEN BadSigAlgID (family mismatch)."""
        key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(BadSigAlgID):
            verify_signature_with_alg_id(key.public_key(), _alg_id(rfc9481.id_RSASSA_PSS_SHAKE256), b"data", b"\x00")


class TestGenericDispatch(unittest.TestCase):
    """sign_data / verify_signature now cover EC (hashed) and EdDSA keys directly."""

    def test_ec_default_hash(self):
        """GIVEN an EC key / WHEN sign_data with no hash_alg / THEN ECDSA-SHA256 round-trips."""
        key = ec.generate_private_key(ec.SECP256R1())
        msg = b"generic ecdsa default"
        sig = sign_data(msg, key)
        verify_signature(key.public_key(), sig, msg)
        key.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))

    def test_ec_explicit_hash(self):
        """GIVEN an EC key + hash_alg=sha384 / WHEN sign_data→verify_signature / THEN round-trips."""
        key = ec.generate_private_key(ec.SECP384R1())
        msg = b"generic ecdsa sha384"
        sig = sign_data(msg, key, hash_alg="sha384")
        verify_signature(key.public_key(), sig, msg, hash_alg="sha384")
        key.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA384()))

    def test_ec_tampered_rejected(self):
        """GIVEN a generic EC signature / WHEN a byte is flipped / THEN InvalidSignature."""
        key = ec.generate_private_key(ec.SECP256R1())
        msg = b"generic ecdsa"
        tampered = bytearray(sign_data(msg, key))
        tampered[-1] ^= 0x01
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), bytes(tampered), msg)

    def test_ed25519_round_trip(self):
        """GIVEN an Ed25519 key / WHEN sign_data→verify_signature / THEN round-trips."""
        key = ed25519.Ed25519PrivateKey.generate()
        msg = b"generic ed25519"
        sig = sign_data(msg, key)
        verify_signature(key.public_key(), sig, msg)

    def test_ed448_round_trip(self):
        """GIVEN an Ed448 key / WHEN sign_data→verify_signature / THEN round-trips."""
        key = ed448.Ed448PrivateKey.generate()
        msg = b"generic ed448"
        sig = sign_data(msg, key)
        verify_signature(key.public_key(), sig, msg)


class TestDsaSign(unittest.TestCase):
    """DSA is sign-only: produced via sign_data, rejected by sign_with_alg_id.

    The public ``generate_key`` does not cover traditional-only keys, so the DSA
    key is generated through ``TradKeyFactory`` (the trad key-generation entry).
    """

    key: dsa.DSAPrivateKey

    @classmethod
    def setUpClass(cls):
        key = TradKeyFactory.generate_trad_key("dsa")
        assert isinstance(key, dsa.DSAPrivateKey)
        cls.key = key

    def test_sign_data_native_verify(self):
        """GIVEN a generated DSA key / WHEN sign_data / THEN cryptography verifies it natively."""
        msg = b"dsa sign+verify"
        sig = sign_data(msg, self.key)
        # The library only signs DSA; verify with cryptography's native DSA verify.
        self.key.public_key().verify(sig, msg, hashes.SHA256())

    def test_sign_data_explicit_hash(self):
        """GIVEN a DSA key + hash_alg=sha384 / WHEN sign_data / THEN native verify with SHA384."""
        msg = b"dsa sha384"
        sig = sign_data(msg, self.key, hash_alg="sha384")
        self.key.public_key().verify(sig, msg, hashes.SHA384())

    def test_sign_data_tampered_rejected(self):
        """GIVEN a DSA signature / WHEN a byte is flipped / THEN native verify raises InvalidSignature."""
        msg = b"dsa tamper"
        tampered = bytearray(sign_data(msg, self.key))
        tampered[-1] ^= 0x01
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(bytes(tampered), msg, hashes.SHA256())

    def test_prepare_sig_alg_id_builds_dsa_alg_id(self):
        """GIVEN a DSA key / WHEN prepare_sig_alg_id / THEN id-dsa-with-sha256 with absent params that validates."""
        alg_id = prepare_sig_alg_id(self.key)
        self.assertEqual(alg_id["algorithm"], rfc5480.id_dsa_with_sha256)
        self.assertFalse(alg_id["parameters"].isValue)  # DSA parameters are absent (RFC 5758)
        validate_sig_alg_id(alg_id)  # recognised and valid (no exception)

    def test_sign_with_alg_id_rejects_dsa(self):
        """GIVEN a DSA key + its prepare_sig_alg_id output / WHEN sign_with_alg_id / THEN BadAlg (unsupported)."""
        alg_id = prepare_sig_alg_id(self.key)
        with self.assertRaises(BadAlg) as cm:
            sign_with_alg_id(self.key, alg_id, b"data")
        self.assertIn("DSA algorithm is not supported", str(cm.exception))

    def test_verify_with_alg_id_rejects_dsa_consistently(self):
        """GIVEN a DSA public key / WHEN verify_signature_with_alg_id / THEN the SAME BadAlg as the sign path."""
        alg_id = prepare_sig_alg_id(self.key)
        with self.assertRaises(BadAlg) as cm:
            verify_signature_with_alg_id(self.key.public_key(), alg_id, b"data", b"\x00")
        self.assertIn("DSA algorithm is not supported", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
