# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for RSA-PSS sign/verify, prepare_rsa_pss_alg_id, and prepare_spki."""

import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc9481

from keyutils_py import (
    generate_key,
    prepare_spki,
    sign_data,
    sign_with_alg_id,
    verify_signature_with_alg_id,
)
from keyutils_py.compute import (
    sign_data_rsa_pss,
    verify_rsassa_pss_from_alg_id,
)
from keyutils_py.keyutils import prepare_rsa_pss_alg_id
from keyutils_py.keyutils import prepare_subject_public_key_info
from keyutils_py.enums import SigAlgParametersSpec
from keyutils_py.keyutils import (
    decode_alg_id_parameters,
    prepare_alg_id,
    prepare_hash_alg_id,
    prepare_mgf1_alg_id,
)
from keyutils_py.oids import SIG_ALG_OID_2_PARAMETERS_SPEC
from keyutils_py.data_objects import FixedSHAKE128, FixedSHAKE256


class TestRsaPssRoundTrip(unittest.TestCase):
    """sign_data_rsa_pss + verify_rsassa_pss_from_alg_id round-trip across hashes."""

    @classmethod
    def setUpClass(cls):
        cls.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub = cls.priv.public_key()
        cls.msg = b"keyutils-py RSA-PSS round-trip"

    def test_sha256_round_trip(self):
        """GIVEN RSA + sha256 / WHEN sign→verify via PSS / THEN succeeds."""
        sig = sign_data_rsa_pss(self.priv, self.msg, hash_alg="sha256")
        alg_id = prepare_rsa_pss_alg_id("sha256")
        verify_rsassa_pss_from_alg_id(self.pub, self.msg, sig, alg_id)

    def test_sha384_round_trip(self):
        """GIVEN RSA + sha384 / WHEN sign→verify via PSS / THEN succeeds."""
        sig = sign_data_rsa_pss(self.priv, self.msg, hash_alg="sha384")
        verify_rsassa_pss_from_alg_id(self.pub, self.msg, sig, prepare_rsa_pss_alg_id("sha384"))

    def test_sha512_round_trip(self):
        """GIVEN RSA + sha512 / WHEN sign→verify via PSS / THEN succeeds."""
        sig = sign_data_rsa_pss(self.priv, self.msg, hash_alg="sha512")
        verify_rsassa_pss_from_alg_id(self.pub, self.msg, sig, prepare_rsa_pss_alg_id("sha512"))

    def test_shake128_round_trip(self):
        """GIVEN RSA + shake128 / WHEN sign→verify via PSS-SHAKE / THEN succeeds."""
        sig = sign_data_rsa_pss(self.priv, self.msg, hash_alg="shake128")
        verify_rsassa_pss_from_alg_id(self.pub, self.msg, sig, prepare_rsa_pss_alg_id("shake128"))

    def test_shake256_round_trip(self):
        """GIVEN RSA + shake256 / WHEN sign→verify via PSS-SHAKE / THEN succeeds."""
        sig = sign_data_rsa_pss(self.priv, self.msg, hash_alg="shake256")
        verify_rsassa_pss_from_alg_id(self.pub, self.msg, sig, prepare_rsa_pss_alg_id("shake256"))

    def test_tampered_signature_rejected(self):
        """GIVEN tampered signature / WHEN verifying / THEN InvalidSignature."""
        sig = sign_data_rsa_pss(self.priv, self.msg, hash_alg="sha256")
        bad = bytes([sig[0] ^ 0xFF]) + sig[1:]
        with self.assertRaises(InvalidSignature):
            verify_rsassa_pss_from_alg_id(self.pub, self.msg, bad, prepare_rsa_pss_alg_id("sha256"))


class TestSignDataDispatch(unittest.TestCase):
    """sign_data routes RSA + use_rsa_pss=True to the PSS path."""

    def test_sign_data_use_rsa_pss(self):
        """GIVEN RSA key + use_rsa_pss=True / WHEN sign_data / THEN PSS verifier accepts the result."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sig = sign_data(b"payload", priv, use_rsa_pss=True, hash_alg="sha256")
        verify_rsassa_pss_from_alg_id(priv.public_key(), b"payload", sig, prepare_rsa_pss_alg_id("sha256"))


class TestSignWithAlgIdRsa(unittest.TestCase):
    """sign_with_alg_id / verify_signature_with_alg_id handle RSA-PSS and PKCS#1 v1.5."""

    def test_sign_with_alg_id_rsassa_pss(self):
        """GIVEN id-RSASSA-PSS alg_id / WHEN sign_with_alg_id / THEN verify_with_alg_id accepts."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alg_id = prepare_rsa_pss_alg_id("sha256")
        sig = sign_with_alg_id(priv, alg_id, b"abc")
        verify_signature_with_alg_id(priv.public_key(), alg_id, b"abc", sig)

    def test_sign_with_alg_id_rsassa_pss_shake256(self):
        """GIVEN id-RSASSA-PSS-SHAKE256 / WHEN sign→verify / THEN succeeds."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alg_id = prepare_rsa_pss_alg_id("shake256")
        sig = sign_with_alg_id(priv, alg_id, b"abc")
        verify_signature_with_alg_id(priv.public_key(), alg_id, b"abc", sig)

    def test_sign_with_alg_id_rsa_pkcs1(self):
        """GIVEN rsa-sha256 PKCS#1 v1.5 alg_id / WHEN sign→verify / THEN succeeds."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alg_id = rfc5280.AlgorithmIdentifier()
        alg_id["algorithm"] = rfc9481.sha256WithRSAEncryption
        alg_id["parameters"] = univ.Any(b"\x05\x00")
        sig = sign_with_alg_id(priv, alg_id, b"abc")
        verify_signature_with_alg_id(priv.public_key(), alg_id, b"abc", sig)


class TestPrepareRsaPssAlgId(unittest.TestCase):
    """Structural checks on prepare_rsa_pss_alg_id output."""

    def test_sha256_carries_pss_params(self):
        """GIVEN sha256 / WHEN preparing / THEN id_RSASSA_PSS + RSASSA_PSS_params present."""
        alg_id = prepare_rsa_pss_alg_id("sha256")
        self.assertEqual(alg_id["algorithm"], rfc9481.id_RSASSA_PSS)
        self.assertTrue(alg_id["parameters"].isValue)
        # round-trip through decode_alg_id_parameters
        decode_alg_id_parameters(alg_id)
        self.assertIsInstance(alg_id["parameters"], rfc4055.RSASSA_PSS_params)
        self.assertEqual(int(alg_id["parameters"]["saltLength"]), 32)  # SHA-256 digest size

    def test_shake128_no_params(self):
        """GIVEN shake128 / WHEN preparing / THEN id_RSASSA_PSS_SHAKE128 with absent params."""
        alg_id = prepare_rsa_pss_alg_id("shake128")
        self.assertEqual(alg_id["algorithm"], rfc9481.id_RSASSA_PSS_SHAKE128)
        self.assertFalse(alg_id["parameters"].isValue)

    def test_custom_salt_length(self):
        """GIVEN a custom salt length / WHEN preparing / THEN saltLength carried through."""
        alg_id = prepare_rsa_pss_alg_id("sha256", salt_length=64)
        decode_alg_id_parameters(alg_id)
        self.assertEqual(int(alg_id["parameters"]["saltLength"]), 64)


class TestPrepareSpki(unittest.TestCase):
    """SPKI builders cover RSA / RSA-PSS / EC / Ed25519 / PQ / RSA-KEM / KGA."""

    def test_rsa_default(self):
        """GIVEN RSA private key / WHEN preparing SPKI / THEN rsaEncryption OID."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spki = prepare_spki(priv)
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "1.2.840.113549.1.1.1")

    def test_rsa_use_pss(self):
        """GIVEN RSA + use_rsa_pss=True / WHEN preparing SPKI / THEN id_RSASSA_PSS."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spki = prepare_spki(priv, use_rsa_pss=True, hash_alg="sha256")
        self.assertEqual(spki["algorithm"]["algorithm"], rfc9481.id_RSASSA_PSS)

    def test_ec(self):
        """GIVEN EC private key / WHEN preparing SPKI / THEN ecPublicKey OID."""
        priv = ec.generate_private_key(ec.SECP256R1())
        spki = prepare_spki(priv)
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "1.2.840.10045.2.1")

    def test_ed25519(self):
        """GIVEN Ed25519 / WHEN preparing SPKI / THEN id_Ed25519."""
        priv = ed25519.Ed25519PrivateKey.generate()
        spki = prepare_spki(priv)
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "1.3.101.112")

    def test_ml_dsa(self):
        """GIVEN ML-DSA / WHEN preparing SPKI / THEN ml-dsa OID."""
        priv = generate_key("ml-dsa-44")
        spki = prepare_spki(priv)
        # OID for ml-dsa-44
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "2.16.840.1.101.3.4.3.17")

    def test_ml_dsa_with_prehash(self):
        """GIVEN ML-DSA + hash_alg=sha512 / WHEN preparing SPKI / THEN pre-hash OID."""
        priv = generate_key("ml-dsa-44")
        spki = prepare_spki(priv, hash_alg="sha512")
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "2.16.840.1.101.3.4.3.32")

    def test_rsa_kem(self):
        """GIVEN RSA + key_name=rsa-kem / WHEN preparing SPKI / THEN rsa-kem-spki OID."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spki = prepare_spki(priv, key_name="rsa-kem")
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "1.2.840.113549.1.9.16.3")

    def test_for_kga_rsa(self):
        """GIVEN for_kga + key_name=rsa / WHEN preparing SPKI / THEN empty bitstring + rsa OID."""
        spki = prepare_spki(for_kga=True, key_name="rsa")
        self.assertEqual(str(spki["algorithm"]["algorithm"]), "1.2.840.113549.1.1.1")
        self.assertEqual(spki["subjectPublicKey"].asOctets(), b"")

    def test_add_null(self):
        """GIVEN add_null=True / WHEN preparing SPKI / THEN parameters is NULL."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spki = prepare_spki(priv, add_null=True)
        self.assertIsInstance(spki["algorithm"]["parameters"], univ.Null)

    def test_invalid_key_size(self):
        """GIVEN invalid_key_size=True / WHEN preparing SPKI / THEN extra trailing bytes."""
        priv = ec.generate_private_key(ec.SECP256R1())
        normal = prepare_spki(priv)
        bad = prepare_spki(priv, invalid_key_size=True)
        self.assertEqual(
            len(bad["subjectPublicKey"].asOctets()),
            len(normal["subjectPublicKey"].asOctets()) + 2,
        )

    def test_no_key_no_kga_raises(self):
        """GIVEN neither key nor for_kga / WHEN preparing / THEN ValueError."""
        with self.assertRaises(ValueError):
            prepare_subject_public_key_info()

    def test_alias(self):
        """prepare_spki is the same callable as prepare_subject_public_key_info."""
        self.assertIs(prepare_spki, prepare_subject_public_key_info)


class TestAlgIdHelpers(unittest.TestCase):
    """Direct coverage for algid_utils building blocks."""

    def test_catalog_covers_traditional(self):
        """GIVEN known traditional sig OIDs / WHEN looking up / THEN entries present."""
        self.assertEqual(
            SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.sha256WithRSAEncryption],
            SigAlgParametersSpec.MUST_BE_NULL,
        )
        self.assertEqual(
            SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.id_RSASSA_PSS],
            SigAlgParametersSpec.MUST_BE_RSASSA_PSS_PARAMS,
        )
        self.assertEqual(
            SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.id_RSASSA_PSS_SHAKE128],
            SigAlgParametersSpec.MUST_BE_ABSENT,
        )
        self.assertEqual(
            SIG_ALG_OID_2_PARAMETERS_SPEC[rfc9481.ecdsa_with_SHA256],
            SigAlgParametersSpec.MUST_BE_ABSENT,
        )

    def test_prepare_alg_id_with_value_and_random_raises(self):
        """GIVEN both value and fill_random_params / WHEN preparing / THEN ValueError."""
        with self.assertRaises(ValueError):
            prepare_alg_id(rfc9481.id_Ed25519, value=univ.Null(""), fill_random_params=True)

    def test_prepare_hash_alg_id_sha256_carries_null(self):
        """GIVEN sha256 / WHEN building hash alg id / THEN parameters=NULL."""
        alg_id = prepare_hash_alg_id("sha256")
        self.assertEqual(alg_id["parameters"], univ.Null(""))

    def test_prepare_mgf1_alg_id(self):
        """GIVEN sha256 / WHEN building MGF1 alg id / THEN id_mgf1 OID + nested hash."""
        alg_id = prepare_mgf1_alg_id("sha256")
        from pyasn1_alt_modules import rfc8017

        self.assertEqual(alg_id["algorithm"], rfc8017.id_mgf1)


class TestFixedSHAKE(unittest.TestCase):
    """FixedSHAKE wrappers expose the digest_size that PyCryptodome PSS expects."""

    def test_shake128_digest_size(self):
        """GIVEN FixedSHAKE128 / WHEN reading digest_size / THEN 32."""
        h = FixedSHAKE128.new(b"hello")
        self.assertEqual(h.digest_size, 32)
        self.assertEqual(len(h.digest()), 32)

    def test_shake256_digest_size(self):
        """GIVEN FixedSHAKE256 / WHEN reading digest_size / THEN 64."""
        h = FixedSHAKE256.new(b"hello")
        self.assertEqual(h.digest_size, 64)
        self.assertEqual(len(h.digest()), 64)


if __name__ == "__main__":
    unittest.main()
