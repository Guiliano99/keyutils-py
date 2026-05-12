# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Smoke tests for the validate / encaps / decaps / ECDH / utility APIs."""

import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x448, x25519
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5480, rfc9480, rfc9481

from keyutils_py import (
    compute_decaps,
    compute_ecdh,
    compute_encaps,
    generate_key,
    get_key_name,
    validate_sig_alg_id,
)
from keyutils_py.keyutils import generate_key_based_on_alg_id
from keyutils_py.utils import OQS_AVAILABLE
from keyutils_py.exceptions import BadAlg, BadSigAlgIDParams, InvalidKeyCombination
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.trad_kem_keys import RSADecapKey, RSAEncapKey
from keyutils_py.oids import PQ_STATEFUL_HASH_SIG_NAME_2_OID


def _alg_id(oid, parameters=None) -> rfc9480.AlgorithmIdentifier:
    """Build an ``AlgorithmIdentifier`` from raw OID + optional parameters."""
    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if parameters is not None:
        alg_id["parameters"] = parameters
    return alg_id


class TestValidateSigAlgId(unittest.TestCase):
    """Coverage for the public ``validate_sig_alg_id`` dispatcher."""

    def test_ed25519_no_params_passes(self):
        """GIVEN ed25519 alg_id without params / WHEN validating / THEN no error."""
        validate_sig_alg_id(_alg_id(rfc9481.id_Ed25519))

    def test_ed25519_with_params_raises(self):
        """GIVEN ed25519 alg_id with params / WHEN validating / THEN BadSigAlgIDParams."""
        alg_id = _alg_id(rfc9481.id_Ed25519, univ.Null(""))
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(alg_id)

    def test_rsa_sha256_with_null_params_passes(self):
        """GIVEN RSA-SHA256 alg_id with NULL params / WHEN validating / THEN no error."""
        validate_sig_alg_id(_alg_id(rfc9481.sha256WithRSAEncryption, univ.Null("")))

    def test_rsa_sha256_without_params_raises(self):
        """GIVEN RSA-SHA256 alg_id without NULL params / WHEN validating / THEN BadSigAlgIDParams."""
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(_alg_id(rfc9481.sha256WithRSAEncryption))

    def test_ecdsa_no_params_passes(self):
        """GIVEN ECDSA-SHA256 without params / WHEN validating / THEN no error."""
        validate_sig_alg_id(_alg_id(rfc9481.ecdsa_with_SHA256))

    def test_pq_sig_with_params_raises(self):
        """GIVEN ML-DSA alg_id with params / WHEN validating / THEN BadSigAlgIDParams."""
        from keyutils_py.oids import id_ml_dsa_44_oid

        alg_id = _alg_id(id_ml_dsa_44_oid, univ.Null(""))
        with self.assertRaises(BadSigAlgIDParams):
            validate_sig_alg_id(alg_id)

    def test_unknown_oid_raises_badalg(self):
        """GIVEN unknown OID / WHEN validating / THEN BadAlg."""
        with self.assertRaises(BadAlg):
            validate_sig_alg_id(_alg_id(univ.ObjectIdentifier("1.2.3.4.5.99")))

    def test_stateful_hash_no_params_passes(self):
        """GIVEN HSS alg_id without params / WHEN validating / THEN no error."""
        validate_sig_alg_id(_alg_id(PQ_STATEFUL_HASH_SIG_NAME_2_OID["hss"]))


class TestEncapsDecaps(unittest.TestCase):
    """Round-trip tests for compute_encaps / compute_decaps."""

    def test_rsa_round_trip(self):
        """GIVEN an RSA key / WHEN encaps→decaps / THEN secrets match."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ss, ct = compute_encaps(priv.public_key(), key_length=32)
        self.assertEqual(len(ss), 32)
        recovered = compute_decaps(priv, ct, key_length=32)
        self.assertEqual(recovered, ss)

    def test_rsa_with_other_key_raises(self):
        """GIVEN RSA-KEM with an ECDH ephemeral / WHEN encaps / THEN InvalidKeyCombination."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ephemeral = x25519.X25519PrivateKey.generate()
        with self.assertRaises(InvalidKeyCombination):
            compute_encaps(priv.public_key(), other_key=ephemeral)

    def test_rsa_encap_wrapped_round_trip(self):
        """GIVEN pre-wrapped RSAEncapKey / WHEN encaps→decaps via RSADecapKey / THEN match."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrapper_pub = RSAEncapKey(priv.public_key())
        wrapper_priv = RSADecapKey(priv)
        ss, ct = compute_encaps(wrapper_pub)
        self.assertEqual(compute_decaps(wrapper_priv, ct), ss)

    @unittest.skipUnless(OQS_AVAILABLE, "ML-KEM works without oqs but other PQ KEMs may not be available")
    def test_ml_kem_round_trip(self):
        """GIVEN an ML-KEM key / WHEN encaps→decaps / THEN secrets match."""
        priv = generate_key("ml-kem-768")
        ss, ct = compute_encaps(priv.public_key())
        self.assertEqual(compute_decaps(priv, ct), ss)

    def test_unsupported_key_raises(self):
        """GIVEN a non-KEM public key / WHEN encaps / THEN BadAlg."""
        priv = ed25519.Ed25519PrivateKey.generate()
        with self.assertRaises(BadAlg):
            compute_encaps(priv.public_key())


class TestComputeEcdh(unittest.TestCase):
    """compute_ecdh covers EC, X25519, X448, certificate input, and cofactor."""

    def test_ec_p256(self):
        """GIVEN two P-256 keys / WHEN compute_ecdh / THEN both sides agree."""
        a = ec.generate_private_key(ec.SECP256R1())
        b = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(compute_ecdh(a, b.public_key()), compute_ecdh(b, a.public_key()))

    def test_x25519(self):
        """GIVEN X25519 keys / WHEN compute_ecdh / THEN both sides agree."""
        a = x25519.X25519PrivateKey.generate()
        b = x25519.X25519PrivateKey.generate()
        self.assertEqual(compute_ecdh(a, b.public_key()), compute_ecdh(b, a.public_key()))

    def test_x448(self):
        """GIVEN X448 keys / WHEN compute_ecdh / THEN both sides agree."""
        a = x448.X448PrivateKey.generate()
        b = x448.X448PrivateKey.generate()
        self.assertEqual(compute_ecdh(a, b.public_key()), compute_ecdh(b, a.public_key()))

    def test_curve_mismatch_raises(self):
        """GIVEN keys on different curves / WHEN compute_ecdh / THEN ValueError."""
        a = ec.generate_private_key(ec.SECP256R1())
        b = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaises(ValueError):
            compute_ecdh(a, b.public_key())

    def test_x25519_with_cofactor_not_implemented(self):
        """GIVEN X25519 with use_cofactor=True / WHEN compute_ecdh / THEN NotImplementedError."""
        a = x25519.X25519PrivateKey.generate()
        b = x25519.X25519PrivateKey.generate()
        with self.assertRaises(NotImplementedError):
            compute_ecdh(a, b.public_key(), use_cofactor=True)

    def test_ec_with_cofactor_one(self):
        """GIVEN P-256 (cofactor=1) with use_cofactor=True / WHEN compute_ecdh / THEN matches plain ECDH."""
        a = ec.generate_private_key(ec.SECP256R1())
        b = ec.generate_private_key(ec.SECP256R1())
        plain = compute_ecdh(a, b.public_key())
        with_cofactor = compute_ecdh(a, b.public_key(), use_cofactor=True)
        self.assertEqual(plain, with_cofactor)

    def test_certificate_input(self):
        """GIVEN a CMPCertificate carrying an EC key / WHEN compute_ecdh / THEN matches direct ECDH."""
        a = ec.generate_private_key(ec.SECP256R1())
        b = ec.generate_private_key(ec.SECP256R1())
        cert = _build_cert_with_ec_pubkey(b.public_key())
        self.assertEqual(compute_ecdh(a, cert), compute_ecdh(a, b.public_key()))


class TestGetKeyName(unittest.TestCase):
    """get_key_name covers traditional + PQ + hybrid + stateful-hash keys."""

    def test_rsa(self):
        """GIVEN an RSA private key / WHEN get_key_name / THEN 'rsa'."""
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertEqual(get_key_name(priv), "rsa")

    def test_ec(self):
        """GIVEN an EC private key / WHEN get_key_name / THEN 'ecdsa'."""
        priv = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(get_key_name(priv), "ecdsa")

    def test_ed25519(self):
        """GIVEN ed25519 / WHEN get_key_name / THEN 'ed25519'."""
        priv = ed25519.Ed25519PrivateKey.generate()
        self.assertEqual(get_key_name(priv), "ed25519")

    def test_x25519(self):
        """GIVEN x25519 / WHEN get_key_name / THEN 'x25519'."""
        priv = x25519.X25519PrivateKey.generate()
        self.assertEqual(get_key_name(priv), "x25519")

    def test_hss_uses_name_attribute(self):
        """GIVEN an HSS private key / WHEN get_key_name / THEN forwarded from .name."""
        key = generate_key("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
        self.assertEqual(get_key_name(key), key.name)


class TestGenerateKeyBasedOnAlgId(unittest.TestCase):
    """generate_key_based_on_alg_id dispatches across factories."""

    def test_ed25519(self):
        """GIVEN an ed25519 alg_id / WHEN generating / THEN an Ed25519PrivateKey."""
        out = generate_key_based_on_alg_id(_alg_id(rfc9481.id_Ed25519))
        self.assertIsInstance(out, ed25519.Ed25519PrivateKey)

    def test_ec_with_named_curve(self):
        """GIVEN an EC alg_id with secp256r1 params / WHEN generating / THEN a P-256 key."""
        from pyasn1.codec.der import encoder

        params = rfc5480.ECParameters()
        params["namedCurve"] = rfc5480.secp256r1
        alg_id = _alg_id(rfc5480.id_ecPublicKey, univ.Any(encoder.encode(params)))
        out = generate_key_based_on_alg_id(alg_id)
        self.assertIsInstance(out, ec.EllipticCurvePrivateKey)
        self.assertEqual(out.curve.name, "secp256r1")

    def test_rsa(self):
        """GIVEN an rsa-sha256 alg_id / WHEN generating / THEN an RSA key."""
        alg_id = _alg_id(rfc9481.sha256WithRSAEncryption, univ.Null(""))
        out = generate_key_based_on_alg_id(alg_id)
        self.assertIsInstance(out, rsa.RSAPrivateKey)

    def test_unknown_oid_raises(self):
        """GIVEN unknown OID / WHEN generating / THEN BadAlg."""
        with self.assertRaises(BadAlg):
            generate_key_based_on_alg_id(_alg_id(univ.ObjectIdentifier("1.2.3.4.5.99")))


def _build_cert_with_ec_pubkey(public_key: ec.EllipticCurvePublicKey) -> rfc9480.CMPCertificate:
    """Construct a minimally-populated CMPCertificate carrying ``public_key``."""
    from cryptography.hazmat.primitives import serialization
    from pyasn1.codec.der import decoder

    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki, _ = decoder.decode(spki_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    cert = rfc9480.CMPCertificate()
    cert["tbsCertificate"]["subjectPublicKeyInfo"] = spki
    return cert


# Suppress unused-import warnings: TradKeyFactory reserved for future tests.
_ = TradKeyFactory


if __name__ == "__main__":
    unittest.main()
