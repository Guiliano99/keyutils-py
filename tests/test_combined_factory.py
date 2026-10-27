# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for the key factory facade and the traditional key factory."""

import os
import unittest

from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5958

from keyutils_py.enums import KeySaveType
from keyutils_py.exceptions import InvalidKeyCombination, InvalidKeyData, MismatchingKey
from keyutils_py.factories import CombinedKeyFactory, TradKeyFactory
from keyutils_py.types import (
    DHPrivateKey,
    DHPublicKey,
    DSAPrivateKey,
    DSAPublicKey,
    MLDSAPrivateKey,
    PrivateKey,
    SignKey,
)

_DER = serialization.Encoding.DER
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def _spki(key) -> bytes:
    return key.public_key().public_bytes(_DER, _SPKI)


class TestCombinedKeyFactory(unittest.TestCase):
    """The facade creates, saves and loads every family of key."""

    def test_private_key_der_round_trip(self):
        """GIVEN a key of each family / WHEN saved as `OneAsymmetricKey` and loaded / THEN the public key is equal."""
        for algorithm in ("rsa", "dsa", "ecdsa", "ed25519", "x25519", "ml-dsa-44", "composite-sig"):
            with self.subTest(algorithm=algorithm):
                key = CombinedKeyFactory.generate_key(algorithm)
                der = CombinedKeyFactory.save_private_key_one_asym_key(key, password=None, version=1)
                loaded = CombinedKeyFactory.load_private_key_from_one_asym_key(der)
                self.assertEqual(type(loaded), type(key))
                self.assertEqual(_spki(loaded), _spki(key))

    def test_dsa_and_dh_are_the_wrapper_classes(self):
        """GIVEN DSA and DH keys / WHEN generated / THEN they are the wrappers, and valid key types."""
        dsa = CombinedKeyFactory.generate_key("dsa")
        dh = CombinedKeyFactory.generate_key("dh", length=512)
        self.assertIsInstance(dsa, DSAPrivateKey)
        self.assertIsInstance(dh, DHPrivateKey)
        self.assertIsInstance(dsa, SignKey)
        self.assertIsInstance(dsa, PrivateKey)
        self.assertIsInstance(dh, PrivateKey)

    def test_dh_private_key_round_trip(self):
        """GIVEN a DH key / WHEN saved and loaded / THEN the same DH key is returned."""
        key = CombinedKeyFactory.generate_key("dh", length=512)
        der = CombinedKeyFactory.save_private_key_one_asym_key(key, password=None)
        self.assertEqual(CombinedKeyFactory.load_private_key_from_one_asym_key(der), key)

    def test_public_key_from_spki(self):
        """GIVEN the SPKI of DSA and DH keys / WHEN loaded / THEN the wrapper public keys are returned."""
        dsa = CombinedKeyFactory.generate_key("dsa")
        dh = CombinedKeyFactory.generate_key("dh", length=512)
        self.assertEqual(CombinedKeyFactory.load_public_key_from_spki(_spki(dsa)), dsa.public_key())
        self.assertIsInstance(CombinedKeyFactory.load_public_key_from_spki(_spki(dsa)), DSAPublicKey)
        self.assertIsInstance(CombinedKeyFactory.load_public_key_from_spki(_spki(dh)), DHPublicKey)

    def test_generate_from_seed(self):
        """GIVEN a seed / WHEN a key is generated twice from it / THEN the keys are equal."""
        seed = b"\x07" * 32
        first = CombinedKeyFactory.generate_key_from_seed("ed25519", seed)
        second = CombinedKeyFactory.generate_key_from_seed("ed25519", seed)
        self.assertEqual(_spki(first), _spki(second))

    def test_invalid_composite_combination_is_rejected(self):
        """GIVEN a composite name with a combination the draft does not allow / WHEN generated / THEN it is rejected."""
        with self.assertRaises(InvalidKeyCombination):
            CombinedKeyFactory.generate_key_from_name("composite-kem-ml-kem-1024-ecdh-secp256r1")

    def test_password_protected_pem_is_pkcs8_encrypted(self):
        """GIVEN a PQ key / WHEN saved as PEM with a password / THEN it is a PKCS#8 `ENCRYPTED PRIVATE KEY`."""
        key = CombinedKeyFactory.generate_key("ml-dsa-44")
        pem = CombinedKeyFactory.save_private_key_one_asym_key(
            key, password="pw1234", version=1, encoding=serialization.Encoding.PEM
        )
        self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))

    def test_validate_key_export_type(self):
        """GIVEN an ML-DSA key saved as seed / WHEN the export type is validated / THEN only `seed` is accepted."""
        key = CombinedKeyFactory.generate_key("ml-dsa-44")
        der = key.private_bytes(_DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        content = decoder.decode(der, asn1Spec=rfc5958.OneAsymmetricKey())[0]["privateKey"].asOctets()
        CombinedKeyFactory.validate_key_export_type(key, content, KeySaveType.SEED)
        with self.assertRaises((InvalidKeyData, ValueError)):
            CombinedKeyFactory.validate_key_export_type(key, content, KeySaveType.RAW)

    def test_malformed_composite_public_key_is_invalid_key_data(self):
        """GIVEN a composite key with a truncated public key in its `OneAsymmetricKey` / WHEN loaded / THEN it fails."""
        for algorithm in ("composite-kem-ml-kem-768-x25519", "composite-sig-ml-dsa-44-ed25519"):
            with self.subTest(algorithm=algorithm):
                key = CombinedKeyFactory.generate_key_from_name(algorithm)
                der = CombinedKeyFactory.save_private_key_one_asym_key(
                    key, password=None, version=1, include_public_key=True
                )
                one_asym_key, _ = decoder.decode(der, asn1Spec=rfc5958.OneAsymmetricKey())
                truncated = one_asym_key["publicKey"].asOctets()[:-1]
                one_asym_key["publicKey"] = univ.BitString.fromOctetString(truncated).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                )
                with self.assertRaises(InvalidKeyData):
                    CombinedKeyFactory.load_private_key_from_one_asym_key(one_asym_key)

    def test_unsupported_key_type_raises(self):
        """GIVEN an unknown algorithm / WHEN a key is generated / THEN a ValueError lists the supported ones."""
        with self.assertRaises(ValueError):
            CombinedKeyFactory.generate_key("no-such-algorithm")


class TestMLKeySerialisation(unittest.TestCase):
    """ML-DSA and ML-KEM keys are written as the standardised `Choice`, which the loader reads back."""

    def test_private_bytes_is_the_choice_and_loads_back(self):
        """GIVEN an ML-DSA key from a seed / WHEN written as PKCS#8 / THEN the content is the seed `Choice`."""
        from keyutils_py.data_objects import MLDSA44PrivateKeyASN1

        seed = b"A" * 32
        key = MLDSAPrivateKey(alg_name="ml-dsa-44", seed=seed)
        der = key.private_bytes(_DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        one_asym_key, _ = decoder.decode(der, asn1Spec=rfc5958.OneAsymmetricKey())
        choice, rest = decoder.decode(one_asym_key["privateKey"].asOctets(), asn1Spec=MLDSA44PrivateKeyASN1())
        self.assertEqual(rest, b"")
        self.assertEqual(choice["seed"].asOctets(), seed)
        self.assertEqual(CombinedKeyFactory.load_private_key_from_one_asym_key(der), key)


class TestTradKeyFactory(unittest.TestCase):
    """Loading and saving of the traditional keys."""

    def test_trailing_data_is_rejected(self):
        """GIVEN an RSA private key with trailing data / WHEN loaded / THEN InvalidKeyData is raised."""
        key = TradKeyFactory.generate_trad_key("rsa", length=1024)
        der = TradKeyFactory.save_private_key_one_asym_key(key, version=1, include_public_key=False)
        one_asym_key, _ = decoder.decode(der, asn1Spec=rfc5958.OneAsymmetricKey())
        bad = rfc5958.OneAsymmetricKey()
        bad["version"] = 1
        bad["privateKeyAlgorithm"] = one_asym_key["privateKeyAlgorithm"]
        bad["privateKey"] = one_asym_key["privateKey"].asOctets() + os.urandom(4)
        with self.assertRaises(InvalidKeyData):
            TradKeyFactory.parse_trad_key_from_one_asym_key(bad)

    def test_mismatching_public_key_is_rejected(self):
        """GIVEN a key with the public key of another key / WHEN loaded / THEN MismatchingKey is raised."""
        key = TradKeyFactory.generate_trad_key("ed25519")
        other = TradKeyFactory.generate_trad_key("ed25519")
        der = TradKeyFactory.save_private_key_one_asym_key(key, public_key=other.public_key(), version=1)
        with self.assertRaises(MismatchingKey):
            TradKeyFactory.parse_trad_key_from_one_asym_key(der)

    def test_invalid_private_key_does_not_load(self):
        """GIVEN an RSA key saved with `invalid_private_key` / WHEN loaded / THEN it is rejected."""
        key = TradKeyFactory.generate_trad_key("rsa", length=1024)
        der = TradKeyFactory.save_private_key_one_asym_key(key, version=0, invalid_private_key=True)
        with self.assertRaises((InvalidKeyData, ValueError)):
            TradKeyFactory.parse_trad_key_from_one_asym_key(der, must_be_version_2=False)

    def test_dsa_and_dh_with_public_key(self):
        """GIVEN DSA and DH keys saved with their public key / WHEN loaded / THEN the wrappers are returned."""
        for algorithm, params in (("dsa", {}), ("dh", {"length": 512})):
            with self.subTest(algorithm=algorithm):
                key = TradKeyFactory.generate_trad_key(algorithm, **params)
                der = TradKeyFactory.save_private_key_one_asym_key(key, version=1)
                self.assertEqual(TradKeyFactory.parse_trad_key_from_one_asym_key(der), key)


if __name__ == "__main__":
    unittest.main()
