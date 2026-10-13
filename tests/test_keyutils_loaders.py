# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the public loaders and consistency check exported by ``keyutils_py``."""

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from keyutils_py import (
    check_consistency_sig_alg_id_and_key,
    generate_key,
    load_private_key_from_one_asym_key,
    load_public_key_from_spki,
    prepare_spki,
    save_key,
)
from keyutils_py.exceptions import BadSigAlgID, InvalidKeyData
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.trad_keys import DSAPrivateKey
from keyutils_py.keyutils import prepare_alg_id, prepare_sig_alg_id
from keyutils_py.oids import PQ_NAME_2_OID
from keyutils_py.utils import load_and_decode_pem_file, try_decode_pyasn1
from pyasn1_alt_modules import rfc5958


def _spki_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _saved_der(key) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "key.pem")
        save_key(key, path, password=None)
        return load_and_decode_pem_file(path)


class TestLoadPrivateKeyFromOneAsymKey(unittest.TestCase):
    """``load_private_key_from_one_asym_key`` takes DER bytes or a decoded structure."""

    def test_bytes_and_structure_round_trip(self):
        """GIVEN PQ and stateful keys / WHEN loaded from bytes and from a structure / THEN both match."""
        for alg in ("ml-kem-768", "ml-dsa-65", "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"):
            with self.subTest(alg=alg):
                key = generate_key(alg)
                der = _saved_der(key)
                structure, _ = try_decode_pyasn1(der, rfc5958.OneAsymmetricKey())
                for loaded in (load_private_key_from_one_asym_key(der), load_private_key_from_one_asym_key(structure)):
                    self.assertIs(type(loaded), type(key))
                    self.assertEqual(_spki_der(loaded.public_key()), _spki_der(key.public_key()))

    def test_dsa(self):
        """GIVEN a PKCS#8 DSA key / WHEN loaded / THEN the private value matches."""
        key = DSAPrivateKey.generate(2048)
        der = key.private_bytes(serialization.Encoding.DER)
        loaded = load_private_key_from_one_asym_key(der)
        self.assertIsInstance(loaded, DSAPrivateKey)
        assert isinstance(loaded, DSAPrivateKey)  # narrows the union for the type checker
        self.assertEqual(loaded.x, key.x)

    def test_garbage_raises_invalid_key_data(self):
        """GIVEN bytes that are not a OneAsymmetricKey / WHEN loaded / THEN InvalidKeyData."""
        with self.assertRaises(InvalidKeyData):
            load_private_key_from_one_asym_key(b"\x30\x03\x02\x01\x00")


class TestLoadPublicKeyFromSpki(unittest.TestCase):
    """``load_public_key_from_spki`` takes DER bytes or a decoded structure."""

    def test_bytes_and_structure_round_trip(self):
        """GIVEN PQ and hybrid public keys / WHEN loaded from bytes and a structure / THEN both match."""
        for alg in ("ml-kem-768", "ml-dsa-65", "xwing"):
            with self.subTest(alg=alg):
                pub = generate_key(alg).public_key()
                self.assertEqual(_spki_der(load_public_key_from_spki(_spki_der(pub))), _spki_der(pub))
                self.assertEqual(_spki_der(load_public_key_from_spki(prepare_spki(pub))), _spki_der(pub))

    def test_dsa(self):
        """GIVEN a DSA SPKI / WHEN loaded / THEN the public key is equal."""
        pub = DSAPrivateKey.generate(2048).public_key()
        self.assertEqual(load_public_key_from_spki(_spki_der(pub)), pub)

    def test_garbage_raises_invalid_key_data(self):
        """GIVEN bytes that are not a SubjectPublicKeyInfo / WHEN loaded / THEN InvalidKeyData."""
        with self.assertRaises(InvalidKeyData):
            load_public_key_from_spki(b"\x30\x03\x02\x01\x00")

    def test_traditional_key_not_implemented(self):
        """GIVEN an EC SPKI / WHEN loaded / THEN NotImplementedError, as in the file loaders."""
        pub = TradKeyFactory.generate_trad_key("ecdsa").public_key()
        with self.assertRaises(NotImplementedError):
            load_public_key_from_spki(_spki_der(pub))


class TestCheckConsistency(unittest.TestCase):
    """``check_consistency_sig_alg_id_and_key`` accepts matching and rejects mismatching pairs."""

    @classmethod
    def setUpClass(cls):
        """Generate one key per family once."""
        cls.rsa = TradKeyFactory.generate_trad_key("rsa")
        cls.ec = TradKeyFactory.generate_trad_key("ecdsa")
        cls.ml_dsa = generate_key("ml-dsa-65")

    def test_matching_pairs(self):
        """GIVEN an alg_id built for the key / WHEN checked / THEN no error (public or private key)."""
        check_consistency_sig_alg_id_and_key(prepare_sig_alg_id(self.rsa, hash_alg="sha256"), self.rsa.public_key())
        check_consistency_sig_alg_id_and_key(prepare_sig_alg_id(self.ec, hash_alg="sha256"), self.ec)
        check_consistency_sig_alg_id_and_key(prepare_alg_id(PQ_NAME_2_OID["ml-dsa-65"]), self.ml_dsa.public_key())

    def test_mismatching_pairs(self):
        """GIVEN an alg_id for another key type / WHEN checked / THEN BadSigAlgID."""
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(prepare_sig_alg_id(self.ec, hash_alg="sha256"), self.rsa.public_key())
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(prepare_alg_id(PQ_NAME_2_OID["ml-dsa-65"]), self.ec.public_key())


if __name__ == "__main__":
    unittest.main()
