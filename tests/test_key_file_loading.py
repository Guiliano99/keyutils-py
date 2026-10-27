# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for loading and saving keys as PEM files, and for the failure information on the exceptions."""

import os
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from keyutils_py import exceptions
from keyutils_py.exceptions import InvalidKeyData
from keyutils_py.factories import CombinedKeyFactory
from keyutils_py.keys.serialize_utils import prepare_enc_key_pem
from keyutils_py.keyutils import generate_key, load_private_key_from_file, save_key

_PEM = serialization.Encoding.PEM
_NO_ENC = serialization.NoEncryption()


def _pub(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class TestLoadPrivateKeyFromFile(unittest.TestCase):
    """`load_private_key_from_file` takes the kind of key from the PEM label."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)

    def _write(self, data: bytes) -> str:
        path = os.path.join(self._dir.name, "key.pem")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_save_and_load_every_family(self):
        """GIVEN keys of each family / WHEN saved with and without password / THEN they load back equal."""
        for algorithm, params in (
            ("rsa", {"length": 1024}),
            ("dsa", {}),
            ("dh", {"length": 512}),
            ("ecdsa", {}),
            ("ed25519", {}),
            ("ml-dsa-44", {}),
            ("composite-sig", {}),
        ):
            for password in (None, "pw1234"):
                with self.subTest(algorithm=algorithm, password=password):
                    key = generate_key(algorithm, **params)
                    path = os.path.join(self._dir.name, f"{algorithm}.pem")
                    save_key(key, path, password=password)
                    self.assertEqual(_pub(load_private_key_from_file(path, password=password)), _pub(key))

    def test_dsa_and_dh_load_as_wrappers(self):
        """GIVEN a saved DSA and DH key / WHEN loaded / THEN the keys are equal wrapper keys."""
        for algorithm, params in (("dsa", {}), ("dh", {"length": 512})):
            with self.subTest(algorithm=algorithm):
                key = generate_key(algorithm, **params)
                path = os.path.join(self._dir.name, "wrapper.pem")
                save_key(key, path, password="pw1234")
                self.assertEqual(load_private_key_from_file(path, password="pw1234"), key)

    def test_traditional_openssl_format(self):
        """GIVEN `RSA PRIVATE KEY` and `EC PRIVATE KEY` files / WHEN loaded / THEN the keys are returned."""
        for key in (rsa.generate_private_key(65537, 1024), ec.generate_private_key(ec.SECP256R1())):
            with self.subTest(key=type(key).__name__):
                pem = key.private_bytes(_PEM, serialization.PrivateFormat.TraditionalOpenSSL, _NO_ENC)
                self.assertEqual(_pub(load_private_key_from_file(self._write(pem), password=None)), _pub(key))

    def test_traditional_der_under_the_pkcs8_label(self):
        """GIVEN a PKCS#1 `RSAPrivateKey` under a `PRIVATE KEY` label / WHEN loaded / THEN it still loads."""
        key = rsa.generate_private_key(65537, 1024)
        pem = key.private_bytes(_PEM, serialization.PrivateFormat.TraditionalOpenSSL, _NO_ENC)
        relabelled = pem.replace(b"RSA PRIVATE KEY", b"PRIVATE KEY")
        self.assertEqual(_pub(load_private_key_from_file(self._write(relabelled), password=None)), _pub(key))

    def test_text_around_the_pem_block_is_ignored(self):
        """GIVEN a license header before the PEM block / WHEN loaded / THEN the key is returned."""
        key = rsa.generate_private_key(65537, 1024)
        pem = key.private_bytes(_PEM, serialization.PrivateFormat.PKCS8, _NO_ENC)
        # The marker is split, because the REUSE tool also reads license markers from strings in a file.
        path = self._write(b"# SPDX-" + b"License-Identifier: Apache-2.0\n\n" + pem)
        self.assertEqual(_pub(load_private_key_from_file(path, password=None)), _pub(key))

    def test_legacy_encrypted_pem(self):
        """GIVEN a key in the `Proc-Type`/`DEK-Info` format / WHEN loaded with the password / THEN it is decrypted."""
        key = generate_key("ml-dsa-44")
        der = CombinedKeyFactory.save_private_key_one_asym_key(key, password=None, version=1)
        path = self._write(prepare_enc_key_pem("pw1234", der, key_name=b"ML-DSA-44"))
        self.assertEqual(load_private_key_from_file(path, password="pw1234"), key)

    def test_encrypted_key_without_password_raises(self):
        """GIVEN an encrypted key / WHEN loaded without password / THEN a ValueError is raised."""
        path = os.path.join(self._dir.name, "enc.pem")
        save_key(generate_key("ml-dsa-44"), path, password="pw1234")
        with self.assertRaises(ValueError):
            load_private_key_from_file(path, password=None)

    def test_file_without_pem_block_raises(self):
        """GIVEN a file without a private key / WHEN loaded / THEN InvalidKeyData is raised."""
        with self.assertRaises(InvalidKeyData):
            load_private_key_from_file(self._write(b"nothing here"), password=None)


class TestFailInfoOnExceptions(unittest.TestCase):
    """The exceptions carry the RFC 4210 failure information for the callers that build responses."""

    def test_defaults_and_overrides(self):
        """GIVEN the exceptions / WHEN their failinfo is read / THEN it is the draft's name and bit."""
        self.assertEqual(exceptions.KeyUtilsError("x").get_failinfo(), "systemFailure")
        self.assertEqual(exceptions.BadAlg("x").get_failinfo(), "badAlg")
        self.assertEqual(exceptions.BadAlg.bit_num, 0)
        self.assertEqual(exceptions.InvalidKeyData("x").get_failinfo(), "badDataFormat")
        self.assertEqual(exceptions.BadDataFormat.bit_num, 5)
        self.assertEqual(exceptions.BadAlg("x", failinfo="badPOP").get_failinfo(), "badPOP")

    def test_hierarchy(self):
        """GIVEN the exceptions / WHEN their bases are checked / THEN they share one root."""
        self.assertTrue(issubclass(exceptions.InvalidKeyCombination, exceptions.BadAlg))
        self.assertTrue(issubclass(exceptions.MismatchingKey, exceptions.InvalidKeyData))
        self.assertTrue(issubclass(exceptions.InvalidKeyData, exceptions.KeyUtilsError))

    def test_error_details(self):
        """GIVEN a string as detail / WHEN read back / THEN it is a one-element list."""
        self.assertEqual(exceptions.BadAlg("x", error_details="because").get_error_details(), ["because"])


if __name__ == "__main__":
    unittest.main()
