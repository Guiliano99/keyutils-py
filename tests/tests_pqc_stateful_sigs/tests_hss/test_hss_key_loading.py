# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

import unittest
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from keyutils_py.keys.stateful_sig_keys import HSSPrivateKey, HSSPublicKey
from keyutils_py.keyutils import _load_private_key_from_one_asym_key
from pyasn1_alt_modules import rfc5958
from pyasn1.codec.der.decoder import decode as der_decode


def _load_from_pkcs8_der(der_bytes: bytes) -> HSSPrivateKey:
    one_asym_key, _ = der_decode(der_bytes, asn1Spec=rfc5958.OneAsymmetricKey())
    return _load_private_key_from_one_asym_key(one_asym_key)


class TestHSSKeyLoading(unittest.TestCase):
    SHA256_ALG = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"
    DIFF_HASH_ALG = "hss_lms_shake_m24_h10_lmots_shake_n24_w1"

    def test_roundtrip_serialization(self):
        """
        GIVEN an HSS private key.
        WHEN serializing to raw bytes and deserializing back,
        THEN the restored key should match the original in all properties.
        """
        original = HSSPrivateKey(self.SHA256_ALG, levels=2)
        restored = HSSPrivateKey.from_private_bytes(original.private_bytes_raw())
        self.assertEqual(restored.name, original.name)
        self.assertEqual(restored.max_sig_size, original.max_sig_size)
        self.assertEqual(restored.public_key().public_bytes_raw(), original.public_key().public_bytes_raw())
        spki = original.public_key().public_bytes_raw()
        restored_pub = HSSPublicKey.from_public_bytes(spki)
        self.assertEqual(restored_pub.name, original.name)
        self.assertEqual(restored_pub.sig_size, original.public_key().sig_size)

    def test_generate_with_length_9_and_pkcs8_load(self):
        """
        GIVEN an HSS private key with 9 levels.
        WHEN generating the key and serializing/deserializing it,
        THEN the restored key and its public key should retain the 9 levels.
        """
        key = HSSPrivateKey(self.SHA256_ALG, levels=9)
        self.assertEqual(key.levels, 9)
        raw = key.private_bytes_raw()
        restored = HSSPrivateKey.from_private_bytes(raw)
        self.assertEqual(restored.levels, 9)
        self.assertEqual(restored.public_key().levels, 9)
        loaded = _load_from_pkcs8_der(
            key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )
        self.assertEqual(loaded.levels, 9)
        self.assertEqual(loaded.public_key(), key.public_key())
