# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Adapted from ``unit_tests/.../tests_hss/test_hss_sign.py``."""

import unittest
from cryptography.exceptions import InvalidSignature

from keyutils_py.keys.stateful_sig_keys import HSSPrivateKey


class TestHSSSigning(unittest.TestCase):
    SHA256_ALG = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"
    SHAKE_ALG = "hss_lms_shake_m24_h5_lmots_shake_n24_w4"
    DIFF_HASH_ALG = "hss_lms_shake_m24_h10_lmots_shake_n24_w1"

    def test_sign_and_verify_sha256(self):
        """GIVEN an HSS key with SHA-256 / WHEN signing+verifying / THEN signature is valid."""
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        msg = b"CMP HSS unit test"
        sig = key.sign(msg)
        key.public_key().verify(msg, sig)
        self.assertEqual(key.public_key().get_leaf_index(sig), int.from_bytes(key.used_keys[-1], "big"))

    def test_sign_and_verify_shake(self):
        """GIVEN an HSS SHAKE key / WHEN signing+verifying / THEN signature is valid."""
        key = HSSPrivateKey(self.SHAKE_ALG, levels=2)
        msg = b"HSS SHAKE message"
        sig = key.sign(msg)
        key.public_key().verify(msg, sig)

    def test_used_keys_returns_copy(self):
        """GIVEN an HSS key / WHEN mutating used_keys() / THEN internal state is unchanged."""
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        sig = key.sign(b"tracking test")
        original_used = key.used_keys
        self.assertGreater(len(original_used), 0)
        original_used.append(b"tamper")
        self.assertNotEqual(key.used_keys[-1], b"tamper")
        key.public_key().verify(b"tracking test", sig)

    def test_verify_fails_on_modified_signature(self):
        """GIVEN a valid signature / WHEN one byte is flipped / THEN verification fails."""
        key = HSSPrivateKey(self.SHA256_ALG, levels=2)
        msg = b"Integrity check"
        sig = bytearray(key.sign(msg))
        if len(sig) > 10:
            sig[10] ^= 0xFF
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(msg, bytes(sig))


if __name__ == "__main__":
    unittest.main()
