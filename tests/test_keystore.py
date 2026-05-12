# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""End-to-end load/save round-trip covering all three families.

Adapted from ``unit_tests/.../test_xmss_xmssmt_key_loading_file.py`` plus the
HSS portion of ``tests_keys_related/tests_key_loading/test_load_key_from_file.py``.
"""

import os
import tempfile
import unittest

from keyutils_py.utils import OQS_AVAILABLE
from keyutils_py.keys.stateful_sig_keys import (
    HSSPrivateKey,
    XMSSMTPrivateKey,
    XMSSPrivateKey,
)
from keyutils_py import load_private_key_from_file, save_key

from tests.conftest import HSS_KEYS_DIR, discover_xmss_xmssmt_key_paths


class TestRoundTrip(unittest.TestCase):
    def test_save_and_load_hss(self):
        """GIVEN a fresh HSS key / WHEN saving and reloading / THEN keys match."""
        key = HSSPrivateKey("hss_lms_sha256_m32_h5_lmots_sha256_n32_w8", levels=2)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hss.pem")
            save_key(key, path, password="test-pwd-123")
            reloaded = load_private_key_from_file(path, password="test-pwd-123")
        self.assertEqual(reloaded.name, key.name)
        self.assertEqual(reloaded.public_key().public_bytes_raw(), key.public_key().public_bytes_raw())

    def test_load_hss_fixture_directory(self):
        """GIVEN the bundled hss_keys directory / WHEN loading every PEM / THEN all keys load."""
        any_loaded = False
        for entry in sorted(os.listdir(HSS_KEYS_DIR)):
            if not entry.endswith(".pem"):
                continue
            path = os.path.join(HSS_KEYS_DIR, entry)
            key = load_private_key_from_file(path)
            self.assertIsInstance(key, HSSPrivateKey)
            any_loaded = True
        self.assertTrue(any_loaded, "No HSS fixture keys found under HSS_KEYS_DIR")


@unittest.skipUnless(OQS_AVAILABLE, "liboqs (oqs) is not installed; XMSS/XMSSMT tests skipped")
class TestXMSSXMSSMTLoading(unittest.TestCase):
    def test_xmss_loading_from_fixture(self):
        """GIVEN bundled XMSS PEMs / WHEN loaded / THEN names match."""
        keys = discover_xmss_xmssmt_key_paths()
        any_xmss = False
        for alg_name, path in keys.items():
            if not alg_name.startswith("xmss-"):
                continue
            with self.subTest(alg=alg_name):
                priv = load_private_key_from_file(path)
                self.assertEqual(priv.name, alg_name)
                self.assertIsInstance(priv, XMSSPrivateKey)
                any_xmss = True
        if not any_xmss:
            self.skipTest("No XMSS fixtures discovered for the enabled liboqs mechanisms")

    def test_xmssmt_loading_from_fixture(self):
        """GIVEN bundled XMSSMT PEMs / WHEN loaded / THEN names match."""
        keys = discover_xmss_xmssmt_key_paths()
        any_xmssmt = False
        for alg_name, path in keys.items():
            if not alg_name.startswith("xmssmt-"):
                continue
            with self.subTest(alg=alg_name):
                priv = load_private_key_from_file(path)
                self.assertEqual(priv.name, alg_name)
                self.assertIsInstance(priv, XMSSMTPrivateKey)
                any_xmssmt = True
        if not any_xmssmt:
            self.skipTest("No XMSSMT fixtures discovered for the enabled liboqs mechanisms")


if __name__ == "__main__":
    unittest.main()
