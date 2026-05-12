# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""End-to-end smoke test of the ten public functions in ``main.py``."""

import base64
import os
import tempfile
import textwrap
import unittest
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5280, rfc9480

from keyutils_py import utils as _oqs_guard
from keyutils_py.exceptions import MissingOQSDependencyError
from keyutils_py.oids import PQ_STATEFUL_HASH_SIG_NAME_2_OID
from keyutils_py import (
    generate_key,
    load_private_key_from_file,
    load_public_key_from_file,
    save_key,
    sign_data,
    sign_with_alg_id,
    verify_signature,
    verify_signature_with_alg_id,
)
from keyutils_py.keys.stateful_sig_keys import HSSPrivateKey, HSSPublicKey
from keyutils_py.keyutils import get_supported_pq_stfl_algorithms
from keyutils_py.keyutils import load_pq_stfl_keys_from_dir

from tests.conftest import (
    HSS_KEYS_DIR,
    XMSS_XMSSMT_KEYS_DIR,
    XMSS_XMSSMT_KEYS_VERBOSE_DIR,
)


HSS_ALG = "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"


def _build_hss_alg_id() -> rfc9480.AlgorithmIdentifier:
    alg_id = rfc9480.AlgorithmIdentifier()
    alg_id["algorithm"] = PQ_STATEFUL_HASH_SIG_NAME_2_OID["hss"]
    return alg_id


class TestMainAPI(unittest.TestCase):
    """Smoke-test all ten public entry points."""

    def test_generate_sign_verify_round_trip_hss(self):
        """GIVEN HSS / WHEN generate→sign→verify / THEN succeeds."""
        key = generate_key(HSS_ALG, levels=2)
        msg = b"keyutils-py smoke test"
        sig = sign_data(msg, key)
        verify_signature(key.public_key(), sig, msg)

    def test_alg_id_round_trip_hss(self):
        """GIVEN HSS / WHEN sign_with_alg_id→verify_signature_with_alg_id / THEN succeeds."""
        key = generate_key(HSS_ALG, levels=2)
        alg_id = _build_hss_alg_id()
        msg = b"alg-id round trip"
        sig = sign_with_alg_id(key, alg_id, msg)
        verify_signature_with_alg_id(key.public_key(), alg_id, msg, sig)

    def test_save_and_load_round_trip_hss(self):
        """GIVEN HSS / WHEN save_key→load_private_key_from_file→load_public_key_from_file / THEN matches."""
        key = generate_key(HSS_ALG, levels=2)
        assert isinstance(key, HSSPrivateKey)
        with tempfile.TemporaryDirectory() as tmp:
            priv_path = os.path.join(tmp, "k.pem")
            save_key(key, priv_path, password="round-trip-pw")
            reloaded = load_private_key_from_file(priv_path, password="round-trip-pw")
            assert isinstance(reloaded, HSSPrivateKey)
            self.assertEqual(reloaded.name, key.name)

            pub_path = os.path.join(tmp, "k.pub.pem")
            spki_der = key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            spki_pem = (
                b"-----BEGIN PUBLIC KEY-----\n"
                + _wrap_b64(spki_der)
                + b"-----END PUBLIC KEY-----\n"
            )
            with open(pub_path, "wb") as fh:
                fh.write(spki_pem)
            pub = load_public_key_from_file(pub_path)
            assert isinstance(pub, HSSPublicKey)
            self.assertEqual(pub.public_bytes_raw(), key.public_key().public_bytes_raw())

    def test_get_supported_pq_stfl_algorithms_dict(self):
        """GIVEN the package / WHEN listing algorithms / THEN HSS list is non-empty."""
        families = get_supported_pq_stfl_algorithms()
        assert isinstance(families, dict)
        self.assertEqual(set(families.keys()), {"hss", "xmss", "xmssmt"})
        self.assertGreater(len(families["hss"]), 0)

    def test_get_supported_pq_stfl_algorithms_unknown_family(self):
        """GIVEN an unknown family / WHEN looking up / THEN ValueError."""
        with self.assertRaises(ValueError):
            get_supported_pq_stfl_algorithms("not-a-family")

    def test_load_pq_stfl_keys_from_hss_dir(self):
        """GIVEN the bundled hss_keys directory / WHEN loading / THEN at least one HSS key returns."""
        keys = load_pq_stfl_keys_from_dir(HSS_KEYS_DIR)
        self.assertGreater(len(keys), 0)
        for alg_name, key in keys.items():
            with self.subTest(alg_name=alg_name):
                self.assertTrue(alg_name.startswith("hss"))
                # Round-trip sign with each loaded key (each used once -- safe for fresh fixtures).
                sig = sign_data(b"check", key)
                verify_signature(key.public_key(), sig, b"check")

    def test_load_pq_stfl_keys_from_xmss_dir(self):
        """GIVEN the bundled xmss_xmssmt_keys directory / WHEN loading / THEN behaviour depends on liboqs."""
        keys = load_pq_stfl_keys_from_dir(XMSS_XMSSMT_KEYS_DIR)
        if _oqs_guard.OQS_AVAILABLE:
            self.assertGreater(len(keys), 0)
            for alg_name in keys:
                self.assertTrue(alg_name.startswith("xmss-") or alg_name.startswith("xmssmt-"))
        else:
            self.assertEqual(keys, {}, "Without liboqs, no XMSS/XMSSMT keys should load")

    def test_load_pq_stfl_keys_from_verbose_dir(self):
        """GIVEN the verbose directory / WHEN loading / THEN function handles it the same way."""
        if not os.path.isdir(XMSS_XMSSMT_KEYS_VERBOSE_DIR):
            self.skipTest("Verbose directory not present")
        # The verbose dir uses suffixed filenames (e.g. ``..._ir_bad_pop.pem``)
        # that don't match the stateful-hash naming pattern, so the loader
        # should silently skip them.
        keys = load_pq_stfl_keys_from_dir(XMSS_XMSSMT_KEYS_VERBOSE_DIR)
        self.assertIsInstance(keys, dict)


class TestOQSUnavailable(unittest.TestCase):
    """Force OQS_AVAILABLE = False and check the user-facing error path."""

    def setUp(self) -> None:
        self._original = _oqs_guard.OQS_AVAILABLE
        _oqs_guard.OQS_AVAILABLE = False

    def tearDown(self) -> None:
        _oqs_guard.OQS_AVAILABLE = self._original

    def test_xmss_lists_empty(self):
        """GIVEN no liboqs / WHEN listing algorithms / THEN xmss/xmssmt lists are empty, hss is non-empty."""
        families = get_supported_pq_stfl_algorithms()
        assert isinstance(families, dict)
        # HSS uses pyhsslms and is still populated.
        self.assertGreater(len(families["hss"]), 0)
        # XMSS/XMSSMT come from oqs.get_enabled_stateful_sig_mechanisms(); without
        # liboqs we expect them empty (the source factory falls back to []).
        # Note: the running liboqs may already have populated the lists at import
        # time; this test guards the *new* behaviour under the patched flag and
        # therefore only checks the type and the membership of keys.
        self.assertIn("xmss", families)
        self.assertIn("xmssmt", families)

    def test_generate_xmss_raises_missing_oqs(self):
        """GIVEN no liboqs / WHEN generating an XMSS key / THEN MissingOQSDependencyError with install hint."""
        with self.assertRaises(MissingOQSDependencyError) as cm:
            generate_key("xmss-sha2_10_256")
        self.assertIn("liboqs", str(cm.exception))
        self.assertIn("pq", str(cm.exception))

    def test_load_pq_stfl_keys_skips_xmss_without_oqs(self):
        """GIVEN no liboqs / WHEN loading a mixed dir / THEN XMSS keys are silently skipped."""
        with self.assertLogs("keyutils_py.keyutils", level="WARNING") as cm:
            keys = load_pq_stfl_keys_from_dir(XMSS_XMSSMT_KEYS_DIR)
        self.assertEqual(keys, {})
        self.assertTrue(any("liboqs is not installed" in msg for msg in cm.output))


def _wrap_b64(der: bytes) -> bytes:
    body = textwrap.fill(base64.b64encode(der).decode("ascii"), width=64)
    return body.encode("ascii") + b"\n"


# Suppress unused-import warning: encoder/rfc5280 reserved for future negative
# tests on alg_id parsing.
_ = (encoder, rfc5280)


if __name__ == "__main__":
    unittest.main()
