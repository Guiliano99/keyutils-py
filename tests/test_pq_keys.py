# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Round-trip tests for PQ signature and KEM keys (non-stateful)."""

import os
import tempfile
import unittest

from keyutils_py import (
    generate_key,
    load_private_key_from_file,
    save_key,
    sign_data,
    verify_signature,
)
from keyutils_py.keyutils import get_supported_pq_algorithms
from keyutils_py.utils import OQS_AVAILABLE
from keyutils_py.data import PQ_KEYS_DIR
from keyutils_py.exceptions import MissingOQSDependencyError
from keyutils_py.keys.abstract_pq import (
    PQKEMPrivateKey,
    PQSignaturePrivateKey,
)


class TestPQSignatureRoundTrip(unittest.TestCase):
    """ML-DSA / SLH-DSA work without liboqs (bundled FIPS implementations)."""

    def test_ml_dsa_44_sign_verify(self):
        """GIVEN ML-DSA-44 / WHEN sign+verify / THEN succeeds."""
        key = generate_key("ml-dsa-44")
        self.assertIsInstance(key, PQSignaturePrivateKey)
        sig = sign_data(b"keyutils-py PQ test", key)
        verify_signature(key.public_key(), sig, b"keyutils-py PQ test")

    def test_slh_dsa_sha2_128f_sign_verify(self):
        """GIVEN SLH-DSA-SHA2-128f / WHEN sign+verify / THEN succeeds."""
        key = generate_key("slh-dsa-sha2-128f")
        sig = sign_data(b"keyutils-py SLH test", key)
        verify_signature(key.public_key(), sig, b"keyutils-py SLH test")

    def test_ml_dsa_save_load_roundtrip(self):
        """GIVEN ML-DSA / WHEN save+load (seed) / THEN names match."""
        key = generate_key("ml-dsa-44")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.pem")
            save_key(key, path, password="test-pw", save_type="seed")
            loaded = load_private_key_from_file(path, password="test-pw")
        self.assertEqual(loaded.name, "ml-dsa-44")

    def test_slh_dsa_save_load_roundtrip(self):
        """GIVEN SLH-DSA / WHEN save+load (seed) / THEN names match and signing works."""
        key = generate_key("slh-dsa-sha2-128f")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.pem")
            save_key(key, path, password="test-pw", save_type="seed")
            loaded = load_private_key_from_file(path, password="test-pw")
        self.assertEqual(loaded.name, "slh-dsa-sha2-128f")
        sig = sign_data(b"after reload", loaded)
        verify_signature(loaded.public_key(), sig, b"after reload")


class TestPQKEMRoundTrip(unittest.TestCase):
    """ML-KEM works without liboqs (bundled fips203)."""

    def test_ml_kem_encaps_decaps(self):
        """GIVEN ML-KEM-512 / WHEN encaps+decaps / THEN shared secrets match."""
        key = generate_key("ml-kem-512")
        self.assertIsInstance(key, PQKEMPrivateKey)
        ss_a, ct = key.public_key().encaps()
        ss_b = key.decaps(ct)
        self.assertEqual(ss_a, ss_b)
        self.assertEqual(len(ss_a), 32)

    def test_ml_kem_save_load_roundtrip(self):
        """GIVEN ML-KEM / WHEN save+load+decaps / THEN shared secrets match."""
        key = generate_key("ml-kem-768")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.pem")
            save_key(key, path, password="kem-pw", save_type="seed")
            loaded = load_private_key_from_file(path, password="kem-pw")
        self.assertEqual(loaded.name, "ml-kem-768")
        # Use the loaded key end-to-end:
        ss_a, ct = loaded.public_key().encaps()
        ss_b = loaded.decaps(ct)
        self.assertEqual(ss_a, ss_b)


class TestPQAlgorithmListing(unittest.TestCase):
    def test_get_supported_pq_algorithms_dict_shape(self):
        """GIVEN the package / WHEN listing / THEN ml-dsa / slh-dsa / ml-kem are populated."""
        families = get_supported_pq_algorithms()
        self.assertEqual(
            set(families.keys()),
            {"ml-dsa", "slh-dsa", "falcon", "ml-kem", "frodokem", "mceliece", "sntrup761"},
        )
        self.assertGreater(len(families["ml-dsa"]), 0)
        self.assertGreater(len(families["slh-dsa"]), 0)
        self.assertGreater(len(families["ml-kem"]), 0)

    def test_get_supported_pq_algorithms_unknown_family(self):
        """GIVEN an unknown family / WHEN looked up / THEN ValueError."""
        with self.assertRaises(ValueError):
            get_supported_pq_algorithms("not-a-family")


@unittest.skipUnless(OQS_AVAILABLE, "liboqs not installed; oqs-only tests skipped")
class TestOQSOnlyAlgorithms(unittest.TestCase):
    """Falcon, FrodoKEM (oqs-mode), McEliece, SNTRUP761 require liboqs."""

    def test_falcon_512_sign_verify(self):
        key = generate_key("falcon-512")
        sig = sign_data(b"falcon", key)
        verify_signature(key.public_key(), sig, b"falcon")


class TestOQSGatedErrors(unittest.TestCase):
    """Without liboqs, oqs-only algorithms raise the clean MissingOQSDependencyError."""

    def setUp(self) -> None:
        from keyutils_py import utils

        self._utils_mod = utils
        self._original = utils.OQS_AVAILABLE
        utils.OQS_AVAILABLE = False

    def tearDown(self) -> None:
        self._utils_mod.OQS_AVAILABLE = self._original

    def test_falcon_generate_raises_without_oqs(self):
        """GIVEN no liboqs / WHEN generating Falcon / THEN MissingOQSDependencyError."""
        with self.assertRaises(MissingOQSDependencyError):
            generate_key("falcon-512")

    def test_mceliece_generate_raises_without_oqs(self):
        with self.assertRaises(MissingOQSDependencyError):
            generate_key("mceliece-348864")

    def test_sntrup761_generate_raises_without_oqs(self):
        with self.assertRaises(MissingOQSDependencyError):
            generate_key("sntrup761")

    def test_ml_dsa_works_without_oqs(self):
        """GIVEN no liboqs / WHEN generating ML-DSA / THEN succeeds (uses bundled fips204)."""
        key = generate_key("ml-dsa-44")
        self.assertEqual(key.name, "ml-dsa-44")


class TestPQFixtureLoading(unittest.TestCase):
    """Load the bundled ML-DSA / ML-KEM / SLH-DSA fixtures (no oqs required)."""

    def test_load_ml_dsa_seed_fixture(self):
        path = os.path.join(PQ_KEYS_DIR, "private-key-ml-dsa-44-seed.pem")
        if not os.path.exists(path):
            self.skipTest(f"Fixture not present: {path}")
        key = load_private_key_from_file(path)
        self.assertEqual(key.name, "ml-dsa-44")

    def test_load_ml_kem_seed_fixture(self):
        path = os.path.join(PQ_KEYS_DIR, "private-key-ml-kem-512-seed.pem")
        if not os.path.exists(path):
            self.skipTest(f"Fixture not present: {path}")
        key = load_private_key_from_file(path)
        self.assertEqual(key.name, "ml-kem-512")

    def test_load_slh_dsa_seed_fixture(self):
        path = os.path.join(PQ_KEYS_DIR, "private-key-slh-dsa-sha2-128f-seed.pem")
        if not os.path.exists(path):
            self.skipTest(f"Fixture not present: {path}")
        key = load_private_key_from_file(path)
        self.assertEqual(key.name, "slh-dsa-sha2-128f")


class TestCryptographyInteroperability(unittest.TestCase):
    """Keys generated and serialised by our library must load and work in the cryptography package.

    Our ``PQKeyFactory.save_private_key_one_asym_key(version=0)`` produces a
    standard PKCS#8 OneAsymmetricKey with the seed encoded as ``[0] IMPLICIT``
    — the exact format that OpenSSL / cryptography expects.  These tests verify:

    * The DER parses without error.
    * The derived public key is bit-for-bit identical in both libraries.
    * Cross-library encaps/decaps (ML-KEM) and sign/verify (ML-DSA) succeed.
    """

    def test_ml_kem_768_save_ours_load_cryptography(self):
        """GIVEN ML-KEM-768 / WHEN saved with our PKCS8 logic / THEN cryptography loads and cross-decaps works."""
        from cryptography.hazmat.primitives.asymmetric import mlkem as crypto_mlkem
        from cryptography.hazmat.primitives.serialization import load_der_private_key

        from keyutils_py.factories.pq_factory import PQKeyFactory

        key = generate_key("ml-kem-768")

        # Serialise with our own ASN.1 encoding (version-0 = seed-only, no trailing public key blob)
        der = PQKeyFactory.save_private_key_one_asym_key(
            private_key=key,
            save_type="seed",
            version=0,
            include_public_key=None,
        )

        crypto_key = load_der_private_key(der, password=None)
        self.assertIsInstance(crypto_key, crypto_mlkem.MLKEM768PrivateKey)

        # Both libraries must agree on the public key
        self.assertEqual(
            key.public_key().public_bytes_raw(),
            crypto_key.public_key().public_bytes_raw(),
        )

        # Our encaps → cryptography decaps
        ss_our, ct = key.public_key().encaps()
        ss_crypto = crypto_key.decapsulate(ct)
        self.assertEqual(ss_our, ss_crypto)

        # Cryptography encaps → our decaps
        ss_crypto2, ct2 = crypto_key.public_key().encapsulate()
        ss_our2 = key.decaps(ct2)
        self.assertEqual(ss_crypto2, ss_our2)

    def test_ml_dsa_44_save_ours_load_cryptography(self):
        """GIVEN ML-DSA-44 / WHEN saved with our PKCS8 logic / THEN cryptography loads and cross-sign/verify works."""
        from cryptography.hazmat.primitives.asymmetric import mldsa as crypto_mldsa
        from cryptography.hazmat.primitives.serialization import load_der_private_key

        from keyutils_py.factories.pq_factory import PQKeyFactory

        key = generate_key("ml-dsa-44")

        der = PQKeyFactory.save_private_key_one_asym_key(
            private_key=key,
            save_type="seed",
            version=0,
            include_public_key=None,
        )

        crypto_key = load_der_private_key(der, password=None)
        self.assertIsInstance(crypto_key, crypto_mldsa.MLDSA44PrivateKey)

        # Both libraries must agree on the public key
        self.assertEqual(
            key.public_key().public_bytes_raw(),
            crypto_key.public_key().public_bytes_raw(),
        )

        msg = b"keyutils-py cross-library interop test"

        # Our library signs → cryptography verifies
        sig = sign_data(msg, key)
        crypto_key.public_key().verify(sig, msg)  # raises InvalidSignature on failure

        # Cryptography signs → our library verifies
        sig2 = crypto_key.sign(msg)
        verify_signature(key.public_key(), sig2, msg)


if __name__ == "__main__":
    unittest.main()
