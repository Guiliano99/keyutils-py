# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Tests for the cryptography-native ML-DSA / ML-KEM dispatch.

The wrappers in :mod:`keyutils_py.keys.sig_keys` and
:mod:`keyutils_py.keys.kem_keys` must:

* Hold a :class:`cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA*PrivateKey`
  / ``MLKEM*PrivateKey`` whenever a seed is available and the algorithm is
  exposed by ``cryptography`` (``ml-dsa-44/65/87``, ``ml-kem-768/1024``).
* Always hold a ``MLDSA*PublicKey`` / ``MLKEM*PublicKey`` for the same set,
  regardless of how the key was constructed.
* Fall back to liboqs / FIPS-203 / FIPS-204 for ``ml-kem-512``, pre-hashed
  ML-DSA, and keys loaded from raw expanded private bytes only.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa as crypto_mldsa
from cryptography.hazmat.primitives.asymmetric import mlkem as crypto_mlkem

from keyutils_py.enums import KeySaveType
from keyutils_py.factories.pq_factory import PQKeyFactory
from keyutils_py.keys._crypto_backend import is_cryptography_native_alg
from keyutils_py.keys.kem_keys import ML_KEM_PRIVATE_KEY_SIZE, MLKEMPrivateKey
from keyutils_py.keys.sig_keys import ML_DSA_PRIVATE_KEY_SIZE, MLDSAPrivateKey, MLDSAPublicKey


class TestNativeAlgPredicate(unittest.TestCase):
    """:func:`is_cryptography_native_alg` enumerates exactly the cryptography-supported set."""

    def test_native_set(self):
        for name in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "ml-kem-768", "ml-kem-1024"):
            self.assertTrue(is_cryptography_native_alg(name), name)

    def test_non_native_set(self):
        for name in ("ml-kem-512", "slh-dsa-sha2-128f", "falcon-512", "sntrup761"):
            self.assertFalse(is_cryptography_native_alg(name), name)


class TestMLDSAPrivateBackend(unittest.TestCase):
    """ML-DSA private keys go to cryptography when a seed is in scope."""

    def test_generate_holds_native_key(self):
        for name in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
            key = MLDSAPrivateKey(alg_name=name)
            self.assertIsNotNone(key._native_key, f"{name}: _native_key must be set after generate()")
            self.assertIsNone(
                key._private_key_bytes,
                f"{name}: expanded private bytes must be lazy on the cryptography path",
            )
            self.assertEqual(len(key._seed), 32)

    def test_from_seed_holds_native_key(self):
        seed = os.urandom(32)
        key = MLDSAPrivateKey.from_seed(alg_name="ml-dsa-65", seed=seed)
        self.assertIsNotNone(key._native_key)
        self.assertEqual(key._seed, seed)

    def test_from_expanded_only_falls_back(self):
        seed_key = MLDSAPrivateKey.from_seed(alg_name="ml-dsa-44", seed=os.urandom(32))
        expanded = seed_key.private_bytes_raw()  # forces lazy expand
        loaded = MLDSAPrivateKey.from_private_bytes(data=expanded, name="ml-dsa-44")
        self.assertIsNone(loaded._native_key)
        self.assertEqual(loaded.private_bytes_raw(), expanded)

    def test_from_seed_plus_expanded_validates_and_uses_native(self):
        seed = os.urandom(32)
        seed_key = MLDSAPrivateKey.from_seed(alg_name="ml-dsa-65", seed=seed)
        combined = seed + seed_key.private_bytes_raw()
        loaded = MLDSAPrivateKey.from_private_bytes(data=combined, name="ml-dsa-65")
        self.assertIsNotNone(loaded._native_key)
        self.assertEqual(loaded._seed, seed)

    def test_lazy_private_bytes_match_fips_expansion(self):
        """The lazy-expanded raw bytes must match a fresh FIPS-204 keygen from the same seed."""
        from keyutils_py.fips.fips204 import ML_DSA

        seed = os.urandom(32)
        key = MLDSAPrivateKey.from_seed(alg_name="ml-dsa-44", seed=seed)
        _, expected = ML_DSA("ml-dsa-44").keygen_internal(xi=seed)
        self.assertEqual(key.private_bytes_raw(), expected)
        self.assertEqual(len(key.private_bytes_raw()), ML_DSA_PRIVATE_KEY_SIZE["ml-dsa-44"])

    def test_sign_uses_native_when_no_prehash(self):
        key = MLDSAPrivateKey(alg_name="ml-dsa-44")
        sig = key.sign(b"payload")
        # Signature must verify under the cryptography native public key directly.
        crypto_pub = crypto_mldsa.MLDSA44PublicKey.from_public_bytes(key.public_key().public_bytes_raw())
        crypto_pub.verify(sig, b"payload")  # raises if invalid

    def test_sign_with_context(self):
        key = MLDSAPrivateKey(alg_name="ml-dsa-44")
        ctx = b"keyutils-py"
        sig = key.sign(b"payload", ctx=ctx)
        # round-trips through the wrapper public-key API
        key.public_key().verify(sig, b"payload", ctx=ctx)
        # and detects a bad context
        with self.assertRaises(InvalidSignature):
            key.public_key().verify(sig, b"payload", ctx=b"wrong-ctx")

    def test_prehashed_sign_skips_native(self):
        """Pre-hash bypasses the cryptography backend even when ``_native_key`` is set."""
        key = MLDSAPrivateKey(alg_name="ml-dsa-44")
        self.assertIsNotNone(key._native_key)
        # A hash_alg forces the FIPS / liboqs path. The signature must still verify.
        sig = key.sign(b"payload", hash_alg="sha512")
        key.public_key().verify(sig, b"payload", hash_alg="sha512")


class TestMLDSAPublicBackend(unittest.TestCase):
    """ML-DSA public keys *always* hold a cryptography native key for the supported set."""

    def test_native_pub_after_from_public_bytes(self):
        for name in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
            priv = MLDSAPrivateKey(alg_name=name)
            pub_raw = priv.public_key().public_bytes_raw()
            loaded = MLDSAPublicKey.from_public_bytes(data=pub_raw, name=name)
            self.assertIsNotNone(loaded._native_key)

    def test_verify_uses_native(self):
        priv = MLDSAPrivateKey(alg_name="ml-dsa-65")
        sig = priv.sign(b"data")
        pub = priv.public_key()
        self.assertIsNotNone(pub._native_key)
        pub.verify(sig, b"data")

    def test_verify_raises_invalid_signature(self):
        priv = MLDSAPrivateKey(alg_name="ml-dsa-44")
        sig = bytearray(priv.sign(b"data"))
        sig[0] ^= 0xFF
        with self.assertRaises(InvalidSignature):
            priv.public_key().verify(bytes(sig), b"data")


class TestMLKEMPrivateBackend(unittest.TestCase):
    """ML-KEM private keys go to cryptography when a seed is in scope; ml-kem-512 stays on FIPS."""

    def test_generate_holds_native_key_for_768_1024(self):
        for name in ("ml-kem-768", "ml-kem-1024"):
            key = MLKEMPrivateKey(alg_name=name)
            self.assertIsNotNone(key._native_key, name)
            self.assertIsNone(key._private_key_bytes, f"{name}: expanded bytes must be lazy")
            self.assertEqual(len(key._seed), 64)

    def test_ml_kem_512_does_not_use_native(self):
        key = MLKEMPrivateKey(alg_name="ml-kem-512")
        self.assertIsNone(key._native_key)
        # For ml-kem-512 the private bytes are populated eagerly by FIPS-203.
        self.assertEqual(len(key.private_bytes_raw()), ML_KEM_PRIVATE_KEY_SIZE["ml-kem-512"])

    def test_from_seed_holds_native_key(self):
        seed = os.urandom(64)
        key = MLKEMPrivateKey.from_seed(alg_name="ml-kem-1024", seed=seed)
        self.assertIsNotNone(key._native_key)
        self.assertEqual(key._seed, seed)

    def test_from_expanded_only_falls_back(self):
        seed_key = MLKEMPrivateKey.from_seed(alg_name="ml-kem-768", seed=os.urandom(64))
        expanded = seed_key.private_bytes_raw()
        loaded = MLKEMPrivateKey.from_private_bytes(data=expanded, name="ml-kem-768")
        self.assertIsNone(loaded._native_key)

    def test_lazy_private_bytes_match_fips_expansion(self):
        from keyutils_py.fips.fips203 import ML_KEM

        seed = os.urandom(64)
        key = MLKEMPrivateKey.from_seed(alg_name="ml-kem-768", seed=seed)
        _, expected = ML_KEM("ml-kem-768").keygen_internal(d=seed[:32], z=seed[32:])
        self.assertEqual(key.private_bytes_raw(), expected)

    def test_decaps_uses_native(self):
        key = MLKEMPrivateKey(alg_name="ml-kem-768")
        ss, ct = key.public_key().encaps()
        recovered = key.decaps(ct)
        self.assertEqual(ss, recovered)

    def test_native_decaps_interop_with_crypto_lib(self):
        """A cryptography-native ciphertext decaps correctly through the wrapper."""
        key = MLKEMPrivateKey(alg_name="ml-kem-1024")
        crypto_pub = crypto_mlkem.MLKEM1024PublicKey.from_public_bytes(
            key.public_key().public_bytes_raw()
        )
        ss, ct = crypto_pub.encapsulate()
        self.assertEqual(key.decaps(ct), ss)


class TestMLKEMPublicBackend(unittest.TestCase):
    """ML-KEM public keys hold cryptography natives for ml-kem-768/1024."""

    def test_native_pub_for_768_1024(self):
        for name in ("ml-kem-768", "ml-kem-1024"):
            priv = MLKEMPrivateKey(alg_name=name)
            pub = priv.public_key()
            self.assertIsNotNone(pub._native_key, name)

    def test_no_native_pub_for_512(self):
        priv = MLKEMPrivateKey(alg_name="ml-kem-512")
        pub = priv.public_key()
        self.assertIsNone(pub._native_key)

    def test_encaps_returns_ss_then_ct(self):
        priv = MLKEMPrivateKey(alg_name="ml-kem-768")
        ss, ct = priv.public_key().encaps()
        self.assertEqual(len(ss), 32)
        self.assertEqual(len(ct), priv.public_key().ct_length)


class TestPKCS8RoundTripAcrossBackends(unittest.TestCase):
    """PKCS#8 ``OneAsymmetricKey`` round-trips for each save_type, covering both backends."""

    def _roundtrip(self, alg, save_type):
        priv = PQKeyFactory.generate_pq_key(alg)
        der = PQKeyFactory.save_private_key_one_asym_key(
            private_key=priv, save_type=save_type, version=1
        )
        loaded = PQKeyFactory.from_one_asym_key(der)
        return priv, loaded

    def test_ml_dsa_seed_roundtrip_holds_native(self):
        priv, loaded = self._roundtrip("ml-dsa-44", KeySaveType.SEED)
        self.assertIsInstance(loaded, MLDSAPrivateKey)
        self.assertIsNotNone(loaded._native_key)
        self.assertEqual(loaded._seed, priv._seed)
        self.assertEqual(
            loaded.public_key().public_bytes_raw(),
            priv.public_key().public_bytes_raw(),
        )

    def test_ml_dsa_raw_roundtrip_falls_back(self):
        _, loaded = self._roundtrip("ml-dsa-44", KeySaveType.RAW)
        self.assertIsInstance(loaded, MLDSAPrivateKey)
        # No seed in the on-disk bytes → can't use cryptography backend.
        self.assertIsNone(loaded._native_key)

    def test_ml_dsa_seed_and_raw_roundtrip_uses_native(self):
        priv, loaded = self._roundtrip("ml-dsa-65", KeySaveType.SEED_AND_RAW)
        self.assertIsNotNone(loaded._native_key)
        self.assertEqual(loaded._seed, priv._seed)

    def test_ml_kem_seed_roundtrip_holds_native(self):
        priv, loaded = self._roundtrip("ml-kem-768", KeySaveType.SEED)
        self.assertIsInstance(loaded, MLKEMPrivateKey)
        self.assertIsNotNone(loaded._native_key)
        self.assertEqual(loaded._seed, priv._seed)

    def test_ml_kem_512_seed_roundtrip_no_native(self):
        priv, loaded = self._roundtrip("ml-kem-512", KeySaveType.SEED)
        self.assertIsInstance(loaded, MLKEMPrivateKey)
        self.assertIsNone(loaded._native_key)
        self.assertEqual(loaded._seed, priv._seed)


class TestCrossBackendInterop(unittest.TestCase):
    """A signature produced by one backend must verify under the other."""

    def test_native_sign_fips_verify_ml_dsa(self):
        priv = MLDSAPrivateKey(alg_name="ml-dsa-44")
        sig = priv.sign(b"interop")  # cryptography backend
        # Force the public key off the cryptography path and verify via FIPS.
        pub = priv.public_key()
        pub._native_key = None
        try:
            import keyutils_py.keys.abstract_pq as abstract_pq

            saved_oqs = abstract_pq.oqs
            abstract_pq.oqs = None
            try:
                pub.verify(sig, b"interop")
            finally:
                abstract_pq.oqs = saved_oqs
        finally:
            pass


class TestNoOqsFallback(unittest.TestCase):
    """Patch ``oqs`` to ``None`` across all key-class modules and confirm:

    * ML-DSA-44/65/87 sign / verify still works (via the ``cryptography`` backend).
    * ML-KEM-768/1024 encaps / decaps still works (via the ``cryptography`` backend).
    * ML-KEM-512 still works (via the bundled FIPS-203 reference).
    * Pre-hashed ML-DSA still works (via the bundled FIPS-204 reference).

    This is the "no liboqs installed" scenario after the cryptography backend
    is in place: most users never install the ``[pq]`` extra, so the cryptography
    path has to carry the load for the native algorithms.
    """

    def setUp(self):
        self._patches = [
            mock.patch(f"{module_path}.oqs", None)
            for module_path in (
                "keyutils_py.keys.abstract_pq",
                "keyutils_py.keys.sig_keys",
                "keyutils_py.keys.kem_keys",
            )
        ]
        for patcher in self._patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self._patches):
            patcher.stop()

    def test_ml_dsa_sign_verify_without_oqs(self):
        for name in ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87"):
            with self.subTest(alg=name):
                key = MLDSAPrivateKey(alg_name=name)
                self.assertIsNotNone(key._native_key, f"{name}: cryptography backend must take over when oqs is absent")
                sig = key.sign(b"keyutils-py without liboqs")
                key.public_key().verify(sig, b"keyutils-py without liboqs")

    def test_ml_kem_encaps_decaps_without_oqs(self):
        for name in ("ml-kem-768", "ml-kem-1024"):
            with self.subTest(alg=name):
                key = MLKEMPrivateKey(alg_name=name)
                self.assertIsNotNone(key._native_key, name)
                ss, ct = key.public_key().encaps()
                self.assertEqual(ss, key.decaps(ct))

    def test_ml_kem_512_falls_back_to_fips_when_oqs_absent(self):
        """``ml-kem-512`` has no cryptography backend; must succeed via FIPS-203."""
        key = MLKEMPrivateKey(alg_name="ml-kem-512")
        self.assertIsNone(key._native_key)
        ss, ct = key.public_key().encaps()
        self.assertEqual(ss, key.decaps(ct))

    def test_prehashed_ml_dsa_falls_back_to_fips_when_oqs_absent(self):
        """Pre-hash skips both cryptography (no API) and liboqs (patched out)."""
        key = MLDSAPrivateKey(alg_name="ml-dsa-44")
        sig = key.sign(b"prehash payload", hash_alg="sha512")
        key.public_key().verify(sig, b"prehash payload", hash_alg="sha512")


if __name__ == "__main__":
    unittest.main()
