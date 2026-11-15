# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``sign_data`` and ``verify_signature``, the functions that choose the algorithm from the key.

``cryptography`` is the independent oracle for RSA PKCS#1 v1.5, RSASSA-PSS and ECDSA: what ``sign_data`` makes must
verify there, and what ``cryptography`` makes must verify here.
"""

import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from keyutils_py import generate_key, sign_data, verify_signature
from keyutils_py.keys.sig_keys import MLDSAPrivateKey

DATA = b"keyutils-py sign and verify by name"
_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _pss(hash_name: str, salt_length: int, mgf_hash_name: str = "") -> padding.PSS:
    """Return the ``cryptography`` PSS padding for a message hash, an MGF1 hash and a salt length."""
    return padding.PSS(mgf=padding.MGF1(_HASHES[mgf_hash_name or hash_name]()), salt_length=salt_length)


class _RsaKeyTestCase(unittest.TestCase):
    """Test case with one RSA key for the whole class."""

    @classmethod
    def setUpClass(cls):
        """Generate the RSA key once."""
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub = cls.key.public_key()


class TestRsaPkcs1v15ByName(_RsaKeyTestCase):
    """RSA PKCS#1 v1.5 signatures by name; before, ``sign_data`` and ``verify_signature`` had no RSA branch."""

    def test_sign_here_verify_with_cryptography(self):
        """GIVEN an RSA key / WHEN sign_data with each hash / THEN cryptography verifies the PKCS#1 v1.5 signature."""
        for name, hash_cls in _HASHES.items():
            with self.subTest(hash=name):
                signature = sign_data(DATA, self.key, hash_alg=name)
                self.pub.verify(signature, DATA, padding.PKCS1v15(), hash_cls())

    def test_sign_with_cryptography_verify_here(self):
        """GIVEN a PKCS#1 v1.5 signature made by cryptography / WHEN verify_signature / THEN it verifies."""
        for name, hash_cls in _HASHES.items():
            with self.subTest(hash=name):
                signature = self.key.sign(DATA, padding.PKCS1v15(), hash_cls())
                verify_signature(self.pub, signature, DATA, hash_alg=name)

    def test_wrong_hash_or_data_is_an_invalid_signature(self):
        """GIVEN a SHA-256 signature / WHEN verified with SHA-384 or other data / THEN InvalidSignature."""
        signature = sign_data(DATA, self.key, hash_alg="sha256")
        with self.assertRaises(InvalidSignature):
            verify_signature(self.pub, signature, DATA, hash_alg="sha384")
        with self.assertRaises(InvalidSignature):
            verify_signature(self.pub, signature, DATA + b"x", hash_alg="sha256")

    def test_pkcs1_is_deterministic(self):
        """GIVEN the same key, data and hash / WHEN signed twice / THEN the signatures are equal (no salt)."""
        self.assertEqual(sign_data(DATA, self.key, hash_alg="sha256"), sign_data(DATA, self.key, hash_alg="sha256"))


class TestRsaPssByName(_RsaKeyTestCase):
    """RSASSA-PSS by name: hash, salt length 0 and the SHAKE variants."""

    def test_default_salt_is_the_digest_size_and_interoperates(self):
        """GIVEN use_rsa_pss with sha256 and sha384 / WHEN signed / THEN cryptography verifies with the digest salt."""
        for name, size in (("sha256", 32), ("sha384", 48)):
            with self.subTest(hash=name):
                signature = sign_data(DATA, self.key, hash_alg=name, use_rsa_pss=True)
                self.pub.verify(signature, DATA, _pss(name, size), _HASHES[name]())
                verify_signature(self.pub, signature, DATA, hash_alg=name, use_rsa_pss=True)

    def test_cryptography_signature_verifies_here(self):
        """GIVEN a PSS signature made by cryptography with sha384 / WHEN verify_signature / THEN it verifies."""
        signature = self.key.sign(DATA, _pss("sha384", 48), hashes.SHA384())
        verify_signature(self.pub, signature, DATA, hash_alg="sha384", use_rsa_pss=True)

    def test_salt_length_zero_is_signed_and_verified(self):
        """GIVEN salt_length=0 / WHEN signed / THEN cryptography verifies with salt 0 and not with the digest size."""
        signature = sign_data(DATA, self.key, hash_alg="sha256", use_rsa_pss=True, salt_length=0)
        self.pub.verify(signature, DATA, _pss("sha256", 0), hashes.SHA256())
        with self.assertRaises(InvalidSignature):
            self.pub.verify(signature, DATA, _pss("sha256", 32), hashes.SHA256())
        verify_signature(self.pub, signature, DATA, hash_alg="sha256", use_rsa_pss=True, salt_length=0)
        with self.assertRaises(InvalidSignature):  # the default salt of the verifier is the digest size
            verify_signature(self.pub, signature, DATA, hash_alg="sha256", use_rsa_pss=True)

    def test_salt_zero_signature_of_cryptography_verifies_here(self):
        """GIVEN a salt 0 signature of cryptography / WHEN verify_signature with salt_length=0 / THEN it verifies."""
        signature = self.key.sign(DATA, _pss("sha256", 0), hashes.SHA256())
        verify_signature(self.pub, signature, DATA, hash_alg="sha256", use_rsa_pss=True, salt_length=0)

    def test_other_salt_lengths(self):
        """GIVEN salt lengths 20 and 48 / WHEN signed with sha256 / THEN cryptography verifies each with that salt."""
        for salt in (20, 48):
            with self.subTest(salt=salt):
                signature = sign_data(DATA, self.key, hash_alg="sha256", use_rsa_pss=True, salt_length=salt)
                self.pub.verify(signature, DATA, _pss("sha256", salt), hashes.SHA256())

    def test_mgf1_hash_can_differ_for_negative_tests(self):
        """GIVEN second_hash_alg / WHEN signed / THEN the MGF1 hash is the first and the message hash the second."""
        signature = sign_data(DATA, self.key, hash_alg="sha256", use_rsa_pss=True, second_hash_alg="sha512")
        self.pub.verify(signature, DATA, _pss("sha512", 32, mgf_hash_name="sha256"), hashes.SHA512())

    def test_shake_pss_round_trip_and_wrong_salt(self):
        """GIVEN RSASSA-PSS-SHAKE128 and -SHAKE256 / WHEN signed and verified by name / THEN they round-trip."""
        for name in ("shake128", "shake256"):
            with self.subTest(hash=name):
                signature = sign_data(DATA, self.key, hash_alg=name, use_rsa_pss=True)
                verify_signature(self.pub, signature, DATA, hash_alg=name, use_rsa_pss=True)
                with self.assertRaises(InvalidSignature):
                    verify_signature(self.pub, signature, DATA, hash_alg=name, use_rsa_pss=True, salt_length=7)
                with self.assertRaises(InvalidSignature):
                    verify_signature(self.pub, signature, DATA + b"x", hash_alg=name, use_rsa_pss=True)

    def test_shake_pss_salt_length_zero(self):
        """GIVEN SHAKE256 with salt_length=0 / WHEN signed and verified / THEN it round-trips with salt 0 only."""
        signature = sign_data(DATA, self.key, hash_alg="shake256", use_rsa_pss=True, salt_length=0)
        verify_signature(self.pub, signature, DATA, hash_alg="shake256", use_rsa_pss=True, salt_length=0)
        with self.assertRaises(InvalidSignature):
            verify_signature(self.pub, signature, DATA, hash_alg="shake256", use_rsa_pss=True)

    def test_pss_signature_is_not_a_pkcs1_signature(self):
        """GIVEN a PSS signature / WHEN verified as PKCS#1 v1.5 / THEN InvalidSignature."""
        signature = sign_data(DATA, self.key, hash_alg="sha256", use_rsa_pss=True)
        with self.assertRaises(InvalidSignature):
            verify_signature(self.pub, signature, DATA, hash_alg="sha256")


class TestNoSilentHashDefault(_RsaKeyTestCase):
    """A family that needs a hash raises ValueError without ``hash_alg`` instead of signing with SHA-256."""

    @classmethod
    def setUpClass(cls):
        """Generate one key per hashing family."""
        super().setUpClass()
        cls.ec = ec.generate_private_key(ec.SECP256R1())
        cls.dsa = generate_key("dsa")

    def test_sign_data_needs_a_hash(self):
        """GIVEN RSA, RSA-PSS, ECDSA and DSA keys / WHEN sign_data has no hash_alg / THEN ValueError."""
        cases = {"rsa": {}, "rsa-pss": {"use_rsa_pss": True}, "ecdsa": {}, "dsa": {}}
        keys = {"rsa": self.key, "rsa-pss": self.key, "ecdsa": self.ec, "dsa": self.dsa}
        for name, kwargs in cases.items():
            with self.subTest(key=name), self.assertRaisesRegex(ValueError, "hash"):
                sign_data(DATA, keys[name], **kwargs)

    def test_verify_signature_needs_a_hash(self):
        """GIVEN a SHA-384 ECDSA signature / WHEN verified without hash_alg / THEN ValueError, not InvalidSignature."""
        signature = sign_data(DATA, self.ec, hash_alg="sha384")
        with self.assertRaisesRegex(ValueError, "hash"):
            verify_signature(self.ec.public_key(), signature, DATA)
        with self.assertRaisesRegex(ValueError, "hash"):
            verify_signature(self.pub, b"\x00", DATA)
        with self.assertRaisesRegex(ValueError, "hash"):
            verify_signature(self.dsa.public_key(), b"\x00", DATA)

    def test_families_without_a_hash_need_none(self):
        """GIVEN Ed25519, ML-DSA and HSS keys / WHEN signed without hash_alg / THEN they sign and verify."""
        for name in ("ed25519", "ml-dsa-44", "hss"):
            with self.subTest(key=name):
                key = generate_key(name)
                verify_signature(key.public_key(), sign_data(DATA, key), DATA)

    def test_ecdsa_interoperates_with_cryptography(self):
        """GIVEN an ECDSA key / WHEN signed by name and by cryptography / THEN each verifies in the other."""
        signature = sign_data(DATA, self.ec, hash_alg="sha384")
        self.ec.public_key().verify(signature, DATA, ec.ECDSA(hashes.SHA384()))
        verify_signature(self.ec.public_key(), self.ec.sign(DATA, ec.ECDSA(hashes.SHA512())), DATA, hash_alg="sha512")


class TestKeywordOptions(_RsaKeyTestCase):
    """The options are keyword-only and an unknown keyword is an error, not silently ignored."""

    def test_unknown_keyword_is_a_type_error(self):
        """GIVEN a misspelled option / WHEN sign_data or verify_signature is called / THEN TypeError."""
        signature = sign_data(DATA, self.key, hash_alg="sha256")
        with self.assertRaises(TypeError):
            sign_data(DATA, self.key, hash_algo="sha256")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            verify_signature(self.pub, signature, DATA, hash_algo="sha256")  # type: ignore[call-arg]

    def test_options_are_keyword_only(self):
        """GIVEN hash_alg passed by position / WHEN sign_data or verify_signature is called / THEN TypeError."""
        signature = sign_data(DATA, self.key, hash_alg="sha256")
        with self.assertRaises(TypeError):
            sign_data(DATA, self.key, "sha256")  # type: ignore[misc]
        with self.assertRaises(TypeError):
            verify_signature(self.pub, signature, DATA, "sha256")  # type: ignore[misc]

    def test_composite_use_pss_keyword_is_gone(self):
        """GIVEN the old composite keyword use_pss / WHEN passed / THEN TypeError (it is use_rsa_pss now)."""
        key = generate_key("composite-sig-ml-dsa-44-ed25519")
        with self.assertRaises(TypeError):
            sign_data(DATA, key, use_pss=True)  # type: ignore[call-arg]


class TestCompositeByName(unittest.TestCase):
    """Composite signatures take ``use_rsa_pss`` and ``ctx`` through the same functions as every other key."""

    @classmethod
    def setUpClass(cls):
        """Generate a composite key with an RSA half and one with an EC half."""
        cls.rsa_key = generate_key("composite-sig-ml-dsa-44-rsa2048-pss")
        cls.ec_key = generate_key("composite-sig-ml-dsa-44-ecdsa-secp256r1")

    def test_use_rsa_pss_selects_the_pss_variant(self):
        """GIVEN an RSA composite key / WHEN signed with use_rsa_pss / THEN only a PSS verification succeeds."""
        signature = sign_data(DATA, self.rsa_key, use_rsa_pss=True)
        verify_signature(self.rsa_key.public_key(), signature, DATA, use_rsa_pss=True)
        with self.assertRaises(InvalidSignature):
            verify_signature(self.rsa_key.public_key(), signature, DATA)

    def test_default_is_pkcs1v15(self):
        """GIVEN an RSA composite key / WHEN signed without use_rsa_pss / THEN the PKCS#1 v1.5 variant is signed."""
        signature = sign_data(DATA, self.rsa_key)
        verify_signature(self.rsa_key.public_key(), signature, DATA)
        with self.assertRaises(InvalidSignature):
            verify_signature(self.rsa_key.public_key(), signature, DATA, use_rsa_pss=True)

    def test_ctx_is_part_of_the_signature(self):
        """GIVEN ctx=b'x' / WHEN verified with the same, another and no ctx / THEN only the same ctx verifies."""
        signature = sign_data(DATA, self.ec_key, ctx=b"x")
        verify_signature(self.ec_key.public_key(), signature, DATA, ctx=b"x")
        for ctx in (b"y", b""):
            with self.subTest(ctx=ctx), self.assertRaises(InvalidSignature):
                verify_signature(self.ec_key.public_key(), signature, DATA, ctx=ctx)

    def test_hash_alg_is_accepted_and_ignored(self):
        """GIVEN a composite key and hash_alg / WHEN signed / THEN the draft's pre-hash is used, not hash_alg."""
        signature = sign_data(DATA, self.ec_key, hash_alg="sha384")
        verify_signature(self.ec_key.public_key(), signature, DATA)


class TestPostQuantumByName(unittest.TestCase):
    """ML-DSA keeps its ``ctx`` and ``hash_alg`` (HashML-DSA) options."""

    def test_ml_dsa_ctx_and_pre_hash(self):
        """GIVEN ML-DSA with ctx and sha512 / WHEN signed and verified / THEN the options must match."""
        key = generate_key("ml-dsa-44")
        self.assertIsInstance(key, MLDSAPrivateKey)
        signature = sign_data(DATA, key, ctx=b"c", hash_alg="sha512")
        verify_signature(key.public_key(), signature, DATA, ctx=b"c", hash_alg="sha512")
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), signature, DATA, ctx=b"c")
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), signature, DATA, hash_alg="sha512")

    def test_ed25519_ignores_hash_alg(self):
        """GIVEN an Ed25519 key / WHEN signed with a hash_alg / THEN cryptography verifies the plain signature."""
        key = ed25519.Ed25519PrivateKey.generate()
        signature = sign_data(DATA, key, hash_alg="sha256")
        key.public_key().verify(signature, DATA)


if __name__ == "__main__":
    unittest.main()
