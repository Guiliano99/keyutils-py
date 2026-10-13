# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pycryptodome-backed DSA wrapper in ``keyutils_py.keys.trad_keys``."""

import os
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from keyutils_py.compute import sign_data, sign_with_alg_id, verify_signature
from keyutils_py.data import TRAD_KEYS_DIR
from keyutils_py.exceptions import BadAlg
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.key_pyasn1_utils import (
    MAX_PBKDF2_ITERATIONS,
    decrypt_private_key_pkcs8,
    encrypt_private_key_pkcs8,
)
from keyutils_py.keys.trad_keys import DSAPrivateKey, DSAPublicKey, to_pycryptodome_hash
from keyutils_py.keyutils import (
    get_key_name,
    load_private_key_from_file,
    load_public_key_from_file,
    prepare_sig_alg_id,
)
from keyutils_py.utils import encode_to_der, try_decode_pyasn1
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5208, rfc5280, rfc5480, rfc8018

try:  # cryptography still ships DSA today; the cross-checks vanish with it.
    from cryptography.hazmat.primitives.asymmetric import dsa as crypto_dsa
except ImportError:  # pragma: no cover
    crypto_dsa = None

FIXTURE = os.path.join(TRAD_KEYS_DIR, "private-key-dsa-2048.pem")
DATA = b"keyutils-py dsa wrapper"


def _fixture_key() -> DSAPrivateKey:
    with open(FIXTURE, "rb") as fh:
        return DSAPrivateKey.load(fh.read())


class TestFixtureLoad(unittest.TestCase):
    """The bundled PEM was written by ``cryptography`` and must load as-is."""

    def test_load_private_key(self):
        """GIVEN the cryptography-written PKCS#8 PEM / WHEN loaded / THEN a 2048-bit wrapper key."""
        key = _fixture_key()
        self.assertIsInstance(key, DSAPrivateKey)
        self.assertEqual(key.key_size, 2048)
        self.assertEqual(key.public_key().q.bit_length(), 256)

    def test_load_private_key_from_file(self):
        """GIVEN the fixture path / WHEN loaded via keyutils / THEN the DSA branch is taken."""
        key = load_private_key_from_file(FIXTURE, password=None)
        self.assertIsInstance(key, DSAPrivateKey)
        self.assertEqual(key.x, _fixture_key().x)

    def test_load_encrypted_private_key_from_file(self):
        """GIVEN a wrapper-encrypted PEM / WHEN loaded via keyutils' default password / THEN same key."""
        key = _fixture_key()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dsa.enc.pem")
            with open(path, "wb") as fh:
                fh.write(
                    key.private_bytes(
                        Encoding.PEM, PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"11111")
                    )
                )
            loaded = load_private_key_from_file(path)  # default password "11111"
        self.assertIsInstance(loaded, DSAPrivateKey)
        self.assertEqual(loaded.x, key.x)

    def test_load_public_key_from_file(self):
        """GIVEN an SPKI PEM / WHEN loaded via keyutils / THEN equals the fixture's public key."""
        pub = _fixture_key().public_key()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dsa.pub.pem")
            with open(path, "wb") as fh:
                fh.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            self.assertEqual(load_public_key_from_file(path), pub)

    def test_get_key_name(self):
        """GIVEN the wrapper key / WHEN named / THEN resolves to ``dsa`` via the class-name mapping."""
        key = _fixture_key()
        self.assertEqual(get_key_name(key), "dsa")
        self.assertEqual(get_key_name(key.public_key()), "dsa")


class TestSignVerify(unittest.TestCase):
    """Sign / verify go through pycryptodome and accept both hash spellings."""

    @classmethod
    def setUpClass(cls):
        """Load the fixture key once per class."""
        cls.key = _fixture_key()

    def test_str_hash(self):
        """GIVEN ``"sha256"`` / WHEN signing and verifying / THEN verify passes."""
        sig = self.key.sign(DATA, "sha256")
        self.key.public_key().verify(sig, DATA, "sha256")

    def test_hash_algorithm_instance(self):
        """GIVEN ``hashes.SHA256()`` / WHEN signing / THEN the str-named verify accepts it and vice versa."""
        sig = self.key.sign(DATA, hashes.SHA256())
        self.key.public_key().verify(sig, DATA, "sha256")
        self.key.public_key().verify(self.key.sign(DATA), DATA, hashes.SHA256())

    def test_tampered_raises_invalid_signature(self):
        """GIVEN a bit-flipped message / WHEN verifying / THEN cryptography's InvalidSignature."""
        sig = self.key.sign(DATA)
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(sig, DATA + b"x")

    def test_unsupported_hash_rejected(self):
        """GIVEN a non-DSA hash / WHEN converting / THEN ValueError."""
        with self.assertRaises(ValueError):
            to_pycryptodome_hash("shake128", DATA)

    @unittest.skipIf(crypto_dsa is None, "cryptography no longer ships DSA")
    def test_cross_verify_with_cryptography(self):
        """GIVEN both backends / WHEN each signs / THEN the other verifies (DER Dss-Sig-Value)."""
        with open(FIXTURE, "rb") as fh:
            legacy = serialization.load_pem_private_key(fh.read(), password=None)
        legacy.public_key().verify(self.key.sign(DATA), DATA, hashes.SHA256())
        self.key.public_key().verify(legacy.sign(DATA, hashes.SHA256()), DATA)

    def test_compute_dispatch(self):
        """GIVEN sign_data / verify_signature / WHEN given the wrapper / THEN both dispatch to it."""
        sig = sign_data(DATA, self.key, hash_alg="sha1")
        verify_signature(self.key.public_key(), sig, DATA, hash_alg="sha1")
        with self.assertRaises(InvalidSignature):
            verify_signature(self.key.public_key(), sig, DATA)  # wrong default hash

    def test_sign_with_alg_id_still_rejected(self):
        """GIVEN an alg_id / WHEN signing with a DSA key / THEN BadAlg as before."""
        with self.assertRaises(BadAlg):
            sign_with_alg_id(self.key, prepare_sig_alg_id(self.key, "sha256"), DATA)


class TestSerialization(unittest.TestCase):
    """cryptography-style ``*_bytes`` with DER / PEM / encrypted round-trips."""

    @classmethod
    def setUpClass(cls):
        """Load the fixture key once per class."""
        cls.key = _fixture_key()

    def test_pkcs8_roundtrip(self):
        """GIVEN PKCS#8 DER and PEM / WHEN reloaded / THEN same private value."""
        for enc in (Encoding.DER, Encoding.PEM):
            data = self.key.private_bytes(enc, PrivateFormat.PKCS8, serialization.NoEncryption())
            self.assertEqual(DSAPrivateKey.load(data).x, self.key.x)
        self.assertTrue(self.key.private_bytes().endswith(b"-----END PRIVATE KEY-----\n"))

    def test_traditional_openssl_pem(self):
        """GIVEN TraditionalOpenSSL / WHEN exported / THEN ``DSA PRIVATE KEY`` block that reloads."""
        data = self.key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL)
        self.assertTrue(data.startswith(b"-----BEGIN DSA PRIVATE KEY-----"))
        self.assertEqual(DSAPrivateKey.load(data).x, self.key.x)

    def test_encrypted_pem_roundtrip(self):
        """GIVEN BestAvailableEncryption / WHEN reloaded with the password / THEN same key."""
        data = self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))
        self.assertTrue(data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertEqual(DSAPrivateKey.load(data, password=b"pw").x, self.key.x)
        with self.assertRaises(ValueError):
            self.key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))

    def test_unknown_encryption_fails_closed(self):
        """GIVEN an unsupported encryption object / WHEN serialising / THEN ValueError, never plaintext."""

        class _Other(serialization.KeySerializationEncryption):
            pass

        for encoding in (Encoding.PEM, Encoding.DER):
            with self.assertRaises(ValueError):
                self.key.private_bytes(encoding, PrivateFormat.PKCS8, _Other())

    def test_spki_roundtrip(self):
        """GIVEN SPKI DER and PEM / WHEN reloaded / THEN equal and carries id-dsa."""
        pub = self.key.public_key()
        der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(DSAPublicKey.load(der), pub)
        self.assertEqual(DSAPublicKey.load(pub.public_bytes(Encoding.PEM)), pub)
        spki, _ = try_decode_pyasn1(der, rfc5280.SubjectPublicKeyInfo())
        self.assertEqual(spki["algorithm"]["algorithm"], rfc5480.id_dsa)

    def test_public_cannot_masquerade_as_private(self):
        """GIVEN a public PEM / WHEN loaded as private / THEN ValueError."""
        with self.assertRaises(ValueError):
            DSAPrivateKey.load(self.key.public_key().public_bytes())


def _tamper_pbkdf2(enc_der: bytes, iterations=None, key_length=None) -> bytes:
    """Rewrite the PBKDF2 parameters inside a PBES2 EncryptedPrivateKeyInfo."""
    enc_pki, _ = try_decode_pyasn1(enc_der, rfc5208.EncryptedPrivateKeyInfo())
    pbes2, _ = try_decode_pyasn1(enc_pki["encryptionAlgorithm"]["parameters"], rfc8018.PBES2_params())
    kdf = pbes2["keyDerivationFunc"]
    params, _ = try_decode_pyasn1(kdf["parameters"], rfc8018.PBKDF2_params())
    if iterations is not None:
        params["iterationCount"] = iterations
    if key_length is not None:
        params["keyLength"] = key_length
    kdf["parameters"] = univ.Any(encode_to_der(params))
    enc_pki["encryptionAlgorithm"]["parameters"] = univ.Any(encode_to_der(pbes2))
    return encode_to_der(enc_pki)


class TestPbkdf2Limits(unittest.TestCase):
    """Untrusted PBKDF2 parameters must be rejected before any key derivation runs."""

    def setUp(self):
        """Encrypt the fixture key with a cheap iteration count."""
        self.enc = encrypt_private_key_pkcs8(_fixture_key().private_bytes(Encoding.DER), b"pw", iterations=1000)

    def test_valid_file_still_decrypts(self):
        """GIVEN a normal encrypted key / WHEN decrypted / THEN the PKCS#8 DER comes back."""
        self.assertTrue(decrypt_private_key_pkcs8(self.enc, b"pw"))

    def test_excessive_iterations_rejected(self):
        """GIVEN iterationCount above the cap / WHEN decrypting / THEN ValueError (fast, no PBKDF2)."""
        bad = _tamper_pbkdf2(self.enc, iterations=MAX_PBKDF2_ITERATIONS + 1)
        with self.assertRaisesRegex(ValueError, "iteration count"):
            decrypt_private_key_pkcs8(bad, b"pw")

    def test_wrong_key_length_rejected(self):
        """GIVEN keyLength != 32 / WHEN decrypting / THEN ValueError instead of a silent cipher downgrade."""
        bad = _tamper_pbkdf2(self.enc, key_length=16)
        with self.assertRaisesRegex(ValueError, "keyLength"):
            decrypt_private_key_pkcs8(bad, b"pw")

    def test_dsa_load_uses_same_limits(self):
        """GIVEN a tampered encrypted DSA PEM / WHEN loaded with a password / THEN ValueError."""
        import base64

        bad = base64.b64encode(_tamper_pbkdf2(self.enc, iterations=MAX_PBKDF2_ITERATIONS + 1)).decode()
        pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{bad}\n-----END ENCRYPTED PRIVATE KEY-----\n".encode()
        with self.assertRaisesRegex(ValueError, "iteration count"):
            DSAPrivateKey.load(pem, password=b"pw")


class TestGenerate(unittest.TestCase):
    """Generation goes through pycryptodome, including the factory path."""

    def test_factory_returns_wrapper(self):
        """GIVEN ``generate_trad_key("dsa")`` / WHEN called / THEN a wrapper key of the requested size."""
        key = TradKeyFactory.generate_trad_key("dsa", length=1024)
        self.assertIsInstance(key, DSAPrivateKey)
        self.assertEqual(key.key_size, 1024)
        key.public_key().verify(key.sign(DATA), DATA)

    def test_unsupported_size(self):
        """GIVEN 4096 bits / WHEN generating / THEN pycryptodome's ValueError propagates."""
        with self.assertRaises(ValueError):
            DSAPrivateKey.generate(4096)


if __name__ == "__main__":
    unittest.main()
