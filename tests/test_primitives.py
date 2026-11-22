# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``keyutils_py.primitives``, the keyless lower layer, and for its exceptions.

External vectors, so that a shared misreading cannot pass both sides (the source of each is named where it is used):

* RFC 5869 Appendix A.1 to A.3 (HKDF-SHA-256), HKDF with SHA-3 against a ten-line reference built on ``hmac``.
* RFC 6070 (PBKDF2-HMAC-SHA-1), RFC 7914 Section 11 (PBKDF2-HMAC-SHA-256), all hashes against ``hashlib``.
* X9.63 (KDF2) against ``cryptography``'s ``X963KDF`` and a ``hashlib`` reference; KDF3 against RFC 9690 Appendix D.1.
* RFC 2202 and RFC 4231 (HMAC test case 1), ``hmac`` for every hash.
* NIST SP 800-185 KMAC samples 1 to 6, GCM specification (McGrew and Viega) test cases 1, 2, 4, 7 and 13 for GMAC and
  GCM, NIST SP 800-38A F.2.1 for CBC, F.2.1 to F.2.6 for CBC without padding.
* RFC 3394 Section 4.1 to 4.6 (AES key wrap) and RFC 5649 Section 6 (key wrap with padding).
"""

import ast
import hashlib
import hmac
import sys
import unittest
from pathlib import Path

import keyutils_py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from keyutils_py import primitives
from keyutils_py.exceptions import BadAlg, BadAlgParams, IntegrityError, KeyUtilsError

_HASHES = ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512")
_CRYPTOGRAPHY_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha3_224": hashes.SHA3_224,
    "sha3_256": hashes.SHA3_256,
    "sha3_384": hashes.SHA3_384,
    "sha3_512": hashes.SHA3_512,
}


def _hkdf_reference(hash_name: str, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Section 2 with ``hmac``: extract, then expand."""
    digest_size = hashlib.new(hash_name).digest_size
    prk = hmac.new(salt or bytes(digest_size), ikm, hash_name).digest()
    okm, block = b"", b""
    for counter in range(1, -(-length // digest_size) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hash_name).digest()
        okm += block
    return okm[:length]


class TestExceptions(unittest.TestCase):
    """``BadAlgParams`` and ``IntegrityError`` are errors of the package, nothing more specific."""

    def test_new_exceptions_derive_directly_from_the_package_error(self):
        """GIVEN the two new classes / WHEN their bases are read / THEN both derive from KeyUtilsError only."""
        self.assertEqual(BadAlgParams.__bases__, (KeyUtilsError,))
        self.assertEqual(IntegrityError.__bases__, (KeyUtilsError,))
        self.assertFalse(issubclass(BadAlgParams, BadAlg))

    def test_new_exceptions_carry_the_message(self):
        """GIVEN a message / WHEN raised and caught as the package error / THEN the message is kept."""
        for error in (BadAlgParams, IntegrityError):
            with self.assertRaisesRegex(KeyUtilsError, "text"):
                raise error("text")


class TestBoundary(unittest.TestCase):
    """The lower layer imports cryptography, pycryptodome and ``keyutils_py.exceptions`` only."""

    def test_imports_are_cryptography_pycryptodome_and_exceptions_only(self):
        """GIVEN the source of primitives / WHEN its imports are read / THEN only the allowed packages occur."""
        tree = ast.parse(Path(primitives.__file__).read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "no relative imports")
                imported.append(node.module or "")
        self.assertTrue(imported)
        for name in imported:
            root = name.split(".")[0]
            allowed = root in ("cryptography", "Crypto", "__future__") or root in sys.stdlib_module_names
            allowed = allowed or name == "keyutils_py.exceptions"
            self.assertTrue(allowed, f"primitives imports {name}")

    def test_is_importable_but_not_public(self):
        """GIVEN the package / WHEN __all__ is read / THEN primitives is importable but not in the public API."""
        own = {
            name for name, value in vars(primitives).items() if getattr(value, "__module__", "") == primitives.__name__
        }
        self.assertIn("hkdf", own)
        self.assertNotIn("primitives", keyutils_py.__all__)
        # The one exception: key-wrap constructions above keyutils (RFC 3211 Section 2.3) need unpadded CBC.
        self.assertEqual(own & set(keyutils_py.__all__), {"aes_cbc_encrypt_no_padding", "aes_cbc_decrypt_no_padding"})

    def test_hash_names_are_the_names_of_the_hash_registry(self):
        """GIVEN the hash names of primitives / WHEN compared with the registry / THEN the registry minus SHAKE."""
        from keyutils_py.oids import _HASH_REGISTRY

        self.assertEqual(set(primitives._HASHES), {name for name in _HASH_REGISTRY if not name.startswith("shake")})


class TestHashNames(unittest.TestCase):
    """A hash is named by a string; a name that is no fixed-output hash is ``BadAlg``."""

    def test_unknown_and_xof_names_raise_bad_alg(self):
        """GIVEN an unknown name, SHAKE or a wrong case / WHEN a function resolves it / THEN BadAlg."""
        for name in ("md5", "shake128", "shake256", "SHA256", "sha-256", ""):
            with self.subTest(name=name):
                with self.assertRaises(BadAlg):
                    primitives.hkdf(name, b"k", 16)
                with self.assertRaises(BadAlg):
                    primitives.kdf2(name, b"k", 16)
                with self.assertRaises(BadAlg):
                    primitives.kdf3(name, b"k", 16)
                with self.assertRaises(BadAlg):
                    primitives.pbkdf2(name, b"k", b"s", 1, 16)
                with self.assertRaises(BadAlg):
                    primitives.hmac_digest(name, b"k", b"d")


class TestHkdf(unittest.TestCase):
    """HKDF: RFC 5869 Appendix A, and the SHA-3 hashes against an independent reference."""

    def test_rfc_5869_a1_basic(self):
        """GIVEN RFC 5869 A.1 / WHEN derived / THEN the OKM of the RFC."""
        okm = primitives.hkdf(
            "sha256",
            bytes([0x0B]) * 22,
            42,
            bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            bytes.fromhex("000102030405060708090a0b0c"),
        )
        self.assertEqual(
            okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )

    def test_rfc_5869_a2_longer_inputs(self):
        """GIVEN RFC 5869 A.2 (80 octets each) / WHEN derived / THEN the 82 octets of the RFC."""
        okm = primitives.hkdf(
            "sha256", bytes(range(0x00, 0x50)), 82, bytes(range(0xB0, 0x100)), bytes(range(0x60, 0xB0))
        )
        self.assertEqual(
            okm.hex(),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        )

    def test_rfc_5869_a3_zero_length_salt_and_info(self):
        """GIVEN RFC 5869 A.3 / WHEN derived without salt and info / THEN the OKM of the RFC."""
        okm = primitives.hkdf("sha256", bytes([0x0B]) * 22, 42)
        self.assertEqual(
            okm.hex(), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )
        self.assertEqual(primitives.hkdf("sha256", bytes([0x0B]) * 22, 42, b"", b""), okm)

    def test_every_hash_equals_the_reference(self):
        """GIVEN each hash incl. SHA-3 / WHEN derived / THEN equal to RFC 5869 written with hmac, salt or not."""
        ikm, info, salt = bytes(range(40)), b"context", b"salty"
        for name in _HASHES:
            for length in (1, 32, 100):
                with self.subTest(hash=name, length=length):
                    self.assertEqual(
                        primitives.hkdf(name, ikm, length, info, salt), _hkdf_reference(name, ikm, salt, info, length)
                    )
                    self.assertEqual(
                        primitives.hkdf(name, ikm, length, info), _hkdf_reference(name, ikm, b"", info, length)
                    )

    def test_too_long_output_is_a_value_error(self):
        """GIVEN more than 255 blocks / WHEN derived / THEN ValueError (RFC 5869 Section 2.3)."""
        with self.assertRaises(ValueError):
            primitives.hkdf("sha256", b"k", 255 * 32 + 1)


class TestKdf2AndKdf3(unittest.TestCase):
    """KDF2 is X9.63 (counter after Z), KDF3 puts the counter first (RFC 9690 Appendix B)."""

    Z = bytes(range(32))
    INFO = b"shared-info" * 4

    @staticmethod
    def _reference(hash_name: str, z: bytes, info: bytes, length: int, counter_first: bool) -> bytes:
        """Return Hash(counter || Z || info) or Hash(Z || counter || info) over the counters 1, 2, ..."""
        out = b""
        for counter in range(1, -(-length // hashlib.new(hash_name).digest_size) + 1):
            c = counter.to_bytes(4, "big")
            out += hashlib.new(hash_name, (c + z if counter_first else z + c) + info).digest()
        return out[:length]

    def test_kdf2_equals_the_x963_kdf_of_cryptography(self):
        """GIVEN SHA-1/224/256/384/512 and SHA3-256 at 16, 32, 70 octets / WHEN derived / THEN equal to X963KDF."""
        for name in ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256"):
            for length in (16, 32, 70):
                with self.subTest(hash=name, length=length):
                    expected = X963KDF(_CRYPTOGRAPHY_HASHES[name](), length, self.INFO).derive(self.Z)
                    self.assertEqual(primitives.kdf2(name, self.Z, length, self.INFO), expected)

    def test_kdf2_and_kdf3_equal_a_hashlib_reference_for_every_hash(self):
        """GIVEN each hash incl. SHA-3 / WHEN derived / THEN equal to the textbook definition, empty info too."""
        for name in _HASHES:
            for info in (b"", self.INFO):
                with self.subTest(hash=name, info=len(info)):
                    self.assertEqual(
                        primitives.kdf2(name, self.Z, 70, info), self._reference(name, self.Z, info, 70, False)
                    )
                    self.assertEqual(
                        primitives.kdf3(name, self.Z, 70, info), self._reference(name, self.Z, info, 70, True)
                    )

    def test_kdf2_and_kdf3_differ(self):
        """GIVEN the same input / WHEN derived with both / THEN the outputs differ (the counter position)."""
        self.assertNotEqual(primitives.kdf2("sha256", self.Z, 32), primitives.kdf3("sha256", self.Z, 32))

    def test_kdf3_rfc_9690_appendix_d1(self):
        """GIVEN the example of RFC 9690 D.1 / WHEN KDF3-SHA-256 runs / THEN SS and, over SS and info, the KEK."""
        z = bytes.fromhex(
            "9c126102a5c1c0354672a3c2f19fc9ddea988f815e1da812c7bd4f8eb082bdd14f85a7f7c2f1af11d5333e0d6bcb375b"
            "f855f208da72ba27e6fb0655f2825aa62b93b1f9bbd3491fed58f0380fa0de36430e3a144d569600bd362609be5b9481"
            "0875990b614e406fa6dff500043cbca95968faba61f795096a7fb3687a51078c4ca2cb663366b0bea0cd9cccac72a25f"
            "3f4ed03deb68b4453bba44b943f4367b67d6cd10c8ace53f545aac50968fc3c6ecc80f3224b64e37038504e2d2c0e2b2"
            "9d45e46c62826d96331360e4c17ea3ef89a9efc5fac99eda830e81450b6534dc0bdf042b8f3b706649c631fe51fc2445"
            "cc8d447203ec2f41f79cdfea16de1ce6abdfdc1e2ef2e5d5d8a65e645f397240ef5a26f5e4ff715de782e30ecf477293"
            "e89e13171405909a8e04dd31d21d0c57935fc1ceea8e1033e31e1bc8c56da0f3d79510f3f380ff58e5a61d361f2f18e9"
            "9fbae5663172e8cd1f21deaddc5bbbea060d55f1842b93d1a9c888d0bf85d0af9947fe51acf940c7e7577eb79cabecb3"
        )
        ss = primitives.kdf3("sha256", z, 16)
        self.assertEqual(ss.hex(), "3cf82ec41b54ed4d37402bbd8f805a52")
        info = bytes.fromhex("3010300b0609608648016503040105020110")
        self.assertEqual(primitives.kdf3("sha256", ss, 16, info).hex(), "e6dc9d62ff2b469bef604c617b018718")

    def test_zero_length_is_empty(self):
        """GIVEN length 0 / WHEN derived / THEN no octets."""
        self.assertEqual((primitives.kdf2("sha256", b"z", 0), primitives.kdf3("sha256", b"z", 0)), (b"", b""))

    def test_negative_length_is_a_value_error(self):
        """GIVEN a negative length / WHEN derived / THEN ValueError, not an empty key or an overflow."""
        for function in (primitives.kdf2, primitives.kdf3, primitives.hkdf):
            with self.assertRaises(ValueError):
                function("sha256", b"z", -1)
        with self.assertRaises(ValueError):
            primitives.pbkdf2("sha256", b"z", b"salt", 1, -1)


class TestPbkdf2(unittest.TestCase):
    """PBKDF2-HMAC: RFC 6070, RFC 7914 Section 11 and ``hashlib`` for every hash."""

    def test_rfc_6070_sha1(self):
        """GIVEN the RFC 6070 test vectors / WHEN derived with SHA-1 / THEN the DK of the RFC."""
        cases = (
            (b"password", b"salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            (b"password", b"salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            (b"password", b"salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
            (b"pass\0word", b"sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
        )
        for password, salt, iterations, length, expected in cases:
            with self.subTest(iterations=iterations, length=length):
                self.assertEqual(primitives.pbkdf2("sha1", password, salt, iterations, length).hex(), expected)

    def test_rfc_7914_section_11_sha256(self):
        """GIVEN the two PBKDF2-HMAC-SHA-256 vectors of RFC 7914 Section 11 / WHEN derived / THEN the DK of the RFC."""
        self.assertEqual(
            primitives.pbkdf2("sha256", b"passwd", b"salt", 1, 64).hex(),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        )
        self.assertEqual(
            primitives.pbkdf2("sha256", b"Password", b"NaCl", 80000, 64).hex(),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        )

    def test_every_hash_equals_hashlib(self):
        """GIVEN each hash incl. SHA-3 / WHEN derived / THEN equal to hashlib.pbkdf2_hmac."""
        for name in _HASHES:
            with self.subTest(hash=name):
                self.assertEqual(
                    primitives.pbkdf2(name, b"pw", b"salty salt", 3, 45),
                    hashlib.pbkdf2_hmac(name, b"pw", b"salty salt", 3, 45),
                )


class TestHmac(unittest.TestCase):
    """HMAC: RFC 2202 and RFC 4231 test case 1, and ``hmac`` for every hash."""

    def test_rfc_2202_and_4231_test_case_1(self):
        """GIVEN key 0x0b x 20 and "Hi There" / WHEN MACed / THEN the values of RFC 2202 and RFC 4231."""
        key, data = bytes([0x0B]) * 20, b"Hi There"
        expected = {
            "sha1": "b617318655057264e28bc0b6fb378c8ef146be00",
            "sha224": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            "sha256": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "sha384": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
            "faea9ea9076ede7f4af152e8b2fa9cb6",
            "sha512": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4"
            "be9d914eeb61f1702e696c203a126854",
        }
        for name, mac in expected.items():
            with self.subTest(hash=name):
                self.assertEqual(primitives.hmac_digest(name, key, data).hex(), mac)

    def test_every_hash_equals_hmac_of_the_standard_library(self):
        """GIVEN each hash incl. SHA-3 and key sizes around the block size / WHEN MACed / THEN equal to hmac."""
        for name in _HASHES:
            for key_length in (0, 1, 64, 144, 200):
                with self.subTest(hash=name, key_length=key_length):
                    key = bytes(range(key_length % 256)) if key_length < 256 else b""
                    self.assertEqual(
                        primitives.hmac_digest(name, key, b"message"), hmac.new(key, b"message", name).digest()
                    )


class TestKmac(unittest.TestCase):
    """KMAC128 and KMAC256 against the samples of NIST SP 800-185."""

    KEY = bytes(range(0x40, 0x60))
    SHORT = bytes(range(4))
    LONG = bytes(range(200))
    TAG = b"My Tagged Application"

    def test_nist_sp_800_185_kmac128_samples(self):
        """GIVEN KMAC samples 1 to 3 / WHEN computed / THEN the output of NIST."""
        self.assertEqual(
            primitives.kmac("shake128", self.KEY, self.SHORT, mac_len=32).hex(),
            "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
        )
        self.assertEqual(
            primitives.kmac("shake128", self.KEY, self.SHORT, mac_len=32, custom=self.TAG).hex(),
            "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
        )
        self.assertEqual(
            primitives.kmac("shake128", self.KEY, self.LONG, mac_len=32, custom=self.TAG).hex(),
            "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
        )

    def test_nist_sp_800_185_kmac256_samples(self):
        """GIVEN KMAC samples 4 to 6 / WHEN computed / THEN the output of NIST."""
        self.assertEqual(
            primitives.kmac("shake256", self.KEY, self.SHORT, mac_len=64, custom=self.TAG).hex(),
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
            "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
        )
        self.assertEqual(
            primitives.kmac("shake256", self.KEY, self.LONG, mac_len=64).hex(),
            "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691"
            "589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
        )
        self.assertEqual(
            primitives.kmac("shake256", self.KEY, self.LONG, mac_len=64, custom=self.TAG).hex(),
            "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9"
            "70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
        )

    def test_unknown_function_raises_bad_alg(self):
        """GIVEN a name that is no SHAKE / WHEN KMAC is asked / THEN BadAlg."""
        with self.assertRaises(BadAlg):
            primitives.kmac("sha256", self.KEY, b"d", mac_len=32)


class TestGmac(unittest.TestCase):
    """AES-GMAC is AES-GCM over no plaintext: the GCM specification test cases 1, 7 and 13 are GMACs of no data."""

    def test_gcm_specification_test_cases_1_7_13(self):
        """GIVEN zero key and nonce, no data, 128/192/256 bit keys / WHEN MACed / THEN the tag of the specification."""
        expected = {
            16: "58e2fccefa7e3061367f1d57a4e7455a",
            24: "cd33b28ac773f74ba00ed1f312572435",
            32: "530f8afbc74536b9a963b4f1c4cb738b",
        }
        for key_length, tag in expected.items():
            with self.subTest(key_length=key_length):
                self.assertEqual(primitives.gmac(bytes(key_length), bytes(12), b"").hex(), tag)

    def test_gcm_specification_test_case_4_aad_only(self):
        """GIVEN the authenticated data of test case 4 and no plaintext / WHEN MACed / THEN it equals GCM over it."""
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        self.assertEqual(primitives.gmac(key, nonce, aad), primitives.aes_gcm_encrypt(key, nonce, b"", aad)[1])
        self.assertEqual(len(primitives.gmac(key, nonce, aad)), 16)

    def test_the_data_changes_the_tag(self):
        """GIVEN two data / WHEN MACed / THEN two tags."""
        self.assertNotEqual(primitives.gmac(bytes(16), bytes(12), b"a"), primitives.gmac(bytes(16), bytes(12), b"b"))


class TestKeyWrap(unittest.TestCase):
    """AES key wrap (RFC 3394) and with padding (RFC 5649): the vectors of the RFCs."""

    DATA_128 = bytes.fromhex("00112233445566778899aabbccddeeff")
    KEK = bytes(range(32))

    def test_rfc_3394_section_4_vectors(self):
        """GIVEN the six vectors of RFC 3394 Section 4 / WHEN wrapped and unwrapped / THEN the RFC wrapped key."""
        cases = (
            (16, self.DATA_128, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"),
            (24, self.DATA_128, "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"),
            (32, self.DATA_128, "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"),
            (
                24,
                bytes.fromhex("00112233445566778899aabbccddeeff0001020304050607"),
                "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2",
            ),
            (
                32,
                bytes.fromhex("00112233445566778899aabbccddeeff0001020304050607"),
                "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1",
            ),
            (
                32,
                bytes.fromhex("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"),
                "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
            ),
        )
        for kek_length, data, wrapped in cases:
            with self.subTest(kek_bits=kek_length * 8, key_bits=len(data) * 8):
                kek = self.KEK[:kek_length]
                self.assertEqual(primitives.aes_kw_wrap(kek, data).hex(), wrapped)
                self.assertEqual(primitives.aes_kw_unwrap(kek, bytes.fromhex(wrapped)), data)

    def test_rfc_5649_section_6_vectors(self):
        """GIVEN the 20 and 7 octet keys of RFC 5649 Section 6 / WHEN wrapped and unwrapped / THEN the RFC values."""
        kek = bytes.fromhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
        cases = (
            (
                "c37b7e6492584340bed12207808941155068f738",
                "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            ),
            ("466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"),
        )
        for key, wrapped in cases:
            with self.subTest(octets=len(key) // 2):
                self.assertEqual(primitives.aes_kwp_wrap(kek, bytes.fromhex(key)).hex(), wrapped)
                self.assertEqual(primitives.aes_kwp_unwrap(kek, bytes.fromhex(wrapped)).hex(), key)

    def test_kwp_wraps_a_key_that_kw_refuses(self):
        """GIVEN a 3 octet key / WHEN wrapped / THEN KWP wraps it to 16 octets and KW raises ValueError."""
        kek = bytes(16)
        self.assertEqual(len(primitives.aes_kwp_wrap(kek, b"abc")), 16)
        self.assertEqual(primitives.aes_kwp_unwrap(kek, primitives.aes_kwp_wrap(kek, b"abc")), b"abc")
        with self.assertRaises(ValueError):
            primitives.aes_kw_wrap(kek, b"abc")

    def test_unwrap_failures_are_integrity_errors(self):
        """GIVEN a flipped bit, a short value, a wrong KEK / WHEN unwrapped / THEN IntegrityError, nothing bare."""
        kek = bytes(16)
        for wrap, unwrap, key in (
            (primitives.aes_kw_wrap, primitives.aes_kw_unwrap, bytes(16)),
            (primitives.aes_kwp_wrap, primitives.aes_kwp_unwrap, bytes(13)),
        ):
            wrapped = wrap(kek, key)
            flipped = bytes([wrapped[0] ^ 1]) + wrapped[1:]
            for bad_kek, value in ((kek, flipped), (kek, wrapped[:-1]), (kek, b""), (bytes(range(16)), wrapped)):
                with self.subTest(wrapped=len(value), kek=bad_kek[:2].hex()):
                    with self.assertRaises(IntegrityError):
                        unwrap(bad_kek, value)

    def test_an_invalid_kek_size_is_a_value_error(self):
        """GIVEN a 15 octet KEK / WHEN wrapping / THEN ValueError (the layer does not look at OIDs)."""
        with self.assertRaises(ValueError):
            primitives.aes_kw_wrap(bytes(15), bytes(16))


class TestAesCbc(unittest.TestCase):
    """AES-CBC with PKCS#7 padding."""

    def test_nist_sp_800_38a_f2_1_first_block(self):
        """GIVEN the first block of NIST SP 800-38A F.2.1 / WHEN encrypted / THEN the first ciphertext block of NIST."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes(range(16))
        plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        ciphertext = primitives.aes_cbc_encrypt(key, iv, plaintext)
        self.assertEqual(len(ciphertext), 32, "a full block gets a whole padding block")
        self.assertEqual(ciphertext[:16].hex(), "7649abac8119b246cee98e9b12e9197d")
        self.assertEqual(primitives.aes_cbc_decrypt(key, iv, ciphertext), plaintext)

    def test_round_trip_for_every_length_and_key_size(self):
        """GIVEN 0 to 33 octets and three key sizes / WHEN encrypted and decrypted / THEN the plaintext comes back."""
        for key_length in (16, 24, 32):
            for size in range(34):
                data = bytes(range(size))
                with self.subTest(key_length=key_length, size=size):
                    ciphertext = primitives.aes_cbc_encrypt(bytes(key_length), bytes(16), data)
                    self.assertEqual(len(ciphertext), (size // 16 + 1) * 16)
                    self.assertEqual(primitives.aes_cbc_decrypt(bytes(key_length), bytes(16), ciphertext), data)

    def test_bad_padding_and_bad_length_are_integrity_errors(self):
        """GIVEN a wrong key, a truncated and an empty ciphertext / WHEN decrypted / THEN one IntegrityError text."""
        ciphertext = primitives.aes_cbc_encrypt(bytes(16), bytes(16), b"secret data")
        messages = set()
        for key, value in ((bytes(range(16)), ciphertext), (bytes(16), ciphertext[:-1]), (bytes(16), b"")):
            with self.assertRaises(IntegrityError) as caught:
                primitives.aes_cbc_decrypt(key, bytes(16), value)
            messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1, "the text must not tell the padding from the length")

    def test_a_wrong_iv_size_is_a_value_error(self):
        """GIVEN a 12 octet IV / WHEN used / THEN ValueError, not IntegrityError."""
        with self.assertRaises(ValueError):
            primitives.aes_cbc_encrypt(bytes(16), bytes(12), b"x")


# NIST SP 800-38A Appendix F.2: the IV and the four plaintext blocks of every CBC example, and the ciphertext by key.
# F.2.1/F.2.2 are AES-128, F.2.3/F.2.4 AES-192 and F.2.5/F.2.6 AES-256; each decrypt example reverses its encrypt one.
_SP800_38A_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_SP800_38A_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
_SP800_38A_CBC = (
    (
        "F.2.1/F.2.2",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7",
    ),
    (
        "F.2.3/F.2.4",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "4f021db243bc633d7178183a9fa071e8"
        "b4d9ada9ad7dedf4e5e738763f69145a"
        "571b242012fb7ae07fa9baac3df102e0"
        "08b0e27988598881d920a9e64f5615cd",
    ),
    (
        "F.2.5/F.2.6",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b",
    ),
)


class TestAesCbcNoPadding(unittest.TestCase):
    """AES-CBC without padding, for key-wrap constructions such as id-alg-PWRI-KEK (RFC 3211 Section 2.3)."""

    def test_nist_sp_800_38a_f2_vectors(self):
        """GIVEN NIST SP 800-38A F.2.1 to F.2.6 / WHEN encrypted and decrypted / THEN the values of NIST."""
        iv, plaintext = _SP800_38A_IV, _SP800_38A_PLAINTEXT
        for example, key_hex, ciphertext_hex in _SP800_38A_CBC:
            key, ciphertext = bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex)
            with self.subTest(example=example):
                self.assertEqual(primitives.aes_cbc_encrypt_no_padding(key, iv, plaintext), ciphertext)
                self.assertEqual(primitives.aes_cbc_decrypt_no_padding(key, iv, ciphertext), plaintext)
                # cryptography as an independent check of the transcription.
                encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                self.assertEqual(encryptor.update(plaintext) + encryptor.finalize(), ciphertext)

    def test_one_block_is_the_first_block_of_nist(self):
        """GIVEN the first block of F.2.1 / WHEN encrypted / THEN the 16 octets of the first block of NIST, no more."""
        _, key_hex, ciphertext_hex = _SP800_38A_CBC[0]
        key = bytes.fromhex(key_hex)
        ciphertext = primitives.aes_cbc_encrypt_no_padding(key, _SP800_38A_IV, _SP800_38A_PLAINTEXT[:16])
        self.assertEqual(ciphertext.hex(), ciphertext_hex[:32])

    def test_wrong_sizes_are_value_errors(self):
        """GIVEN a wrong key, IV or data size / WHEN encrypted or decrypted / THEN ValueError."""
        cases = (
            ("15 octet key", bytes(15), bytes(16), bytes(16)),
            ("64 octet key (AES-256-XTS)", bytes(64), bytes(16), bytes(16)),
            ("12 octet IV", bytes(16), bytes(12), bytes(16)),
            ("17 octet IV", bytes(16), bytes(17), bytes(16)),
            ("empty data", bytes(16), bytes(16), b""),
            ("15 octets of data", bytes(16), bytes(16), bytes(15)),
            ("17 octets of data", bytes(16), bytes(16), bytes(17)),
        )
        for function in (primitives.aes_cbc_encrypt_no_padding, primitives.aes_cbc_decrypt_no_padding):
            for name, key, iv, data in cases:
                with self.subTest(function=function.__name__, case=name), self.assertRaises(ValueError):
                    function(key, iv, data)


class TestAesGcm(unittest.TestCase):
    """AES-GCM: the test cases of the GCM specification."""

    def test_gcm_specification_test_case_2(self):
        """GIVEN test case 2 (zero key and nonce, one zero block) / WHEN encrypted / THEN ciphertext and tag."""
        ciphertext, tag = primitives.aes_gcm_encrypt(bytes(16), bytes(12), bytes(16))
        self.assertEqual(ciphertext.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")

    def test_gcm_specification_test_case_4_with_aad(self):
        """GIVEN test case 4 (60 octets and 20 octets of authenticated data) / WHEN en- and decrypted / THEN NIST's."""
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        ciphertext, tag = primitives.aes_gcm_encrypt(key, nonce, plaintext, aad)
        self.assertEqual(
            ciphertext.hex(),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091",
        )
        self.assertEqual(tag.hex(), "5bc94fbc3221a5db94fae95ae7121a47")
        self.assertEqual(primitives.aes_gcm_decrypt(key, nonce, ciphertext, tag, aad), plaintext)

    def test_a_truncated_tag_is_accepted_at_its_own_length(self):
        """GIVEN the first 12 octets of the tag / WHEN decrypted / THEN the plaintext (RFC 5084 allows 12 to 16)."""
        ciphertext, tag = primitives.aes_gcm_encrypt(bytes(16), bytes(12), b"hello")
        self.assertEqual(primitives.aes_gcm_decrypt(bytes(16), bytes(12), ciphertext, tag[:12]), b"hello")

    def test_tampering_is_an_integrity_error(self):
        """GIVEN a changed ciphertext, tag, nonce, aad or key / WHEN decrypted / THEN IntegrityError."""
        key, nonce = bytes(16), bytes(12)
        ciphertext, tag = primitives.aes_gcm_encrypt(key, nonce, b"hello", b"aad")
        flipped = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        for args in (
            (key, nonce, flipped, tag, b"aad"),
            (key, nonce, ciphertext, bad_tag, b"aad"),
            (key, bytes(range(12)), ciphertext, tag, b"aad"),
            (key, nonce, ciphertext, tag, b"other"),
            (key, nonce, ciphertext, tag, None),
            (bytes(range(16)), nonce, ciphertext, tag, b"aad"),
        ):
            with self.subTest(args=[len(a) if a is not None else None for a in args]):
                with self.assertRaises(IntegrityError):
                    primitives.aes_gcm_decrypt(*args)


if __name__ == "__main__":
    unittest.main()
