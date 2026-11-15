# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``encrypt_content``, ``decrypt_content`` and ``Encrypted`` of ``keyutils_py.mechanisms``.

External vectors, so that a shared misreading of the OID, the parameters or the mode cannot pass both sides:

* AES-CBC: NIST SP 800-38A F.2.1, F.2.3 and F.2.5 (the first blocks, with PKCS#7 padding behind them), and
  ``cryptography`` with ``PKCS7`` for every size.
* AES-GCM: the test cases 2, 4 and 16 of the GCM specification (McGrew and Viega), through the OIDs of RFC 5084 and
  ``GCMParameters``, and ``cryptography``'s ``AESGCM`` for the 192 bit key and every tag length.
"""

import dataclasses
import unittest
from typing import Optional

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from keyutils_py import _algs
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data, IntegrityError
from keyutils_py.mechanisms import Encrypted, decrypt_content, encrypt_content
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3565, rfc5084, rfc5280, rfc8018, rfc8619

_CBC = {16: rfc3565.id_aes128_CBC, 24: rfc3565.id_aes192_CBC, 32: rfc3565.id_aes256_CBC}
_GCM = {16: rfc5084.id_aes128_GCM, 24: rfc5084.id_aes192_GCM, 32: rfc5084.id_aes256_GCM}


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Return an ``AlgorithmIdentifier``; ``parameters`` is an ASN.1 object, DER bytes (kept as ``Any``) or None."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if isinstance(parameters, bytes):
        alg_id["parameters"] = univ.Any(parameters)
    elif parameters is not None:
        alg_id["parameters"] = univ.Any(encoder.encode(parameters))
    return alg_id


def _cbc(key_length: int, iv: bytes = bytes(16)) -> rfc5280.AlgorithmIdentifier:
    """Return an AES-CBC identifier whose parameters are the IV (an OCTET STRING)."""
    return _alg_id(_CBC[key_length], univ.OctetString(iv))


def _gcm(key_length: int, nonce: bytes = bytes(12), icv_length: Optional[int] = None) -> rfc5280.AlgorithmIdentifier:
    """Return an AES-GCM identifier with ``GCMParameters``; without ``icv_length`` the DEFAULT 12 applies."""
    params = rfc5084.GCMParameters()
    params["aes-nonce"] = nonce
    if icv_length is not None:
        params["aes-ICVlen"] = icv_length
    return _alg_id(_GCM[key_length], params)


def _round_trip(alg_id: rfc5280.AlgorithmIdentifier) -> rfc5280.AlgorithmIdentifier:
    """Return the identifier as a receiver has it: DER encoded and decoded."""
    decoded, rest = decoder.decode(encoder.encode(alg_id), asn1Spec=rfc5280.AlgorithmIdentifier())
    assert not rest
    return decoded


class TestEncrypted(unittest.TestCase):
    """``Encrypted`` carries the ciphertext and, for AES-GCM, the tag."""

    def test_is_a_frozen_value_with_an_optional_tag(self):
        """GIVEN an Encrypted / WHEN built and changed / THEN the tag defaults to None and nothing can be assigned."""
        value = Encrypted(b"ct")
        self.assertEqual((value.ciphertext, value.tag), (b"ct", None))
        self.assertEqual(value, Encrypted(b"ct", None))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.tag = b"t"  # type: ignore[misc]


class TestAesCbc(unittest.TestCase):
    """AES-CBC with PKCS#7 padding, the IV in the parameters."""

    IV = bytes(range(16))
    PLAIN = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    )
    KEYS = {
        16: "2b7e151628aed2a6abf7158809cf4f3c",
        24: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        32: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    }
    FIRST_BLOCK = {
        16: "7649abac8119b246cee98e9b12e9197d",
        24: "4f021db243bc633d7178183a9fa071e8",
        32: "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    }

    def test_nist_sp_800_38a_first_blocks(self):
        """GIVEN F.2.1, F.2.3 and F.2.5 / WHEN encrypted by OID / THEN the first ciphertext block of NIST."""
        for key_length, block in self.FIRST_BLOCK.items():
            with self.subTest(key_bits=key_length * 8):
                key = bytes.fromhex(self.KEYS[key_length])
                encrypted = encrypt_content(_round_trip(_cbc(key_length, self.IV)), key, self.PLAIN)
                self.assertIsNone(encrypted.tag)
                self.assertEqual(encrypted.ciphertext[:16].hex(), block)
                self.assertEqual(len(encrypted.ciphertext), len(self.PLAIN) + 16)

    def test_nist_sp_800_38a_f2_1_all_four_blocks(self):
        """GIVEN the four blocks of F.2.1 / WHEN encrypted / THEN the four ciphertext blocks of NIST."""
        key = bytes.fromhex(self.KEYS[16])
        expected = (
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
        )
        encrypted = encrypt_content(_cbc(16, self.IV), key, self.PLAIN)
        self.assertEqual(encrypted.ciphertext[:64].hex(), expected)
        self.assertEqual(decrypt_content(_cbc(16, self.IV), key, encrypted.ciphertext), self.PLAIN)

    def test_every_size_and_key_length_equals_cryptography(self):
        """GIVEN 0 to 33 octets and the three AES sizes / WHEN encrypted / THEN equal to Cipher with PKCS7."""
        for key_length in (16, 24, 32):
            key = bytes(range(key_length))
            for size in range(34):
                with self.subTest(key_bits=key_length * 8, size=size):
                    data = bytes(range(size))
                    padder = padding.PKCS7(128).padder()
                    encryptor = Cipher(algorithms.AES(key), modes.CBC(self.IV)).encryptor()
                    expected = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()
                    alg_id = _round_trip(_cbc(key_length, self.IV))
                    self.assertEqual(encrypt_content(alg_id, key, data).ciphertext, expected)
                    self.assertEqual(decrypt_content(alg_id, key, expected), data)

    def test_the_iv_of_the_parameters_is_used(self):
        """GIVEN two IVs / WHEN encrypted / THEN two ciphertexts, each decrypting only under its IV."""
        key = bytes(16)
        a = encrypt_content(_cbc(16, bytes(16)), key, b"x" * 20).ciphertext
        b = encrypt_content(_cbc(16, bytes(range(16))), key, b"x" * 20).ciphertext
        self.assertNotEqual(a, b)
        self.assertNotEqual(decrypt_content(_cbc(16, bytes(range(16))), key, a)[:16], b"x" * 16)

    def test_parameters_are_required_16_octets_and_nothing_else(self):
        """GIVEN absent, 15 octet, 17 octet, NULL and trailing parameters / WHEN used / THEN the errors."""
        key = bytes(16)
        with self.assertRaises(BadAlgParams):
            encrypt_content(_alg_id(_CBC[16]), key, b"x")
        for iv in (bytes(15), bytes(17), b""):
            with self.subTest(iv=len(iv)):
                with self.assertRaises(BadAsn1Data):
                    encrypt_content(_cbc(16, iv), key, b"x")
        with self.assertRaises(BadAsn1Data):
            encrypt_content(_alg_id(_CBC[16], univ.Null("")), key, b"x")
        with self.assertRaises(BadAlgParams):
            encrypt_content(_alg_id(_CBC[16], encoder.encode(univ.OctetString(bytes(16))) + b"\x05\x00"), key, b"x")

    def test_aad_and_tag_are_type_errors(self):
        """GIVEN aad or tag for AES-CBC / WHEN used / THEN TypeError."""
        key = bytes(16)
        with self.assertRaises(TypeError):
            encrypt_content(_cbc(16), key, b"x", aad=b"a")
        ciphertext = encrypt_content(_cbc(16), key, b"x").ciphertext
        with self.assertRaises(TypeError):
            decrypt_content(_cbc(16), key, ciphertext, tag=b"t" * 12)
        with self.assertRaises(TypeError):
            decrypt_content(_cbc(16), key, ciphertext, aad=b"")

    def test_bad_padding_and_bad_length_are_integrity_errors_with_one_message(self):
        """GIVEN a wrong key, a cut and an empty ciphertext / WHEN decrypted / THEN IntegrityError, no oracle."""
        ciphertext = encrypt_content(_cbc(16), bytes(16), b"secret data").ciphertext
        messages = set()
        for key, value in ((bytes(range(16)), ciphertext), (bytes(16), ciphertext[:-1]), (bytes(16), b"")):
            with self.assertRaises(IntegrityError) as caught:
                decrypt_content(_cbc(16), key, value)
            messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1)


class TestAesGcm(unittest.TestCase):
    """AES-GCM, the nonce and the tag length in ``GCMParameters``."""

    KEY_4 = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    NONCE_4 = bytes.fromhex("cafebabefacedbaddecaf888")
    PLAIN_4 = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39"
    )
    AAD_4 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")

    def test_gcm_specification_test_case_2(self):
        """GIVEN test case 2 (zero key, nonce and block) with aes-ICVlen 16 / WHEN encrypted / THEN NIST's values."""
        encrypted = encrypt_content(_round_trip(_gcm(16, icv_length=16)), bytes(16), bytes(16))
        self.assertEqual(encrypted.ciphertext.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(encrypted.tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")  # type: ignore[union-attr]

    def test_gcm_specification_test_case_4_with_aad(self):
        """GIVEN test case 4 / WHEN encrypted and decrypted with aad / THEN ciphertext and tag of the specification."""
        alg_id = _round_trip(_gcm(16, self.NONCE_4, 16))
        encrypted = encrypt_content(alg_id, self.KEY_4, self.PLAIN_4, aad=self.AAD_4)
        self.assertEqual(
            encrypted.ciphertext.hex(),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091",
        )
        self.assertEqual(encrypted.tag.hex(), "5bc94fbc3221a5db94fae95ae7121a47")  # type: ignore[union-attr]
        self.assertEqual(
            decrypt_content(alg_id, self.KEY_4, encrypted.ciphertext, tag=encrypted.tag, aad=self.AAD_4), self.PLAIN_4
        )

    def test_192_and_256_bit_keys_equal_cryptography(self):
        """GIVEN a 192 and a 256 bit key / WHEN encrypted / THEN equal to AESGCM, tag cut to aes-ICVlen."""
        for key in (self.KEY_4 + bytes.fromhex("feffe9928665731c"), self.KEY_4 + self.KEY_4):
            for icv_length in (12, 13, 14, 15, 16):
                with self.subTest(key_bits=len(key) * 8, icv=icv_length):
                    alg_id = _round_trip(_gcm(len(key), self.NONCE_4, icv_length))
                    sealed = AESGCM(key).encrypt(self.NONCE_4, self.PLAIN_4, self.AAD_4)
                    encrypted = encrypt_content(alg_id, key, self.PLAIN_4, aad=self.AAD_4)
                    self.assertEqual(encrypted.ciphertext, sealed[:-16])
                    self.assertEqual(encrypted.tag, sealed[-16:][:icv_length])

    def test_gcm_specification_test_case_16_tag(self):
        """GIVEN the 256 bit key case of the specification / WHEN encrypted / THEN the tag of NIST."""
        key = self.KEY_4 + self.KEY_4
        alg_id = _gcm(len(key), self.NONCE_4, 16)
        encrypted = encrypt_content(alg_id, key, self.PLAIN_4, aad=self.AAD_4)
        self.assertEqual(encrypted.ciphertext.hex()[:32], "522dc1f099567d07f47f37a32a84427d")
        self.assertEqual(encrypted.tag.hex(), "76fc6ece0f4e1768cddf8853bb2d551b")  # type: ignore[union-attr]

    def test_the_default_tag_length_is_12_octets(self):
        """GIVEN parameters without aes-ICVlen / WHEN encrypted / THEN a tag of 12 octets (RFC 5084 DEFAULT 12)."""
        encrypted = encrypt_content(_round_trip(_gcm(16)), bytes(16), b"x")
        self.assertEqual(len(encrypted.tag), 12)  # type: ignore[arg-type]

    def test_decrypt_checks_the_tag_length_against_the_parameters(self):
        """GIVEN a tag of 12 octets and aes-ICVlen 16 / WHEN decrypted / THEN BadAlgParams."""
        alg_id = _gcm(16, icv_length=16)
        encrypted = encrypt_content(alg_id, bytes(16), b"x")
        with self.assertRaises(BadAlgParams):
            decrypt_content(alg_id, bytes(16), encrypted.ciphertext, tag=encrypted.tag[:12])  # type: ignore[index]

    def test_tampering_is_an_integrity_error(self):
        """GIVEN a changed ciphertext, tag, nonce, aad or key / WHEN decrypted / THEN IntegrityError, one message."""
        key = bytes(range(16))
        alg_id = _gcm(16, bytes(range(12)))
        encrypted = encrypt_content(alg_id, key, b"hello world", aad=b"aad")
        tag, ciphertext = encrypted.tag, encrypted.ciphertext
        assert tag is not None
        messages = set()
        for name, args in (
            ("ciphertext", (alg_id, key, bytes([ciphertext[0] ^ 1]) + ciphertext[1:], tag, b"aad")),
            ("tag", (alg_id, key, ciphertext, bytes([tag[0] ^ 1]) + tag[1:], b"aad")),
            ("nonce", (_gcm(16, bytes(12)), key, ciphertext, tag, b"aad")),
            ("aad", (alg_id, key, ciphertext, tag, b"other")),
            ("no aad", (alg_id, key, ciphertext, tag, None)),
            ("key", (alg_id, bytes(16), ciphertext, tag, b"aad")),
        ):
            with self.subTest(changed=name):
                with self.assertRaises(IntegrityError) as caught:
                    decrypt_content(args[0], args[1], args[2], tag=args[3], aad=args[4])
                messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1)

    def test_decrypt_needs_the_tag(self):
        """GIVEN no tag / WHEN decrypting AES-GCM / THEN TypeError."""
        with self.assertRaises(TypeError):
            decrypt_content(_gcm(16), bytes(16), b"ct")

    def test_the_nonce_range_is_8_to_128_octets(self):
        """GIVEN nonces of 7, 8, 128 and 129 octets / WHEN encrypted / THEN the ends of the range decide."""
        for size, ok in ((7, False), (8, True), (128, True), (129, False)):
            with self.subTest(nonce=size):
                if ok:
                    encrypt_content(_gcm(16, bytes(size)), bytes(16), b"x")
                else:
                    with self.assertRaises(BadAlgParams):
                        encrypt_content(_gcm(16, bytes(size)), bytes(16), b"x")

    def test_parameters_are_required_and_must_decode(self):
        """GIVEN absent parameters, ICVlen 11 and 17, a bare OCTET STRING, trailing data / WHEN used / THEN errors."""
        key = bytes(16)
        with self.assertRaises(BadAlgParams):
            encrypt_content(_alg_id(_GCM[16]), key, b"x")
        for icv in (11, 17):
            der = b"\x30\x11\x04\x0c" + bytes(12) + b"\x02\x01" + bytes([icv])
            with self.subTest(icv=icv):
                with self.assertRaises(BadAsn1Data):
                    encrypt_content(_alg_id(_GCM[16], der), key, b"x")
        with self.assertRaises(BadAsn1Data):
            encrypt_content(_alg_id(_GCM[16], univ.OctetString(bytes(12))), key, b"x")
        with self.assertRaises(BadAlgParams):
            encrypt_content(_alg_id(_GCM[16], b"\x30\x0e\x04\x0c" + bytes(12) + b"\x05\x00"), key, b"x")


class TestTheCall(unittest.TestCase):
    """What every content encryption algorithm has in common."""

    def test_the_key_must_have_the_size_of_the_oid(self):
        """GIVEN keys of 15, 24 and 32 octets under the AES-128 OIDs / WHEN used / THEN BadAlgParams."""
        for alg_id in (_cbc(16), _gcm(16)):
            for key_length in (0, 15, 24, 32):
                with self.subTest(oid=str(alg_id["algorithm"]), key=key_length):
                    with self.assertRaises(BadAlgParams):
                        encrypt_content(alg_id, bytes(key_length), b"x")
                    with self.assertRaises(BadAlgParams):
                        decrypt_content(alg_id, bytes(key_length), b"x" * 16, tag=bytes(12))

    def test_every_row_round_trips(self):
        """GIVEN each of the six rows / WHEN encrypted and decrypted / THEN the plaintext comes back."""
        for row in _algs.CONTENT_ROWS:
            with self.subTest(mode=row.mode, key=row.key_len):
                alg_id = _cbc(row.key_len) if row.mode == "cbc" else _gcm(row.key_len)
                key = bytes(range(row.key_len))
                encrypted = encrypt_content(alg_id, key, b"the plaintext")
                self.assertEqual(
                    decrypt_content(
                        alg_id, key, encrypted.ciphertext, **({"tag": encrypted.tag} if encrypted.tag else {})
                    ),
                    b"the plaintext",
                )

    def test_an_oid_that_is_no_content_encryption_is_bad_alg(self):
        """GIVEN a key wrap, an HMAC and an unknown OID / WHEN used / THEN BadAlg."""
        for oid in (rfc3565.id_aes128_wrap, rfc8018.id_hmacWithSHA256, univ.ObjectIdentifier("1.2.3.4")):
            with self.assertRaises(BadAlg):
                encrypt_content(_alg_id(oid), bytes(16), b"x")
            with self.assertRaises(BadAlg):
                decrypt_content(_alg_id(oid), bytes(16), b"x")

    def test_an_identifier_without_oid_is_bad_alg_and_a_wrong_type_a_type_error(self):
        """GIVEN an empty identifier, an OID, bytes / WHEN used / THEN BadAlg or TypeError."""
        with self.assertRaises(BadAlg):
            encrypt_content(rfc5280.AlgorithmIdentifier(), bytes(16), b"x")
        for value in (rfc8619.id_alg_hkdf_with_sha256, b"x", None):
            with self.assertRaises(TypeError):
                encrypt_content(value, bytes(16), b"x")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
