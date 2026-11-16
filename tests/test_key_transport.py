# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

r"""Tests for the RSA key transport functions and the RSAES-OAEP identifier of ``make_alg_id``.

They cover ``encrypt_data_with_public_key_alg_id``, ``decrypt_data_with_public_key_alg_id`` and the identifier that
``make_alg_id("key_transport", ...)`` writes.

External witnesses, so that a shared misreading of RFC 4055 cannot pass both sides:

* the ``AlgorithmIdentifier`` values that the ASN.1 module of RFC 4055 itself builds (``rSAES_OAEP_SHA256_Identifier``
  and its siblings, in ``pyasn1_alt_modules.rfc4055``) and DER written out by hand below;
* the ``EnvelopedData`` files of ``tests/vectors`` made by ``openssl cms -encrypt`` (OpenSSL 3.5.7) for the key of
  ``tests/vectors/openssl_rsa_key.pem`` (made by ``openssl req -x509 -newkey rsa:2048 -nodes -keyout
  openssl_rsa_key.pem -out cert.pem -subj /CN=oaep-test``); the message is ``oaep test message`` and CR LF
  (``openssl cms`` canonicalises text that is not ``-binary``)::

      openssl cms -encrypt -aes-128-cbc -in msg.txt -recip cert.pem -outform DER -out openssl_ktri_pkcs1.der
      openssl cms -encrypt -aes-128-cbc -in msg.txt -recip cert.pem -keyopt rsa_padding_mode:oaep \\
          -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256 -outform DER -out openssl_ktri_oaep_sha256.der
      (md sha1 and mgf1 sha1 for ..._oaep_sha1.der, md sha384 with mgf1 sha256 for ..._oaep_sha384_mgf1_sha256.der)

  OpenSSL writes the hash identifiers inside the OAEP parameters without NULL, which RFC 4055 Section 2.1 allows, and
  the all-defaults parameters as an empty SEQUENCE;
* ``cryptography``'s own ``padding.OAEP``, which makes and opens OAEP ciphertext with the same hashes and label.
"""

import unittest
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from keyutils_py import compute, make_alg_id
from keyutils_py.compute import decrypt_data_with_public_key_alg_id, encrypt_data_with_public_key_alg_id
from keyutils_py.exceptions import BadAlg, BadAlgParams, BadAsn1Data, IntegrityError, InvalidKeyCombination
from keyutils_py.mechanisms import decrypt_content
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc8017

from tests.cms_vectors import key_transport_recipient, load_private_key

HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
MESSAGE = b"oaep test message\r\n"

# The OIDs of the hash functions as DER, and of id-mgf1 and id-pSpecified (RFC 4055 Section 2.2 and 4.1).
_OID = {
    "sha1": "06052b0e03021a",
    "sha224": "0609608648016503040204",
    "sha256": "0609608648016503040201",
    "sha384": "0609608648016503040202",
    "sha512": "0609608648016503040203",
    "sha3_256": "0609608648016503040208",
    "shake128": "060960864801650304020b",
    "unknown": "06032a0304",
}
_ID_MGF1 = "06092a864886f70d010108"
_ID_P_SPECIFIED = "06092a864886f70d010109"
_ID_RSAES_OAEP = "06092a864886f70d010107"


def _tlv(tag: str, content: str) -> str:
    """Return the DER of one element as hex; the contents of these tests are shorter than 128 octets."""
    length = len(content) // 2
    assert length < 128
    return f"{tag}{length:02x}{content}"


def _hash_id(name: str, null: bool = True) -> str:
    """Return the DER of the AlgorithmIdentifier of a hash, with NULL parameters or without parameters."""
    return _tlv("30", _OID[name] + ("0500" if null else ""))


def _mgf1(name: str, null: bool = True) -> str:
    """Return the DER of the AlgorithmIdentifier of MGF1 over a hash."""
    return _tlv("30", _ID_MGF1 + _hash_id(name, null))


def _p_specified(label: bytes) -> str:
    """Return the DER of the AlgorithmIdentifier of id-pSpecified with the label."""
    return _tlv("30", _ID_P_SPECIFIED + _tlv("04", label.hex()))


def _params(hash_func: Optional[str] = None, mask_gen: Optional[str] = None, p_source: Optional[str] = None) -> str:
    """Return the DER of RSAES-OAEP-params from the three identifiers (as hex), each in its context tag."""
    body = ""
    for tag, field in (("a0", hash_func), ("a1", mask_gen), ("a2", p_source)):
        if field is not None:
            body += _tlv(tag, field)
    return _tlv("30", body)


def _rfc_params(hash_name: str, mgf1_name: str, label: bytes = b"") -> str:
    """Return RSAES-OAEP-params as RFC 4055 writes them (NULL inside), the DEFAULT fields left out."""
    return _params(
        None if hash_name == "sha1" else _hash_id(hash_name),
        None if mgf1_name == "sha1" else _mgf1(mgf1_name),
        _p_specified(label) if label else None,
    )


def _alg_id(oid, parameters=None) -> rfc5280.AlgorithmIdentifier:
    """Return an ``AlgorithmIdentifier`` whose parameters are the DER of an ASN.1 object, or the given DER bytes."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if parameters is not None:
        der = parameters if isinstance(parameters, bytes) else encoder.encode(parameters)
        alg_id["parameters"] = univ.Any(der)
    return alg_id


def _oaep(params_hex: str) -> rfc5280.AlgorithmIdentifier:
    """Return an id-RSAES-OAEP identifier whose parameters are the given DER, as a sender may write them."""
    return _alg_id(rfc4055.id_RSAES_OAEP, bytes.fromhex(params_hex))


# RFC 4055 Section 4.1 for SHA-256, written by hand.
OAEP_SHA256_DER = _tlv("30", _ID_RSAES_OAEP + _rfc_params("sha256", "sha256"))
# What the callers of this package wrote before: hashFunc without parameters and a bare hash OID as the MGF1 parameter
# (which is no AlgorithmIdentifier, so RFC 4055 Section 2.2 does not allow it).
OLD_OAEP_SHA256_DER = _tlv(
    "30", _ID_RSAES_OAEP + _params(_hash_id("sha256", null=False), _tlv("30", _ID_MGF1 + _OID["sha256"]))
)


class TestOaepIdentifier(unittest.TestCase):
    """``make_alg_id("key_transport", "rsa-oaep", ...)`` writes RSAES-OAEP-params as RFC 4055 does."""

    def test_the_literals_are_what_the_helpers_write(self):
        """GIVEN the helpers above / WHEN SHA-256 is written / THEN these literal bytes (RFC 4055 module, below)."""
        self.assertEqual(
            OAEP_SHA256_DER,
            "303c06092a864886f70d010107302fa00f300d0609608648016503040201"
            "0500a11c301a06092a864886f70d010108300d06096086480165030402010500",
        )
        self.assertEqual(
            OLD_OAEP_SHA256_DER,
            "303606092a864886f70d0101073029a00d300b0609608648016503040201"
            "a118301606092a864886f70d0101080609608648016503040201",
        )

    def test_sha256_is_the_der_of_rfc_4055(self):
        """GIVEN SHA-256 for both hashes / WHEN built / THEN the DER written by hand: NULL inside, MGF1 with an id."""
        alg_id = make_alg_id("key_transport", "rsa-oaep", hash="sha256")
        self.assertEqual(encoder.encode(alg_id).hex(), OAEP_SHA256_DER)

    def test_the_identifiers_of_the_asn1_module_of_rfc_4055(self):
        """GIVEN SHA-224/256/384/512 / WHEN built / THEN the bytes of rSAES-OAEP-SHAxxx-Identifier of RFC 4055."""
        for name, expected in (
            ("sha224", rfc4055.rSAES_OAEP_SHA224_Identifier),
            ("sha256", rfc4055.rSAES_OAEP_SHA256_Identifier),
            ("sha384", rfc4055.rSAES_OAEP_SHA384_Identifier),
            ("sha512", rfc4055.rSAES_OAEP_SHA512_Identifier),
        ):
            with self.subTest(hash=name):
                alg_id = make_alg_id("key_transport", "rsa-oaep", hash=name)
                self.assertEqual(encoder.encode(alg_id), encoder.encode(expected))

    def test_the_defaults_are_left_out(self):
        """GIVEN SHA-1 for both hashes and no label / WHEN built / THEN an empty SEQUENCE: DER omits defaults."""
        alg_id = make_alg_id("key_transport", "rsa-oaep", hash="sha1")
        self.assertEqual(encoder.encode(alg_id).hex(), "300d06092a864886f70d0101073000")

    def test_hash_mgf1_hash_and_label_are_independent(self):
        """GIVEN other MGF1 hashes and labels / WHEN built / THEN the three fields as written by hand."""
        for hash_name, mgf1_name, label in (
            ("sha384", "sha256", b""),
            ("sha256", "sha1", b"label"),
            ("sha1", "sha256", b""),
            ("sha1", "sha1", b"x"),
            ("sha512", "sha512", bytes(range(40))),
        ):
            with self.subTest(hash=hash_name, mgf1=mgf1_name, label=label):
                alg_id = make_alg_id("key_transport", "rsa-oaep", hash=hash_name, mgf1_hash=mgf1_name, label=label)
                expected = _tlv("30", _ID_RSAES_OAEP + _rfc_params(hash_name, mgf1_name, label))
                self.assertEqual(encoder.encode(alg_id).hex(), expected)

    def test_pkcs1_v1_5_is_rsa_encryption_with_null(self):
        """GIVEN rsa-pkcs1v15 / WHEN built / THEN rsaEncryption with NULL parameters, as OpenSSL writes it."""
        alg_id = make_alg_id("key_transport", "rsa-pkcs1v15")
        self.assertEqual(encoder.encode(alg_id).hex(), "300d06092a864886f70d0101010500")

    def test_unknown_keywords_hashes_and_families(self):
        """GIVEN a misspelled keyword, SHA-3, an unknown hash or family / WHEN built / THEN TypeError or BadAlg."""
        with self.assertRaises(TypeError):
            make_alg_id("key_transport", "rsa-oaep", hash="sha256", mgf_hash="sha256")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            make_alg_id("key_transport", "rsa-oaep")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            make_alg_id("key_transport", "rsa-pkcs1v15", hash="sha256")  # type: ignore[arg-type]
        for hash_name, mgf1_name in (("sha3_256", None), ("md5", None), ("sha256", "shake128"), ("SHA256", None)):
            with self.subTest(hash=hash_name, mgf1=mgf1_name):
                with self.assertRaises(BadAlg):
                    make_alg_id("key_transport", "rsa-oaep", hash=hash_name, mgf1_hash=mgf1_name)
        with self.assertRaises(BadAlg):
            make_alg_id("key_transport", "rsa-pss")


class TestWithCryptography(unittest.TestCase):
    """What this package encrypts is opened by ``cryptography`` with the same parameters, and the other way round."""

    @classmethod
    def setUpClass(cls):
        """Load the RSA key of the vectors."""
        cls.key = load_private_key("openssl_rsa_key.pem")

    def test_every_hash_mgf1_hash_and_label(self):
        """GIVEN the five hashes, MGF1 hashes and labels / WHEN encrypted by either side / THEN opened by the other."""
        cek = bytes(range(32))
        for hash_name in HASHES:
            for mgf1_name in ("sha1", "sha256", "sha512"):
                for label in (b"", b"a label"):
                    with self.subTest(hash=hash_name, mgf1=mgf1_name, label=label):
                        alg_id = make_alg_id(
                            "key_transport", "rsa-oaep", hash=hash_name, mgf1_hash=mgf1_name, label=label
                        )
                        pad = padding.OAEP(
                            mgf=padding.MGF1(HASHES[mgf1_name]()), algorithm=HASHES[hash_name](), label=label or None
                        )
                        ours = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, cek)
                        self.assertEqual(self.key.decrypt(ours, pad), cek)
                        self.assertEqual(
                            decrypt_data_with_public_key_alg_id(self.key, alg_id, ours, allow_sha1=True), cek
                        )
                        theirs = self.key.public_key().encrypt(cek, pad)
                        self.assertEqual(
                            decrypt_data_with_public_key_alg_id(self.key, alg_id, theirs, allow_sha1=True), cek
                        )

    def test_a_label_that_differs_does_not_open(self):
        """GIVEN a ciphertext of the label a / WHEN opened with the identifier of the label b / THEN IntegrityError."""
        a = make_alg_id("key_transport", "rsa-oaep", hash="sha256", label=b"a")
        b = make_alg_id("key_transport", "rsa-oaep", hash="sha256", label=b"b")
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), a, b"key material 16b")
        with self.assertRaises(IntegrityError):
            decrypt_data_with_public_key_alg_id(self.key, b, ct)

    def test_pkcs1_v1_5(self):
        """GIVEN rsa-pkcs1v15 / WHEN encrypted either side / THEN opened by the other."""
        alg_id = make_alg_id("key_transport", "rsa-pkcs1v15")
        ours = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, b"cek")
        self.assertEqual(self.key.decrypt(ours, padding.PKCS1v15()), b"cek")
        theirs = self.key.public_key().encrypt(b"cek", padding.PKCS1v15())
        self.assertEqual(decrypt_data_with_public_key_alg_id(self.key, alg_id, theirs), b"cek")


class TestOpenSslVectors(unittest.TestCase):
    """The key transport of ``openssl cms -encrypt`` opens, and the content decrypts to the message."""

    @classmethod
    def setUpClass(cls):
        """Load the RSA key of the vectors."""
        cls.key = load_private_key("openssl_rsa_key.pem")

    def _open(self, name: str, **kwargs) -> bytes:
        """Return the content of a vector file: the CEK by key transport, then the content by identifier."""
        key_enc_alg, encrypted_key, eci = key_transport_recipient(name)
        cek = decrypt_data_with_public_key_alg_id(self.key, key_enc_alg, encrypted_key, **kwargs)
        return decrypt_content(eci["contentEncryptionAlgorithm"], cek, eci["encryptedContent"].asOctets())

    def test_oaep_with_sha256(self):
        """GIVEN OAEP with SHA-256, hash identifiers without NULL / WHEN opened / THEN the message."""
        self.assertEqual(self._open("openssl_ktri_oaep_sha256.der"), MESSAGE)

    def test_oaep_with_sha384_and_an_mgf1_with_sha256(self):
        """GIVEN OAEP with SHA-384 and MGF1 over SHA-256 / WHEN opened / THEN the message."""
        self.assertEqual(self._open("openssl_ktri_oaep_sha384_mgf1_sha256.der"), MESSAGE)

    def test_oaep_with_sha1_is_the_all_defaults_sequence_and_needs_allow_sha1(self):
        """GIVEN OAEP over SHA-1 as an empty SEQUENCE / WHEN opened / THEN BadAlg, and the message if allowed."""
        key_enc_alg, encrypted_key, _ = key_transport_recipient("openssl_ktri_oaep_sha1.der")
        self.assertEqual(encoder.encode(key_enc_alg).hex(), "300d06092a864886f70d0101073000")
        with self.assertRaises(BadAlg):
            decrypt_data_with_public_key_alg_id(self.key, key_enc_alg, encrypted_key)
        self.assertEqual(self._open("openssl_ktri_oaep_sha1.der", allow_sha1=True), MESSAGE)

    def test_pkcs1_v1_5(self):
        """GIVEN rsaEncryption with NULL / WHEN opened / THEN the message."""
        self.assertEqual(self._open("openssl_ktri_pkcs1.der"), MESSAGE)

    def test_null_after_the_hash_makes_no_difference(self):
        """GIVEN OpenSSL's SHA-384/SHA-256 identifier and ours / WHEN both open the key / THEN the same CEK."""
        theirs, encrypted_key, _ = key_transport_recipient("openssl_ktri_oaep_sha384_mgf1_sha256.der")
        ours = make_alg_id("key_transport", "rsa-oaep", hash="sha384", mgf1_hash="sha256")
        self.assertEqual(len(encoder.encode(ours)) - len(encoder.encode(theirs)), 4)
        self.assertEqual(
            decrypt_data_with_public_key_alg_id(self.key, ours, encrypted_key),
            decrypt_data_with_public_key_alg_id(self.key, theirs, encrypted_key),
        )


class TestParameterChecks(unittest.TestCase):
    """The reader is strict about what it receives, and says why with the class of the error."""

    @classmethod
    def setUpClass(cls):
        """Load the RSA key of the vectors."""
        cls.key = load_private_key("openssl_rsa_key.pem")
        cls.sha256 = make_alg_id("key_transport", "rsa-oaep", hash="sha256")
        cls.ct = encrypt_data_with_public_key_alg_id(cls.key.public_key(), cls.sha256, b"0123456789abcdef")

    def _both(self, alg_id, error):
        """Assert that encrypting and decrypting with ``alg_id`` raise ``error``."""
        with self.assertRaises(error):
            encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, b"cek")
        with self.assertRaises(error):
            decrypt_data_with_public_key_alg_id(self.key, alg_id, self.ct)

    def test_the_old_bytes_are_rejected(self):
        """GIVEN a bare OID as the MGF1 parameter (and hashFunc without parameters) / WHEN used / THEN BadAlgParams."""
        self._both(_oaep(OLD_OAEP_SHA256_DER[len("3036" + _ID_RSAES_OAEP) :]), BadAlgParams)

    def test_hash_without_parameters_is_fine_when_the_rest_is_rfc_4055(self):
        """GIVEN hashFunc and the MGF1 hash without parameters / WHEN opened / THEN the key (OpenSSL writes this)."""
        alg_id = _oaep(_params(_hash_id("sha256", null=False), _mgf1("sha256", null=False)))
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, b"cek")
        self.assertEqual(decrypt_data_with_public_key_alg_id(self.key, alg_id, ct), b"cek")

    def test_absent_parameters_are_bad_alg_params(self):
        """GIVEN id-RSAES-OAEP without parameters (RFC 4055 Section 4.1 wants the SEQUENCE) / WHEN used / THEN error."""
        self._both(_alg_id(rfc4055.id_RSAES_OAEP), BadAlgParams)

    def test_trailing_data_is_bad_alg_params_and_garbage_is_bad_asn1_data(self):
        """GIVEN data after the parameters, and bytes that are no SEQUENCE / WHEN used / THEN the two classes."""
        self._both(_oaep(_rfc_params("sha256", "sha256") + "00"), BadAlgParams)
        self._both(_oaep("0403616263"), BadAsn1Data)

    def test_hash_other_than_sha1_and_sha2_is_bad_alg(self):
        """GIVEN SHA3-256, SHAKE128 and an unknown OID as the hash / WHEN used / THEN BadAlg."""
        for name in ("sha3_256", "shake128", "unknown"):
            with self.subTest(hash=name):
                self._both(_oaep(_params(_tlv("30", _OID[name] + "0500"), _mgf1("sha256"))), BadAlg)
                self._both(_oaep(_params(_hash_id("sha256"), _tlv("30", _ID_MGF1 + _tlv("30", _OID[name])))), BadAlg)

    def test_hash_parameters_must_be_absent_or_null(self):
        """GIVEN an OCTET STRING as the parameters of the hash / WHEN used / THEN BadAlgParams."""
        self._both(_oaep(_params(_tlv("30", _OID["sha256"] + "0400"), _mgf1("sha256"))), BadAlgParams)

    def test_mask_generation_function_other_than_mgf1_is_bad_alg(self):
        """GIVEN a maskGenFunc whose OID is id-sha256 / WHEN used / THEN BadAlg."""
        self._both(_oaep(_params(_hash_id("sha256"), _tlv("30", _OID["sha256"] + _hash_id("sha256")))), BadAlg)

    def test_mgf1_without_parameters_is_bad_alg_params(self):
        """GIVEN id-mgf1 without the hash identifier / WHEN used / THEN BadAlgParams."""
        self._both(_oaep(_params(_hash_id("sha256"), _tlv("30", _ID_MGF1))), BadAlgParams)

    def test_a_p_source_function_other_than_p_specified_is_bad_alg(self):
        """GIVEN a pSourceFunc whose OID is id-sha256 / WHEN used / THEN BadAlg."""
        self._both(_oaep(_params(_hash_id("sha256"), _mgf1("sha256"), _hash_id("sha256"))), BadAlg)

    def test_p_specified_without_a_label_or_with_an_oversize_label_is_bad_alg_params(self):
        """GIVEN id-pSpecified with no parameters, and a label of MAX + 1 octets / WHEN used / THEN BadAlgParams."""
        self._both(_oaep(_params(_hash_id("sha256"), _mgf1("sha256"), _tlv("30", _ID_P_SPECIFIED))), BadAlgParams)
        too_long = make_alg_id(
            "key_transport", "rsa-oaep", hash="sha256", label=bytes(compute.MAX_OAEP_LABEL_LENGTH + 1)
        )
        self._both(too_long, BadAlgParams)
        longest = make_alg_id("key_transport", "rsa-oaep", hash="sha256", label=bytes(compute.MAX_OAEP_LABEL_LENGTH))
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), longest, b"cek")
        self.assertEqual(decrypt_data_with_public_key_alg_id(self.key, longest, ct), b"cek")

    def test_pkcs1_v1_5_parameters_are_absent_or_null(self):
        """GIVEN rsaEncryption with absent, NULL and OCTET STRING parameters / WHEN used / THEN fine, fine, error."""
        cek = b"0123456789abcdef"
        for alg_id in (_alg_id(rfc8017.rsaEncryption), _alg_id(rfc8017.rsaEncryption, univ.Null(""))):
            ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, cek)
            self.assertEqual(decrypt_data_with_public_key_alg_id(self.key, alg_id, ct), cek)
        self._both(_alg_id(rfc8017.rsaEncryption, univ.OctetString(b"x")), BadAlgParams)

    def test_other_oids_are_bad_alg(self):
        """GIVEN id-sha256 and id-RSASSA-PSS as the key transport algorithm / WHEN used / THEN BadAlg."""
        self._both(_alg_id(rfc4055.id_sha256), BadAlg)
        self._both(_alg_id(rfc4055.id_RSASSA_PSS), BadAlg)

    def test_a_key_of_another_family_is_invalid_key_combination(self):
        """GIVEN an EC key, and the public key for decryption / WHEN used / THEN InvalidKeyCombination."""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(InvalidKeyCombination):
            encrypt_data_with_public_key_alg_id(ec_key.public_key(), self.sha256, b"cek")  # type: ignore[arg-type]
        with self.assertRaises(InvalidKeyCombination):
            decrypt_data_with_public_key_alg_id(ec_key, self.sha256, self.ct)  # type: ignore[arg-type]
        with self.assertRaises(InvalidKeyCombination):
            decrypt_data_with_public_key_alg_id(self.key.public_key(), self.sha256, self.ct)  # type: ignore[arg-type]

    def test_an_identifier_of_the_wrong_type_is_a_type_error(self):
        """GIVEN DER bytes instead of an AlgorithmIdentifier / WHEN used / THEN TypeError."""
        with self.assertRaises(TypeError):
            decrypt_data_with_public_key_alg_id(self.key, encoder.encode(self.sha256), self.ct)  # type: ignore[arg-type]


class TestSha1IsAnExplicitChoice(unittest.TestCase):
    """SHA-1 in the parameters of a received identifier is refused unless the caller allows it."""

    @classmethod
    def setUpClass(cls):
        """Load the RSA key of the vectors."""
        cls.key = load_private_key("openssl_rsa_key.pem")

    def test_every_way_to_name_sha1_is_refused_before_anything_is_decrypted(self):
        """GIVEN SHA-1 as the hash, as the MGF1 hash, explicit or by the defaults / WHEN opened / THEN BadAlg."""
        cases = {
            "explicit hash": make_alg_id("key_transport", "rsa-oaep", hash="sha1", mgf1_hash="sha256"),
            "explicit MGF1 hash": make_alg_id("key_transport", "rsa-oaep", hash="sha256", mgf1_hash="sha1"),
            "both defaults": make_alg_id("key_transport", "rsa-oaep", hash="sha1"),
            "hash absent": _oaep(_params(None, _mgf1("sha256"))),
            "MGF1 absent": _oaep(_params(_hash_id("sha256"))),
            "explicit defaults": _oaep(_params(_hash_id("sha1"), _mgf1("sha1"))),
            "empty SEQUENCE": _oaep("3000"),
        }
        for name, alg_id in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(BadAlg):
                    decrypt_data_with_public_key_alg_id(self.key, alg_id, b"not a ciphertext")

    def test_allow_sha1_lets_a_sha1_ciphertext_open_and_encryption_is_not_restricted(self):
        """GIVEN OAEP over SHA-1 / WHEN encrypted and opened with allow_sha1 / THEN the key; SHA-2 needs no flag."""
        alg_id = make_alg_id("key_transport", "rsa-oaep", hash="sha1")
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, b"cek")
        self.assertEqual(decrypt_data_with_public_key_alg_id(self.key, alg_id, ct, allow_sha1=True), b"cek")
        sha256 = make_alg_id("key_transport", "rsa-oaep", hash="sha256")
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), sha256, b"cek")
        self.assertEqual(decrypt_data_with_public_key_alg_id(self.key, sha256, ct, allow_sha1=False), b"cek")


class TestDecryptionFailureIsOneError(unittest.TestCase):
    """A failed decryption is an IntegrityError that says nothing about why."""

    @classmethod
    def setUpClass(cls):
        """Load the RSA key of the vectors and make another one."""
        cls.key = load_private_key("openssl_rsa_key.pem")
        cls.other = rsa.generate_private_key(65537, 2048)

    def test_every_kind_of_failure_of_oaep_gives_the_same_error_and_message(self):
        """GIVEN six kinds of bad ciphertext (wrong key, short, changed, empty, big, >= n) / WHEN opened / THEN one."""
        alg_id = make_alg_id("key_transport", "rsa-oaep", hash="sha256")
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, b"0123456789abcdef")
        wrong_key = encrypt_data_with_public_key_alg_id(self.other.public_key(), alg_id, b"0123456789abcdef")
        messages = set()
        for name, ciphertext in (
            ("wrong key", wrong_key),
            ("short", ct[:-1]),
            ("changed", bytes([ct[0] ^ 1]) + ct[1:]),
            ("empty", b""),
            ("oversize", ct + b"\x00"),
            ("above the modulus", b"\xff" * len(ct)),
        ):
            with self.subTest(case=name):
                with self.assertRaises(IntegrityError) as caught:
                    decrypt_data_with_public_key_alg_id(self.key, alg_id, ciphertext)
                messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1, messages)

    def test_pkcs1_v1_5_with_a_ciphertext_of_the_wrong_length_is_integrity_error(self):
        """GIVEN rsaEncryption and a short, an empty and an oversize ciphertext / WHEN opened / THEN IntegrityError."""
        alg_id = make_alg_id("key_transport", "rsa-pkcs1v15")
        ct = encrypt_data_with_public_key_alg_id(self.key.public_key(), alg_id, b"0123456789abcdef")
        messages = set()
        for ciphertext in (ct[:-1], b"", ct + b"\x00"):
            with self.assertRaises(IntegrityError) as caught:
                decrypt_data_with_public_key_alg_id(self.key, alg_id, ciphertext)
            messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1, messages)


class TestTheOldOaepHelperIsGone(unittest.TestCase):
    """``get_rsa_oaep_padding`` read the old parameter form and left the public API."""

    def test_not_exported_and_not_importable_from_compute(self):
        """GIVEN the package and compute / WHEN looked up / THEN get_rsa_oaep_padding is not there."""
        import keyutils_py

        self.assertNotIn("get_rsa_oaep_padding", keyutils_py.__all__)
        self.assertNotIn("get_rsa_oaep_padding", compute.__all__)
        self.assertFalse(hasattr(compute, "get_rsa_oaep_padding"))


if __name__ == "__main__":
    unittest.main()
