# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the public loaders and consistency check exported by ``keyutils_py``."""

import os
import tempfile
import unittest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from keyutils_py import (
    check_consistency_sig_alg_id_and_key,
    compute_decaps,
    compute_encaps,
    encode_to_der,
    generate_key,
    is_public_key_oid,
    load_private_key_from_one_asym_key,
    load_public_key_from_spki,
    prepare_spki,
    save_key,
)
from keyutils_py.exceptions import BadAlg, BadSigAlgID, InvalidKeyCombination, InvalidKeyData
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.chempat_key import ChempatPublicKey
from keyutils_py.keys.trad_keys import DSAPrivateKey
from keyutils_py.keyutils import prepare_alg_id, prepare_sig_alg_id
from keyutils_py.oids import (
    CHEMPAT_NAME_2_OID,
    COMPOSITE_KEM_NAME_2_OID,
    COMPOSITE_SIG_NAME_TO_OID,
    DSA_OID_2_NAME,
    ECDSA_OID_2_NAME,
    FALCON_NAME_2_OID,
    FRODOKEM_NAME_2_OID,
    MCELIECE_NAME_2_OID,
    ML_DSA_NAME_2_OID,
    ML_DSA_PRE_HASH_OID_2_NAME,
    ML_KEM_NAME_2_OID,
    PQ_KEM_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_STATEFUL_HASH_SIG_NAME_2_OID,
    RSA_OID_2_NAME,
    SLH_DSA_NAME_2_OID,
    SLH_DSA_PRE_HASH_NAME_2_OID,
    XWING_OID_STR,
    get_hash_from_oid,
    id_ml_dsa_44_with_sha512,
    id_rsa_kem_spki,
)
from keyutils_py.utils import OQS_AVAILABLE, load_and_decode_pem_file, try_decode_pyasn1
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3279, rfc5280, rfc5480, rfc5958, rfc9481


def _spki_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _saved_der(key) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "key.pem")
        save_key(key, path, password=None)
        return load_and_decode_pem_file(path)


class TestLoadPrivateKeyFromOneAsymKey(unittest.TestCase):
    """``load_private_key_from_one_asym_key`` takes DER bytes or a decoded structure."""

    def test_bytes_and_structure_round_trip(self):
        """GIVEN PQ and stateful keys / WHEN loaded from bytes and from a structure / THEN both match."""
        for alg in ("ml-kem-768", "ml-dsa-65", "hss_lms_sha256_m32_h5_lmots_sha256_n32_w8"):
            with self.subTest(alg=alg):
                key = generate_key(alg)
                der = _saved_der(key)
                structure, _ = try_decode_pyasn1(der, rfc5958.OneAsymmetricKey())
                for loaded in (load_private_key_from_one_asym_key(der), load_private_key_from_one_asym_key(structure)):
                    self.assertIs(type(loaded), type(key))
                    self.assertEqual(_spki_der(loaded.public_key()), _spki_der(key.public_key()))

    def test_dsa(self):
        """GIVEN a PKCS#8 DSA key / WHEN loaded / THEN the private value matches."""
        key = DSAPrivateKey.generate(2048)
        der = key.private_bytes(serialization.Encoding.DER)
        loaded = load_private_key_from_one_asym_key(der)
        self.assertIsInstance(loaded, DSAPrivateKey)
        assert isinstance(loaded, DSAPrivateKey)  # narrows the union for the type checker
        self.assertEqual(loaded.x, key.x)

    def test_garbage_raises_invalid_key_data(self):
        """GIVEN bytes that are not a OneAsymmetricKey / WHEN loaded / THEN InvalidKeyData."""
        with self.assertRaises(InvalidKeyData):
            load_private_key_from_one_asym_key(b"\x30\x03\x02\x01\x00")


class TestLoadPublicKeyFromSpki(unittest.TestCase):
    """``load_public_key_from_spki`` takes DER bytes or a decoded structure."""

    def test_bytes_and_structure_round_trip(self):
        """GIVEN PQ and hybrid public keys / WHEN loaded from bytes and a structure / THEN both match."""
        for alg in ("ml-kem-768", "ml-dsa-65", "xwing"):
            with self.subTest(alg=alg):
                pub = generate_key(alg).public_key()
                self.assertEqual(_spki_der(load_public_key_from_spki(_spki_der(pub))), _spki_der(pub))
                self.assertEqual(_spki_der(load_public_key_from_spki(prepare_spki(pub))), _spki_der(pub))

    def test_dsa(self):
        """GIVEN a DSA SPKI / WHEN loaded / THEN the public key is equal."""
        pub = DSAPrivateKey.generate(2048).public_key()
        self.assertEqual(load_public_key_from_spki(_spki_der(pub)), pub)

    def test_garbage_raises_invalid_key_data(self):
        """GIVEN bytes that are not a SubjectPublicKeyInfo / WHEN loaded / THEN InvalidKeyData."""
        with self.assertRaises(InvalidKeyData):
            load_public_key_from_spki(b"\x30\x03\x02\x01\x00")

    def test_composite_sig_with_wrong_rsa_size_raises_invalid_key_combination(self):
        """GIVEN a composite signature key with a 512-bit RSA key / WHEN its SPKI is loaded / THEN the combination fails."""
        key = generate_key(
            "composite-sig", trad_key=TradKeyFactory.generate_trad_key("bad_rsa_key"), pq_key=generate_key("ml-dsa-44")
        )
        with self.assertRaises(InvalidKeyCombination):
            load_public_key_from_spki(prepare_spki(key))

    def test_traditional_key_is_loaded(self):
        """GIVEN an EC SPKI / WHEN loaded / THEN the EC public key is returned."""
        pub = TradKeyFactory.generate_trad_key("ecdsa").public_key()
        self.assertEqual(load_public_key_from_spki(_spki_der(pub)).public_numbers(), pub.public_numbers())

    def test_what_cryptography_cannot_load_raises_bad_alg(self):
        """GIVEN an EC SPKI on secp112r1 or of an unknown OID / WHEN loaded / THEN BadAlg from UnsupportedAlgorithm."""
        der = _spki_der(TradKeyFactory.generate_trad_key("ecdsa").public_key())
        on_secp112r1, _ = try_decode_pyasn1(der, rfc5280.SubjectPublicKeyInfo())
        on_secp112r1["algorithm"]["parameters"] = encode_to_der(univ.ObjectIdentifier("1.3.132.0.6"))  # SEC 2 secp112r1
        unknown_oid, _ = try_decode_pyasn1(der, rfc5280.SubjectPublicKeyInfo())
        unknown_oid["algorithm"]["algorithm"] = univ.ObjectIdentifier("1.2.3.4.5.6")  # an OID of no table
        for name, spki in (("secp112r1", on_secp112r1), ("unknown OID", unknown_oid)):
            for data in (spki, encode_to_der(spki)):
                with self.subTest(name=name, type=type(data).__name__):
                    with self.assertRaises(BadAlg) as caught:
                        load_public_key_from_spki(data)
                    self.assertIsInstance(caught.exception.__cause__, UnsupportedAlgorithm)


class TestCheckConsistency(unittest.TestCase):
    """``check_consistency_sig_alg_id_and_key`` accepts matching and rejects mismatching pairs."""

    @classmethod
    def setUpClass(cls):
        """Generate one key per family once."""
        cls.rsa = TradKeyFactory.generate_trad_key("rsa")
        cls.ec = TradKeyFactory.generate_trad_key("ecdsa")
        cls.ml_dsa = generate_key("ml-dsa-65")

    def test_matching_pairs(self):
        """GIVEN an alg_id built for the key / WHEN checked / THEN no error (public or private key)."""
        check_consistency_sig_alg_id_and_key(prepare_sig_alg_id(self.rsa, hash_alg="sha256"), self.rsa.public_key())
        check_consistency_sig_alg_id_and_key(prepare_sig_alg_id(self.ec, hash_alg="sha256"), self.ec)
        check_consistency_sig_alg_id_and_key(prepare_alg_id(PQ_NAME_2_OID["ml-dsa-65"]), self.ml_dsa.public_key())

    def test_slh_dsa_pure_and_pre_hash_oids(self):
        """GIVEN an SLH-DSA key / WHEN checked against its pure and its pre-hash OID / THEN both are consistent."""
        pure = {name: oid for name, oid in SLH_DSA_NAME_2_OID.items() if name not in SLH_DSA_PRE_HASH_NAME_2_OID}
        for name, oid in pure.items():
            with self.subTest(name=name):
                self.assertIsNone(get_hash_from_oid(oid))
                public_key = generate_key(name).public_key()
                check_consistency_sig_alg_id_and_key(prepare_alg_id(oid), public_key)
                pre_hash = next(pre for pre in SLH_DSA_PRE_HASH_NAME_2_OID if pre.startswith(name + "-"))
                check_consistency_sig_alg_id_and_key(prepare_alg_id(SLH_DSA_PRE_HASH_NAME_2_OID[pre_hash]), public_key)

    def test_slh_dsa_other_parameter_set_is_rejected(self):
        """GIVEN an SLH-DSA key / WHEN checked against the OID of another parameter set / THEN BadSigAlgID."""
        public_key = generate_key("slh-dsa-shake-128s").public_key()
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(prepare_alg_id(SLH_DSA_NAME_2_OID["slh-dsa-sha2-128s"]), public_key)

    def test_mismatching_pairs(self):
        """GIVEN an alg_id for another key type / WHEN checked / THEN BadSigAlgID."""
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(prepare_sig_alg_id(self.ec, hash_alg="sha256"), self.rsa.public_key())
        with self.assertRaises(BadSigAlgID):
            check_consistency_sig_alg_id_and_key(prepare_alg_id(PQ_NAME_2_OID["ml-dsa-65"]), self.ec.public_key())


class TestChempatRoundTrip(unittest.TestCase):
    """A Chempat key survives save -> load; the raw public-key layout is written and parsed consistently."""

    ALGORITHMS = (
        "chempat-ml-kem-768-x25519",
        "chempat-ml-kem-1024-x448",
        "chempat-ml-kem-768-ecdh-secp256r1",
        "chempat-ml-kem-1024-ecdh-secp384r1",
    )

    def test_private_key_round_trip_decapsulates(self):
        """GIVEN a saved Chempat key / WHEN reloaded / THEN it decapsulates what the original encapsulated."""
        for alg in self.ALGORITHMS:
            with self.subTest(alg=alg):
                key = generate_key(alg)
                reloaded = load_private_key_from_one_asym_key(_saved_der(key))
                shared, ciphertext = compute_encaps(key.public_key())  # type: ignore[arg-type]
                self.assertEqual(compute_decaps(reloaded, ciphertext), shared)  # type: ignore[arg-type]

    def test_spki_round_trip(self):
        """GIVEN a Chempat public key / WHEN its SPKI is loaded / THEN the raw bytes are unchanged."""
        for alg in self.ALGORITHMS:
            with self.subTest(alg=alg):
                pub = generate_key(alg).public_key()
                loaded = load_public_key_from_spki(prepare_spki(pub))
                self.assertEqual(loaded.public_bytes_raw(), pub.public_bytes_raw())  # type: ignore[union-attr]

    def test_malformed_public_bytes_rejected(self):
        """GIVEN truncated, over-long or empty raw bytes / WHEN parsed / THEN InvalidKeyData."""
        name = "chempat-ml-kem-768-x25519"
        raw = generate_key(name).public_key().public_bytes_raw()  # type: ignore[union-attr]
        for data in (raw[:20], raw + b"\x00", b""):
            with self.subTest(length=len(data)):
                with self.assertRaises(InvalidKeyData):
                    ChempatPublicKey.from_public_bytes(data, name)


# PKCS #3 dhKeyAgreement: the second DH identifier that the loader knows, next to X9.42 dhpublicnumber.
_DH_KEY_AGREEMENT = univ.ObjectIdentifier("1.2.840.113549.1.3.1")

# The key algorithms of a SubjectPublicKeyInfo by family; the OIDs of the post-quantum and hybrid families are
# those of the tables of keyutils. The HashML-DSA identifiers are left out of "ML-DSA" (RFC 9881 Section 8.3), the
# HashSLH-DSA identifiers stay in "SLH-DSA" (RFC 9909 Section 5).
_KEY_OIDS_BY_FAMILY = {
    "rsaEncryption": [rfc9481.rsaEncryption],
    "id-RSASSA-PSS": [rfc9481.id_RSASSA_PSS],
    "EC": [rfc5480.id_ecPublicKey],
    "EdDSA": [rfc9481.id_Ed25519, rfc9481.id_Ed448],
    "XDH": [rfc9481.id_X25519, rfc9481.id_X448],
    "DSA": [rfc5480.id_dsa],
    "DH": [rfc3279.dhpublicnumber, _DH_KEY_AGREEMENT],
    "RSA-KEM": [id_rsa_kem_spki],
    "ML-DSA": [oid for oid in ML_DSA_NAME_2_OID.values() if oid not in ML_DSA_PRE_HASH_OID_2_NAME],
    "ML-KEM": list(ML_KEM_NAME_2_OID.values()),
    "SLH-DSA": list(SLH_DSA_NAME_2_OID.values()),
    "Falcon": list(FALCON_NAME_2_OID.values()),
    "FrodoKEM": list(FRODOKEM_NAME_2_OID.values()),
    "McEliece": list(MCELIECE_NAME_2_OID.values()),
    "sntrup761": [PQ_KEM_NAME_2_OID["sntrup761"]],
    "stateful hash-based": list(PQ_STATEFUL_HASH_SIG_NAME_2_OID.values()),
    "composite signature": list(COMPOSITE_SIG_NAME_TO_OID.values()),
    "composite KEM": list(COMPOSITE_KEM_NAME_2_OID.values()),
    "Chempat": list(CHEMPAT_NAME_2_OID.values()),
    "X-Wing": [XWING_OID_STR],
}


class TestIsPublicKeyOid(unittest.TestCase):
    """``is_public_key_oid`` is ``True`` for the OIDs that ``load_public_key_from_spki`` takes as a key, not HashML-DSA."""

    def test_every_key_family_is_a_public_key_oid(self):
        """GIVEN the OIDs of each key family / WHEN asked / THEN every one is a public key OID, as OID and as str."""
        for family, oids in _KEY_OIDS_BY_FAMILY.items():
            with self.subTest(family=family):
                self.assertTrue(oids)
                for oid in oids:
                    self.assertTrue(is_public_key_oid(oid), str(oid))
                    self.assertTrue(is_public_key_oid(str(oid)), str(oid))

    def test_signature_algorithms_are_no_public_key_oids(self):
        """GIVEN signature, hash and unsupported key agreement OIDs / WHEN asked / THEN none is a public key OID."""
        oids = [
            *RSA_OID_2_NAME,  # sha256WithRSAEncryption, ...
            *ECDSA_OID_2_NAME,
            *DSA_OID_2_NAME,
            rfc9481.id_RSASSA_PSS_SHAKE128,  # RFC 8702: the key is rsaEncryption or id-RSASSA-PSS
            rfc9481.id_RSASSA_PSS_SHAKE256,
            rfc9481.id_sha256,
            rfc5480.id_ecDH,  # the loader does not know it
            rfc5480.id_ecMQV,
        ]
        for oid in oids:
            with self.subTest(oid=str(oid)):
                self.assertFalse(is_public_key_oid(oid))
                self.assertFalse(is_public_key_oid(str(oid)))

    def test_unknown_oid_is_no_public_key_oid(self):
        """GIVEN an OID of no table / WHEN asked / THEN False, and the loader raises BadAlg for it."""
        oid = univ.ObjectIdentifier("1.2.3.4.5.99")
        self.assertFalse(is_public_key_oid(oid))
        spki = prepare_spki(generate_key("ml-dsa-44").public_key())
        spki["algorithm"]["algorithm"] = oid
        with self.assertRaises(BadAlg):
            load_public_key_from_spki(spki)

    def test_the_oid_of_a_generated_key_is_a_public_key_oid(self):
        """GIVEN a fresh key of each family that needs no liboqs / WHEN its SPKI is prepared / THEN its OID is one."""
        names = (
            "rsa",
            "ecdsa",
            "ed25519",
            "ed448",
            "x25519",
            "x448",
            "dsa",
            "dh",
            "rsa-kem",
            "ml-dsa-44",
            "ml-kem-512",
            "slh-dsa-sha2-128s",
            "hss",
            "composite-sig-ml-dsa-44-ecdsa-secp256r1",
            "composite-kem-ml-kem-768-ecdh-secp256r1",
            "chempat-ml-kem-768-x25519",
            "xwing",
        )
        for name in names:
            with self.subTest(key=name):
                spki = prepare_spki(generate_key(name).public_key())
                self.assertTrue(is_public_key_oid(spki["algorithm"]["algorithm"]))
        pss_spki = prepare_spki(generate_key("rsa").public_key(), use_rsa_pss=True)
        self.assertEqual(pss_spki["algorithm"]["algorithm"], rfc9481.id_RSASSA_PSS)
        self.assertTrue(is_public_key_oid(pss_spki["algorithm"]["algorithm"]))

    @unittest.skipUnless(OQS_AVAILABLE, "liboqs not installed; oqs-only tests skipped")
    def test_the_oid_of_a_generated_oqs_only_key_is_a_public_key_oid(self):
        """GIVEN a fresh Falcon, McEliece, sntrup761 and XMSS key / WHEN its SPKI is prepared / THEN its OID is one."""
        for name in ("falcon-512", "mceliece-348864", "sntrup761", "xmss"):
            with self.subTest(key=name):
                spki = prepare_spki(generate_key(name).public_key())
                self.assertTrue(is_public_key_oid(spki["algorithm"]["algorithm"]))

    def test_hash_ml_dsa_identifiers_are_no_public_key_oids_although_the_loader_reads_them(self):
        """GIVEN the HashML-DSA OIDs / WHEN asked / THEN none is a public key OID (RFC 9881 Section 8.3).

        The RFC says: "public keys identified by id-hash-ml-dsa-44-with-sha512, id-hash-ml-dsa-65-with-sha512, and
        id-hash-ml-dsa-87-with-sha512 MUST NOT be in X.509 certificates used for CRLs, OCSP, certificate issuance,
        and related PKIX protocols". The loader still reads such an SPKI as the pure key, so a consumer that must
        not accept it asks ``is_public_key_oid`` first.
        """
        self.assertEqual(len(ML_DSA_PRE_HASH_OID_2_NAME), 3)
        for oid in ML_DSA_PRE_HASH_OID_2_NAME:
            with self.subTest(oid=str(oid)):
                self.assertFalse(is_public_key_oid(oid))
                self.assertFalse(is_public_key_oid(str(oid)))
        pub = generate_key("ml-dsa-44").public_key()
        spki = prepare_spki(pub)
        spki["algorithm"]["algorithm"] = id_ml_dsa_44_with_sha512
        self.assertEqual(_spki_der(load_public_key_from_spki(spki)), _spki_der(pub))

    def test_hash_slh_dsa_identifiers_are_public_key_oids(self):
        """GIVEN the HashSLH-DSA OIDs / WHEN asked / THEN every one is a public key OID (RFC 9909 Section 5).

        The RFC says: "The AlgorithmIdentifier for an SLH-DSA public key MUST use one of the id-slh-dsa-* or
        id-hash-slh-dsa-* object identifiers from Section 3", and Section 8: "SLH-DSA uses the same OID to identify
        a public key and a signature algorithm". Unlike RFC 9881 for ML-DSA, it does not exclude HashSLH-DSA.
        """
        self.assertEqual(len(SLH_DSA_PRE_HASH_NAME_2_OID), 12)
        for oid in SLH_DSA_PRE_HASH_NAME_2_OID.values():
            with self.subTest(oid=str(oid)):
                self.assertTrue(is_public_key_oid(oid))
                self.assertTrue(is_public_key_oid(str(oid)))


if __name__ == "__main__":
    unittest.main()
