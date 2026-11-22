# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the OID lookup tables."""

import unittest

import keyutils_py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from keyutils_py import load_private_key_from_one_asym_key, load_public_key_from_spki, prepare_spki
from keyutils_py.keys.trad_kem_keys import RSADecapKey, RSAEncapKey
from keyutils_py.oids import (
    COMPOSITE_KEM_OID_2_NAME,
    KEM_OID_2_NAME,
    PQ_KEM_OID_2_NAME,
    id_alg,
    id_alg_PWRI_KEK,
    id_rsa_kem_spki,
    may_return_oid_to_name,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5990, rfc9690


class TestKemOidTable(unittest.TestCase):
    """``KEM_OID_2_NAME`` names every KEM OID, including the traditional RSA-KEM."""

    def test_rsa_kem_is_named(self):
        """GIVEN the ISO 18033-2 RSA-KEM OID / WHEN looked up / THEN its name is `rsa-kem`."""
        self.assertEqual(KEM_OID_2_NAME[rfc5990.id_kem_rsa], "rsa-kem")

    def test_pq_and_composite_kems_are_named(self):
        """GIVEN the PQ and composite KEM tables / WHEN merged / THEN every entry is in `KEM_OID_2_NAME`."""
        for table in (PQ_KEM_OID_2_NAME, COMPOSITE_KEM_OID_2_NAME):
            for oid, name in table.items():
                with self.subTest(name=name):
                    self.assertEqual(KEM_OID_2_NAME[oid], name)


def _spki_with_oid(oid: univ.ObjectIdentifier) -> rfc5280.SubjectPublicKeyInfo:
    """Return the SPKI of a fresh RSA-KEM public key, with the algorithm OID replaced by ``oid``."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki, _ = decoder.decode(
        encoder.encode(prepare_spki(private_key, key_name="rsa-kem")), asn1Spec=rfc5280.SubjectPublicKeyInfo()
    )
    spki["algorithm"]["algorithm"] = oid
    return spki


def _failure_of_loading(spki: rfc5280.SubjectPublicKeyInfo) -> type:
    """Return the exception class raised by ``load_public_key_from_spki``; fail the test if it loads."""
    oid = str(spki["algorithm"]["algorithm"])  # ``RSAEncapKey.from_spki`` overwrites the OID of its argument.
    try:
        load_public_key_from_spki(spki)
    except Exception as err:  # pylint: disable=broad-exception-caught
        return type(err)
    raise AssertionError(f"The SPKI with OID {oid} was loaded.")


class TestRsaKemSpkiOid(unittest.TestCase):
    """The RSA-KEM key OID is ``id-rsa-kem-spki`` of RFC 9690 Appendix B, not the ``id-alg`` arc."""

    def test_constant_is_the_rfc_9690_oid(self):
        """GIVEN the RSA-KEM SPKI constant / WHEN compared with RFC 9690 / THEN it is ...16.3.14, not the arc."""
        self.assertEqual(id_rsa_kem_spki, rfc9690.id_rsa_kem_spki)
        self.assertEqual(str(id_rsa_kem_spki), "1.2.840.113549.1.9.16.3.14")
        self.assertNotEqual(id_rsa_kem_spki, id_alg)

    def test_key_class_reports_the_rfc_oid(self):
        """GIVEN an RSA-KEM public and private key / WHEN `get_oid` is called / THEN it is the RFC 9690 OID."""
        private_key = RSADecapKey(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        self.assertEqual(private_key.public_key().get_oid(), rfc9690.id_rsa_kem_spki)
        self.assertEqual(private_key.get_oid(), rfc9690.id_rsa_kem_spki)

    def test_oid_is_named_rsa_kem(self):
        """GIVEN the RSA-KEM SPKI OID / WHEN looked up by name / THEN it is `rsa-kem`, like the ISO 18033-2 OID."""
        self.assertEqual(may_return_oid_to_name(rfc9690.id_rsa_kem_spki), "rsa-kem")

    def test_prepare_spki_uses_the_rfc_oid(self):
        """GIVEN key name `rsa-kem` / WHEN preparing an SPKI, with or without a key / THEN the OID is RFC 9690's."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for key_name in ("rsa-kem", "rsa_kem"):
            for spki in (prepare_spki(private_key, key_name=key_name), prepare_spki(for_kga=True, key_name=key_name)):
                with self.subTest(key_name=key_name, for_kga=not spki["subjectPublicKey"].asOctets()):
                    self.assertEqual(spki["algorithm"]["algorithm"], rfc9690.id_rsa_kem_spki)

    def test_spki_with_the_rfc_oid_loads(self):
        """GIVEN an SPKI with the RFC 9690 OID / WHEN loaded / THEN it is an RSA-KEM public key."""
        public_key = load_public_key_from_spki(_spki_with_oid(rfc9690.id_rsa_kem_spki))
        self.assertIsInstance(public_key, RSAEncapKey)

    def test_spki_with_the_old_oid_no_longer_loads(self):
        """GIVEN an SPKI with the id-alg arc as OID / WHEN loaded / THEN it fails like any unknown OID."""
        unknown = _failure_of_loading(_spki_with_oid(univ.ObjectIdentifier("1.2.3.4.5.6")))
        self.assertIs(_failure_of_loading(_spki_with_oid(id_alg)), unknown)

    def test_private_key_round_trips_with_the_rfc_oid(self):
        """GIVEN an RSA-KEM private key / WHEN saved and loaded as OneAsymmetricKey / THEN it is an RSA-KEM key."""
        private_key = RSADecapKey(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        self.assertEqual(decoder.decode(der)[0][1][0], rfc9690.id_rsa_kem_spki)
        loaded = load_private_key_from_one_asym_key(der)
        self.assertIsInstance(loaded, RSADecapKey)
        self.assertEqual(loaded.public_key().get_oid(), rfc9690.id_rsa_kem_spki)


class TestPwriKekOid(unittest.TestCase):
    """``id_alg_PWRI_KEK`` is the OID of RFC 3211 Section 2.3."""

    def test_constant_is_the_rfc_3211_oid(self):
        """GIVEN the PWRI-KEK constant / WHEN compared with RFC 3211 Section 2.3 / THEN it is id-alg 9, exported."""
        self.assertEqual(str(id_alg_PWRI_KEK), "1.2.840.113549.1.9.16.3.9")
        self.assertEqual(id_alg_PWRI_KEK, id_alg + (9,))
        self.assertIs(keyutils_py.id_alg_PWRI_KEK, id_alg_PWRI_KEK)


if __name__ == "__main__":
    unittest.main()
