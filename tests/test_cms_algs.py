# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CMS digest profile of EdDSA, ML-DSA and SLH-DSA in :mod:`keyutils_py.cms_algs`."""

import unittest
from typing import Tuple

from keyutils_py.cms_algs import PURE_PQ_SIG_NAME_2_OID, cms_digest_algs
from keyutils_py.oids import compute_hash

# RFC 9882 Table 1, written out from the RFC and not derived from the code under test.
_TABLE_1 = {
    "ml-dsa-44": {"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512", "shake128", "shake256"},
    "ml-dsa-65": {"sha384", "sha512", "sha3_384", "sha3_512", "shake256"},
    "ml-dsa-87": {"sha512", "sha3_512", "shake256"},
}
# RFC 9814 Section 4: the hash of the tree, which is the digest that a signer uses when it has no reason to use another.
_SLH_DSA_TREE_HASH = {
    "128": {"sha2": "sha256", "shake": "shake128"},
    "192": {"sha2": "sha512", "shake": "shake256"},
    "256": {"sha2": "sha512", "shake": "shake256"},
}
_SLH_DSA_NAMES = [name for name in PURE_PQ_SIG_NAME_2_OID if name.startswith("slh-dsa-")]
_HASHES = ("sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512")
_HASHES += ("shake128", "shake256")


def _digests(name: str, signed_attrs: bool = True) -> Tuple[str, ...]:
    """Return the digests of a key, failing the test if the key has no rule."""
    result = cms_digest_algs(name, signed_attrs)
    assert result is not None, name
    return result


def _level(name: str) -> int:
    """Return the security level of an SLH-DSA name, which is the number before the ``s`` or ``f``."""
    return int(name.split("-")[-1][:-1])


class TestPureIdentifiers(unittest.TestCase):
    """The identifiers of the pure modes by key name."""

    def test_names_and_arcs_are_those_of_the_rfcs(self):
        """GIVEN the table WHEN read THEN each name has the last arc of RFC 9882 Section 2 or RFC 9814 Section 3."""
        names = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]
        names += [f"slh-dsa-{family}-{level}{variant}" for family in ("sha2", "shake") for level in (128, 192, 256)
                  for variant in ("s", "f")]
        got = {name: oid.asTuple() for name, oid in PURE_PQ_SIG_NAME_2_OID.items()}
        self.assertEqual({name: (2, 16, 840, 1, 101, 3, 4, 3, 17 + i) for i, name in enumerate(names)}, got)


class TestCmsDigestAlgs(unittest.TestCase):
    """The digests that a SignerInfo of a key may name."""

    def test_ml_dsa_with_signed_attrs_is_table_1_of_rfc_9882(self):
        """GIVEN each ML-DSA key WHEN signed attributes are present THEN the digests are those of Table 1."""
        for name, expected in _TABLE_1.items():
            with self.subTest(name):
                self.assertEqual(expected, set(_digests(name)))

    def test_the_default_comes_first_and_is_sha_512_for_ml_dsa(self):
        """GIVEN an ML-DSA key WHEN the digests are listed THEN SHA-512 is first, as RFC 9882 Section 3.3 has it."""
        for name in _TABLE_1:
            with self.subTest(name):
                self.assertEqual("sha512", _digests(name)[0])

    def test_slh_dsa_digest_has_at_least_twice_the_bits_of_the_level(self):
        """GIVEN each SLH-DSA key WHEN the digests are listed THEN those with 2 * level bits of output are in."""
        for name in _SLH_DSA_NAMES:
            with self.subTest(name):
                allowed = set(_digests(name))
                by_output = {h for h in _HASHES if 8 * len(compute_hash(h, b"")) >= 2 * _level(name)}
                self.assertEqual(by_output, allowed)

    def test_slh_dsa_default_is_the_hash_of_the_tree(self):
        """GIVEN each SLH-DSA key WHEN the digests are listed THEN the first is the hash of the tree (RFC 9814 4)."""
        for name in _SLH_DSA_NAMES:
            with self.subTest(name):
                family = name.split("-")[2]
                self.assertEqual(_SLH_DSA_TREE_HASH[str(_level(name))][family], _digests(name)[0])

    def test_without_signed_attrs_ml_dsa_uses_sha_512_only(self):
        """GIVEN an ML-DSA key WHEN signed attributes are absent THEN SHA-512 is the only digest (RFC 9882 3.3)."""
        for name in _TABLE_1:
            with self.subTest(name):
                self.assertEqual(("sha512",), cms_digest_algs(name, signed_attrs=False))

    def test_without_signed_attrs_slh_dsa_uses_the_tree_hash_or_sha_256(self):
        """GIVEN an SLH-DSA key WHEN signed attributes are absent THEN the tree hash and SHA-256 are allowed."""
        for name in _SLH_DSA_NAMES:
            with self.subTest(name):
                default = _SLH_DSA_TREE_HASH[str(_level(name))][name.split("-")[2]]
                self.assertEqual({default, "sha256"}, set(_digests(name, signed_attrs=False)))

    def test_eddsa_has_the_one_digest_of_rfc_8419(self):
        """GIVEN an EdDSA key WHEN the digests are listed THEN there is one: SHA-512 or SHAKE256 (RFC 8419 3.1)."""
        self.assertEqual(("sha512",), cms_digest_algs("ed25519"))
        self.assertEqual(("shake256",), cms_digest_algs("ed448"))
        self.assertEqual(("shake256",), cms_digest_algs("ed448", signed_attrs=False))

    def test_other_keys_leave_the_digest_to_the_signer(self):
        """GIVEN a key that is not EdDSA, ML-DSA or SLH-DSA WHEN the digests are listed THEN there is no rule."""
        for name in ("rsa", "ecdsa", "dsa", "ml-kem-512", "unknown"):
            with self.subTest(name):
                self.assertIsNone(cms_digest_algs(name))


if __name__ == "__main__":
    unittest.main()
