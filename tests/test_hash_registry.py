# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the one hash registry behind the hash helpers in :mod:`keyutils_py.oids`."""

import hashlib
import unittest
from typing import Callable, Dict, Set

from keyutils_py.oids import (
    SLH_DSA_PRE_HASH_OID_2_NAME,
    compute_hash,
    get_hash_from_oid,
    hash_name_to_instance,
    sha_alg_name_to_oid,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5480, rfc8017, rfc8702, rfc9688

# name -> OID, taken from the RFC modules and not from ``keyutils_py``.
_EXPECTED: Dict[str, univ.ObjectIdentifier] = {
    "sha1": rfc5480.id_sha1,
    "sha224": rfc8017.id_sha224,
    "sha256": rfc8017.id_sha256,
    "sha384": rfc8017.id_sha384,
    "sha512": rfc8017.id_sha512,
    "sha3_224": rfc9688.id_sha3_224,
    "sha3_256": rfc9688.id_sha3_256,
    "sha3_384": rfc9688.id_sha3_384,
    "sha3_512": rfc9688.id_sha3_512,
    "shake128": rfc8702.id_shake128,
    "shake256": rfc8702.id_shake256,
}
_DATA = b"abc"


def _hashlib_digest(name: str, data: bytes) -> bytes:
    """Return the ``hashlib`` digest; SHAKE128 gives 32 and SHAKE256 64 bytes, as in RFC 9814 Section 4."""
    if name == "shake128":
        return hashlib.shake_128(data).digest(32)
    if name == "shake256":
        return hashlib.shake_256(data).digest(64)
    return hashlib.new(name, data).digest()


def _compute_hash_of_data(name: str) -> bytes:
    """Hash the test data with ``compute_hash``, so it can be compared with the other name based entry points."""
    return compute_hash(name, _DATA)


def _accepted(func: Callable[[str], object], candidates: Set[str]) -> Set[str]:
    """Return the candidates that ``func`` takes without raising ``ValueError``."""
    accepted = set()
    for name in candidates:
        try:
            func(name)
        except ValueError:
            continue
        accepted.add(name)
    return accepted


class TestHashRegistry(unittest.TestCase):
    """Every hash entry point reads the same registry of names, OIDs and digests."""

    def test_compute_hash_matches_hashlib(self):
        """GIVEN every registry name / WHEN `compute_hash` hashes `abc` / THEN the digest is the one of hashlib."""
        for name in _EXPECTED:
            with self.subTest(name=name):
                self.assertEqual(compute_hash(name, _DATA), _hashlib_digest(name, _DATA))

    def test_compute_hash_ignores_case(self):
        """GIVEN an upper-case name / WHEN `compute_hash` is called / THEN it still hashes."""
        self.assertEqual(compute_hash("SHA3_256", _DATA), hashlib.sha3_256(_DATA).digest())

    def test_sha_alg_name_to_oid_matches_rfc(self):
        """GIVEN every registry name / WHEN the OID is looked up / THEN it is the OID of the RFC."""
        for name, oid in _EXPECTED.items():
            with self.subTest(name=name):
                self.assertEqual(sha_alg_name_to_oid(name), oid)

    def test_sha_alg_name_to_oid_ignores_case(self):
        """GIVEN an upper-case name / WHEN the OID is looked up / THEN the OID is found."""
        self.assertEqual(sha_alg_name_to_oid("SHA256"), rfc8017.id_sha256)

    def test_get_hash_from_oid_names_every_registry_oid(self):
        """GIVEN the hash OIDs of the RFCs, SHA-3 (RFC 9688) included / WHEN looked up / THEN the name comes back."""
        for name, oid in _EXPECTED.items():
            with self.subTest(name=name):
                self.assertEqual(get_hash_from_oid(oid), name)

    def test_oid_round_trips(self):
        """GIVEN every registry name / WHEN name -> OID -> name / THEN the name comes back."""
        for name in _EXPECTED:
            with self.subTest(name=name):
                self.assertEqual(get_hash_from_oid(sha_alg_name_to_oid(name)), name)

    def test_get_hash_from_oid_unknown_oid_is_none(self):
        """GIVEN an OID that is not a hash / WHEN `get_hash_from_oid` is called / THEN it returns None."""
        self.assertIsNone(get_hash_from_oid(univ.ObjectIdentifier("1.2.3.4.5.6")))
        self.assertIsNone(get_hash_from_oid(rfc8017.sha256WithRSAEncryption))

    def test_get_hash_from_oid_pre_hash_oid_keeps_the_embedded_hash(self):
        """GIVEN an SLH-DSA pre-hash OID / WHEN `get_hash_from_oid` is called / THEN it names a registry hash."""
        for oid in SLH_DSA_PRE_HASH_OID_2_NAME:
            with self.subTest(oid=str(oid)):
                self.assertIn(get_hash_from_oid(oid), _EXPECTED)

    def test_hash_name_to_instance_digest_sizes(self):
        """GIVEN every registry name / WHEN the instance is built / THEN its digest size is the one of the digest."""
        for name in _EXPECTED:
            with self.subTest(name=name):
                self.assertEqual(hash_name_to_instance(name).digest_size, len(_hashlib_digest(name, _DATA)))

    def test_all_name_entry_points_accept_the_same_names(self):
        """GIVEN registry and foreign names / WHEN each name entry point is tried / THEN each accepts the registry."""
        candidates = set(_EXPECTED) | {"md5", "sha-256", "sha512_256", "sha3-256", "shake_128", "blake2b", ""}
        for func in (_compute_hash_of_data, sha_alg_name_to_oid, hash_name_to_instance):
            with self.subTest(entry_point=func.__name__):
                self.assertEqual(_accepted(func, candidates), set(_EXPECTED))

    def test_unknown_name_raises_value_error(self):
        """GIVEN an unknown name / WHEN any name based entry point is called / THEN a ValueError is raised."""
        for func in (_compute_hash_of_data, sha_alg_name_to_oid, hash_name_to_instance):
            with self.subTest(entry_point=func.__name__):
                with self.assertRaises(ValueError):
                    func("md5")


if __name__ == "__main__":
    unittest.main()
