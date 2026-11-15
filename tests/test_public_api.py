# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Snapshot of the public API: ``keyutils_py.__all__`` and the shape of the signature entry points.

A name may be added to ``tests/golden/public_api.tsv`` in the same change that adds it to ``__all__``. Removing or
renaming one is a breaking change of the package and has to show up as a changed line here.
"""

import inspect
import unittest
from pathlib import Path

import keyutils_py
from keyutils_py import algorithms

GOLDEN = Path(__file__).with_name("golden") / "public_api.tsv"

# The names that the package had before the signature algorithm table: none of them may go away.
_NAMES_OF_THE_FIRST_RELEASE = frozenset(
    {
        "MissingOQSDependencyError",
        "check_consistency_sig_alg_id_and_key",
        "compute_decaps",
        "compute_ecdh",
        "compute_encaps",
        "decrypt_data_with_public_key_alg_id",
        "encrypt_data_with_public_key_alg_id",
        "estimate_key_security_strength",
        "generate_key",
        "get_key_name",
        "get_rsa_oaep_padding",
        "load_private_key_from_file",
        "load_private_key_from_one_asym_key",
        "load_public_key_from_file",
        "load_public_key_from_spki",
        "manipulate_pq_stateful_signature_bytes",
        "manipulate_sig_based_on_key",
        "modify_pq_stateful_sig_private_key",
        "prepare_spki",
        "save_key",
        "sign_data",
        "sign_with_alg_id",
        "validate_sig_alg_id",
        "verify_signature",
        "verify_signature_with_alg_id",
    }
)

# str(inspect.signature(...)) of the entry points whose options are keyword-only.
_SIGNATURES = {
    "sign_data": "(data: 'bytes', key: 'SignKey', *, hash_alg: 'Optional[str]' = None, ctx: 'bytes' = b'', "
    "use_rsa_pss: 'bool' = False, salt_length: 'Optional[int]' = None, second_hash_alg: 'Optional[str]' = None) "
    "-> 'bytes'",
    "verify_signature": "(public_key: 'VerifyKey', signature: 'bytes', data: 'bytes', *, "
    "hash_alg: 'Optional[str]' = None, ctx: 'bytes' = b'', use_rsa_pss: 'bool' = False, "
    "salt_length: 'Optional[int]' = None, use_pre_hash: 'bool' = False) -> 'None'",
    "sign_with_alg_id": "(key: 'SignKey', alg_id: 'rfc9480.AlgorithmIdentifier', data: 'bytes', *, "
    "hash_alg: 'Optional[str]' = None) -> 'bytes'",
    "verify_signature_with_alg_id": "(public_key: 'VerifyKey', alg_id: 'rfc9480.AlgorithmIdentifier', data: 'bytes', "
    "signature: 'bytes', *, hash_alg: 'Optional[str]' = None, allow_sha1: 'bool' = False) -> 'None'",
    "validate_sig_alg_id": "(alg_id: 'rfc9480.AlgorithmIdentifier', *, strict: 'bool' = True) -> 'None'",
    "prepare_sig_alg_id": "(key: 'Union[PrivateKey, PublicKey]', hash_alg: 'Optional[str]' = None, "
    "use_rsa_pss: 'bool' = False) -> 'rfc5280.AlgorithmIdentifier'",
    "prepare_hash_alg_id": "(hash_alg: 'str', fill_random_params: 'bool' = False, *, "
    "with_null: 'Optional[bool]' = None) -> 'rfc5280.AlgorithmIdentifier'",
}


def _golden_names() -> list:
    """Return the names of the golden file."""
    lines = GOLDEN.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "name"
    return lines[1:]


class TestPublicApi(unittest.TestCase):
    """``keyutils_py.__all__`` is exactly the golden list."""

    def test_all_equals_the_golden_list(self):
        """GIVEN the golden list / WHEN compared with __all__ / THEN no name is added or removed unnoticed."""
        golden = set(_golden_names())
        actual = set(keyutils_py.__all__)
        self.assertEqual(sorted(actual - golden), [], "name in __all__ that the golden list does not have")
        self.assertEqual(sorted(golden - actual), [], "name of the golden list that __all__ lost")

    def test_golden_list_is_sorted_and_unique(self):
        """GIVEN the golden file / WHEN read / THEN its names are sorted without duplicates (a clean diff)."""
        names = _golden_names()
        self.assertEqual(names, sorted(set(names)))

    def test_all_has_no_duplicates_and_every_name_resolves(self):
        """GIVEN __all__ / WHEN every name is looked up / THEN it exists and none is listed twice."""
        self.assertEqual(len(keyutils_py.__all__), len(set(keyutils_py.__all__)))
        for name in keyutils_py.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(keyutils_py, name))

    def test_nothing_of_the_first_release_is_gone(self):
        """GIVEN the names of the first release / WHEN compared with __all__ / THEN each is still exported."""
        self.assertEqual(sorted(_NAMES_OF_THE_FIRST_RELEASE - set(keyutils_py.__all__)), [])

    def test_names_that_outside_code_reached_by_module_path_are_exported(self):
        """GIVEN the 17 names that consumers import from a submodule / WHEN looked up / THEN they are top-level too."""
        by_module = {
            "keyutils_py.asn1utils": ("encode_to_der", "try_decode_pyasn1"),
            "keyutils_py.exceptions": ("BadAsn1Data", "BadAlg", "BadSigAlgID", "BadSigAlgIDParams", "KeyUtilsError"),
            "keyutils_py.keyutils": ("prepare_sig_alg_id", "prepare_hash_alg_id"),
            "keyutils_py.oids": ("get_hash_from_oid", "sha_alg_name_to_oid", "RSA_OID_2_NAME"),
            "keyutils_py.types": ("PublicKey", "SignKey", "VerifyKey", "TradVerifyKey", "DSAPublicKey"),
        }
        for module_name, names in by_module.items():
            module = __import__(module_name, fromlist=["x"])
            for name in names:
                with self.subTest(module=module_name, name=name):
                    self.assertIn(name, keyutils_py.__all__)
                    self.assertIs(getattr(keyutils_py, name), getattr(module, name))

    def test_signatures_of_the_signature_entry_points(self):
        """GIVEN the entry points with keyword-only options / WHEN inspected / THEN the signatures are pinned."""
        for name, expected in _SIGNATURES.items():
            with self.subTest(name=name):
                self.assertEqual(str(inspect.signature(getattr(keyutils_py, name))), expected)


class TestListAlgorithms(unittest.TestCase):
    """``list_algorithms`` lists the rows of a kind of algorithm."""

    def test_sig_lists_every_row_sorted_by_oid(self):
        """GIVEN kind sig / WHEN listed / THEN a tuple with one row per signature OID, sorted by OID."""
        rows = keyutils_py.list_algorithms("sig")
        self.assertIsInstance(rows, tuple)
        self.assertEqual(len(rows), 81)
        self.assertEqual({row.oid for row in rows}, set(keyutils_py.SIG_ALG_OID_2_INFO))
        self.assertTrue(all(isinstance(row, keyutils_py.SigAlgInfo) for row in rows))
        oids = [row.oid.asTuple() for row in rows]
        self.assertEqual(oids, sorted(oids))

    def test_unknown_kind_names_the_known_kinds(self):
        """GIVEN an unknown kind / WHEN listed / THEN ValueError that lists the known kinds."""
        with self.assertRaisesRegex(ValueError, "sig"):
            keyutils_py.list_algorithms("kem")
        with self.assertRaises(ValueError):
            algorithms.list_algorithms("")


if __name__ == "__main__":
    unittest.main()
