# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the algorithm tables of ``keyutils_py._algs``.

The golden rows in ``tests/golden/alg_tables.tsv`` are not derived from the tables under test: they are written by
``tests/golden/generate_alg_tables.py`` from the facts of the RFCs (named there) and cross-checked against the OIDs of
``pyasn1_alt_modules``. The old name tables of ``keyutils_py.oids`` are a third witness for the OIDs they have.
"""

import csv
import dataclasses
import unittest
from collections import Counter
from pathlib import Path
from typing import Dict, List

from keyutils_py import _algs
from keyutils_py.oids import (
    AES_CBC_OID_2_NAME,
    AES_GCM_OID_2_NAME,
    AES_GMAC_OID_2_NAME,
    HKDF_OID_2_NAME,
    HMAC_OID_2_NAME,
    KEY_WRAP_OID_2_NAME,
    KMAC_OID_2_NAME,
    compute_hash,
    sha_alg_name_to_oid,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3370, rfc8018

GOLDEN = Path(__file__).with_name("golden") / "alg_tables.tsv"

# The attribute of a row that holds the golden column "variant", and the fields that are compared, per table.
_TABLES = {
    "kdf": (_algs.KDF_ROWS, None, ("family", "hash")),
    "mac": (_algs.MAC_ROWS, None, ("family", "hash", "bits", "prf")),
    "wrap": (_algs.WRAP_ROWS, "mode", ("kek_len",)),
    "content": (_algs.CONTENT_ROWS, "mode", ("key_len",)),
    "kari": (_algs.KARI_ROWS, "kind", ("hash",)),
    "key_transport": (_algs.KT_ROWS, "padding", ()),
}


def _golden() -> Dict[str, List[dict]]:
    """Return the golden rows by table."""
    with open(GOLDEN, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    tables: Dict[str, List[dict]] = {name: [] for name in _TABLES}
    for row in rows:
        tables[row["table"]].append(row)
    return tables


def _expected(row: dict, field: str):
    """Return the golden cell of a row field as the type that the row field has."""
    if field in ("kek_len", "key_len"):
        return int(row["size"])
    if field == "bits":
        return int(row["bits"]) if row["bits"] else None
    if field == "prf":
        return row["prf"] == "true"
    return row[field] or None


class TestGoldenTable(unittest.TestCase):
    """Every row of every table is a row of the golden file, and the other way round."""

    def test_golden_file_has_the_rows_the_design_lists(self):
        """GIVEN the golden file / WHEN counted per table / THEN 10 KDF, 16 MAC, 6 wrap, 6 content, 15 KARI, 2 KT."""
        counts = {name: len(rows) for name, rows in _golden().items()}
        self.assertEqual(counts, {"kdf": 10, "mac": 16, "wrap": 6, "content": 6, "kari": 15, "key_transport": 2})

    def test_every_table_equals_its_golden_rows(self):
        """GIVEN a table / WHEN compared with the golden rows / THEN same OIDs, same facts, nothing more or less."""
        golden = _golden()
        for table, (rows, variant_field, fields) in _TABLES.items():
            with self.subTest(table=table):
                by_oid = {row.oid: row for row in rows}
                self.assertEqual({str(oid) for oid in by_oid}, {row["oid"] for row in golden[table]})
                for expected in golden[table]:
                    row = by_oid[univ.ObjectIdentifier(expected["oid"])]
                    for field in fields:
                        self.assertEqual(getattr(row, field), _expected(expected, field), f"{expected['name']}.{field}")
                    if variant_field is not None:
                        self.assertEqual(getattr(row, variant_field), expected["variant"], expected["name"])

    def test_oids_are_unique_within_and_across_the_tables(self):
        """GIVEN all rows / WHEN their OIDs are counted / THEN no OID is in two rows or two tables."""
        oids = [row.oid for rows, _, _ in _TABLES.values() for row in rows]
        self.assertEqual([oid for oid, count in Counter(oids).items() if count > 1], [])

    def test_row_counts_per_family(self):
        """GIVEN the rows / WHEN counted per family / THEN HKDF 7 (SHA-2 x3, SHA-3 x4), HMAC 10, KMAC 2, GMAC 3."""
        self.assertEqual(Counter(row.family for row in _algs.KDF_ROWS), {"hkdf": 7, "kdf2": 1, "kdf3": 1, "pbkdf2": 1})
        self.assertEqual(Counter(row.family for row in _algs.MAC_ROWS), {"hmac": 10, "kmac": 2, "gmac": 3, "pbmac1": 1})
        self.assertEqual(Counter(row.mode for row in _algs.WRAP_ROWS), {"kw": 3, "kwp": 3})
        self.assertEqual(
            Counter(row.kind for row in _algs.KARI_ROWS), {"stdDH": 4, "cofactorDH": 4, "mqv": 4, "legacy": 3}
        )

    def test_rows_are_frozen(self):
        """GIVEN a row / WHEN a field is assigned / THEN it fails: a table cannot be changed by a caller."""
        with self.assertRaises(dataclasses.FrozenInstanceError):
            _algs.KDF_ROWS[0].family = "kdf2"  # type: ignore[misc]


class TestHashNames(unittest.TestCase):
    """The hash of a row is a name of the hash registry, and a hash that HMAC cannot use is in no HMAC-based row."""

    def test_every_hash_of_a_row_is_in_the_registry(self):
        """GIVEN the hash names of the rows / WHEN looked up in the registry / THEN each resolves and digests."""
        names = {row.hash for rows in (_algs.KDF_ROWS, _algs.MAC_ROWS, _algs.KARI_ROWS) for row in rows if row.hash}
        for name in sorted(names):
            with self.subTest(hash=name):
                self.assertIsInstance(sha_alg_name_to_oid(name), univ.ObjectIdentifier)
                self.assertTrue(compute_hash(name, b"x"))

    def test_hkdf_and_hmac_rows_name_no_shake_function(self):
        """GIVEN HKDF and HMAC rows / WHEN their hashes are read / THEN none is SHAKE (HKDF is HMAC based)."""
        for row in (*_algs.KDF_ROWS, *_algs.MAC_ROWS):
            if row.family in ("hkdf", "hmac"):
                self.assertNotIn(row.hash, ("shake128", "shake256"))


class TestIndexes(unittest.TestCase):
    """The inverse indexes are derived from the rows: they cannot disagree with them."""

    def test_by_oid_indexes_hold_every_row(self):
        """GIVEN the by-OID indexes / WHEN compared with the rows / THEN each maps every OID to its row."""
        pairs = (
            (_algs.KDF_BY_OID, _algs.KDF_ROWS),
            (_algs.MAC_BY_OID, _algs.MAC_ROWS),
            (_algs.WRAP_BY_OID, _algs.WRAP_ROWS),
            (_algs.CONTENT_BY_OID, _algs.CONTENT_ROWS),
            (_algs.KARI_BY_OID, _algs.KARI_ROWS),
            (_algs.KT_BY_OID, _algs.KT_ROWS),
        )
        for index, rows in pairs:
            with self.subTest(index=len(rows)):
                self.assertEqual(dict(index), {row.oid: row for row in rows})

    def test_by_fact_indexes_find_the_oid_of_a_row(self):
        """GIVEN the by-fact indexes / WHEN a fact is looked up / THEN the OID of the row that states it comes back."""
        self.assertEqual(_algs.KDF_OID[("hkdf", "sha3_256")], univ.ObjectIdentifier("1.2.840.113549.1.9.16.3.33"))
        self.assertEqual(_algs.KDF_OID[("pbkdf2", None)], rfc8018.id_PBKDF2)
        self.assertEqual(_algs.MAC_OID[("gmac", None, 192)], univ.ObjectIdentifier("2.16.840.1.101.3.4.1.29"))
        self.assertEqual(_algs.MAC_OID[("kmac", "shake256", None)], univ.ObjectIdentifier("2.16.840.1.101.3.4.2.20"))
        self.assertEqual(_algs.WRAP_OID[("kwp", 24)], univ.ObjectIdentifier("2.16.840.1.101.3.4.1.28"))
        self.assertEqual(_algs.CONTENT_OID[("gcm", 32)], univ.ObjectIdentifier("2.16.840.1.101.3.4.1.46"))

    def test_sha1_hmac_has_two_oids_and_each_use_gets_its_own(self):
        """GIVEN the two HMAC-SHA1 OIDs / WHEN indexed / THEN a MAC gets hMAC-SHA1, PBKDF2 RFC 8018."""
        self.assertEqual(_algs.MAC_OID[("hmac", "sha1", None)], rfc3370.hMAC_SHA1)
        self.assertEqual(_algs.PRF_OID["sha1"], rfc8018.id_hmacWithSHA1)
        self.assertEqual(_algs.MAC_BY_OID[rfc3370.hMAC_SHA1].hash, "sha1")
        self.assertEqual(_algs.MAC_BY_OID[rfc8018.id_hmacWithSHA1].hash, "sha1")

    def test_prf_oids_are_the_pseudorandom_functions_of_rfc_8018(self):
        """GIVEN the PRF index / WHEN listed / THEN HMAC with SHA-1 and SHA-2 (Appendix B.1), none of SHA-3."""
        self.assertEqual(set(_algs.PRF_OID), {"sha1", "sha224", "sha256", "sha384", "sha512"})


class TestAgainstTheOldNameTables(unittest.TestCase):
    """The rows hold every OID that the name tables of ``keyutils_py.oids`` have, and name the same fact."""

    def test_hkdf_rows_equal_hkdf_oid_2_name(self):
        """GIVEN HKDF_OID_2_NAME / WHEN compared / THEN the same OIDs, and the hash of the name is the row's hash."""
        rows = {row.oid: row for row in _algs.KDF_ROWS if row.family == "hkdf"}
        self.assertEqual(set(rows), set(HKDF_OID_2_NAME))
        for oid, name in HKDF_OID_2_NAME.items():
            self.assertEqual(name, f"hkdf-{rows[oid].hash.replace('_', '-')}")

    def test_hmac_rows_hold_hmac_oid_2_name_and_the_pbkdf2_default(self):
        """GIVEN HMAC_OID_2_NAME / WHEN compared / THEN every OID is a row with that hash, plus hmacWithSHA1."""
        rows = {row.oid: row for row in _algs.MAC_ROWS if row.family == "hmac"}
        self.assertEqual(set(rows) - set(HMAC_OID_2_NAME), {rfc8018.id_hmacWithSHA1})
        for oid, name in HMAC_OID_2_NAME.items():
            self.assertEqual(name, f"hmac-{rows[oid].hash}")

    def test_kmac_and_gmac_rows_equal_their_tables(self):
        """GIVEN KMAC and AES-GMAC tables / WHEN compared / THEN same OIDs, same SHAKE function and key size."""
        kmac = {row.oid: row for row in _algs.MAC_ROWS if row.family == "kmac"}
        self.assertEqual({oid: f"kmac-{row.hash}" for oid, row in kmac.items()}, dict(KMAC_OID_2_NAME))
        gmac = {row.oid: row for row in _algs.MAC_ROWS if row.family == "gmac"}
        self.assertEqual({oid: f"aes{row.bits}_gmac" for oid, row in gmac.items()}, dict(AES_GMAC_OID_2_NAME))

    def test_wrap_and_content_rows_equal_their_tables(self):
        """GIVEN key wrap, CBC and GCM tables / WHEN compared / THEN same OIDs and the size of the name."""
        wrap = {row.oid: f"aes{row.kek_len * 8}_wrap" for row in _algs.WRAP_ROWS if row.mode == "kw"}
        self.assertEqual(wrap, dict(KEY_WRAP_OID_2_NAME))
        cbc = {row.oid: f"aes{row.key_len * 8}_cbc" for row in _algs.CONTENT_ROWS if row.mode == "cbc"}
        self.assertEqual(cbc, dict(AES_CBC_OID_2_NAME))
        gcm = {row.oid: f"aes{row.key_len * 8}_gcm" for row in _algs.CONTENT_ROWS if row.mode == "gcm"}
        self.assertEqual(gcm, dict(AES_GCM_OID_2_NAME))


if __name__ == "__main__":
    unittest.main()
