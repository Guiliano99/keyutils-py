# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests that the OID tables of :mod:`keyutils_py.oids` equal the golden copy of the cmp-test-suite tables.

``golden/oid_tables.tsv`` is written by ``golden/generate_oid_tables.py``, which has to be run by hand from a
cmp-test-suite checkout. These tests only read the file.
"""

import csv
import unittest
from collections import defaultdict
from pathlib import Path
from typing import Dict, Set, Tuple

from keyutils_py import oids
from keyutils_py.oids import may_return_oid_to_name
from pyasn1.type import univ
from pyasn1_alt_modules import rfc9688

_GOLDEN = Path(__file__).with_name("golden") / "oid_tables.tsv"
_NAME_LOOKUP_TABLE = "may_return_oid_to_name"
_CONSTANTS_TABLE = "constants"

# Tables of the package that map OID to name, next to the ones in the golden file, and that
# ``may_return_oid_to_name`` has to know.
_OTHER_OID_KEYED_TABLES = (
    "KEM_OID_2_NAME",
    "COMPOSITE_KEM_OID_2_NAME",
    "CHEMPAT_OID_2_NAME",
    "TRAD_SIG_OID_2_NAME",
    "ML_KEM_OID_2_NAME",
    "FALCON_OID_2_NAME",
    "FRODOKEM_OID_2_NAME",
    "MCELIECE_OID_2_NAME",
    "SLH_DSA_OID_2_NAME",
)


def _read_golden() -> Dict[str, Set[Tuple[str, str]]]:
    """Return ``table -> {(name, dotted OID)}`` of the golden file."""
    tables: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    with open(_GOLDEN, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            tables[row["table"]].add((row["name"], row["oid"]))
    return tables


def _pairs(table: Dict) -> Set[Tuple[str, str]]:
    """Return ``{(name, dotted OID)}`` of a table that maps OID to name or name to OID."""
    pairs = set()
    for key, value in table.items():
        if isinstance(key, univ.ObjectIdentifier):
            pairs.add((value, str(key)))
        else:
            assert isinstance(value, univ.ObjectIdentifier), f"{key!r}: {value!r} holds no OID"
            pairs.add((key, str(value)))
    return pairs


def _oid_keyed(table_name: str) -> Dict[univ.ObjectIdentifier, str]:
    """Return the package table ``table_name`` if it maps OID to name, else an empty dict."""
    table = getattr(oids, table_name)
    return table if all(isinstance(key, univ.ObjectIdentifier) for key in table) else {}


class TestGoldenTables(unittest.TestCase):
    """The package tables have the same names and OIDs as the cmp-test-suite tables."""

    @classmethod
    def setUpClass(cls):
        """Read the golden file once."""
        cls.golden = _read_golden()

    def test_tables_equal_golden(self):
        """GIVEN the golden tables / WHEN the package table of that name is read / THEN name and OID are equal."""
        for table_name, golden_pairs in self.golden.items():
            if table_name in (_NAME_LOOKUP_TABLE, _CONSTANTS_TABLE):
                continue
            with self.subTest(table=table_name):
                self.assertTrue(hasattr(oids, table_name), f"keyutils_py.oids has no table {table_name}")
                self.assertEqual(_pairs(getattr(oids, table_name)), golden_pairs)

    def test_constants_equal_golden(self):
        """GIVEN the golden OID constants / WHEN the package constant of that name is read / THEN it is equal."""
        for name, dotted in self.golden[_CONSTANTS_TABLE]:
            with self.subTest(constant=name):
                self.assertTrue(hasattr(oids, name), f"keyutils_py.oids has no constant {name}")
                self.assertEqual(str(getattr(oids, name)), dotted)


class TestMayReturnOidToName(unittest.TestCase):
    """``may_return_oid_to_name`` names every OID of the package tables and never a wrong one."""

    @classmethod
    def setUpClass(cls):
        """Read the golden file once."""
        cls.golden = _read_golden()

    def test_known_names_agree_with_cmp_test_suite(self):
        """GIVEN the cmp-test-suite names / WHEN the package names the OID / THEN it is the same name."""
        for name, dotted in sorted(self.golden[_NAME_LOOKUP_TABLE]):
            with self.subTest(oid=dotted):
                self.assertIn(may_return_oid_to_name(univ.ObjectIdentifier(dotted)), (name, dotted))

    def test_names_of_package_tables_equal_the_cmp_test_suite_names(self):
        """GIVEN a golden table name for an OID / WHEN the package table has the OID / THEN the name is returned."""
        package_oids = set()
        for table_name, pairs in self.golden.items():
            if table_name not in (_NAME_LOOKUP_TABLE, _CONSTANTS_TABLE) and _oid_keyed(table_name):
                package_oids.update(oid for _, oid in pairs)
        expected = {(name, dotted) for name, dotted in self.golden[_NAME_LOOKUP_TABLE] if dotted in package_oids}
        self.assertGreater(len(expected), 100)
        for name, dotted in sorted(expected):
            with self.subTest(oid=dotted):
                self.assertEqual(may_return_oid_to_name(univ.ObjectIdentifier(dotted)), name)

    def test_every_oid_keyed_package_table_is_known(self):
        """GIVEN each package table that maps OID to name / WHEN an OID is looked up / THEN its name is returned."""
        table_names = {name for name in self.golden if name not in (_NAME_LOOKUP_TABLE, _CONSTANTS_TABLE)}
        for table_name in sorted(table_names | set(_OTHER_OID_KEYED_TABLES)):
            for oid, name in _oid_keyed(table_name).items():
                with self.subTest(table=table_name, oid=str(oid)):
                    self.assertEqual(may_return_oid_to_name(oid), name)

    def test_hash_oids_are_named_by_the_hash_registry(self):
        """GIVEN the SHA-3 hash OIDs of RFC 9688 / WHEN they are looked up / THEN the hash name is returned."""
        self.assertEqual(may_return_oid_to_name(rfc9688.id_sha3_256), "sha3_256")

    def test_unknown_oid_and_string_are_returned_as_dotted_string(self):
        """GIVEN an unknown OID and a string / WHEN looked up / THEN the dotted string comes back."""
        self.assertEqual(may_return_oid_to_name(univ.ObjectIdentifier("1.2.3.4.5.6")), "1.2.3.4.5.6")
        self.assertEqual(may_return_oid_to_name("1.2.3.4.5.6"), "1.2.3.4.5.6")

    def test_no_wrong_direction_entries(self):
        """GIVEN the combined OID -> name table / WHEN its entries are read / THEN keys are OIDs and values names."""
        for key, value in oids.ALG_OID_2_NAME.items():
            with self.subTest(key=str(key)):
                self.assertIsInstance(key, univ.ObjectIdentifier)
                self.assertIsInstance(value, str)
                self.assertFalse(value.replace(".", "").isdigit(), f"{value!r} is a dotted OID, not a name")


if __name__ == "__main__":
    unittest.main()
