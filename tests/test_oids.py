# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Tests for the OID lookup tables."""

import unittest

from keyutils_py.oids import COMPOSITE_KEM_OID_2_NAME, KEM_OID_2_NAME, PQ_KEM_OID_2_NAME
from pyasn1_alt_modules import rfc5990


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


if __name__ == "__main__":
    unittest.main()
