# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""ML-KEM encapsulation / decapsulation tests: round-trip and invalid-ciphertext paths."""

import unittest

from keyutils_py import compute_decaps, compute_encaps, generate_key
from keyutils_py.utils import manipulate_first_byte


class TestMLKEMEncaps(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key_512 = generate_key("ml-kem-512")
        cls.key_768 = generate_key("ml-kem-768")

    def test_mlkem_512_encaps_decaps(self):
        """
        GIVEN an ML-KEM-512 key pair.
        WHEN encapsulating and decapsulating,
        THEN the shared secrets should be equal.
        """
        ss_a, ct = compute_encaps(self.key_512.public_key())
        ss_b = compute_decaps(self.key_512, ct)
        self.assertEqual(ss_a.hex(), ss_b.hex())

    def test_mlkem_768_encaps_decaps(self):
        """
        GIVEN an ML-KEM-768 key pair.
        WHEN encapsulating and decapsulating,
        THEN the shared secrets should be equal.
        """
        ss_a, ct = compute_encaps(self.key_768.public_key())
        ss_b = compute_decaps(self.key_768, ct)
        self.assertEqual(ss_a.hex(), ss_b.hex())

    def test_invalid_mlkem_decaps(self):
        """
        GIVEN an ML-KEM-768 key pair.
        WHEN the ciphertext is manipulated before decapsulation,
        THEN the derived shared secrets should not be equal.
        """
        ss_a, ct = compute_encaps(self.key_768.public_key())
        ct = manipulate_first_byte(ct)
        ss_b = compute_decaps(self.key_768, ct)
        self.assertNotEqual(ss_a, ss_b)


if __name__ == "__main__":
    unittest.main()
