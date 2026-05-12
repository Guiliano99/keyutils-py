# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Falcon-512 / Falcon-1024 sign / verify tests (require liboqs)."""

import unittest

from cryptography.exceptions import InvalidSignature

from keyutils_py import generate_key, sign_data, verify_signature
from keyutils_py.utils import manipulate_first_byte, OQS_AVAILABLE


@unittest.skipUnless(OQS_AVAILABLE, "liboqs not installed; Falcon tests skipped")
class TestFalconSignVerify(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = b"Hello, World!"

    def test_sign_verify_falcon512(self):
        """
        GIVEN a Falcon-512 key.
        WHEN signing and verifying data,
        THEN verification should succeed.
        """
        key = generate_key("falcon-512")
        sig = sign_data(self.data, key)
        verify_signature(key.public_key(), sig, self.data)

    def test_sign_verify_falcon1024(self):
        """
        GIVEN a Falcon-1024 key.
        WHEN signing and verifying data,
        THEN verification should succeed.
        """
        key = generate_key("falcon-1024")
        sig = sign_data(self.data, key)
        verify_signature(key.public_key(), sig, self.data)

    def test_sign_verify_falcon512_invalid_sig(self):
        """
        GIVEN a Falcon-512 key.
        WHEN the signature is manipulated,
        THEN verification should raise InvalidSignature.
        """
        key = generate_key("falcon-512")
        sig = sign_data(self.data, key)
        invalid_sig = manipulate_first_byte(sig)
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), invalid_sig, self.data)

    def test_sign_verify_falcon1024_invalid_sig(self):
        """
        GIVEN a Falcon-1024 key.
        WHEN the signature is manipulated,
        THEN verification should raise InvalidSignature.
        """
        key = generate_key("falcon-1024")
        sig = sign_data(self.data, key)
        invalid_sig = manipulate_first_byte(sig)
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), invalid_sig, self.data)


if __name__ == "__main__":
    unittest.main()
