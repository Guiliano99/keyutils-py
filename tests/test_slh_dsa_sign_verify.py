# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""SLH-DSA sign / verify tests: pure, SHA-256 / SHAKE-128 / SHAKE-256 pre-hash, invalid signatures."""

import os
import unittest

from cryptography.exceptions import InvalidSignature

from keyutils_py import generate_key, sign_data, verify_signature
from keyutils_py.utils import manipulate_first_byte


class TestSLHDSASignVerify(unittest.TestCase):

    def setUp(self):
        self.data = os.urandom(1024)

    def test_slh_dsa_sign_without_alg(self):
        """
        GIVEN an SLH-DSA SHA2-128f key.
        WHEN signing and verifying without a hash algorithm,
        THEN verification should succeed.
        """
        key = generate_key("slh-dsa-sha2-128f")
        signature = sign_data(self.data, key)
        verify_signature(key.public_key(), signature, self.data)

    def test_slh_dsa_sign_with_sha256(self):
        """
        GIVEN an SLH-DSA SHA2-128f key.
        WHEN signing and verifying with SHA-256 pre-hash,
        THEN verification should succeed.
        """
        key = generate_key("slh-dsa-sha2-128f")
        signature = sign_data(self.data, key, hash_alg="sha256")
        verify_signature(key.public_key(), signature, self.data, hash_alg="sha256")

    def test_slh_dsa_sign_with_shake128(self):
        """
        GIVEN an SLH-DSA SHAKE-128f key.
        WHEN signing and verifying with SHAKE-128 pre-hash,
        THEN verification should succeed.
        """
        key = generate_key("slh-dsa-shake-128f")
        signature = sign_data(self.data, key, hash_alg="shake128")
        verify_signature(key.public_key(), signature, self.data, hash_alg="shake128")

    def test_slh_dsa_sign_with_shake256(self):
        """
        GIVEN an SLH-DSA SHAKE-256f key.
        WHEN signing and verifying with SHAKE-256 pre-hash,
        THEN verification should succeed.
        """
        key = generate_key("slh-dsa-shake-256f")
        signature = sign_data(self.data, key, hash_alg="shake256")
        verify_signature(key.public_key(), signature, self.data, hash_alg="shake256")

    def test_slh_dsa_invalid_signature(self):
        """
        GIVEN an SLH-DSA SHA2-128f key.
        WHEN the signature is manipulated,
        THEN verification should raise InvalidSignature.
        """
        key = generate_key("slh-dsa-sha2-128f")
        signature = sign_data(self.data, key)
        signature = manipulate_first_byte(signature)
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), signature, self.data)

    def test_slh_dsa_invalid_signature_with_shake256(self):
        """
        GIVEN an SLH-DSA SHAKE-256f key.
        WHEN the signature is manipulated and SHAKE-256 pre-hash is used,
        THEN verification should raise InvalidSignature.
        """
        key = generate_key("slh-dsa-shake-256f")
        signature = sign_data(self.data, key, hash_alg="shake256")
        signature = manipulate_first_byte(signature)
        with self.assertRaises(InvalidSignature):
            verify_signature(key.public_key(), signature, self.data, hash_alg="shake256")


if __name__ == "__main__":
    unittest.main()
