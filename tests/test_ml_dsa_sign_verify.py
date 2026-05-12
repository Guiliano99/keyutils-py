# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""ML-DSA sign / verify tests: context, pre-hash, and invalid-signature paths."""

import os
import unittest

from cryptography.exceptions import InvalidSignature

from keyutils_py import generate_key, sign_data, verify_signature
from keyutils_py.oids import compute_hash
from keyutils_py.utils import manipulate_first_byte


class TestMLDSASignVerify(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = generate_key("ml-dsa-44")
        cls.ctx = b"keyutils-py test context"
        cls.data = os.urandom(1024)

    def test_mldsa_invalid_sig_verify(self):
        """
        GIVEN an ML-DSA private key.
        WHEN signing with a context and the signature is manipulated,
        THEN verification should raise InvalidSignature.
        """
        signature = sign_data(self.data, self.key, ctx=self.ctx)
        signature = manipulate_first_byte(signature)
        with self.assertRaises(InvalidSignature):
            verify_signature(self.key.public_key(), signature, self.data, ctx=self.ctx)

    def test_mldsa_invalid_sig_verify_with_hash(self):
        """
        GIVEN an ML-DSA private key.
        WHEN signing with a context and SHA-512 pre-hash and the signature is manipulated,
        THEN verification should raise InvalidSignature.
        """
        signature = sign_data(self.data, self.key, ctx=self.ctx, hash_alg="sha512")
        signature = manipulate_first_byte(signature)
        with self.assertRaises(InvalidSignature):
            verify_signature(self.key.public_key(), signature, self.data, ctx=self.ctx, hash_alg="sha512")

    def test_mldsa_sign_verify_with_ctx(self):
        """
        GIVEN an ML-DSA private key.
        WHEN signing and verifying with a context,
        THEN verification should succeed.
        """
        signature = sign_data(self.data, self.key, ctx=self.ctx)
        verify_signature(self.key.public_key(), signature, self.data, ctx=self.ctx)

    def test_mldsa_sign_verify_prehash_ctx(self):
        """
        GIVEN an ML-DSA private key.
        WHEN signing and verifying with a context and SHA-512 pre-hash,
        THEN verification should succeed.
        """
        signature = sign_data(self.data, self.key, ctx=self.ctx, hash_alg="sha512")
        verify_signature(self.key.public_key(), signature, self.data, ctx=self.ctx, hash_alg="sha512")

    def test_mldsa_sign_verify_prehashed_data(self):
        """
        GIVEN an ML-DSA private key.
        WHEN signing with SHA-512 pre-hash and verifying with externally pre-hashed data,
        THEN verification should succeed.
        """
        signature = sign_data(self.data, self.key, ctx=self.ctx, hash_alg="sha512")
        prehashed_data = compute_hash("sha512", self.data)
        verify_signature(self.key.public_key(), signature, prehashed_data, ctx=self.ctx, hash_alg="sha512", use_pre_hash=True)


if __name__ == "__main__":
    unittest.main()
