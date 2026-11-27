# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Direct unit tests for the RFC 8554 HSS validators (keyutils_py.keys.hss_validation).

These tests cover the validators directly and pin the RFC 8554 rules —
LMS/LMOTS pairing (§5.1), hierarchy depth (§6) — and the cross-level uniformity
checks, through the module's public interface.

Note on ``enforce_lw``: despite its docstring, the flag as implemented *skips*
the cross-level uniformity checks when true (its only caller maps
``hss_allow_diff_hash_and_output_size_per_level`` onto it, which is behaviorally
consistent). These tests pin the implemented behavior.
"""

import unittest

import keyutils_py as ku
from keyutils_py.exceptions import InvalidKeyData
from keyutils_py.keys.hss_validation import validate_hss_key, validate_hss_key_levels
from keyutils_py.keys.stateful_sig_keys import HSSPrivateKey

SHA256_PAIR = ("lms_sha256_m32_h5", "lmots_sha256_n32_w8")
SHAKE_PAIR = ("lms_shake_m32_h5", "lmots_shake_n32_w8")


class TestValidateHssKeyLevels(unittest.TestCase):
    """RFC 8554 pairing, depth and cross-level uniformity rules."""

    def test_valid_single_level_passes(self):
        """GIVEN one well-formed sha256 level / WHEN validated / THEN no error is raised."""
        validate_hss_key_levels([SHA256_PAIR])

    def test_valid_uniform_two_levels_pass(self):
        """GIVEN two uniform levels / WHEN validated / THEN no error is raised."""
        validate_hss_key_levels([SHA256_PAIR, SHA256_PAIR])

    def test_intra_pair_hash_family_mismatch_raises(self):
        """GIVEN an LMS/LMOTS pair mixing sha256 and shake / WHEN validated / THEN InvalidKeyData cites §5.1."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([("lms_sha256_m32_h5", "lmots_shake_n32_w8")])
        self.assertIn("Hash family mismatch", str(cm.exception))

    def test_intra_pair_digest_size_mismatch_raises(self):
        """GIVEN an LMS m=24 paired with LMOTS n=32 / WHEN validated / THEN InvalidKeyData cites digest size."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([("lms_sha256_m24_h5", "lmots_sha256_n32_w8")])
        self.assertIn("Digest size mismatch", str(cm.exception))

    def test_cross_level_hash_family_mismatch_raises(self):
        """GIVEN a sha256 level above a shake level / WHEN validated / THEN InvalidKeyData names the level."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([SHA256_PAIR, SHAKE_PAIR])
        self.assertIn("Level 1", str(cm.exception))
        self.assertIn("Hash family mismatch", str(cm.exception))

    def test_cross_level_digest_size_mismatch_raises(self):
        """GIVEN levels with n=32 and n=24 digests / WHEN validated / THEN InvalidKeyData cites the mismatch."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([SHA256_PAIR, ("lms_sha256_m24_h5", "lmots_sha256_n24_w8")])
        self.assertIn("Digest size mismatch", str(cm.exception))

    def test_cross_level_winternitz_mismatch_raises(self):
        """GIVEN levels with w=8 and w=4 / WHEN validated / THEN InvalidKeyData cites Winternitz."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([SHA256_PAIR, ("lms_sha256_m32_h5", "lmots_sha256_n32_w4")])
        self.assertIn("Winternitz", str(cm.exception))

    def test_unknown_lms_name_raises(self):
        """GIVEN an unknown LMS parameter set / WHEN validated / THEN InvalidKeyData names it."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([("lms_sha512_m64_h5", "lmots_sha256_n32_w8")])
        self.assertIn("Unknown LMS parameter set", str(cm.exception))

    def test_empty_hierarchy_raises(self):
        """GIVEN zero levels / WHEN validated / THEN InvalidKeyData cites the RFC 8554 §6 depth range."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([])
        self.assertIn("1 to 8", str(cm.exception))

    def test_nine_levels_raise(self):
        """GIVEN nine uniform levels / WHEN validated / THEN InvalidKeyData cites the RFC 8554 §6 depth range."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([SHA256_PAIR] * 9)
        self.assertIn("1 to 8", str(cm.exception))

    def test_enforce_lw_skips_cross_level_checks(self):
        """GIVEN mixed Winternitz levels with enforce_lw=True / WHEN validated / THEN no error (pins implemented semantics)."""
        validate_hss_key_levels(
            [SHA256_PAIR, ("lms_sha256_m32_h5", "lmots_sha256_n32_w4")],
            enforce_lw=True,
        )

    def test_error_details_carry_individual_issues(self):
        """GIVEN two independent violations / WHEN validated / THEN error_details lists each issue."""
        with self.assertRaises(InvalidKeyData) as cm:
            validate_hss_key_levels([SHA256_PAIR, SHAKE_PAIR, ("lms_sha256_m32_h5", "lmots_sha256_n32_w4")])
        details = getattr(cm.exception, "error_details", None)
        assert details is not None
        self.assertGreaterEqual(len(details), 2)


class TestValidateHssKey(unittest.TestCase):
    """Whole-key validation via get_level_names."""

    def test_generated_two_level_key_validates(self):
        """GIVEN a freshly generated 2-level HSS key / WHEN validated / THEN both private and public pass."""
        key = ku.generate_key("hss", levels=2)
        assert isinstance(key, HSSPrivateKey)
        validate_hss_key(key)
        validate_hss_key(key.public_key())


if __name__ == "__main__":
    unittest.main()
