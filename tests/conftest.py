# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Shared paths and helpers for the keyutils-py test suite.

Re-exports the bundled fixture paths from :mod:`keyutils_py.data` so the
tests work both from a source checkout and from an installed wheel.
"""

import os
from typing import Dict

from keyutils_py.utils import OQS_AVAILABLE
from keyutils_py.data import (
    DATA_DIR,
    HSS_KEYS_DIR,
    KEYS_DIR as DATA_KEYS_DIR,
    XMSS_XMSSMT_KEYS_DIR,
    XMSS_XMSSMT_KEYS_VERBOSE_DIR,
)

if not OQS_AVAILABLE:
    raise ImportError(
        "liboqs (oqs) is required to run the keyutils-py unit test suite. "
        "Install with: pip install 'keyutils-py[pq]'"
    )

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

__all__ = [
    "TESTS_DIR",
    "DATA_DIR",
    "DATA_KEYS_DIR",
    "HSS_KEYS_DIR",
    "XMSS_XMSSMT_KEYS_DIR",
    "XMSS_XMSSMT_KEYS_VERBOSE_DIR",
    "discover_xmss_xmssmt_key_paths",
]


def discover_xmss_xmssmt_key_paths() -> Dict[str, str]:
    """Return ``{algorithm: filepath}`` for the XMSS/XMSSMT fixture set.

    Mirrors ``unit_tests/utils_for_test.get_all_xmss_xmssmt_keys`` but uses
    the bundled fixture directory rather than the source repo.
    """
    if not OQS_AVAILABLE:
        return {}

    import oqs  # type: ignore[import]

    keys: Dict[str, str] = {}
    for alg_name in oqs.get_enabled_stateful_sig_mechanisms():
        alg_name = alg_name.lower()
        if not (alg_name.startswith("xmss-") or alg_name.startswith("xmssmt-")):
            continue
        filename = "private-key-" + alg_name.replace("/", "_layers_", 1) + ".pem"
        path = os.path.join(XMSS_XMSSMT_KEYS_DIR, filename)
        if os.path.exists(path):
            keys[alg_name] = path
    return keys
