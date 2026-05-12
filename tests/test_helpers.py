# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

import os

from keyutils_py.data import XMSS_XMSSMT_KEYS_DIR
from keyutils_py.keyutils import _stateful_hash_filename_to_algorithm


def get_all_xmss_xmssmt_keys() -> dict[str, str]:
    """Return ``{algorithm_name: filepath}`` for all XMSS/XMSSMT key files in the bundled data dir."""
    result = {}
    for fname in sorted(os.listdir(XMSS_XMSSMT_KEYS_DIR)):
        if not fname.endswith(".pem"):
            continue
        algo = _stateful_hash_filename_to_algorithm(fname)
        if algo is not None:
            result[algo] = os.path.join(XMSS_XMSSMT_KEYS_DIR, fname)
    return result
