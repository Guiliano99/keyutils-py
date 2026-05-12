# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Bundled PQ stateful-hash key fixtures.

These PEM files are shipped with the package so ``load_pq_stfl_keys_from_dir``
and downstream tests work after ``pip install`` without needing a checkout
of the source repo.

Use the path constants below to feed
:func:`keyutils_py._dispatch.load_pq_stfl_keys_from_dir`.
"""

import os

DATA_DIR: str = os.path.dirname(os.path.abspath(__file__))
"""Absolute path to the bundled ``data`` directory."""

KEYS_DIR: str = os.path.join(DATA_DIR, "keys")
"""Absolute path to ``data/keys/``."""

HSS_KEYS_DIR: str = os.path.join(KEYS_DIR, "hss_keys")
"""HSS PEM fixtures (load without liboqs)."""

XMSS_XMSSMT_KEYS_DIR: str = os.path.join(KEYS_DIR, "xmss_xmssmt_keys")
"""XMSS / XMSSMT PEM fixtures (require liboqs to load)."""

XMSS_XMSSMT_KEYS_VERBOSE_DIR: str = os.path.join(KEYS_DIR, "xmss_xmssmt_keys_verbose")
"""Verbose XMSS / XMSSMT PEM fixtures used by Robot Framework verbose flows."""

PQ_KEYS_DIR: str = os.path.join(KEYS_DIR, "pq_keys")
"""ML-DSA / ML-KEM / SLH-DSA / FrodoKEM / McEliece / SNTRUP761 PEM fixtures."""


__all__ = [
    "DATA_DIR",
    "KEYS_DIR",
    "HSS_KEYS_DIR",
    "XMSS_XMSSMT_KEYS_DIR",
    "XMSS_XMSSMT_KEYS_VERBOSE_DIR",
    "PQ_KEYS_DIR",
]
