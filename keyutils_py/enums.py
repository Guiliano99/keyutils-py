# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Project-wide enums.

* :class:`KeySaveType` — controls how PQ private keys are serialised
  (seed / raw / seed-and-raw) for ``OneAsymmetricKey``.
* :class:`SigAlgParametersSpec` — parameter-shape catalog token, drives
  :func:`keyutils_py.keyutils.validate_sig_alg_id` (absent / NULL / RSASSA-PSS-params).
"""

from __future__ import annotations

import enum
from typing import Union


class KeySaveType(enum.Enum):
    """How to serialise a PQ private key (seed, raw bytes, or both)."""

    SEED = "seed"
    RAW = "raw"
    SEED_AND_RAW = "seed_and_raw"

    @staticmethod
    def get(value: Union[str, "KeySaveType"]) -> "KeySaveType":
        """Return the matching enum member (case-insensitive, ``-`` → ``_``)."""
        if isinstance(value, KeySaveType):
            return value
        normalized = value.replace("-", "_").lower()
        try:
            return KeySaveType(normalized)
        except ValueError as exc:
            raise ValueError(f"Unknown KeySaveType value {value!r}. Valid: {[m.value for m in KeySaveType]}.") from exc


class SigAlgParametersSpec(str, enum.Enum):
    """Expected shape of ``AlgorithmIdentifier.parameters`` for one signature OID."""

    MUST_BE_ABSENT = "must_be_absent"
    MUST_BE_NULL = "must_be_null"
    MUST_BE_RSASSA_PSS_PARAMS = "must_be_rsassa_pss_params"


__all__ = ["KeySaveType", "SigAlgParametersSpec"]
