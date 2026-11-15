# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Listing of the algorithms that keyutils-py knows, by kind.

A generator of test cases reads these lists instead of keeping its own table of algorithms. The kind ``sig`` lists
the signature algorithms; further kinds are added here when their tables exist.
"""

from typing import Tuple

from keyutils_py.oids import SIG_ALG_OID_2_INFO, SigAlgInfo

_KINDS = ("sig",)


def list_algorithms(kind: str) -> Tuple[SigAlgInfo, ...]:
    """Return what the package knows about the algorithms of a kind.

    :param kind: ``"sig"``: every signature algorithm, one :class:`keyutils_py.oids.SigAlgInfo` row per OID,
        sorted by OID.
    :raises ValueError: If ``kind`` is not one of the known kinds; the message lists them.
    """
    if kind == "sig":
        return tuple(sorted(SIG_ALG_OID_2_INFO.values(), key=lambda info: info.oid.asTuple()))
    raise ValueError(f"Unknown kind of algorithm {kind!r}; the known kinds are: {', '.join(_KINDS)}.")
