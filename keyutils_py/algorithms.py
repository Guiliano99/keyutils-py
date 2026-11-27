# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0

"""Listing of the algorithms that keyutils-py knows, by kind.

A generator of test cases reads these lists instead of keeping its own table of algorithms. The kind ``sig`` lists
the signature algorithms; ``kdf``, ``mac``, ``wrap`` and ``content`` list the key derivation functions, MACs, AES key
wraps and AES content encryptions that :func:`keyutils_py.make_alg_id` builds and the mechanisms of
:mod:`keyutils_py.mechanisms` use; further kinds are added here when their tables have a reader.
"""

from typing import Tuple, Union

from keyutils_py._algs import CONTENT_ROWS, KDF_ROWS, MAC_ROWS, WRAP_ROWS, AlgInfo
from keyutils_py.oids import SIG_ALG_OID_2_INFO, SigAlgInfo

_ROWS = {"kdf": KDF_ROWS, "mac": MAC_ROWS, "wrap": WRAP_ROWS, "content": CONTENT_ROWS}
_KINDS = ("sig", *_ROWS)


def list_algorithms(kind: str) -> Tuple[Union[SigAlgInfo, AlgInfo], ...]:
    """Return what the package knows about the algorithms of a kind.

    :param kind: ``"sig"``: every signature algorithm, one :class:`keyutils_py.oids.SigAlgInfo` row per OID.
        ``"kdf"``, ``"mac"``, ``"wrap"`` or ``"content"``: one :class:`AlgInfo` ``(kind, family, params, oid)`` per OID
        (10, 16, 6 and 6). ``params`` holds the keywords of :func:`keyutils_py.make_alg_id` that the row fixes, for
        example ``{"hash": "sha3_256"}`` for HKDF or ``{"bits": 256, "mode": "kwp"}`` for a key wrap. All are sorted by
        OID.
    :raises ValueError: If ``kind`` is not one of the known kinds; the message lists them.
    """
    if kind == "sig":
        return tuple(sorted(SIG_ALG_OID_2_INFO.values(), key=lambda info: info.oid.asTuple()))
    if kind in _ROWS:
        return tuple(sorted((row.info() for row in _ROWS[kind]), key=lambda info: info.oid.asTuple()))
    raise ValueError(f"Unknown kind of algorithm {kind!r}; the known kinds are: {', '.join(_KINDS)}.")
