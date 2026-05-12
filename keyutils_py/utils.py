# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Internal utility helpers.

This module is **internal** — its symbols are not re-exported from
:mod:`keyutils_py`. Other modules inside the package may import from here.

Contents:

* PEM/DER helpers (:func:`decode_pem_string`, :func:`load_and_decode_pem_file`).
* Generic byte mutation (:func:`manipulate_first_byte`) — kept private; the
  public negative-test entry point is :func:`keyutils_py.manipulate_sig_based_on_key`.
* OQS gating (:data:`OQS_AVAILABLE`, :func:`require_oqs`,
  :func:`is_xmss_or_xmssmt`).
* Algorithm-name predicates used by the dispatchers
  (:func:`algorithm_needs_oqs`, :func:`require_oqs_if_needed`,
  :func:`is_*_algorithm`).
"""

import importlib.util
import logging
import os
from base64 import b64decode
from typing import Any, Union

from keyutils_py.asn1utils import encode_to_der, try_decode_pyasn1
from keyutils_py.exceptions import MissingOQSDependencyError

# ---------------------------------------------------------------------------
# PEM helpers
# ---------------------------------------------------------------------------


def decode_pem_string(data: Union[bytes, str]) -> bytes:
    """Decode a PEM-armoured string/bytes into the raw DER bytes."""
    if isinstance(data, bytes):
        data = data.decode("ascii")

    filtered = [line for line in data.splitlines() if line.strip() and not line.startswith("#")]
    if not filtered:
        return b""

    if "-----BEGIN" in filtered[0]:
        result = "".join(filtered[1:-1])
    else:
        result = "".join(filtered)
    return b64decode(result)


def load_and_decode_pem_file(path: str) -> bytes:
    """Read ``path`` as PEM (with optional `# comment` lines) and return DER bytes."""
    with open(path, "r", encoding="ascii") as f:
        return decode_pem_string(f.read())


# ---------------------------------------------------------------------------
# Byte-mutation primitives (internal)
# ---------------------------------------------------------------------------


def manipulate_first_byte(data: bytes) -> bytes:
    """Flip the first byte of ``data`` (``0x00`` ↔ ``0x01``).

    Internal helper used by :func:`keyutils_py.manipulate_sig_based_on_key`
    and the stateful-hash signature mutators. Not part of the public API.
    """
    if not data:
        return data
    if data[0] == 0:
        return b"\x01" + data[1:]
    return b"\x00" + data[1:]


# ---------------------------------------------------------------------------
# OQS gating
# ---------------------------------------------------------------------------


OQS_AVAILABLE: bool = importlib.util.find_spec("oqs") is not None
"""``True`` if ``import oqs`` will succeed at runtime."""

oqs: Any
"""The :mod:`oqs` module if liboqs is installed, otherwise ``None``.

Centralised so callers can write ``from keyutils_py.utils import oqs`` and then
gate logic on ``oqs is not None`` instead of re-importing in every module.
"""

if OQS_AVAILABLE:
    import oqs  # type: ignore[no-redef] # pylint: disable=import-error
else:
    logging.warning("oqs module is not installed. Some functionalities may be disabled.")
    oqs = None  # type: ignore[assignment] # pylint: disable=invalid-name


def require_oqs(algorithm: str) -> None:
    """Raise :class:`MissingOQSDependencyError` if liboqs is not importable."""
    if not OQS_AVAILABLE:
        raise MissingOQSDependencyError(algorithm)


def is_xmss_or_xmssmt(algorithm: str) -> bool:
    """Return ``True`` if ``algorithm`` is an XMSS or XMSSMT family name."""
    name = algorithm.lower()
    return name.startswith("xmss-") or name.startswith("xmssmt-") or name in ("xmss", "xmssmt")


# ---------------------------------------------------------------------------
# Algorithm-name predicates (used by the dispatchers in compute / keyutils)
# ---------------------------------------------------------------------------


NOT_IMPLEMENTED_HINT = (
    "Algorithm not supported by keyutils-py. The package covers PQ "
    "(ML-DSA / ML-KEM / SLH-DSA / Falcon / FrodoKEM / McEliece / SNTRUP761), "
    "PQ stateful-hash (HSS / LMS / XMSS / XMSSMT), and hybrid keys "
    "(composite-sig / composite-kem / chempat / xwing). Traditional-only "
    "keys are not supported here."
)

_OQS_REQUIRED_PREFIXES = ("falcon-", "mceliece-", "frodokem-")


def algorithm_needs_oqs(algorithm: str) -> bool:
    """Return ``True`` if ``algorithm`` cannot be handled without liboqs."""
    name = algorithm.lower()
    if is_xmss_or_xmssmt(name):
        return True
    if name == "sntrup761":
        return True
    return any(name.startswith(p) for p in _OQS_REQUIRED_PREFIXES)


def require_oqs_if_needed(algorithm: str) -> None:
    """Raise :class:`MissingOQSDependencyError` if needed; otherwise return."""
    if algorithm_needs_oqs(algorithm):
        require_oqs(algorithm)


def is_stateful_hash_algorithm(algorithm: str) -> bool:
    """Return True for HSS / LMS / XMSS / XMSSMT names."""
    name = algorithm.lower()
    if is_xmss_or_xmssmt(name):
        return True
    return name == "hss" or name.startswith("hss_") or name.startswith("lms_")


def is_pq_sig_algorithm(algorithm: str) -> bool:
    """Return True for ML-DSA / SLH-DSA / Falcon names (with and without pre-hash)."""
    from keyutils_py.oids import (  # local import: avoids load-order issues at package init
        FALCON_NAME_2_OID,
        ML_DSA_NAME_2_OID,
        SLH_DSA_NAME_2_OID,
    )

    name = algorithm.lower()
    return (
        name in ML_DSA_NAME_2_OID
        or name in SLH_DSA_NAME_2_OID
        or name in FALCON_NAME_2_OID
        or name.startswith("ml-dsa-")
        or name.startswith("slh-dsa-")
        or name.startswith("falcon-")
    )


def is_pq_kem_algorithm(algorithm: str) -> bool:
    """Return True for ML-KEM / McEliece / FrodoKEM / SNTRUP761."""
    from keyutils_py.oids import (
        FRODOKEM_NAME_2_OID,
        MCELIECE_NAME_2_OID,
        ML_KEM_NAME_2_OID,
    )

    name = algorithm.lower()
    return (
        name in ML_KEM_NAME_2_OID
        or name in MCELIECE_NAME_2_OID
        or name in FRODOKEM_NAME_2_OID
        or name == "sntrup761"
        or name.startswith("ml-kem-")
        or name.startswith("mceliece-")
        or name.startswith("frodokem-")
    )


def is_supported_pq_algorithm(algorithm: str) -> bool:
    """Return True if ``algorithm`` is a PQ signature, PQ KEM, or stateful-hash name."""
    return is_stateful_hash_algorithm(algorithm) or is_pq_sig_algorithm(algorithm) or is_pq_kem_algorithm(algorithm)


def is_hybrid_algorithm(algorithm: str) -> bool:
    """Return True for xwing / composite-sig / composite-kem / chempat names."""
    from keyutils_py.factories.hybrid_factory import HybridKeyFactory

    name = algorithm.lower()
    if name in HybridKeyFactory.supported_algorithms():
        return True
    return any(name.startswith(p) for p in ("composite-sig-", "composite-kem-", "chempat-"))


def get_random_bytes(length: int = 16) -> bytes:
    """Return ``length`` cryptographically random bytes (default ``16``).

    :param length: Number of bytes to generate. Must be non-negative.
    :returns: Random bytes from :func:`os.urandom`.
    :raises ValueError: If ``length`` is negative.
    """
    if length < 0:
        raise ValueError(f"length must be non-negative, got {length}.")
    return os.urandom(length)


__all__ = [
    "decode_pem_string",
    "load_and_decode_pem_file",
    "encode_to_der",
    "try_decode_pyasn1",
    "OQS_AVAILABLE",
    "oqs",
    "require_oqs",
    "is_xmss_or_xmssmt",
    "NOT_IMPLEMENTED_HINT",
    "algorithm_needs_oqs",
    "require_oqs_if_needed",
    "is_stateful_hash_algorithm",
    "is_pq_sig_algorithm",
    "is_pq_kem_algorithm",
    "is_supported_pq_algorithm",
    "is_hybrid_algorithm",
    "get_random_bytes",
]
