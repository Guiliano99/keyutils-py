# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Low-level JWK helpers: base64url codecs and RFC 7638 thumbprints.

This module is a leaf helper with no dependency on the key-wrapper classes so
that it can be imported from anywhere in the ``keyutils_py.jwt`` package without
risking import cycles.

* base64url is the *unpadded* variant mandated by RFC 7515 Appendix C: the
  ``=`` padding is stripped on encode and rejected on decode.
* :func:`int_to_b64u` / :func:`b64u_to_int` implement the big-endian integer
  encoding used for ``RSA`` members (minimal length) and ``EC`` coordinates
  (fixed length, left zero-padded).
* :func:`jwk_thumbprint` implements RFC 7638 over the canonical required-member
  subset for each ``kty``.
"""

import base64
import hashlib
import json
from typing import Any, Dict

from keyutils_py.exceptions import InvalidJWK

__all__ = [
    "b64u_encode",
    "b64u_decode",
    "int_to_b64u",
    "b64u_to_int",
    "jwk_thumbprint",
    "THUMBPRINT_MEMBERS",
]


# RFC 7638 §3.2 — the lexicographically ordered required members per key type
# whose values form the canonical JSON used to compute a JWK Thumbprint.
# ``AKP`` follows draft-ietf-cose-dilithium (``alg``, ``kty``, ``pub``).
THUMBPRINT_MEMBERS: Dict[str, list] = {
    "EC": ["crv", "kty", "x", "y"],
    "OKP": ["crv", "kty", "x"],
    "RSA": ["e", "kty", "n"],
    "AKP": ["alg", "kty", "pub"],
}

_HASHES = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def b64u_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url.

    :param data: The raw bytes to encode.
    :returns: The base64url string without ``=`` padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    """Decode an unpadded base64url string into bytes.

    :param value: The base64url string. Padding characters and any character
        outside the URL-safe alphabet are rejected.
    :returns: The decoded raw bytes.
    :raises InvalidJWK: If ``value`` is not valid unpadded base64url.
    """
    if not isinstance(value, str):
        raise InvalidJWK(f"Expected a base64url string, got {type(value).__name__}.")
    if "=" in value:
        raise InvalidJWK("base64url value must not contain '=' padding.")
    if any(c in value for c in "+/ \t\r\n"):
        raise InvalidJWK("base64url value contains characters outside the URL-safe alphabet.")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise InvalidJWK(f"Invalid base64url value: {exc}") from exc


def int_to_b64u(value: int, *, length: int | None = None) -> str:
    """Encode a non-negative integer as a big-endian base64url string.

    :param value: The integer to encode (must be non-negative).
    :param length: When given, the integer is left zero-padded to exactly
        ``length`` bytes (used for fixed-length ``EC`` coordinates). When
        ``None``, the minimal big-endian representation is used (``RSA``).
    :returns: The base64url-encoded integer.
    :raises InvalidJWK: If ``value`` is negative or does not fit in ``length``.
    """
    if value < 0:
        raise InvalidJWK("Cannot encode a negative integer as a JWK member.")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    elif value.bit_length() > length * 8:
        raise InvalidJWK(f"Integer does not fit in {length} bytes.")
    return b64u_encode(value.to_bytes(length, "big"))


def b64u_to_int(value: str) -> int:
    """Decode a base64url string into a big-endian non-negative integer.

    :param value: The base64url string.
    :returns: The decoded integer.
    """
    return int.from_bytes(b64u_decode(value), "big")


def jwk_thumbprint(jwk: Dict[str, Any], *, hash_alg: str = "sha256") -> str:
    """Compute the RFC 7638 JWK Thumbprint of ``jwk``.

    The thumbprint is the base64url-encoded digest of the canonical JSON object
    built from the required members for the key's ``kty`` (lexicographically
    ordered, no whitespace, UTF-8).

    :param jwk: The JWK as a dict. Only the required members are consulted.
    :param hash_alg: One of ``sha256`` / ``sha384`` / ``sha512``.
    :returns: The base64url-encoded thumbprint.
    :raises InvalidJWK: If ``kty`` is missing/unsupported, a required member is
        absent, or ``hash_alg`` is unknown.
    """
    hasher = _HASHES.get(hash_alg)
    if hasher is None:
        raise InvalidJWK(f"Unsupported thumbprint hash algorithm: {hash_alg}.")

    kty = jwk.get("kty")
    members = THUMBPRINT_MEMBERS.get(kty) if isinstance(kty, str) else None
    if members is None:
        raise InvalidJWK(f"Cannot compute thumbprint for kty: {kty!r}.")

    canonical = {}
    for name in members:
        if name not in jwk:
            raise InvalidJWK(f"JWK is missing required thumbprint member {name!r}.")
        canonical[name] = jwk[name]

    serialized = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64u_encode(hasher(serialized).digest())
