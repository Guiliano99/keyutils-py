# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

# pylint: disable=too-few-public-methods

"""ASN.1 data structures and small data wrappers.

* ML-DSA / ML-KEM private-key ``CHOICE`` structures (``MLDSA*PrivateKeyASN1``,
  ``MLKEM*PrivateKeyASN1`` and their ``Both*`` helpers): used for the
  IETF drafts' bare-``CHOICE`` ``seed [0] IMPLICIT`` / ``expandedKey`` /
  ``both`` representation as expected by OpenSSL 3.5+.
* :class:`FixedSHAKE128` / :class:`FixedSHAKE256` — tiny wrappers around
  PyCryptodome SHAKE that expose a fixed ``digest_size`` so they can drop
  into RSA-PSS with SHAKE.
"""

from typing import Optional

from Crypto.Hash import SHAKE128, SHAKE256
from pyasn1.type import constraint, namedtype, tag, univ


def _OctetStringFixed(size: int) -> univ.OctetString:
    """Return an ``OctetString`` constrained to exactly ``size`` bytes."""
    return univ.OctetString().subtype(subtypeSpec=constraint.ValueSizeConstraint(size, size))


# ---------------------------------------------------------------------------
# ML-DSA private-key Choice structures
# ---------------------------------------------------------------------------


class BothMLDSA44(univ.Sequence):
    """``seed || expandedKey`` payload for ML-DSA-44."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(32)),
        namedtype.NamedType("expandedKey", _OctetStringFixed(2560)),
    )


class BothMLDSA65(univ.Sequence):
    """``seed || expandedKey`` payload for ML-DSA-65."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(32)),
        namedtype.NamedType("expandedKey", _OctetStringFixed(4032)),
    )


class BothMLDSA87(univ.Sequence):
    """``seed || expandedKey`` payload for ML-DSA-87."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(32)),
        namedtype.NamedType("expandedKey", _OctetStringFixed(4896)),
    )


class MLDSA44PrivateKeyASN1(univ.Choice):
    """ML-DSA-44 private-key payload: seed (``[0]``), expandedKey, or both."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed",
            _OctetStringFixed(32).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(2560)),
        namedtype.NamedType("both", BothMLDSA44()),
    )


class MLDSA65PrivateKeyASN1(univ.Choice):
    """ML-DSA-65 private-key payload: seed (``[0]``), expandedKey, or both."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed",
            _OctetStringFixed(32).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(4032)),
        namedtype.NamedType("both", BothMLDSA65()),
    )


class MLDSA87PrivateKeyASN1(univ.Choice):
    """ML-DSA-87 private-key payload: seed (``[0]``), expandedKey, or both."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed",
            _OctetStringFixed(32).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(4896)),
        namedtype.NamedType("both", BothMLDSA87()),
    )


# ---------------------------------------------------------------------------
# ML-KEM private-key Choice structures
# ---------------------------------------------------------------------------


class BothMLKEM512(univ.Sequence):
    """``seed || expandedKey`` payload for ML-KEM-512."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(64)),
        namedtype.NamedType("expandedKey", _OctetStringFixed(1632)),
    )


class BothMLKEM768(univ.Sequence):
    """``seed || expandedKey`` payload for ML-KEM-768."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(64)),
        namedtype.NamedType("expandedKey", _OctetStringFixed(2400)),
    )


class BothMLKEM1024(univ.Sequence):
    """``seed || expandedKey`` payload for ML-KEM-1024."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("seed", _OctetStringFixed(64)),
        namedtype.NamedType("expandedKey", _OctetStringFixed(3168)),
    )


class MLKEM512PrivateKeyASN1(univ.Choice):
    """ML-KEM-512 private-key payload: seed (``[0]``), expandedKey, or both."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed",
            _OctetStringFixed(64).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(1632)),
        namedtype.NamedType("both", BothMLKEM512()),
    )


class MLKEM768PrivateKeyASN1(univ.Choice):
    """ML-KEM-768 private-key payload: seed (``[0]``), expandedKey, or both."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed",
            _OctetStringFixed(64).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(2400)),
        namedtype.NamedType("both", BothMLKEM768()),
    )


class MLKEM1024PrivateKeyASN1(univ.Choice):
    """ML-KEM-1024 private-key payload: seed (``[0]``), expandedKey, or both."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "seed",
            _OctetStringFixed(64).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
        ),
        namedtype.NamedType("expandedKey", _OctetStringFixed(3168)),
        namedtype.NamedType("both", BothMLKEM1024()),
    )


# ---------------------------------------------------------------------------
# Hash wrappers — give SHAKE a fixed digest_size for use with RSA-PSS
# ---------------------------------------------------------------------------


class FixedSHAKE128:
    """SHAKE128 wrapper exposing a fixed 32-byte ``digest_size`` (RFC 9481 §3.2.3)."""

    digest_length = 32

    def __init__(self, data: Optional[bytes] = None) -> None:
        """Initialise the wrapper.

        :param data: Optional initial bytes absorbed into the SHAKE state.
        """
        self._shake = SHAKE128.new(data) if data else SHAKE128.new()
        self._digest: Optional[bytes] = None

    def update(self, data: bytes) -> None:
        """Feed more bytes into the SHAKE state."""
        self._shake.update(data)

    def digest(self) -> bytes:
        """Return the fixed-length digest."""
        if self._digest is None:
            self._digest = self._shake.read(self.digest_length)
        return self._digest

    @property
    def digest_size(self) -> int:
        """Return the fixed digest size in bytes."""
        return self.digest_length

    @classmethod
    def new(cls, data: Optional[bytes] = None) -> "FixedSHAKE128":
        """Construct a fresh instance, optionally pre-absorbing ``data``.

        :param data: Optional initial bytes absorbed into the SHAKE state.
        """
        return cls(data=data)


class FixedSHAKE256:
    """SHAKE256 wrapper with a 64-byte fixed ``digest_size`` (RFC 9481 §3.2.3)."""

    digest_length = 64

    def __init__(self, data: Optional[bytes] = None) -> None:
        """Initialise the wrapper.

        :param data: Optional initial bytes absorbed into the SHAKE state.
        """
        self._shake = SHAKE256.new(data) if data else SHAKE256.new()
        self._digest: Optional[bytes] = None

    def update(self, data: bytes) -> None:
        """Feed more bytes into the SHAKE state."""
        self._shake.update(data)

    def digest(self) -> bytes:
        """Return the fixed-length digest."""
        if self._digest is None:
            self._digest = self._shake.read(self.digest_length)
        return self._digest

    @property
    def digest_size(self) -> int:
        """Return the fixed digest size in bytes."""
        return self.digest_length

    @classmethod
    def new(cls, data: Optional[bytes] = None) -> "FixedSHAKE256":
        """Construct a fresh instance, optionally pre-absorbing ``data``.

        :param data: Optional initial bytes absorbed into the SHAKE state.
        """
        return cls(data=data)


__all__ = [
    "BothMLDSA44",
    "BothMLDSA65",
    "BothMLDSA87",
    "MLDSA44PrivateKeyASN1",
    "MLDSA65PrivateKeyASN1",
    "MLDSA87PrivateKeyASN1",
    "BothMLKEM512",
    "BothMLKEM768",
    "BothMLKEM1024",
    "MLKEM512PrivateKeyASN1",
    "MLKEM768PrivateKeyASN1",
    "MLKEM1024PrivateKeyASN1",
    "FixedSHAKE128",
    "FixedSHAKE256",
]
