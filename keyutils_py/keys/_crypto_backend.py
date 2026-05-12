# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Bridge from keyutils-py wrappers to ``cryptography``-native ML-DSA / ML-KEM.

The ``cryptography`` library (>= 48) exposes:

* ``ML-DSA-44/65/87`` — ``from_seed_bytes(32)``, ``sign``, ``verify``.
* ``ML-KEM-768/1024`` — ``from_seed_bytes(64)``, ``encapsulate``, ``decapsulate``.

Out of scope for the cryptography backend (still served by liboqs / the bundled
FIPS reference implementations):

* ``ML-KEM-512`` — not exposed by ``cryptography``.
* Pre-hashed ML-DSA — no ``hash_alg`` / ``is_prehashed`` parameters in the API.
* Loading a private key from the raw expanded bytes (``cryptography`` only
  supports loading from a seed).

Centralising the imports keeps the optional ``cryptography``-dispatch logic
isolated to one module.
"""

from __future__ import annotations

from typing import Type, Union

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

_MLDSA_PRIV_CLASSES: dict[str, Type] = {
    "ml-dsa-44": mldsa.MLDSA44PrivateKey,
    "ml-dsa-65": mldsa.MLDSA65PrivateKey,
    "ml-dsa-87": mldsa.MLDSA87PrivateKey,
}
_MLDSA_PUB_CLASSES: dict[str, Type] = {
    "ml-dsa-44": mldsa.MLDSA44PublicKey,
    "ml-dsa-65": mldsa.MLDSA65PublicKey,
    "ml-dsa-87": mldsa.MLDSA87PublicKey,
}
_MLKEM_PRIV_CLASSES: dict[str, Type] = {
    "ml-kem-768": mlkem.MLKEM768PrivateKey,
    "ml-kem-1024": mlkem.MLKEM1024PrivateKey,
}
_MLKEM_PUB_CLASSES: dict[str, Type] = {
    "ml-kem-768": mlkem.MLKEM768PublicKey,
    "ml-kem-1024": mlkem.MLKEM1024PublicKey,
}

NATIVE_MLDSA_NAMES = frozenset(_MLDSA_PRIV_CLASSES)
NATIVE_MLKEM_NAMES = frozenset(_MLKEM_PRIV_CLASSES)
NATIVE_NAMES = NATIVE_MLDSA_NAMES | NATIVE_MLKEM_NAMES

NativeMLDSAPriv = Union[mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey]
NativeMLDSAPub = Union[mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey]
NativeMLKEMPriv = Union[mlkem.MLKEM768PrivateKey, mlkem.MLKEM1024PrivateKey]
NativeMLKEMPub = Union[mlkem.MLKEM768PublicKey, mlkem.MLKEM1024PublicKey]


def is_cryptography_native_alg(name: str) -> bool:
    """Return ``True`` if ``cryptography`` 48+ has a native class for ``name``.

    Only matches ``ml-dsa-44/65/87`` and ``ml-kem-768/1024``.
    ``ml-kem-512`` is not supported by ``cryptography`` and returns ``False``.
    """
    return name.lower() in NATIVE_NAMES


def build_native_mldsa_priv(name: str, seed: bytes) -> NativeMLDSAPriv:
    """Construct an ML-DSA private key from a 32-byte seed."""
    return _MLDSA_PRIV_CLASSES[name].from_seed_bytes(seed)


def build_native_mldsa_pub(name: str, raw: bytes) -> NativeMLDSAPub:
    """Construct an ML-DSA public key from raw public-key bytes."""
    return _MLDSA_PUB_CLASSES[name].from_public_bytes(raw)


def build_native_mlkem_priv(name: str, seed: bytes) -> NativeMLKEMPriv:
    """Construct an ML-KEM private key from a 64-byte seed."""
    return _MLKEM_PRIV_CLASSES[name].from_seed_bytes(seed)


def build_native_mlkem_pub(name: str, raw: bytes) -> NativeMLKEMPub:
    """Construct an ML-KEM public key from raw public-key bytes."""
    return _MLKEM_PUB_CLASSES[name].from_public_bytes(raw)


__all__ = [
    "NATIVE_MLDSA_NAMES",
    "NATIVE_MLKEM_NAMES",
    "NATIVE_NAMES",
    "NativeMLDSAPriv",
    "NativeMLDSAPub",
    "NativeMLKEMPriv",
    "NativeMLKEMPub",
    "is_cryptography_native_alg",
    "build_native_mldsa_priv",
    "build_native_mldsa_pub",
    "build_native_mlkem_priv",
    "build_native_mlkem_pub",
]
