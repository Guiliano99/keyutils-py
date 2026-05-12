# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Stateful hash signature key abstract base classes (HSS / LMS / XMSS / XMSSMT).

Copy of ``cmp-test-suite/pq_logic/keys/abstract_stateful_hash_sig.py`` with
imports rewired to the keyutils-py layout.
"""

from abc import ABC, abstractmethod
from typing import Any

from pyasn1.type import univ

from keyutils_py.keys.abstract_wrapper_keys import PQPrivateKey, PQPublicKey
from keyutils_py.oids import PQ_NAME_2_OID


class PQHashStatefulSigPublicKey(PQPublicKey, ABC):
    """Abstract base class for PQ stateful-hash signature public keys."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the algorithm OID derived from this key's name."""
        if self.name.startswith("xmss-") or self.name.startswith("xmssmt-"):
            alg_name = self.name.split("-")[0]
        else:
            alg_name = self.name.split("_")[0]
        return PQ_NAME_2_OID[alg_name]

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> int:
        """Verify ``signature`` over ``data``.

        :return: The leaf index when the signature is valid.
        :raises cryptography.exceptions.InvalidSignature: If the signature is invalid.
        """

    @classmethod
    @abstractmethod
    def from_public_bytes(cls, data: bytes) -> "PQHashStatefulSigPublicKey":  # type: ignore[override]
        """Create a public key object from its raw bytes."""

    @abstractmethod
    def _export_public_key(self) -> bytes:
        """Return the public key bytes."""

    def __eq__(self, other: Any) -> bool:
        """Return True if ``other`` is a stateful-hash public key with identical name and bytes."""
        if not isinstance(other, PQHashStatefulSigPublicKey):
            return False
        if self.name != other.name or self.public_bytes_raw() != other.public_bytes_raw():
            return False
        return True

    @abstractmethod
    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from a signature."""

    @property
    @abstractmethod
    def max_sig_size(self) -> int:
        """Return the maximum signature size in bytes."""

    @property
    @abstractmethod
    def hash_alg(self) -> str:
        """Return the hash algorithm name used by this key."""


class PQHashStatefulSigPrivateKey(PQPrivateKey, ABC):
    """Abstract base class for PQ stateful-hash signature private keys."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the algorithm OID derived from this key's name."""
        if self.name.startswith("xmss-") or self.name.startswith("xmssmt-"):
            alg_name = self.name.split("-")[0]
        else:
            alg_name = self.name.split("_")[0]
        return PQ_NAME_2_OID[alg_name]

    @abstractmethod
    def _export_private_key(self) -> bytes:
        """Return the private key bytes."""

    @abstractmethod
    def public_key(self) -> PQHashStatefulSigPublicKey:
        """Return the matching public key."""

    def get_leaf_index(self, signature: bytes) -> int:
        """Extract the leaf index from a signature by delegating to the public key.

        :param signature: A signature produced by this key.
        """
        return self.public_key().get_leaf_index(signature)

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "PQHashStatefulSigPrivateKey":  # type: ignore[override]
        """Create a private key from its raw bytes."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign ``data``."""

    @property
    @abstractmethod
    def max_sig_size(self) -> int:
        """Return the maximum signature size in bytes."""

    @property
    @abstractmethod
    def sigs_remaining(self) -> int:
        """Return the number of signatures remaining."""

    @property
    @abstractmethod
    def used_keys(self) -> list[bytes]:
        """Return a list of used keys / leaves."""

    @property
    def hash_alg(self) -> str:
        """Return the hash algorithm name (delegated to the public key)."""
        return self.public_key().hash_alg
