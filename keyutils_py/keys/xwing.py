# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

# pylint: disable=invalid-name

"""XWing hybrid KEM key classes."""

import copy
import logging
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from pyasn1.type import univ

from keyutils_py.exceptions import InvalidKeyData
from keyutils_py.keys.abstract_wrapper_keys import AbstractHybridRawPrivateKey, AbstractHybridRawPublicKey
from keyutils_py.keys.kem_keys import MLKEMPrivateKey, MLKEMPublicKey
from keyutils_py.oids import XWING_OID_STR
from keyutils_py.types import ECDHPrivateKey

_XWING_LABEL = rb"""
                \./
                /^\
              """.replace(b"\n", b"").replace(b" ", b"")


class XWingPublicKey(AbstractHybridRawPublicKey):
    """XWing public key (ML-KEM-768 + X25519)."""

    _pq_key: MLKEMPublicKey  # type: ignore
    _trad_key: x25519.X25519PublicKey  # type: ignore

    def __init__(self, pq_key: MLKEMPublicKey, trad_key: x25519.X25519PublicKey):
        """Initialise the XWing public key.

        :param pq_key: ML-KEM-768 public key half.
        :param trad_key: X25519 public key half.
        :raises ValueError: If either argument is of the wrong type.
        """
        super().__init__(pq_key, trad_key)  # type: ignore
        if not isinstance(pq_key, MLKEMPublicKey):
            raise ValueError("pq_key must be an instance of MLKEMPublicKey.")
        if not isinstance(trad_key, x25519.X25519PublicKey):
            raise ValueError("trad_key must be an instance of X25519PublicKey.")

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the XWing algorithm OID."""
        return univ.ObjectIdentifier(XWING_OID_STR)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "XWingPublicKey":
        """Build an XWing public key from its 1216-byte raw encoding.

        :param data: Concatenated ML-KEM-768 (1184 bytes) and X25519 (32 bytes) public keys.
        :raises InvalidKeyData: If ``data`` is not exactly 1216 bytes long.
        """
        if len(data) != 1216:
            raise InvalidKeyData(f"Public key must be 1216 bytes in total, but got: {len(data)}.")
        pk_M = data[:1184]
        pk_X = data[1184:]
        trad_key = x25519.X25519PublicKey.from_public_bytes(pk_X)
        pq_key = MLKEMPublicKey.from_public_bytes(name="ml-kem-768", data=pk_M)
        return cls(pq_key=pq_key, trad_key=trad_key)

    def public_bytes_raw(self) -> bytes:
        """Return the concatenated raw ML-KEM and X25519 public-key bytes."""
        return self._pq_key.public_bytes_raw() + self._trad_key.public_bytes_raw()

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate against this XWing public key and return ``(shared_secret, ct)``.

        :param private_key: Optional ephemeral X25519 private key; one is
            generated if omitted or of the wrong type.
        """
        if not isinstance(private_key, x25519.X25519PrivateKey):
            private_key = x25519.X25519PrivateKey.generate()

        pk_X = self._trad_key.public_bytes_raw()
        ss_X = private_key.exchange(self._trad_key)
        ss_M, ct_M = self._pq_key.encaps()
        ct_X = private_key.public_key().public_bytes_raw()
        ss = XWingPrivateKey.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        ct = ct_M + ct_X
        return ss, ct

    @property
    def key_size(self) -> int:
        """Return the encoded XWing public-key size in bytes."""
        return self._pq_key.key_size + 32

    @property
    def ct_length(self) -> int:
        """Return the XWing ciphertext length in bytes."""
        return self._pq_key.ct_length + 32

    @property
    def name(self) -> str:
        """Return the algorithm name, ``"xwing"``."""
        return "xwing"

    @property
    def trad_key(self) -> x25519.X25519PublicKey:
        """Return the X25519 public key half."""
        return self._trad_key

    @property
    def pq_key(self) -> MLKEMPublicKey:
        """Return the ML-KEM-768 public key half."""
        return self._pq_key


class XWingPrivateKey(AbstractHybridRawPrivateKey):
    """XWing private key (ML-KEM-768 + X25519)."""

    _pq_key: MLKEMPrivateKey
    _trad_key: x25519.X25519PrivateKey
    _seed: Optional[bytes]

    def __init__(
        self,
        pq_key: Optional[MLKEMPrivateKey] = None,
        trad_key: Optional[x25519.X25519PrivateKey] = None,
        seed: Optional[bytes] = None,
    ):
        """Initialise the XWing private key.

        :param pq_key: Optional ML-KEM-768 private key half.
        :param trad_key: Optional X25519 private key half.
        :param seed: Optional 32-byte seed; when provided alone, both halves
            are deterministically expanded from it.
        :raises ValueError: If exactly one of ``pq_key`` / ``trad_key`` is given.
        """
        super().__init__(pq_key, trad_key)  # type: ignore
        if pq_key is None and trad_key is None:
            _key = XWingPrivateKey.expand(seed)
            pq_key = _key.pq_key
            trad_key = _key.trad_key
            seed = _key._seed
        elif pq_key is None or trad_key is None:
            raise ValueError("Both keys must be provided or none.")

        self._pq_key = pq_key  # type: ignore
        self._trad_key = trad_key  # type: ignore
        self._seed = seed  # type: ignore

    def private_numbers(self) -> bytes:
        """Return the 32-byte seed used to derive this key.

        :raises ValueError: If the key was not built from a seed.
        """
        if self._seed is None:
            raise ValueError("The private key does not have a seed set.")
        return self._seed

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the XWing algorithm OID."""
        return univ.ObjectIdentifier(XWING_OID_STR)

    def _get_header_name(self) -> bytes:
        return b"XWING"

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "XWingPrivateKey":
        """Build an XWing private key from one of its accepted byte encodings.

        Accepted lengths: 32 bytes (seed), 96 bytes (expanded seed), 2432 bytes
        (raw ML-KEM-768 + X25519), or 2432+32 bytes (seed prefix + raw bytes).

        :param data: Encoded private key bytes.
        :raises InvalidKeyData: If ``data`` has an unexpected length or the
            seed and raw forms disagree.
        """
        if len(data) == 96:
            pq_key = MLKEMPrivateKey.from_private_bytes(name="ml-kem-768", data=data[:64])
            trad_key = x25519.X25519PrivateKey.from_private_bytes(data[64:])
            return cls(pq_key, trad_key)

        if len(data) == 32:
            return cls.expand(data)

        if len(data) != 2432 and len(data) != 2432 + 32:
            raise InvalidKeyData(
                f"The private key must be 2400 bytes for ML-KEM and 32 bytes for X25519. "
                f"Or the private key must be the 32 bytes seed and then raw key. "
                f"Got: {len(data)} bytes."
            )
        seed_key = None
        if len(data) == 2432 + 32:
            seed_key = cls(seed=data[:32])
            trad_data = data[2432:]
            pq_data = data[32:2432]
        else:
            trad_data = data[2400:]
            pq_data = data[:2400]

        trad_key = x25519.X25519PrivateKey.from_private_bytes(trad_data)
        pq_key = MLKEMPrivateKey.from_private_bytes(pq_data, "ml-kem-768")
        key = cls(pq_key, trad_key)
        if seed_key is not None:
            if seed_key.private_bytes_raw() != key.private_bytes_raw():
                raise InvalidKeyData("The X-Wing private key does not match the seed.")
            return seed_key
        return key

    @staticmethod
    def kem_combiner(mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes) -> bytes:
        """Combine ML-KEM and X25519 shared secrets per the XWing specification.

        :param mlkem_ss: ML-KEM-768 shared secret.
        :param trad_ss: X25519 shared secret.
        :param trad_ct: X25519 ciphertext (sender's ephemeral public key).
        :param trad_pk: Recipient's X25519 public key.
        """
        hash_function = hashes.Hash(hashes.SHA3_256())
        hash_function.update(mlkem_ss + trad_ss + trad_ct + trad_pk + _XWING_LABEL)
        ss = hash_function.finalize()
        logging.info("XWing ss: %s", ss)
        return ss

    def encaps(self, public_key: XWingPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate against ``public_key`` using this private key's X25519 half.

        :param public_key: Recipient XWing public key.
        """
        pk_X = public_key.trad_key.public_bytes_raw()
        ss_X = self._trad_key.exchange(public_key.trad_key)
        ss_M, ct_M = public_key.pq_key.encaps()
        ct_X = self._trad_key.public_key().public_bytes_raw()
        ss = self.kem_combiner(ss_M, ss_X, ct_X, pk_X)
        ct = ct_M + ct_X
        return ss, ct

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate an XWing ciphertext.

        :param ct: 1120-byte concatenation of ML-KEM-768 (1088) and X25519 (32) ciphertexts.
        """
        ct_M = ct[:1088]
        ct_X = ct[1088:1120]
        ss_M = self.pq_key.decaps(ct_M)
        ss_X = self._trad_key.exchange(x25519.X25519PublicKey.from_public_bytes(ct_X))
        pk_X = self._trad_key.public_key().public_bytes_raw()
        return self.kem_combiner(ss_M, ss_X, ct_X, pk_X)

    @staticmethod
    def generate(**params) -> "XWingPrivateKey":
        """Generate a fresh XWing private key, optionally from a fixed seed.

        :param params: Accepts ``seed`` (32 or 96 bytes); a random 32-byte
            seed is drawn when omitted.
        """
        return XWingPrivateKey.expand(params.get("seed"))

    def public_key(self) -> XWingPublicKey:
        """Return the matching XWing public key."""
        return XWingPublicKey(self.pq_key.public_key(), self._trad_key.public_key())

    def _export_private_key(self) -> bytes:
        return self._seed or self.private_bytes_raw()

    @staticmethod
    def _from_seed(seed: bytes) -> Tuple[MLKEMPrivateKey, x25519.X25519PrivateKey, bytes]:
        seed_before = copy.copy(seed)
        if len(seed) == 32:
            shake = hashes.SHAKE256(digest_size=96)
            hasher = hashes.Hash(shake)
            hasher.update(seed)
            seed = hasher.finalize()

        if len(seed) != 96:
            raise ValueError("The seed must be 32 or 96 bytes long.")

        ml_kem_key = MLKEMPrivateKey.from_private_bytes(name="ml-kem-768", data=seed[:64])
        x25519_key = x25519.X25519PrivateKey.from_private_bytes(seed[64:96])
        return ml_kem_key, x25519_key, seed_before

    @classmethod
    def from_seed(cls, seed: bytes) -> "XWingPrivateKey":
        """Build an XWing private key from a 32- or 96-byte seed.

        :param seed: 32-byte SHAKE256 seed or 96-byte expanded seed.
        :raises ValueError: If ``seed`` is of an unsupported length.
        """
        if len(seed) in [32, 96]:
            return cls(*cls._from_seed(seed))
        raise ValueError("The seed must be 32 bytes for X25519 and 96 bytes for ML-KEM.")

    @classmethod
    def expand(cls, sk: Optional[bytes] = None) -> "XWingPrivateKey":
        """Expand ``sk`` (or a fresh random 32-byte seed) into an XWing private key.

        :param sk: Optional 32-byte seed; one is drawn at random when omitted.
        """
        sk = sk or os.urandom(32)
        return cls(*cls._from_seed(sk))

    @property
    def key_size(self) -> int:
        """Return the encoded XWing private-key size in bytes."""
        return self.pq_key.key_size + 32

    @property
    def name(self) -> str:
        """Return the algorithm name, ``"xwing"``."""
        return "xwing"

    @property
    def trad_key(self) -> x25519.X25519PrivateKey:
        """Return the X25519 private key half."""
        return self._trad_key

    @property
    def pq_key(self) -> MLKEMPrivateKey:
        """Return the ML-KEM-768 private key half."""
        return self._pq_key
