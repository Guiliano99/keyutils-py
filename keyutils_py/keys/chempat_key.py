# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Chempat hybrid KEM key classes (draft-josefsson-chempat)."""

import logging
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from pyasn1.type import univ

from keyutils_py.exceptions import InvalidKeyCombination
from keyutils_py.factories.pq_factory import PQKeyFactory
from keyutils_py.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from keyutils_py.keys.abstract_wrapper_keys import (
    AbstractHybridRawPrivateKey,
    AbstractHybridRawPublicKey,
)
from keyutils_py.keys.kem_keys import (
    FrodoKEMPrivateKey,
    FrodoKEMPublicKey,
    McEliecePrivateKey,
    McEliecePublicKey,
    MLKEMPrivateKey,
    MLKEMPublicKey,
    Sntrup761PrivateKey,
    Sntrup761PublicKey,
)
from keyutils_py.keys.trad_kem_keys import DHKEMPrivateKey, DHKEMPublicKey
from keyutils_py.oids import CHEMPAT_NAME_2_OID
from keyutils_py.types import ECDHPrivateKey, ECDHPublicKey

CURVE_NAME_2_CONTEXT_NAME = {
    "secp256r1": "P256",
    "brainpoolP256r1": "brainpoolP256",
    "secp384r1": "P384",
    "brainpoolP384r1": "brainpoolP384",
    "brainpoolP512r1": "brainpoolP512",
    "x448": "X448",
    "x25519": "X25519",
}


class ChempatPublicKey(AbstractHybridRawPublicKey):
    """Chempat public key."""

    _pq_key: PQKEMPublicKey
    _trad_key: DHKEMPublicKey
    _name = "chempat"

    @property
    def name(self) -> str:
        """Return the canonical Chempat combination name."""
        return self._name + "-" + self._pq_key.name + "-" + self._trad_key.get_trad_name

    @property
    def pq_key(self) -> PQKEMPublicKey:
        """Return the post-quantum KEM public key half."""
        return self._pq_key

    @property
    def trad_key(self) -> DHKEMPublicKey:
        """Return the traditional DHKEM public key half."""
        return self._trad_key

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Union[ECDHPublicKey, DHKEMPublicKey]):
        """Initialise the Chempat public key.

        :param pq_key: PQ KEM public key half.
        :param trad_key: Traditional public key half; bare ECDH keys are
            wrapped in a :class:`DHKEMPublicKey` adapter.
        """
        super().__init__(pq_key, trad_key)  # type: ignore
        self._pq_key = pq_key
        self._trad_key = DHKEMPublicKey(trad_key, use_rfc9180=True)

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "ChempatPublicKey":
        """Build a Chempat public key from its raw byte encoding.

        :param data: Concatenated PQ + traditional public-key bytes.
        :param name: Canonical Chempat combination name (e.g.
            ``chempat-ml-kem-768-x25519``); used to choose the concrete subclass.
        """
        pq_key, rest = PQKeyFactory.from_public_bytes(name=name, data=data, allow_rest=True)  # type: ignore
        pq_key: PQKEMPublicKey
        trad_name = name.replace("chempat-", "", 1)
        trad_name = trad_name.replace(f"{pq_key.name}-", "", 1)
        trad_key = DHKEMPublicKey.from_public_bytes(name=trad_name, data=rest)

        if "ml-kem" in name:
            key = ChempatMLKEMPublicKey(pq_key, trad_key)
        elif "mceliece" in name:
            key = ChempatMcEliecePublicKey(pq_key, trad_key)
        elif "sntrup761" in name:
            key = ChempatSntrup761PublicKey(pq_key, trad_key)
        elif "frodokem" in name:
            key = ChempatFrodoKEMPublicKey(pq_key, trad_key)
        else:
            key = cls(pq_key, trad_key)

        key.get_oid()
        return key

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for this Chempat combination.

        :raises InvalidKeyCombination: If the combination is not registered.
        """
        if CHEMPAT_NAME_2_OID.get(self.name) is not None:
            return CHEMPAT_NAME_2_OID[self.name]
        raise InvalidKeyCombination(f"Unknown Chempat key combination: {self.name}")

    @property
    def key_size(self) -> int:
        """Return the encoded Chempat public-key size in bytes."""
        return len(self.public_bytes_raw())

    @staticmethod
    def _hash_sha3_256(data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def get_context(
        pq_key: Union[PQKEMPrivateKey, PQKEMPublicKey], trad_key: Union[DHKEMPublicKey, DHKEMPrivateKey]
    ) -> bytes:
        """Generate the Chempat context string."""
        if pq_key.name == "sntrup761":
            pq_name = "sntrup761"
        elif isinstance(pq_key, (McEliecePrivateKey, McEliecePublicKey)):
            pq_name = pq_key.name.replace("-", "").lower()
        elif isinstance(pq_key, (MLKEMPrivateKey, MLKEMPublicKey)):
            pq_name = pq_key.name.upper()
        elif isinstance(pq_key, (FrodoKEMPrivateKey, FrodoKEMPublicKey)):
            pq_name = pq_key.name.replace("frodokem", "FrodoKEM")
            pq_name = pq_name.replace("-aes", "")
            pq_name = pq_name.replace("-shake", "")
        else:
            raise InvalidKeyCombination(f"Unsupported post-quantum key type for Chempat.: {pq_key.name}")

        curve_name = trad_key.curve_name
        if curve_name in ["x448", "x25519"]:
            curve_name = curve_name.upper()
        else:
            curve_name = CURVE_NAME_2_CONTEXT_NAME[curve_name]

        return b"Chempat-" + bytes(curve_name, "utf-8") + b"-" + bytes(pq_name, "utf-8")

    @staticmethod
    def kem_combiner(
        trad_ct: bytes,
        trad_ss: bytes,
        pq_ct: bytes,
        pq_ss: bytes,
        pq_pub_key: bytes,
        trad_pub_key: bytes,
        context: bytes,
    ) -> bytes:
        """Combine shared secrets per Chempat specification."""
        hybrid_pk = pq_pub_key + trad_pub_key
        hybrid_ct = trad_ct + pq_ct

        h_hybrid_ct = ChempatPublicKey._hash_sha3_256(hybrid_ct)
        h_hybrid_pk = ChempatPublicKey._hash_sha3_256(hybrid_pk)

        concatenated_data = trad_ss + pq_ss + h_hybrid_ct + h_hybrid_pk + context
        hybrid_ss = ChempatPublicKey._hash_sha3_256(concatenated_data)
        logging.debug("Chempat shared secret: %s", hybrid_ss.hex())
        return hybrid_ss

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate against this Chempat public key and return ``(shared_secret, ct)``.

        :param private_key: Optional ephemeral ECDH private key for the
            traditional half (auto-generated when omitted).
        """
        pq_ss, pq_ct = self._pq_key.encaps()
        trad_ss, trad_ct = self._trad_key.encaps(private_key)
        context = self.get_context(self._pq_key, self._trad_key)
        pq_pub_key = self.pq_key.public_bytes_raw()
        trad_pub_key = self.trad_key.encode()
        ss = self.kem_combiner(trad_ct, trad_ss, pq_ct, pq_ss, pq_pub_key, trad_pub_key, context)
        return ss, b"".join([trad_ct, pq_ct])

    def public_bytes_raw(self) -> bytes:
        """Return the concatenated raw PQ and DHKEM public-key bytes."""
        return self._pq_key.public_bytes_raw() + self._trad_key.encode()


class ChempatPrivateKey(AbstractHybridRawPrivateKey):
    """Chempat private key."""

    _pq_key: PQKEMPrivateKey
    _trad_key: DHKEMPrivateKey
    _name = "chempat"

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Union[ECDHPrivateKey, DHKEMPrivateKey]):
        """Initialise the Chempat private key.

        :param pq_key: PQ KEM private key half.
        :param trad_key: Traditional private key half; bare ECDH keys are
            wrapped in a :class:`DHKEMPrivateKey` adapter.
        """
        super().__init__(pq_key, trad_key)  # type: ignore
        self._pq_key = pq_key
        self._trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=True)

    @property
    def name(self) -> str:
        """Return the canonical Chempat combination name."""
        return self._name + "-" + self._pq_key.name + "-" + self._trad_key.get_trad_name

    @property
    def pq_key(self) -> PQKEMPrivateKey:
        """Return the post-quantum KEM private key half."""
        return self._pq_key

    @property
    def trad_key(self) -> DHKEMPrivateKey:
        """Return the traditional DHKEM private key half."""
        return self._trad_key

    @classmethod
    def from_private_bytes(cls, data: bytes, name: str) -> "ChempatPrivateKey":
        """Build a Chempat private key from its raw byte encoding.

        :param data: Length-prefixed PQ private key followed by the traditional
            private key bytes.
        :param name: Canonical Chempat combination name.
        :raises InvalidKeyCombination: If the parsed PQ key is not a KEM key.
        """
        _length = int.from_bytes(data[:4], "little")
        pq_data = data[4 : 4 + _length]
        trad_data = data[4 + _length :]
        name = name.lower()
        tmp_name = name.replace("chempat-", "", 1)
        pq_name = PQKeyFactory.get_pq_alg_name(tmp_name)
        pq_key = PQKeyFactory.from_private_bytes(data=pq_data, name=pq_name)

        if not isinstance(pq_key, PQKEMPrivateKey):
            raise InvalidKeyCombination(f"Unsupported post-quantum key type for Chempat: {pq_key.name}")

        tmp_name = tmp_name.replace(f"{pq_name}-", "", 1)
        trad_key = DHKEMPrivateKey.from_private_bytes(data=trad_data, name=tmp_name)
        return cls(pq_key, trad_key)

    @property
    def ct_length(self) -> int:
        """Return the combined Chempat ciphertext length in bytes."""
        return self._pq_key.ct_length + self._trad_key.ct_length

    def get_context(self) -> bytes:
        """Return the Chempat context string for this key combination."""
        return ChempatPublicKey.get_context(self._pq_key, self._trad_key)

    def _check_ct_length(self, ct: bytes) -> bool:
        if len(ct) != self.ct_length:
            if self.trad_key.get_trad_name.startswith("ecdh"):
                if len(ct) == self.ct_length + self.trad_key.ct_length - 1:
                    return False
            raise ValueError(f"Invalid ciphertext length. Expected: {self.ct_length}, got: {len(ct)}")
        return True

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a Chempat ciphertext into the combined shared secret.

        :param ct: Concatenated traditional and PQ ciphertexts.
        :raises ValueError: If ``ct`` does not match the expected length.
        """
        nenc = self._trad_key.ct_length
        is_compressed = self._check_ct_length(ct)
        if is_compressed:
            trad_ct = ct[0:nenc]
            pq_ct = ct[nenc:]
        else:
            nenc = nenc + self.trad_key.ct_length - 1
            trad_ct = ct[0:nenc]
            pq_ct = ct[nenc:]

        trad_ss = self._trad_key.decaps(trad_ct)
        logging.info("Traditional decapsulated shared secret: %s", trad_ss.hex())
        pq_ss = self._pq_key.decaps(pq_ct)
        logging.info("PQ decapsulated shared secret: %s", pq_ss.hex())

        context = self.get_context()
        pq_pub_key = self._pq_key.public_key().public_bytes_raw()
        ss = ChempatPublicKey.kem_combiner(
            trad_ct=trad_ct,
            trad_ss=trad_ss,
            pq_ct=pq_ct,
            pq_ss=pq_ss,
            trad_pub_key=self._trad_key.public_key().encode(),
            pq_pub_key=pq_pub_key,
            context=context,
        )
        logging.info("Decapsulated shared secret: %s", ss.hex())
        return ss

    def public_key(self) -> ChempatPublicKey:
        """Return the matching Chempat public key."""
        return ChempatPublicKey(self._pq_key.public_key(), self._trad_key.public_key())

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for this Chempat combination.

        :raises InvalidKeyCombination: If the combination is not registered.
        """
        if CHEMPAT_NAME_2_OID.get(self.name) is not None:
            return CHEMPAT_NAME_2_OID[self.name]
        raise InvalidKeyCombination(f"Unknown Chempat key combination: {self.name}")

    @property
    def key_size(self) -> int:
        """Return the encoded Chempat private-key size in bytes."""
        return self._pq_key.key_size + self._trad_key.key_size

    @classmethod
    def parse_keys(cls, pq_key, trad_key) -> "ChempatPrivateKey":
        """Wrap raw PQ + ECDH private keys into the appropriate Chempat subclass.

        :param pq_key: PQ KEM private key.
        :param trad_key: Traditional ECDH private key.
        :raises InvalidKeyCombination: If the PQ family is unsupported.
        """
        trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=True)

        if isinstance(pq_key, MLKEMPrivateKey):
            return ChempatMLKEMPrivateKey(pq_key, trad_key)
        if isinstance(pq_key, McEliecePrivateKey):
            return ChempatMcEliecePrivateKey(pq_key, trad_key)
        if isinstance(pq_key, Sntrup761PrivateKey):
            return ChempatSntrup761PrivateKey(pq_key, trad_key)
        if isinstance(pq_key, FrodoKEMPrivateKey):
            return ChempatFrodoKEMPrivateKey(pq_key, trad_key)
        raise InvalidKeyCombination(f"Unsupported key combination: {pq_key.name}-{trad_key.get_trad_name}")


class ChempatMLKEMPublicKey(ChempatPublicKey):
    """Chempat ML-KEM public key."""

    _pq_key: MLKEMPublicKey


class ChempatMLKEMPrivateKey(ChempatPrivateKey):
    """Chempat ML-KEM private key."""

    _pq_key: MLKEMPrivateKey

    def public_key(self) -> ChempatMLKEMPublicKey:
        """Return the matching Chempat ML-KEM public key."""
        return ChempatMLKEMPublicKey(self._pq_key.public_key(), self.trad_key.public_key())


class ChempatMcEliecePublicKey(ChempatPublicKey):
    """Chempat McEliece public key."""

    _pq_key: McEliecePublicKey


class ChempatMcEliecePrivateKey(ChempatPrivateKey):
    """Chempat McEliece private key."""

    _pq_key: McEliecePrivateKey

    def public_key(self) -> ChempatMcEliecePublicKey:
        """Return the matching Chempat McEliece public key."""
        return ChempatMcEliecePublicKey(self._pq_key.public_key(), self._trad_key.public_key())


class ChempatSntrup761PublicKey(ChempatPublicKey):
    """Chempat Sntrup761 public key."""

    _pq_key: Sntrup761PublicKey


class ChempatSntrup761PrivateKey(ChempatPrivateKey):
    """Chempat Sntrup761 private key."""

    _pq_key: Sntrup761PrivateKey

    @classmethod
    def generate(cls) -> "ChempatSntrup761PrivateKey":
        """Generate a fresh Chempat-Sntrup761 private key paired with X25519."""
        return cls(PQKeyFactory.generate_pq_key("sntrup761"), x25519.X25519PrivateKey.generate())  # type: ignore

    def public_key(self) -> ChempatSntrup761PublicKey:
        """Return the matching Chempat Sntrup761 public key."""
        return ChempatSntrup761PublicKey(self._pq_key.public_key(), self._trad_key.public_key())


class ChempatFrodoKEMPublicKey(ChempatPublicKey):
    """Chempat FrodoKEM public key."""

    _pq_key: FrodoKEMPublicKey


class ChempatFrodoKEMPrivateKey(ChempatPrivateKey):
    """Chempat FrodoKEM private key."""

    _pq_key: FrodoKEMPrivateKey

    def public_key(self) -> ChempatFrodoKEMPublicKey:
        """Return the matching Chempat FrodoKEM public key."""
        return ChempatFrodoKEMPublicKey(self._pq_key.public_key(), self._trad_key.public_key())
