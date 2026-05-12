# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Composite KEM implementation (draft-ietf-lamps-pq-composite-kem)."""

import logging
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import NoEncryption
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from pyasn1.type import univ

from keyutils_py.exceptions import InvalidKeyCombination
from keyutils_py.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from keyutils_py.keys.abstract_wrapper_keys import (
    AbstractCompositePrivateKey,
    AbstractCompositePublicKey,
    HybridKEMPrivateKey,
    HybridKEMPublicKey,
    TradKEMPrivateKey,
    TradKEMPublicKey,
)
from keyutils_py.keys.trad_kem_keys import DHKEMPrivateKey, DHKEMPublicKey, RSADecapKey, RSAEncapKey
from keyutils_py.oids import COMPOSITE_KEM_NAME_2_OID
from keyutils_py.types import ECDHPrivateKey, ECDHPublicKey

COMPOSITE_KEM_LABELS = {
    "composite-kem-ml-kem-768-rsa2048": b"MLKEM768-RSAOAEP2048",
    "composite-kem-ml-kem-768-rsa3072": b"MLKEM768-RSAOAEP3072",
    "composite-kem-ml-kem-768-rsa4096": b"MLKEM768-RSAOAEP4096",
    "composite-kem-ml-kem-768-x25519": bytes.fromhex("5c2e2f2f5e5c"),
    "composite-kem-ml-kem-768-ecdh-secp256r1": b"MLKEM768-P256",
    "composite-kem-ml-kem-768-ecdh-secp384r1": b"MLKEM768-P384",
    "composite-kem-ml-kem-768-ecdh-brainpoolP256r1": b"MLKEM768-BP256",
    "composite-kem-ml-kem-1024-rsa3072": b"MLKEM1024-RSAOAEP3072",
    "composite-kem-ml-kem-1024-ecdh-secp384r1": b"MLKEM1024-P384",
    "composite-kem-ml-kem-1024-ecdh-brainpoolP384r1": b"MLKEM1024-BP384",
    "composite-kem-ml-kem-1024-x448": b"MLKEM1024-X448",
    "composite-kem-ml-kem-1024-ecdh-secp521r1": b"MLKEM1024-P521",
}


class CompositeKEMPublicKey(HybridKEMPublicKey, AbstractCompositePublicKey):
    """Composite KEM public key."""

    _trad_key: TradKEMPublicKey
    _pq_key: PQKEMPublicKey
    _name = "composite-kem"

    def __init__(self, pq_key: PQKEMPublicKey, trad_key: Union[TradKEMPublicKey, ECDHPublicKey, RSAPublicKey]):
        """Initialise the composite public key.

        :param pq_key: ML-KEM public key half.
        :param trad_key: Traditional public key half (KEM wrapper, ECDH, or RSA);
            ECDH and RSA keys are auto-wrapped in their KEM adapters.
        :raises ValueError: If ``trad_key`` is of an unsupported type.
        """
        super().__init__(pq_key, trad_key)

        if isinstance(trad_key, TradKEMPublicKey):
            self._trad_key = trad_key
        elif isinstance(trad_key, ECDHPublicKey):
            self._trad_key = DHKEMPublicKey(trad_key, use_rfc9180=False)
        elif isinstance(trad_key, RSAPublicKey):
            self._trad_key = RSAEncapKey(trad_key)
        else:
            raise ValueError(f"Unsupported trad_key type: {type(trad_key)}")

    @property
    def key_size(self) -> int:
        """Return the combined key size in bits."""
        return self.pq_key.key_size + self.trad_key.key_size

    @property
    def pq_key(self) -> PQKEMPublicKey:
        """Return the ML-KEM public key half."""
        return self._pq_key

    @property
    def trad_key(self) -> TradKEMPublicKey:
        """Return the traditional public key half."""
        return self._trad_key

    @property
    def name(self) -> str:
        """Return the canonical composite KEM name."""
        return self._name + "-" + self.pq_key.name + "-" + self.trad_key.get_trad_name

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for this composite KEM combination.

        :raises InvalidKeyCombination: If the combination has no registered OID.
        """
        if COMPOSITE_KEM_NAME_2_OID.get(self.name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {self.name}")
        return COMPOSITE_KEM_NAME_2_OID[self.name]

    def kem_combiner(
        self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes, use_in_cms: bool = False
    ) -> bytes:
        """Combine shared secrets: SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)."""
        label = COMPOSITE_KEM_LABELS[self.name]
        concatenated_inputs = mlkem_ss + trad_ss + trad_ct + trad_pk + label
        logging.info("CompositeKEM concatenated inputs: %s", concatenated_inputs.hex())
        h = hashes.Hash(hashes.SHA3_256())
        h.update(concatenated_inputs)
        ss = h.finalize()
        logging.debug("COMPOSITE KEM SHA3-256 output: %s", ss.hex())
        return ss

    def _trad_encaps(self, private_key: Optional[ECDHPrivateKey]) -> Tuple[bytes, bytes]:
        if isinstance(self.trad_key, RSAEncapKey):
            ss, ct = self.trad_key.encaps(use_oaep=True, hash_alg="sha256")
        else:
            ss, ct = self.trad_key.encaps(private_key=private_key)
        logging.info("Traditional KEM encaps ss: %s", ss.hex())
        logging.info("Traditional KEM encaps ct: %s", ct.hex())
        return ss, ct

    def encaps(self, private_key: Optional[ECDHPrivateKey] = None, use_in_cms: bool = True) -> Tuple[bytes, bytes]:
        """Encapsulate against this composite key.

        :param private_key: Optional ephemeral ECDH private key for the
            traditional half (auto-generated when omitted).
        :param use_in_cms: When true, format the combined shared secret for CMS use.
        """
        mlkem_ss, mlkem_ct = self.pq_key.encaps()
        trad_ss, trad_ct = self._trad_encaps(private_key)
        combined_ss = self.kem_combiner(mlkem_ss, trad_ss, trad_ct, self.encode_trad_part(), use_in_cms=use_in_cms)
        return combined_ss, mlkem_ct + trad_ct

    def _export_public_key(self) -> bytes:
        return self.pq_key.public_bytes_raw() + self._trad_key.encode()

    def public_bytes_raw(self) -> bytes:
        """Return the raw byte concatenation of the PQ and traditional public keys."""
        return self._export_public_key()


class CompositeKEMPrivateKey(HybridKEMPrivateKey, AbstractCompositePrivateKey):
    """Composite KEM private key."""

    _trad_key: TradKEMPrivateKey
    _pq_key: PQKEMPrivateKey
    _name = "composite-kem"

    def __init__(self, pq_key: PQKEMPrivateKey, trad_key: Union[TradKEMPrivateKey, ECDHPrivateKey, RSAPrivateKey]):
        """Initialise the composite private key.

        :param pq_key: ML-KEM private key half.
        :param trad_key: Traditional private key half (KEM wrapper, ECDH, or RSA);
            ECDH and RSA keys are auto-wrapped in their KEM adapters.
        :raises ValueError: If ``trad_key`` is of an unsupported type.
        """
        super().__init__(pq_key, trad_key)
        if isinstance(trad_key, TradKEMPrivateKey):
            self._trad_key = trad_key
        elif isinstance(trad_key, ECDHPrivateKey):
            self._trad_key = DHKEMPrivateKey(trad_key, use_rfc9180=False)
        elif isinstance(trad_key, RSAPrivateKey):
            self._trad_key = RSADecapKey(trad_key)
        else:
            raise ValueError(f"Unsupported trad_key type: {type(trad_key)}")

    @property
    def pq_key(self) -> PQKEMPrivateKey:
        """Return the ML-KEM private key half."""
        return self._pq_key

    @property
    def trad_key(self) -> TradKEMPrivateKey:
        """Return the traditional private key half."""
        return self._trad_key

    @property
    def name(self) -> str:
        """Return the canonical composite KEM name."""
        return self._name + "-" + self.pq_key.name + "-" + self.trad_key.get_trad_name

    def _export_trad_private_key(self) -> bytes:
        name = self._trad_key.get_trad_name
        if name.startswith("ecdh"):
            return self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption(),
            )
        return super()._export_trad_private_key()

    def _export_private_key(self) -> bytes:
        if hasattr(self._pq_key, "private_numbers"):
            _pq_export = self._pq_key.private_numbers()
        else:
            _pq_export = self.pq_key.private_bytes_raw()
        return _pq_export + self._export_trad_private_key()

    def private_bytes_raw(self) -> bytes:
        """Return the raw byte concatenation of the PQ and traditional private keys."""
        return self._export_private_key()

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for this composite KEM combination.

        For RSA-based composites the modulus size is rounded to a registered
        bucket (e.g. 2048 / 3072 / 4096) before lookup.

        :raises InvalidKeyCombination: If the combination has no registered OID.
        """
        if isinstance(self._trad_key, RSADecapKey):
            value = self._get_rsa_size(self._trad_key._private_key.key_size)  # pylint:disable=protected-access
            name = f"{self._name}-{self.pq_key.name}-rsa{value}"
        else:
            name = self.name
        if COMPOSITE_KEM_NAME_2_OID.get(name) is None:
            raise InvalidKeyCombination(f"Unsupported composite KEM combination: {name}")
        return COMPOSITE_KEM_NAME_2_OID[name]

    def public_key(self) -> CompositeKEMPublicKey:
        """Return the matching composite public key."""
        return CompositeKEMPublicKey(self.pq_key.public_key(), self.trad_key.public_key())

    def kem_combiner(
        self, mlkem_ss: bytes, trad_ss: bytes, trad_ct: bytes, trad_pk: bytes, use_in_cms: bool = False
    ) -> bytes:
        """Combine PQ and traditional shared secrets via the public-key combiner.

        :param mlkem_ss: ML-KEM shared secret.
        :param trad_ss: Traditional shared secret.
        :param trad_ct: Traditional ciphertext (or encoded ephemeral pubkey).
        :param trad_pk: Encoded traditional public key.
        :param use_in_cms: When true, format the combined output for CMS use.
        """
        return self.public_key().kem_combiner(mlkem_ss, trad_ss, trad_ct, trad_pk, use_in_cms)

    def encode_trad_part(self) -> bytes:
        """Return the encoded traditional public key, used as combiner input."""
        return self.trad_key.public_key().encode()

    def decaps(self, ct: bytes, use_in_cms: bool = True) -> bytes:
        """Decapsulate a composite ciphertext into the combined shared secret.

        :param ct: Concatenated ML-KEM and traditional ciphertexts.
        :param use_in_cms: When true, format the combined shared secret for CMS use.
        """
        mlkem_ct = ct[: self.pq_key.ct_length]
        trad_ct = ct[self.pq_key.ct_length :]
        mlkem_ss = self.pq_key.decaps(mlkem_ct)
        trad_ss = self._trad_key.decaps(trad_ct)
        combined_ss = self.kem_combiner(mlkem_ss, trad_ss, trad_ct, self.encode_trad_part(), use_in_cms=use_in_cms)
        return combined_ss
