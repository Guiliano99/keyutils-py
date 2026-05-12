# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""KEM mechanisms: ECDH-KEM, DHKEM-RFC9180, RSA-KEM, RSA-OAEP-KEM.

Copy of ``cmp-test-suite/pq_logic/kem_mechanism.py`` with imports
rewired to :mod:`keyutils_py.oids`.
"""

import logging
import os
import random
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keyutils_py.oids import hash_name_to_instance
from keyutils_py.types import ECDHPrivateKey, ECDHPublicKey


def _perform_ecdh(private_key: ECDHPrivateKey, public_key: ECDHPublicKey) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(public_key, ec.EllipticCurvePublicKey):
        return private_key.exchange(ec.ECDH(), public_key)
    if isinstance(private_key, x25519.X25519PrivateKey) and isinstance(public_key, x25519.X25519PublicKey):
        return private_key.exchange(public_key)
    if isinstance(private_key, x448.X448PrivateKey) and isinstance(public_key, x448.X448PublicKey):
        return private_key.exchange(public_key)
    raise ValueError(
        f"Incompatible key types for ECDH: private={type(private_key).__name__}, public={type(public_key).__name__}"
    )


def _compute_kdf3(shared_secret: bytes, key_length: int) -> bytes:
    hash_algorithm = hash_name_to_instance("sha256")
    hasher = hashes.Hash(hash_algorithm)
    counter = 1
    keying_material = b""
    while len(keying_material) < key_length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        hasher.update(counter_bytes + shared_secret)
        keying_material += hasher.finalize()
        hasher = hashes.Hash(hash_algorithm)
        counter += 1
    return keying_material[:key_length]


class ECDHKEM:
    """ECDH-KEM mechanism using ephemeral ECDH."""

    def __init__(self, private_key: Optional[ECDHPrivateKey] = None):
        """Initialise the mechanism.

        :param private_key: Optional pre-existing private key; one is generated
            on demand if omitted.
        """
        self.private_key = private_key

    @staticmethod
    def encode_public_key(pubkey: ECDHPublicKey) -> bytes:
        """Encode an ECDH public key to its raw / uncompressed byte form.

        :param pubkey: The public key to encode.
        :raises TypeError: If ``pubkey`` is not a supported ECDH key type.
        """
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            return pubkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)
        if isinstance(pubkey, (x25519.X25519PublicKey, x448.X448PublicKey)):
            return pubkey.public_bytes_raw()
        raise TypeError("Unsupported public key type for encoding.")

    @staticmethod
    def generate_matching_private_key(peer_pubkey: ECDHPublicKey) -> ECDHPrivateKey:
        """Generate a fresh private key on the same curve / family as ``peer_pubkey``.

        :param peer_pubkey: The peer's public key.
        :raises TypeError: If the peer key family is not supported.
        """
        if isinstance(peer_pubkey, ec.EllipticCurvePublicKey):
            return ec.generate_private_key(peer_pubkey.curve)
        if isinstance(peer_pubkey, x25519.X25519PublicKey):
            return x25519.X25519PrivateKey.generate()
        if isinstance(peer_pubkey, x448.X448PublicKey):
            return x448.X448PrivateKey.generate()
        raise TypeError("Unsupported peer public key type.")

    def encaps(self, public_key: ECDHPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate against ``public_key`` and return ``(shared_secret, encoded_pubkey)``.

        :param public_key: Recipient's public key.
        """
        if not self.private_key:
            self.private_key = self.generate_matching_private_key(public_key)
        shared_secret = _perform_ecdh(self.private_key, public_key)
        ephemeral_public_key = self.private_key.public_key()
        return shared_secret, ECDHKEM.encode_public_key(ephemeral_public_key)

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate ``ct`` using this instance's private key.

        :param ct: The encoded ephemeral public key produced by :meth:`encaps`.
        """
        return self._exchange_from_bytes(ct)

    def _exchange_from_bytes(self, enc: Union[bytes, ECDHPublicKey]) -> bytes:
        if not isinstance(enc, ECDHPublicKey):
            if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                enc_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(self.private_key.curve, enc)
            elif isinstance(self.private_key, x25519.X25519PrivateKey):
                enc_pub_key = x25519.X25519PublicKey.from_public_bytes(enc)
            else:
                enc_pub_key = x448.X448PublicKey.from_public_bytes(enc)
        else:
            enc_pub_key = enc
        if self.private_key is None:
            raise ValueError("Private key is not set for decapsulation.")
        return _perform_ecdh(self.private_key, enc_pub_key)


KEY_TYPE_TO_ID = {
    "secp256r1": 0x0010,
    "brainpoolp256r1": 0x0010,
    "secp384r1": 0x0011,
    "brainpoolp384r1": 0x0011,
    "secp521r1": 0x0012,
    "brainpoolp512r1": 0x0012,
    "x25519": 0x0020,
    "x448": 0x0021,
}

ID_TO_SHA = {
    0x0010: hashes.SHA256(),
    0x0020: hashes.SHA256(),
    0x0011: hashes.SHA384(),
    0x0012: hashes.SHA512(),
    0x0021: hashes.SHA512(),
}


def _get_key_id(key: Union[ECDHPrivateKey, ECDHPublicKey]) -> int:
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return KEY_TYPE_TO_ID[key.curve.name.lower()]
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return KEY_TYPE_TO_ID["x448"]
    return KEY_TYPE_TO_ID["x25519"]


def _i2osp(num: int, size: int) -> bytes:
    return num.to_bytes(size, byteorder="big", signed=False)


class DHKEMRFC9180:
    """DHKEM per RFC 9180."""

    def __init__(self, private_key: Optional[ECDHPrivateKey] = None):
        """Initialise the mechanism.

        :param private_key: Optional pre-existing private key; one is generated
            on demand by :meth:`encaps` if omitted.
        """
        self.context = b"HPKE-v1"
        self.private_key = private_key
        self.hash_algorithm = hashes.SHA256()

    def _get_hash_length(self) -> int:
        return self.hash_algorithm.digest_size

    @staticmethod
    def encode_public_key(pubkey: ECDHPublicKey) -> bytes:
        """Encode an ECDH public key per RFC 9180 § 7.1.

        :param pubkey: The public key to encode.
        :raises TypeError: If ``pubkey`` is not a supported ECDH key type.
        """
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            return pubkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.UncompressedPoint)
        if isinstance(pubkey, (x25519.X25519PublicKey, x448.X448PublicKey)):
            return pubkey.public_bytes_raw()
        raise TypeError("Unsupported public key type for encoding.")

    def _extract_and_expand(self, dh: bytes, kem_context: bytes, cipher_id: int) -> bytes:
        suite_id = b"KEM" + _i2osp(cipher_id, 2)
        labeled_ikm = self.context + suite_id + b"eae_prk" + dh
        length_bytes = _i2osp(self._get_hash_length(), 2)
        labeled_info = length_bytes + self.context + suite_id + b"shared_secret" + kem_context
        hkdf = HKDF(algorithm=self.hash_algorithm, length=self._get_hash_length(), salt=b"", info=labeled_info)
        shared_secret = hkdf.derive(labeled_ikm)
        logging.info("DHKEM ss: %s", shared_secret.hex())
        return shared_secret

    def encaps(self, peer_pubkey: ECDHPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate against ``peer_pubkey`` and return ``(shared_secret, enc)``.

        :param peer_pubkey: Recipient's public key.
        """
        if self.private_key is None:
            self.private_key = ECDHKEM.generate_matching_private_key(peer_pubkey)
        shared_tmp = self._perform_exchange(peer_pubkey=peer_pubkey)
        enc = self.encode_public_key(self.private_key.public_key())
        key_id = _get_key_id(self.private_key)
        self.hash_algorithm = ID_TO_SHA[key_id]
        kem_context = enc + self.encode_public_key(peer_pubkey)
        return self._extract_and_expand(shared_tmp, kem_context, key_id), enc

    def _perform_exchange(self, peer_pubkey: ECDHPublicKey) -> bytes:
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            if not isinstance(peer_pubkey, ec.EllipticCurvePublicKey):
                raise TypeError("Peer public key must be an EllipticCurvePublicKey.")
            return self.private_key.exchange(ec.ECDH(), peer_pubkey)
        return self.private_key.exchange(peer_pubkey)  # type: ignore

    def _exchange_from_bytes(self, enc: Union[bytes, ECDHPublicKey]) -> bytes:
        if not isinstance(enc, ECDHPublicKey):
            if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                enc_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(self.private_key.curve, enc)
            elif isinstance(self.private_key, x25519.X25519PrivateKey):
                enc_pub_key = x25519.X25519PublicKey.from_public_bytes(enc)
            else:
                enc_pub_key = x448.X448PublicKey.from_public_bytes(enc)
        else:
            enc_pub_key = enc
        return self._perform_exchange(enc_pub_key)

    def decaps(self, enc: bytes) -> bytes:
        """Decapsulate the encoded peer public key ``enc`` using this private key.

        :param enc: The encoded ephemeral public key from the sender.
        :raises ValueError: If no private key has been associated with this instance.
        """
        if self.private_key is None:
            raise ValueError("Private key is not set for decapsulation.")
        shared_tmp = self._exchange_from_bytes(enc=enc)
        key_id = _get_key_id(self.private_key)
        self.hash_algorithm = ID_TO_SHA[key_id]
        kem_context = enc + self.encode_public_key(self.private_key.public_key())
        return self._extract_and_expand(shared_tmp, kem_context, key_id)


class RSAKem:
    """RSA-based KEM mechanism."""

    def __init__(self, ss_length: Optional[int] = None):
        """Initialise the mechanism.

        :param ss_length: Optional KDF3 output length. When ``None`` the raw
            shared-secret bytes are returned without KDF post-processing.
        """
        self.length = ss_length

    def encaps(self, public_key: rsa.RSAPublicKey, rand: Optional[int] = None) -> Tuple[bytes, bytes]:
        """Encapsulate against ``public_key`` and return ``(shared_secret, ciphertext)``.

        :param public_key: Recipient's RSA public key.
        :param rand: Optional fixed integer in ``[2, n-1]``; used by tests for
            deterministic output, otherwise drawn at random.
        """
        pub_num = public_key.public_numbers()
        e, n = pub_num.e, pub_num.n
        n_len = (n.bit_length() + 7) // 8
        shared_secret = rand or random.randint(2, n - 1)
        ct = pow(shared_secret, e, n)
        ct = _i2osp(ct, n_len)
        z_bytes = _i2osp(shared_secret, n_len)
        if self.length is None:
            return z_bytes, ct
        return _compute_kdf3(z_bytes, self.length), ct

    def decaps(self, private_key: rsa.RSAPrivateKey, ct_or_public_data: bytes) -> bytes:
        """Decapsulate ``ct_or_public_data`` using ``private_key``.

        :param private_key: Recipient's RSA private key.
        :param ct_or_public_data: The ciphertext produced by :meth:`encaps`.
        :raises ValueError: If the ciphertext length or value is invalid.
        """
        numbers = private_key.private_numbers()
        d, n = numbers.d, numbers.public_numbers.n
        n_len = (n.bit_length() + 7) // 8
        ct = ct_or_public_data
        if len(ct) != n_len:
            raise ValueError(f"Ciphertext length mismatch (expected {n_len}, got {len(ct)}).")
        c = int.from_bytes(ct, byteorder="big")
        if c >= n:
            raise ValueError("Ciphertext integer >= RSA modulus.")
        z = pow(c, d, n)
        z_bytes = _i2osp(z, n_len)
        if self.length is None:
            return z_bytes
        return _compute_kdf3(z_bytes, self.length)


class RSAOaepKem:
    """RSA-OAEP KEM mechanism."""

    def __init__(self, hash_alg: str = "sha256", ss_len: int = 32):
        """Initialise the mechanism.

        :param hash_alg: OAEP hash and MGF1 hash name (e.g. ``sha256``).
        :param ss_len: Length in bytes of the freshly generated shared secret.
        """
        self.hash_alg = hash_name_to_instance(hash_alg)
        self.ss_len = ss_len

    def encaps(self, public_key: rsa.RSAPublicKey) -> Tuple[bytes, bytes]:
        """Encapsulate a fresh shared secret under ``public_key`` using RSA-OAEP.

        :param public_key: Recipient's RSA public key.
        """
        shared_secret = os.urandom(self.ss_len)
        ciphertext = public_key.encrypt(
            shared_secret,
            padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_alg), algorithm=self.hash_alg, label=None),
        )
        return shared_secret, ciphertext

    def decaps(self, private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        """Decapsulate ``ciphertext`` with ``private_key`` using RSA-OAEP.

        :param private_key: Recipient's RSA private key.
        :param ciphertext: The ciphertext produced by :meth:`encaps`.
        """
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_alg), algorithm=self.hash_alg, label=None),
        )


__all__ = ["ECDHKEM", "DHKEMRFC9180", "RSAKem", "RSAOaepKem"]
