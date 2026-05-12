# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

# pylint: disable=redefined-builtin

"""Abstract public/private key wrapper classes.

Copy of ``cmp-test-suite/pq_logic/keys/abstract_wrapper_keys.py`` with
imports rewired to :mod:`keyutils_py.oids`.
"""

import base64
import textwrap
from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958

from keyutils_py.oids import PQ_NAME_2_OID
from keyutils_py.utils import encode_to_der, try_decode_pyasn1

ECSignKey = Union[ec.EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey]
ECVerifyKey = Union[ec.EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey]

ECDHPublicKey = Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]
ECDHPrivateKey = Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]

HybridTradPubComp = Union["TradKEMPublicKey", ECDHPublicKey, rsa.RSAPublicKey, ECVerifyKey]
HybridTradPrivComp = Union["TradKEMPrivateKey", ECDHPrivateKey, rsa.RSAPrivateKey, ECSignKey]


class BaseKey(ABC):
    """Abstract base class shared by all key types."""

    _name: str
    _other_name: Optional[str]

    def __eq__(self, other: object) -> bool:
        """Return True if ``other`` is a key of the exact same concrete type."""
        if not isinstance(other, BaseKey):
            return False
        return type(self) is type(other)

    @property
    def name(self) -> str:
        """Return the canonical lowercase algorithm name."""
        return self._name.lower()

    @abstractmethod
    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the Object Identifier of the key."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Return the size of the key in bytes."""

    def _get_header_name(self) -> bytes:
        return b"BASE"


class WrapperPublicKey(BaseKey):
    """Abstract public key with ``cryptography``-style serialisation helpers."""

    _public_key_bytes: bytes

    def __eq__(self, other: object) -> bool:
        """Return True if ``other`` is the same key type with identical raw public bytes."""
        if not super().__eq__(other):
            return False
        assert isinstance(other, WrapperPublicKey)
        return self._public_key_bytes == other._public_key_bytes

    @abstractmethod
    def _export_public_key(self) -> bytes:
        """Return the public key as raw bytes (no ASN.1 wrapping)."""

    @abstractmethod
    def _get_subject_public_key(self) -> bytes:
        """Return the bytes that go inside ``SubjectPublicKeyInfo.subjectPublicKey``."""

    def _to_spki(self) -> bytes:
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(self._get_subject_public_key())
        return encode_to_der(spki)

    def public_bytes(
        self,
        encoding: Encoding = Encoding.Raw,
        format: PublicFormat = PublicFormat.SubjectPublicKeyInfo,
    ) -> bytes:
        """Serialise the public key.

        :param encoding: Output encoding (``Raw``, ``DER`` or ``PEM``).
        :param format: Output format (``Raw`` or ``SubjectPublicKeyInfo``).
        :raises ValueError: For unsupported encoding / format combinations.
        """
        if encoding == Encoding.Raw and format == PublicFormat.Raw:
            return self._export_public_key()

        if encoding == Encoding.DER:
            if format == PublicFormat.SubjectPublicKeyInfo:
                return self._to_spki()
            raise ValueError(f"Unsupported format for DER encoding: {format}")

        if encoding == Encoding.PEM:
            if format != PublicFormat.SubjectPublicKeyInfo:
                raise ValueError(f"Unsupported format for PEM encoding: {format}")
            data = self._to_spki()
            b64 = "\n".join(textwrap.wrap(base64.b64encode(data).decode("ascii"), width=64))
            header = (
                self._get_header_name().decode("ascii")
                if isinstance(self._get_header_name(), bytes)
                else self._get_header_name()
            )
            return f"-----BEGIN {header} PUBLIC KEY-----\n{b64}\n-----END {header} PUBLIC KEY-----\n".encode("ascii")

        raise ValueError(f"Unsupported encoding: {encoding}")


class WrapperPrivateKey(BaseKey):
    """Abstract private key with ``cryptography``-style serialisation helpers."""

    @abstractmethod
    def public_key(self) -> WrapperPublicKey:
        """Return the matching public key."""

    @abstractmethod
    def _export_private_key(self) -> bytes:
        """Return the bytes that go inside ``OneAsymmetricKey.privateKey``."""

    def _to_one_asym_key(self) -> bytes:
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = 0
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        one_asym_key["privateKey"] = univ.OctetString(self._export_private_key())
        return encode_to_der(one_asym_key)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm: Union[NoEncryption, BestAvailableEncryption] = NoEncryption(),
    ) -> bytes:
        """Serialise the private key as PKCS#8 (DER or PEM, optionally encrypted).

        :param encoding: Output encoding (``DER`` or ``PEM``).
        :param format: Output format; only ``PKCS8`` is supported.
        :param encryption_algorithm: Optional PEM encryption (``BestAvailableEncryption``).
        :raises ValueError: For unsupported format or encryption combinations.
        :raises NotImplementedError: For unsupported encoding values.
        """
        if format != PrivateFormat.PKCS8:
            raise ValueError("Only PKCS8 format is supported.")

        if not isinstance(encryption_algorithm, serialization.NoEncryption) and encoding == Encoding.DER:
            raise ValueError("Encryption is not supported for DER encoding, only for PEM.")

        if encoding == Encoding.DER:
            return self._to_one_asym_key()

        if encoding == Encoding.PEM and isinstance(encryption_algorithm, serialization.BestAvailableEncryption):
            from keyutils_py.keys.key_pyasn1_utils import encrypt_private_key_pkcs8_pem

            return encrypt_private_key_pkcs8_pem(
                private_key_der=self._to_one_asym_key(),
                password=encryption_algorithm.password,
            )

        if encoding == Encoding.PEM:
            data = self._to_one_asym_key()
            header = self._get_header_name()
            if isinstance(header, bytes):
                header = header.decode("ascii")
            b64 = "\n".join(textwrap.wrap(base64.b64encode(data).decode("ascii"), width=64))
            return (f"-----BEGIN {header} PRIVATE KEY-----\n{b64}\n-----END {header} PRIVATE KEY-----\n").encode(
                "ascii"
            )

        raise NotImplementedError(f"The encoding is not supported. Encoding: {encoding} .Format: {format}.")


class KEMPublicKey(WrapperPublicKey, ABC):
    """Abstract base class for KEM public keys."""

    @classmethod
    @abstractmethod
    def encaps(cls, **kwargs) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret. Returns ``(shared_secret, ciphertext)``."""

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return len(self.encaps()[1])


class KEMPrivateKey(WrapperPrivateKey, ABC):
    """Abstract base class for KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate the ciphertext to recover the shared secret."""

    @abstractmethod
    def public_key(self) -> KEMPublicKey:  # type: ignore[override]
        """Return the matching KEM public key."""

    @property
    def ct_length(self) -> int:
        """Return the length of the ciphertext."""
        return self.public_key().ct_length


class PQPublicKey(WrapperPublicKey, ABC):
    """Post-quantum public key base class."""

    _public_key_bytes: bytes

    def __init__(self, alg_name: str, public_key: bytes) -> None:
        """Initialise the PQ public key.

        :param alg_name: Canonical algorithm name (e.g. ``ml-kem-768``).
        :param public_key: Raw public-key bytes.
        """
        self._public_key_bytes = public_key
        self._name, self._other_name = self._check_name(alg_name)
        self._initialize_key()

    def __eq__(self, other: Any) -> bool:
        """Return True if ``other`` is the same concrete type with identical raw bytes."""
        if type(other) is not type(self):
            return False
        return self._public_key_bytes == other._public_key_bytes

    @abstractmethod
    def _initialize_key(self) -> None:
        """Initialise any backend state held by the concrete subclass."""

    def _get_header_name(self) -> bytes:
        return b"PQ"

    def public_bytes_raw(self) -> bytes:
        """Return the raw PQ public-key bytes."""
        return self._public_key_bytes

    def _export_public_key(self) -> bytes:
        return self._public_key_bytes

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the PQ algorithm OID derived from the key name."""
        return PQ_NAME_2_OID[self.name]

    @abstractmethod
    def _check_name(self, name: str) -> Tuple[str, str]:
        """Validate ``name`` and return ``(canonical_name, backend_name)``."""

    @classmethod
    def from_public_bytes(cls, data: bytes, name: str) -> "PQPublicKey":
        """Build a PQ public key from raw bytes.

        :param data: Raw public-key bytes.
        :param name: Canonical algorithm name.
        :raises ValueError: If ``data`` does not match the expected key size.
        """
        key = cls(name, data)  # type: ignore[call-arg]
        if len(data) != key.key_size:
            raise ValueError(f"Invalid key size. Expected {key.key_size}, but got: {len(data)}")
        return key

    def _get_subject_public_key(self) -> bytes:
        return self._public_key_bytes

    @property
    def key_size(self) -> int:
        """Return the raw public-key length in bytes."""
        return len(self.public_bytes_raw())


class PQPrivateKey(WrapperPrivateKey, ABC):
    """Post-quantum private key base class."""

    _seed: Optional[bytes]
    _private_key_bytes: bytes
    _public_key_bytes: bytes

    def __init__(
        self,
        alg_name: str,
        private_bytes: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
        seed: Optional[bytes] = None,
    ) -> None:
        """Initialise the PQ private key.

        :param alg_name: Canonical algorithm name (e.g. ``ml-dsa-65``).
        :param private_bytes: Raw private-key bytes (optional if ``seed`` is given).
        :param public_key: Raw public-key bytes paired with ``private_bytes``.
        :param seed: Optional seed used to derive both halves deterministically.
        """
        self._name, self._other_name = self._check_name(alg_name)
        self._private_key_bytes = private_bytes  # type: ignore[assignment]
        self._public_key_bytes = public_key  # type: ignore[assignment]
        self._seed = seed
        self._initialize_key()

    @property
    def name(self) -> str:
        """Return the canonical algorithm name."""
        return self._name

    def _initialize_key(self) -> None:
        if self._private_key_bytes is not None and self._public_key_bytes is not None:
            return
        if self._seed is not None:
            self._private_key_bytes, self._public_key_bytes, self._seed = self._from_seed(self._name, self._seed)
            return
        raise NotImplementedError("The private key cannot be initialised without a seed or private key.")

    @staticmethod
    def _from_seed(alg_name: str, seed: bytes) -> Tuple[bytes, bytes, bytes]:
        raise NotImplementedError("The method `_from_seed` is not implemented.")

    @classmethod
    def from_seed(cls, alg_name: str, seed: bytes) -> "PQPrivateKey":
        """Build a PQ private key by expanding ``seed``.

        :param alg_name: Canonical algorithm name.
        :param seed: Algorithm-specific seed bytes.
        """
        private_key, public_key, seed_out = cls._from_seed(alg_name, seed)
        return cls(alg_name, private_key, public_key, seed_out)  # type: ignore[call-arg]

    @abstractmethod
    def _check_name(self, name: str) -> Tuple[str, str]:
        """Validate ``name`` and return ``(canonical_name, backend_name)``."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the PQ algorithm OID derived from the key name."""
        return PQ_NAME_2_OID[self.name]

    def _to_one_asym_key(self) -> bytes:
        one_asym_key = rfc5958.OneAsymmetricKey()
        # MUST be version 1; otherwise liboqs generates a wrong key.
        one_asym_key["version"] = 1
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = self.get_oid()
        one_asym_key["privateKey"] = univ.OctetString(self._export_private_key())
        public_key_asn1 = univ.BitString(hexValue=self.public_key().public_bytes_raw().hex()).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )
        one_asym_key["publicKey"] = public_key_asn1
        return encode_to_der(one_asym_key)

    def private_bytes_raw(self) -> bytes:
        """Return the raw PQ private-key bytes."""
        return self._private_key_bytes

    def _export_private_key(self) -> bytes:
        return self._seed or self._private_key_bytes

    @abstractmethod
    def public_key(self) -> PQPublicKey:
        """Return the matching public key."""


class TradKEMPublicKey(KEMPublicKey, ABC):
    """Abstract class for traditional KEM public keys."""

    _public_key: Union[ECDHPublicKey, rsa.RSAPublicKey]

    def __eq__(self, other: object) -> bool:
        """Return True if ``other`` wraps an identical traditional public key."""
        if not isinstance(other, TradKEMPublicKey):
            return False
        return self._public_key == other._public_key

    @abstractmethod
    def encaps(self, **kwargs) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret. Returns ``(shared_secret, ciphertext)``."""

    @property
    @abstractmethod
    def get_trad_name(self) -> str:
        """Return the name of the traditional algorithm."""

    @abstractmethod
    def encode(self) -> bytes:
        """Encode the public key as raw bytes."""


class TradKEMPrivateKey(KEMPrivateKey, ABC):
    """Abstract class for traditional KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate the ciphertext to recover the shared secret."""

    @abstractmethod
    def encode(self) -> bytes:
        """Encode the private key as raw bytes."""

    @abstractmethod
    def public_key(self) -> TradKEMPublicKey:
        """Return the matching public key."""

    @property
    def ct_length(self) -> int:
        """Return the ciphertext length in bytes (delegated to the public key)."""
        return self.public_key().ct_length

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Return the size of the key in bytes."""

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID of the underlying traditional KEM (delegated to the public key)."""
        return self.public_key().get_oid()

    @property
    def get_trad_name(self) -> str:
        """Return the canonical traditional name (delegated to the public key)."""
        return self.public_key().get_trad_name


class HybridPublicKey(WrapperPublicKey, ABC):
    """Abstract class for hybrid public keys."""

    _pq_key: PQPublicKey
    _trad_key: HybridTradPubComp

    def __init__(self, pq_key: PQPublicKey, trad_key: HybridTradPubComp) -> None:
        """Initialise the hybrid public key.

        :param pq_key: Post-quantum public key half.
        :param trad_key: Traditional public key half.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    def __eq__(self, other: Any) -> bool:
        """Return True if ``other`` is the same hybrid name with identical halves."""
        if not isinstance(other, HybridPublicKey):
            return False
        if other.name != self.name:
            return False
        return self._pq_key == other.pq_key and self._trad_key == other.trad_key  # type: ignore[comparison-overlap]

    @property
    def pq_key(self) -> PQPublicKey:
        """Return the post-quantum public key half."""
        return self._pq_key

    @property
    def trad_key(self) -> HybridTradPubComp:
        """Return the traditional public key half."""
        return self._trad_key


class HybridPrivateKey(WrapperPrivateKey, ABC):
    """Abstract class for hybrid private keys."""

    _pq_key: PQPrivateKey
    _trad_key: HybridTradPrivComp

    def __init__(self, pq_key: PQPrivateKey, trad_key: HybridTradPrivComp) -> None:
        """Initialise the hybrid private key.

        :param pq_key: Post-quantum private key half.
        :param trad_key: Traditional private key half.
        """
        self._pq_key = pq_key
        self._trad_key = trad_key

    @property
    def pq_key(self) -> PQPrivateKey:
        """Return the post-quantum private key half."""
        return self._pq_key

    @property
    def trad_key(self) -> HybridTradPrivComp:
        """Return the traditional private key half."""
        return self._trad_key

    @abstractmethod
    def public_key(self) -> HybridPublicKey:
        """Return the matching public key."""


class HybridSigPublicKey(HybridPublicKey, ABC):
    """A public key for a hybrid signature scheme."""

    _trad_key: ECVerifyKey
    _name: str = "hybrid-sig"

    def __eq__(self, other: Any) -> bool:
        """Return True if ``other`` is the same hybrid signature key with identical halves."""
        if not isinstance(other, HybridSigPublicKey):
            return False
        if other.name != self.name:
            return False
        return self._pq_key == other.pq_key and self._trad_key == other.trad_key

    @property
    def trad_key(self) -> ECVerifyKey:
        """Return the traditional verification key half."""
        return self._trad_key

    @property
    def pq_key(self):  # type: ignore[override]
        """Return the post-quantum public key half."""
        return self._pq_key

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, hash_alg: Optional[str] = None) -> bool:
        """Verify the signature."""

    def _get_trad_key_name(self) -> str:
        if isinstance(self._trad_key, ec.EllipticCurvePublicKey):
            return "ecdsa-" + self._trad_key.curve.name
        if isinstance(self._trad_key, ed25519.Ed25519PublicKey):
            return "ed25519"
        if isinstance(self._trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        if isinstance(self._trad_key, rsa.RSAPublicKey):
            return f"rsa-{self._trad_key.key_size}"
        raise ValueError("Unsupported key type: " + str(type(self._trad_key)))

    @property
    def name(self) -> str:
        """Return the canonical hybrid signature name."""
        return f"{self._name}-{self._pq_key.name}-{self._get_trad_key_name()}"


class HybridSigPrivateKey(HybridPrivateKey, ABC):
    """A private key for a hybrid signature scheme."""

    _trad_key: Union[ECSignKey, RSAPrivateKey]
    _name: str = "hybrid-sig"

    @property
    def trad_key(self) -> Union[ECSignKey, RSAPrivateKey]:
        """Return the traditional signing key half."""
        return self._trad_key

    @property
    def pq_key(self):  # type: ignore[override]
        """Return the post-quantum private key half."""
        return self._pq_key

    @abstractmethod
    def sign(self, data: bytes, **kwargs) -> bytes:
        """Sign the message."""

    def _get_trad_key_name(self) -> str:
        if isinstance(self._trad_key, ec.EllipticCurvePrivateKey):
            return "ecdsa-" + self._trad_key.curve.name
        if isinstance(self._trad_key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(self._trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        if isinstance(self._trad_key, rsa.RSAPrivateKey):
            return f"rsa-{self._trad_key.key_size}"
        raise ValueError("Unsupported key type: " + str(type(self._trad_key)))

    @property
    def name(self) -> str:
        """Return the canonical hybrid signature name."""
        return f"{self._name}-{self._pq_key.name}-{self._get_trad_key_name()}"


class HybridKEMPublicKey(HybridPublicKey, KEMPublicKey, ABC):
    """Abstract class for hybrid KEM public keys."""

    @abstractmethod
    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID for the hybrid KEM algorithm."""

    @abstractmethod
    def encaps(self, private_key: Optional[ECDHPrivateKey] = None) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret. Returns ``(shared_secret, ciphertext)``."""

    @property
    def ct_length(self) -> int:
        """Return the hybrid KEM ciphertext length in bytes."""
        return len(self.encaps()[1])


class HybridKEMPrivateKey(HybridPrivateKey, KEMPrivateKey, ABC):
    """Abstract class for hybrid KEM private keys."""

    @abstractmethod
    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate the ciphertext to recover the shared secret."""

    @abstractmethod
    def public_key(self) -> HybridKEMPublicKey:
        """Return the matching public key."""

    @property
    def ct_length(self) -> int:
        """Return the hybrid KEM ciphertext length in bytes (delegated to the public key)."""
        return self.public_key().ct_length

    def _get_trad_key_name(self) -> str:
        if isinstance(self._trad_key, TradKEMPrivateKey):
            return self._trad_key.get_trad_name
        if isinstance(self._trad_key, ec.EllipticCurvePublicKey):
            return f"ecdh-{self._trad_key.curve.name.lower()}"
        if isinstance(self._trad_key, x25519.X25519PrivateKey):
            return "x25519"
        if isinstance(self._trad_key, x448.X448PrivateKey):
            return "x448"
        raise ValueError(f"Unsupported Hybrid KEM key type: {type(self._trad_key).__name__}")


class AbstractCompositePublicKey(HybridPublicKey, ABC):
    """Abstract class for Composite public keys."""

    _pq_key: PQPublicKey
    _trad_key: Union[ECDHPublicKey, rsa.RSAPublicKey]

    def _get_subject_public_key(self) -> bytes:
        return self._export_public_key()

    def _get_trad_key_name(self, use_pss: bool = False) -> str:
        trad_key = self._trad_key
        if isinstance(trad_key, ec.EllipticCurvePublicKey):
            trad_name = f"ecdsa-{trad_key.curve.name}"
        elif isinstance(trad_key, rsa.RSAPublicKey):
            trad_name = f"rsa{trad_key.key_size}"
            if use_pss:
                trad_name += "-pss"
        elif isinstance(trad_key, ed25519.Ed25519PublicKey):
            trad_name = "ed25519"
        elif isinstance(trad_key, ed448.Ed448PublicKey):
            trad_name = "ed448"
        else:
            raise ValueError(f"Unsupported key type: {type(trad_key).__name__}")
        return trad_name

    @abstractmethod
    def get_oid(self, use_pss: bool = False) -> univ.ObjectIdentifier:
        """Return the OID for the composite signature algorithm."""

    def encode_trad_part(self) -> bytes:
        """Return the on-the-wire encoded traditional public key half."""
        if isinstance(self._trad_key, TradKEMPublicKey):
            return self._trad_key.encode()
        if isinstance(self._trad_key, (x25519.X25519PublicKey, x448.X448PublicKey)):
            return self._trad_key.public_bytes_raw()
        if isinstance(self._trad_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            return self._trad_key.public_bytes_raw()
        if isinstance(self._trad_key, rsa.RSAPublicKey):
            return self._trad_key.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        return self._trad_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def _export_public_key(self) -> bytes:
        """Return the raw composite public-key bytes (concatenation of the PQ half and the traditional half)."""
        return self._pq_key.public_bytes_raw() + self.encode_trad_part()

    def public_bytes_raw(self) -> bytes:
        """Return the raw composite public-key bytes (concatenation of the PQ half and the traditional half)."""
        return self._export_public_key()

    def to_spki(self, use_pss: bool = False) -> rfc5280.SubjectPublicKeyInfo:
        """Serialise this composite public key into a ``SubjectPublicKeyInfo`` structure.

        :param use_pss: Forwarded to :meth:`get_oid` to choose RSA-PSS / PKCS#1 v1.5.
        """
        data = self._export_public_key()
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = self.get_oid(use_pss)
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(data)
        return spki

    def public_bytes(
        self,
        encoding: Encoding = Encoding.Raw,
        format: PublicFormat = PublicFormat.SubjectPublicKeyInfo,
    ) -> bytes:
        """Serialise the composite public key.

        :param encoding: Output encoding (``Raw``, ``DER`` or ``PEM``).
        :param format: Output format. ``DER`` + ``Raw`` returns the bare
            concatenated halves; otherwise falls back to the SPKI helpers.
        """
        if encoding == Encoding.DER and format == PublicFormat.Raw:
            return self._export_public_key()
        return super().public_bytes(encoding, format)

    @property
    def key_size(self) -> int:
        """Return the encoded composite public-key size in bytes."""
        return len(self._export_public_key())


class AbstractCompositePrivateKey(HybridPrivateKey, ABC):
    """Abstract class for Composite private keys."""

    @abstractmethod
    def public_key(self) -> "AbstractCompositePublicKey":
        """Return the corresponding public key."""

    def _export_trad_private_key(self) -> bytes:
        if isinstance(self._trad_key, (X25519PrivateKey, X448PrivateKey, Ed25519PrivateKey, Ed448PrivateKey)):
            return self._trad_key.private_bytes_raw()
        if isinstance(self._trad_key, EllipticCurvePrivateKey):
            return self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        if isinstance(self._trad_key, RSAPrivateKey):
            der = self._trad_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            decoded = try_decode_pyasn1(der, rfc5958.OneAsymmetricKey())[0]
            return decoded["privateKey"].asOctets()
        return self._trad_key.encode()  # type: ignore[union-attr]

    def _export_private_key(self) -> bytes:
        if hasattr(self._pq_key, "private_numbers"):
            return self._pq_key.private_numbers() + self._export_trad_private_key()  # type: ignore[operator]
        return self._pq_key.private_bytes_raw() + self._export_trad_private_key()

    @property
    def key_size(self) -> int:
        """Return the encoded composite private-key size in bytes."""
        return len(self._export_private_key())

    @classmethod
    def _get_rsa_size(cls, value: int) -> int:
        predefined_values = [2048, 3072, 4096]
        return min(predefined_values, key=lambda x: abs(x - value))

    def _get_trad_key_name(self) -> str:
        if isinstance(self.trad_key, rsa.RSAPrivateKey):
            return f"rsa{self._get_rsa_size(self.trad_key.key_size)}"
        if isinstance(self.trad_key, ec.EllipticCurvePrivateKey):
            _curve = self.trad_key.curve.name
            if "kem" in self.name:
                return f"ecdh-{_curve}"
            return f"ecdsa-{_curve}"
        if isinstance(self.trad_key, ed25519.Ed25519PrivateKey):
            return "ed25519"
        if isinstance(self.trad_key, ed448.Ed448PrivateKey):
            return "ed448"
        if isinstance(self.trad_key, x25519.X25519PrivateKey):
            return "x25519"
        if isinstance(self.trad_key, x448.X448PrivateKey):
            return "x448"
        raise ValueError("Unsupported key type: " + str(type(self.trad_key)))


class AbstractHybridRawPublicKey(HybridKEMPublicKey, ABC):
    """Abstract class for a raw hybrid public key (XWing / Chempat)."""

    _pq_key: PQPublicKey
    _trad_key: ECDHPublicKey

    def __init__(self, pq_key: PQPublicKey, trad_key: ECDHPublicKey) -> None:
        """Initialise the raw hybrid public key.

        :param pq_key: Post-quantum public key half.
        :param trad_key: Traditional ECDH public key half.
        """
        super().__init__(pq_key, trad_key)
        self._pq_key = pq_key
        self._trad_key = trad_key

    @abstractmethod
    def public_bytes_raw(self) -> bytes:
        """Return the public key as raw bytes."""

    @classmethod
    @abstractmethod
    def from_public_bytes(cls, data: bytes) -> "AbstractHybridRawPublicKey":
        """Create a public key from raw bytes."""

    def _get_subject_public_key(self) -> bytes:
        return self.public_bytes_raw()

    def _export_public_key(self) -> bytes:
        return self.public_bytes_raw()


class AbstractHybridRawPrivateKey(HybridKEMPrivateKey, ABC):
    """Abstract class for a raw hybrid private key (XWing / Chempat)."""

    _pq_key: PQPrivateKey
    _trad_key: ECDHPrivateKey

    def _encode_trad_part(self) -> bytes:
        if isinstance(self._trad_key, TradKEMPrivateKey):
            return self._trad_key.encode()
        if isinstance(self._trad_key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
            return self._trad_key.private_bytes_raw()
        private_numbers = self._trad_key.private_numbers()  # type: ignore[union-attr]
        return private_numbers.private_value.to_bytes(self._trad_key.key_size, byteorder="big")  # type: ignore[union-attr]

    def private_bytes_raw(self) -> bytes:
        """Return the concatenated raw PQ + traditional private-key bytes."""
        return self._pq_key.private_bytes_raw() + self._encode_trad_part()

    def _export_private_key(self) -> bytes:
        pq_data = self._pq_key.private_bytes_raw()
        _length = len(pq_data)
        return _length.to_bytes(4, "little") + pq_data + self._encode_trad_part()

    @classmethod
    @abstractmethod
    def from_private_bytes(cls, data: bytes) -> "AbstractHybridRawPrivateKey":
        """Create a private key from raw bytes."""


__all__ = [
    "ECDHPrivateKey",
    "ECDHPublicKey",
    "ECSignKey",
    "ECVerifyKey",
    "HybridTradPubComp",
    "HybridTradPrivComp",
    "BaseKey",
    "WrapperPublicKey",
    "WrapperPrivateKey",
    "KEMPublicKey",
    "KEMPrivateKey",
    "PQPublicKey",
    "PQPrivateKey",
    "TradKEMPublicKey",
    "TradKEMPrivateKey",
    "HybridPublicKey",
    "HybridPrivateKey",
    "HybridSigPublicKey",
    "HybridSigPrivateKey",
    "HybridKEMPublicKey",
    "HybridKEMPrivateKey",
    "AbstractCompositePublicKey",
    "AbstractCompositePrivateKey",
    "AbstractHybridRawPublicKey",
    "AbstractHybridRawPrivateKey",
]
