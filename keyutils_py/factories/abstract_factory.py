# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Abstract base class for all key factories, with singleton semantics."""

from abc import ABCMeta, abstractmethod
from typing import ClassVar, Dict, List, Optional, Type

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from pyasn1.type import tag, univ
from pyasn1_alt_modules import rfc5280, rfc5958

from keyutils_py.exceptions import InvalidKeyData
from keyutils_py.types import PrivateKey, PublicKey
from keyutils_py.utils import try_decode_pyasn1


class _SingletonABCMeta(ABCMeta):
    """ABCMeta extended with per-class singleton semantics.

    Combining with ABCMeta preserves abstract-method enforcement.
    Calling ``FactoryClass()`` multiple times returns the same instance,
    while ``FactoryClass.static_method()`` still works without instantiation.
    """

    _instances: ClassVar[Dict[type, "AbstractKeyFactory"]] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class AbstractKeyFactory(metaclass=_SingletonABCMeta):
    """Abstract factory for creating, loading, and saving cryptographic keys.

    All concrete factories are singletons: ``MyFactory() is MyFactory()`` is
    always ``True``. Static/class methods remain the primary interface.
    """

    # ------------------------------------------------------------------
    # Algorithm lookup helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_alg_family(algs: List[str], alg: str) -> list:
        """Return algorithms from ``algs`` that start with ``alg``."""
        return [a for a in algs if a.startswith(alg)]

    @staticmethod
    def get_class_by_prefix(algorithm: str, prefix_map: Dict[str, Type]) -> type:
        """Return the key class whose prefix matches ``algorithm``.

        :raises NotImplementedError: If no prefix matches.
        """
        for prefix, cls in prefix_map.items():
            if algorithm.startswith(prefix):
                return cls
        raise NotImplementedError(f"Unimplemented algorithm: {algorithm}")

    @classmethod
    def _get_matching_prefix(cls, name: str, prefixes: List[str]) -> str:
        """Return the first prefix that ``name`` starts with."""
        for prefix in prefixes:
            if name.startswith(prefix):
                return prefix
        raise ValueError(f"Unsupported algorithm: {name}. Supported: {cls.supported_algorithms()}")

    # ------------------------------------------------------------------
    # Abstract interface — every concrete factory must implement these
    # ------------------------------------------------------------------

    @staticmethod
    @abstractmethod
    def supported_algorithms() -> list:
        """Return all algorithm names supported by this factory."""

    @staticmethod
    @abstractmethod
    def get_supported_keys() -> list:
        """Return supported key-type tokens (family prefixes or short names)."""

    @staticmethod
    @abstractmethod
    def generate_key_by_name(algorithm: str) -> PrivateKey:
        """Generate a private key for ``algorithm``."""

    @staticmethod
    @abstractmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PublicKey:
        """Load a public key from a SubjectPublicKeyInfo structure."""

    @staticmethod
    @abstractmethod
    def validate_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> None:
        """Validate ``alg_id``, raising if unsupported or malformed."""

    @classmethod
    @abstractmethod
    def _load_private_key_from_pkcs8(
        cls,
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> PrivateKey:
        """Load a private key from raw inner PKCS#8 bytes."""

    # ------------------------------------------------------------------
    # Shared OneAsymmetricKey helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_one_asym_key_version(one_asym_key: rfc5958.OneAsymmetricKey) -> None:
        version = one_asym_key["version"]
        if int(version) not in (0, 1):
            raise InvalidKeyData(f"Unsupported PKCS#8 version: {version}")
        if one_asym_key["publicKey"].isValue and version == 0:
            raise InvalidKeyData("Public key is not allowed in PKCS#8 version 0.")

    @classmethod
    def load_private_key_from_one_asym_key(cls, one_asym_key: rfc5958.OneAsymmetricKey) -> PrivateKey:
        """Load a private key from a OneAsymmetricKey structure."""
        cls._validate_one_asym_key_version(one_asym_key)
        cls.validate_alg_id(one_asym_key["privateKeyAlgorithm"])
        private_key_bytes = one_asym_key["privateKey"].asOctets()
        public_key_bytes = one_asym_key["publicKey"].asOctets() if one_asym_key["publicKey"].isValue else None
        return cls._load_private_key_from_pkcs8(
            one_asym_key["privateKeyAlgorithm"], private_key_bytes, public_key_bytes
        )

    @staticmethod
    def _set_public_key_in_one_asym_key(
        one_asym_key: rfc5958.OneAsymmetricKey,
        public_key_bytes: Optional[bytes],
    ) -> None:
        """Encode ``public_key_bytes`` as a tagged BitString and store it in ``one_asym_key``.

        Both PQKeyFactory and HybridKeyFactory need exactly this encoding;
        centralising it here removes the duplication.
        """
        if public_key_bytes is not None:
            one_asym_key["publicKey"] = univ.BitString(hexValue=public_key_bytes.hex()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )

    # ------------------------------------------------------------------
    # Shared public-key export helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _export_public_key(public_key: PublicKey) -> bytes:
        """Return the raw bit-string bytes of ``public_key`` from its SPKI DER encoding."""
        der_data = public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        spki, _ = try_decode_pyasn1(der_data, rfc5280.SubjectPublicKeyInfo())
        return spki["subjectPublicKey"].asOctets()

    @staticmethod
    def _get_public_bytes(
        private_key: PrivateKey,
        public_key: Optional[PublicKey] = None,
        version: int = 1,
        include_public_key: Optional[bool] = None,
        mismatching_public_key: bool = False,
    ) -> Optional[bytes]:
        if mismatching_public_key:
            from keyutils_py.keyutils import generate_key  # avoid circular at module level

            new_key = generate_key(private_key.name).public_key()  # type: ignore[union-attr]
            return AbstractKeyFactory._export_public_key(new_key)

        if include_public_key is None and version == 0 and public_key is not None:
            return None
        if include_public_key is None and version == 1:
            public_key = public_key or private_key.public_key()
            return AbstractKeyFactory._export_public_key(public_key)
        if include_public_key is False:
            return None
        if include_public_key:
            public_key = public_key or private_key.public_key()
            return AbstractKeyFactory._export_public_key(public_key)
        return None

    # ------------------------------------------------------------------
    # Shared OneAsymmetricKey builder (used by test-oriented save paths)
    # ------------------------------------------------------------------

    @staticmethod
    def _prepare_one_asym_key(
        private_key: bytes,
        version: int,
        alg_id: rfc5280.AlgorithmIdentifier,
        public_key: Optional[bytes] = None,
        add_public_trailing_data: bool = False,
        add_private_trailing_data: bool = False,
    ) -> rfc5958.OneAsymmetricKey:
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = int(version)
        one_asym_key["privateKeyAlgorithm"] = alg_id

        if public_key is not None:
            if add_public_trailing_data:
                public_key += b"\x00" * 16
            one_asym_key["publicKey"] = public_key

        if add_private_trailing_data:
            private_key += b"\x00" * 16
        one_asym_key["privateKey"] = private_key
        return one_asym_key

    @staticmethod
    def _prepare_invalid_private_key(private_key: PrivateKey) -> bytes:
        raise NotImplementedError("Override in subclass.")

    @staticmethod
    def save_private_key_to_one_asym_key(
        private_key: PrivateKey,
        version: int = 1,
        include_public_key: bool = True,
        mismatching_public_key: bool = False,
        add_public_trailing_data: bool = False,
        add_private_trailing_data: bool = False,
        alg_id: Optional[rfc5280.AlgorithmIdentifier] = None,
        invalid_private_key: bool = False,
    ) -> rfc5958.OneAsymmetricKey:
        """Serialise ``private_key`` into a ``OneAsymmetricKey`` (RFC 5958) structure.

        :param private_key: Private key to serialise.
        :param version: ``OneAsymmetricKey`` version field.
        :param include_public_key: When true, embed the matching public key in
            the optional ``publicKey`` attribute.
        :param mismatching_public_key: When true, intentionally embed a
            different public key (used to build negative test vectors).
        :param add_public_trailing_data: When true, append junk bytes after the
            embedded public key.
        :param add_private_trailing_data: When true, append junk bytes after
            the encoded private key.
        :param alg_id: Optional algorithm identifier override.
        :param invalid_private_key: When true, replace the private-key bytes
            with a deliberately invalid encoding.
        """
        public_key_bytes = AbstractKeyFactory._get_public_bytes(
            private_key,
            include_public_key=include_public_key,
            version=version,
            mismatching_public_key=mismatching_public_key,
        )

        der_private_key = private_key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        )
        dec_private_key = try_decode_pyasn1(der_private_key, rfc5958.OneAsymmetricKey())[0]

        private_key_bytes = (
            AbstractKeyFactory._prepare_invalid_private_key(private_key)
            if invalid_private_key
            else dec_private_key["privateKey"].asOctets()
        )

        resolved_alg_id: rfc5280.AlgorithmIdentifier = (
            alg_id if alg_id is not None else dec_private_key["privateKeyAlgorithm"]
        )

        return AbstractKeyFactory._prepare_one_asym_key(
            private_key=private_key_bytes,
            version=version,
            alg_id=resolved_alg_id,
            public_key=public_key_bytes,
            add_public_trailing_data=add_public_trailing_data,
            add_private_trailing_data=add_private_trailing_data,
        )
