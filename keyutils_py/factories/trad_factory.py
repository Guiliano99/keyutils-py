# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Factory for generating, loading and saving traditional (RSA/DSA/EC/EdDSA/X25519/X448/DH) keys."""

import os
from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3279, rfc4211, rfc5280, rfc5480, rfc5915, rfc5958, rfc6664, rfc8017, rfc9481

from keyutils_py.exceptions import BadAlg, InvalidKeyData, MismatchingKey
from keyutils_py.factories.abstract_factory import AbstractKeyFactory
from keyutils_py.keys.serialize_utils import ecc_private_key_to_bytes, prepare_ec_private_key, prepare_rsa_private_key
from keyutils_py.keys.trad_keys import DHPrivateKey, DHPublicKey
from keyutils_py.oids import get_curve_instance, may_return_oid_to_name
from keyutils_py.types import (
    DSAPrivateKey,
    DSAPublicKey,
    PrivateKey,
    PublicKey,
    TradKEMPublicKey,
    TradPrivateKey,
    TradPublicKey,
)
from keyutils_py.utils import encode_to_der, try_decode_pyasn1

# PKCS#3 ``dhKeyAgreement``; ``rfc3279.dhpublicnumber`` is the X9.42 identifier.
_DH_KEY_AGREEMENT = univ.ObjectIdentifier("1.2.840.113549.1.3.1")

_RAW_KEY_SIZES = {"x25519": 32, "x448": 56, "ed25519": 32, "ed448": 57}


class TradKeyFactory(AbstractKeyFactory):
    """Factory for traditional (RSA, DSA, ECDSA, EdDSA, X25519, X448, DH) keys."""

    #: Algorithm identifier of each traditional key type, as it appears in an SPKI or ``OneAsymmetricKey``.
    _OID_2_NAME = {
        rfc9481.rsaEncryption: "rsa",
        rfc6664.id_ecPublicKey: "ec",
        rfc9481.id_Ed25519: "ed25519",
        rfc9481.id_Ed448: "ed448",
        rfc9481.id_X25519: "x25519",
        rfc9481.id_X448: "x448",
        rfc5480.id_dsa: "dsa",
        rfc3279.dhpublicnumber: "dh",
        _DH_KEY_AGREEMENT: "dh",
    }

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return the list of traditional algorithm names this factory can generate."""
        return ["rsa", "dsa", "ecdsa", "ecdh", "ec", "ed25519", "ed448", "x25519", "x448", "dh"]

    @staticmethod
    def get_supported_keys() -> List[str]:
        """Return the supported algorithm names (alias of :meth:`supported_algorithms`)."""
        return TradKeyFactory.supported_algorithms()

    @staticmethod
    def is_trad_oid(oid: univ.ObjectIdentifier) -> bool:
        """Return ``True`` if ``oid`` is the algorithm identifier of a traditional key type."""
        return oid in TradKeyFactory._OID_2_NAME

    @staticmethod
    def generate_key_by_name(algorithm: str, **params) -> TradPrivateKey:  # type: ignore[override]
        """Generate a traditional private key by algorithm name.

        :param algorithm: One of the names returned by :meth:`supported_algorithms`.
        :param params: Algorithm-specific keyword parameters (e.g. ``length``,
            ``curve``) forwarded to :meth:`generate_trad_key`.
        """
        return TradKeyFactory.generate_trad_key(algorithm, **params)

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_ec_key(algorithm: str, curve: Optional[str] = None) -> TradPrivateKey:
        """Generate an elliptic-curve private key for the given algorithm."""
        if algorithm in ["ecdh", "ecdsa", "ecc", "ec"]:
            if curve is None:
                curve = "secp256r1"
            return ec.generate_private_key(curve=get_curve_instance(curve_name=curve))
        if algorithm == "ed25519":
            return ed25519.Ed25519PrivateKey.generate()
        if algorithm == "ed448":
            return ed448.Ed448PrivateKey.generate()
        if algorithm == "x25519":
            return x25519.X25519PrivateKey.generate()
        if algorithm == "x448":
            return x448.X448PrivateKey.generate()
        raise ValueError(f"Unsupported EC/EdDSA algorithm: {algorithm!r}")

    @staticmethod
    def generate_dh_key(
        p: Optional[int] = None,
        g: int = 2,
        secret_scalar: Optional[int] = None,
        length: int = 2048,
    ) -> TradPrivateKey:
        """Generate a Diffie-Hellman private key.

        PyCryptodome has no finite-field DH public-key primitive, so the
        (deprecated) cryptography FFDH API is retained intentionally until it
        is removed; default parameter generation uses that library.
        """
        return DHPrivateKey.generate(key_size=length, p=p, g=g, secret_scalar=secret_scalar)

    @staticmethod
    def generate_trad_key(algorithm: str = "rsa", **params) -> TradPrivateKey:
        """Generate a traditional private key.

        Supported: ``rsa``, ``dsa``, ``ecdsa``, ``ecdh``, ``ec``, ``ed25519``,
        ``ed448``, ``x25519``, ``x448``, ``dh``, and ``bad_rsa_key`` (a 512 bit RSA key).

        :param algorithm: The algorithm name.
        :param params: ``length`` (RSA/DSA modulus bits), ``curve`` (EC curve name), and for ``dh``
            ``p``, ``g``, ``secret_scalar`` and ``length``.
        :raises ValueError: If the algorithm is not supported.
        """
        algorithm = algorithm.lower()

        if algorithm == "bad_rsa_key":
            from cryptography.hazmat.bindings._rust import (  # pylint: disable=import-outside-toplevel
                openssl as rust_openssl,
            )

            return rust_openssl.rsa.generate_private_key(65537, 512)  # type: ignore[return-value]

        if algorithm == "rsa":
            length = int(params.get("length") or 2048)
            return rsa.generate_private_key(public_exponent=65537, key_size=length)

        if algorithm == "dsa":
            return DSAPrivateKey.generate(key_size=int(params.get("length", 2048)))

        if algorithm in {"ed25519", "ed448", "x25519", "x448", "ecdh", "ecdsa", "ecc", "ec"}:
            curve = params.get("curve", "secp256r1")
            return TradKeyFactory.generate_ec_key(algorithm, curve)

        if algorithm == "dh":
            return TradKeyFactory.generate_dh_key(
                p=params.get("p"),
                g=params.get("g", 2),
                secret_scalar=params.get("secret_scalar"),
                length=int(params.get("length", 2048)),
            )

        raise ValueError(f"Unsupported traditional algorithm: {algorithm!r}")

    # ------------------------------------------------------------------
    # Public key loading
    # ------------------------------------------------------------------

    @staticmethod
    def validate_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> None:
        """Validate that ``alg_id`` identifies a traditional key type.

        :param alg_id: Algorithm identifier to validate.
        :raises BadAlg: If the algorithm is not a traditional key type.
        """
        oid = alg_id["algorithm"]
        if not TradKeyFactory.is_trad_oid(oid):
            raise BadAlg(f"Unsupported traditional key algorithm: {may_return_oid_to_name(oid)}")

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PublicKey:
        """Load a traditional public key from a ``SubjectPublicKeyInfo``.

        DSA and DH keys are returned as the :mod:`keyutils_py.keys.trad_keys` wrappers.

        :param spki: The ``SubjectPublicKeyInfo`` to decode.
        :raises ValueError: If the key data cannot be loaded.
        """
        der = encode_to_der(spki)
        name = TradKeyFactory._OID_2_NAME.get(spki["algorithm"]["algorithm"])
        if name == "dsa":
            return DSAPublicKey.load(der)
        if name == "dh":
            return DHPublicKey.load(der)
        return serialization.load_der_public_key(der)  # type: ignore[return-value]

    @staticmethod
    def _load_raw_public_key(trad_name: Union[str, univ.ObjectIdentifier], public_key_bytes: bytes) -> PublicKey:
        """Load an EdDSA or X25519/X448 public key from its raw bytes.

        :raises InvalidKeyData: If the length is wrong.
        :raises ValueError: If the key type is not a raw one.
        """
        loaders = {
            "x25519": (rfc9481.id_X25519, x25519.X25519PublicKey),
            "x448": (rfc9481.id_X448, x448.X448PublicKey),
            "ed25519": (rfc9481.id_Ed25519, ed25519.Ed25519PublicKey),
            "ed448": (rfc9481.id_Ed448, ed448.Ed448PublicKey),
        }
        for name, (oid, key_class) in loaders.items():
            if trad_name in (name, oid):
                expected = _RAW_KEY_SIZES[name]
                if len(public_key_bytes) != expected:
                    raise InvalidKeyData(
                        f"The {key_class.__name__.removesuffix('PublicKey').upper()} public key has an invalid length. "
                        f"Expected: {expected} bytes, got: {len(public_key_bytes)} bytes."
                    )
                return key_class.from_public_bytes(public_key_bytes)

        raise ValueError(f"Unsupported raw algorithm name: {trad_name}")

    @staticmethod
    def load_trad_public_key(
        trad_name: Union[str, univ.ObjectIdentifier], data: bytes, curve_name: Optional[str] = None
    ) -> PublicKey:
        """Load a traditional public key from the bytes of its ``subjectPublicKey``.

        Supported algorithms are RSA, ECDSA, ECDH, Ed25519, Ed448, X25519, and X448.

        :param trad_name: The traditional public key name or the OID.
        :param data: The data to load.
        :param curve_name: The name of the curve for ECC keys.
        :return: The loaded public key.
        :raises NotImplementedError: If the algorithm is not implemented.
        :raises ValueError: If the curve name is not provided for ECC keys or not supported.
        :raises InvalidKeyData: If the key data is invalid.
        """
        if trad_name in ["rsa", rfc9481.rsaEncryption]:
            _, rest = try_decode_pyasn1(data, rfc3279.RSAPublicKey())
            if rest:
                raise InvalidKeyData("The `RSAPublicKey` data contains trailing data.")
            try:
                return serialization.load_der_public_key(data)  # type: ignore[return-value]
            except ValueError as e:
                raise InvalidKeyData("The `RSAPublicKey` cannot be loaded.") from e

        if trad_name in ["ecdsa", "ecdh", "ec", rfc6664.id_ecPublicKey, rfc5480.id_ecMQV, rfc5480.id_ecDH]:
            if curve_name is None:
                raise ValueError("Curve name is required for ECC keys.")
            curve_instance = get_curve_instance(curve_name=curve_name)
            try:
                return ec.EllipticCurvePublicKey.from_encoded_point(curve_instance, data)
            except ValueError as e:
                raise InvalidKeyData("The `ECPoint` data is not a valid point on the curve.") from e

        if trad_name in ["x25519", "ed25519", "x448", "ed448"] or trad_name in (
            rfc9481.id_X25519,
            rfc9481.id_Ed25519,
            rfc9481.id_X448,
            rfc9481.id_Ed448,
        ):
            return TradKeyFactory._load_raw_public_key(public_key_bytes=data, trad_name=trad_name)

        raise NotImplementedError(f"The algorithm name: {trad_name} is not implemented to be loaded.")

    @staticmethod
    def _load_public_key(public_key_bytes: bytes, oid: univ.ObjectIdentifier) -> PublicKey:
        """Load the public key stored in a ``OneAsymmetricKey`` for the algorithm ``oid``."""
        try:
            return TradKeyFactory.load_trad_public_key(oid, public_key_bytes)
        except ValueError as e:
            raise InvalidKeyData(f"Failed to load {may_return_oid_to_name(oid)} public key.") from e

    # ------------------------------------------------------------------
    # Private key loading
    # ------------------------------------------------------------------

    @staticmethod
    def _check_private_key_encoding(oid: univ.ObjectIdentifier, private_key_bytes: bytes) -> None:
        """Raise if the inner encoding of the private key has trailing data."""
        if oid in (rfc9481.id_Ed25519, rfc9481.id_Ed448, rfc9481.id_X25519, rfc9481.id_X448):
            _, rest = try_decode_pyasn1(private_key_bytes, univ.OctetString())
            if rest:
                raise InvalidKeyData(f"The {may_return_oid_to_name(oid).upper()} private key contained trailing data")

        if oid == rfc6664.id_ecPublicKey:
            _, rest = try_decode_pyasn1(private_key_bytes, rfc5915.ECPrivateKey())
            if rest:
                raise InvalidKeyData("The `ECPrivateKey` data contains trailing data.")

        if oid == rfc9481.rsaEncryption:
            _, rest = try_decode_pyasn1(private_key_bytes, rfc8017.RSAPrivateKey())
            if rest:
                raise InvalidKeyData("The `RSAPrivateKey` data contains trailing data.")

    @classmethod
    def _decode_private_key(cls, alg_id: rfc5280.AlgorithmIdentifier, private_key_bytes: bytes) -> TradPrivateKey:
        """Decode the private key; DSA and DH keys become the ``keyutils_py`` wrappers."""
        oid = alg_id["algorithm"]
        # the `cryptography` library does not support version 2.
        info = rfc4211.PrivateKeyInfo()
        info["version"] = 0
        info["privateKeyAlgorithm"]["algorithm"] = oid
        info["privateKeyAlgorithm"]["parameters"] = alg_id["parameters"]
        info["privateKey"] = univ.OctetString(private_key_bytes)
        der = encode_to_der(info)

        name = cls._OID_2_NAME[oid]
        try:
            if name == "dsa":
                return DSAPrivateKey.load(der)
            if name == "dh":
                return DHPrivateKey.load(der)
            return serialization.load_der_private_key(der, password=None)  # type: ignore[return-value]
        except ValueError as e:
            raise InvalidKeyData("The private key is not a valid DER-encoded private key.") from e
        except Exception as e:  # noqa: BLE001
            raise InvalidKeyData("The ECC private key is not a valid private key.") from e

    @classmethod
    def _check_public_key(
        cls, oid: univ.ObjectIdentifier, private_key: TradPrivateKey, public_key_bytes: bytes
    ) -> None:
        """Check that ``public_key_bytes`` is the public key of ``private_key``.

        :raises MismatchingKey: If it is not.
        """
        name = cls._OID_2_NAME[oid]
        if name in ("dsa", "dh"):
            y, rest = try_decode_pyasn1(public_key_bytes, univ.Integer())
            if rest:
                raise InvalidKeyData(f"The {name.upper()} public key contained trailing data")
            if int(y) != private_key.public_key().y:  # type: ignore[union-attr]
                raise MismatchingKey("The public key does not match the private key.")
            return

        if name == "ec":
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("The private key is not an Elliptic Curve private key.")
            try:
                public_key = serialization.load_der_public_key(public_key_bytes)
            except ValueError:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    data=public_key_bytes, curve=private_key.curve
                )
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise InvalidKeyData("The public key is not an Elliptic Curve public key.")
        else:
            # The public key is saved as raw bytes (EdDSA, X25519, X448) or as a PKCS#1 ``RSAPublicKey``.
            public_key = cls._load_public_key(public_key_bytes, oid)

        if private_key.public_key() != public_key:
            raise MismatchingKey("The public key does not match the private key.")

    @classmethod
    def _load_private_key_from_pkcs8(
        cls,
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> TradPrivateKey:
        """Load a traditional private key from the inner bytes of a ``OneAsymmetricKey``.

        :param alg_id: The private key algorithm identifier.
        :param private_key_bytes: The content of the ``privateKey`` field.
        :param public_key_bytes: The content of the ``publicKey`` field, if present; it is checked against the
            private key.
        :raises BadAlg: If the algorithm is not a traditional key type.
        :raises InvalidKeyData: If the key data is invalid.
        :raises MismatchingKey: If the public key does not match the private key.
        """
        cls.validate_alg_id(alg_id)
        oid = alg_id["algorithm"]
        cls._check_private_key_encoding(oid, private_key_bytes)
        private_key = cls._decode_private_key(alg_id, private_key_bytes)
        if public_key_bytes is not None:
            cls._check_public_key(oid, private_key, public_key_bytes)
        return private_key

    @classmethod
    def parse_trad_key_from_one_asym_key(
        cls,
        one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes],
        must_be_version_2: bool = True,
    ) -> TradPrivateKey:
        """Parse a traditional private key from a ``OneAsymmetricKey``.

        :param one_asym_key: The ``OneAsymmetricKey`` or its DER encoding.
        :param must_be_version_2: If True, the key must be a version 2 key.
        :return: The parsed private key.
        :raises ValueError: If the key is not a version 2 key.
        :raises InvalidKeyData: If the key data is invalid or does not match the expected format.
        :raises MismatchingKey: If the public key does not match the private key.
        """
        if isinstance(one_asym_key, bytes):
            decoded, rest = try_decode_pyasn1(one_asym_key, rfc5958.OneAsymmetricKey())
            if rest:
                raise InvalidKeyData("Decoding the `OneAsymmetricKey` structure had a remainder.")
        else:
            decoded = one_asym_key

        version = int(decoded["version"])
        if version not in [0, 1]:
            raise InvalidKeyData(f"Unsupported `OneAsymmetricKey` version: {version}. Supported versions are 0 and 1.")
        if version != 1 and must_be_version_2:
            raise ValueError("The provided key is not a version 2 key.")
        if version == 0 and decoded["publicKey"].isValue:
            raise InvalidKeyData("The `OneAsymmetricKey` version is 0, but a public key is present.")

        public_key_bytes = decoded["publicKey"].asOctets() if decoded["publicKey"].isValue else None
        return cls._load_private_key_from_pkcs8(
            decoded["privateKeyAlgorithm"], decoded["privateKey"].asOctets(), public_key_bytes
        )

    # ------------------------------------------------------------------
    # Private key saving
    # ------------------------------------------------------------------

    @staticmethod
    def prepare_invalid_trad_private_key(
        private_key: TradPrivateKey,
        invalid_key: bool = False,
        invalid_key_size: bool = False,
    ) -> bytes:
        """Prepare an invalid encoding of a traditional private key, to test validation and error handling.

        :param private_key: The private key to be prepared to be invalid.
        :param invalid_key: If True, the key value is invalid.
        :param invalid_key_size: If True, the key has trailing data (an invalid size).
        :return: The DER-encoded invalid private key bytes.
        :raises ValueError: If neither flag is set, or the private key type is not supported.
        """
        if not invalid_key and not invalid_key_size:
            raise ValueError("Either `invalid_key` or `invalid_key_size` must be True.")

        if isinstance(private_key, rsa.RSAPrivateKey):
            if invalid_key_size:
                return prepare_rsa_private_key(private_key, add_to_n=False) + os.urandom(10)
            return prepare_rsa_private_key(private_key, add_to_n=True)

        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            if invalid_key_size:
                return encode_to_der(prepare_ec_private_key(private_key)) + os.urandom(10)
            # creates a too big private key for the curve.
            neg_ecc_key_bytes = ecc_private_key_to_bytes(private_key) + os.urandom(10)
            return encode_to_der(prepare_ec_private_key(private_key, private_key_bytes=neg_ecc_key_bytes))

        if isinstance(
            private_key,
            (x25519.X25519PrivateKey, x448.X448PrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
        ):
            if invalid_key:
                raise ValueError(f"Invalid key is not supported for this type of key.Got: {type(private_key)}")
            return private_key.private_bytes_raw() + os.urandom(10)

        raise ValueError(f"Unsupported private key type: {type(private_key)}")

    @staticmethod
    def _prepare_invalid_private_key(private_key: PrivateKey) -> bytes:
        return TradKeyFactory.prepare_invalid_trad_private_key(private_key, invalid_key=True)  # type: ignore[arg-type]

    @staticmethod
    def _get_public_key_bytes(public_key: TradPublicKey) -> bytes:
        """Return the content of the ``publicKey`` field for ``public_key``.

        :raises TypeError: If the public key type is not supported.
        """
        if isinstance(public_key, TradKEMPublicKey):
            return public_key.encode()
        if not isinstance(public_key, TradPublicKey):
            raise TypeError(f"Unsupported public key type. Got: {type(public_key)}")
        return AbstractKeyFactory._export_public_key(public_key)

    @staticmethod
    def _prepare_private_key_bytes(
        private_key: TradPrivateKey, invalid_private_key: bool
    ) -> Tuple[bytes, rfc5280.AlgorithmIdentifier]:
        """Return the content of the ``privateKey`` field and the algorithm identifier of ``private_key``."""
        der_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        one_asym_key, _ = try_decode_pyasn1(der_data, rfc5958.OneAsymmetricKey())
        alg_id = one_asym_key["privateKeyAlgorithm"]

        if invalid_private_key and not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ValueError("Invalid private key is only supported for RSA and ECC keys.")
        if invalid_private_key:
            return TradKeyFactory._prepare_invalid_private_key(private_key), alg_id
        return one_asym_key["privateKey"].asOctets(), alg_id

    @staticmethod
    def save_private_key_one_asym_key(
        private_key: TradPrivateKey,
        public_key: Optional[TradPublicKey] = None,
        version: int = 1,
        include_public_key: Optional[bool] = None,
        invalid_private_key: bool = False,
    ) -> bytes:
        """Encode a traditional private key as a ``OneAsymmetricKey``.

        :param private_key: The private key to be converted.
        :param public_key: The corresponding public key, derived from the private key if not given.
        :param version: The version of the ``OneAsymmetricKey``. Defaults to `1`.
        :param include_public_key: If True, include the public key; if False, omit it. If `None` the public key is
            included for every version but `0`.
        :param invalid_private_key: If True, the private key value is invalid, only supported for RSA and ECC keys.
        :return: The DER encoded ``OneAsymmetricKey``.
        """
        private_key_bytes, alg_id = TradKeyFactory._prepare_private_key_bytes(private_key, invalid_private_key)

        public_key_bytes = None
        if not (version == 0 and not include_public_key or include_public_key is False):
            public_key_bytes = TradKeyFactory._get_public_key_bytes(public_key or private_key.public_key())

        one_asym_key = AbstractKeyFactory._prepare_one_asym_key(
            private_key=private_key_bytes, version=version, alg_id=alg_id
        )
        AbstractKeyFactory._set_public_key_in_one_asym_key(one_asym_key, public_key_bytes)
        return encode_to_der(one_asym_key)
