# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Factory for generating traditional (RSA/DSA/EC/EdDSA/DH) private keys."""

from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from pyasn1_alt_modules import rfc5280

from keyutils_py.factories.abstract_factory import AbstractKeyFactory
from keyutils_py.oids import get_curve_instance
from keyutils_py.types import PrivateKey, PublicKey, TradPrivateKey


class TradKeyFactory(AbstractKeyFactory):
    """Factory for traditional (RSA, DSA, ECDSA, EdDSA, X25519, X448, DH) private keys."""

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return the list of traditional algorithm names this factory can generate."""
        return ["rsa", "dsa", "ecdsa", "ecdh", "ec", "ed25519", "ed448", "x25519", "x448", "dh"]

    @staticmethod
    def get_supported_keys() -> List[str]:
        """Return the supported algorithm names (alias of :meth:`supported_algorithms`)."""
        return TradKeyFactory.supported_algorithms()

    @staticmethod
    def generate_key_by_name(algorithm: str, **params) -> TradPrivateKey:  # type: ignore[override]
        """Generate a traditional private key by algorithm name.

        :param algorithm: One of the names returned by :meth:`supported_algorithms`.
        :param params: Algorithm-specific keyword parameters (e.g. ``length``,
            ``curve``) forwarded to :meth:`generate_trad_key`.
        """
        return TradKeyFactory.generate_trad_key(algorithm, **params)

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> PublicKey:
        """Not implemented for traditional keys.

        :param spki: The ``SubjectPublicKeyInfo`` to decode.
        :raises NotImplementedError: Always; use ``cryptography`` directly instead.
        """
        raise NotImplementedError(
            "Traditional public key loading from SPKI is not implemented in this package. "
            "Use the cryptography library directly."
        )

    @staticmethod
    def validate_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> None:
        """Not implemented for traditional keys.

        :param alg_id: Algorithm identifier to validate.
        :raises NotImplementedError: Always.
        """
        raise NotImplementedError("Traditional AlgorithmIdentifier validation is not implemented in this package.")

    @classmethod
    def _load_private_key_from_pkcs8(
        cls,
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> PrivateKey:
        raise NotImplementedError(
            "Traditional PKCS#8 key loading is not implemented in this package. Use the cryptography library directly."
        )

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
    ) -> dh.DHPrivateKey:
        """Generate a Diffie-Hellman private key."""
        if p is None:
            parameters = dh.generate_parameters(generator=g, key_size=length)
        else:
            parameters = dh.DHParameterNumbers(p, g).parameters()

        if secret_scalar is not None:
            if p is None:
                raise ValueError("`p` must be provided when using `secret_scalar`.")
            public_number = pow(g, secret_scalar, p)
            return dh.DHPrivateNumbers(
                x=secret_scalar,
                public_numbers=dh.DHPublicNumbers(public_number, parameters.parameter_numbers()),
            ).private_key()

        return parameters.generate_private_key()

    @staticmethod
    def generate_trad_key(algorithm: str = "rsa", **params) -> TradPrivateKey:
        """Generate a traditional private key.

        Supported: ``rsa``, ``dsa``, ``ecdsa``, ``ecdh``, ``ec``, ``ed25519``,
        ``ed448``, ``x25519``, ``x448``, ``dh``.
        """
        algorithm = algorithm.lower()

        if algorithm == "bad_rsa_key":
            from cryptography.hazmat.bindings._rust import (
                openssl as rust_openssl,  # pylint: disable=import-outside-toplevel
            )

            return rust_openssl.rsa.generate_private_key(65537, 512)  # type: ignore[return-value]

        if algorithm == "rsa":
            length = int(params.get("length") or 2048)
            return rsa.generate_private_key(public_exponent=65537, key_size=length)

        if algorithm == "dsa":
            length = int(params.get("length", 2048))
            return dsa.generate_private_key(key_size=length)

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
