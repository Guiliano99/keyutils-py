# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Facade to create, load and save every supported key type.

It only dispatches: the key type specific work stays in :class:`TradKeyFactory`, :class:`PQKeyFactory`,
:class:`PQStatefulSigFactory` and :class:`HybridKeyFactory`.
"""

import base64
import textwrap
from typing import Dict, List, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1_alt_modules import rfc5280, rfc5958

from keyutils_py.enums import KeySaveType
from keyutils_py.exceptions import BadAlg, InvalidKeyCombination, InvalidKeyData
from keyutils_py.factories.hybrid_factory import HybridKeyFactory
from keyutils_py.factories.pq_factory import PQKeyFactory
from keyutils_py.factories.pq_stfl_factory import PQStatefulSigFactory
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.key_pyasn1_utils import encrypt_private_key_pkcs8_pem
from keyutils_py.oids import (
    PQ_OID_2_NAME,
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
    get_curve_instance,
    id_rsa_kem_spki,
)
from keyutils_py.types import (
    DHKEMPrivateKey,
    HybridPrivateKey,
    HybridPublicKey,
    MLDSAPrivateKey,
    MLKEMPrivateKey,
    PQPrivateKey,
    PQPublicKey,
    PrivateKey,
    PublicKey,
    RSADecapKey,
    RSAEncapKey,
    TradKEMPrivateKey,
    TradPrivateKey,
    WrapperPrivateKey,
    XWingPrivateKey,
)
from keyutils_py.utils import decode_key_structure


class CombinedKeyFactory:
    """Factory for creating, loading and saving all known key types."""

    @staticmethod
    def supported_algorithms() -> List[str]:
        """List all key types that :meth:`generate_key` supports.

        :return: List of supported key types.
        """
        trad_names = TradKeyFactory.supported_algorithms() + ["bad_rsa_key", "rsa-kem"]
        stateful_names = PQStatefulSigFactory.supported_algorithms()
        return (
            trad_names + stateful_names + PQKeyFactory.supported_algorithms() + HybridKeyFactory.supported_algorithms()
        )

    @staticmethod
    def get_stateful_sig_algorithms() -> Dict[str, List[str]]:
        """Get all supported stateful signature algorithms, by family."""
        return PQStatefulSigFactory.get_algorithms_by_family()

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key_from_name(algorithm: str):
        """Generate a key from its full name, including composite and Chempat keys.

        :param algorithm: The name of the key (e.g., "rsa", "ml-kem-768", "composite-kem-ml-kem-768-rsa2048").
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if algorithm.lower().startswith(("composite", "chempat")):
            return HybridKeyFactory.generate_hybrid_key_by_name(algorithm)

        return CombinedKeyFactory.generate_key(algorithm)

    @staticmethod
    def generate_key(algorithm: str, **kwargs):
        """Generate a key based on the provided key type, including composite keys.

        :param algorithm: The type of key to generate (e.g., "rsa", "ml-kem-768", "composite-sig").
        :param kwargs: Additional parameters required by the specific key generator. With `by_name=True` the
            algorithm is a full name, see :meth:`generate_key_from_name`.
        :return: Generated key object.
        :raises ValueError: If the key type is not supported.
        """
        if kwargs.get("by_name", False):
            return CombinedKeyFactory.generate_key_from_name(algorithm)

        if algorithm in TradKeyFactory.supported_algorithms() + ["ecc", "bad_rsa_key"]:
            return TradKeyFactory.generate_trad_key(algorithm, **kwargs)

        if algorithm.startswith("xmss") or algorithm.startswith("hss"):
            return PQStatefulSigFactory.generate_pq_stateful_key(algorithm, **kwargs)

        if algorithm == "rsa-kem":
            trad_key = kwargs.get("trad_key") or TradKeyFactory.generate_trad_key("rsa", **kwargs)
            if not isinstance(trad_key, (RSAPrivateKey, RSADecapKey)):
                raise InvalidKeyCombination("RSA-KEM requires a valid RSA or RSA-KEM private key.")
            return RSADecapKey(trad_key)

        if PQKeyFactory.may_be_pq_alg(algorithm=algorithm):
            return PQKeyFactory.generate_pq_key(algorithm=algorithm)

        if algorithm.lower().startswith(("composite-sig-", "composite-kem-", "chempat-")):
            return HybridKeyFactory.generate_hybrid_key_by_name(algorithm)

        if algorithm in HybridKeyFactory.supported_algorithms():
            if kwargs.get("pq_key") is not None or kwargs.get("trad_key") is not None:
                return HybridKeyFactory.from_keys(
                    algorithm=algorithm, pq_key=kwargs.get("pq_key"), trad_key=kwargs.get("trad_key")
                )
            return HybridKeyFactory.generate_hybrid_key(algorithm=algorithm, **kwargs)

        options = ", ".join(CombinedKeyFactory.supported_algorithms())
        raise ValueError(f"Unsupported key type: {algorithm}. Supported are {options}.")

    @staticmethod
    def _load_trad_private_key_from_seed(name: str, private_data: bytes, curve: Optional[str] = None) -> PrivateKey:
        """Load a traditional private key from its raw private key data."""
        if name in ["x25519", "x448", "ecdh"]:
            return DHKEMPrivateKey.from_private_bytes(name, private_data, curve=curve)._private_key  # pylint: disable=protected-access
        if name == "ed25519":
            return Ed25519PrivateKey.from_private_bytes(private_data)
        if name == "ed448":
            return Ed448PrivateKey.from_private_bytes(private_data)

        return serialization.load_der_private_key(private_data, password=None)  # type: ignore[return-value]

    @staticmethod
    def generate_key_from_seed(algorithm: str, seed: Union[int, bytes], curve: Optional[str] = None) -> PrivateKey:
        """Generate a key from the provided seed or private value for the given algorithm.

        :param algorithm: The type of key to generate (e.g., "rsa", "ecdsa", "x25519").
        :param seed: The seed value for key generation.
        :param curve: The name of the elliptic curve (if applicable).
        :raises BadAlg: If the algorithm is not supported.
        """
        if algorithm in ["ecc", "ecdsa", "ecdh", "ec"] and curve is not None and isinstance(seed, int):
            curve_inst = get_curve_instance(curve_name=curve)
            return ec.derive_private_key(curve=curve_inst, private_value=seed)

        if not isinstance(seed, bytes):
            raise ValueError(f"The seed must be a byte string, for the algorithm: {algorithm}.")

        if algorithm in ["x25519", "x448", "ecdsa", "ecc", "ed448", "ed25519"]:
            return CombinedKeyFactory._load_trad_private_key_from_seed(name=algorithm, private_data=seed)

        if algorithm.startswith("ml-dsa") or algorithm.startswith("slh-dsa") or algorithm.startswith("ml-kem"):
            return PQKeyFactory.from_private_bytes(algorithm, seed)

        if algorithm == "xwing":
            return XWingPrivateKey.from_seed(seed)

        if algorithm == "rsa":
            return serialization.load_der_private_key(seed, password=None)  # type: ignore[return-value]

        if algorithm == "rsa-kem":
            key = serialization.load_der_private_key(seed, password=None)
            if not isinstance(key, RSAPrivateKey):
                raise InvalidKeyData("Invalid RSA KEM key")
            return RSADecapKey(key)

        raise BadAlg(f"Unknown algorithm: {algorithm}")

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @staticmethod
    def load_public_key_from_spki(spki: Union[rfc5280.SubjectPublicKeyInfo, bytes]) -> PublicKey:
        """Load a public key from a ``SubjectPublicKeyInfo``.

        :param spki: The ``SubjectPublicKeyInfo`` structure or its DER encoding.
        :return: The loaded public key.
        """
        if isinstance(spki, bytes):
            spki = decode_key_structure(spki, rfc5280.SubjectPublicKeyInfo(), "SubjectPublicKeyInfo")

        oid = spki["algorithm"]["algorithm"]

        if HybridKeyFactory.is_hybrid_oid(oid):
            return HybridKeyFactory.load_hybrid_public_key_from_spki(spki)

        if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
            return PQStatefulSigFactory.load_public_key_from_spki(spki)

        if oid in PQ_OID_2_NAME or str(oid) in PQ_OID_2_NAME:
            return PQKeyFactory.load_public_key_from_spki(spki=spki)

        if oid == id_rsa_kem_spki:
            return RSAEncapKey.from_spki(spki)

        return TradKeyFactory.load_public_key_from_spki(spki)

    @staticmethod
    def load_private_key_from_one_asym_key(
        data: Union[bytes, rfc5958.OneAsymmetricKey], must_be_version_2: bool = False
    ) -> PrivateKey:
        """Parse a key from a ``OneAsymmetricKey`` structure.

        :param data: The ``OneAsymmetricKey`` structure or its DER encoding.
        :param must_be_version_2: If True, the key must be version 2 (include the public key). Defaults to `False`.
        :return: The loaded private key.
        :raises ValueError: If the key type is invalid.
        :raises BadAlg: If the algorithm is not supported.
        :raises InvalidKeyData: If the key data is invalid.
        :raises InvalidKeyCombination: If the key combination is invalid.
        :raises MismatchingKey: If the private key does not match the public key.
        """
        if isinstance(data, bytes):
            one_asym_key = decode_key_structure(data, rfc5958.OneAsymmetricKey(), "OneAsymmetricKey")
        else:
            one_asym_key = data

        version = int(one_asym_key["version"])
        if version not in [0, 1]:
            raise InvalidKeyData(f"Invalid `OneAsymmetricKey` version: {version}. Supported versions are 0 and 1.")

        if version == 0 and one_asym_key["publicKey"].isValue:
            raise InvalidKeyData("Version 0 keys do not support public key data.")

        oid = one_asym_key["privateKeyAlgorithm"]["algorithm"]

        if oid == id_rsa_kem_spki:
            return RSADecapKey.from_pkcs8(one_asym_key)

        if TradKeyFactory.is_trad_oid(oid):
            return TradKeyFactory.parse_trad_key_from_one_asym_key(one_asym_key, must_be_version_2=must_be_version_2)

        if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
            return PQStatefulSigFactory.load_private_key_from_one_asym_key(one_asym_key)

        if oid in PQ_OID_2_NAME:
            return PQKeyFactory.from_one_asym_key(one_asym_key)

        return HybridKeyFactory.from_one_asym_key(one_asym_key)

    # ------------------------------------------------------------------
    # Saving
    # ------------------------------------------------------------------

    @staticmethod
    def save_private_key_one_asym_key(
        private_key: PrivateKey,
        password: Optional[str] = "11111",
        public_key: Optional[PublicKey] = None,
        version: Optional[int] = None,
        save_type: Union[str, KeySaveType] = "seed",
        include_public_key: Optional[bool] = None,
        encoding: Encoding = Encoding.DER,
        invalid_private_key: bool = False,
        unsafe: bool = False,
    ) -> bytes:
        """Save a private key as a ``OneAsymmetricKey``, as DER or as (optionally password protected) PEM.

        :param private_key: The private key to save.
        :param password: Optional password; encrypts the key as a PKCS#8 ``ENCRYPTED PRIVATE KEY``, PEM only.
        :param public_key: Optional public key to include.
        :param version: The version of the key format. Defaults to `1` for PQ and hybrid keys, else `0`.
        :param save_type: The type of key to save (e.g., "seed", "raw", "seed_and_raw").
        :param include_public_key: If True, include the public key in the output.
        :param encoding: The encoding format (DER or PEM).
        :param invalid_private_key: If True, the private key is invalid, only supported for RSA, ECC and
            ML-KEM and ML-DSA keys. Defaults to `False`.
        :param unsafe: The PQ liboqs keys do not allow to derive the public key from the
            private key, disables the exception call. Defaults to `False`.
        :return: The encoded private key data.
        :raises TypeError: If the key type is not supported.
        """
        if encoding not in [Encoding.DER, Encoding.PEM]:
            raise NotImplementedError(f"Unsupported encoding: {encoding}. Only DER and PEM are supported.")

        if password is not None and encoding == Encoding.DER:
            raise NotImplementedError("Encryption is not supported for DER encoding, only for PEM.")

        if isinstance(private_key, PQPrivateKey):
            if not isinstance(public_key, PQPublicKey) and public_key is not None:
                raise InvalidKeyCombination("The public key must be a PQ public key, if provided.")

            der_data = PQKeyFactory.save_private_key_one_asym_key(
                private_key=private_key,
                public_key=public_key,
                version=1 if version is None else version,
                save_type=save_type,
                include_public_key=include_public_key,
                unsafe=unsafe,
                invalid_key=invalid_private_key,
            )
        elif isinstance(private_key, (TradPrivateKey, TradKEMPrivateKey)):
            der_data = TradKeyFactory.save_private_key_one_asym_key(
                private_key=private_key,
                public_key=public_key,  # type: ignore[arg-type]
                version=0 if version is None else version,
                include_public_key=include_public_key,
                invalid_private_key=invalid_private_key,
            )
        elif isinstance(private_key, HybridPrivateKey):
            if not isinstance(public_key, HybridPublicKey) and public_key is not None:
                raise InvalidKeyCombination("The public key must be a hybrid public key, if provided.")

            der_data = HybridKeyFactory.save_private_key_one_asym_key(
                private_key=private_key,
                public_key=public_key,
                version=1 if version is None else version,
                save_type=save_type,
                include_public_key=include_public_key,
            )
        else:
            raise TypeError(f"Unsupported key type: {type(private_key)}")

        if encoding == Encoding.DER:
            return der_data

        if not isinstance(private_key, WrapperPrivateKey):
            raise TypeError(f"Unsupported key type: {type(private_key)} for PEM encoding.")

        if password is not None:
            return encrypt_private_key_pkcs8_pem(private_key_der=der_data, password=password)

        header_name = private_key._get_header_name()  # pylint: disable=protected-access
        if isinstance(header_name, bytes):
            header_name = header_name.decode("ascii")

        b64_encoded = "\n".join(textwrap.wrap(base64.b64encode(der_data).decode("ascii"), width=64))
        begin, end = f"-----BEGIN {header_name} PRIVATE KEY-----", f"-----END {header_name} PRIVATE KEY-----"
        return f"{begin}\n{b64_encoded}\n{end}\n".encode("ascii")

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_key_export_single(
        private_key: Union[PQPrivateKey, HybridPrivateKey],
        private_key_bytes: bytes,
        key_type: KeySaveType,
    ) -> None:
        """Validate the key export type for a single key.

        :raises InvalidKeyData: If the key data is invalid.
        :raises NotImplementedError: If the key export type is not supported for that key.
        """
        if isinstance(private_key, (MLDSAPrivateKey, MLKEMPrivateKey)):
            PQKeyFactory.validate_ml_key_export_single(private_key, private_key_bytes, key_type)
            return

        if not callable(getattr(private_key, "private_numbers", None)):
            raise NotImplementedError(
                "The private key does not have a `private_numbers` method. Can not determine the key export type."
            )

        if not callable(getattr(private_key, "private_bytes_raw", None)):
            raise NotImplementedError("The private key does not have a `private_bytes_raw` method.")

        if key_type == KeySaveType.SEED:
            if private_key_bytes != private_key.private_numbers():  # type: ignore[union-attr]
                raise InvalidKeyData("The private key bytes do not match the private key data, for type `seed`.")

        elif key_type == KeySaveType.SEED_AND_RAW:
            data = private_key.private_numbers() + private_key.private_bytes_raw()  # type: ignore[union-attr]
            if private_key_bytes != data:
                raise InvalidKeyData(
                    "The private key bytes do not match the private key data, for type `seed_and_raw`."
                )

        elif key_type == KeySaveType.RAW:
            if private_key_bytes != private_key.private_bytes_raw():  # type: ignore[union-attr]
                raise InvalidKeyData("The private key bytes do not match the private key data, for type `raw`.")

        else:
            raise NotImplementedError(f"Unsupported key export type: {key_type.value}.")

    @staticmethod
    def validate_key_export_type(
        private_key: Union[PQPrivateKey, HybridPrivateKey],
        private_key_bytes: bytes,
        key_save_type: Union[str, KeySaveType],
    ) -> None:
        """Validate the key export type for PQ and hybrid keys.

        :param private_key: The private key to validate.
        :param private_key_bytes: The bytes of the private key.
        :param key_save_type: The type of key export (e.g., "seed", "raw", "seed_and_raw").
        :raises InvalidKeyData: If the key data is invalid.
        :raises NotImplementedError: If the key export type is not supported for that key.
        :raises TypeError: If the key type is not supported.
        """
        key_type = KeySaveType.get(key_save_type)

        if isinstance(private_key, PQPrivateKey):
            PQKeyFactory.validate_pq_key_export(private_key, private_key_bytes, key_type)
        elif isinstance(private_key, XWingPrivateKey):
            CombinedKeyFactory._validate_key_export_single(private_key, private_key_bytes, key_type)
        elif isinstance(private_key, HybridPrivateKey):
            CombinedKeyFactory._validate_key_export_single(private_key.pq_key, private_key_bytes, key_type)
        else:
            raise TypeError(f"Unsupported key type: {type(private_key)}. Only PQ keys and hybrid keys are supported.")
