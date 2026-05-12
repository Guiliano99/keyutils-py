# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

# pylint: disable=redefined-builtin

"""Traditional key encapsulation mechanism classes for RSA and DHKEM."""

from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5958, rfc6664, rfc9481

from keyutils_py.exceptions import InvalidKeyData
from keyutils_py.keys.abstract_wrapper_keys import TradKEMPrivateKey, TradKEMPublicKey
from keyutils_py.keys.kem_mechanism import DHKEMRFC9180, ECDHKEM, RSAKem, RSAOaepKem
from keyutils_py.oids import get_curve_instance, id_rsa_kem_spki
from keyutils_py.types import ECDHPrivateKey, ECDHPublicKey
from keyutils_py.utils import encode_to_der, try_decode_pyasn1


class RSAEncapKey(TradKEMPublicKey):
    """Wrapper class to support encaps method using RSA-OAEP or RSA-KEM."""

    _public_key: rsa.RSAPublicKey

    def __init__(self, public_key: Union[rsa.RSAPublicKey, "RSAEncapKey"]):
        """Initialise the wrapper.

        :param public_key: An RSA public key, or another :class:`RSAEncapKey`
            (in which case its underlying key is reused).
        """
        if isinstance(public_key, RSAEncapKey):
            public_key = public_key._public_key
        self._public_key = public_key

    @classmethod
    def from_spki(cls, spki: rfc5280.SubjectPublicKeyInfo) -> "RSAEncapKey":
        """Create an RSAEncapKey from a SubjectPublicKeyInfo."""
        spki["algorithm"]["algorithm"] = rfc9481.rsaEncryption
        der_data = encode_to_der(spki)
        public_key = serialization.load_der_public_key(der_data)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise InvalidKeyData("Invalid RSA public key.")
        return cls(public_key)

    def _export_public_key(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the RSA-KEM SPKI OID."""
        return id_rsa_kem_spki

    def _get_subject_public_key(self) -> bytes:
        return self._export_public_key()

    def encaps(
        self, use_oaep: bool = True, hash_alg: str = "sha256", ss_length: Optional[int] = None
    ) -> Tuple[bytes, bytes]:
        """Encapsulate using RSA-OAEP (default) or RSA-KEM."""
        if use_oaep:
            kem = RSAOaepKem(hash_alg=hash_alg, ss_len=ss_length or 32)
        else:
            kem = RSAKem(ss_length=ss_length)
        return kem.encaps(self._public_key)

    @property
    def name(self) -> str:
        """Return the algorithm family name, ``"rsa-kem"``."""
        return "rsa-kem"

    @property
    def key_size(self) -> int:
        """Return the RSA modulus size in bytes."""
        return self._public_key.key_size // 8

    @property
    def get_trad_name(self) -> str:
        """Return the canonical traditional name (e.g. ``"rsa2048"``)."""
        return f"rsa{self._public_key.key_size}"

    @property
    def public_numbers(self):
        """Return the underlying RSA public numbers."""
        return self._public_key.public_numbers()

    def encode(self) -> bytes:
        """Return the DER-encoded PKCS#1 public key bytes."""
        return self._export_public_key()


class RSADecapKey(TradKEMPrivateKey):
    """Wrapper class to support decaps method using RSA-OAEP or RSA-KEM."""

    _private_key: rsa.RSAPrivateKey

    def __init__(self, private_key: Optional[Union[rsa.RSAPrivateKey, "RSADecapKey"]] = None):
        """Initialise the wrapper.

        :param private_key: An RSA private key, another :class:`RSADecapKey`, or
            ``None`` to generate a fresh 2048-bit RSA key.
        """
        if isinstance(private_key, RSADecapKey):
            private_key = private_key._private_key  # pylint: disable=protected-access
        self._private_key = private_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _get_header_name(self) -> bytes:
        return b"RSA-KEM"

    @classmethod
    def from_pkcs8(cls, data: Union[bytes, rfc5958.OneAsymmetricKey]) -> "RSADecapKey":
        """Create an RSADecapKey from a PKCS8 structure."""
        if isinstance(data, rfc5958.OneAsymmetricKey):
            obj = data
        else:
            obj, rest = try_decode_pyasn1(data, rfc5958.OneAsymmetricKey())
            if rest:
                raise InvalidKeyData("Invalid PKCS8 structure, got a remainder.")

        private_key = serialization.load_der_private_key(obj["privateKey"].asOctets(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise InvalidKeyData("Invalid RSA private key.")

        if obj["publicKey"].isValue:
            public_key = serialization.load_der_public_key(obj["publicKey"].asOctets())
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise InvalidKeyData("Invalid RSA public key.")
            if public_key != private_key.public_key():
                raise InvalidKeyData("Public key does not match the private key.")

        return cls(private_key)

    def _export_private_key(self) -> bytes:
        der_data = self._private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        obj, _ = try_decode_pyasn1(der_data, rfc5958.OneAsymmetricKey())
        return obj["privateKey"].asOctets()

    @classmethod
    def generate_key(cls, key_size: int = 2048) -> "RSADecapKey":
        """Generate a fresh RSA decapsulation key.

        :param key_size: RSA modulus size in bits.
        """
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=key_size))

    @property
    def name(self) -> str:
        """Return the algorithm family name, ``"rsa-kem"``."""
        return "rsa-kem"

    @property
    def key_size(self) -> int:
        """Return the RSA modulus size in bits."""
        return self._private_key.key_size

    def public_key(self) -> RSAEncapKey:
        """Return the matching encapsulation key."""
        return RSAEncapKey(self._private_key.public_key())

    def decaps(
        self, ct: bytes, use_oaep: bool = True, hash_alg: str = "sha256", ss_length: Optional[int] = None
    ) -> bytes:
        """Decapsulate ``ct`` using RSA-OAEP (default) or RSA-KEM.

        :param ct: Ciphertext bytes.
        :param use_oaep: When true, use RSA-OAEP; otherwise RSA-KEM.
        :param hash_alg: Hash and MGF1 hash name for OAEP.
        :param ss_length: Optional KDF3 output length for RSA-KEM.
        """
        if use_oaep:
            kem = RSAOaepKem(hash_alg=hash_alg)
        else:
            kem = RSAKem(ss_length=ss_length)
        return kem.decaps(self._private_key, ct)

    @property
    def get_trad_name(self) -> str:
        """Return the canonical traditional name (e.g. ``"rsa2048"``)."""
        return f"rsa{self._private_key.key_size}"

    @property
    def private_numbers(self):
        """Return the underlying RSA private numbers."""
        return self._private_key.private_numbers()

    def encode(self) -> bytes:
        """Return the bare PKCS#8 ``privateKey`` octets (without the SPKI wrapper)."""
        der_data = self._private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        decoded, _ = try_decode_pyasn1(der_data, rfc5958.OneAsymmetricKey())
        return decoded["privateKey"].asOctets()


class DHKEMPublicKey(TradKEMPublicKey):
    """Wrapper for DHKEM (RFC 9180) or ECDH-KEM public keys."""

    _use_rfc9180: bool
    _public_key: Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey]

    def __eq__(self, other: object) -> bool:
        """Return True if ``other`` wraps an ECDH public key with identical encoded bytes."""
        if isinstance(other, ECDHPublicKey):
            return DHKEMPublicKey(other) == self
        if not isinstance(other, DHKEMPublicKey):
            return False
        return self.encode() == other.encode()

    def get_oid(self) -> univ.ObjectIdentifier:
        """Return the OID matching the wrapped curve (X25519 / X448 / ecPublicKey)."""
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return rfc9481.id_X25519
        if isinstance(self._public_key, x448.X448PublicKey):
            return rfc9481.id_X448
        return rfc6664.id_ecPublicKey

    def _export_public_key(self) -> bytes:
        return self.encode()

    def _get_subject_public_key(self) -> bytes:
        data = self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        obj, _ = try_decode_pyasn1(data, rfc5280.SubjectPublicKeyInfo())
        return obj["subjectPublicKey"].asOctets()

    def __init__(
        self,
        public_key: Union[ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey, "DHKEMPublicKey"],
        use_rfc9180: bool = True,
    ):
        """Initialise the wrapper.

        :param public_key: An ECDH public key, or another :class:`DHKEMPublicKey`.
        :param use_rfc9180: When true, run RFC 9180 DHKEM; otherwise plain ECDH-KEM.
        """
        if isinstance(public_key, DHKEMPublicKey):
            public_key = public_key._public_key  # pylint: disable=protected-access

        self._public_key = public_key  # type: ignore
        self.use_rfc9180 = use_rfc9180  # type: ignore

    def encaps(self, private_key: Optional[Union["DHKEMPrivateKey", "ECDHPrivateKey"]]) -> Tuple[bytes, bytes]:
        """Encapsulate using DHKEM (RFC 9180) or ECDH-KEM."""
        private_key = DHKEMPrivateKey(private_key, self.use_rfc9180)  # type: ignore
        if self.use_rfc9180:
            kem = DHKEMRFC9180(private_key._private_key)  # pylint: disable=protected-access
        else:
            kem = ECDHKEM(private_key._private_key)  # pylint: disable=protected-access
        return kem.encaps(self._public_key)

    @property
    def name(self) -> str:
        """Return the algorithm family name (``dhkem-...`` or ``ecdh-kem-...``)."""
        return "dhkem-" if self.use_rfc9180 else "ecdh-kem-" + self.get_trad_name

    @property
    def key_size(self) -> int:
        """Return the encoded public-key size in bytes."""
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return 32
        if isinstance(self._public_key, x448.X448PublicKey):
            return 56
        return self._public_key.curve.key_size // 8 + 1

    @property
    def ct_length(self) -> int:
        """Return the DHKEM ciphertext length in bytes (equal to ``key_size``)."""
        return self.key_size

    @property
    def get_trad_name(self) -> str:
        """Return the canonical traditional name (e.g. ``ecdh-secp256r1``).

        :raises ValueError: If the wrapped key is of an unsupported type.
        """
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return "ecdh-" + self._public_key.curve.name
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return "x25519"
        if isinstance(self._public_key, x448.X448PublicKey):
            return "x448"
        raise ValueError("Unsupported public key type.")

    @property
    def curve_name(self) -> str:
        """Return the bare curve name of the wrapped key.

        :raises ValueError: If the wrapped key is of an unsupported type.
        """
        if isinstance(self._public_key, x25519.X25519PublicKey):
            return "x25519"
        if isinstance(self._public_key, x448.X448PublicKey):
            return "x448"
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.curve.name
        raise ValueError(f"Unsupported public key type, got: {self._public_key.__class__.__name__}.")

    @property
    def public_numbers(self):
        """Return the underlying EC public numbers.

        :raises ValueError: For X25519 / X448 which expose no public numbers API.
        """
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.public_numbers()
        raise ValueError("Public numbers are not available for this key type.")

    def public_bytes(
        self, encoding: Encoding = Encoding.Raw, format: PublicFormat = PublicFormat.SubjectPublicKeyInfo
    ) -> bytes:
        """Serialise the wrapped public key.

        :param encoding: Output encoding (defaults to raw bytes).
        :param format: Output format (defaults to ``SubjectPublicKeyInfo``).
        """
        return self._public_key.public_bytes(encoding, format)

    def encode(self) -> bytes:
        """Return the on-the-wire encoded public key (X9.62 uncompressed for EC, raw for X25519/X448)."""
        if isinstance(self._public_key, ec.EllipticCurvePublicKey):
            return self._public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return self._public_key.public_bytes_raw()

    @classmethod
    def _ec_key_from_der(cls, data: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePublicKey:
        return ec.EllipticCurvePublicKey.from_encoded_point(curve=curve, data=data)

    @classmethod
    def from_public_bytes(cls, name: str, data: bytes) -> "DHKEMPublicKey":
        """Load the public key from raw bytes."""
        trad_key = None
        try:
            if name not in ["x25519", "x448"]:
                curve = name.replace("ecdh-", "", 1)
                curve_inst = get_curve_instance(curve)
                trad_key = cls._ec_key_from_der(data, curve_inst)
            elif name == "x25519":
                trad_key = x25519.X25519PublicKey.from_public_bytes(data)
            elif name == "x448":
                trad_key = x448.X448PublicKey.from_public_bytes(data)
        except ValueError as e:
            raise InvalidKeyData(f"Invalid public key data for {name}: {e}") from e

        if trad_key is not None:
            return cls(trad_key)

        raise ValueError(f"Unsupported key type: {name}. Expected one of 'x25519', 'x448' or 'ecdh-*'.")


class DHKEMPrivateKey(TradKEMPrivateKey):
    """Wrapper for DHKEM (RFC 9180) or ECDH-KEM private keys."""

    _private_key: Union[ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey]

    def __init__(
        self,
        private_key: Union["DHKEMPrivateKey", ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey],
        use_rfc9180: bool = True,
    ):
        """Initialise the wrapper.

        :param private_key: An ECDH private key, or another :class:`DHKEMPrivateKey`.
        :param use_rfc9180: When true, run RFC 9180 DHKEM; otherwise plain ECDH-KEM.
        """
        if isinstance(private_key, DHKEMPrivateKey):
            private_key = private_key._private_key

        self._private_key = private_key
        self.use_rfc9180 = use_rfc9180

    @classmethod
    def generate_key(cls, curve: str = "secp256r1", use_rfc9180: bool = True) -> "DHKEMPrivateKey":
        """Generate a fresh DHKEM private key on ``curve``.

        :param curve: Curve name (e.g. ``secp256r1``, ``x25519``, ``x448``).
        :param use_rfc9180: When true, run RFC 9180 DHKEM; otherwise plain ECDH-KEM.
        """
        if curve.lower() == "x25519":
            return cls(x25519.X25519PrivateKey.generate(), use_rfc9180)
        if curve.lower() == "x448":
            return cls(x448.X448PrivateKey.generate(), use_rfc9180)
        curve_obj = get_curve_instance(curve)
        return cls(ec.generate_private_key(curve_obj), use_rfc9180)

    @property
    def name(self) -> str:
        """Return the algorithm family name (``dhkem-rfc9180`` or ``ecdh-kem``)."""
        return "dhkem-rfc9180" if self.use_rfc9180 else "ecdh-kem"

    @property
    def key_size(self) -> int:
        """Return the underlying public-key size in bytes."""
        return self.public_key().key_size

    @property
    def ct_length(self) -> int:
        """Return the DHKEM ciphertext length in bytes."""
        return self.public_key().ct_length

    @property
    def get_trad_name(self) -> str:
        """Return the canonical traditional name (delegated to the public key)."""
        return self.public_key().get_trad_name

    @property
    def private_numbers(self):
        """Return the underlying EC private numbers.

        :raises ValueError: For X25519 / X448 which expose no private numbers API.
        """
        if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            return self._private_key.private_numbers()
        raise ValueError("Private numbers are not available for this key type.")

    def public_key(self) -> DHKEMPublicKey:
        """Return the matching DHKEM public key."""
        return DHKEMPublicKey(self._private_key.public_key(), use_rfc9180=self.use_rfc9180)

    def decaps(self, ct: bytes) -> bytes:
        """Decapsulate a DHKEM ciphertext.

        :param ct: Encoded ephemeral public key from the sender.
        """
        kem = (
            DHKEMRFC9180(private_key=self._private_key)
            if self.use_rfc9180
            else (ECDHKEM(private_key=self._private_key))
        )
        return kem.decaps(ct)

    def encode(self) -> bytes:
        """Return the raw private-key bytes (big-endian scalar for EC, raw bytes for X25519/X448)."""
        if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            private_numbers = self._private_key.private_numbers()
            return private_numbers.private_value.to_bytes(self._private_key.key_size, byteorder="big")
        return self._private_key.private_bytes_raw()

    @staticmethod
    def _ec_key_from_der(der_data: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
        private_value = int.from_bytes(der_data, byteorder="big")
        return ec.derive_private_key(private_value, curve)

    @classmethod
    def from_private_bytes(cls, name: str, data: bytes, curve: Optional[str] = None) -> "DHKEMPrivateKey":
        """Load the private key from raw bytes."""
        if name not in ["x25519", "x448"] and curve is None:
            curve = name.replace("ecdh-", "", 1)

        if name == "x25519":
            trad_key = x25519.X25519PrivateKey.from_private_bytes(data)
        elif name == "x448":
            trad_key = x448.X448PrivateKey.from_private_bytes(data)
        else:
            if curve is None:
                raise ValueError("Curve name must be provided for ECDH keys.")
            curve_inst = get_curve_instance(curve)
            trad_key = cls._ec_key_from_der(data, curve_inst)

        return cls(trad_key)

    def private_bytes(
        self,
        encoding: Encoding = Encoding.PEM,
        format: PrivateFormat = PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ) -> bytes:
        """Serialise the wrapped private key.

        :param encoding: Output encoding (defaults to PEM).
        :param format: Output format (defaults to PKCS#8).
        :param encryption_algorithm: Optional encryption (defaults to none).
        """
        return self._private_key.private_bytes(encoding, format, encryption_algorithm)

    def _export_private_key(self) -> bytes:
        if isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            return self._private_key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
        return self._private_key.private_bytes_raw()

    @property
    def curve_name(self) -> str:
        """Return the bare curve name (delegated to the public key)."""
        return self.public_key().curve_name
