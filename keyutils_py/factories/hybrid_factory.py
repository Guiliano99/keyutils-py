# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Factory for hybrid (composite / chempat / xwing) keys."""

from typing import List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3370, rfc5280, rfc5958

from keyutils_py.enums import KeySaveType
from keyutils_py.exceptions import (
    BadAlg,
    BadSigAlgIDParams,
    InvalidKeyCombination,
    InvalidKeyData,
    MismatchingKey,
)
from keyutils_py.factories.abstract_factory import AbstractKeyFactory
from keyutils_py.factories.pq_factory import PQKeyFactory
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.abstract_pq import PQKEMPrivateKey, PQKEMPublicKey
from keyutils_py.keys.abstract_wrapper_keys import HybridPrivateKey, HybridPublicKey, PQPrivateKey, TradKEMPrivateKey
from keyutils_py.keys.chempat_key import ChempatPrivateKey, ChempatPublicKey
from keyutils_py.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey
from keyutils_py.keys.composite_sig import CompositeSigPrivateKey, CompositeSigPublicKey
from keyutils_py.keys.serialize_utils import prepare_ec_private_key
from keyutils_py.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey
from keyutils_py.keys.trad_kem_keys import DHKEMPrivateKey, RSADecapKey, RSAEncapKey
from keyutils_py.keys.xwing import XWingPrivateKey, XWingPublicKey
from keyutils_py.oids import (
    ALL_COMPOSITE_SIG_COMBINATIONS,
    CHEMPAT_OID_2_NAME,
    COMPOSITE_KEM_OID_2_NAME,
    COMPOSITE_SIG_OID_TO_NAME,
    CURVE_NAMES_TO_INSTANCES,
    KEY_CLASS_MAPPING,
    PQ_NAME_2_OID,
    XWING_OID_STR,
    may_return_oid_to_name,
)
from keyutils_py.types import ECDHPrivateKey, ECPrivateKey, ECSignKey, Strint
from keyutils_py.utils import encode_to_der, try_decode_pyasn1

TradPartPrivateKey = Union[ECSignKey, ECDHPrivateKey, RSAPrivateKey, TradKEMPrivateKey]


class HybridKeyFactory(AbstractKeyFactory):
    """Factory for hybrid (composite / chempat / xwing) keys."""

    _CHEMPAT_COMBINATIONS: List[dict] = [
        {"pq_name": "sntrup761", "trad_name": "x25519"},
        {"pq_name": "mceliece-348864", "trad_name": "x25519"},
        {"pq_name": "mceliece-460896", "trad_name": "x25519"},
        {"pq_name": "mceliece-6688128", "trad_name": "x25519"},
        {"pq_name": "mceliece-6960119", "trad_name": "x25519"},
        {"pq_name": "mceliece-8192128", "trad_name": "x25519"},
        {"pq_name": "mceliece-348864", "trad_name": "x448"},
        {"pq_name": "mceliece-460896", "trad_name": "x448"},
        {"pq_name": "mceliece-6688128", "trad_name": "x448"},
        {"pq_name": "mceliece-6960119", "trad_name": "x448"},
        {"pq_name": "mceliece-8192128", "trad_name": "x448"},
        {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        {"pq_name": "ml-kem-1024", "trad_name": "x448"},
        {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp256r1"},
        {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp384r1"},
        {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "brainpoolP256r1"},
        {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "brainpoolP384r1"},
        {"pq_name": "frodokem-976-aes", "trad_name": "x25519"},
        {"pq_name": "frodokem-976-shake", "trad_name": "x25519"},
        {"pq_name": "frodokem-640-aes", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
        {"pq_name": "frodokem-640-shake", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
        {"pq_name": "frodokem-976-aes", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
        {"pq_name": "frodokem-976-shake", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
        {"pq_name": "frodokem-1344-aes", "trad_name": "ecdh", "curve": "brainpoolp512r1"},
        {"pq_name": "frodokem-1344-shake", "trad_name": "ecdh", "curve": "brainpoolp512r1"},
        {"pq_name": "frodokem-1344-aes", "trad_name": "x448"},
        {"pq_name": "frodokem-1344-shake", "trad_name": "x448"},
    ]

    _COMPOSITE_KEM_COMBINATIONS: List[dict] = [
        {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp256r1"},
        {"pq_name": "ml-kem-1024", "trad_name": "rsa", "length": "3072"},
        {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp512r1"},
        {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": "2048"},
        {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": "3072"},
        {"pq_name": "ml-kem-768", "trad_name": "rsa", "length": "4096"},
        {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "secp384r1"},
        {"pq_name": "ml-kem-768", "trad_name": "ecdh", "curve": "brainpoolp256r1"},
        {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "secp384r1"},
        {"pq_name": "ml-kem-1024", "trad_name": "ecdh", "curve": "brainpoolp384r1"},
        {"pq_name": "ml-kem-1024", "trad_name": "x448"},
    ]

    hybrid_mappings = {
        "sig": ALL_COMPOSITE_SIG_COMBINATIONS,
        "kem": _COMPOSITE_KEM_COMBINATIONS,
        "chempat": _CHEMPAT_COMBINATIONS,
        "xwing": [],
    }

    default_comb = {
        "sig": {"pq_name": "ml-dsa-44", "trad_name": "rsa", "length": "2048"},
        "kem": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
        "chempat": {"pq_name": "ml-kem-768", "trad_name": "x25519"},
    }

    @staticmethod
    def _get_trad_key_from_pq_key(
        trad_key, allowed_key: List[str], comb_name: str
    ) -> Tuple[str, Optional[str], Optional[str]]:
        trad_name = KEY_CLASS_MAPPING[trad_key.__class__.__name__]
        if trad_name == "ecdsa" and "ecdh" in allowed_key:
            trad_name = "ecdh"
        if trad_name not in allowed_key:
            raise ValueError(f"Traditional key '{trad_name}' not allowed for '{comb_name}'.")

        length = curve = None
        if trad_name == "rsa":
            value = trad_key.key_size
            predefined_values = [2048, 3072, 4096]
            length = str(min(predefined_values, key=lambda x: abs(x - value)))
        elif trad_name in ["ecdsa", "ecdh"]:
            curve = trad_key.curve.name

        return trad_name, length, curve

    @staticmethod
    def _get_valid_hybrid_combination(
        combinations: List[dict],
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ) -> dict:
        if not pq_name and not trad_name and not length and not curve:
            return combinations[0]

        if length:
            length = str(length)
        if curve:
            curve = curve.lower()

        for entry in combinations:
            if pq_name and entry["pq_name"] != pq_name:
                continue
            if trad_name and entry["trad_name"] != trad_name:
                continue
            if length and entry.get("length") != length:
                continue
            if curve and entry.get("curve", "").lower() != curve:
                continue
            return entry

        raise ValueError(
            f"No valid {algorithm} combination found for pq_name={pq_name}, "
            f"trad_name={trad_name}, length={length}, curve={curve}"
        )

    @staticmethod
    def _parse_private_keys(hybrid_type: str, pq_key, trad_key) -> HybridPrivateKey:
        if hybrid_type == "chempat":
            return ChempatPrivateKey.parse_keys(pq_key, trad_key)
        hybrid_type = hybrid_type.replace("composite-", "")
        key_class_mappings = {
            "kem": CompositeKEMPrivateKey,
            "sig": CompositeSigPrivateKey,
        }
        return key_class_mappings[hybrid_type](pq_key, trad_key)

    @staticmethod
    def _get_pq_and_trad_name(hybrid_name: str) -> Tuple[str, str]:
        alg = hybrid_name.lower()
        if alg.startswith("chempat-"):
            prefix = "chempat-"
        elif alg.startswith("composite-sig-"):
            prefix = "composite-sig-"
        elif alg.startswith("composite-kem-"):
            prefix = "composite-kem-"
        else:
            raise NotImplementedError(f"Unsupported hybrid algorithm name format: {hybrid_name}")

        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=alg)
        trad_name = alg.replace(prefix, "", 1).replace(pq_name + "-", "", 1)
        return pq_name, trad_name

    @staticmethod
    def generate_hybrid_key(
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
        trad_key: Optional[TradPartPrivateKey] = None,
        pq_key: Optional[PQPrivateKey] = None,
    ) -> HybridPrivateKey:
        """Generate a hybrid private key."""
        if pq_key is not None or trad_key is not None:
            return HybridKeyFactory.from_keys(algorithm, pq_key, trad_key)

        if algorithm == "xwing":
            return XWingPrivateKey(pq_key=pq_key, trad_key=trad_key)

        if all(x is None for x in [pq_name, trad_name, length, curve]):
            hybrid = algorithm.replace("composite-", "")
            default_entry = HybridKeyFactory.default_comb[hybrid]
            return HybridKeyFactory.generate_hybrid_key(algorithm, **default_entry)  # type: ignore

        return HybridKeyFactory._generate_default_hybrid_key(
            algorithm=algorithm,
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

    @staticmethod
    def from_keys(algorithm: str, pq_key=None, trad_key=None) -> HybridPrivateKey:
        """Create a hybrid key from existing PQ and traditional keys."""
        if pq_key is None and trad_key is None:
            raise ValueError("Either pq_key or trad_key must be provided.")

        if algorithm == "xwing":
            if pq_key is None:
                pq_key = PQKeyFactory.generate_pq_key("ml-kem-768")
            if trad_key is None:
                trad_key = TradKeyFactory.generate_trad_key("x25519")
            return XWingPrivateKey(pq_key=pq_key, trad_key=trad_key)  # type: ignore

        algo = algorithm.lower()
        pq_name = trad_name = length = curve = None
        if pq_key is None:
            allowed_keys = {
                "chempat": ["ecdh", "x25519", "x448"],
                "composite-kem": ["rsa", "ecdh", "x25519", "x448"],
                "composite-sig": ["rsa", "ecdsa", "ed25519", "ed448"],
                "xwing": ["x25519"],
            }.get(algo, [])

            trad_name, length, curve = HybridKeyFactory._get_trad_key_from_pq_key(
                trad_key, allowed_key=allowed_keys, comb_name=algorithm
            )

        if pq_key is not None:
            pq_name = pq_key.name

        hybrid_key = HybridKeyFactory._generate_default_hybrid_key(
            algorithm=algorithm,
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

        if trad_key is None:
            trad_key = hybrid_key.trad_key
        if pq_key is None:
            pq_key = hybrid_key.pq_key

        return HybridKeyFactory._parse_private_keys(hybrid_type=algorithm, pq_key=pq_key, trad_key=trad_key)

    @staticmethod
    def supported_algorithms() -> List[str]:
        """Return the hybrid family names this factory can generate."""
        return ["xwing", "composite-sig", "composite-kem", "chempat"]

    @staticmethod
    def _generate_default_hybrid_key(
        algorithm: str,
        pq_name: Optional[str] = None,
        trad_name: Optional[str] = None,
        length: Optional[Strint] = None,
        curve: Optional[str] = None,
    ) -> HybridPrivateKey:
        hybrid_type = algorithm.lower().replace("composite-", "")

        if hybrid_type not in HybridKeyFactory.hybrid_mappings:
            raise InvalidKeyCombination(f"Unsupported hybrid type: {algorithm}")

        valid_combinations = HybridKeyFactory.hybrid_mappings[hybrid_type]

        if hybrid_type == "kem" and pq_name in ["frodokem-aes-640", "frodokem-shake-640"]:
            raise InvalidKeyCombination("FrodoKEM-640 is not supported (the claimed NIST level is only `1`).")

        params = HybridKeyFactory._get_valid_hybrid_combination(
            valid_combinations,
            algorithm=algorithm,
            pq_name=pq_name,
            trad_name=trad_name,
            length=length,
            curve=curve,
        )

        pq_key = PQKeyFactory.generate_pq_key(params["pq_name"])
        trad_key = TradKeyFactory.generate_trad_key(
            algorithm=params["trad_name"],
            length=params.get("length"),
            curve=params.get("curve"),
        )
        return HybridKeyFactory._parse_private_keys(algorithm, pq_key, trad_key)

    @staticmethod
    def _load_pq_key(name: str, data: bytes) -> PQPrivateKey:
        pq_one_asym_key = rfc5958.OneAsymmetricKey()
        pq_one_asym_key["version"] = 0
        pq_one_asym_key["privateKeyAlgorithm"]["algorithm"] = PQ_NAME_2_OID[name]
        pq_one_asym_key["privateKey"] = data
        return PQKeyFactory.from_one_asym_key(pq_one_asym_key)

    @staticmethod
    def _load_chempat_private_key(
        private_bytes: bytes,
        oid: univ.ObjectIdentifier,
    ) -> ChempatPrivateKey:
        name = CHEMPAT_OID_2_NAME[oid]
        name = name.lower()
        tmp_name = name.replace("chempat-", "", 1)
        _length = int.from_bytes(private_bytes[:4], "little")

        pq_private_bytes = private_bytes[4 : 4 + _length]
        pq_name = PQKeyFactory.get_pq_alg_name(tmp_name)
        try:
            pq_key = HybridKeyFactory._load_pq_key(name=pq_name, data=pq_private_bytes)
        except InvalidKeyData as e:
            raise InvalidKeyData(f"Invalid Chempat pq private key data for {tmp_name}: {e}") from e

        trad_private_bytes = private_bytes[4 + _length :]
        tmp_name = tmp_name.replace(f"{pq_name}-", "", 1)
        try:
            trad_key = DHKEMPrivateKey.from_private_bytes(data=trad_private_bytes, name=tmp_name)
        except ValueError as e:
            raise InvalidKeyData(f"Invalid Chempat traditional private key data for {tmp_name}: {e}") from e
        return ChempatPrivateKey.parse_keys(pq_key, trad_key)

    @staticmethod
    def _load_trad_raw_key(name: str, trad_key_bytes: bytes):
        """Load an ed448/ed25519/x25519/x448 raw key."""
        if name == "ed448":
            return ed448.Ed448PrivateKey.from_private_bytes(trad_key_bytes)
        if name == "ed25519":
            return ed25519.Ed25519PrivateKey.from_private_bytes(trad_key_bytes)
        if name == "x25519":
            return x25519.X25519PrivateKey.from_private_bytes(trad_key_bytes)
        if name == "x448":
            return x448.X448PrivateKey.from_private_bytes(trad_key_bytes)
        raise ValueError(f"Unsupported raw traditional key type: {name!r}")

    @staticmethod
    def _try_load_ec_private_from_der(trad_key_bytes: bytes, curve_name: Optional[str] = None):
        """Load an EC private key from DER-encoded ECPrivateKey."""
        key = load_der_private_key(trad_key_bytes, password=None)
        if not isinstance(key, EllipticCurvePrivateKey):
            raise InvalidKeyData(f"Expected EC private key, got {type(key)}")
        if curve_name and key.curve.name.lower() != curve_name.lower():
            raise InvalidKeyData(f"Expected EC curve {curve_name!r}, got {key.curve.name.lower()!r}")
        return key

    @staticmethod
    def _load_trad_composite_private_key(trad_name: str, trad_key_bytes: bytes, prefix: str = "Sig"):
        """Load a traditional key for composite sig/kem from raw/DER bytes."""
        try:
            if trad_name.startswith("ecdsa") or trad_name.startswith("ecdh"):
                curve_name = trad_name.replace("ecdsa-", "").replace("ecdh-", "")
                return HybridKeyFactory._try_load_ec_private_from_der(trad_key_bytes, curve_name)
            if trad_name in ["ed448", "ed25519", "x25519", "x448"]:
                return HybridKeyFactory._load_trad_raw_key(trad_name, trad_key_bytes)
            if trad_name.startswith("rsa"):
                trad_key = load_der_private_key(trad_key_bytes, password=None)
                if not isinstance(trad_key, RSAPrivateKey):
                    raise InvalidKeyData(f"Expected RSA private key, got {type(trad_key)}")
                return trad_key
            raise ValueError(f"Unsupported trad key type for composite {prefix}: {trad_name!r}")
        except (ValueError, InvalidKeyData):
            raise
        except Exception as exc:
            raise InvalidKeyData(f"Failed to load composite {prefix} traditional key ({trad_name!r}): {exc}") from exc

    @staticmethod
    def _load_composite_sig_from_private_bytes(algorithm: str, private_bytes: bytes) -> CompositeSigPrivateKey:
        """Load a CompositeSigPrivateKey from serialised private bytes."""
        pq_name, trad_name = HybridKeyFactory._get_pq_and_trad_name(algorithm)
        seed_size = 32
        pq_bytes, trad_bytes = private_bytes[:seed_size], private_bytes[seed_size:]
        pq_key = MLDSAPrivateKey.from_private_bytes(pq_bytes, name=pq_name)
        trad_key = HybridKeyFactory._load_trad_composite_private_key(trad_name, trad_bytes, prefix="Sig")
        return CompositeSigPrivateKey(pq_key=pq_key, trad_key=trad_key)  # type: ignore

    @staticmethod
    def _load_composite_kem_from_private_bytes(algorithm: str, private_bytes: bytes) -> CompositeKEMPrivateKey:
        """Load a CompositeKEMPrivateKey from serialised private bytes."""
        pq_name, trad_name = HybridKeyFactory._get_pq_and_trad_name(algorithm)
        tmp_pq_key = PQKeyFactory.generate_pq_key(pq_name)
        if hasattr(tmp_pq_key, "private_numbers"):
            seed_size = len(tmp_pq_key.private_numbers())  # type: ignore[attr-defined]
        else:
            seed_size = len(tmp_pq_key.private_bytes_raw())  # type: ignore[attr-defined]

        pq_data, trad_bytes = private_bytes[:seed_size], private_bytes[seed_size:]
        pq_key = tmp_pq_key.from_private_bytes(pq_data, name=pq_name)  # type: ignore[attr-defined]
        trad_key = HybridKeyFactory._load_trad_composite_private_key(trad_name, trad_bytes, prefix="KEM")

        if not isinstance(trad_key, RSAPrivateKey):
            trad_key = DHKEMPrivateKey(private_key=trad_key, use_rfc9180=False)  # type: ignore[arg-type]
        if not isinstance(pq_key, PQKEMPrivateKey):
            raise InvalidKeyCombination("Expected PQ KEM private key for composite KEM.")

        composite_key = CompositeKEMPrivateKey(pq_key=pq_key, trad_key=trad_key)
        composite_key.get_oid()  # validates the combination
        return composite_key

    @staticmethod
    def from_one_asym_key(one_asym_key: Union[rfc5958.OneAsymmetricKey, bytes]) -> HybridPrivateKey:
        """Load a hybrid private key from a OneAsymmetricKey structure."""
        if isinstance(one_asym_key, bytes):
            one_asym_key = try_decode_pyasn1(one_asym_key, rfc5958.OneAsymmetricKey())[0]

        parsed_key: rfc5958.OneAsymmetricKey = one_asym_key  # type: ignore[assignment]
        oid = parsed_key["privateKeyAlgorithm"]["algorithm"]
        alg_oid = str(oid)

        private_bytes = parsed_key["privateKey"].asOctets()
        public_bytes = parsed_key["publicKey"].asOctets() if parsed_key["publicKey"].isValue else None

        if alg_oid == XWING_OID_STR:
            private_key = XWingPrivateKey.from_private_bytes(private_bytes)
            if public_bytes is not None:
                pub = private_key.public_key().from_public_bytes(public_bytes)
                if pub.public_bytes_raw() != private_key.public_key().public_bytes_raw():
                    raise MismatchingKey("Public key does not match the private key.")
            return private_key

        if oid in COMPOSITE_SIG_OID_TO_NAME:
            name = COMPOSITE_SIG_OID_TO_NAME[oid]
            private_key = HybridKeyFactory._load_composite_sig_from_private_bytes(name, private_bytes)
            if public_bytes is not None:
                spki = rfc5280.SubjectPublicKeyInfo()
                spki["algorithm"]["algorithm"] = oid
                spki["subjectPublicKey"] = univ.BitString.fromOctetString(public_bytes)
                pub_key = HybridKeyFactory._load_composite_sig_from_spki(oid, public_bytes)
                if private_key.public_key() != pub_key:
                    raise MismatchingKey("Composite-sig public key does not match the private key.")
            return private_key

        if oid in COMPOSITE_KEM_OID_2_NAME:
            name = COMPOSITE_KEM_OID_2_NAME[oid]
            private_key = HybridKeyFactory._load_composite_kem_from_private_bytes(name, private_bytes)
            if public_bytes is not None:
                pub_key = HybridKeyFactory._load_composite_kem_from_spki(oid, public_bytes)
                if private_key.public_key() != pub_key:
                    raise MismatchingKey("Composite-kem public key does not match the private key.")
            return private_key

        if oid in CHEMPAT_OID_2_NAME:
            name = CHEMPAT_OID_2_NAME[oid]
            private_key = HybridKeyFactory._load_chempat_private_key(
                private_bytes=private_bytes,
                oid=oid,
            )
            if public_bytes is not None:
                public_key = ChempatPublicKey.from_public_bytes(data=public_bytes, name=name)
                private_key.pq_key._public_key_bytes = public_key.pq_key._public_key_bytes  # pylint: disable=protected-access
                if public_key.public_bytes_raw() != private_key.public_key().public_bytes_raw():
                    raise MismatchingKey("Public key does not match the private key.")
            return private_key

        _name = may_return_oid_to_name(oid)
        raise BadAlg(f"Cannot load the private key. Unsupported algorithm: {_name}")

    @staticmethod
    def _may_get_pub_key(
        private_key: HybridPrivateKey,
        public_key: Optional[HybridPublicKey],
        include_pub_key: Optional[bool] = True,
        version: int = 1,
    ) -> Optional[bytes]:
        if include_pub_key or version >= 1:
            public_key = public_key or private_key.public_key()
            return AbstractKeyFactory._export_public_key(public_key)
        return None

    @staticmethod
    def _get_private_trad_key_der_data(
        private_key: Union[TradKEMPrivateKey, TradPartPrivateKey],
    ) -> bytes:
        if isinstance(private_key, RSAPrivateKey):
            private_key = RSADecapKey(private_key)
        elif isinstance(private_key, EllipticCurvePrivateKey):
            return encode_to_der(prepare_ec_private_key(ec_key=private_key))

        if isinstance(private_key, ECPrivateKey):
            private_key = DHKEMPrivateKey(private_key)  # type: ignore[arg-type]

        return private_key.encode()

    @staticmethod
    def _save_keys_with_support_seed(
        private_key: HybridPrivateKey,
        save_type: Union[str, KeySaveType] = "seed",
        unsafe: bool = False,
    ) -> bytes:
        key_type = KeySaveType.get(save_type)

        pq_key_bytes = PQKeyFactory.save_keys_with_support_seed(
            private_key=private_key.pq_key,
            key_type=key_type,
        )

        if isinstance(private_key, (CompositeKEMPrivateKey, CompositeSigPrivateKey)):
            if key_type == KeySaveType.SEED and hasattr(private_key.pq_key, "private_numbers"):
                pq_key_bytes = private_key.pq_key.private_numbers()  # type: ignore[union-attr]
            elif key_type == KeySaveType.SEED_AND_RAW and hasattr(private_key.pq_key, "private_numbers"):
                pq_key_bytes = private_key.pq_key.private_numbers() + private_key.private_bytes_raw()  # type: ignore[union-attr]
            else:
                pq_key_bytes = private_key.pq_key.private_bytes_raw()
            trad_key_bytes = private_key._export_trad_private_key()  # pylint: disable=protected-access
            return pq_key_bytes + trad_key_bytes

        if isinstance(private_key, XWingPrivateKey):
            if key_type == KeySaveType.SEED:
                return private_key.private_numbers()
            if key_type == KeySaveType.RAW:
                return private_key.private_bytes_raw()
            return private_key.private_numbers() + private_key.private_bytes_raw()

        if isinstance(private_key, ChempatPrivateKey):
            _length = len(pq_key_bytes)
            return _length.to_bytes(4, "little") + pq_key_bytes + private_key.trad_key.encode()

        raise ValueError(
            f"Unsupported private key type: {type(private_key)}. "
            f"Supported types are: {HybridKeyFactory.hybrid_mappings}"
        )

    @staticmethod
    def save_private_key_one_asym_key(
        private_key: HybridPrivateKey,
        public_key: Optional[HybridPublicKey] = None,
        version: int = 1,
        save_type: Union[str, KeySaveType] = "seed",
        include_public_key: Optional[bool] = None,
        unsafe: bool = False,
    ) -> bytes:
        """Convert a hybrid private key to a DER-encoded OneAsymmetricKey."""
        key_type = KeySaveType.get(save_type)
        one_asym_key = rfc5958.OneAsymmetricKey()
        one_asym_key["version"] = version

        oid = private_key.get_oid()
        one_asym_key["privateKeyAlgorithm"]["algorithm"] = oid
        one_asym_key["privateKey"] = HybridKeyFactory._save_keys_with_support_seed(
            private_key=private_key, save_type=key_type, unsafe=unsafe
        )
        public_key_bytes = HybridKeyFactory._may_get_pub_key(
            private_key=private_key, public_key=public_key, include_pub_key=include_public_key, version=version
        )

        AbstractKeyFactory._set_public_key_in_one_asym_key(one_asym_key, public_key_bytes)

        return encode_to_der(one_asym_key)

    # ------------------------------------------------------------------
    # Public-key loading from SubjectPublicKeyInfo
    # ------------------------------------------------------------------

    @staticmethod
    def _load_composite_sig_from_spki(oid: univ.ObjectIdentifier, public_key_bytes: bytes) -> CompositeSigPublicKey:
        """Load a CompositeSigPublicKey from raw public-key bytes + OID."""
        orig_name = COMPOSITE_SIG_OID_TO_NAME[oid]
        pq_name, trad_name = HybridKeyFactory._get_pq_and_trad_name(orig_name)
        pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key_bytes, allow_rest=True)

        if trad_name == "ed448":
            trad_key = ed448.Ed448PublicKey.from_public_bytes(rest)
        elif trad_name == "ed25519":
            trad_key = ed25519.Ed25519PublicKey.from_public_bytes(rest)
        elif trad_name.startswith("ecdsa-"):
            trad_key = ec.EllipticCurvePublicKey.from_encoded_point(
                CURVE_NAMES_TO_INSTANCES[trad_name.replace("ecdsa-", "")],
                rest,
            )
        else:
            _, rest_dec = try_decode_pyasn1(rest, rfc3370.RSAPublicKey())
            if rest_dec:
                raise InvalidKeyData(f"Unexpected composite-sig traditional key data for {orig_name}")
            trad_key = load_der_public_key(rest)

        if not isinstance(pq_key, MLDSAPublicKey):
            raise InvalidKeyData(f"Expected ML-DSA public key for {orig_name}, got: {type(pq_key)}")

        return CompositeSigPublicKey(pq_key=pq_key, trad_key=trad_key)  # type: ignore

    @staticmethod
    def _load_composite_kem_from_spki(oid: univ.ObjectIdentifier, public_key_bytes: bytes) -> CompositeKEMPublicKey:
        """Load a CompositeKEMPublicKey from raw public-key bytes + OID."""
        orig_name = COMPOSITE_KEM_OID_2_NAME[oid]
        pq_name, trad_name = HybridKeyFactory._get_pq_and_trad_name(orig_name)
        pq_key, rest = PQKeyFactory.from_public_bytes(pq_name, public_key_bytes, allow_rest=True)

        if trad_name == "x25519":
            trad_key = x25519.X25519PublicKey.from_public_bytes(rest)
        elif trad_name == "x448":
            trad_key = x448.X448PublicKey.from_public_bytes(rest)
        elif trad_name.startswith("ecdh-"):
            curve_name = trad_name.replace("ecdh-", "")
            curve = CURVE_NAMES_TO_INSTANCES.get(curve_name)
            if curve is None:
                raise InvalidKeyCombination(f"Unsupported ECDH curve: {curve_name}")
            trad_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, rest)
        elif trad_name.startswith("rsa"):
            trad_key = load_der_public_key(rest)
            if not isinstance(trad_key, RSAPublicKey):
                raise InvalidKeyCombination(f"Expected RSA public key, got {type(trad_key)}")
            trad_key = RSAEncapKey(trad_key)
        else:
            raise ValueError(f"Unsupported traditional key type: {trad_name}")

        if not isinstance(pq_key, PQKEMPublicKey):
            raise InvalidKeyData(f"Expected PQ KEM public key for {orig_name}")

        return CompositeKEMPublicKey(pq_key, trad_key)  # type: ignore

    @staticmethod
    def load_hybrid_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> HybridPublicKey:
        """Load any hybrid public key from a SubjectPublicKeyInfo structure."""
        oid = spki["algorithm"]["algorithm"]
        alg_oid = str(oid)
        pub_bytes = spki["subjectPublicKey"].asOctets()

        if alg_oid == XWING_OID_STR:
            return XWingPublicKey.from_public_bytes(pub_bytes)

        if oid in COMPOSITE_SIG_OID_TO_NAME:
            return HybridKeyFactory._load_composite_sig_from_spki(oid, pub_bytes)

        if oid in COMPOSITE_KEM_OID_2_NAME:
            return HybridKeyFactory._load_composite_kem_from_spki(oid, pub_bytes)

        if oid in CHEMPAT_OID_2_NAME:
            alg_name = CHEMPAT_OID_2_NAME[oid]
            return ChempatPublicKey.from_public_bytes(data=pub_bytes, name=alg_name)

        _name = may_return_oid_to_name(oid)
        raise BadAlg(f"Cannot load hybrid public key. Unsupported algorithm: {_name}")

    @staticmethod
    def is_hybrid_oid(oid: univ.ObjectIdentifier) -> bool:
        """Return True if the OID belongs to a known hybrid algorithm."""
        alg_oid = str(oid)
        return (
            alg_oid == XWING_OID_STR
            or oid in COMPOSITE_SIG_OID_TO_NAME
            or oid in COMPOSITE_KEM_OID_2_NAME
            or oid in CHEMPAT_OID_2_NAME
        )

    @staticmethod
    def is_hybrid_private_key(key) -> bool:
        """Return True if key is a HybridPrivateKey instance."""
        return isinstance(key, HybridPrivateKey)

    @staticmethod
    def is_hybrid_public_key(key) -> bool:
        """Return True if key is a HybridPublicKey instance."""
        return isinstance(key, HybridPublicKey)

    @staticmethod
    def _generate_composite_key_by_name(algorithm: str) -> HybridPrivateKey:
        """Parse a full composite name and generate the key.

        Handles names like ``"composite-sig-ml-dsa-44-ed25519"`` or
        ``"composite-kem-ml-kem-768-x25519"``.
        """
        algorithm = algorithm.lower()
        # Determine prefix (sig or kem)
        if algorithm.startswith("composite-sig"):
            prefix = "sig"
        elif algorithm.startswith("composite-kem"):
            prefix = "kem"
        else:
            raise ValueError(f"Unknown composite prefix in: {algorithm}")

        pq_name = PQKeyFactory.get_pq_alg_name(algorithm=algorithm)
        pq_key = PQKeyFactory.generate_pq_key(pq_name)

        # Strip "-hash" variant used by prehash composites
        if "-hash" in algorithm:
            algorithm = algorithm.replace("-hash", "", 1)

        rest = algorithm.replace(f"composite-{prefix}-{pq_name}-", "", 1)
        trad_candidates = ["rsa", "ecdsa", "ecdh", "ec", "ed25519", "ed448", "x25519", "x448"]
        trad_name = next((t for t in trad_candidates if t in rest), None)
        if trad_name is None:
            raise ValueError(f"Cannot parse traditional algorithm from: {algorithm!r}")
        rest = rest.replace(trad_name, "").replace("-pss", "").strip("-")

        curve = None
        length = None
        if rest.isdigit():
            length = rest
        else:
            curve = rest.lstrip("-") if rest else None

        trad_key = TradKeyFactory.generate_trad_key(trad_name, curve=curve, length=length)
        return HybridKeyFactory.generate_hybrid_key(
            f"composite-{prefix}",
            pq_key=pq_key,
            trad_key=trad_key,  # type: ignore[arg-type]
        )

    @staticmethod
    def _generate_chempat_key_by_name(algorithm: str) -> HybridPrivateKey:
        """Parse a full chempat name and generate the key.

        Handles names like ``"chempat-ml-kem-768-x25519"``.
        """
        pq_name, trad_name_with_curve = HybridKeyFactory._get_pq_and_trad_name(algorithm)
        trad_candidates = ["ecdh", "x448", "x25519"]
        trad_name = next((t for t in trad_candidates if t in trad_name_with_curve), None)
        if trad_name is None:
            raise ValueError(f"Cannot parse traditional algorithm from chempat name: {algorithm!r}")
        rest = trad_name_with_curve.replace(trad_name, "", 1)
        curve = rest.lstrip("-") if rest else None
        return HybridKeyFactory.generate_hybrid_key("chempat", pq_name=pq_name, trad_name=trad_name, curve=curve)

    @staticmethod
    def generate_hybrid_key_by_name(algorithm: str) -> HybridPrivateKey:
        """Generate a hybrid key from a fully-qualified name.

        Accepts full algorithm names such as
        ``"composite-sig-ml-dsa-44-ed25519"``,
        ``"composite-kem-ml-kem-768-x25519"``,
        ``"chempat-ml-kem-768-x25519"``, and ``"xwing"``.
        """
        name = algorithm.lower()
        if name == "xwing":
            return HybridKeyFactory.generate_hybrid_key("xwing")
        if name.startswith("composite-"):
            return HybridKeyFactory._generate_composite_key_by_name(name)
        if name.startswith("chempat-"):
            return HybridKeyFactory._generate_chempat_key_by_name(name)
        raise ValueError(f"Cannot determine hybrid type from algorithm name: {algorithm!r}")

    # ------------------------------------------------------------------
    # AbstractKeyFactory required implementations
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key_by_name(algorithm: str, **_params) -> HybridPrivateKey:  # type: ignore[override]
        """Generate a hybrid private key by family name.

        :param algorithm: Hybrid family name (e.g. ``xwing``, ``composite-sig``).
        :param _params: Ignored; accepted for compatibility with the abstract base.
        """
        return HybridKeyFactory.generate_hybrid_key_by_name(algorithm)

    @staticmethod
    def get_supported_keys() -> List[str]:
        """Return the supported hybrid family names (alias of :meth:`supported_algorithms`)."""
        return HybridKeyFactory.supported_algorithms()

    @staticmethod
    def load_public_key_from_spki(spki: rfc5280.SubjectPublicKeyInfo) -> HybridPublicKey:  # type: ignore[override]
        """Load a hybrid public key from a ``SubjectPublicKeyInfo`` structure.

        :param spki: The encoded ``SubjectPublicKeyInfo``.
        """
        return HybridKeyFactory.load_hybrid_public_key_from_spki(spki)

    @staticmethod
    def validate_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> None:
        """Validate that ``alg_id`` references a recognised hybrid OID.

        :param alg_id: Algorithm identifier to check.
        :raises ValueError: If the OID does not belong to a hybrid family.
        """
        if not HybridKeyFactory.is_hybrid_oid(alg_id["algorithm"]):
            raise ValueError(f"AlgorithmIdentifier OID is not a hybrid algorithm: {alg_id['algorithm']}")

        if alg_id["parameters"].isValue:
            raise BadSigAlgIDParams("Hybrid algorithms should not have parameters in AlgorithmIdentifier.")

    @classmethod
    def _load_private_key_from_pkcs8(
        cls,
        alg_id: rfc5280.AlgorithmIdentifier,
        private_key_bytes: bytes,
        public_key_bytes: Optional[bytes] = None,
    ) -> HybridPrivateKey:  # type: ignore[override]
        raise NotImplementedError(
            "Hybrid PKCS#8 key loading is not implemented via this path. "
            "Use HybridKeyFactory.from_one_asym_key instead."
        )
