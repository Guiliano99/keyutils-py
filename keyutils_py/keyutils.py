# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""High-level user-facing key utilities.

* Lifecycle: :func:`generate_key`, :func:`generate_key_based_on_alg_id`,
  :func:`save_key`, :func:`load_private_key_from_file`,
  :func:`load_public_key_from_file`, :func:`load_pq_stfl_keys_from_dir`.
* Inspection: :func:`get_supported_pq_algorithms`,
  :func:`get_supported_pq_stfl_algorithms`, :func:`get_key_name`.
* SPKI: :func:`prepare_spki`, :func:`prepare_subject_public_key_info`,
  :func:`subject_public_key_info_from_pubkey`.
* Algorithm-identifier builders + validator: :func:`validate_sig_alg_id`,
  :func:`prepare_alg_id`, :func:`prepare_hash_alg_id`,
  :func:`prepare_mgf1_alg_id`, :func:`prepare_rsa_pss_alg_id`,
  :func:`decode_alg_id_parameters`.
* Negative-test entry point: :func:`manipulate_sig_based_on_key`
  (the only exposed mutation helper; the byte-level
  :func:`keyutils_py.utils.manipulate_first_byte` stays internal).
"""

from __future__ import annotations

import base64
import logging
import math
import os
import textwrap
from typing import Any, Dict, List, Optional, Tuple, TypeVar, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pyasn1.type import base, univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc5480, rfc5958, rfc8017, rfc9480, rfc9481

from keyutils_py.exceptions import (
    BadAlg,
    BadAsn1Data,
    InvalidKeyData,
    MissingOQSDependencyError,
)
from keyutils_py.factories.hybrid_factory import HybridKeyFactory
from keyutils_py.factories.pq_factory import PQKeyFactory
from keyutils_py.factories.pq_stfl_factory import PQStatefulSigFactory
from keyutils_py.factories.trad_factory import TradKeyFactory
from keyutils_py.keys.abstract_pq import (
    PQKEMPrivateKey,
    PQSignaturePrivateKey,
    PQSignaturePublicKey,
)
from keyutils_py.keys.abstract_stateful_hash_sig import PQHashStatefulSigPrivateKey
from keyutils_py.keys.abstract_wrapper_keys import (
    AbstractCompositePrivateKey,
    HybridPrivateKey,
)
from keyutils_py.keys.composite_sig import CompositeSigPrivateKey, CompositeSigPublicKey
from keyutils_py.keys.key_pyasn1_utils import decrypt_private_key_pkcs8_pem
from keyutils_py.keys.stateful_sig_keys import (
    HSS_ALGORITHM_DETAILS,
    HSSPrivateKey,
    XMSSMTPrivateKey,
    XMSSPrivateKey,
)
from keyutils_py.keys.trad_kem_keys import RSAEncapKey
from keyutils_py.oids import (
    ALG_ID_PARAMETERS_OID_2_SPEC,
    COMPOSITE_SIG_OID_TO_NAME,
    ECDSA_OID_2_NAME,
    FALCON_NAME_2_OID,
    FRODOKEM_NAME_2_OID,
    KEY_CLASS_MAPPING,
    MCELIECE_NAME_2_OID,
    ML_DSA_NAME_2_OID,
    ML_KEM_NAME_2_OID,
    PQ_NAME_2_OID,
    PQ_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
    RSA_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SIG_ALG_OID_2_PARAMETERS_SPEC,
    SLH_DSA_NAME_2_OID,
    TRAD_SIG_NAME_2_OID,
    get_curve_instance,
    hash_name_to_instance,
    id_rsa_kem_spki,
    may_return_oid_to_name,
    sha_alg_name_to_oid,
)
from keyutils_py.types import PrivateKey, PublicKey
from keyutils_py.utils import (
    NOT_IMPLEMENTED_HINT,
    OQS_AVAILABLE,
    encode_to_der,
    is_stateful_hash_algorithm,
    is_xmss_or_xmssmt,
    load_and_decode_pem_file,
    manipulate_first_byte,
    require_oqs_if_needed,
    try_decode_pyasn1,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AlgorithmIdentifier validation + builders
# ---------------------------------------------------------------------------


def validate_sig_alg_id(alg_id: rfc9480.AlgorithmIdentifier) -> None:
    """Validate a signature ``AlgorithmIdentifier`` against the catalog.

    Catalog-driven (see :data:`keyutils_py.oids.SIG_ALG_OID_2_PARAMETERS_SPEC`):
    covers RSA / RSASSA-PSS / ECDSA / EdDSA / PQ / stateful-hash / composite-sig.

    :raises BadSigAlgIDParams: parameters don't match the expected shape.
    :raises BadAlg: OID is not a recognised signature algorithm.
    """
    from keyutils_py.compute import _validate_sig_alg_id  # pylint: disable=import-outside-toplevel

    _validate_sig_alg_id(alg_id)


def _cast_to_bytes(data: Union[bytes, str, base.Asn1Item]) -> bytes:
    """Normalise byte carriers to plain ``bytes``."""
    if isinstance(data, str):
        return bytes.fromhex(data[2:]) if data.startswith("0x") else data.encode("utf-8")
    if isinstance(data, bytes):
        return data
    if isinstance(data, (univ.Any, univ.OctetString)):
        return data.asOctets()
    raise TypeError(f"Expected bytes/str/univ.Any/univ.OctetString, got {type(data).__name__}")


def prepare_alg_id(
    oid: univ.ObjectIdentifier,
    value: Optional[Union[bytes, str, base.Asn1Item]] = None,
    fill_random_params: bool = False,
) -> rfc5280.AlgorithmIdentifier:
    """Tiny composable builder for an ``AlgorithmIdentifier``."""
    if value is not None and fill_random_params:
        raise ValueError("Only one of `value` or `fill_random_params` can be provided.")
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = oid
    if value is not None:
        if isinstance(value, (bytes, str)):
            alg_id["parameters"] = univ.Any(_cast_to_bytes(value))
        else:
            alg_id["parameters"] = value
    elif fill_random_params:
        alg_id["parameters"] = univ.Any(encode_to_der(univ.OctetString(os.urandom(16))))
    return alg_id


_HASH_PARAMS_NULL = {
    rfc8017.id_sha224,
    rfc8017.id_sha256,
    rfc8017.id_sha384,
    rfc8017.id_sha512,
    univ.ObjectIdentifier("1.3.14.3.2.26"),  # sha1
}


def prepare_hash_alg_id(hash_alg: str, fill_random_params: bool = False) -> rfc5280.AlgorithmIdentifier:
    """Build the ``AlgorithmIdentifier`` for a SHA / SHA-3 / SHAKE hash."""
    oid = sha_alg_name_to_oid(hash_alg)
    if fill_random_params:
        return prepare_alg_id(oid, fill_random_params=True)
    if oid in _HASH_PARAMS_NULL:
        return prepare_alg_id(oid, value=univ.Null(""))
    return prepare_alg_id(oid)


def prepare_mgf1_alg_id(hash_alg: str, fill_random_params: bool = False) -> rfc5280.AlgorithmIdentifier:
    """Build the ``AlgorithmIdentifier`` for MGF1 over a given hash."""
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = rfc8017.id_mgf1
    alg_id["parameters"] = prepare_hash_alg_id(hash_alg, fill_random_params=fill_random_params)
    return alg_id


def prepare_rsa_pss_alg_id(
    hash_alg: str,
    salt_length: Optional[int] = None,
    mgf1_hash_alg: Optional[str] = None,
    fill_random_params: bool = False,
) -> rfc9480.AlgorithmIdentifier:
    """Build the ``AlgorithmIdentifier`` for RSASSA-PSS."""
    if hash_alg in {"shake128", "shake256"}:
        oid = rfc9481.id_RSASSA_PSS_SHAKE128 if hash_alg == "shake128" else rfc9481.id_RSASSA_PSS_SHAKE256
        return prepare_alg_id(oid, fill_random_params=fill_random_params)
    if fill_random_params:
        return prepare_alg_id(rfc9481.id_RSASSA_PSS, fill_random_params=True)

    inner_hash_alg_id = prepare_hash_alg_id(hash_alg)
    mgf_alg_id = prepare_mgf1_alg_id(mgf1_hash_alg or hash_alg)
    hash_inst = hash_name_to_instance(hash_alg)

    params = rfc4055.RSASSA_PSS_params()
    params["hashAlgorithm"]["algorithm"] = inner_hash_alg_id["algorithm"]
    if inner_hash_alg_id["parameters"].isValue:
        params["hashAlgorithm"]["parameters"] = inner_hash_alg_id["parameters"]
    params["maskGenAlgorithm"]["algorithm"] = mgf_alg_id["algorithm"]
    params["maskGenAlgorithm"]["parameters"] = mgf_alg_id["parameters"]
    params["saltLength"] = salt_length if salt_length is not None else hash_inst.digest_size

    return prepare_alg_id(rfc9481.id_RSASSA_PSS, value=params)


def prepare_sig_alg_id(
    key: Union[PrivateKey, PublicKey],
    hash_alg: str = "sha256",
    use_rsa_pss: bool = False,
) -> rfc5280.AlgorithmIdentifier:
    """Build the signature ``AlgorithmIdentifier`` for a traditional signing/verifying key.

    Maps a key plus a digest to the matching signature OID (e.g. a DSA key with
    ``sha256`` to ``id-dsa-with-sha256``; an EC key with ``sha384`` to
    ``ecdsa-with-SHA384``). EdDSA keys ignore ``hash_alg`` (Ed25519 / Ed448 carry
    no separate digest); RSA keys yield a PKCS#1 v1.5 identifier (NULL parameters)
    unless ``use_rsa_pss`` selects RSASSA-PSS.

    :param key: The signature key, private or public.
    :param hash_alg: The digest name (e.g. ``sha256``); ignored for EdDSA keys.
    :param use_rsa_pss: For an RSA key, build a RSASSA-PSS identifier instead of
        PKCS#1 v1.5.
    :raises BadAlg: If the key type / hash combination has no known signature OID.
    """
    name = get_key_name(key)
    if name in ("ed25519", "ed448"):
        return prepare_alg_id(TRAD_SIG_NAME_2_OID[name])
    if name == "rsa" and use_rsa_pss:
        return prepare_rsa_pss_alg_id(hash_alg)
    oid = TRAD_SIG_NAME_2_OID.get(f"{name}-{hash_alg}")
    if oid is None:
        raise BadAlg(f"No signature AlgorithmIdentifier for a {name!r} key with hash {hash_alg!r}.")
    if name == "rsa":
        # RSA PKCS#1 v1.5 carries NULL parameters (RFC 4055 / RFC 8017).
        return prepare_alg_id(oid, value=univ.Null(""))
    # ECDSA / DSA — parameters absent (RFC 5758).
    return prepare_alg_id(oid)


def decode_alg_id_parameters(alg_id: rfc5280.AlgorithmIdentifier) -> rfc5280.AlgorithmIdentifier:
    """Replace ``alg_id["parameters"]`` with its structured form (mutates ``alg_id``).

    No-op if no spec is registered for the OID or if the field is already
    structured. Returns the same ``alg_id`` for chaining.
    """
    spec = ALG_ID_PARAMETERS_OID_2_SPEC.get(alg_id["algorithm"])
    if spec is None:
        return alg_id
    if isinstance(alg_id["parameters"], spec):
        return alg_id
    if not alg_id["parameters"].isValue:
        return alg_id
    decoded, _ = try_decode_pyasn1(alg_id["parameters"], spec())
    alg_id["parameters"] = decoded
    return alg_id


# ---------------------------------------------------------------------------
# Lifecycle: generate
# ---------------------------------------------------------------------------


def generate_key(algorithm: str = "hss", **params):
    """Generate a private key.

    See the package README for the algorithm name reference.
    """
    from keyutils_py.utils import is_hybrid_algorithm, is_supported_pq_algorithm  # avoid load-order issues

    name = algorithm.lower()
    if is_hybrid_algorithm(name):
        if name in HybridKeyFactory.supported_algorithms():
            return HybridKeyFactory.generate_hybrid_key(name, **params)
        return HybridKeyFactory.generate_hybrid_key_by_name(name)
    if not is_supported_pq_algorithm(name):
        raise NotImplementedError(f"{algorithm!r}: {NOT_IMPLEMENTED_HINT}")
    require_oqs_if_needed(name)
    if is_stateful_hash_algorithm(name):
        return PQStatefulSigFactory.generate_pq_stateful_key(name, **params)
    return PQKeyFactory.generate_key_by_name(name, **params)


def _curve_oid_to_name(oid: univ.ObjectIdentifier) -> str:
    """Best-effort EC curve OID → name lookup."""
    from pyasn1_alt_modules import rfc5639  # pylint: disable=import-outside-toplevel

    table: Dict[univ.ObjectIdentifier, str] = {
        rfc5480.secp192r1: "secp192r1",
        rfc5480.secp224r1: "secp224r1",
        rfc5480.secp256r1: "secp256r1",
        rfc5480.secp384r1: "secp384r1",
        rfc5480.secp521r1: "secp521r1",
        rfc5639.brainpoolP256r1: "brainpoolP256r1",
        rfc5639.brainpoolP384r1: "brainpoolP384r1",
        rfc5639.brainpoolP512r1: "brainpoolP512r1",
    }
    if oid in table:
        return table[oid]
    raise ValueError(f"Unsupported EC curve OID: {oid}")


def _generate_trad_key_from_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> Any:
    """Generate an RSA / ECDSA / EdDSA / X25519 / X448 key from an alg_id."""
    oid = alg_id["algorithm"]
    if oid == rfc9481.id_Ed25519:
        return TradKeyFactory.generate_trad_key("ed25519")
    if oid == rfc9481.id_Ed448:
        return TradKeyFactory.generate_trad_key("ed448")
    if oid == rfc9481.id_X25519:
        return TradKeyFactory.generate_trad_key("x25519")
    if oid == rfc9481.id_X448:
        return TradKeyFactory.generate_trad_key("x448")
    if oid in RSA_OID_2_NAME or oid in RSASSA_PSS_OID_2_NAME or oid == rfc9481.rsaEncryption:
        return TradKeyFactory.generate_trad_key("rsa")
    if oid == rfc5480.id_ecPublicKey or oid in ECDSA_OID_2_NAME:
        params = alg_id["parameters"]
        if params.isValue:
            substrate = params.asOctets() if hasattr(params, "asOctets") else encode_to_der(params)
            curve_oid_obj, rest = try_decode_pyasn1(substrate, rfc5480.ECParameters())
            if rest:
                raise BadAsn1Data("ECParameters")
            curve_name = _curve_oid_to_name(curve_oid_obj["namedCurve"])
            return ec.generate_private_key(curve=get_curve_instance(curve_name))
        return TradKeyFactory.generate_trad_key("ecdsa")
    raise BadAlg(f"Cannot generate traditional key for OID: {may_return_oid_to_name(oid)}.")


def generate_key_based_on_alg_id(alg_id: rfc5280.AlgorithmIdentifier) -> Any:
    """Generate a fresh private key matching ``alg_id``."""
    oid = alg_id["algorithm"]
    if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
        name = PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
        require_oqs_if_needed(name)
        return PQStatefulSigFactory.generate_pq_stateful_key(name)
    if oid in PQ_OID_2_NAME:
        name = PQ_OID_2_NAME[oid]
        if oid in PQ_SIG_PRE_HASH_OID_2_NAME:
            name = "-".join(PQ_SIG_PRE_HASH_OID_2_NAME[oid].split("-")[:-1])
        require_oqs_if_needed(name)
        return PQKeyFactory.generate_key_by_name(name)
    if HybridKeyFactory.is_hybrid_oid(oid):
        if oid in COMPOSITE_SIG_OID_TO_NAME:
            return HybridKeyFactory.generate_hybrid_key_by_name(COMPOSITE_SIG_OID_TO_NAME[oid])
        return HybridKeyFactory.generate_hybrid_key_by_name(may_return_oid_to_name(oid))
    return _generate_trad_key_from_alg_id(alg_id)


# ---------------------------------------------------------------------------
# Lifecycle: save / load
# ---------------------------------------------------------------------------


def save_key(
    key,
    path: str,
    password: Optional[str] = "11111",
    save_type: str = "seed",
) -> None:
    """Write ``key`` to ``path`` as a (optionally encrypted) PEM file."""
    if not isinstance(key, (PQHashStatefulSigPrivateKey, PQSignaturePrivateKey, PQKEMPrivateKey, HybridPrivateKey)):
        raise NotImplementedError(f"{type(key).__name__}: {NOT_IMPLEMENTED_HINT}")

    if password:
        enc_alg: Union[serialization.NoEncryption, serialization.BestAvailableEncryption] = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
        )
    else:
        enc_alg = serialization.NoEncryption()

    if isinstance(key, HybridPrivateKey):
        der = HybridKeyFactory.save_private_key_one_asym_key(
            private_key=key,
            save_type=save_type,
            version=1,
        )
    elif isinstance(key, PQHashStatefulSigPrivateKey):
        del save_type  # ignored
        data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg,
        )
        with open(path, "wb") as fh:
            fh.write(data)
        return
    else:
        require_oqs_if_needed(key.name)
        der = PQKeyFactory.save_private_key_one_asym_key(
            private_key=key,
            save_type=save_type,
            version=1,
        )

    if password:
        from keyutils_py.keys.key_pyasn1_utils import (
            encrypt_private_key_pkcs8_pem,  # pylint: disable=import-outside-toplevel
        )

        data = encrypt_private_key_pkcs8_pem(private_key_der=der, password=password)
    else:
        body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
        data = (f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n").encode("ascii")

    with open(path, "wb") as fh:
        fh.write(data)


def _load_private_key_from_one_asym_key(one_asym_key: rfc5958.OneAsymmetricKey):
    alg_id = one_asym_key["privateKeyAlgorithm"]
    oid = alg_id["algorithm"]
    if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
        require_oqs_if_needed(PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid])
        return PQStatefulSigFactory.load_private_key_from_one_asym_key(one_asym_key)
    if oid in PQ_OID_2_NAME:
        require_oqs_if_needed(PQ_OID_2_NAME[oid])
        return PQKeyFactory.from_one_asym_key(one_asym_key)
    if HybridKeyFactory.is_hybrid_oid(oid):
        return HybridKeyFactory.from_one_asym_key(one_asym_key)
    raise NotImplementedError(f"Algorithm {may_return_oid_to_name(oid)}: {NOT_IMPLEMENTED_HINT}")


def load_private_key_from_file(filepath: str, password: Optional[str] = "11111"):
    """Load a private key from a PEM file (PKCS#8 or plain)."""
    with open(filepath, "rb") as fh:
        raw = fh.read()
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in raw:
        if password is None:
            raise ValueError("Password required to decrypt PKCS#8 encrypted private key.")
        der = decrypt_private_key_pkcs8_pem(pem_data=raw, password=password)
    else:
        der = load_and_decode_pem_file(filepath)
    try:
        one_asym_key, rest = try_decode_pyasn1(der, rfc5958.OneAsymmetricKey())
    except Exception as exc:  # noqa: BLE001
        raise InvalidKeyData(f"Failed to decode OneAsymmetricKey from {filepath}.") from exc
    if rest:
        raise BadAsn1Data("OneAsymmetricKey")
    return _load_private_key_from_one_asym_key(one_asym_key)


def load_public_key_from_file(filepath: str):
    """Load a public key from a PEM ``SubjectPublicKeyInfo`` file."""
    der = load_and_decode_pem_file(filepath)
    try:
        spki, rest = try_decode_pyasn1(der, rfc5280.SubjectPublicKeyInfo())
    except Exception as exc:  # noqa: BLE001
        raise InvalidKeyData(f"Failed to decode SubjectPublicKeyInfo from {filepath}.") from exc
    if rest:
        raise BadAsn1Data("SubjectPublicKeyInfo")
    oid = spki["algorithm"]["algorithm"]
    if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
        require_oqs_if_needed(PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid])
        return PQStatefulSigFactory.load_public_key_from_spki(spki)
    if oid in PQ_OID_2_NAME:
        require_oqs_if_needed(PQ_OID_2_NAME[oid])
        return PQKeyFactory.load_public_key_from_spki(spki)
    if HybridKeyFactory.is_hybrid_oid(oid):
        return HybridKeyFactory.load_hybrid_public_key_from_spki(spki)
    raise NotImplementedError(f"Algorithm {may_return_oid_to_name(oid)}: {NOT_IMPLEMENTED_HINT}")


def _stateful_hash_filename_to_algorithm(filename: str) -> Optional[str]:
    name = filename.replace("_layers_", "/")
    if name.endswith(".pem"):
        name = name[: -len(".pem")]
    if name.startswith("private-key-"):
        name = name[len("private-key-") :]
    if not is_stateful_hash_algorithm(name):
        return None
    return name


def load_pq_stfl_keys_from_dir(
    directory: str,
    password: Optional[str] = "11111",
) -> Dict[str, PQHashStatefulSigPrivateKey]:
    """Load every stateful-hash private key in ``directory`` (non-recursive)."""
    keys: Dict[str, PQHashStatefulSigPrivateKey] = {}
    if not os.path.isdir(directory):
        raise FileNotFoundError(directory)
    skipped_xmss = 0
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry)
        if not os.path.isfile(path) or not entry.endswith(".pem"):
            continue
        algorithm = _stateful_hash_filename_to_algorithm(entry)
        if algorithm is None:
            continue
        if not OQS_AVAILABLE and is_xmss_or_xmssmt(algorithm):
            skipped_xmss += 1
            continue
        try:
            loaded = load_private_key_from_file(path, password=password)
        except MissingOQSDependencyError:
            skipped_xmss += 1
            continue
        if isinstance(loaded, PQHashStatefulSigPrivateKey):
            keys[algorithm] = loaded
    if skipped_xmss:
        logger.warning(
            "Skipped %d XMSS/XMSSMT key file(s) in %s because liboqs is not installed.",
            skipped_xmss,
            directory,
        )
    return keys


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


_STFL_FAMILIES = ("hss", "xmss", "xmssmt")
_PQ_FAMILIES = ("ml-dsa", "slh-dsa", "falcon", "ml-kem", "frodokem", "mceliece", "sntrup761")


def get_supported_pq_stfl_algorithms(
    family: Optional[str] = None,
) -> Union[Dict[str, List[str]], List[str]]:
    """Return supported stateful-hash algorithms.

    ``family=None`` → ``{"hss": [...], "xmss": [...], "xmssmt": [...]}``.
    """
    if family is not None and family not in _STFL_FAMILIES:
        raise ValueError(f"Unknown family {family!r}. Valid families: {list(_STFL_FAMILIES)}")
    families = PQStatefulSigFactory.get_algorithms_by_family()
    snapshot: Dict[str, List[str]] = {f: list(families.get(f, [])) for f in _STFL_FAMILIES}
    if family is None:
        return snapshot
    return snapshot[family]


def get_supported_pq_algorithms(
    family: Optional[str] = None,
) -> Union[Dict[str, List[str]], List[str]]:
    """Return supported PQ signature + KEM algorithms (excluding stateful-hash)."""
    if family is not None and family not in _PQ_FAMILIES:
        raise ValueError(f"Unknown family {family!r}. Valid families: {list(_PQ_FAMILIES)}")
    snapshot: Dict[str, List[str]] = {f: [] for f in _PQ_FAMILIES}
    snapshot["ml-dsa"] = sorted(ML_DSA_NAME_2_OID.keys())
    snapshot["ml-kem"] = sorted(ML_KEM_NAME_2_OID.keys())
    snapshot["slh-dsa"] = sorted(SLH_DSA_NAME_2_OID.keys())
    if OQS_AVAILABLE:
        snapshot["falcon"] = sorted(FALCON_NAME_2_OID.keys())
        snapshot["frodokem"] = sorted(FRODOKEM_NAME_2_OID.keys())
        snapshot["mceliece"] = sorted(MCELIECE_NAME_2_OID.keys())
        snapshot["sntrup761"] = ["sntrup761"]
    if family is None:
        return snapshot
    return snapshot[family]


def get_key_name(key: Union[PrivateKey, PublicKey]) -> str:
    """Return the canonical algorithm name for ``key``."""
    if hasattr(key, "name"):
        return key.name  # type: ignore[union-attr]
    cls_name = key.__class__.__name__
    if cls_name in KEY_CLASS_MAPPING:
        return KEY_CLASS_MAPPING[cls_name]
    raise ValueError(f"Unknown key class: {cls_name!r}.")


# ---------------------------------------------------------------------------
# SPKI builders
# ---------------------------------------------------------------------------


def _is_private_key(key: object) -> bool:
    """Return True if ``key`` is a private key (has a ``public_key()`` method)."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, ed448, x25519, x448  # noqa

    return isinstance(
        key,
        (
            RSAPrivateKey,
            dsa.DSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
            x25519.X25519PrivateKey,
            x448.X448PrivateKey,
        ),
    ) or hasattr(key, "_export_private_key")


def _to_public_key(key: Union[PrivateKey, PublicKey]) -> PublicKey:
    """Reduce a private key to its public key; pass-through for public keys."""
    if _is_private_key(key) and hasattr(key, "public_key"):
        return key.public_key()  # type: ignore[union-attr,return-value]
    return key  # type: ignore[return-value]


def _prepare_rsa_pss_spki(
    key: RSAPublicKey,
    hash_alg: Optional[str] = None,
) -> rfc5280.SubjectPublicKeyInfo:
    """SPKI carrying an RSA-PSS-tagged ``algorithm`` and the RSA public key."""
    spki = rfc5280.SubjectPublicKeyInfo()
    der_data = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1,
    )
    spki["subjectPublicKey"] = univ.BitString.fromOctetString(der_data)
    spki["algorithm"] = prepare_rsa_pss_alg_id(hash_alg or "sha256")
    return spki


def subject_public_key_info_from_pubkey(
    public_key: PublicKey,
    use_rsa_pss: bool = False,
    hash_alg: Optional[str] = None,
) -> rfc5280.SubjectPublicKeyInfo:
    """Convert ``public_key`` to an :class:`rfc5280.SubjectPublicKeyInfo`."""
    if isinstance(public_key, CompositeSigPublicKey):
        return public_key.to_spki(use_pss=use_rsa_pss)
    if isinstance(public_key, RSAPublicKey) and use_rsa_pss:
        return _prepare_rsa_pss_spki(public_key, hash_alg=hash_alg)

    oid = None
    if hash_alg is not None and isinstance(public_key, PQSignaturePublicKey):
        checked_hash = public_key.check_hash_alg(hash_alg)
        if checked_hash is None:
            raise BadAlg(f"Hash {hash_alg!r} is not supported for {public_key.name}.")
        oid = PQ_NAME_2_OID.get(public_key.name + "-" + checked_hash)

    der_data = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki, rest = try_decode_pyasn1(der_data, rfc5280.SubjectPublicKeyInfo())
    if rest:
        raise BadAsn1Data("SubjectPublicKeyInfo")
    if oid is not None:
        spki["algorithm"]["algorithm"] = oid
    return spki


_KGA_KEY_NAMES_2_OID = {
    "rsa": univ.ObjectIdentifier("1.2.840.113549.1.1.1"),
    "dsa": univ.ObjectIdentifier("1.2.840.10040.4.1"),
    "ecc": univ.ObjectIdentifier("1.2.840.10045.3.1.7"),
    "rsa-kem": id_rsa_kem_spki,
    "rsa_kem": id_rsa_kem_spki,
}


def _prepare_spki_for_kga(
    key: Optional[Union[PrivateKey, PublicKey]],
    key_name: Optional[str],
    use_pss: bool,
    add_null: bool,
    add_params_rand_bytes: bool,
) -> rfc5280.SubjectPublicKeyInfo:
    """Produce an empty-key SPKI (KGA mode)."""
    if add_null and add_params_rand_bytes:
        raise ValueError("Either `add_null` or `add_params_rand_bytes` can be set, not both.")
    spki = rfc5280.SubjectPublicKeyInfo()
    spki["subjectPublicKey"] = univ.BitString("")
    if key is not None:
        key = _to_public_key(key)
    if key_name and key_name in _KGA_KEY_NAMES_2_OID:
        spki["algorithm"]["algorithm"] = _KGA_KEY_NAMES_2_OID[key_name]
        if key_name == "ecc":
            ec_params = rfc5480.ECParameters()
            ec_params["namedCurve"] = rfc5480.secp256r1
            spki["algorithm"]["parameters"] = univ.Any(encode_to_der(ec_params))
    if key is not None and key_name not in _KGA_KEY_NAMES_2_OID:
        spki_tmp = subject_public_key_info_from_pubkey(public_key=key, use_rsa_pss=use_pss)
        spki["algorithm"]["algorithm"] = spki_tmp["algorithm"]["algorithm"]
    if add_null:
        spki["algorithm"]["parameters"] = univ.Null("")
    if add_params_rand_bytes:
        spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))
    return spki


def prepare_subject_public_key_info(
    key: Optional[Union[PrivateKey, PublicKey]] = None,
    *,
    for_kga: bool = False,
    key_name: Optional[str] = None,
    use_rsa_pss: bool = False,
    hash_alg: Optional[str] = None,
    invalid_key_size: bool = False,
    add_params_rand_bytes: bool = False,
    add_null: bool = False,
) -> rfc5280.SubjectPublicKeyInfo:
    """Prepare a :class:`SubjectPublicKeyInfo` for a Certificate / CSR / CertTemplate."""
    if key is None and not for_kga:
        raise ValueError("Either a `key` must be provided or `for_kga` must be True.")
    if add_null and add_params_rand_bytes:
        raise ValueError("Either `add_null` or `add_params_rand_bytes` can be set, not both.")

    if isinstance(key, AbstractCompositePrivateKey):
        public_key_obj = key.public_key()
        pub_bytes = public_key_obj.public_bytes_raw()
        spki = rfc5280.SubjectPublicKeyInfo()
        if invalid_key_size:
            pub_bytes = pub_bytes + b"\x00"
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(pub_bytes)
        if isinstance(key, CompositeSigPrivateKey):
            oid = key.get_oid(use_pss=use_rsa_pss)
        else:
            oid = key.get_oid()
        spki["algorithm"]["algorithm"] = oid
        if add_null:
            spki["algorithm"]["parameters"] = univ.Null("")
        if add_params_rand_bytes:
            spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))
        return spki

    if key is not None:
        key = _to_public_key(key)

    if for_kga:
        return _prepare_spki_for_kga(
            key=key,
            key_name=key_name,
            use_pss=use_rsa_pss,
            add_null=add_null,
            add_params_rand_bytes=add_params_rand_bytes,
        )

    if key_name in {"rsa-kem", "rsa_kem"}:
        if not isinstance(key, RSAPublicKey):
            raise BadAlg("`key_name='rsa-kem'` requires an RSA public key.")
        rsa_kem_pub = RSAEncapKey(key)
        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = rsa_kem_pub.get_oid()
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(rsa_kem_pub.encode())
    elif isinstance(key, RSAPublicKey) and use_rsa_pss:
        spki = _prepare_rsa_pss_spki(key, hash_alg=hash_alg)
    else:
        spki = subject_public_key_info_from_pubkey(
            public_key=key,  # type: ignore[arg-type]
            use_rsa_pss=use_rsa_pss,
            hash_alg=hash_alg,
        )

    if invalid_key_size:
        tmp = spki["subjectPublicKey"].asOctets() + b"\x00\x00"
        spki["subjectPublicKey"] = univ.BitString.fromOctetString(tmp)
    if add_params_rand_bytes:
        spki["algorithm"]["parameters"] = univ.BitString.fromOctetString(os.urandom(16))
    if add_null:
        spki["algorithm"]["parameters"] = univ.Null("")
    return spki


# Short alias.
prepare_spki = prepare_subject_public_key_info


# ---------------------------------------------------------------------------
# Negative-test helper
# ---------------------------------------------------------------------------


def manipulate_sig_based_on_key(
    data: bytes,
    key: Optional[Union[PrivateKey, PublicKey]] = None,
) -> bytes:
    """Mutate ``data`` so it no longer verifies under ``key``.

    Friendly entry point for negative tests:

    * Stateful-hash keys (HSS / XMSS / XMSSMT) → mutate the signature
      payload after the LMS leaf-index prefix. For HSS this targets the
      LMOTS portion only, leaving the auth-path intact.
    * Anything else, or ``key=None`` → flip the first byte of ``data``.

    :returns: The mutated bytes (same length as the input).
    """
    if key is None:
        return manipulate_first_byte(data)
    if isinstance(key, PQHashStatefulSigPrivateKey):
        return _manipulate_pq_stateful_signature_bytes(data, key, manipulate_sig=True)
    return manipulate_first_byte(data)


def _manipulate_pq_stateful_signature_bytes(
    data: bytes,
    key: PQHashStatefulSigPrivateKey,
    manipulate_sig: bool = True,
    index: Optional[int] = None,
) -> bytes:
    """Mutate a stateful-hash signature (XMSS / XMSSMT / HSS) for negative tests."""
    index_start = 0
    alg_details: Optional[Dict[str, Any]] = None
    if isinstance(key, XMSSPrivateKey):
        index_length = 4
    elif isinstance(key, XMSSMTPrivateKey):
        index_length = math.ceil(key.tree_height / 8)
    elif isinstance(key, HSSPrivateKey):
        index_length = 4
        alg_details = HSS_ALGORITHM_DETAILS.get(key.name)
        if alg_details is None:
            raise ValueError(f"Unsupported HSS algorithm for manipulation: {key.name}")
        if key.levels < 1:
            raise ValueError("HSS keys must declare at least one LMS level.")
        header_length = 4
        per_level_span = alg_details["lms_signature_length"] + alg_details["lms_public_key_length"]
        index_start = header_length + max(0, key.levels - 1) * per_level_span
    else:
        raise NotImplementedError("Stateful-signature manipulation is only implemented for XMSS, XMSSMT, and HSS keys.")

    signature_start = index_start + index_length
    if len(data) < signature_start:
        raise ValueError("Signature data is too short to contain the LMS leaf-index prefix.")

    if manipulate_sig:
        if len(data) == signature_start:
            raise ValueError("No signature payload available after the index prefix to manipulate.")
        suffix = _mutate_stateful_payload(key, data[signature_start:])
        return data[:signature_start] + suffix

    if index is None:
        index = _default_lms_max_sig_size(key, alg_details)
    if index < 0:
        raise ValueError("The signature index must be non-negative.")
    max_value = (1 << (index_length * 8)) - 1
    if index > max_value:
        raise ValueError(f"index={index} does not fit in {index_length} bytes.")
    index_bytes = index.to_bytes(index_length, "little")
    return data[:index_start] + index_bytes + data[signature_start:]


def _default_lms_max_sig_size(
    key: PQHashStatefulSigPrivateKey,
    details: Optional[Dict[str, Any]] = None,
) -> int:
    if isinstance(key, HSSPrivateKey):
        info = details or HSS_ALGORITHM_DETAILS.get(key.name)
        if info is None:
            raise ValueError(f"Unsupported HSS algorithm for manipulation: {key.name}")
        return info["max_per_tree"]
    return key.max_sig_size


def _mutate_stateful_payload(
    key: PQHashStatefulSigPrivateKey,
    payload: bytes,
) -> bytes:
    if isinstance(key, HSSPrivateKey):
        return _mutate_hss_lms_signature(key, payload)
    return manipulate_first_byte(payload)


def _mutate_hss_lms_signature(key: HSSPrivateKey, payload: bytes) -> bytes:
    details = HSS_ALGORITHM_DETAILS.get(key.name)
    if details is None:
        raise ValueError(f"Unsupported HSS algorithm for manipulation: {key.name}")
    lmots_length = details["lmots_signature_length"]
    if len(payload) < lmots_length:
        raise ValueError("Signature payload is too short to contain the LMOTS portion.")
    return manipulate_first_byte(payload[:lmots_length]) + payload[lmots_length:]


def _get_index(
    key: Union[XMSSPrivateKey, XMSSMTPrivateKey],
    last_index: bool,
    index: Optional[int],
) -> Tuple[bytes, int]:
    """Compute serialized index bytes and their byte-length for XMSS / XMSSMT."""
    if not isinstance(key, (XMSSPrivateKey, XMSSMTPrivateKey)):
        raise NotImplementedError("Index manipulation is only implemented for XMSS and XMSSMT keys.")
    length = 4 if isinstance(key, XMSSPrivateKey) else math.ceil(key.tree_height / 8)
    if index is not None and last_index:
        index_bytes = (key.max_sig_size - 1).to_bytes(length, "big")
    elif index is not None:
        index_bytes = index.to_bytes(length, "big")
    else:
        index_bytes = key.max_sig_size.to_bytes(length, "big")
    return index_bytes, length


def modify_pq_stateful_sig_private_key(
    key: PQHashStatefulSigPrivateKey,
    last_index: bool = False,
    index: Optional[int] = None,
    used_index: bool = False,
) -> PQHashStatefulSigPrivateKey:
    """Rewrite a stateful key's internal counter for negative / exhaustion tests.

    :param key: The stateful-hash private key to modify.
    :param last_index: Set the counter to ``max_sig_size - 1`` (one sign left).
    :param index: Set the counter to this exact value.
    :param used_index: Restore the key to the state saved at position ``index``
        inside ``key.used_keys`` (default: last saved state).
    """
    index = int(index) if index is not None else None
    if used_index:
        if index is not None and len(key.used_keys) < index:
            raise ValueError(f"index {index} exceeds used_keys length {len(key.used_keys)} for {key.name}")
        slot = index if index is not None else -1
        return key.from_private_bytes(key.used_keys[slot])

    if isinstance(key, (XMSSPrivateKey, XMSSMTPrivateKey)):
        private_bytes = key.private_bytes_raw()
        index_bytes, length = _get_index(key, last_index, index)
        key_bytes = private_bytes[:4] + index_bytes + private_bytes[4 + length :]
        public_key_bytes = key.public_key().public_bytes_raw()
        if isinstance(key, XMSSPrivateKey):
            return XMSSPrivateKey(alg_name=key.name, private_bytes=key_bytes, public_key=public_key_bytes)
        return XMSSMTPrivateKey(alg_name=key.name, private_bytes=key_bytes, public_key=public_key_bytes)

    if isinstance(key, HSSPrivateKey):
        modified_key = HSSPrivateKey.from_private_bytes(key.private_bytes_raw())
        hss = modified_key._hss
        if hss is None:
            raise ValueError("HSS private key is not properly initialized.")
        if index is not None and last_index:
            target = hss.maxSignatures() - 1
        elif index is not None:
            target = index
        else:
            target = hss.maxSignatures()
        if target >= hss.maxSignatures():
            for level_key in hss.prv:
                level_key.q = level_key.maxSignatures()
        elif hss.levels > 0 and hss.prv:
            hss.prv[0].q = target
        return HSSPrivateKey.from_private_bytes(hss.serialize())

    raise NotImplementedError(f"modify_pq_stateful_sig_private_key: unsupported key type {type(key).__name__}")


# Suppress unused-import noise (TypeVar / Tuple kept for downstream callers).
_ = (TypeVar, Tuple, SIG_ALG_OID_2_PARAMETERS_SPEC)


__all__ = [
    # Lifecycle
    "generate_key",
    "generate_key_based_on_alg_id",
    "save_key",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "load_pq_stfl_keys_from_dir",
    # Inspection
    "get_supported_pq_algorithms",
    "get_supported_pq_stfl_algorithms",
    "get_key_name",
    # SPKI
    "prepare_spki",
    "prepare_subject_public_key_info",
    "subject_public_key_info_from_pubkey",
    # AlgorithmIdentifier helpers
    "validate_sig_alg_id",
    "prepare_alg_id",
    "prepare_hash_alg_id",
    "prepare_mgf1_alg_id",
    "prepare_rsa_pss_alg_id",
    "prepare_sig_alg_id",
    "decode_alg_id_parameters",
    # Negative-test helpers
    "manipulate_sig_based_on_key",
    "modify_pq_stateful_sig_private_key",
]
