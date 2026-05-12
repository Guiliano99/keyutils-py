# SPDX-FileCopyrightText: Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Cryptographic computations: sign, verify, encapsulate, decapsulate, ECDH.

Top-level entry points:

* :func:`sign_data` / :func:`verify_signature` — algorithm-by-key dispatch.
* :func:`sign_with_alg_id` / :func:`verify_signature_with_alg_id` — driven
  by an :class:`AlgorithmIdentifier`.
* :func:`sign_data_rsa_pss`, :func:`verify_rsassa_pss_from_alg_id`,
  :func:`verify_rsassa_pss_shake` — RSASSA-PSS variants.
* :func:`compute_encaps` / :func:`compute_decaps` — KEM operations across
  PQ, hybrid, RSA-KEM, and DHKEM keys.
* :func:`compute_ecdh` — accepts a :class:`CMPCertificate` or an ECDH
  public key. Supports cofactor multiplication for EC curves.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Tuple, Union

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x448, x25519
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc8017, rfc9480, rfc9481

from keyutils_py.data_objects import FixedSHAKE128, FixedSHAKE256
from keyutils_py.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadDataFormat,
    BadSigAlgIDParams,
    InvalidKeyCombination,
)
from keyutils_py.keys.abstract_pq import (
    PQKEMPrivateKey,
    PQKEMPublicKey,
    PQSignaturePrivateKey,
    PQSignaturePublicKey,
)
from keyutils_py.keys.abstract_stateful_hash_sig import (
    PQHashStatefulSigPrivateKey,
    PQHashStatefulSigPublicKey,
)
from keyutils_py.keys.abstract_wrapper_keys import (
    AbstractHybridRawPrivateKey,
    AbstractHybridRawPublicKey,
    HybridSigPrivateKey,
    HybridSigPublicKey,
    KEMPrivateKey,
    KEMPublicKey,
)
from keyutils_py.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey
from keyutils_py.keys.trad_kem_keys import DHKEMPublicKey, RSADecapKey, RSAEncapKey
from keyutils_py.oids import (
    COMPOSITE_SIG_OID_TO_NAME,
    CURVE_2_COFACTORS,
    PQ_SIG_OID_2_NAME,
    PQ_SIG_PRE_HASH_OID_2_NAME,
    PQ_STATEFUL_HASH_SIG_OID_2_NAME,
    RSASSA_PSS_OID_2_NAME,
    SIG_ALG_OID_2_PARAMETERS_SPEC,
    TRAD_SIG_OID_2_NAME,
    get_hash_from_oid,
    hash_name_to_instance,
    may_return_oid_to_name,
)
from keyutils_py.types import ECDHPrivateKey, ECDHPublicKey
from keyutils_py.utils import (
    NOT_IMPLEMENTED_HINT,
    encode_to_der,
    require_oqs_if_needed,
    try_decode_pyasn1,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signature parameter validation (catalog-driven, exposed via keyutils.validate_sig_alg_id)
# ---------------------------------------------------------------------------


def _is_parameters_null(params_field) -> bool:
    """Return True if the AlgorithmIdentifier ``parameters`` field carries ASN.1 NULL."""
    if not params_field.isValue:
        return False
    if isinstance(params_field, univ.Null):
        return True
    if hasattr(params_field, "asOctets"):
        return params_field.asOctets() == b"\x05\x00"
    return False


def _validate_sig_alg_id(alg_id: rfc9480.AlgorithmIdentifier) -> None:
    """Catalog-driven validator; called by :func:`keyutils.validate_sig_alg_id`."""
    from keyutils_py.enums import SigAlgParametersSpec  # local import to keep enum module light

    oid = alg_id["algorithm"]
    spec = SIG_ALG_OID_2_PARAMETERS_SPEC.get(oid)
    if spec is None:
        raise BadAlg(f"Unsupported signature AlgorithmIdentifier OID: {oid}.")

    has_value = alg_id["parameters"].isValue

    if spec is SigAlgParametersSpec.MUST_BE_ABSENT:
        if has_value:
            raise BadSigAlgIDParams(
                f"AlgorithmIdentifier `parameters` must be absent for {oid}; got {alg_id['parameters'].prettyPrint()}"
            )
        return
    if spec is SigAlgParametersSpec.MUST_BE_NULL:
        if not _is_parameters_null(alg_id["parameters"]):
            raise BadSigAlgIDParams(
                f"AlgorithmIdentifier `parameters` must be NULL for {oid}; "
                f"got {alg_id['parameters'].prettyPrint() if has_value else '<absent>'}"
            )
        return
    if spec is SigAlgParametersSpec.MUST_BE_RSASSA_PSS_PARAMS:
        if not has_value:
            raise BadSigAlgIDParams(f"RSASSA-PSS requires `parameters` to be present (OID {oid}).")
        if not isinstance(alg_id["parameters"], rfc4055.RSASSA_PSS_params):
            try:
                try_decode_pyasn1(alg_id["parameters"], rfc4055.RSASSA_PSS_params())
            except Exception as exc:
                raise BadSigAlgIDParams(f"RSASSA-PSS `parameters` is not a valid RSASSA-PSS-params: {exc}") from exc
        return
    raise NotImplementedError(f"Unsupported SigAlgParametersSpec: {spec!r}")


# ---------------------------------------------------------------------------
# RSA-PSS sign / verify
# ---------------------------------------------------------------------------


def sign_data_rsa_pss(
    private_key: rsa.RSAPrivateKey,
    data: bytes,
    hash_alg: Optional[str] = None,
    salt_length: Optional[int] = None,
    second_hash_alg: Optional[str] = None,
) -> bytes:
    """Sign ``data`` with RSASSA-PSS (SHA-* via cryptography, SHAKE via PyCryptodome)."""
    if hash_alg in {"shake128", "shake256"}:
        return _sign_data_rsa_pss_shake(private_key, data, hash_alg, salt_length)

    hash_alg = hash_alg or "sha256"
    hash_algorithm = hash_name_to_instance(hash_alg)
    second_hash_algorithm = hash_name_to_instance(second_hash_alg) if second_hash_alg else hash_algorithm
    pss_padding = padding.PSS(
        mgf=padding.MGF1(hash_algorithm),
        salt_length=salt_length or hash_algorithm.digest_size,
    )
    return private_key.sign(data=data, padding=pss_padding, algorithm=second_hash_algorithm)


def _sign_data_rsa_pss_shake(
    private_key: rsa.RSAPrivateKey,
    data: bytes,
    hash_alg: Optional[str] = None,
    salt_length: Optional[int] = None,
) -> bytes:
    """Sign with RSASSA-PSS-SHAKE128 / SHAKE256 via PyCryptodome."""
    if hash_alg is None:
        hash_alg = "shake256"
    if hash_alg not in {"shake128", "shake256"}:
        raise ValueError(f"Unsupported hash for SHAKE-PSS: {hash_alg!r}.")

    hash_for_signing = FixedSHAKE128.new(data) if hash_alg == "shake128" else FixedSHAKE256.new(data)

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if salt_length is None:
        salt_length = hash_for_signing.digest_size

    pycrypto_key = RSA.import_key(pem_data)
    signer = pss.new(pycrypto_key, salt_bytes=salt_length)
    signature = signer.sign(hash_for_signing)  # type: ignore[arg-type]
    logger.debug("RSA-PSS-%s Signature: %s", hash_alg, signature.hex())
    return signature


def verify_rsassa_pss_from_alg_id(
    public_key: rsa.RSAPublicKey,
    data: bytes,
    signature: bytes,
    alg_id: rfc9480.AlgorithmIdentifier,
) -> None:
    """Verify an RSASSA-PSS signature using the parameters carried in ``alg_id``."""
    oid = alg_id["algorithm"]
    if oid in (rfc9481.id_RSASSA_PSS_SHAKE128, rfc9481.id_RSASSA_PSS_SHAKE256):
        verify_rsassa_pss_shake(public_key, data, signature, alg_id)
        return

    if oid != rfc9481.id_RSASSA_PSS:
        raise BadAlg(f"Unsupported RSASSA-PSS OID: {oid}.")

    if not alg_id["parameters"].isValue:
        raise BadSigAlgIDParams("RSASSA-PSS requires `parameters` to be present.")

    if isinstance(alg_id["parameters"], rfc4055.RSASSA_PSS_params):
        params = alg_id["parameters"]
    else:
        params, _ = try_decode_pyasn1(alg_id["parameters"], rfc4055.RSASSA_PSS_params())

    salt_length = int(params["saltLength"])
    hash_alg = get_hash_from_oid(params["hashAlgorithm"]["algorithm"])
    if hash_alg is None:
        raise BadSigAlgIDParams("Unrecognised hash algorithm in RSASSA-PSS parameters.")
    hash_algorithm = hash_name_to_instance(hash_alg)

    mgf_oid = params["maskGenAlgorithm"]["algorithm"]
    if mgf_oid != rfc8017.id_mgf1:
        raise BadSigAlgIDParams(f"`maskGenAlgorithm` must be MGF1, got {mgf_oid}.")

    mgf_params_field = params["maskGenAlgorithm"]["parameters"]
    if isinstance(mgf_params_field, rfc9480.AlgorithmIdentifier):
        mgf = mgf_params_field
    else:
        mgf, _ = try_decode_pyasn1(mgf_params_field, rfc9480.AlgorithmIdentifier())

    if mgf["algorithm"] != params["hashAlgorithm"]["algorithm"]:
        raise BadSigAlgIDParams("MGF1 hash and `hashAlgorithm` must match.")

    public_key.verify(
        signature=signature,
        data=data,
        padding=padding.PSS(
            mgf=padding.MGF1(algorithm=hash_algorithm),
            salt_length=salt_length or hash_algorithm.digest_size,
        ),
        algorithm=hash_algorithm,
    )


def verify_rsassa_pss_shake(
    public_key: rsa.RSAPublicKey,
    data: bytes,
    signature: bytes,
    alg_id: rfc9480.AlgorithmIdentifier,
    salt_length: Optional[int] = None,
) -> None:
    """Verify RSASSA-PSS-SHAKE128 / SHAKE256 via PyCryptodome (RFC 9481 §3.2.3)."""
    if alg_id["parameters"].isValue:
        raise BadDataFormat("RSASSA-PSS-SHAKE: `parameters` must be absent.")

    if alg_id["algorithm"] == rfc9481.id_RSASSA_PSS_SHAKE128:
        hash_for_verifying = FixedSHAKE128.new(data)
    elif alg_id["algorithm"] == rfc9481.id_RSASSA_PSS_SHAKE256:
        hash_for_verifying = FixedSHAKE256.new(data)
    else:
        raise BadAlg(f"Unsupported SHAKE-PSS OID: {alg_id['algorithm']}.")

    n, e = public_key.public_numbers().n, public_key.public_numbers().e
    pub_key_tmp = RSA.construct((n, e))
    if salt_length is None:
        salt_length = hash_for_verifying.digest_size

    verifier = pss.new(pub_key_tmp, salt_bytes=salt_length)
    try:
        verifier.verify(hash_for_verifying, signature)  # type: ignore[arg-type]
    except ValueError as err:
        raise InvalidSignature("Signature verification failed for RSASSA-PSS-SHAKE.") from err


# ---------------------------------------------------------------------------
# sign_data / verify_signature
# ---------------------------------------------------------------------------


def sign_data(data: bytes, key, **kwargs) -> bytes:
    """Sign ``data`` with a signature private key.

    Stateful-hash keys take only the message bytes. PQ signatures
    (ML-DSA / SLH-DSA / Falcon) honour ``hash_alg`` and ``ctx`` kwargs.
    Composite-sig keys delegate to :meth:`CompositeSigPrivateKey.sign`.

    For an :class:`rsa.RSAPrivateKey`, set ``use_rsa_pss=True`` to use
    RSASSA-PSS padding (with optional ``hash_alg``, ``salt_length``,
    ``second_hash_alg``).
    """
    if isinstance(key, PQHashStatefulSigPrivateKey):
        require_oqs_if_needed(key.name)
        return key.sign(data)
    if isinstance(key, HybridSigPrivateKey):
        return key.sign(data, **kwargs)
    if isinstance(key, PQSignaturePrivateKey):
        require_oqs_if_needed(key.name)
        hash_alg = key.check_hash_alg(kwargs.get("hash_alg"))
        ctx = kwargs.get("ctx", b"")
        return key.sign(data, hash_alg=hash_alg, ctx=ctx)
    if isinstance(key, rsa.RSAPrivateKey) and kwargs.get("use_rsa_pss"):
        return sign_data_rsa_pss(
            private_key=key,
            data=data,
            hash_alg=kwargs.get("hash_alg"),
            salt_length=kwargs.get("salt_length"),
            second_hash_alg=kwargs.get("second_hash_alg"),
        )
    raise NotImplementedError(f"{type(key).__name__}: {NOT_IMPLEMENTED_HINT}")


def verify_signature(public_key, signature: bytes, data: bytes, **kwargs) -> None:
    """Verify ``signature`` over ``data`` with a signature public key.

    :raises cryptography.exceptions.InvalidSignature: on signature mismatch.
    """
    if isinstance(public_key, PQHashStatefulSigPublicKey):
        require_oqs_if_needed(public_key.name)
        public_key.verify(data=data, signature=signature)
        return
    if isinstance(public_key, HybridSigPublicKey):
        public_key.verify(signature=signature, data=data, **kwargs)
        return
    if isinstance(public_key, PQSignaturePublicKey):
        require_oqs_if_needed(public_key.name)
        hash_alg = public_key.check_hash_alg(kwargs.get("hash_alg"))
        public_key.verify(
            signature=signature,
            data=data,
            hash_alg=hash_alg,
            is_prehashed=kwargs.get("use_pre_hash", False),
            ctx=kwargs.get("ctx", b""),
        )
        return
    raise NotImplementedError(f"{type(public_key).__name__}: {NOT_IMPLEMENTED_HINT}")


# ---------------------------------------------------------------------------
# sign_with_alg_id / verify_signature_with_alg_id
# ---------------------------------------------------------------------------


def _resolve_sig_alg_name(alg_id: rfc9480.AlgorithmIdentifier) -> str:
    """Return the registered name for ``alg_id`` (validates first)."""
    _validate_sig_alg_id(alg_id)
    oid = alg_id["algorithm"]
    if oid in PQ_STATEFUL_HASH_SIG_OID_2_NAME:
        return PQ_STATEFUL_HASH_SIG_OID_2_NAME[oid]
    if oid in PQ_SIG_OID_2_NAME:
        return PQ_SIG_OID_2_NAME[oid]
    if oid in PQ_SIG_PRE_HASH_OID_2_NAME:
        return PQ_SIG_PRE_HASH_OID_2_NAME[oid]
    if oid in COMPOSITE_SIG_OID_TO_NAME:
        return COMPOSITE_SIG_OID_TO_NAME[oid]
    if oid in TRAD_SIG_OID_2_NAME:
        return TRAD_SIG_OID_2_NAME[oid]
    raise BadAlg(f"Unsupported signature AlgorithmIdentifier: {may_return_oid_to_name(oid)}.")


_AllSigPriv = (PQSignaturePrivateKey, PQHashStatefulSigPrivateKey, HybridSigPrivateKey, rsa.RSAPrivateKey)
_AllSigPub = (PQSignaturePublicKey, PQHashStatefulSigPublicKey, HybridSigPublicKey, rsa.RSAPublicKey)


def sign_with_alg_id(key, alg_id: rfc9480.AlgorithmIdentifier, data: bytes) -> bytes:
    """Sign ``data`` with the algorithm identifier ``alg_id``."""
    name = _resolve_sig_alg_name(alg_id)
    if not isinstance(key, _AllSigPriv):
        raise BadAlg(f"Key is not a signature private key (got {type(key).__name__}).")

    oid = alg_id["algorithm"]
    if oid in RSASSA_PSS_OID_2_NAME:
        if not isinstance(key, rsa.RSAPrivateKey):
            raise BadAlg(f"RSASSA-PSS alg_id requires an RSA private key (got {type(key).__name__}).")
        if oid == rfc9481.id_RSASSA_PSS_SHAKE128:
            return sign_data_rsa_pss(key, data, hash_alg="shake128")
        if oid == rfc9481.id_RSASSA_PSS_SHAKE256:
            return sign_data_rsa_pss(key, data, hash_alg="shake256")
        params_field = alg_id["parameters"]
        if isinstance(params_field, rfc4055.RSASSA_PSS_params):
            params = params_field
        else:
            params, _ = try_decode_pyasn1(params_field, rfc4055.RSASSA_PSS_params())
        hash_alg = get_hash_from_oid(params["hashAlgorithm"]["algorithm"]) or "sha256"
        salt_length = int(params["saltLength"]) if params_field.isValue else None
        return sign_data_rsa_pss(key, data, hash_alg=hash_alg, salt_length=salt_length)

    if isinstance(key, HybridSigPrivateKey):
        return key.sign(data)
    if isinstance(key, rsa.RSAPrivateKey):
        hash_alg = TRAD_SIG_OID_2_NAME[oid].split("-", 1)[1]
        return key.sign(
            data=data,
            padding=padding.PKCS1v15(),
            algorithm=hash_name_to_instance(hash_alg),
        )
    require_oqs_if_needed(name)
    return key.sign(data)


def verify_signature_with_alg_id(
    public_key,
    alg_id: rfc9480.AlgorithmIdentifier,
    data: bytes,
    signature: bytes,
) -> None:
    """Verify ``signature`` over ``data`` against ``alg_id``."""
    name = _resolve_sig_alg_name(alg_id)
    if not isinstance(public_key, _AllSigPub):
        raise BadAlg(f"Public key is not a signature public key (got {type(public_key).__name__}).")

    oid = alg_id["algorithm"]
    if oid in RSASSA_PSS_OID_2_NAME:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise BadAlg(f"RSASSA-PSS alg_id requires an RSA public key (got {type(public_key).__name__}).")
        verify_rsassa_pss_from_alg_id(public_key, data, signature, alg_id)
        return

    if isinstance(public_key, HybridSigPublicKey):
        public_key.verify(signature=signature, data=data)
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        hash_alg = TRAD_SIG_OID_2_NAME[oid].split("-", 1)[1]
        public_key.verify(
            signature=signature,
            data=data,
            padding=padding.PKCS1v15(),
            algorithm=hash_name_to_instance(hash_alg),
        )
        return
    require_oqs_if_needed(name)
    if isinstance(public_key, PQHashStatefulSigPublicKey):
        public_key.verify(data=data, signature=signature)
        return
    public_key.verify(signature=signature, data=data)


# ---------------------------------------------------------------------------
# compute_encaps / compute_decaps
# ---------------------------------------------------------------------------


def compute_encaps(
    key: Any,
    *,
    other_key: Optional[ECDHPrivateKey] = None,
    key_length: int = 32,
    use_in_cms: bool = False,
) -> Tuple[bytes, bytes]:
    """Encapsulate a fresh shared secret against ``key``.

    Supports PQ KEMs, RSA-KEM, DHKEM, composite-KEM, and the raw hybrid
    KEMs (chempat / xwing). Plain :class:`rsa.RSAPublicKey` is wrapped as
    :class:`RSAEncapKey`; plain ECDH public keys are wrapped as
    :class:`DHKEMPublicKey` (RFC 9180).

    :raises InvalidKeyCombination: if ``other_key`` is given for an RSA-KEM
        or PQ-only KEM.
    :raises BadAlg: if ``key`` is not a recognised KEM public key.
    """
    if isinstance(key, rsa.RSAPublicKey):
        key = RSAEncapKey(key)

    if isinstance(key, RSAEncapKey):
        if other_key is not None:
            raise InvalidKeyCombination("RSA-KEM cannot be encapsulated with an ECDH ephemeral key.")
        return key.encaps(use_oaep=False, ss_length=key_length)
    if isinstance(key, AbstractHybridRawPublicKey):
        return key.encaps(private_key=other_key)
    if isinstance(key, CompositeKEMPublicKey):
        if isinstance(key.trad_key, RSAEncapKey) and other_key is not None:
            raise InvalidKeyCombination("Composite-KEM RSA cannot be encapsulated with ECDH.")
        if isinstance(key.trad_key, RSAEncapKey):
            return key.encaps(use_in_cms=use_in_cms)
        return key.encaps(private_key=other_key, use_in_cms=use_in_cms)
    if isinstance(key, DHKEMPublicKey):
        return key.encaps(private_key=other_key)
    if isinstance(key, (ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey)):
        return DHKEMPublicKey(key).encaps(private_key=other_key)
    if isinstance(key, PQKEMPublicKey):
        if other_key is not None:
            raise InvalidKeyCombination("PQ KEM cannot be encapsulated with an ECDH ephemeral key.")
        require_oqs_if_needed(key.name)
        return key.encaps()
    if isinstance(key, KEMPublicKey):
        return key.encaps()
    raise BadAlg(f"Unsupported KEM public key type: {type(key).__name__}.")


def compute_decaps(
    key: Any,
    ciphertext: bytes,
    *,
    key_length: int = 32,
    use_in_cms: bool = False,
) -> bytes:
    """Decapsulate ``ciphertext``. Symmetric counterpart of :func:`compute_encaps`."""
    if isinstance(key, rsa.RSAPrivateKey):
        key = RSADecapKey(key)
    if isinstance(key, RSADecapKey):
        return key.decaps(ct=ciphertext, use_oaep=False, ss_length=key_length)
    if isinstance(key, CompositeKEMPrivateKey):
        return key.decaps(ct=ciphertext, use_in_cms=use_in_cms)
    if isinstance(key, AbstractHybridRawPrivateKey):
        return key.decaps(ciphertext)
    if isinstance(key, PQKEMPrivateKey):
        require_oqs_if_needed(key.name)
        return key.decaps(ciphertext)
    if isinstance(key, KEMPrivateKey):
        return key.decaps(ciphertext)
    raise BadAlg(f"Unsupported KEM private key type: {type(key).__name__}.")


# ---------------------------------------------------------------------------
# RSA-OAEP helpers
# ---------------------------------------------------------------------------


def get_rsa_oaep_padding(param: rfc4055.RSAES_OAEP_params) -> padding.OAEP:
    """Return a :class:`padding.OAEP` instance configured from an ASN.1 ``RSAES_OAEP_params``.

    :param param: Decoded ``RSAES_OAEP_params`` structure.
    :raises BadAsn1Data: If the MGF1 parameter encoding is malformed.
    :raises NotImplementedError: If ``pSourceFunc`` is present (unsupported).
    """
    hash_name = get_hash_from_oid(param["hashFunc"]["algorithm"])
    if hash_name is None:
        raise BadAsn1Data("Unknown hash OID in RSAES_OAEP_params hashFunc")
    hash_fun = hash_name_to_instance(hash_name)
    raw_mgf_params = param["maskGenFunc"]["parameters"]
    oid, rest = try_decode_pyasn1(raw_mgf_params, univ.ObjectIdentifier())
    if rest != b"":
        raise BadAsn1Data("MGF1 parameters")
    mgf_hash_name = get_hash_from_oid(oid)
    if mgf_hash_name is None:
        raise BadAsn1Data("Unknown hash OID in RSAES_OAEP_params maskGenFunc")
    mgf_hash = hash_name_to_instance(mgf_hash_name)
    if param["pSourceFunc"].isValue:
        raise NotImplementedError("pSourceFunc is not supported")
    return padding.OAEP(mgf=padding.MGF1(algorithm=mgf_hash), algorithm=hash_fun, label=None)


def _resolve_rsa_key_transport_padding(alg_id: rfc9480.AlgorithmIdentifier) -> padding.AsymmetricPadding:
    """Return the cryptography padding instance described by an RSA key-transport ``alg_id``.

    :param alg_id: Key-encryption ``AlgorithmIdentifier``.
    :raises BadAlg: If the OID is not ``rsaEncryption`` or ``id-RSAES-OAEP``.
    :raises BadAsn1Data: If the ``RSAES_OAEP_params`` cannot be decoded.
    :raises ValueError: If the ``rsaEncryption`` parameters field is not absent/NULL.
    """
    oid = alg_id["algorithm"]

    if oid == rfc9481.rsaEncryption:
        params = alg_id["parameters"]
        params_absent = (
            not params.isValue
            or isinstance(params, univ.Null)
            or (hasattr(params, "asOctets") and params.asOctets() == b"\x05\x00")
        )
        if not params_absent:
            raise ValueError(
                "The `parameters` field must be absent or NULL for `rsaEncryption` key transport. "
                f"Got: {params.prettyPrint()}"
            )
        return padding.PKCS1v15()

    if oid == rfc4055.id_RSAES_OAEP:
        param, rest = try_decode_pyasn1(alg_id["parameters"], rfc4055.RSAES_OAEP_params())
        if rest != b"":
            raise BadAsn1Data("RSAES_OAEP_params")
        return get_rsa_oaep_padding(param)

    raise BadAlg(f"Unsupported key-transport OID: {oid}. Only `rsaEncryption` and `id-RSAES-OAEP` are allowed.")


def decrypt_data_with_public_key_alg_id(
    private_key: rsa.RSAPrivateKey,
    alg_id: rfc9480.AlgorithmIdentifier,
    ciphertext: bytes,
) -> bytes:
    """Decrypt *ciphertext* using the RSA key-transport algorithm specified by *alg_id*.

    Supported OIDs:

    * ``rsaEncryption`` (1.2.840.113549.1.1.1) — PKCS#1 v1.5 padding.
      The ``parameters`` field must be absent or NULL.
    * ``id-RSAES-OAEP`` (1.2.840.113549.1.1.7) — RSA-OAEP padding.
      The ``parameters`` field must be a DER-encoded ``RSAES_OAEP_params``.

    :param private_key: Recipient RSA private key.
    :param alg_id: Key-encryption ``AlgorithmIdentifier``.
    :param ciphertext: Encrypted bytes to decrypt.
    :raises BadAlg: If the OID is not ``rsaEncryption`` or ``id-RSAES-OAEP``.
    :raises BadAsn1Data: If the ``RSAES_OAEP_params`` cannot be decoded.
    :raises ValueError: If the ``rsaEncryption`` parameters field is not absent/NULL.
    """
    return private_key.decrypt(ciphertext, _resolve_rsa_key_transport_padding(alg_id))


def encrypt_data_with_public_key_alg_id(
    public_key: rsa.RSAPublicKey,
    alg_id: rfc9480.AlgorithmIdentifier,
    data: bytes,
) -> bytes:
    """Encrypt *data* using the RSA key-transport algorithm specified by *alg_id*.

    Inverse of :func:`decrypt_data_with_public_key_alg_id`. Supported OIDs:

    * ``rsaEncryption`` (1.2.840.113549.1.1.1) — PKCS#1 v1.5 padding.
      The ``parameters`` field must be absent or NULL.
    * ``id-RSAES-OAEP`` (1.2.840.113549.1.1.7) — RSA-OAEP padding.
      The ``parameters`` field must be a DER-encoded ``RSAES_OAEP_params``.

    :param public_key: Recipient RSA public key.
    :param alg_id: Key-encryption ``AlgorithmIdentifier``.
    :param data: Plaintext to encrypt (typically a content-encryption key).
    :raises BadAlg: If the OID is not ``rsaEncryption`` or ``id-RSAES-OAEP``.
    :raises BadAsn1Data: If the ``RSAES_OAEP_params`` cannot be decoded.
    :raises ValueError: If the ``rsaEncryption`` parameters field is not absent/NULL.
    """
    return public_key.encrypt(data, _resolve_rsa_key_transport_padding(alg_id))


# ---------------------------------------------------------------------------
# compute_ecdh
# ---------------------------------------------------------------------------


def _compute_ecdh_with_cofactor(
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    cofactor: int,
) -> bytes:
    """Compute ECDH with explicit cofactor multiplication (Z = h * d * Q)."""
    if private_key.curve.name != public_key.curve.name:
        raise ValueError(
            f"Private and public keys are on different curves: {private_key.curve.name} vs {public_key.curve.name}."
        )
    try:
        from tinyec import registry  # pylint: disable=import-outside-toplevel
        from tinyec.ec import Inf, Point  # pylint: disable=import-outside-toplevel
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "tinyec is required for cofactor multiplication. Install it with `pip install tinyec`."
        ) from exc

    curve = registry.get_curve(private_key.curve.name.lower())
    public_numbers = public_key.public_numbers()
    bob_point = Point(curve, public_numbers.x, public_numbers.y)
    alice_value = private_key.private_numbers().private_value
    tmp = alice_value * bob_point
    if isinstance(tmp, Inf):
        raise ValueError("Computed point is at infinity. Invalid key agreement.")
    result = cofactor * tmp
    if isinstance(result, Inf):
        raise ValueError("Computed point with cofactor is at infinity. Invalid key agreement.")
    x = result.x
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")


def _public_key_from_cert(cert: rfc9480.CMPCertificate) -> Any:
    """Extract and decode the public key from a :class:`CMPCertificate`."""
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    der = encode_to_der(spki)
    return serialization.load_der_public_key(der)


def compute_ecdh(
    private_key: ECDHPrivateKey,
    public_key: Union[ECDHPublicKey, rfc9480.CMPCertificate],
    *,
    use_cofactor: bool = False,
) -> bytes:
    """Derive an ECDH shared secret. ``public_key`` may be a key or a CMPCertificate."""
    if isinstance(public_key, rfc9480.CMPCertificate):
        extracted = _public_key_from_cert(public_key)
        if not isinstance(extracted, (ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey)):
            raise ValueError(f"Certificate does not carry an ECDH public key (got {type(extracted).__name__}).")
        public_key = extracted

    if use_cofactor and isinstance(private_key, (x25519.X25519PrivateKey, x448.X448PrivateKey)):
        raise NotImplementedError("Cofactor multiplication is not supported for X25519 / X448 keys.")

    if isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(public_key, ec.EllipticCurvePublicKey):
        if not use_cofactor:
            return private_key.exchange(ec.ECDH(), public_key)
        cofactor = CURVE_2_COFACTORS.get(private_key.curve.name)
        if cofactor is None:
            raise ValueError(
                f"Unsupported curve for cofactor: {private_key.curve.name}. See `keyutils_py.oids.CURVE_2_COFACTORS`."
            )
        if cofactor == 1:
            logger.debug("Cofactor is 1; no cofactor multiplication applied.")
            return private_key.exchange(ec.ECDH(), public_key)
        if cofactor < 1:
            raise ValueError(f"Invalid cofactor value: {cofactor}.")
        return _compute_ecdh_with_cofactor(private_key, public_key, cofactor)

    if isinstance(private_key, x25519.X25519PrivateKey) and isinstance(public_key, x25519.X25519PublicKey):
        return private_key.exchange(public_key)
    if isinstance(private_key, x448.X448PrivateKey) and isinstance(public_key, x448.X448PublicKey):
        return private_key.exchange(public_key)

    raise ValueError(
        f"Incompatible ECDH key types: private_key={type(private_key).__name__}, "
        f"public_key={type(public_key).__name__}."
    )


__all__ = [
    "sign_data",
    "verify_signature",
    "sign_with_alg_id",
    "verify_signature_with_alg_id",
    "sign_data_rsa_pss",
    "verify_rsassa_pss_from_alg_id",
    "verify_rsassa_pss_shake",
    "compute_encaps",
    "compute_decaps",
    "compute_ecdh",
    "encrypt_data_with_public_key_alg_id",
    "decrypt_data_with_public_key_alg_id",
    "get_rsa_oaep_padding",
]
