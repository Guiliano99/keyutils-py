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
from typing import Any, Dict, Optional, Tuple, Union, get_args

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, x448, x25519
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc9480, rfc9481

from keyutils_py.data_objects import FixedSHAKE128, FixedSHAKE256
from keyutils_py.exceptions import (
    BadAlg,
    BadAsn1Data,
    BadDataFormat,
    BadSigAlgID,
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
    KEMPrivateKey,
    KEMPublicKey,
)
from keyutils_py.keys.composite_kem import CompositeKEMPrivateKey, CompositeKEMPublicKey
from keyutils_py.keys.composite_sig import CompositeSigPrivateKey, CompositeSigPublicKey
from keyutils_py.keys.trad_kem_keys import DHKEMPublicKey, RSADecapKey, RSAEncapKey
from keyutils_py.oids import (
    CURVE_2_COFACTORS,
    SIG_ALG_OID_2_PARAMETERS_SPEC,
    SigAlgInfo,
    get_hash_from_oid,
    get_sig_alg_info,
    hash_name_to_instance,
)
from keyutils_py.types import DSAPrivateKey, DSAPublicKey, ECDHPrivateKey, ECDHPublicKey, SignKey, VerifyKey
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
    """Sign ``data`` with RSASSA-PSS (SHA-* via cryptography, SHAKE via PyCryptodome).

    :param salt_length: The salt length in bytes; ``None`` is the digest size, ``0`` is a salt of length 0.
    :param second_hash_alg: The hash of the message if it differs from the MGF1 hash (negative tests).
    """
    if hash_alg in {"shake128", "shake256"}:
        return _sign_data_rsa_pss_shake(private_key, data, hash_alg, salt_length)

    hash_alg = hash_alg or "sha256"
    hash_algorithm = hash_name_to_instance(hash_alg)
    second_hash_algorithm = hash_name_to_instance(second_hash_alg) if second_hash_alg else hash_algorithm
    pss_padding = padding.PSS(
        mgf=padding.MGF1(hash_algorithm),
        salt_length=hash_algorithm.digest_size if salt_length is None else salt_length,
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

    info = get_sig_alg_info(alg_id)
    verify_signature(
        public_key, signature, data, hash_alg=info.hash_alg, use_rsa_pss=True, salt_length=info.salt_length
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
        hash_alg = "shake128"
    elif alg_id["algorithm"] == rfc9481.id_RSASSA_PSS_SHAKE256:
        hash_alg = "shake256"
    else:
        raise BadAlg(f"Unsupported SHAKE-PSS OID: {alg_id['algorithm']}.")
    _verify_rsa_pss_shake(public_key, data, signature, hash_alg, salt_length)


def _verify_rsa_pss_shake(
    public_key: rsa.RSAPublicKey, data: bytes, signature: bytes, hash_alg: str, salt_length: Optional[int]
) -> None:
    """Verify RSASSA-PSS-SHAKE128 / SHAKE256 via PyCryptodome; ``None`` is the digest size, ``0`` a salt of length 0."""
    hash_for_verifying = FixedSHAKE128.new(data) if hash_alg == "shake128" else FixedSHAKE256.new(data)
    numbers = public_key.public_numbers()
    pub_key_tmp = RSA.construct((numbers.n, numbers.e))
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


def _require_hash(hash_alg: Optional[str], key: object) -> str:
    """Return ``hash_alg``; a family that signs a hash has no default, so ``None`` is an error.

    :raises ValueError: If ``hash_alg`` is ``None``.
    """
    if hash_alg is None:
        raise ValueError(f"A {type(key).__name__} signature needs a hash algorithm: pass `hash_alg`, e.g. 'sha256'.")
    return hash_alg


def sign_data(
    data: bytes,
    key: SignKey,
    *,
    hash_alg: Optional[str] = None,
    ctx: bytes = b"",
    use_rsa_pss: bool = False,
    salt_length: Optional[int] = None,
    second_hash_alg: Optional[str] = None,
) -> bytes:
    """Sign ``data`` with the algorithm that ``key`` is, and the options given by name.

    This is the one place that looks at the class of the key. It never reads an ``AlgorithmIdentifier``;
    :func:`sign_with_alg_id` does, and calls this function. There is no default hash: a key family that signs a
    hash needs ``hash_alg``. Dispatches on the type of ``key``:

    * Stateful-hash keys (HSS / XMSS / XMSSMT) sign the message bytes directly.
    * PQ signatures (ML-DSA / SLH-DSA / Falcon) take ``ctx``; ``hash_alg`` selects the pre-hash mode
      (HashML-DSA, HashSLH-DSA) and is optional.
    * Composite-sig (hybrid) keys take ``ctx`` and ``use_rsa_pss`` (the RSASSA-PSS variant of the combination);
      ``hash_alg`` is ignored, the draft fixes the hash.
    * RSA keys sign PKCS#1 v1.5 with ``hash_alg``, or RSASSA-PSS with ``use_rsa_pss=True`` (``hash_alg``,
      ``salt_length``, ``second_hash_alg``; SHAKE128 and SHAKE256 are possible).
    * EC and DSA keys need ``hash_alg``.
    * Ed25519 / Ed448 keys sign the message directly.

    :param data: The message bytes to sign.
    :param key: The signature private key selecting the algorithm.
    :param hash_alg: The hash name, e.g. ``sha256``.
    :param ctx: The context string of ML-DSA, SLH-DSA and composite signatures.
    :param use_rsa_pss: Sign with RSASSA-PSS (RSA keys) or with the PSS combination (composite keys).
    :param salt_length: The RSASSA-PSS salt length in bytes: ``None`` is the digest size, ``0`` is a salt of
        length 0.
    :param second_hash_alg: RSASSA-PSS only: the hash of the message if it differs from the MGF1 hash, to build
        a signature that the RFC 4056 profile refuses.
    :raises ValueError: If the key family needs a hash and ``hash_alg`` is ``None``, or ``hash_alg`` is unknown.
    :raises NotImplementedError: If ``key`` is not a supported signature key type.
    """
    if isinstance(key, PQHashStatefulSigPrivateKey):
        require_oqs_if_needed(key.name)
        return key.sign(data)
    if isinstance(key, CompositeSigPrivateKey):
        return key.sign(data, ctx=ctx, use_pss=use_rsa_pss)
    if isinstance(key, PQSignaturePrivateKey):
        require_oqs_if_needed(key.name)
        return key.sign(data, hash_alg=key.check_hash_alg(hash_alg), ctx=ctx)
    if isinstance(key, rsa.RSAPrivateKey):
        hash_alg = _require_hash(hash_alg, key)
        if use_rsa_pss:
            return sign_data_rsa_pss(
                private_key=key, data=data, hash_alg=hash_alg, salt_length=salt_length, second_hash_alg=second_hash_alg
            )
        return key.sign(data, padding.PKCS1v15(), hash_name_to_instance(hash_alg))
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hash_name_to_instance(_require_hash(hash_alg, key))))
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return key.sign(data)
    if isinstance(key, DSAPrivateKey):
        return key.sign(data, _require_hash(hash_alg, key))
    raise NotImplementedError(f"{type(key).__name__}: {NOT_IMPLEMENTED_HINT}")


def verify_signature(
    public_key: VerifyKey,
    signature: bytes,
    data: bytes,
    *,
    hash_alg: Optional[str] = None,
    ctx: bytes = b"",
    use_rsa_pss: bool = False,
    salt_length: Optional[int] = None,
    use_pre_hash: bool = False,
) -> None:
    """Verify ``signature`` over ``data`` with the algorithm that ``public_key`` is.

    The verification counterpart of :func:`sign_data`, with the same options by the same names and without a
    default hash. Dispatches on the type of ``public_key``:

    * Stateful-hash keys verify the message bytes directly.
    * PQ signatures take ``ctx``, ``hash_alg`` (pre-hash mode) and ``use_pre_hash`` (``data`` is already hashed).
    * Composite-sig keys take ``ctx`` and ``use_rsa_pss``; ``hash_alg`` is ignored.
    * RSA keys verify PKCS#1 v1.5 with ``hash_alg``, or RSASSA-PSS with ``use_rsa_pss=True`` (``hash_alg`` and
      ``salt_length``; SHAKE128 and SHAKE256 are possible).
    * EC and DSA keys need ``hash_alg``. Ed25519 / Ed448 keys verify the message directly.

    :param public_key: The signature public key selecting the algorithm.
    :param signature: The signature bytes to check.
    :param data: The message bytes the signature is over.
    :param hash_alg: The hash name, e.g. ``sha256``.
    :param ctx: The context string of ML-DSA, SLH-DSA and composite signatures.
    :param use_rsa_pss: Verify RSASSA-PSS (RSA keys) or the PSS combination (composite keys).
    :param salt_length: The RSASSA-PSS salt length in bytes: ``None`` is the digest size, ``0`` is a salt of
        length 0.
    :param use_pre_hash: ML-DSA / SLH-DSA only: ``data`` is the hash of the message.
    :raises cryptography.exceptions.InvalidSignature: If the signature does not verify.
    :raises ValueError: If the key family needs a hash and ``hash_alg`` is ``None``, or ``hash_alg`` is unknown.
    :raises NotImplementedError: If ``public_key`` is not a supported signature key type.
    """
    if isinstance(public_key, PQHashStatefulSigPublicKey):
        require_oqs_if_needed(public_key.name)
        public_key.verify(data=data, signature=signature)
        return
    if isinstance(public_key, CompositeSigPublicKey):
        public_key.verify(signature=signature, data=data, ctx=ctx, use_pss=use_rsa_pss)
        return
    if isinstance(public_key, PQSignaturePublicKey):
        require_oqs_if_needed(public_key.name)
        public_key.verify(
            signature=signature,
            data=data,
            hash_alg=public_key.check_hash_alg(hash_alg),
            is_prehashed=use_pre_hash,
            ctx=ctx,
        )
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        hash_alg = _require_hash(hash_alg, public_key)
        if use_rsa_pss and hash_alg in {"shake128", "shake256"}:
            _verify_rsa_pss_shake(public_key, data, signature, hash_alg, salt_length)
        elif use_rsa_pss:
            hash_algorithm = hash_name_to_instance(hash_alg)
            pss_padding = padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=hash_algorithm.digest_size if salt_length is None else salt_length,
            )
            public_key.verify(signature, data, pss_padding, hash_algorithm)
        else:
            public_key.verify(signature, data, padding.PKCS1v15(), hash_name_to_instance(hash_alg))
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_name_to_instance(_require_hash(hash_alg, public_key))))
        return
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, data)
        return
    if isinstance(public_key, DSAPublicKey):
        public_key.verify(signature, data, _require_hash(hash_alg, public_key))
        return
    raise NotImplementedError(f"{type(public_key).__name__}: {NOT_IMPLEMENTED_HINT}")


# ---------------------------------------------------------------------------
# sign_with_alg_id / verify_signature_with_alg_id
# ---------------------------------------------------------------------------


# Runtime ``isinstance`` tuples derived from the SignKey / VerifyKey unions, so the
# accepted key types stay a single source of truth (see ``keyutils_py.types``).
_AllSigPriv = get_args(SignKey)
_AllSigPub = get_args(VerifyKey)


def _check_key_matches(info: SigAlgInfo, key: Any) -> None:
    """Raise :class:`BadSigAlgID` unless ``key`` may be used with the algorithm of the row ``info``.

    This is the one function that knows what "matches" means, for every family and for a private as for a public
    key: RSA and RSASSA-PSS rows take any RSA key (RFC 4055 Section 1.2: an ``rsaEncryption`` key may be used with
    RSASSA-PSS), ECDSA, EdDSA, ML-DSA, SLH-DSA and Falcon rows the key of their name, the stateful rows the key with
    the same OID, and a composite row the composite key whose OID for that padding is the row's OID.

    :raises BadSigAlgID: If the key does not match the row.
    :raises ValueError: If ``key`` is not a key class that ``get_key_name`` knows.
    """
    from keyutils_py.keyutils import get_key_name  # pylint: disable=import-outside-toplevel

    if info.family == "composite":
        matches = False
        if isinstance(key, (CompositeSigPrivateKey, CompositeSigPublicKey)):
            try:
                matches = key.get_oid(use_pss=info.pss) == info.oid
            except InvalidKeyCombination:
                matches = False
    elif info.family in ("hss", "xmss", "xmssmt"):
        matches = isinstance(key, (PQHashStatefulSigPrivateKey, PQHashStatefulSigPublicKey)) and (
            key.get_oid() == info.oid
        )
    else:
        matches = get_key_name(key) == info.key_name
    if not matches:
        raise BadSigAlgID(
            "The key was not of the same type as the algorithm identifier implied.",
            error_details=[f"OID {info.name} ({info.oid}); key {type(key).__name__}"],
        )


def _options_from_row(info: SigAlgInfo, hash_alg: Optional[str]) -> Dict[str, Any]:
    """Return the keyword options of :func:`sign_data` / :func:`verify_signature` that the row ``info`` stands for.

    :raises BadAlg: If the row names no hash for RSA PKCS#1 v1.5 (``rsaEncryption``) and ``hash_alg`` is ``None``.
    :raises BadSigAlgID: If ``hash_alg`` is given and contradicts the hash that the row names.
    """
    if info.hash_alg is not None and hash_alg is not None and hash_alg != info.hash_alg:
        raise BadSigAlgID(f"`hash_alg` {hash_alg!r} contradicts the hash {info.hash_alg!r} of {info.name}.")
    if info.family == "composite":
        return {"use_rsa_pss": info.pss}
    if info.family == "rsa-pss":
        return {"hash_alg": info.hash_alg, "use_rsa_pss": True, "salt_length": info.salt_length}
    if info.family == "rsa":
        if info.hash_alg is None and hash_alg is None:
            raise BadAlg(f"{info.name} names no hash: pass `hash_alg`.")
        return {"hash_alg": info.hash_alg or hash_alg}
    if info.family in ("ecdsa", "dsa") or info.pre_hash:
        return {"hash_alg": info.hash_alg}
    return {}


def sign_with_alg_id(
    key: SignKey, alg_id: rfc9480.AlgorithmIdentifier, data: bytes, *, hash_alg: Optional[str] = None
) -> bytes:
    """Sign ``data`` with the algorithm that ``alg_id`` names.

    Reads the table row of the OID (:func:`keyutils_py.oids.get_sig_alg_info`), checks that ``key`` belongs to it
    and calls :func:`sign_data` with the options of the row. Every key family, the post-quantum, stateful-hash and
    composite ones too, only accepts the identifiers of its own family and parameter set; a key paired with a
    foreign OID is rejected rather than mis-signed. The OID decides how the signature is made: a ML-DSA or SLH-DSA
    pre-hash OID signs in pre-hash mode with the hash it names, a composite ``-pss`` OID signs with RSASSA-PSS, and
    an ``id-RSASSA-PSS`` identifier signs with the hash and the salt length of its parameters (a salt length of 0
    is honoured; omitted fields have the DEFAULT values of RFC 4055 Section 3.1). Absent and NULL parameters of the
    PKCS#1 v1.5 identifiers are both accepted (RFC 4055 Section 5, RFC 5754 Section 3.2).

    :param key: The signature private key. Must match the ``alg_id`` family.
    :param alg_id: The :class:`AlgorithmIdentifier` selecting the algorithm.
    :param data: The message bytes to sign.
    :param hash_alg: The hash for ``rsaEncryption``, which names none (RFC 3370 Section 3.2). For any other
        identifier that names a hash, a different ``hash_alg`` is an error; it is ignored by the identifiers that
        name none (EdDSA, pure ML-DSA, ...).
    :raises BadAlg: If the OID is not a supported signature OID, ``key`` is not a signature key, ``key`` is a DSA
        key (DSA is not supported here), or ``rsaEncryption`` is used without ``hash_alg``.
    :raises BadSigAlgID: If ``key`` does not match the algorithm identifier, or ``hash_alg`` contradicts it.
    :raises BadSigAlgIDParams: If the ``alg_id`` parameters are invalid for the OID.
    """
    info = get_sig_alg_info(alg_id)
    if not isinstance(key, _AllSigPriv):
        raise BadAlg(f"Key is not a signature private key (got {type(key).__name__}).")
    if isinstance(key, DSAPrivateKey):
        raise BadAlg("DSA algorithm is not supported.")
    _check_key_matches(info, key)
    return sign_data(data, key, **_options_from_row(info, hash_alg))


def verify_signature_with_alg_id(
    public_key: VerifyKey,
    alg_id: rfc9480.AlgorithmIdentifier,
    data: bytes,
    signature: bytes,
    *,
    hash_alg: Optional[str] = None,
) -> None:
    """Verify ``signature`` over ``data`` with the algorithm that ``alg_id`` names.

    The verification counterpart of :func:`sign_with_alg_id`, with the same rules for the key, the OID and the
    parameters. RSA-SHA1 (``sha1WithRSAEncryption``) is verified: whether to refuse it is the policy of the caller,
    who can read the hash from :func:`keyutils_py.oids.get_sig_alg_info`.

    :param public_key: The signature public key. Must match the ``alg_id`` family.
    :param alg_id: The :class:`AlgorithmIdentifier` selecting the algorithm.
    :param data: The message bytes the signature is over.
    :param signature: The signature bytes to check.
    :param hash_alg: The hash for ``rsaEncryption``; see :func:`sign_with_alg_id`.
    :raises BadAlg: If the OID is not a supported signature OID, ``public_key`` is not a signature key, ``public_key``
        is a DSA key (DSA is not supported here), or ``rsaEncryption`` is used without ``hash_alg``.
    :raises BadSigAlgID: If ``public_key`` does not match the algorithm identifier, or ``hash_alg`` contradicts it.
    :raises BadSigAlgIDParams: If the ``alg_id`` parameters are invalid for the OID.
    :raises cryptography.exceptions.InvalidSignature: If the signature does not verify.
    """
    info = get_sig_alg_info(alg_id)
    if not isinstance(public_key, _AllSigPub):
        raise BadAlg(f"Public key is not a signature public key (got {type(public_key).__name__}).")
    if isinstance(public_key, DSAPublicKey):
        raise BadAlg("DSA algorithm is not supported.")
    _check_key_matches(info, public_key)
    verify_signature(public_key, signature, data, **_options_from_row(info, hash_alg))


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
