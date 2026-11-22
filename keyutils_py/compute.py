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
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union, get_args

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, x448, x25519
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc9480, rfc9481

from keyutils_py._algs import KT_BY_OID
from keyutils_py.data_objects import FixedSHAKE128, FixedSHAKE256
from keyutils_py.exceptions import (
    BadAlg,
    BadAlgParams,
    BadDataFormat,
    BadSigAlgID,
    IntegrityError,
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
    _HASH_OID_2_NAME,
    CURVE_2_COFACTORS,
    SigAlgInfo,
    _is_parameters_null,
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
    allow_sha1: bool = False,
) -> None:
    """Verify ``signature`` over ``data`` with the algorithm that ``alg_id`` names.

    The verification counterpart of :func:`sign_with_alg_id`, with the same rules for the key, the OID and the
    parameters. Verification is a trust decision, so a SHA-1 signature is refused unless the caller passes
    ``allow_sha1=True``: ``sha1WithRSAEncryption``, ``rsaEncryption`` with ``hash_alg="sha1"``, and RSASSA-PSS whose
    hash or MGF1 hash is SHA-1, which includes the parameters that leave every field out (RFC 4055 Section 3.1).
    Signing is not restricted, and :func:`verify_signature` takes the hash from its caller.

    :param public_key: The signature public key. Must match the ``alg_id`` family.
    :param alg_id: The :class:`AlgorithmIdentifier` selecting the algorithm.
    :param data: The message bytes the signature is over.
    :param signature: The signature bytes to check.
    :param hash_alg: The hash for ``rsaEncryption``; see :func:`sign_with_alg_id`.
    :param allow_sha1: Verify SHA-1 signatures instead of refusing them.
    :raises BadAlg: If the OID is not a supported signature OID, ``public_key`` is not a signature key, ``public_key``
        is a DSA key (DSA is not supported here), ``rsaEncryption`` is used without ``hash_alg``, or the signature
        uses SHA-1 and ``allow_sha1`` is false.
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
    options = _options_from_row(info, hash_alg)
    if not allow_sha1 and "sha1" in (options.get("hash_alg"), info.mgf1_hash_alg):
        raise BadAlg(f"{info.name} uses SHA-1; pass `allow_sha1=True` to verify it.")
    verify_signature(public_key, signature, data, **options)


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
# RSA key transport (RSAES-PKCS1-v1_5 and RSAES-OAEP)
# ---------------------------------------------------------------------------

MAX_OAEP_LABEL_LENGTH = 4096
"""The longest OAEP label, in octets, that a received identifier may carry (fail-closed; the label is hashed)."""

# The hash functions of RFC 4055 Section 2.1 (RFC 8017 Appendix B.1 lists these five and SHA-512/224 and SHA-512/256).
_OAEP_HASHES = ("sha1", "sha224", "sha256", "sha384", "sha512")


@dataclass(frozen=True)
class _OaepParameters:
    """The fields of ``RSAES-OAEP-params`` (RFC 4055 Section 4.1) after the checks and the DEFAULTs."""

    hash: str
    mgf1_hash: str
    label: bytes


def _der_of(parameters: Any) -> bytes:
    """Return the DER of the ``parameters`` field of an ``AlgorithmIdentifier``, which holds DER or a decoded object."""
    return parameters.asOctets() if isinstance(parameters, univ.Any) else encode_to_der(parameters)


def _oaep_hash(hash_alg_id: Any, what: str) -> str:
    """Return the name of the hash of an ``AlgorithmIdentifier`` inside RSAES-OAEP-params.

    :raises BadAlg: If the OID is no SHA-1 or SHA-2 hash.
    :raises BadAlgParams: If the parameters are neither absent nor NULL (RFC 4055 Section 2.1: both are legal).
    """
    name = _HASH_OID_2_NAME.get(hash_alg_id["algorithm"])
    if name not in _OAEP_HASHES:
        raise BadAlg(f"{hash_alg_id['algorithm']} is not a hash of {what}: RFC 4055 Section 2.1 has SHA-1 and SHA-2.")
    parameters = hash_alg_id["parameters"]
    if parameters.isValue and not _is_parameters_null(parameters):
        raise BadAlgParams(f"The parameters of the hash of {what} must be absent or NULL.")
    return name


def _oaep_mgf1_hash(mask_gen: Any) -> str:
    """Return the hash of the ``maskGenFunc`` of RSAES-OAEP-params, which must be MGF1 over an identifier of a hash.

    :raises BadAlg: If the function is not id-mgf1, or the hash is no SHA-1 or SHA-2 hash.
    :raises BadAlgParams: If the parameters are absent, are the bare OID of a hash (which the callers of this package
        wrote before; RFC 4055 Section 2.2 says an ``AlgorithmIdentifier``), or have data after them.
    :raises BadAsn1Data: If the parameters do not decode.
    """
    if mask_gen["algorithm"] != rfc4055.id_mgf1:
        raise BadAlg(f"{mask_gen['algorithm']} is not id-mgf1, the only mask generation function of RFC 4055.")
    if not mask_gen["parameters"].isValue:
        raise BadAlgParams("The parameters of id-mgf1 are the AlgorithmIdentifier of a hash (RFC 4055 Section 2.2).")
    der = _der_of(mask_gen["parameters"])
    if der[:1] == b"\x06":
        raise BadAlgParams(
            "The parameters of id-mgf1 are a bare OID; RFC 4055 Section 2.2 wants an AlgorithmIdentifier."
        )
    hash_alg_id, rest = try_decode_pyasn1(der, rfc9480.AlgorithmIdentifier())
    if rest:
        raise BadAlgParams("The parameters of id-mgf1 have trailing data.")
    return _oaep_hash(hash_alg_id, "id-mgf1")


def _oaep_label(p_source: Any) -> bytes:
    """Return the label of the ``pSourceFunc`` of RSAES-OAEP-params.

    :raises BadAlg: If the function is not id-pSpecified.
    :raises BadAlgParams: If the label is absent, has trailing data, or is longer than ``MAX_OAEP_LABEL_LENGTH``.
    :raises BadAsn1Data: If the label does not decode as an OCTET STRING.
    """
    if p_source["algorithm"] != rfc4055.id_pSpecified:
        raise BadAlg(f"{p_source['algorithm']} is not id-pSpecified, the only source of the label (RFC 4055).")
    if not p_source["parameters"].isValue:
        raise BadAlgParams("The parameters of id-pSpecified are the label, an OCTET STRING (RFC 4055 Section 4.1).")
    label, rest = try_decode_pyasn1(_der_of(p_source["parameters"]), univ.OctetString())
    if rest:
        raise BadAlgParams("The label of id-pSpecified has trailing data.")
    if len(label) > MAX_OAEP_LABEL_LENGTH:
        raise BadAlgParams(f"The OAEP label has {len(label)} octets, more than the limit of {MAX_OAEP_LABEL_LENGTH}.")
    return label.asOctets()


def _read_oaep_parameters(alg_id: rfc9480.AlgorithmIdentifier) -> _OaepParameters:
    """Read the ``RSAES-OAEP-params`` of an id-RSAES-OAEP identifier in the form of RFC 4055.

    Absent ``hashFunc`` and ``maskGenFunc`` are SHA-1 and an absent ``pSourceFunc`` is the empty label (the DEFAULTs of
    RFC 4055 Section 4.1). The parameters themselves must be present: the SEQUENCE, empty for the defaults.

    :raises BadAlg: If a hash is no SHA-1 or SHA-2 hash, the mask generation function is not MGF1 or the label source
        is not id-pSpecified.
    :raises BadAlgParams: If the parameters are absent, have trailing data, or a field is wrong (see the helpers).
    :raises BadAsn1Data: If the parameters do not decode.
    """
    if not alg_id["parameters"].isValue:
        raise BadAlgParams("The parameters of id-RSAES-OAEP are the RSAES-OAEP-params SEQUENCE (RFC 4055 Section 4.1).")
    params, rest = try_decode_pyasn1(_der_of(alg_id["parameters"]), rfc4055.RSAES_OAEP_params())
    if rest:
        raise BadAlgParams("The parameters of id-RSAES-OAEP have trailing data.")
    hash_func, mask_gen, p_source = params["hashFunc"], params["maskGenFunc"], params["pSourceFunc"]
    return _OaepParameters(
        hash=_oaep_hash(hash_func, "RSAES-OAEP") if hash_func.isValue else "sha1",
        mgf1_hash=_oaep_mgf1_hash(mask_gen) if mask_gen.isValue else "sha1",
        label=_oaep_label(p_source) if p_source.isValue else b"",
    )


def _resolve_rsa_key_transport_padding(
    alg_id: rfc9480.AlgorithmIdentifier, *, allow_sha1: bool
) -> padding.AsymmetricPadding:
    """Return the padding that an RSA key transport identifier names.

    :raises TypeError: If ``alg_id`` is no ``AlgorithmIdentifier``.
    :raises BadAlg: If the OID is not ``rsaEncryption`` or ``id-RSAES-OAEP``, or the OAEP parameters name SHA-1 (as the
        hash, as the MGF1 hash, or by leaving the field out) and ``allow_sha1`` is false.
    :raises BadAlgParams: If the parameters are wrong for the OID.
    :raises BadAsn1Data: If the ``RSAES-OAEP-params`` cannot be decoded.
    """
    if not isinstance(alg_id, univ.Sequence):
        raise TypeError(f"The key transport algorithm must be an AlgorithmIdentifier, not {type(alg_id).__name__}.")
    row = KT_BY_OID.get(alg_id["algorithm"]) if alg_id["algorithm"].isValue else None
    if row is None:
        raise BadAlg(f"Unsupported key-transport OID: {alg_id['algorithm']}. Only `rsaEncryption` and `id-RSAES-OAEP`.")
    if row.padding == "pkcs1v15":
        parameters = alg_id["parameters"]
        if parameters.isValue and not _is_parameters_null(parameters):
            raise BadAlgParams("The parameters of `rsaEncryption` must be absent or NULL (RFC 3370 Section 4.2.1).")
        return padding.PKCS1v15()
    oaep = _read_oaep_parameters(alg_id)
    if not allow_sha1 and "sha1" in (oaep.hash, oaep.mgf1_hash):
        raise BadAlg("RSAES-OAEP over SHA-1 is refused unless the caller passes `allow_sha1=True`.")
    return padding.OAEP(
        mgf=padding.MGF1(hash_name_to_instance(oaep.mgf1_hash)),
        algorithm=hash_name_to_instance(oaep.hash),
        label=oaep.label or None,
    )


def decrypt_data_with_public_key_alg_id(
    private_key: rsa.RSAPrivateKey,
    alg_id: rfc9480.AlgorithmIdentifier,
    ciphertext: bytes,
    *,
    allow_sha1: bool = False,
) -> bytes:
    """Decrypt ``ciphertext`` with the RSA key transport algorithm that ``alg_id`` names.

    * ``rsaEncryption`` (RSAES-PKCS1-v1_5): the parameters are absent or NULL.
    * ``id-RSAES-OAEP``: the parameters are ``RSAES-OAEP-params`` in the form of RFC 4055 Section 4.1: the hash and
      the MGF1 hash as ``AlgorithmIdentifier`` values with NULL or no parameters (SHA-1 or SHA-2), the label as
      id-pSpecified. A field that is absent is its DEFAULT, SHA-1 or the empty label. The old form of this package,
      a bare hash OID as the parameter of id-mgf1, is :class:`~keyutils_py.exceptions.BadAlgParams`.

    Opening is a trust decision, so OAEP over SHA-1, including by the defaults of absent fields, is refused unless
    ``allow_sha1`` is true, as in :func:`verify_signature_with_alg_id`. The identifier is read before the key is used.

    A failed decryption is one error whatever the cause (a wrong key, a changed or short ciphertext, a wrong label,
    bad padding): no detail that a padding oracle could use. RSAES-PKCS1-v1_5 under OpenSSL 3.2 and later does not
    always fail: it may return a pseudorandom plaintext for an invalid ciphertext (implicit rejection), which the
    caller finds out when the key it carries does not unwrap or decrypt.

    :param private_key: Recipient RSA private key.
    :param alg_id: Key-encryption ``AlgorithmIdentifier``.
    :param ciphertext: Encrypted bytes to decrypt.
    :param allow_sha1: Accept RSAES-OAEP over SHA-1.
    :raises TypeError: If ``alg_id`` is no ``AlgorithmIdentifier``.
    :raises InvalidKeyCombination: If ``private_key`` is no RSA private key.
    :raises BadAlg: If the OID is not ``rsaEncryption`` or ``id-RSAES-OAEP``, an OAEP hash is no SHA-1 or SHA-2 hash,
        the mask generation function is not MGF1, the label source is not id-pSpecified, or OAEP names SHA-1 without
        ``allow_sha1``.
    :raises BadAlgParams: If the parameters are absent, wrong or inconsistent for the OID.
    :raises BadAsn1Data: If the ``RSAES-OAEP-params`` cannot be decoded.
    :raises IntegrityError: If the decryption fails.
    """
    key_padding = _resolve_rsa_key_transport_padding(alg_id, allow_sha1=allow_sha1)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise InvalidKeyCombination(f"RSA key transport needs an RSA private key, not {type(private_key).__name__}.")
    try:
        return private_key.decrypt(ciphertext, key_padding)
    except ValueError:
        raise IntegrityError("RSA key transport decryption failed.") from None


def encrypt_data_with_public_key_alg_id(
    public_key: rsa.RSAPublicKey,
    alg_id: rfc9480.AlgorithmIdentifier,
    data: bytes,
) -> bytes:
    """Encrypt ``data`` with the RSA key transport algorithm that ``alg_id`` names.

    The inverse of :func:`decrypt_data_with_public_key_alg_id`, with the same reading of ``alg_id``; encryption is not
    restricted, so OAEP over SHA-1 can be produced. ``keyutils_py.make_alg_id("key_transport", ...)`` writes the
    identifier.

    :param public_key: Recipient RSA public key.
    :param alg_id: Key-encryption ``AlgorithmIdentifier``.
    :param data: Plaintext to encrypt (typically a content-encryption key).
    :raises TypeError: If ``alg_id`` is no ``AlgorithmIdentifier``.
    :raises InvalidKeyCombination: If ``public_key`` is no RSA public key.
    :raises BadAlg: As :func:`decrypt_data_with_public_key_alg_id`, except for SHA-1.
    :raises BadAlgParams: As :func:`decrypt_data_with_public_key_alg_id`.
    :raises BadAsn1Data: As :func:`decrypt_data_with_public_key_alg_id`.
    :raises ValueError: If ``data`` is too long for the key and the padding.
    """
    key_padding = _resolve_rsa_key_transport_padding(alg_id, allow_sha1=True)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise InvalidKeyCombination(f"RSA key transport needs an RSA public key, not {type(public_key).__name__}.")
    return public_key.encrypt(data, key_padding)


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
    """Extract and decode the public key from a :class:`CMPCertificate`.

    :raises BadAlg: If cryptography cannot load the key, as :func:`keyutils_py.load_public_key_from_spki` does.
    """
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    der = encode_to_der(spki)
    try:
        return serialization.load_der_public_key(der)
    except UnsupportedAlgorithm as err:
        raise BadAlg(f"cryptography cannot load the certificate's public key: {err}") from err


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
]
