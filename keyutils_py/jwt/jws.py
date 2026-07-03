# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Sign and verify compact JWS tokens (the JWT wire form) with any supported key.

Produces and verifies the RFC 7515 compact serialisation
``b64u(protected) "." b64u(payload) "." b64u(signature)`` for:

* RSA — ``RS256``/``384``/``512`` (PKCS#1 v1.5) and ``PS256``/``384``/``512`` (PSS).
* EC — ``ES256``/``384``/``512`` (P-256/384/521) and ``ES256K`` (secp256k1, RFC 8812).
* OKP — ``EdDSA`` (Ed25519 / Ed448, RFC 8037).
* AKP — ``ML-DSA-44``/``65``/``87`` and ``SLH-DSA-…`` (draft-ietf-cose-dilithium,
  draft-ietf-cose-sphincs-plus).
* Composite — ``ML-DSA-xx-<trad>`` (draft-ietf-jose-pq-composite-sigs).

ECDSA signatures are emitted/consumed as fixed-length raw ``R‖S`` (JOSE), not DER.
Verification checks the signature only — callers validate ``exp``/``nbf``/``iat``.
``alg`` is rejected unless it is valid for the key (and, when supplied, in the
caller's ``algorithms`` allowlist); ``"none"`` is always rejected.
"""

import json
from typing import Any, Dict, Iterable, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from keyutils_py.compute import sign_data, verify_signature
from keyutils_py.exceptions import InvalidJWK, InvalidJWS
from keyutils_py.jwt.jw_mapping import (
    AKP_NAME_2_ALG,
    COMPOSITE_NAME_2_ALG,
    EC_CURVE_2_CRV,
    akp_alg_to_name,
    composite_alg_to_name,
    ec_coordinate_length,
    jwk_family,
)
from keyutils_py.jwt.jwt_utils import b64u_decode, b64u_encode
from keyutils_py.keys.abstract_wrapper_keys import WrapperPrivateKey
from keyutils_py.oids import hash_name_to_instance

__all__ = [
    "sign_jws",
    "verify_jws",
    "sign_jwt",
    "verify_jwt",
]

# JOSE alg -> hash name (RFC 7518 §3).
_RSA_ALG_2_HASH = {
    "RS256": "sha256",
    "RS384": "sha384",
    "RS512": "sha512",
    "PS256": "sha256",
    "PS384": "sha384",
    "PS512": "sha512",
}
_EC_ALG_2_HASH = {"ES256": "sha256", "ES384": "sha384", "ES512": "sha512", "ES256K": "sha256"}
# JWK crv -> EC JOSE alg (and back).
_CRV_2_EC_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512", "secp256k1": "ES256K"}
_EC_ALG_2_CRV = {v: k for k, v in _CRV_2_EC_ALG.items()}

_PRIVATE_KEY_TYPES = (
    WrapperPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
)
_EDDSA_TYPES = (
    ed25519.Ed25519PublicKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PublicKey,
    ed448.Ed448PrivateKey,
)


# ==========================================================================
# Public API
# ==========================================================================


def sign_jwt(
    claims: Dict[str, Any],
    key: Any,
    *,
    alg: Optional[str] = None,
    headers: Optional[Dict[str, Any]] = None,
    kid: Optional[str] = None,
) -> str:
    """Sign a JWT: JSON-encode ``claims`` and return a compact JWS with ``typ="JWT"``.

    :param claims: The JWT claims set (serialised as compact JSON).
    :param key: The signing private key.
    :param alg: JOSE ``alg``; inferred from the key when ``None``.
    :param headers: Extra protected-header members (merged; ``alg`` is fixed).
    :param kid: Optional ``kid`` protected-header value.
    :returns: The compact JWS string.
    :raises InvalidJWS: If the key cannot sign or ``alg`` is invalid for it.
    """
    protected: Dict[str, Any] = {"typ": "JWT"}
    if headers:
        protected.update(headers)
    if kid is not None:
        protected["kid"] = kid
    payload = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    return sign_jws(payload, key, alg=alg, protected=protected)


def sign_jws(
    payload: Union[bytes, str],
    key: Any,
    *,
    alg: Optional[str] = None,
    protected: Optional[Dict[str, Any]] = None,
) -> str:
    """Sign ``payload`` and return a compact JWS.

    :param payload: The payload bytes (``str`` is UTF-8 encoded).
    :param key: The signing private key.
    :param alg: JOSE ``alg``; inferred from the key when ``None``.
    :param protected: Extra protected-header members (``alg`` is always set).
    :returns: The compact JWS ``header.payload.signature``.
    :raises InvalidJWS: If the key cannot sign or ``alg`` is invalid for it.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    if alg is None:
        alg = _default_alg(key)
    elif alg not in _algs_for_key(key):
        raise InvalidJWS(f"alg {alg!r} is not valid for a {type(key).__name__} key.")

    header: Dict[str, Any] = {"alg": alg}
    if protected:
        header.update(protected)
        header["alg"] = alg  # never let extra headers override the signing alg

    header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64u_encode(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _sign(signing_input, key, alg)
    return f"{header_b64}.{payload_b64}.{b64u_encode(signature)}"


def verify_jwt(token: str, key: Any, *, algorithms: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Verify a JWT's signature and return its claims set.

    :param token: The compact JWS string.
    :param key: The verifying key (public, or a private key to derive it from).
    :param algorithms: Optional allowlist of acceptable ``alg`` values.
    :returns: The decoded claims set.
    :raises InvalidJWS: If the token is malformed, the ``alg`` is not permitted,
        the signature is invalid, or the payload is not a JSON object.
    """
    _, payload = verify_jws(token, key, algorithms=algorithms)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise InvalidJWS(f"JWT payload is not valid JSON: {exc}") from exc


def verify_jws(
    token: str,
    key: Any,
    *,
    algorithms: Optional[Iterable[str]] = None,
) -> Tuple[Dict[str, Any], bytes]:
    """Verify a compact JWS and return ``(protected_header, payload_bytes)``.

    :param token: The compact JWS string.
    :param key: The verifying key (public, or a private key to derive it from).
    :param algorithms: Optional allowlist of acceptable ``alg`` values; the
        token ``alg`` must also be one the key supports.
    :raises InvalidJWS: If the token is malformed, the ``alg`` is ``"none"`` or
        not permitted for the key, or the signature does not verify.
    """
    if not isinstance(token, str):
        raise InvalidJWS(f"token must be a string, got {type(token).__name__}.")
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidJWS("a compact JWS must have exactly three '.'-separated segments.")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(b64u_decode(header_b64))
    except (InvalidJWK, json.JSONDecodeError, ValueError) as exc:
        raise InvalidJWS(f"invalid JWS protected header: {exc}") from exc
    if not isinstance(header, dict):
        raise InvalidJWS("JWS protected header must be a JSON object.")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg.lower() == "none":
        raise InvalidJWS(f"unsupported or missing 'alg': {alg!r}.")

    public_key = _public_key(key)
    permitted = _algs_for_key(public_key)
    if algorithms is not None:
        permitted &= set(algorithms)
    if alg not in permitted:
        raise InvalidJWS(f"alg {alg!r} is not permitted for this key.")

    try:
        signature = b64u_decode(signature_b64)
        payload = b64u_decode(payload_b64)
    except InvalidJWK as exc:
        raise InvalidJWS(f"invalid base64url in token: {exc}") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    _verify(signing_input, signature, public_key, alg)
    return header, payload


# ==========================================================================
# alg resolution
# ==========================================================================


def _family(key: Any) -> str:
    try:
        return jwk_family(key)
    except InvalidJWK as exc:
        raise InvalidJWS(str(exc)) from exc


def _algs_for_key(key: Any) -> set:
    """Return the set of JOSE ``alg`` values this key may sign/verify with."""
    family = _family(key)
    if family == "rsa":
        return set(_RSA_ALG_2_HASH)
    if family == "ec":
        crv = EC_CURVE_2_CRV.get(key.curve.name)
        if crv is None or crv not in _CRV_2_EC_ALG:
            raise InvalidJWS(f"EC curve {key.curve.name!r} has no JOSE signature alg.")
        return {_CRV_2_EC_ALG[crv]}
    if family == "okp":
        if isinstance(key, _EDDSA_TYPES):
            return {"EdDSA"}
        raise InvalidJWS("X25519/X448 keys are key-agreement keys and cannot sign JWTs.")
    if family == "akp":
        name = key.name
        if name.startswith("ml-kem"):
            raise InvalidJWS("ML-KEM is a KEM and cannot sign JWTs.")
        alg = AKP_NAME_2_ALG.get(name)
        if alg is None:
            raise InvalidJWS(f"{name!r} is not a JOSE signature algorithm.")
        return {alg}
    if family == "composite":
        algs = {COMPOSITE_NAME_2_ALG[nm] for nm in (key.name, f"{key.name}-pss") if nm in COMPOSITE_NAME_2_ALG}
        if not algs:
            raise InvalidJWS(f"{key.name!r} is not a JOSE composite signature algorithm.")
        return algs
    raise InvalidJWS(f"unsupported key family: {family}.")  # pragma: no cover


def _default_alg(key: Any) -> str:
    """Return the default JOSE ``alg`` for ``key`` (RSA defaults to RS256)."""
    family = _family(key)
    if family == "rsa":
        return "RS256"
    if family == "ec":
        crv = EC_CURVE_2_CRV.get(key.curve.name)
        if crv is None or crv not in _CRV_2_EC_ALG:
            raise InvalidJWS(f"EC curve {key.curve.name!r} has no JOSE signature alg.")
        return _CRV_2_EC_ALG[crv]
    if family == "okp":
        if isinstance(key, _EDDSA_TYPES):
            return "EdDSA"
        raise InvalidJWS("X25519/X448 keys are key-agreement keys and cannot sign JWTs.")
    if family == "akp":
        name = key.name
        if name.startswith("ml-kem"):
            raise InvalidJWS("ML-KEM is a KEM and cannot sign JWTs.")
        alg = AKP_NAME_2_ALG.get(name)
        if alg is None:
            raise InvalidJWS(f"{name!r} is not a JOSE signature algorithm.")
        return alg
    if family == "composite":
        alg = COMPOSITE_NAME_2_ALG.get(key.name)
        if alg is None:
            raise InvalidJWS(f"{key.name!r} is not a JOSE composite signature algorithm.")
        return alg
    raise InvalidJWS(f"unsupported key family: {family}.")  # pragma: no cover


def _public_key(key: Any) -> Any:
    """Return the public half of ``key`` (or ``key`` itself if already public)."""
    if isinstance(key, _PRIVATE_KEY_TYPES):
        return key.public_key()
    return key


# ==========================================================================
# sign / verify dispatch
# ==========================================================================


def _sign(signing_input: bytes, key: Any, alg: str) -> bytes:
    if alg in _RSA_ALG_2_HASH:
        hash_instance = hash_name_to_instance(_RSA_ALG_2_HASH[alg])
        if alg.startswith("PS"):
            pss = padding.PSS(mgf=padding.MGF1(hash_instance), salt_length=hash_instance.digest_size)
            return key.sign(signing_input, pss, hash_instance)
        return key.sign(signing_input, padding.PKCS1v15(), hash_instance)
    if alg in _EC_ALG_2_HASH:
        hash_instance = hash_name_to_instance(_EC_ALG_2_HASH[alg])
        der = key.sign(signing_input, ec.ECDSA(hash_instance))
        r, s = decode_dss_signature(der)
        length = ec_coordinate_length(key.curve)
        return r.to_bytes(length, "big") + s.to_bytes(length, "big")
    if alg == "EdDSA":
        return key.sign(signing_input)
    if akp_alg_to_name(alg):
        return sign_data(signing_input, key, ctx=b"")
    internal = composite_alg_to_name(alg)
    if internal:
        return sign_data(signing_input, key, ctx=b"", use_pss=internal.endswith("-pss"))
    raise InvalidJWS(f"unsupported alg: {alg!r}.")  # pragma: no cover


def _verify(signing_input: bytes, signature: bytes, public_key: Any, alg: str) -> None:
    try:
        if alg in _RSA_ALG_2_HASH:
            hash_instance = hash_name_to_instance(_RSA_ALG_2_HASH[alg])
            if alg.startswith("PS"):
                pss = padding.PSS(mgf=padding.MGF1(hash_instance), salt_length=hash_instance.digest_size)
                public_key.verify(signature, signing_input, pss, hash_instance)
            else:
                public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_instance)
        elif alg in _EC_ALG_2_HASH:
            length = ec_coordinate_length(public_key.curve)
            if len(signature) != 2 * length:
                raise InvalidJWS("ECDSA signature has an invalid length for the curve.")
            r = int.from_bytes(signature[:length], "big")
            s = int.from_bytes(signature[length:], "big")
            hash_instance = hash_name_to_instance(_EC_ALG_2_HASH[alg])
            public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hash_instance))
        elif alg == "EdDSA":
            public_key.verify(signature, signing_input)
        elif akp_alg_to_name(alg):
            verify_signature(public_key, signature, signing_input, ctx=b"")
        else:
            internal = composite_alg_to_name(alg)
            if not internal:
                raise InvalidJWS(f"unsupported alg: {alg!r}.")  # pragma: no cover
            verify_signature(public_key, signature, signing_input, ctx=b"", use_pss=internal.endswith("-pss"))
    except InvalidSignature as exc:
        raise InvalidJWS("signature verification failed.") from exc
