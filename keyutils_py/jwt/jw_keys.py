# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Serialise and deserialise keys to and from the JSON Web Key (JWK) format.

Supported key families and their references:

* ``EC``  — NIST P-256/P-384/P-521 and ``secp256k1`` (RFC 7518 §6.2, RFC 8812).
* ``OKP`` — Ed25519, Ed448, X25519, X448 (RFC 8037).
* ``RSA`` — RFC 7518 §6.3.
* ``AKP`` — ML-DSA, ML-KEM and SLH-DSA (draft-ietf-cose-dilithium,
  draft-ietf-jose-pqc-kem, draft-ietf-cose-sphincs-plus).
* ``AKP`` composite signatures — draft-ietf-jose-pq-composite-sigs.

The public entry points are :func:`key_to_jwk` / :func:`key_from_jwk` (dict) and
:func:`dumps` / :func:`loads` (JSON string). Binary members are *unpadded*
base64url; AKP ``priv`` members carry the algorithm seed for ML-DSA/ML-KEM and
the full secret key for SLH-DSA, per the respective drafts.
"""

import json
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from keyutils_py.exceptions import InvalidJWK
from keyutils_py.factories.hybrid_factory import HybridKeyFactory
from keyutils_py.jwt.jw_mapping import (
    AKP_NAME_2_ALG,
    COMPOSITE_NAME_2_ALG,
    EC_CRV_2_CURVE,
    EC_CURVE_2_CRV,
    akp_alg_to_name,
    composite_alg_to_name,
    ec_coordinate_length,
    jwk_family,
)
from keyutils_py.jwt.jwt_utils import b64u_decode, b64u_encode, b64u_to_int, int_to_b64u, jwk_thumbprint
from keyutils_py.keys.abstract_wrapper_keys import WrapperPrivateKey
from keyutils_py.keys.composite_sig import CompositeSigPublicKey
from keyutils_py.keys.kem_keys import MLKEMPrivateKey, MLKEMPublicKey
from keyutils_py.keys.sig_keys import MLDSAPrivateKey, MLDSAPublicKey, SLHDSAPrivateKey, SLHDSAPublicKey
from keyutils_py.oids import COMPOSITE_SIG_NAME_TO_OID

__all__ = [
    "JWK",
    "key_to_jwk",
    "key_from_jwk",
    "dumps",
    "loads",
    "jwk_thumbprint",
]

JWK = Dict[str, Any]

_PRIVATE_TYPES = (
    WrapperPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
)

# AKP concrete classes keyed by canonical-name prefix.
_AKP_CLASSES = {
    "ml-dsa": (MLDSAPublicKey, MLDSAPrivateKey),
    "ml-kem": (MLKEMPublicKey, MLKEMPrivateKey),
    "slh-dsa": (SLHDSAPublicKey, SLHDSAPrivateKey),
}

_OKP_PUB_CTOR = {
    "Ed25519": ed25519.Ed25519PublicKey.from_public_bytes,
    "Ed448": ed448.Ed448PublicKey.from_public_bytes,
    "X25519": x25519.X25519PublicKey.from_public_bytes,
    "X448": x448.X448PublicKey.from_public_bytes,
}
_OKP_PRIV_CTOR = {
    "Ed25519": ed25519.Ed25519PrivateKey.from_private_bytes,
    "Ed448": ed448.Ed448PrivateKey.from_private_bytes,
    "X25519": x25519.X25519PrivateKey.from_private_bytes,
    "X448": x448.X448PrivateKey.from_private_bytes,
}


def _is_private_key(key: object) -> bool:
    """Return ``True`` if ``key`` is a private-key object."""
    return isinstance(key, _PRIVATE_TYPES)


def _require(jwk: JWK, name: str) -> Any:
    """Return ``jwk[name]`` or raise :class:`InvalidJWK` if it is absent."""
    if name not in jwk:
        raise InvalidJWK(f"JWK is missing required member {name!r}.")
    return jwk[name]


# ==========================================================================
# Public API
# ==========================================================================


def key_to_jwk(
    key: object,
    *,
    is_private: Optional[bool] = None,
    include_kid: bool = False,
    extra: Optional[Dict[str, Any]] = None,
    allow_expanded_priv: bool = False,
) -> JWK:
    """Serialise a key to a JWK dict.

    :param key: A traditional ``cryptography`` key or a ``keyutils_py`` wrapper
        key (EC, OKP, RSA, ML-DSA, ML-KEM, SLH-DSA, or composite signature).
    :param is_private: Force public/private output. ``None`` infers from the key
        type; ``False`` on a private key emits only the public members.
    :param include_kid: When ``True``, populate ``kid`` with the RFC 7638
        thumbprint of the public members.
    :param extra: Additional JWK members merged into the result (e.g. ``use``,
        ``key_ops``). Existing members are not overwritten.
    :param allow_expanded_priv: For ML-DSA/ML-KEM keys lacking a seed, emit the
        expanded private bytes in ``priv`` instead of raising. The result is only
        interoperable within this library (non-conformant with the drafts).
    :returns: The JWK as a dict.
    :raises InvalidJWK: If the key type has no JWK representation, or a required
        seed is unavailable and ``allow_expanded_priv`` is ``False``.
    """
    family = jwk_family(key)

    if is_private is None:
        is_private = _is_private_key(key)
    elif is_private and not _is_private_key(key):
        raise InvalidJWK("is_private=True but the supplied key is a public key.")

    if not is_private and _is_private_key(key):
        key = key.public_key()  # type: ignore[attr-defined]

    if family == "ec":
        jwk = _ec_to_jwk(key, is_private)
    elif family == "okp":
        jwk = _okp_to_jwk(key, is_private)
    elif family == "rsa":
        jwk = _rsa_to_jwk(key, is_private)
    elif family == "akp":
        jwk = _akp_to_jwk(key, is_private, allow_expanded_priv)
    elif family == "composite":
        jwk = _composite_to_jwk(key, is_private)
    else:  # pragma: no cover - jwk_family only returns the families above
        raise InvalidJWK(f"Unsupported key family: {family}.")

    if extra:
        for name, value in extra.items():
            jwk.setdefault(name, value)

    if include_kid:
        jwk["kid"] = jwk_thumbprint(jwk)

    return jwk


def key_from_jwk(jwk: JWK, *, expect_private: Optional[bool] = None) -> object:
    """Deserialise a key from a JWK dict.

    :param jwk: The JWK as a dict.
    :param expect_private: ``None`` infers public/private from the presence of a
        private member (``d`` or ``priv``). ``True`` requires a private member;
        ``False`` returns the public key even if a private member is present.
    :returns: The reconstructed key object.
    :raises InvalidJWK: If the JWK is malformed or describes an unsupported type.
    """
    if not isinstance(jwk, dict):
        raise InvalidJWK(f"Expected a JWK dict, got {type(jwk).__name__}.")

    kty = jwk.get("kty")
    priv_member = "d" if kty in ("EC", "OKP", "RSA") else "priv"
    has_private = priv_member in jwk

    if expect_private is None:
        is_private = has_private
    else:
        if expect_private and not has_private:
            raise InvalidJWK("expect_private=True but the JWK has no private member.")
        is_private = expect_private

    if kty == "EC":
        return _ec_from_jwk(jwk, is_private)
    if kty == "OKP":
        return _okp_from_jwk(jwk, is_private)
    if kty == "RSA":
        return _rsa_from_jwk(jwk, is_private)
    if kty == "AKP":
        alg = jwk.get("alg")
        if composite_alg_to_name(alg):
            return _composite_from_jwk(jwk, is_private)
        if akp_alg_to_name(alg):
            return _akp_from_jwk(jwk, is_private)
        raise InvalidJWK(f"Unknown or unsupported AKP alg: {alg!r}.")
    raise InvalidJWK(f"Unsupported JWK kty: {kty!r}.")


def dumps(
    key: object,
    *,
    is_private: Optional[bool] = None,
    include_kid: bool = False,
    extra: Optional[Dict[str, Any]] = None,
    allow_expanded_priv: bool = False,
    **json_kwargs: Any,
) -> str:
    """Serialise a key to a JWK JSON string. See :func:`key_to_jwk` for options."""
    jwk = key_to_jwk(
        key,
        is_private=is_private,
        include_kid=include_kid,
        extra=extra,
        allow_expanded_priv=allow_expanded_priv,
    )
    return json.dumps(jwk, **json_kwargs)


def loads(data: Union[str, bytes, JWK], *, expect_private: Optional[bool] = None) -> object:
    """Deserialise a key from a JWK JSON string, bytes, or an already-parsed dict."""
    if isinstance(data, (str, bytes, bytearray)):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as exc:
            raise InvalidJWK(f"Invalid JWK JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidJWK("JWK must be a JSON object.")
    return key_from_jwk(data, expect_private=expect_private)


# ==========================================================================
# EC (RFC 7518 §6.2, RFC 8812)
# ==========================================================================


def _ec_to_jwk(key: Any, is_private: bool) -> JWK:
    pub = key.public_key() if is_private else key  # type: ignore[union-attr]
    numbers = pub.public_numbers()
    curve = pub.curve
    crv = EC_CURVE_2_CRV.get(curve.name)
    if crv is None:
        raise InvalidJWK(f"EC curve {curve.name!r} has no registered JWK 'crv' value.")
    length = ec_coordinate_length(curve)
    jwk: JWK = {
        "kty": "EC",
        "crv": crv,
        "x": int_to_b64u(numbers.x, length=length),
        "y": int_to_b64u(numbers.y, length=length),
    }
    if is_private:
        d = key.private_numbers().private_value  # type: ignore[union-attr]
        jwk["d"] = int_to_b64u(d, length=length)
    return jwk


def _ec_from_jwk(jwk: JWK, is_private: bool) -> Any:
    crv = jwk.get("crv")
    curve_cls = EC_CRV_2_CURVE.get(crv) if isinstance(crv, str) else None
    if curve_cls is None:
        raise InvalidJWK(f"Unsupported EC crv: {crv!r}.")
    curve = curve_cls()
    public_numbers = ec.EllipticCurvePublicNumbers(
        b64u_to_int(_require(jwk, "x")),
        b64u_to_int(_require(jwk, "y")),
        curve,
    )
    if not is_private:
        return public_numbers.public_key()
    d = b64u_to_int(_require(jwk, "d"))
    return ec.EllipticCurvePrivateNumbers(d, public_numbers).private_key()


# ==========================================================================
# OKP (RFC 8037)
# ==========================================================================


def _okp_crv(key: Any) -> str:
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519"
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448"
    raise InvalidJWK(f"Not an OKP key: {type(key).__name__}.")  # pragma: no cover


def _okp_to_jwk(key: Any, is_private: bool) -> JWK:
    crv = _okp_crv(key)
    pub = key.public_key() if is_private else key  # type: ignore[union-attr]
    jwk: JWK = {
        "kty": "OKP",
        "crv": crv,
        "x": b64u_encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)),
    }
    if is_private:
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())  # type: ignore[union-attr]
        jwk["d"] = b64u_encode(raw)
    return jwk


def _okp_from_jwk(jwk: JWK, is_private: bool) -> Any:
    crv = jwk.get("crv")
    if crv not in _OKP_PUB_CTOR:
        raise InvalidJWK(f"Unsupported OKP crv: {crv!r}.")
    if is_private:
        return _OKP_PRIV_CTOR[crv](b64u_decode(_require(jwk, "d")))
    return _OKP_PUB_CTOR[crv](b64u_decode(_require(jwk, "x")))


# ==========================================================================
# RSA (RFC 7518 §6.3)
# ==========================================================================


def _rsa_to_jwk(key: Any, is_private: bool) -> JWK:
    public_numbers = (key.public_key() if is_private else key).public_numbers()  # type: ignore[union-attr]
    jwk: JWK = {
        "kty": "RSA",
        "n": int_to_b64u(public_numbers.n),
        "e": int_to_b64u(public_numbers.e),
    }
    if is_private:
        private_numbers = key.private_numbers()  # type: ignore[union-attr]
        jwk.update(
            {
                "d": int_to_b64u(private_numbers.d),
                "p": int_to_b64u(private_numbers.p),
                "q": int_to_b64u(private_numbers.q),
                "dp": int_to_b64u(private_numbers.dmp1),
                "dq": int_to_b64u(private_numbers.dmq1),
                "qi": int_to_b64u(private_numbers.iqmp),
            }
        )
    return jwk


def _rsa_from_jwk(jwk: JWK, is_private: bool) -> Any:
    public_numbers = rsa.RSAPublicNumbers(
        b64u_to_int(_require(jwk, "e")),
        b64u_to_int(_require(jwk, "n")),
    )
    if not is_private:
        return public_numbers.public_key()
    private_numbers = rsa.RSAPrivateNumbers(
        p=b64u_to_int(_require(jwk, "p")),
        q=b64u_to_int(_require(jwk, "q")),
        d=b64u_to_int(_require(jwk, "d")),
        dmp1=b64u_to_int(_require(jwk, "dp")),
        dmq1=b64u_to_int(_require(jwk, "dq")),
        iqmp=b64u_to_int(_require(jwk, "qi")),
        public_numbers=public_numbers,
    )
    return private_numbers.private_key()


# ==========================================================================
# AKP — ML-DSA / ML-KEM / SLH-DSA
# ==========================================================================


def _akp_kind(name: str) -> str:
    for prefix in _AKP_CLASSES:
        if name.startswith(prefix):
            return prefix
    raise InvalidJWK(f"{name!r} is not a JWK-registered AKP algorithm.")


def _akp_priv_bytes(key: Any, name: str, allow_expanded: bool) -> bytes:
    """Return the bytes for the AKP ``priv`` member.

    SLH-DSA uses the full secret key; ML-DSA/ML-KEM use the algorithm seed.
    """
    if name.startswith("slh-dsa"):
        return key.private_bytes_raw()  # type: ignore[union-attr]
    try:
        return key.private_numbers()  # seed  # type: ignore[union-attr]
    except ValueError as exc:
        if allow_expanded:
            return key.private_bytes_raw()  # type: ignore[union-attr]
        raise InvalidJWK(
            f"{name} private key has no seed; cannot emit the AKP 'priv' seed member. "
            "Pass allow_expanded_priv=True to emit the expanded private bytes "
            "(non-conformant with the JOSE PQC drafts)."
        ) from exc


def _akp_to_jwk(key: Any, is_private: bool, allow_expanded_priv: bool) -> JWK:
    name = key.name  # type: ignore[union-attr]
    alg = AKP_NAME_2_ALG.get(name)
    if alg is None:
        raise InvalidJWK(f"{name!r} is not a JWK-registered AKP algorithm.")
    pub = key.public_key() if is_private else key  # type: ignore[union-attr]
    jwk: JWK = {"kty": "AKP", "alg": alg, "pub": b64u_encode(pub.public_bytes_raw())}
    if is_private:
        jwk["priv"] = b64u_encode(_akp_priv_bytes(key, name, allow_expanded_priv))
    return jwk


def _akp_from_jwk(jwk: JWK, is_private: bool) -> Any:
    name = akp_alg_to_name(jwk.get("alg"))
    if name is None:
        raise InvalidJWK(f"Unknown AKP alg: {jwk.get('alg')!r}.")
    public_cls, private_cls = _AKP_CLASSES[_akp_kind(name)]
    if is_private:
        return private_cls.from_private_bytes(b64u_decode(_require(jwk, "priv")), name)
    return public_cls.from_public_bytes(b64u_decode(_require(jwk, "pub")), name)


# ==========================================================================
# Composite signatures (draft-ietf-jose-pq-composite-sigs)
# ==========================================================================


def _composite_to_jwk(key: Any, is_private: bool) -> JWK:
    name = key.name  # type: ignore[union-attr]
    alg = COMPOSITE_NAME_2_ALG.get(name)
    if alg is None:
        raise InvalidJWK(f"{name!r} is not a JWK-registered composite algorithm.")
    pub = key.public_key() if is_private else key  # type: ignore[union-attr]
    jwk: JWK = {"kty": "AKP", "alg": alg, "pub": b64u_encode(pub.public_bytes_raw())}
    if is_private:
        # Reuse the library's own seed-form composite serialisation so the bytes
        # round-trip exactly through ``_load_composite_sig_from_private_bytes``.
        try:
            priv_bytes = HybridKeyFactory._save_keys_with_support_seed(  # pylint: disable=protected-access
                key, save_type="seed"
            )
        except ValueError as exc:
            raise InvalidJWK(
                f"{name} composite private key has no ML-DSA seed; cannot emit the AKP 'priv' member."
            ) from exc
        jwk["priv"] = b64u_encode(priv_bytes)
    return jwk


def _composite_from_jwk(jwk: JWK, is_private: bool) -> Any:
    name = composite_alg_to_name(jwk.get("alg"))
    if name is None:
        raise InvalidJWK(f"Unknown composite alg: {jwk.get('alg')!r}.")
    if is_private:
        priv_bytes = b64u_decode(_require(jwk, "priv"))
        # pylint: disable-next=protected-access
        return HybridKeyFactory._load_composite_sig_from_private_bytes(name, priv_bytes)
    pub_bytes = b64u_decode(_require(jwk, "pub"))
    oid = COMPOSITE_SIG_NAME_TO_OID[name]
    # pylint: disable-next=protected-access
    public_key: CompositeSigPublicKey = HybridKeyFactory._load_composite_sig_from_spki(oid, pub_bytes)
    return public_key
