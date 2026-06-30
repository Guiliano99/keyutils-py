# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# The original code is from the cmp-test-suite project:
#   https://github.com/siemens/cmp-test-suite
#  Code owner: Alexandr Railean
# This code may be modified, or just copy pasted from the original.
#

"""Name and curve mapping tables for JWK serialisation.

This module holds the static tables that translate between ``keyutils_py``
canonical algorithm/curve names and their JOSE registry counterparts, plus the
:func:`jwk_family` classifier used by the serialiser dispatch:

* ``EC`` curves      — :data:`EC_CURVE_2_CRV` / :data:`EC_CRV_2_CURVE`
  (RFC 7518 §6.2.1.1, RFC 8812 for ``secp256k1``).
* ``OKP`` curves     — :data:`OKP_CRVS` (RFC 8037).
* ``AKP`` algorithms — :data:`AKP_NAME_2_ALG` / :data:`AKP_ALG_2_NAME` for
  ML-DSA / ML-KEM / SLH-DSA (draft-ietf-cose-dilithium,
  draft-ietf-jose-pqc-kem, draft-ietf-cose-sphincs-plus).
* Composite signatures — :data:`COMPOSITE_NAME_2_ALG` / :data:`COMPOSITE_ALG_2_NAME`
  (draft-ietf-jose-pq-composite-sigs).
"""

from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from keyutils_py.exceptions import InvalidJWK
from keyutils_py.keys.abstract_wrapper_keys import PQPrivateKey, PQPublicKey
from keyutils_py.keys.composite_sig import CompositeSigPrivateKey, CompositeSigPublicKey
from keyutils_py.keys.kem_keys import ML_KEM_NAMES
from keyutils_py.keys.sig_keys import ML_DSA_NAMES
from keyutils_py.oids import COMPOSITE_SIG_NAME_TO_OID, SLH_DSA_NAME_2_OID

__all__ = [
    "EC_CURVE_2_CRV",
    "EC_CRV_2_CURVE",
    "ec_coordinate_length",
    "OKP_CRVS",
    "AKP_NAME_2_ALG",
    "AKP_ALG_2_NAME",
    "COMPOSITE_NAME_2_ALG",
    "COMPOSITE_ALG_2_NAME",
    "akp_alg_to_name",
    "composite_alg_to_name",
    "jwk_family",
]

# --------------------------------------------------------------------------
# EC (RFC 7518 §6.2 + RFC 8812)
# --------------------------------------------------------------------------

# cryptography curve name -> JWK ``crv``. Only the curves with a registered JWK
# ``crv`` value are listed; brainpool/legacy curves are intentionally absent and
# trigger a clear error when a standalone EC key uses them.
EC_CURVE_2_CRV = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp256k1": "secp256k1",
}

# JWK ``crv`` -> cryptography curve class (instantiated on use).
EC_CRV_2_CURVE = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
    "secp256k1": ec.SECP256K1,
}


def ec_coordinate_length(curve: ec.EllipticCurve) -> int:
    """Return the fixed byte length of an EC coordinate for ``curve``.

    :param curve: The elliptic curve.
    :returns: ``ceil(curve.key_size / 8)`` (e.g. 32 for P-256, 66 for P-521).
    """
    return (curve.key_size + 7) // 8


# --------------------------------------------------------------------------
# OKP (RFC 8037)
# --------------------------------------------------------------------------

OKP_CRVS = ("Ed25519", "Ed448", "X25519", "X448")


# --------------------------------------------------------------------------
# AKP — ML-DSA / ML-KEM / SLH-DSA
# --------------------------------------------------------------------------


def _slh_dsa_to_jose(name: str) -> str:
    """Map a canonical SLH-DSA name to its JOSE ``alg`` (e.g. ``SLH-DSA-SHA2-128s``)."""
    upper = name.upper()
    # The trailing fast/small marker stays lowercase per the draft examples.
    if upper[-1] in ("S", "F"):
        upper = upper[:-1] + upper[-1].lower()
    return upper


_SLH_DSA_PURE_NAMES = [n for n in SLH_DSA_NAME_2_OID if n.count("-") == 3]

# JOSE ``alg`` -> canonical internal name.
AKP_ALG_2_NAME = {}
for _n in ML_DSA_NAMES:
    AKP_ALG_2_NAME[_n.upper()] = _n  # ml-dsa-44 -> ML-DSA-44
for _n in ML_KEM_NAMES:
    AKP_ALG_2_NAME[_n.upper()] = _n  # ml-kem-768 -> ML-KEM-768
for _n in _SLH_DSA_PURE_NAMES:
    AKP_ALG_2_NAME[_slh_dsa_to_jose(_n)] = _n

AKP_NAME_2_ALG = {v: k for k, v in AKP_ALG_2_NAME.items()}

# Case-insensitive lookup table for tolerant deserialisation.
_AKP_ALG_LOWER = {k.lower(): v for k, v in AKP_ALG_2_NAME.items()}


def akp_alg_to_name(alg: Optional[str]) -> Optional[str]:
    """Return the canonical key name for an AKP ``alg`` (case-insensitive), or ``None``."""
    return _AKP_ALG_LOWER.get(alg.lower()) if isinstance(alg, str) else None


# --------------------------------------------------------------------------
# Composite signatures (draft-ietf-jose-pq-composite-sigs)
# --------------------------------------------------------------------------

_EC_CURVE_ABBR = {
    "secp256r1": "P256",
    "secp384r1": "P384",
    "secp521r1": "P521",
    "brainpoolP256r1": "BP256",
    "brainpoolP384r1": "BP384",
    "brainpoolP512r1": "BP512",
}


def _composite_trad_to_jose(trad: str) -> str:
    """Map the traditional half of a composite name to its JOSE token."""
    if trad.startswith("ecdsa-"):
        curve = trad[len("ecdsa-") :]
        if curve not in _EC_CURVE_ABBR:
            raise InvalidJWK(f"Unsupported composite EC curve: {curve!r}.")
        return "ECDSA-" + _EC_CURVE_ABBR[curve]
    if trad.startswith("rsa"):
        return trad.upper()  # rsa2048 -> RSA2048, rsa2048-pss -> RSA2048-PSS
    if trad == "ed25519":
        return "Ed25519"
    if trad == "ed448":
        return "Ed448"
    raise InvalidJWK(f"Unsupported composite traditional algorithm: {trad!r}.")


def _composite_to_jose(internal_name: str) -> str:
    """Map a canonical composite-sig name to its JOSE ``alg``.

    ``composite-sig-ml-dsa-44-ecdsa-secp256r1`` -> ``ML-DSA-44-ECDSA-P256``.
    """
    body = internal_name[len("composite-sig-") :]
    # The PQ half is always ``ml-dsa-<level>``; the rest is the traditional half.
    parts = body.split("-")
    pq_name = "-".join(parts[:3])  # ml-dsa-44
    trad_name = "-".join(parts[3:])
    return f"{pq_name.upper()}-{_composite_trad_to_jose(trad_name)}"


# canonical internal name -> JOSE ``alg`` and inverse.
COMPOSITE_NAME_2_ALG = {name: _composite_to_jose(name) for name in COMPOSITE_SIG_NAME_TO_OID}
COMPOSITE_ALG_2_NAME = {v: k for k, v in COMPOSITE_NAME_2_ALG.items()}
_COMPOSITE_ALG_LOWER = {k.lower(): v for k, v in COMPOSITE_ALG_2_NAME.items()}


def composite_alg_to_name(alg: Optional[str]) -> Optional[str]:
    """Return the canonical composite name for a JOSE ``alg`` (case-insensitive), or ``None``."""
    return _COMPOSITE_ALG_LOWER.get(alg.lower()) if isinstance(alg, str) else None


# --------------------------------------------------------------------------
# Serialiser dispatch classifier
# --------------------------------------------------------------------------

_OKP_TYPES = (
    ed25519.Ed25519PublicKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PublicKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PublicKey,
    x25519.X25519PrivateKey,
    x448.X448PublicKey,
    x448.X448PrivateKey,
)


def jwk_family(key: object) -> str:
    """Classify a key object into a JWK family for serialisation dispatch.

    :param key: A traditional ``cryptography`` key or a ``keyutils_py`` wrapper key.
    :returns: One of ``"composite"``, ``"akp"``, ``"rsa"``, ``"ec"``, ``"okp"``.
    :raises InvalidJWK: If the key type has no JWK representation.
    """
    # Composite must be checked before the generic PQ check.
    if isinstance(key, (CompositeSigPublicKey, CompositeSigPrivateKey)):
        return "composite"
    if isinstance(key, (PQPublicKey, PQPrivateKey)):
        return "akp"
    if isinstance(key, (RSAPublicKey, RSAPrivateKey)):
        return "rsa"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ec"
    if isinstance(key, _OKP_TYPES):
        return "okp"
    raise InvalidJWK(f"No JWK representation for key type: {type(key).__name__}.")
